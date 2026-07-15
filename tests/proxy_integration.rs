use std::collections::HashSet;
use std::convert::Infallible;
use std::io::Read as _;
use std::net::SocketAddr;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use auth_mini_gateway::auth_mini::{
    AuthMini, AuthMiniOperationError, IdentityFetchOutcome, RefreshError, TokenResponse,
};
use auth_mini_gateway::config::{
    parse_trusted_proxy_cidrs, parse_upstream_url, Config, SameSite, TrustedProxySet, UpstreamBase,
};
use auth_mini_gateway::cookies::sign_value;
use auth_mini_gateway::db::{NewSession, Store};
use auth_mini_gateway::jwt::{Jwks, VerifiedAccessToken};
use auth_mini_gateway::proxy::{empty_body, full_body, BoxError, GatewayBody};
use auth_mini_gateway::server::{run_server_with_listener, run_server_with_listener_and_roots};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use chrono::{Duration, SecondsFormat, Utc};
use http::header::{CONNECTION, CONTENT_TYPE, SET_COOKIE, UPGRADE, WARNING};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body_util::BodyExt as _;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha1::{Digest, Sha1};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration as TokioDuration};
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Debug)]
struct Observed {
    method: String,
    target: String,
    headers: HeaderMap,
    body_len: usize,
    body: Vec<u8>,
}

struct FixtureState {
    hits: AtomicUsize,
    connections: AtomicUsize,
    observed: Mutex<Vec<Observed>>,
    upload_first_seen: Semaphore,
    upload_release: Semaphore,
    sse_release: Semaphore,
}

impl Default for FixtureState {
    fn default() -> Self {
        Self {
            hits: AtomicUsize::new(0),
            connections: AtomicUsize::new(0),
            observed: Mutex::new(Vec::new()),
            upload_first_seen: Semaphore::new(0),
            upload_release: Semaphore::new(0),
            sse_release: Semaphore::new(0),
        }
    }
}

struct RunningFixture {
    address: SocketAddr,
    state: Arc<FixtureState>,
    task: JoinHandle<()>,
}

struct RunningTlsFixture {
    address: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    state: Arc<FixtureState>,
    task: JoinHandle<()>,
}

struct RunningRawFixture {
    address: SocketAddr,
    hits: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

struct RunningStaleFixture {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    post_dispatches: Arc<AtomicUsize>,
    warm_response: Arc<Semaphore>,
    close_connection: Arc<Semaphore>,
    task: JoinHandle<()>,
}

struct RunningDenyFixture {
    address: SocketAddr,
    task: JoinHandle<()>,
}

struct RunningEarlyFinalFixture {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    forwarded_later_bytes: Arc<AtomicUsize>,
    reused_early_connection: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

struct RunningGateway {
    address: SocketAddr,
    _dir: TempDir,
    cookie: Option<String>,
    task: JoinHandle<()>,
}

#[derive(Clone)]
struct GatewayOptions {
    max_downstream_connections: usize,
    max_active_upstreams: usize,
    max_blocking_resolvers: usize,
    trusted_proxy_cidrs: TrustedProxySet,
}

impl Default for GatewayOptions {
    fn default() -> Self {
        Self {
            max_downstream_connections: 256,
            max_active_upstreams: 128,
            max_blocking_resolvers: 8,
            trusted_proxy_cidrs: TrustedProxySet::default(),
        }
    }
}

struct NoopAuth;

impl AuthMini for NoopAuth {
    fn verify_initial_access(
        &self,
        _token: &str,
    ) -> Result<VerifiedAccessToken, AuthMiniOperationError> {
        Err(AuthMiniOperationError)
    }

    fn prepare_refresh_verifier(&self) -> Result<Jwks, RefreshError> {
        panic!("fresh integration sessions do not refresh")
    }

    fn verify_refreshed_access(
        &self,
        _token: &str,
        _jwks: &Jwks,
    ) -> Result<VerifiedAccessToken, RefreshError> {
        panic!("fresh integration sessions do not refresh")
    }

    fn fetch_identity(&self, _access_token: &str) -> IdentityFetchOutcome {
        panic!("fresh integration sessions do not fetch identity")
    }

    fn refresh(
        &self,
        _session_id: &str,
        _refresh_token: &str,
    ) -> Result<TokenResponse, RefreshError> {
        panic!("fresh integration sessions do not refresh")
    }

    fn logout(&self, _access_token: &str) -> Result<(), AuthMiniOperationError> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adapter_mode_and_gateway_route_precedence_remain_local() {
    let gateway = start_gateway(None, SessionMode::Missing).await;

    let unknown = request_once(
        gateway.address,
        "GET /unknown HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&unknown, 404);
    assert!(response_body(&unknown).ends_with(b"Not found"));

    let health = request_once(
        gateway.address,
        "GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&health, 204);
    assert!(!response_head(&health)
        .to_ascii_lowercase()
        .contains("cache-control"));

    let connect_owned = request_once(
        gateway.address,
        "CONNECT /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&connect_owned, 404);

    let mut stream = TcpStream::connect(gateway.address)
        .await
        .expect("keep alive");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: public.example\r\n\r\n")
        .await
        .expect("first request");
    assert!(read_head(&mut stream).await.starts_with("HTTP/1.1 204"));
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
        .await
        .expect("second request");
    assert!(read_head(&mut stream).await.starts_with("HTTP/1.1 204"));

    let mut callback = TcpStream::connect(gateway.address)
        .await
        .expect("callback connect");
    callback
        .write_all(b"POST /auth/callback/session HTTP/1.1\r\nHost: public.example\r\nContent-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
        .await
        .expect("callback head");
    assert!(read_head(&mut callback).await.starts_with("HTTP/1.1 100"));
    callback.write_all(b"{}").await.expect("callback body");
    let mut callback_response = Vec::new();
    callback
        .read_to_end(&mut callback_response)
        .await
        .expect("callback response");
    assert_status(&callback_response, 400);

    gateway.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_check_status_identity_cleanup_and_logout_contract_is_directly_asserted() {
    let missing = start_gateway(None, SessionMode::Missing).await;
    let unauthenticated = request_once(
        missing.address,
        "GET /auth/check HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&unauthenticated, 401);
    let unauthenticated_head = response_head(&unauthenticated).to_ascii_lowercase();
    assert!(unauthenticated_head.contains("set-cookie: amg_session="));
    assert!(unauthenticated_head.contains("max-age=0"));

    let forbidden = start_gateway(None, SessionMode::Forbidden).await;
    let forbidden_cookie = forbidden.cookie.as_deref().expect("forbidden cookie");
    let denied = request_once(
        forbidden.address,
        &format!(
            "GET /auth/check HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={forbidden_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&denied, 403);
    let denied_head = response_head(&denied).to_ascii_lowercase();
    assert!(!denied_head.contains("set-cookie:"));
    assert!(!denied_head.contains("x-auth-mini-user-id"));

    let allowed = start_gateway(None, SessionMode::Allowed).await;
    let allowed_cookie = allowed.cookie.as_deref().expect("allowed cookie");
    let accepted = request_once(
        allowed.address,
        &format!(
            "GET /auth/check HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={allowed_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&accepted, 204);
    let accepted_head = response_head(&accepted).to_ascii_lowercase();
    assert!(accepted_head.contains("x-auth-mini-user-id: user-1"));
    assert!(accepted_head.contains("x-auth-mini-email: user@example.com"));

    let logout = request_once(
        allowed.address,
        &format!(
            "POST /logout HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={allowed_cookie}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&logout, 302);
    assert!(response_head(&logout)
        .to_ascii_lowercase()
        .contains("max-age=0"));
    let after_logout = request_once(
        allowed.address,
        &format!(
            "GET /auth/check HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={allowed_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&after_logout, 401);

    missing.task.abort();
    forbidden.task.abort();
    allowed.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_ascii_identity_header_bytes_match_auth_check_and_proxy() {
    const USER_ID: &str = "用户-一";
    const EMAIL: &str = "测试@example.com";

    let fixture = start_fixture().await;
    let gateway = start_gateway(Some(fixture.address), SessionMode::NonAsciiAllowed).await;
    let cookie = gateway.cookie.as_deref().expect("non-ASCII cookie");
    let check = request_once(
        gateway.address,
        &format!(
            "GET /auth/check HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&check, 204);
    let check_head = raw_response_head(&check);
    assert!(check_head
        .windows(USER_ID.len())
        .any(|value| value == USER_ID.as_bytes()));
    assert!(check_head
        .windows(EMAIL.len())
        .any(|value| value == EMAIL.as_bytes()));

    let proxied = request_once(
        gateway.address,
        &format!(
            "GET /identity HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&proxied, 200);
    let observed = fixture.state.observed.lock().expect("identity observed");
    let headers = &observed.last().expect("identity upstream request").headers;
    assert_eq!(
        headers
            .get("x-auth-mini-user-id")
            .expect("user ID header")
            .as_bytes(),
        USER_ID.as_bytes()
    );
    assert_eq!(
        headers
            .get("x-auth-mini-email")
            .expect("email header")
            .as_bytes(),
        EMAIL.as_bytes()
    );

    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_gateway_owned_route_and_unsupported_method_isolated_from_proxy() {
    let fixture = start_fixture().await;
    let gateway = start_gateway(Some(fixture.address), SessionMode::Missing).await;
    let valid = [
        ("GET", "/healthz", ""),
        ("GET", "/login?return_to=%2F", ""),
        ("GET", "/auth/callback", ""),
        ("POST", "/auth/callback/session", "{}"),
        ("GET", "/auth/check", ""),
        ("GET", "/logout", ""),
        ("POST", "/logout", ""),
    ];
    for (method, target, body) in valid {
        let response = request_once(
            gateway.address,
            &format!(
                "{method} {target} HTTP/1.1\r\nHost: public.example\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert_ne!(response_status(&response), 502, "{method} {target}");
    }
    for path in [
        "/healthz",
        "/login",
        "/auth/callback",
        "/auth/callback/session",
        "/auth/check",
        "/logout",
    ] {
        let response = request_once(
            gateway.address,
            &format!(
                "PUT {path}?unsupported=1 HTTP/1.1\r\nHost: public.example\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert_status(&response, 404);
    }
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 0);
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_denials_are_fail_closed_and_do_not_hit_the_upstream() {
    let fixture = start_fixture().await;
    let gateway = start_gateway(Some(fixture.address), SessionMode::Forbidden).await;

    let unsafe_target = request_once(
        gateway.address,
        "GET //attacker.example/x HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&unsafe_target, 400);
    assert!(!response_head(&unsafe_target)
        .to_ascii_lowercase()
        .contains("set-cookie"));

    let anonymous = request_once(
        gateway.address,
        "GET /safe?q=1&q=2 HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&anonymous, 302);
    let anonymous_head = response_head(&anonymous).to_ascii_lowercase();
    assert_eq!(anonymous_head.matches("set-cookie:").count(), 2);
    assert!(anonymous_head.contains("location: http://localhost:7777/"));

    let cookie = gateway.cookie.as_deref().expect("forbidden cookie");
    let forbidden = request_once(
        gateway.address,
        &format!(
            "POST /write HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nContent-Length: 4\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&forbidden, 403);
    assert!(!String::from_utf8_lossy(&forbidden).contains("100 Continue"));

    let owned = request_once(
        gateway.address,
        "GET /healthz?x=1 HTTP/1.1\r\nHost: public.example\r\nUpgrade: made-up\r\nConnection: upgrade, close\r\n\r\n",
    )
    .await;
    assert_status(&owned, 204);

    let invalid_expect = request_once(
        gateway.address,
        "POST /write HTTP/1.1\r\nHost: public.example\r\nContent-Length: 4\r\nExpect: something-else\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&invalid_expect, 417);
    assert!(!String::from_utf8_lossy(&invalid_expect).contains("100 Continue"));

    for request in [
        "CONNECT upstream.example:443 HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
        "OPTIONS * HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    ] {
        let response = request_once(gateway.address, request).await;
        assert_status(
            &response,
            if request.starts_with("CONNECT") { 405 } else { 400 },
        );
    }

    let websocket_head = |cookie: Option<&str>| {
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\n{}Connection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            cookie
                .map(|value| format!("Cookie: amg_session={value}\r\n"))
                .unwrap_or_default()
        )
    };
    let anonymous_websocket = request_once(gateway.address, &websocket_head(None)).await;
    assert_status(&anonymous_websocket, 302);
    let forbidden_websocket = request_once(gateway.address, &websocket_head(Some(cookie))).await;
    assert_status(&forbidden_websocket, 403);
    let malformed_websocket = request_once(
        gateway.address,
        &format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 12\r\nSec-WebSocket-Key: not-canonical\r\n\r\n"
        ),
    )
    .await;
    assert_status(&malformed_websocket, 400);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 0);

    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_unauthenticated_login_database_failure_is_clear_only_500() {
    let fixture = start_fixture().await;
    let gateway = start_gateway(Some(fixture.address), SessionMode::Missing).await;
    std::fs::remove_dir_all(gateway._dir.path()).expect("remove login-state database");
    let response = request_once(
        gateway.address,
        "GET /login-db-failure HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&response, 500);
    assert_eq!(response_body(&response), b"Internal server error");
    let head = response_head(&response).to_ascii_lowercase();
    assert_eq!(head.matches("set-cookie:").count(), 1);
    assert!(head.contains("set-cookie: amg_session="));
    assert!(head.contains("max-age=0"));
    assert!(!head.contains("amg_login_state"));
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 0);
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_streams_required_methods_large_chunked_bodies_and_sse_with_sanitation() {
    let fixture = start_fixture().await;
    let gateway = start_gateway(Some(fixture.address), SessionMode::Allowed).await;
    let cookie = gateway.cookie.as_deref().expect("allowed cookie");

    for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
        let body = if method == "GET" { "" } else { "abc" };
        let content = if body.is_empty() {
            String::new()
        } else {
            format!("Content-Length: {}\r\n", body.len())
        };
        let response = request_once(
            gateway.address,
            &format!(
                "{method} /api?q=1&q=2 HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nAuthorization: Bearer browser-secret\r\nProxy-Authorization: Basic proxy-secret\r\nX-Auth-Mini-User-Id: spoofed\r\nX-Auth-Mini-Email: spoofed@example.com\r\nX-Auth-Mini-Admin: true\r\nForwarded: for=attacker\r\nX-Forwarded-For: attacker\r\nConnection: X-Remove, close\r\nX-Remove: hidden\r\nX-Keep: one\r\nX-Keep: two\r\n{content}\r\n{body}"
            ),
        )
        .await;
        assert_status(&response, 200);
        tokio::time::sleep(TokioDuration::from_millis(10)).await;
    }

    let absolute = request_once(
        gateway.address,
        &format!(
            "GET http://attacker.example/absolute?raw=%2F HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nX-Forwarded-Host: attacker.example\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&absolute, 200);

    let observed = fixture.state.observed.lock().expect("observed").clone();
    assert_eq!(observed.len(), 6);
    for (entry, method) in observed[..5]
        .iter()
        .zip(["GET", "POST", "PUT", "PATCH", "DELETE"])
    {
        assert_eq!(entry.method, method);
        assert_eq!(entry.target, "/base/api?q=1&q=2");
        assert_eq!(entry.headers.get("host").unwrap(), "public.example");
        assert_eq!(entry.headers.get("x-auth-mini-user-id").unwrap(), "user-1");
        assert_eq!(
            entry.headers.get("x-auth-mini-email").unwrap(),
            "user@example.com"
        );
        assert_eq!(
            entry.headers.get_all("x-auth-mini-user-id").iter().count(),
            1
        );
        assert_eq!(entry.headers.get_all("x-auth-mini-email").iter().count(), 1);
        assert!(!entry.headers.contains_key("x-auth-mini-admin"));
        assert_eq!(entry.headers.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(
            entry.headers.get("x-forwarded-host").unwrap(),
            "public.example"
        );
        assert!(entry.headers.contains_key("x-forwarded-for"));
        for removed in [
            "cookie",
            "authorization",
            "proxy-authorization",
            "forwarded",
            "x-remove",
        ] {
            assert!(!entry.headers.contains_key(removed), "{removed}");
        }
        assert_eq!(entry.headers.get_all("x-keep").iter().count(), 2);
        assert_eq!(entry.body_len, if method == "GET" { 0 } else { 3 });
        assert_eq!(
            entry.body,
            if method == "GET" {
                Vec::new()
            } else {
                b"abc".to_vec()
            }
        );
    }
    assert_eq!(observed[5].target, "/base/absolute?raw=%2F");
    assert_eq!(observed[5].headers.get("host").unwrap(), "public.example");
    assert_eq!(
        observed[5].headers.get("x-forwarded-host").unwrap(),
        "public.example"
    );
    assert!(fixture.state.connections.load(Ordering::SeqCst) <= 2);

    let ordinary = request_once(
        gateway.address,
        &format!(
            "GET /cookies HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&ordinary, 200);
    let head = response_head(&ordinary).to_ascii_lowercase();
    assert!(head.contains("set-cookie: app_cookie=ok"));
    assert!(!head.contains("set-cookie: amg_session=upstream"));
    assert_eq!(head.matches("warning:").count(), 2);

    let mut upload = TcpStream::connect(gateway.address)
        .await
        .expect("upload connect");
    upload
        .write_all(
            format!(
                "POST /upload HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nTransfer-Encoding: chunked\r\nTrailer: X-Late\r\nConnection: close\r\n\r\n4\r\npart\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("first upload chunk");
    timeout(
        TokioDuration::from_secs(2),
        fixture.state.upload_first_seen.acquire(),
    )
    .await
    .expect("upstream saw first chunk")
    .expect("semaphore")
    .forget();
    fixture.state.upload_release.add_permits(1);
    let large = vec![b'x'; 1024 * 1024];
    upload
        .write_all(format!("{:x}\r\n", large.len()).as_bytes())
        .await
        .expect("large chunk head");
    upload.write_all(&large).await.expect("large chunk");
    upload
        .write_all(b"\r\n0\r\nX-Late: dropped\r\n\r\n")
        .await
        .expect("upload finish");
    let mut upload_response = Vec::new();
    upload
        .read_to_end(&mut upload_response)
        .await
        .expect("upload response");
    assert_status(&upload_response, 200);
    assert!(response_body(&upload_response)
        .windows(b"1048580".len())
        .any(|window| window == b"1048580"));

    let mut expect = TcpStream::connect(gateway.address)
        .await
        .expect("expect connect");
    expect
        .write_all(
            format!(
                "POST /upload HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nContent-Length: 4\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("expect head");
    assert!(timeout(TokioDuration::from_secs(2), read_head(&mut expect))
        .await
        .expect("allowed expect response")
        .starts_with("HTTP/1.1 100"));
    expect.write_all(b"data").await.expect("expect body");
    timeout(
        TokioDuration::from_secs(2),
        fixture.state.upload_first_seen.acquire(),
    )
    .await
    .expect("expect upload reached upstream")
    .expect("semaphore")
    .forget();
    fixture.state.upload_release.add_permits(1);
    let mut expect_response = Vec::new();
    expect
        .read_to_end(&mut expect_response)
        .await
        .expect("expect final");
    assert_status(&expect_response, 200);

    let chunked = request_once(
        gateway.address,
        &format!(
            "GET /chunks HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&chunked, 200);
    assert_eq!(decoded_response_body(&chunked), b"alphabetagamma");
    let chunked_head = response_head(&chunked).to_ascii_lowercase();
    assert!(chunked_head.contains("transfer-encoding: chunked"));
    assert!(!chunked_head.contains("content-length:"));

    let mut sse = TcpStream::connect(gateway.address)
        .await
        .expect("sse connect");
    sse.write_all(
        format!(
            "GET /events HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .expect("sse request");
    let mut first = Vec::new();
    timeout(TokioDuration::from_secs(2), async {
        let mut byte = [0u8; 1];
        while !first.windows(11).any(|window| window == b"data: one\n\n") {
            sse.read_exact(&mut byte).await.expect("sse first event");
            first.push(byte[0]);
        }
    })
    .await
    .expect("first SSE event streamed");
    fixture.state.sse_release.add_permits(1);
    let mut rest = Vec::new();
    sse.read_to_end(&mut rest).await.expect("sse completion");
    assert!(rest.windows(11).any(|window| window == b"data: two\n\n"));

    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn early_upstream_final_cancels_upload_closes_downstream_and_disables_reuse() {
    let fixture = start_early_final_fixture().await;
    let gateway = start_gateway(Some(fixture.address), SessionMode::Allowed).await;
    let cookie = gateway.cookie.as_deref().expect("early-final cookie");
    let mut upload = TcpStream::connect(gateway.address)
        .await
        .expect("early-final client");
    upload
        .write_all(
            format!(
                "POST /early HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("early-final first chunk");
    let mut early_response = Vec::new();
    timeout(
        TokioDuration::from_secs(2),
        upload.read_to_end(&mut early_response),
    )
    .await
    .expect("early final was not prompt")
    .expect("early-final response");
    assert_status(&early_response, 413);
    assert!(response_head(&early_response)
        .to_ascii_lowercase()
        .contains("connection: close"));

    let _ = upload.write_all(b"c\r\nlater-client\r\n0\r\n\r\n").await;
    let after = request_once(
        gateway.address,
        &format!(
            "GET /after HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&after, 200);
    tokio::time::sleep(TokioDuration::from_millis(50)).await;
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.forwarded_later_bytes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.reused_early_connection.load(Ordering::SeqCst), 0);

    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_websocket_is_bidirectional_and_transport_failures_are_sanitized() {
    let fixture = start_fixture().await;
    let gateway = start_gateway(Some(fixture.address), SessionMode::Allowed).await;
    let cookie = gateway.cookie.as_deref().expect("allowed cookie");
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    for malformed in [
        format!(
            "POST /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nContent-Length: 0\r\n\r\n"
        ),
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 12\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        ),
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: bad\r\n\r\n"
        ),
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        ),
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: made-up\r\n\r\n"
        ),
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        ),
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, Sec-WebSocket-Key, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        ),
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, Sec-WebSocket-Version, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        ),
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, Sec-WebSocket-Protocol, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
        ),
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, Sec-WebSocket-Extensions, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        ),
    ] {
        let response = request_once(gateway.address, &malformed).await;
        assert_status(&response, 400);
    }
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 0);

    let mut socket = TcpStream::connect(gateway.address)
        .await
        .expect("ws connect");
    socket
        .write_all(
            format!(
                "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("ws handshake");
    let head = timeout(TokioDuration::from_secs(2), read_head(&mut socket))
        .await
        .expect("ws response");
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(head
        .to_ascii_lowercase()
        .contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="));
    assert!(head
        .to_ascii_lowercase()
        .contains("sec-websocket-protocol: chat"));
    socket.write_all(b"ping").await.expect("ws client bytes");
    let mut pong = [0u8; 4];
    socket
        .read_exact(&mut pong)
        .await
        .expect("ws upstream bytes");
    assert_eq!(&pong, b"pong");
    socket.shutdown().await.expect("ws half-close");
    let mut eof = [0u8; 1];
    assert_eq!(
        timeout(TokioDuration::from_secs(2), socket.read(&mut eof))
            .await
            .expect("ws close propagated")
            .expect("ws close read"),
        0
    );

    let invalid_accept = request_once(
        gateway.address,
        &format!(
            "GET /bad-ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        ),
    )
    .await;
    assert_status(&invalid_accept, 502);
    let invalid_protocol = request_once(
        gateway.address,
        &format!(
            "GET /bad-protocol-ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
        ),
    )
    .await;
    assert_status(&invalid_protocol, 502);
    let invalid_extension = request_once(
        gateway.address,
        &format!(
            "GET /bad-extension-ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        ),
    )
    .await;
    assert_status(&invalid_extension, 502);
    for nominated in [
        format!(
            "GET /nominated-accept-ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        ),
        format!(
            "GET /nominated-protocol-ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
        ),
        format!(
            "GET /nominated-extension-ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        ),
    ] {
        let response = request_once(gateway.address, &nominated).await;
        assert_status(&response, 502);
        assert!(!response.starts_with(b"HTTP/1.1 101"));
    }

    let unavailable = unused_address().await;
    let broken_gateway = start_gateway(Some(unavailable), SessionMode::Allowed).await;
    let broken_cookie = broken_gateway.cookie.as_deref().expect("broken cookie");
    let response = request_once(
        broken_gateway.address,
        &format!(
            "GET /api HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={broken_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&response, 502);
    assert_eq!(response_body(&response), b"Bad gateway");
    let wire = String::from_utf8_lossy(&response);
    assert!(!wire.contains(&unavailable.to_string()));

    gateway.task.abort();
    broken_gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_upstream_accepts_injected_trust_and_rejects_an_untrusted_certificate() {
    let fixture = start_tls_fixture().await;
    let upstream = parse_upstream_url(Some(&format!(
        "https://localhost:{}/base",
        fixture.address.port()
    )))
    .expect("valid TLS upstream")
    .expect("configured TLS upstream");
    let mut trusted = rustls::RootCertStore::empty();
    trusted
        .add(fixture.certificate.clone())
        .expect("trusted test certificate");
    let good = start_gateway_with_options(
        Some(upstream.clone()),
        SessionMode::Allowed,
        Some(trusted),
        GatewayOptions {
            trusted_proxy_cidrs: parse_trusted_proxy_cidrs(Some("127.0.0.1/32"))
                .expect("trusted TLS peer"),
            ..GatewayOptions::default()
        },
    )
    .await;
    let good_cookie = good.cookie.as_deref().expect("good TLS cookie");
    let connections_before = fixture.state.connections.load(Ordering::SeqCst);
    let accepted = request_once(
        good.address,
        &format!(
            "GET /tls HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={good_cookie}\r\nX-Forwarded-For: 192.0.2.41\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&accepted, 200);
    tokio::time::sleep(TokioDuration::from_millis(25)).await;
    let accepted_again = request_once(
        good.address,
        &format!(
            "GET /tls HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={good_cookie}\r\nX-Forwarded-For: 2001:db8::41\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&accepted_again, 200);
    assert_eq!(
        fixture.state.connections.load(Ordering::SeqCst),
        connections_before + 1,
        "trusted XFF must not alter TLS/SNI destination or pool key"
    );
    {
        let observed = fixture.state.observed.lock().expect("TLS observations");
        let last_two = &observed[observed.len() - 2..];
        assert!(last_two.iter().all(|request| request.target == "/base/tls"));
        let first_authority = last_two[0].headers["host"]
            .to_str()
            .expect("first fixed TLS authority");
        let second_authority = last_two[1].headers["host"]
            .to_str()
            .expect("second fixed TLS authority");
        assert_eq!(first_authority, second_authority);
        assert_eq!(first_authority, "public.example");
        assert_eq!(last_two[0].headers["x-forwarded-for"], "192.0.2.41");
        assert_eq!(last_two[1].headers["x-forwarded-for"], "2001:db8::41");
    }

    let bad = start_gateway_with_upstream(
        Some(upstream),
        SessionMode::Allowed,
        Some(rustls::RootCertStore::empty()),
    )
    .await;
    let bad_cookie = bad.cookie.as_deref().expect("bad TLS cookie");
    let rejected = request_once(
        bad.address,
        &format!(
            "GET /tls HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={bad_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&rejected, 502);
    assert_eq!(response_body(&rejected), b"Bad gateway");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 2);

    good.task.abort();
    bad.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_ip_authority_requires_matching_ip_san_without_dns_substitution() {
    let ip_fixture = start_tls_fixture_with_san("127.0.0.1").await;
    let ip_upstream = parse_upstream_url(Some(&format!(
        "https://127.0.0.1:{}/base",
        ip_fixture.address.port()
    )))
    .expect("IP upstream URL")
    .expect("IP upstream");
    let mut ip_roots = rustls::RootCertStore::empty();
    ip_roots
        .add(ip_fixture.certificate.clone())
        .expect("IP fixture root");
    let accepted =
        start_gateway_with_upstream(Some(ip_upstream), SessionMode::Allowed, Some(ip_roots)).await;
    let accepted_cookie = accepted.cookie.as_deref().expect("IP SAN cookie");
    let response = request_once(
        accepted.address,
        &format!(
            "GET /ip-san HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={accepted_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&response, 200);

    let dns_fixture = start_tls_fixture_with_san("localhost").await;
    let dns_cert_ip_authority = parse_upstream_url(Some(&format!(
        "https://127.0.0.1:{}/base",
        dns_fixture.address.port()
    )))
    .expect("DNS certificate IP URL")
    .expect("DNS certificate IP upstream");
    let mut dns_roots = rustls::RootCertStore::empty();
    dns_roots
        .add(dns_fixture.certificate.clone())
        .expect("DNS fixture root");
    let rejected = start_gateway_with_upstream(
        Some(dns_cert_ip_authority),
        SessionMode::Allowed,
        Some(dns_roots),
    )
    .await;
    let rejected_cookie = rejected.cookie.as_deref().expect("DNS-only cookie");
    let response = request_once(
        rejected.address,
        &format!(
            "GET /dns-not-ip HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={rejected_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&response, 502);
    assert_eq!(dns_fixture.state.hits.load(Ordering::SeqCst), 0);

    accepted.task.abort();
    rejected.task.abort();
    ip_fixture.task.abort();
    dns_fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bracketed_ipv6_gateway_connector_requires_matching_ipv6_ip_san() {
    let matching = start_tls_fixture_with_san_on("::1", "[::1]:0").await;
    assert!(matching.address.is_ipv6());
    let matching_upstream = parse_upstream_url(Some(&format!(
        "https://[::1]:{}/base",
        matching.address.port()
    )))
    .expect("IPv6 IP-SAN URL")
    .expect("IPv6 IP-SAN upstream");
    let mut matching_roots = rustls::RootCertStore::empty();
    matching_roots
        .add(matching.certificate.clone())
        .expect("IPv6 IP-SAN root");
    let accepted = start_gateway_with_upstream(
        Some(matching_upstream),
        SessionMode::Allowed,
        Some(matching_roots),
    )
    .await;
    let accepted_cookie = accepted.cookie.as_deref().expect("IPv6 accepted cookie");
    let response = request_once(
        accepted.address,
        &format!(
            "GET /ipv6-ip-san HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={accepted_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&response, 200);
    assert_eq!(matching.state.hits.load(Ordering::SeqCst), 1);
    assert_eq!(matching.state.connections.load(Ordering::SeqCst), 1);

    let dns_only = start_tls_fixture_with_san_on("localhost", "[::1]:0").await;
    let dns_only_upstream = parse_upstream_url(Some(&format!(
        "https://[::1]:{}/base",
        dns_only.address.port()
    )))
    .expect("IPv6 DNS-only URL")
    .expect("IPv6 DNS-only upstream");
    let mut dns_only_roots = rustls::RootCertStore::empty();
    dns_only_roots
        .add(dns_only.certificate.clone())
        .expect("IPv6 DNS-only root");
    let rejected = start_gateway_with_upstream(
        Some(dns_only_upstream),
        SessionMode::Allowed,
        Some(dns_only_roots),
    )
    .await;
    let rejected_cookie = rejected.cookie.as_deref().expect("IPv6 rejected cookie");
    let response = request_once(
        rejected.address,
        &format!(
            "GET /ipv6-dns-only HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={rejected_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&response, 502);
    assert_eq!(dns_only.state.hits.load(Ordering::SeqCst), 0);
    assert_eq!(dns_only.state.connections.load(Ordering::SeqCst), 0);

    accepted.task.abort();
    rejected.task.abort();
    matching.task.abort();
    dns_only.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hyper_owned_framing_rejects_desync_and_never_duplicates_dispatch() {
    let fixture = start_fixture().await;
    let gateway = start_gateway(Some(fixture.address), SessionMode::Allowed).await;
    let cookie = gateway.cookie.as_deref().expect("framing cookie");
    let attacks = [
        format!(
            "POST /api HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /injected HTTP/1.1\r\nHost: public.example\r\n\r\n"
        ),
        format!(
            "POST /api HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcdeGET /injected HTTP/1.1\r\nHost: public.example\r\n\r\n"
        ),
        format!(
            "POST /api HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nTransfer-Encoding: chunked\r\n\r\nnot-a-size\r\nGET /injected HTTP/1.1\r\nHost: public.example\r\n\r\n"
        ),
    ];
    for attack in attacks {
        let before = fixture.state.hits.load(Ordering::SeqCst);
        let response = request_raw(gateway.address, attack.as_bytes()).await;
        assert!(count_bytes(&response, b"HTTP/1.1") <= 1);
        let after = fixture.state.hits.load(Ordering::SeqCst);
        assert!(after <= before + 1, "ambiguous input dispatched twice");
    }
    assert!(fixture
        .state
        .observed
        .lock()
        .expect("framing observations")
        .iter()
        .all(|entry| entry.target == "/base/api"));

    for (wire, valid_body) in [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ninjected"
                .to_vec(),
            None,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcdeHTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ninjected"
                .to_vec(),
            None,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Late\r\n\r\n4\r\ntest\r\n0\r\nX-Late: hidden\r\n\r\n"
                .to_vec(),
            Some(b"test".as_slice()),
        ),
    ] {
        let raw = start_raw_response_fixture(wire).await;
        let raw_gateway = start_gateway(Some(raw.address), SessionMode::Allowed).await;
        let raw_cookie = raw_gateway.cookie.as_deref().expect("raw response cookie");
        let response = request_once(
            raw_gateway.address,
            &format!(
                "GET /raw HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={raw_cookie}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(count_bytes(&response, b"HTTP/1.1") <= 1);
        assert_eq!(raw.hits.load(Ordering::SeqCst), 1);
        if let Some(body) = valid_body {
            assert_status(&response, 200);
            assert_eq!(decoded_response_body(&response), body);
            let head = response_head(&response).to_ascii_lowercase();
            assert!(!head.contains("trailer:"));
            assert!(!head.contains("content-length:"));
        } else if !response.is_empty() {
            assert!(matches!(response_status(&response), 200 | 502));
            assert!(!decoded_response_body(&response)
                .windows(b"injected".len())
                .any(|window| window == b"injected"));
        }
        raw_gateway.task.abort();
        raw.task.abort();
    }

    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_pool_failure_does_not_replay_a_non_idempotent_request() {
    let stale = start_stale_pool_fixture().await;
    let gateway = start_gateway(Some(stale.address), SessionMode::Allowed).await;
    let cookie = gateway.cookie.as_deref().expect("stale cookie");
    let warm = request_once(
        gateway.address,
        &format!(
            "GET /warm HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&warm, 200);
    timeout(TokioDuration::from_secs(2), stale.warm_response.acquire())
        .await
        .expect("warm response observed")
        .expect("warm semaphore")
        .forget();
    tokio::time::sleep(TokioDuration::from_millis(25)).await;
    stale.close_connection.add_permits(1);
    tokio::time::sleep(TokioDuration::from_millis(25)).await;

    let post = request_once(
        gateway.address,
        &format!(
            "POST /write HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"
        ),
    )
    .await;
    assert_status(&post, 502);
    tokio::time::sleep(TokioDuration::from_millis(100)).await;
    assert_eq!(stale.connections.load(Ordering::SeqCst), 1);
    assert_eq!(stale.post_dispatches.load(Ordering::SeqCst), 0);

    gateway.task.abort();
    stale.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn underscore_aliases_and_trusted_forwarding_fail_closed_before_upstream() {
    let adapter = start_gateway(None, SessionMode::Missing).await;
    let adapter_fallback = request_once(
        adapter.address,
        "GET /adapter HTTP/1.1\r\nHost: public.example\r\nX_Identity_Alias: attacker\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&adapter_fallback, 404);

    let fixture = start_fixture().await;
    let anonymous = start_gateway(Some(fixture.address), SessionMode::Missing).await;
    let rejected = request_once(
        anonymous.address,
        "GET /alias HTTP/1.1\r\nHost: public.example\r\nX_Auth_Mini_User_Id: attacker\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&rejected, 400);
    assert_eq!(response_body(&rejected), b"Bad request");
    assert!(!response_head(&rejected)
        .to_ascii_lowercase()
        .contains("set-cookie:"));
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 0);
    let owned = request_once(
        anonymous.address,
        "GET /healthz HTTP/1.1\r\nHost: public.example\r\nX_Still_Owned: yes\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&owned, 204);

    let untrusted = start_gateway(Some(fixture.address), SessionMode::Allowed).await;
    let untrusted_cookie = untrusted.cookie.as_deref().expect("untrusted cookie");
    let ignored = request_once(
        untrusted.address,
        &format!(
            "GET /xff-untrusted HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={untrusted_cookie}\r\nX-Forwarded-For: attacker, malformed:443\r\nX-Forwarded-For: repeated\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&ignored, 200);
    {
        let observed = fixture.state.observed.lock().expect("untrusted observed");
        assert_eq!(
            observed
                .last()
                .expect("untrusted upstream request")
                .headers
                .get("x-forwarded-for")
                .expect("regenerated XFF"),
            "127.0.0.1"
        );
    }

    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("trusted upstream URL")
        .expect("trusted upstream");
    let trusted_connections_before = fixture.state.connections.load(Ordering::SeqCst);
    let trusted = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            trusted_proxy_cidrs: auth_mini_gateway::config::parse_trusted_proxy_cidrs(Some(
                "127.0.0.1/32",
            ))
            .expect("trusted CIDR"),
            ..GatewayOptions::default()
        },
    )
    .await;
    let trusted_cookie = trusted.cookie.as_deref().expect("trusted cookie");
    let accepted = request_once(
        trusted.address,
        &format!(
            "GET /xff-trusted HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={trusted_cookie}\r\nX-Forwarded-For: 2001:db8::42\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&accepted, 200);
    {
        let observed = fixture.state.observed.lock().expect("trusted observed");
        assert_eq!(
            observed
                .last()
                .expect("trusted upstream request")
                .headers
                .get("x-forwarded-for")
                .expect("trusted regenerated XFF"),
            "2001:db8::42"
        );
    }
    tokio::time::sleep(TokioDuration::from_millis(25)).await;
    let accepted_again = request_once(
        trusted.address,
        &format!(
            "GET /xff-trusted-again HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={trusted_cookie}\r\nX-Forwarded-For: 192.0.2.77\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&accepted_again, 200);
    {
        let observed = fixture
            .state
            .observed
            .lock()
            .expect("trusted observed again");
        let last = observed.last().expect("second trusted upstream request");
        assert_eq!(last.target, "/base/xff-trusted-again");
        assert_eq!(
            last.headers
                .get("x-forwarded-for")
                .expect("second canonical XFF"),
            "192.0.2.77"
        );
        assert_eq!(
            last.headers.get("host").expect("fixed external Host"),
            "public.example"
        );
    }
    assert_eq!(
        fixture.state.connections.load(Ordering::SeqCst),
        trusted_connections_before + 1,
        "changing trusted XFF must not change the pool key or destination"
    );

    let login_store = Store::new(trusted._dir.path().join("gateway.sqlite"));
    for xff in ["192.0.2.10", "2001:db8::10"] {
        let login = request_once(
            trusted.address,
            &format!(
                "GET /return-target?x=1 HTTP/1.1\r\nHost: public.example\r\nX-Forwarded-For: {xff}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert_status(&login, 302);
        let login_head = response_head(&login);
        let state_id = login_head
            .lines()
            .find_map(|line| {
                line.strip_prefix("set-cookie: amg_login_state=")
                    .or_else(|| line.strip_prefix("Set-Cookie: amg_login_state="))
            })
            .and_then(|value| value.split(';').next())
            .and_then(|signed| signed.split('.').next())
            .expect("login-state cookie");
        let state = login_store
            .consume_login_state(state_id)
            .expect("consume login state")
            .expect("stored login state");
        assert_eq!(state.return_to, "/return-target?x=1");
    }

    let before_malformed = fixture.state.hits.load(Ordering::SeqCst);
    for value in [
        "192.0.2.1,192.0.2.2",
        "192.0.2.1:443",
        "[2001:db8::1]",
        "fe80::1%eth0",
        "opaque",
    ] {
        let response = request_once(
            trusted.address,
            &format!(
                "GET /xff-invalid HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={trusted_cookie}\r\nX-Forwarded-For: {value}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert_status(&response, 400);
        assert!(!response_head(&response)
            .to_ascii_lowercase()
            .contains("set-cookie:"));
    }
    let repeated = request_once(
        trusted.address,
        &format!(
            "GET /xff-repeated HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={trusted_cookie}\r\nX-Forwarded-For: 192.0.2.1\r\nX-Forwarded-For: 192.0.2.2\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&repeated, 400);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), before_malformed);

    let mut opaque = format!(
        "GET /xff-opaque HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={trusted_cookie}\r\nX-Forwarded-For: "
    )
    .into_bytes();
    opaque.push(0xff);
    opaque.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    let opaque_response = request_raw(trusted.address, &opaque).await;
    // Hyper may reject obs-text before constructing a HeaderMap. If it does
    // deliver the legal typed value, the gateway's deterministic unit seam
    // pins the trusted-peer 400 behavior.
    if !opaque_response.is_empty() {
        assert_status(&opaque_response, 400);
    }
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), before_malformed);

    adapter.task.abort();
    anonymous.task.abort();
    untrusted.task.abort();
    trusted.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_capacity_is_exact_across_expect_sse_websocket_and_release() {
    let fixture = start_fixture().await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("capacity upstream URL")
        .expect("capacity upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_downstream_connections: 17,
            max_active_upstreams: 1,
            max_blocking_resolvers: 1,
            trusted_proxy_cidrs: TrustedProxySet::default(),
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("capacity cookie");
    let database = gateway._dir.path().join("gateway.sqlite");
    let due_session = Store::new(database.clone())
        .create_session(NewSession {
            auth_session_id: "due-renewal-auth-session".to_string(),
            access_token: "due-renewal-access".to_string(),
            refresh_token: "due-renewal-refresh".to_string(),
            user_id: "user-1".to_string(),
            email: Some("user@example.com".to_string()),
            amr: vec!["fixture".to_string()],
            access_expires_at: Utc::now() + Duration::hours(2),
            idle_ttl_seconds: 604_800,
            absolute_ttl_seconds: 2_592_000,
        })
        .expect("due-renewal session");
    let old_touch = (Utc::now() - Duration::hours(2)).to_rfc3339_opts(SecondsFormat::Millis, true);
    rusqlite::Connection::open(&database)
        .expect("due-renewal database")
        .execute(
            "UPDATE gateway_sessions SET last_touched_at = ?1 WHERE id = ?2",
            rusqlite::params![old_touch, due_session.id],
        )
        .expect("make renewal due");
    let due_cookie = sign_value(
        &due_session.id,
        "integration-cookie-secret-at-least-32-characters",
    );

    let mut sse = TcpStream::connect(gateway.address)
        .await
        .expect("SSE connect");
    sse.write_all(
        format!(
            "GET /events HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .expect("SSE request");
    let mut first = Vec::new();
    timeout(TokioDuration::from_secs(2), async {
        let mut byte = [0u8; 1];
        while !first.windows(11).any(|window| window == b"data: one\n\n") {
            sse.read_exact(&mut byte).await.expect("first SSE event");
            first.push(byte[0]);
        }
    })
    .await
    .expect("SSE holds active capacity");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    let mut saturated = TcpStream::connect(gateway.address)
        .await
        .expect("saturation connect");
    saturated
        .write_all(
            format!(
                "POST /expect-saturated HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={due_cookie}\r\nContent-Length: 19\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("saturation head");
    let mut capacity_response = Vec::new();
    timeout(
        TokioDuration::from_secs(2),
        saturated.read_to_end(&mut capacity_response),
    )
    .await
    .expect("immediate capacity response")
    .expect("capacity read");
    assert_status(&capacity_response, 503);
    assert!(!String::from_utf8_lossy(&capacity_response).contains("100 Continue"));
    assert_eq!(
        decoded_response_body(&capacity_response),
        b"Service temporarily unavailable"
    );
    let capacity_head = response_head(&capacity_response).to_ascii_lowercase();
    assert!(capacity_head.contains("retry-after: 5"));
    assert!(capacity_head.contains("content-length: 31"));
    assert!(capacity_head.contains("content-type: text/plain; charset=utf-8"));
    assert!(capacity_head.contains("cache-control: no-store"));
    assert!(capacity_head.contains("connection: close"));
    assert_eq!(capacity_head.matches("set-cookie:").count(), 1);
    assert!(capacity_head.contains("set-cookie: amg_session="));
    assert!(!capacity_head.contains("max-age=0"));
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    let health = request_once(
        gateway.address,
        "GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&health, 204);

    fixture.state.sse_release.add_permits(1);
    let mut sse_rest = Vec::new();
    sse.read_to_end(&mut sse_rest).await.expect("SSE release");
    let after_sse = eventually_non_capacity_request(
        gateway.address,
        &format!(
            "GET /after-sse HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&after_sse, 200);

    let mut websocket = TcpStream::connect(gateway.address)
        .await
        .expect("capacity websocket");
    websocket
        .write_all(
            format!(
                "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("capacity websocket head");
    assert!(read_head(&mut websocket).await.starts_with("HTTP/1.1 101"));
    let while_websocket = request_once(
        gateway.address,
        &format!(
            "GET /while-websocket HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&while_websocket, 503);
    assert_eq!(
        decoded_response_body(&while_websocket),
        b"Service temporarily unavailable"
    );
    websocket.write_all(b"ping").await.expect("websocket ping");
    let mut pong = [0u8; 4];
    websocket
        .read_exact(&mut pong)
        .await
        .expect("websocket pong");
    assert_eq!(&pong, b"pong");
    websocket.shutdown().await.expect("websocket shutdown");
    let mut eof = [0u8; 1];
    assert_eq!(
        timeout(TokioDuration::from_secs(2), websocket.read(&mut eof))
            .await
            .expect("websocket EOF")
            .expect("websocket read"),
        0
    );
    let after_websocket = eventually_non_capacity_request(
        gateway.address,
        &format!(
            "GET /after-websocket HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&after_websocket, 200);

    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downstream_admission_is_pre_accept_and_websocket_lease_survives_upgrade() {
    let adapter = start_gateway_with_options(
        None,
        SessionMode::Missing,
        None,
        GatewayOptions {
            max_downstream_connections: 1,
            ..GatewayOptions::default()
        },
    )
    .await;
    let mut first = TcpStream::connect(adapter.address)
        .await
        .expect("first downstream");
    first
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: public.example\r\n\r\n")
        .await
        .expect("first health");
    assert!(read_head(&mut first).await.starts_with("HTTP/1.1 204"));
    let mut second = TcpStream::connect(adapter.address)
        .await
        .expect("backlogged downstream");
    second
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
        .await
        .expect("backlogged health");
    assert!(
        timeout(TokioDuration::from_millis(150), read_head(&mut second))
            .await
            .is_err()
    );
    drop(first);
    assert!(timeout(TokioDuration::from_secs(2), read_head(&mut second))
        .await
        .expect("slot released after first connection")
        .starts_with("HTTP/1.1 204"));

    let fixture = start_fixture().await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("lease upstream URL")
        .expect("lease upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_downstream_connections: 17,
            max_active_upstreams: 1,
            max_blocking_resolvers: 1,
            trusted_proxy_cidrs: TrustedProxySet::default(),
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("lease cookie");
    let mut holders = Vec::new();
    for _ in 0..16 {
        let mut stream = TcpStream::connect(gateway.address)
            .await
            .expect("downstream holder");
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: public.example\r\n\r\n")
            .await
            .expect("holder request");
        assert!(read_head(&mut stream).await.starts_with("HTTP/1.1 204"));
        holders.push(stream);
    }

    let mut sse = TcpStream::connect(gateway.address)
        .await
        .expect("lease SSE");
    sse.write_all(
        format!(
            "GET /events HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .expect("lease SSE request");
    let mut first_event = Vec::new();
    timeout(TokioDuration::from_secs(2), async {
        let mut byte = [0u8; 1];
        while !first_event
            .windows(11)
            .any(|window| window == b"data: one\n\n")
        {
            sse.read_exact(&mut byte)
                .await
                .expect("lease SSE first event");
            first_event.push(byte[0]);
        }
    })
    .await
    .expect("lease SSE streamed");
    let mut blocked_by_sse = TcpStream::connect(gateway.address)
        .await
        .expect("SSE-blocked eighteenth connection");
    blocked_by_sse
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
        .await
        .expect("SSE-blocked health request");
    assert!(timeout(
        TokioDuration::from_millis(150),
        read_head(&mut blocked_by_sse)
    )
    .await
    .is_err());
    fixture.state.sse_release.add_permits(1);
    let mut sse_rest = Vec::new();
    sse.read_to_end(&mut sse_rest).await.expect("lease SSE EOF");
    assert!(
        timeout(TokioDuration::from_secs(2), read_head(&mut blocked_by_sse))
            .await
            .expect("SSE downstream lease released")
            .starts_with("HTTP/1.1 204")
    );
    let after_sse = eventually_non_capacity_request(
        gateway.address,
        &format!(
            "GET /after-downstream-sse HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&after_sse, 200);

    let mut upload = TcpStream::connect(gateway.address)
        .await
        .expect("lease streaming upload");
    upload
        .write_all(
            format!(
                "POST /upload HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("lease upload first chunk");
    timeout(
        TokioDuration::from_secs(2),
        fixture.state.upload_first_seen.acquire(),
    )
    .await
    .expect("upstream saw lease upload")
    .expect("upload marker")
    .forget();
    let mut blocked_by_upload = TcpStream::connect(gateway.address)
        .await
        .expect("upload-blocked eighteenth connection");
    blocked_by_upload
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
        .await
        .expect("upload-blocked health request");
    assert!(timeout(
        TokioDuration::from_millis(150),
        read_head(&mut blocked_by_upload)
    )
    .await
    .is_err());
    drop(upload);
    assert!(timeout(
        TokioDuration::from_secs(2),
        read_head(&mut blocked_by_upload)
    )
    .await
    .expect("upload cancellation released downstream lease")
    .starts_with("HTTP/1.1 204"));
    fixture.state.upload_release.add_permits(1);
    let after_upload = eventually_non_capacity_request(
        gateway.address,
        &format!(
            "GET /after-downstream-upload HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&after_upload, 200);

    let mut websocket = TcpStream::connect(gateway.address)
        .await
        .expect("lease websocket");
    websocket
        .write_all(
            format!(
                "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("lease websocket request");
    assert!(read_head(&mut websocket).await.starts_with("HTTP/1.1 101"));

    let mut blocked = TcpStream::connect(gateway.address)
        .await
        .expect("blocked eighteenth connection");
    blocked
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
        .await
        .expect("blocked health request");
    assert!(
        timeout(TokioDuration::from_millis(150), read_head(&mut blocked))
            .await
            .is_err()
    );
    websocket.write_all(b"ping").await.expect("lease ping");
    let mut pong = [0u8; 4];
    websocket.read_exact(&mut pong).await.expect("lease pong");
    websocket.shutdown().await.expect("lease websocket close");
    let mut eof = [0u8; 1];
    let _ = timeout(TokioDuration::from_secs(2), websocket.read(&mut eof))
        .await
        .expect("lease websocket EOF");
    assert!(
        timeout(TokioDuration::from_secs(2), read_head(&mut blocked))
            .await
            .expect("bridge lease released")
            .starts_with("HTTP/1.1 204")
    );

    drop(holders);
    adapter.task.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[test]
fn startup_failures_emit_one_sanitized_process_exit_without_raw_values() {
    const RAW_MARKER: &str = "resolver-limit-raw-marker-must-not-appear";
    let output = Command::new(env!("CARGO_BIN_EXE_auth-mini-gateway"))
        .env(
            "GATEWAY_COOKIE_SECRET",
            "startup-test-secret-at-least-32-characters",
        )
        .env("GATEWAY_MAX_BLOCKING_RESOLVERS", RAW_MARKER)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .expect("run invalid startup");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("structured stderr");
    assert_eq!(stderr.matches("process_exit").count(), 1, "{stderr}");
    assert!(stderr.contains("blocking_resolver_limit_invalid"));
    assert!(!stderr.contains(RAW_MARKER));
    assert!(!stderr.contains("invalid digit"));
}

#[test]
fn process_wide_panic_hook_never_prints_payload_or_location() {
    const PAYLOAD: &str = "panic-payload-session-token-marker";
    let output = Command::new(env!("CARGO_BIN_EXE_auth-mini-gateway"))
        .env("AMG_TEST_PANIC_ON_START", PAYLOAD)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .expect("run panic-hook probe");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("sanitized panic stderr");
    assert_eq!(stderr, "event=process_panic class=runtime_panic\n");
    for forbidden in [PAYLOAD, "panicked at", "src/", "main.rs", "thread '"] {
        assert!(
            !stderr.contains(forbidden),
            "raw panic data leaked: {stderr}"
        );
    }
}

#[test]
fn caught_panic_process_stderr_is_allowlisted_for_both_handler_phases() {
    for payload in [
        "post-unauth-login-session-token-marker",
        "pre-decision-session-token-marker",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_auth-mini-gateway"))
            .env("AMG_TEST_CAUGHT_PANIC", payload)
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .expect("run caught-panic probe");
        assert!(output.status.success());
        let stderr = String::from_utf8(output.stderr).expect("caught panic stderr");
        assert_eq!(stderr, "event=process_panic class=runtime_panic\n");
        for forbidden in [payload, "panicked at", "src/", "thread '", "session-token"] {
            assert!(
                !stderr.contains(forbidden),
                "raw caught panic leaked: {stderr}"
            );
        }
    }
}

#[test]
fn panic_hook_bypasses_stderr_lock_and_stderr_writer_reentrancy() {
    for (environment, marker) in [
        (
            "AMG_TEST_PANIC_WHILE_STDERR_LOCKED",
            "stderr-lock-panic-payload-marker",
        ),
        (
            "AMG_TEST_PANIC_FROM_STDERR_WRITE",
            "stderr-writing-panic-payload-marker",
        ),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_auth-mini-gateway"))
            .env(environment, marker)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn panic lock probe");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll panic lock probe") {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().expect("kill wedged panic lock probe");
                let _ = child.wait();
                panic!("panic hook blocked for mode {environment}");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(status.success());
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .expect("panic lock stderr")
            .read_to_string(&mut stderr)
            .expect("read panic lock stderr");
        assert_eq!(stderr, "event=process_panic class=runtime_panic\n");
        for forbidden in [marker, "panicked at", "src/", "thread '"] {
            assert!(
                !stderr.contains(forbidden),
                "raw panic data leaked: {stderr}"
            );
        }
    }
}

#[test]
fn listener_fatal_process_boundary_is_single_sanitized_nonzero_event() {
    const RAW_MARKER: &str = "raw-listener-os-source-marker";
    let output = Command::new(env!("CARGO_BIN_EXE_auth-mini-gateway"))
        .env("AMG_TEST_LISTENER_FATAL", RAW_MARKER)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .expect("run listener-fatal probe");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("listener fatal stderr");
    assert_eq!(stderr.matches("process_exit").count(), 1, "{stderr}");
    assert!(stderr.contains("listener_fatal"));
    assert!(stderr.contains("bad_fd"));
    assert!(stderr.contains("37"));
    assert!(stderr.contains("5"));
    for forbidden in [RAW_MARKER, "Bad file descriptor", "panicked at", "src/"] {
        assert!(
            !stderr.contains(forbidden),
            "raw fatal data leaked: {stderr}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fatal_accept_exits_without_waiting_for_started_libc_resolver() {
    const COOKIE_SECRET: &str = "terminal-cookie-secret-at-least-32-characters";
    const RAW_ERRNO_MARKER: &str = "raw-fatal-accept-errno-marker";
    const RAW_DOMAIN_MARKER: &str = "unfinishable-resolver-marker.invalid";
    const RELEASE_MARKER: &str = "raw-unfinishable-resolver-release-marker";

    let dir = tempfile::tempdir().expect("terminal process tempdir");
    let database = dir.path().join("gateway.sqlite");
    Store::initialize(&database).expect("terminal process store");
    let session = Store::new(database.clone())
        .create_session(NewSession {
            auth_session_id: "terminal-auth-session".to_string(),
            access_token: "terminal-access-token".to_string(),
            refresh_token: "terminal-refresh-token".to_string(),
            user_id: "user-1".to_string(),
            email: Some("user@example.com".to_string()),
            amr: vec!["fixture".to_string()],
            access_expires_at: Utc::now() + Duration::hours(2),
            idle_ttl_seconds: 604_800,
            absolute_ttl_seconds: 2_592_000,
        })
        .expect("terminal process session");
    let cookie = sign_value(&session.id, COOKIE_SECRET);
    let address = unused_address().await;
    let mut child = Command::new(env!("CARGO_BIN_EXE_auth-mini-gateway"))
        .env("HOST", address.ip().to_string())
        .env("PORT", address.port().to_string())
        .env("GATEWAY_PUBLIC_BASE_URL", "http://public.example")
        .env("AUTH_MINI_ISSUER", "http://127.0.0.1:9")
        .env("AUTH_MINI_PUBLIC_BASE_URL", "http://127.0.0.1:9")
        .env("GATEWAY_DB", &database)
        .env("GATEWAY_COOKIE_SECRET", COOKIE_SECRET)
        .env("COOKIE_SECURE", "false")
        .env("ALLOW_USER_IDS", "user-1")
        .env("UPSTREAM_URL", format!("http://{RAW_DOMAIN_MARKER}:9/base"))
        .env("GATEWAY_MAX_DOWNSTREAM_CONNECTIONS", "18")
        .env("GATEWAY_MAX_ACTIVE_UPSTREAMS", "2")
        .env("GATEWAY_MAX_BLOCKING_RESOLVERS", "1")
        .env(
            "AMG_TEST_FATAL_ACCEPT_WITH_UNFINISHABLE_RESOLVER",
            RAW_ERRNO_MARKER,
        )
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn terminal process");

    let mut stream = timeout(TokioDuration::from_secs(5), async {
        loop {
            match TcpStream::connect(address).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(TokioDuration::from_millis(10)).await,
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        let _ = child.kill();
        let _ = child.wait();
        panic!("terminal process did not listen")
    });
    stream
        .write_all(
            format!(
                "GET /terminal HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("start unfinishable resolver");

    let status = match timeout(TokioDuration::from_secs(5), async {
        loop {
            if let Some(status) = child.try_wait().expect("poll terminal process") {
                break status;
            }
            tokio::time::sleep(TokioDuration::from_millis(10)).await;
        }
    })
    .await
    {
        Ok(status) => status,
        Err(_) => {
            child.kill().expect("kill wedged terminal process");
            let _ = child.wait();
            panic!("runtime drop waited for unfinishable resolver");
        }
    };
    assert!(!status.success());
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("terminal stderr")
        .read_to_string(&mut stderr)
        .expect("read terminal stderr");
    assert_eq!(stderr.matches("process_exit").count(), 1, "{stderr}");
    assert!(stderr.contains("listener_fatal"), "{stderr}");
    for forbidden in [
        RAW_ERRNO_MARKER,
        RAW_DOMAIN_MARKER,
        RELEASE_MARKER,
        "Bad file descriptor",
        "terminal-access-token",
        "terminal-refresh-token",
        cookie.as_str(),
    ] {
        assert!(
            !stderr.contains(forbidden),
            "terminal data leaked: {stderr}"
        );
    }
}

#[test]
fn production_artifacts_pin_proxy_frp_limits_and_safe_rollback() {
    let nginx = include_str!("../examples/nginx-proxy.conf");
    for required in [
        "listen 443 ssl;",
        "proxy_pass http://127.0.0.1:18081;",
        "underscores_in_headers on;",
        "ignore_invalid_headers on;",
        "proxy_set_header Cookie $http_cookie;",
        "proxy_pass_header Set-Cookie;",
        "proxy_set_header Host $host;",
        "proxy_set_header X-Forwarded-Proto https;",
        "proxy_set_header X-Forwarded-For $remote_addr;",
        "proxy_set_header Upgrade $http_upgrade;",
        "proxy_request_buffering off;",
        "proxy_buffering off;",
        "proxy_next_upstream off;",
    ] {
        assert!(
            nginx.contains(required),
            "missing nginx control: {required}"
        );
    }
    for forbidden in [
        "auth_request",
        "$proxy_add_x_forwarded_for",
        "proxy_set_header Cookie \"\"",
    ] {
        assert!(
            !nginx.contains(forbidden),
            "forbidden nginx control: {forbidden}"
        );
    }

    let rollback = include_str!("../examples/nginx-proxy-rollback.conf");
    assert!(rollback.contains("underscores_in_headers off;"));
    assert!(rollback.contains("ignore_invalid_headers on;"));
    let frps = include_str!("../examples/frps.toml");
    assert!(frps.contains("proxyBindAddr = \"127.0.0.1\""));
    assert!(frps.contains("allowPorts = [{ single = 18081 }]"));
    assert!(frps.contains("auth.tokenSource.type = \"file\""));
    assert!(frps.contains("transport.tls.force = true"));
    let frpc = include_str!("../examples/frpc.toml");
    for required in [
        "transport.tls.serverName = \"frp.example.com\"",
        "localIP = \"127.0.0.1\"",
        "localPort = 7780",
        "remotePort = 18081",
    ] {
        assert!(frpc.contains(required), "missing frpc control: {required}");
    }
    let service = include_str!("../examples/auth-mini-gateway.service");
    assert!(service.contains("LimitNOFILE=4096"));
    let environment = include_str!("../.env.example");
    for required in [
        "GATEWAY_MAX_DOWNSTREAM_CONNECTIONS=256",
        "GATEWAY_MAX_ACTIVE_UPSTREAMS=128",
        "GATEWAY_MAX_BLOCKING_RESOLVERS=8",
        "TRUSTED_PROXY_CIDRS=",
    ] {
        assert!(environment.contains(required));
    }
    let deployment = include_str!("../docs/production-deployment.md");
    for required in [
        "Acorn loopback 127.0.0.1:18081",
        "Axiom frpc local target 127.0.0.1:7780",
        "OpenCode 127.0.0.1:4096",
        "frp v0.64.0 or newer",
        "underscores_in_headers off;",
        "X_Auth_Mini_User_Id: attacker",
        "systemctl show auth-mini-gateway -p LimitNOFILE -p TasksMax -p MemoryMax",
    ] {
        assert!(
            deployment.contains(required),
            "missing deployment instruction: {required}"
        );
    }
}

#[test]
fn rustls_identity_matrix_accepts_ipv4_ipv6_ip_sans_and_rejects_dns_only_for_ip() {
    for address in ["127.0.0.1", "2001:db8::1"] {
        let ip = address.parse::<std::net::IpAddr>().expect("IP identity");
        let server_name = rustls::pki_types::ServerName::IpAddress(ip.into());
        assert!(
            in_memory_tls_identity(address, server_name).is_ok(),
            "matching IP SAN must validate: {address}"
        );
    }
    let ip = "2001:db8::1"
        .parse::<std::net::IpAddr>()
        .expect("IPv6 identity");
    assert!(
        in_memory_tls_identity(
            "localhost",
            rustls::pki_types::ServerName::IpAddress(ip.into())
        )
        .is_err(),
        "a DNS-only certificate must not validate for an IP authority"
    );
}

fn in_memory_tls_identity(
    certificate_name: &str,
    server_name: rustls::pki_types::ServerName<'static>,
) -> Result<(), String> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![certificate_name.to_string()])
            .map_err(|_| "certificate generation failed".to_string())?;
    let certificate = cert.der().clone();
    let private_key = PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key)
        .map_err(|_| "server config failed".to_string())?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certificate)
        .map_err(|_| "root add failed".to_string())?;
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client = rustls::ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|_| "client config failed".to_string())?;
    let mut server = rustls::ServerConnection::new(Arc::new(server_config))
        .map_err(|_| "server connection failed".to_string())?;

    for _ in 0..16 {
        let mut progressed = false;
        if client.wants_write() {
            let mut wire = Vec::new();
            client
                .write_tls(&mut wire)
                .map_err(|_| "client write failed".to_string())?;
            if !wire.is_empty() {
                progressed = true;
                server
                    .read_tls(&mut wire.as_slice())
                    .map_err(|_| "server read failed".to_string())?;
                server
                    .process_new_packets()
                    .map_err(|_| "server TLS validation failed".to_string())?;
            }
        }
        if server.wants_write() {
            let mut wire = Vec::new();
            server
                .write_tls(&mut wire)
                .map_err(|_| "server write failed".to_string())?;
            if !wire.is_empty() {
                progressed = true;
                client
                    .read_tls(&mut wire.as_slice())
                    .map_err(|_| "client read failed".to_string())?;
                client
                    .process_new_packets()
                    .map_err(|_| "client TLS validation failed".to_string())?;
            }
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
        if !progressed {
            break;
        }
    }
    Err("TLS handshake did not complete".to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_logs_never_contain_cookie_token_or_secret_values() {
    const COOKIE_SECRET: &str = "log-cookie-secret-never-emit-at-least-32";
    const AUTH_SESSION_ID: &str = "log-auth-session-never-emit";
    const ACCESS_TOKEN: &str = "log-fixture-access-token-never-emit";
    const REFRESH_TOKEN: &str = "log-fixture-refresh-token-never-emit";
    const CALLBACK_SESSION_ID: &str = "log-callback-session-never-emit";
    const CALLBACK_ACCESS_TOKEN: &str = "log-callback-access-token-never-emit";
    const CALLBACK_REFRESH_TOKEN: &str = "log-callback-refresh-token-never-emit";
    const XFF_MARKER: &str = "198.51.100.199";
    const HEADER_MARKER: &str = "raw-forwarding-header-marker-never-emit";
    const CIDR_MARKER: &str = "203.0.113.77/32";

    let dir = tempfile::tempdir().expect("log tempdir");
    let database = dir.path().join("gateway.sqlite");
    Store::initialize(&database).expect("log store");
    let store = Store::new(database.clone());
    let session = store
        .create_session(NewSession {
            auth_session_id: AUTH_SESSION_ID.to_string(),
            access_token: ACCESS_TOKEN.to_string(),
            refresh_token: REFRESH_TOKEN.to_string(),
            user_id: "log-user".to_string(),
            email: Some("log-user@example.com".to_string()),
            amr: vec!["test".to_string()],
            access_expires_at: Utc::now() + Duration::hours(2),
            idle_ttl_seconds: 604_800,
            absolute_ttl_seconds: 2_592_000,
        })
        .expect("log session");
    let signed_cookie = sign_value(&session.id, COOKIE_SECRET);
    let address = unused_address().await;
    let unavailable_upstream = unused_address().await;
    let mut child = Command::new(env!("CARGO_BIN_EXE_auth-mini-gateway"))
        .env("HOST", "127.0.0.1")
        .env("PORT", address.port().to_string())
        .env(
            "GATEWAY_PUBLIC_BASE_URL",
            format!("http://127.0.0.1:{}", address.port()),
        )
        .env("AUTH_MINI_ISSUER", "http://127.0.0.1:9")
        .env("GATEWAY_DB", &database)
        .env("GATEWAY_COOKIE_SECRET", COOKIE_SECRET)
        .env("COOKIE_SECURE", "false")
        .env("ALLOW_USER_IDS", "log-user")
        .env("UPSTREAM_URL", format!("http://{unavailable_upstream}"))
        .env("TRUSTED_PROXY_CIDRS", format!("127.0.0.1/32,{CIDR_MARKER}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gateway for log capture");
    wait_for_gateway(address).await;

    let check = request_once(
        address,
        &format!(
            "GET /auth/check HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={signed_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&check, 204);
    let proxy_failure = request_once(
        address,
        &format!(
            "GET /log-forwarding HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={signed_cookie}\r\nX-Forwarded-For: {XFF_MARKER}\r\nX-Log-Marker: {HEADER_MARKER}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&proxy_failure, 502);
    let callback_body = format!(
        r#"{{"access_token":"{CALLBACK_ACCESS_TOKEN}","refresh_token":"{CALLBACK_REFRESH_TOKEN}","session_id":"{CALLBACK_SESSION_ID}","token_type":"Bearer","state":"missing-state"}}"#
    );
    let callback = request_once(
        address,
        &format!(
            "POST /auth/callback/session HTTP/1.1\r\nHost: public.example\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{callback_body}",
            callback_body.len()
        ),
    )
    .await;
    assert_status(&callback, 400);
    let logout = request_once(
        address,
        &format!(
            "POST /logout HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={signed_cookie}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&logout, 302);

    child.kill().expect("stop log gateway");
    let output = child.wait_with_output().expect("captured gateway output");
    let mut logs = output.stdout;
    logs.extend_from_slice(&output.stderr);
    let logs = String::from_utf8_lossy(&logs);
    for secret in [
        COOKIE_SECRET,
        AUTH_SESSION_ID,
        ACCESS_TOKEN,
        REFRESH_TOKEN,
        CALLBACK_SESSION_ID,
        CALLBACK_ACCESS_TOKEN,
        CALLBACK_REFRESH_TOKEN,
        XFF_MARKER,
        HEADER_MARKER,
        CIDR_MARKER,
        signed_cookie.as_str(),
    ] {
        assert!(!logs.contains(secret), "secret appeared in gateway logs");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adapter_proxy_adapter_mode_switch_reuses_state_without_exposing_the_app() {
    let fixture = start_fixture().await;
    let deny = start_deny_fixture().await;
    let dir = tempfile::tempdir().expect("mode switch tempdir");
    let database = dir.path().join("gateway.sqlite");
    Store::initialize(&database).expect("mode switch store");
    let secret = "mode-switch-cookie-secret-at-least-32";
    let session = Store::new(database.clone())
        .create_session(NewSession {
            auth_session_id: "mode-auth-session".to_string(),
            access_token: "mode-access".to_string(),
            refresh_token: "mode-refresh".to_string(),
            user_id: "user-1".to_string(),
            email: Some("user@example.com".to_string()),
            amr: vec!["test".to_string()],
            access_expires_at: Utc::now() + Duration::hours(2),
            idle_ttl_seconds: 604_800,
            absolute_ttl_seconds: 2_592_000,
        })
        .expect("mode session");
    let cookie = sign_value(&session.id, secret);

    let adapter_address = unused_address().await;
    let mut adapter = spawn_gateway_binary(adapter_address, &database, secret, None);
    wait_for_gateway(adapter_address).await;
    let adapter_response = request_once(
        adapter_address,
        &format!(
            "GET /app HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&adapter_response, 404);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 0);
    let mut public_target = deny.address;
    let maintenance = request_once(
        public_target,
        "GET /app HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&maintenance, 503);
    stop_gateway_binary(&mut adapter);

    let proxy_address = unused_address().await;
    let mut proxy = spawn_gateway_binary(
        proxy_address,
        &database,
        secret,
        Some(format!("http://{}/base", fixture.address)),
    );
    wait_for_gateway(proxy_address).await;
    let still_denied = request_once(
        public_target,
        "GET /app HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&still_denied, 503);
    public_target = proxy_address;
    let proxy_response = request_once(
        public_target,
        &format!(
            "GET /app HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&proxy_response, 200);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    let mut websocket = TcpStream::connect(proxy_address)
        .await
        .expect("mode switch websocket");
    websocket
        .write_all(
            format!(
                "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("mode switch websocket head");
    assert!(read_head(&mut websocket).await.starts_with("HTTP/1.1 101"));
    public_target = deny.address;
    let rollback_maintenance = request_once(
        public_target,
        "GET /app HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&rollback_maintenance, 503);
    stop_gateway_binary(&mut proxy);
    let mut closed = [0u8; 1];
    match timeout(TokioDuration::from_secs(2), websocket.read(&mut closed)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("proxy process exit did not close upgraded connection: {other:?}"),
    }

    let rollback_address = unused_address().await;
    let mut rollback = spawn_gateway_binary(rollback_address, &database, secret, None);
    wait_for_gateway(rollback_address).await;
    public_target = rollback_address;
    let rollback_response = request_once(
        public_target,
        &format!(
            "GET /app HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&rollback_response, 404);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 2);

    stop_gateway_binary(&mut rollback);
    deny.task.abort();
    fixture.task.abort();
}

#[derive(Clone, Copy)]
enum SessionMode {
    Missing,
    Forbidden,
    Allowed,
    NonAsciiAllowed,
}

async fn start_gateway(upstream: Option<SocketAddr>, mode: SessionMode) -> RunningGateway {
    start_gateway_with_upstream(
        upstream.map(|address| {
            parse_upstream_url(Some(&format!("http://{address}/base")))
                .expect("valid fixture upstream")
                .expect("configured fixture upstream")
        }),
        mode,
        None,
    )
    .await
}

async fn start_gateway_with_upstream(
    upstream: Option<UpstreamBase>,
    mode: SessionMode,
    roots: Option<rustls::RootCertStore>,
) -> RunningGateway {
    start_gateway_with_options(upstream, mode, roots, GatewayOptions::default()).await
}

async fn start_gateway_with_options(
    upstream: Option<UpstreamBase>,
    mode: SessionMode,
    roots: Option<rustls::RootCertStore>,
    options: GatewayOptions,
) -> RunningGateway {
    let dir = tempfile::tempdir().expect("tempdir");
    let database_path = dir.path().join("gateway.sqlite");
    Store::initialize(&database_path).expect("initialize store");
    let mut allow_user_ids = HashSet::new();
    let (user_id, email) = if matches!(mode, SessionMode::NonAsciiAllowed) {
        ("用户-一", "测试@example.com")
    } else {
        ("user-1", "user@example.com")
    };
    if matches!(mode, SessionMode::Allowed | SessionMode::NonAsciiAllowed) {
        allow_user_ids.insert(user_id.to_string());
    }
    let config = Config {
        host: "127.0.0.1".to_string(),
        port: 0,
        public_base_url: "https://public.example".to_string(),
        auth_mini_issuer: "http://127.0.0.1:7777".to_string(),
        auth_mini_public_base_url: "http://localhost:7777".to_string(),
        auth_mini_login_url: None,
        database_path: database_path.clone(),
        cookie_secret: "integration-cookie-secret-at-least-32-characters".to_string(),
        cookie_secure: true,
        cookie_same_site: SameSite::Lax,
        session_ttl_seconds: 604_800,
        session_absolute_ttl_seconds: 2_592_000,
        session_touch_interval_seconds: 3_600,
        login_state_ttl_seconds: 600,
        refresh_skew_seconds: 60,
        allow_emails: HashSet::new(),
        allow_user_ids,
        logout_redirect: "/".to_string(),
        upstream,
        max_downstream_connections: options.max_downstream_connections,
        max_active_upstreams: options.max_active_upstreams,
        max_blocking_resolvers: options.max_blocking_resolvers,
        trusted_proxy_cidrs: options.trusted_proxy_cidrs,
    };
    let cookie = if matches!(mode, SessionMode::Missing) {
        None
    } else {
        let store = Store::new(database_path);
        let session = store
            .create_session(NewSession {
                auth_session_id: "auth-session".to_string(),
                access_token: "server-side-access".to_string(),
                refresh_token: "server-side-refresh".to_string(),
                user_id: user_id.to_string(),
                email: Some(email.to_string()),
                amr: vec!["test".to_string()],
                access_expires_at: Utc::now() + Duration::hours(2),
                idle_ttl_seconds: config.session_ttl_seconds,
                absolute_ttl_seconds: config.session_absolute_ttl_seconds,
            })
            .expect("create session");
        Some(sign_value(&session.id, &config.cookie_secret))
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("gateway bind");
    let address = listener.local_addr().expect("gateway address");
    let task = tokio::spawn(async move {
        if let Some(roots) = roots {
            let _ = run_server_with_listener_and_roots(
                config,
                Arc::new(NoopAuth),
                listener,
                Some(roots),
            )
            .await;
        } else {
            let _ = run_server_with_listener(config, Arc::new(NoopAuth), listener).await;
        }
    });
    RunningGateway {
        address,
        _dir: dir,
        cookie,
        task,
    }
}

async fn start_fixture() -> RunningFixture {
    let state = Arc::new(FixtureState::default());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fixture bind");
    let address = listener.local_addr().expect("fixture address");
    let task_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            task_state.connections.fetch_add(1, Ordering::SeqCst);
            let state = Arc::clone(&task_state);
            tokio::spawn(async move {
                let service =
                    service_fn(move |request| fixture_response(request, Arc::clone(&state)));
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    RunningFixture {
        address,
        state,
        task,
    }
}

async fn start_deny_fixture() -> RunningDenyFixture {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("deny fixture bind");
    let address = listener.local_addr().expect("deny fixture address");
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|_request: Request<Incoming>| async {
                    let mut response = Response::new(full_body("Maintenance"));
                    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                    Ok::<_, Infallible>(response)
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    RunningDenyFixture { address, task }
}

fn spawn_gateway_binary(
    address: SocketAddr,
    database: &std::path::Path,
    cookie_secret: &str,
    upstream: Option<String>,
) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_auth-mini-gateway"));
    command
        .env("HOST", address.ip().to_string())
        .env("PORT", address.port().to_string())
        .env("GATEWAY_PUBLIC_BASE_URL", "https://public.example")
        .env("AUTH_MINI_ISSUER", "http://127.0.0.1:9")
        .env("AUTH_MINI_PUBLIC_BASE_URL", "http://127.0.0.1:9")
        .env("GATEWAY_DB", database)
        .env("GATEWAY_COOKIE_SECRET", cookie_secret)
        .env("COOKIE_SECURE", "false")
        .env("ALLOW_USER_IDS", "user-1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(upstream) = upstream {
        command.env("UPSTREAM_URL", upstream);
    } else {
        command.env_remove("UPSTREAM_URL");
    }
    command.spawn().expect("spawn gateway binary")
}

fn stop_gateway_binary(child: &mut Child) {
    child.kill().expect("kill gateway binary");
    let status = child.wait().expect("wait gateway binary");
    assert!(
        !status.success(),
        "killed gateway unexpectedly exited cleanly"
    );
}

async fn start_tls_fixture() -> RunningTlsFixture {
    start_tls_fixture_with_san("localhost").await
}

async fn start_tls_fixture_with_san(subject_alt_name: &str) -> RunningTlsFixture {
    start_tls_fixture_with_san_on(subject_alt_name, "127.0.0.1:0").await
}

async fn start_tls_fixture_with_san_on(
    subject_alt_name: &str,
    bind_address: &str,
) -> RunningTlsFixture {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![subject_alt_name.to_string()]).expect("test certificate");
    let certificate = cert.der().clone();
    let private_key = PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into();
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key)
        .expect("TLS server config");
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let state = Arc::new(FixtureState::default());
    let listener = TcpListener::bind(bind_address)
        .await
        .expect("TLS fixture bind");
    let address = listener.local_addr().expect("TLS fixture address");
    let task_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let state = Arc::clone(&task_state);
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                state.connections.fetch_add(1, Ordering::SeqCst);
                let service =
                    service_fn(move |request| fixture_response(request, Arc::clone(&state)));
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    RunningTlsFixture {
        address,
        certificate,
        state,
        task,
    }
}

async fn start_raw_response_fixture(response: Vec<u8>) -> RunningRawFixture {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("raw response bind");
    let address = listener.local_addr().expect("raw response address");
    let hits = Arc::new(AtomicUsize::new(0));
    let task_hits = Arc::clone(&hits);
    let task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let _ = read_request_head(&mut stream).await;
            task_hits.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        }
    });
    RunningRawFixture {
        address,
        hits,
        task,
    }
}

async fn start_stale_pool_fixture() -> RunningStaleFixture {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("stale fixture bind");
    let address = listener.local_addr().expect("stale fixture address");
    let connections = Arc::new(AtomicUsize::new(0));
    let post_dispatches = Arc::new(AtomicUsize::new(0));
    let warm_response = Arc::new(Semaphore::new(0));
    let close_connection = Arc::new(Semaphore::new(0));
    let task_connections = Arc::clone(&connections);
    let task_posts = Arc::clone(&post_dispatches);
    let task_warm = Arc::clone(&warm_response);
    let task_close = Arc::clone(&close_connection);
    let task = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        task_connections.fetch_add(1, Ordering::SeqCst);
        let first = read_request_head(&mut stream).await.unwrap_or_default();
        if first.starts_with("POST ") {
            task_posts.fetch_add(1, Ordering::SeqCst);
        }
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await;
        task_warm.add_permits(1);
        if let Ok(permit) = task_close.acquire().await {
            permit.forget();
        }
        drop(stream);

        if let Ok(Ok((mut replay, _))) =
            timeout(TokioDuration::from_millis(500), listener.accept()).await
        {
            task_connections.fetch_add(1, Ordering::SeqCst);
            let head = read_request_head(&mut replay).await.unwrap_or_default();
            if head.starts_with("POST ") {
                task_posts.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    RunningStaleFixture {
        address,
        connections,
        post_dispatches,
        warm_response,
        close_connection,
        task,
    }
}

async fn start_early_final_fixture() -> RunningEarlyFinalFixture {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("early-final fixture bind");
    let address = listener.local_addr().expect("early-final fixture address");
    let connections = Arc::new(AtomicUsize::new(0));
    let forwarded_later_bytes = Arc::new(AtomicUsize::new(0));
    let reused_early_connection = Arc::new(AtomicUsize::new(0));
    let task_connections = Arc::clone(&connections);
    let task_later = Arc::clone(&forwarded_later_bytes);
    let task_reused = Arc::clone(&reused_early_connection);
    let task = tokio::spawn(async move {
        let Ok((mut first, _)) = listener.accept().await else {
            return;
        };
        task_connections.fetch_add(1, Ordering::SeqCst);
        let head = read_request_head(&mut first).await.unwrap_or_default();
        if !head.starts_with("POST /base/early ") {
            return;
        }
        let chunk = read_one_chunk(&mut first).await.unwrap_or_default();
        if chunk != b"first" {
            return;
        }
        let _ = first
            .write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 5\r\n\r\nearly")
            .await;

        let deadline = tokio::time::sleep(TokioDuration::from_secs(2));
        tokio::pin!(deadline);
        let mut first_open = true;
        let mut first_bytes = Vec::new();
        let mut second = None;
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    if let Ok((stream, _)) = accepted {
                        task_connections.fetch_add(1, Ordering::SeqCst);
                        second = Some(stream);
                    }
                    break;
                }
                read = first.read_buf(&mut first_bytes), if first_open => {
                    match read {
                        Ok(0) | Err(_) => first_open = false,
                        Ok(_) => {
                            if first_bytes.windows(b"later-client".len()).any(|value| value == b"later-client") {
                                task_later.fetch_add(1, Ordering::SeqCst);
                            }
                            if first_bytes.windows(b"/base/after".len()).any(|value| value == b"/base/after") {
                                task_reused.fetch_add(1, Ordering::SeqCst);
                                let _ = first.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
                                break;
                            }
                        }
                    }
                }
                _ = &mut deadline => break,
            }
        }
        if let Some(mut second) = second {
            let second_head = read_request_head(&mut second).await.unwrap_or_default();
            if second_head.starts_with("GET /base/after ") {
                let _ = second
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
        }
    });
    RunningEarlyFinalFixture {
        address,
        connections,
        forwarded_later_bytes,
        reused_early_connection,
        task,
    }
}

async fn fixture_response(
    mut request: Request<Incoming>,
    state: Arc<FixtureState>,
) -> Result<Response<GatewayBody>, Infallible> {
    state.hits.fetch_add(1, Ordering::SeqCst);
    if matches!(
        request.uri().path(),
        "/base/ws"
            | "/base/bad-ws"
            | "/base/bad-protocol-ws"
            | "/base/bad-extension-ws"
            | "/base/nominated-accept-ws"
            | "/base/nominated-protocol-ws"
            | "/base/nominated-extension-ws"
    ) {
        let path = request.uri().path().to_string();
        let invalid_accept = path == "/base/bad-ws";
        let key = request
            .headers()
            .get("sec-websocket-key")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if path == "/base/ws" {
            let upgrade = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                if let Ok(upgraded) = upgrade.await {
                    let mut upgraded = TokioIo::new(upgraded);
                    let mut ping = [0u8; 4];
                    if upgraded.read_exact(&mut ping).await.is_ok() && &ping == b"ping" {
                        let _ = upgraded.write_all(b"pong").await;
                    }
                }
            });
        }
        let mut response = Response::new(empty_body());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
        response
            .headers_mut()
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
        let accept = if invalid_accept {
            "invalid-accept".to_string()
        } else {
            websocket_accept(&key)
        };
        response.headers_mut().insert(
            "sec-websocket-accept",
            HeaderValue::from_str(&accept).expect("accept"),
        );
        if path == "/base/bad-protocol-ws" {
            response.headers_mut().insert(
                "sec-websocket-protocol",
                HeaderValue::from_static("not-offered"),
            );
        } else if request
            .headers()
            .get("sec-websocket-protocol")
            .is_some_and(|value| value == "chat")
        {
            response
                .headers_mut()
                .insert("sec-websocket-protocol", HeaderValue::from_static("chat"));
        }
        if path == "/base/bad-extension-ws" {
            response.headers_mut().insert(
                "sec-websocket-extensions",
                HeaderValue::from_static("permessage-deflate"),
            );
        }
        match path.as_str() {
            "/base/nominated-accept-ws" => {
                response.headers_mut().insert(
                    CONNECTION,
                    HeaderValue::from_static("upgrade, sec-websocket-accept"),
                );
            }
            "/base/nominated-protocol-ws" => {
                response.headers_mut().insert(
                    CONNECTION,
                    HeaderValue::from_static("upgrade, sec-websocket-protocol"),
                );
            }
            "/base/nominated-extension-ws" => {
                response.headers_mut().insert(
                    "sec-websocket-extensions",
                    HeaderValue::from_static("permessage-deflate"),
                );
                response.headers_mut().insert(
                    CONNECTION,
                    HeaderValue::from_static("upgrade, sec-websocket-extensions"),
                );
            }
            _ => {}
        }
        return Ok(response);
    }
    if request.uri().path() == "/base/events" {
        let (sender, receiver) = mpsc::channel(1);
        let release = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = sender.send(Bytes::from_static(b"data: one\n\n")).await;
            if let Ok(permit) = release.sse_release.acquire().await {
                permit.forget();
            }
            let _ = sender.send(Bytes::from_static(b"data: two\n\n")).await;
        });
        let mut response = Response::new(channel_body(receiver));
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
        return Ok(response);
    }
    if request.uri().path() == "/base/chunks" {
        let (sender, receiver) = mpsc::channel(1);
        tokio::spawn(async move {
            for chunk in [
                Bytes::from_static(b"alpha"),
                Bytes::from_static(b"beta"),
                Bytes::from_static(b"gamma"),
            ] {
                let _ = sender.send(chunk).await;
            }
        });
        return Ok(Response::new(channel_body(receiver)));
    }

    let method = request.method().to_string();
    let target = request.uri().to_string();
    let headers = request.headers().clone();
    let mut body_len = 0usize;
    let mut body_bytes = Vec::new();
    let mut first = true;
    while let Some(frame) = request.body_mut().frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    body_len += data.len();
                    body_bytes.extend_from_slice(&data);
                    if first && request.uri().path() == "/base/upload" {
                        first = false;
                        state.upload_first_seen.add_permits(1);
                        if let Ok(permit) = state.upload_release.acquire().await {
                            permit.forget();
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }
    state.observed.lock().expect("observed").push(Observed {
        method,
        target,
        headers,
        body_len,
        body: body_bytes,
    });
    let mut response = Response::new(full_body(body_len.to_string()));
    if request.uri().path() == "/base/cookies" {
        response.headers_mut().append(
            SET_COOKIE,
            HeaderValue::from_static("amg_session=upstream; Path=/"),
        );
        response.headers_mut().append(
            SET_COOKIE,
            HeaderValue::from_static("app_cookie=ok; Path=/"),
        );
        response
            .headers_mut()
            .append(WARNING, HeaderValue::from_static("199 first"));
        response
            .headers_mut()
            .append(WARNING, HeaderValue::from_static("299 second"));
    }
    Ok(response)
}

struct ChannelBody {
    receiver: mpsc::Receiver<Bytes>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.receiver
            .poll_recv(context)
            .map(|value| value.map(|data| Ok(Frame::data(data))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}

fn channel_body(receiver: mpsc::Receiver<Bytes>) -> GatewayBody {
    ChannelBody { receiver }
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

async fn request_once(address: SocketAddr, request: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    timeout(
        TokioDuration::from_secs(5),
        stream.read_to_end(&mut response),
    )
    .await
    .expect("response timeout")
    .expect("read response");
    response
}

async fn eventually_non_capacity_request(address: SocketAddr, request: &str) -> Vec<u8> {
    timeout(TokioDuration::from_secs(5), async {
        loop {
            let response = request_once(address, request).await;
            if response_status(&response) != 503
                || decoded_response_body(&response) != b"Service temporarily unavailable"
            {
                break response;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("capacity eventually released")
}

async fn wait_for_gateway(address: SocketAddr) {
    for _ in 0..80 {
        if let Ok(mut stream) = TcpStream::connect(address).await {
            if stream
                .write_all(
                    b"GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
                )
                .await
                .is_ok()
            {
                let mut response = Vec::new();
                if stream.read_to_end(&mut response).await.is_ok()
                    && response.starts_with(b"HTTP/1.1 204")
                {
                    return;
                }
            }
        }
        tokio::time::sleep(TokioDuration::from_millis(25)).await;
    }
    panic!("gateway did not become ready");
}

async fn request_raw(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.expect("raw connect");
    stream.write_all(request).await.expect("raw write");
    let _ = stream.shutdown().await;
    let mut response = Vec::new();
    let _ = timeout(
        TokioDuration::from_secs(2),
        stream.read_to_end(&mut response),
    )
    .await;
    response
}

async fn read_head(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.expect("response head");
        bytes.push(byte[0]);
        assert!(bytes.len() < 64 * 1024, "response head too large");
    }
    String::from_utf8(bytes).expect("UTF-8 head")
}

fn assert_status(response: &[u8], status: u16) {
    let head = response_head(response);
    assert!(
        head.starts_with(&format!("HTTP/1.1 {status} ")),
        "unexpected response: {head}"
    );
}

fn response_status(response: &[u8]) -> u16 {
    response_head(response)
        .split_whitespace()
        .nth(1)
        .expect("status")
        .parse()
        .expect("numeric status")
}

fn response_head(response: &[u8]) -> String {
    String::from_utf8_lossy(raw_response_head(response)).into_owned()
}

fn raw_response_head(response: &[u8]) -> &[u8] {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response delimiter");
    &response[..split + 4]
}

fn response_body(response: &[u8]) -> &[u8] {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response delimiter");
    &response[split + 4..]
}

fn decoded_response_body(response: &[u8]) -> Vec<u8> {
    let head = response_head(response).to_ascii_lowercase();
    let body = response_body(response);
    if !head.contains("transfer-encoding: chunked") {
        return body.to_vec();
    }
    let mut decoded = Vec::new();
    let mut offset = 0;
    loop {
        let line_end = body[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|position| offset + position)
            .expect("chunk size line");
        let size_text = std::str::from_utf8(&body[offset..line_end]).expect("chunk size UTF-8");
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or_default(), 16)
            .expect("chunk size");
        offset = line_end + 2;
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&body[offset..offset + size]);
        offset += size;
        assert_eq!(&body[offset..offset + 2], b"\r\n");
        offset += 2;
    }
    decoded
}

fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

async fn read_request_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
        if bytes.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
    }
    String::from_utf8(bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF8 head"))
}

async fn read_one_chunk(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut size_line = Vec::new();
    let mut byte = [0u8; 1];
    while !size_line.ends_with(b"\r\n") {
        stream.read_exact(&mut byte).await?;
        size_line.push(byte[0]);
        if size_line.len() > 128 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chunk size too long",
            ));
        }
    }
    let size_text = std::str::from_utf8(&size_line[..size_line.len() - 2])
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk size"))?;
    let size = usize::from_str_radix(size_text, 16)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk size"))?;
    let mut data = vec![0; size];
    stream.read_exact(&mut data).await?;
    let mut ending = [0u8; 2];
    stream.read_exact(&mut ending).await?;
    if ending != *b"\r\n" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "chunk ending",
        ));
    }
    Ok(data)
}

fn websocket_accept(key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(sha1.finalize())
}

async fn unused_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("unused bind");
    let address = listener.local_addr().expect("unused address");
    drop(listener);
    address
}
