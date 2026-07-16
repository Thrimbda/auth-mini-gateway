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
    UpstreamProtocol,
};
use auth_mini_gateway::cookies::sign_value;
use auth_mini_gateway::db::{NewSession, Store};
use auth_mini_gateway::jwt::{Jwks, VerifiedAccessToken};
use auth_mini_gateway::proxy::{empty_body, full_body, BoxError, GatewayBody};
use auth_mini_gateway::server::run_server_with_listener_and_roots_and_hooks;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use chrono::{Duration, SecondsFormat, Utc};
use http::header::{CONNECTION, CONTENT_TYPE, SET_COOKIE, UPGRADE, WARNING};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http2;
use hyper::server::conn::{http1, http2 as server_http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
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
    version: Version,
    headers: HeaderMap,
    body_len: usize,
    body: Vec<u8>,
}

struct FixtureState {
    hits: AtomicUsize,
    connections: AtomicUsize,
    observed: Mutex<Vec<Observed>>,
    websocket_observed: Mutex<Vec<Observed>>,
    rejected_upgrade_dropped: Semaphore,
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
            websocket_observed: Mutex::new(Vec::new()),
            rejected_upgrade_dropped: Semaphore::new(0),
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

struct H2EarlyFinalState {
    hits: AtomicUsize,
    connections: AtomicUsize,
    body_held: Semaphore,
    allow_response: Semaphore,
    release_body: Semaphore,
    body_dropped: Semaphore,
}

struct RunningH2EarlyFinalFixture {
    address: SocketAddr,
    state: Arc<H2EarlyFinalState>,
    task: JoinHandle<()>,
}

struct H2RevocationState {
    connections: AtomicUsize,
    request_headers: AtomicUsize,
    sibling_seen: Semaphore,
    candidate_seen: Semaphore,
    release_revocation: Semaphore,
    transport_closed: Semaphore,
}

struct RunningH2RevocationFixture {
    address: SocketAddr,
    state: Arc<H2RevocationState>,
    task: JoinHandle<()>,
}

#[derive(Clone, Copy, Debug)]
enum H2NoReplayFailure {
    GoawayBeforeDispatch,
    GoawayAfterDispatch,
    RefusedBeforeBody,
    RefusedAfterBody,
}

struct H2NoReplayState {
    connections: AtomicUsize,
    request_headers: AtomicUsize,
    data_frames: AtomicUsize,
    body_bytes: AtomicUsize,
}

struct RunningH2NoReplayFixture {
    address: SocketAddr,
    state: Arc<H2NoReplayState>,
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
    upstream_protocol: Option<UpstreamProtocol>,
    service_call_counter: Option<Arc<AtomicUsize>>,
    auth_decision_counter: Option<Arc<AtomicUsize>>,
    upstream_admission_counter: Option<Arc<AtomicUsize>>,
}

impl Default for GatewayOptions {
    fn default() -> Self {
        Self {
            max_downstream_connections: 256,
            max_active_upstreams: 128,
            max_blocking_resolvers: 8,
            trusted_proxy_cidrs: TrustedProxySet::default(),
            upstream_protocol: None,
            service_call_counter: None,
            auth_decision_counter: None,
            upstream_admission_counter: None,
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
async fn downstream_auto_serves_actual_h1_and_h2_prior_knowledge() {
    let gateway = start_gateway(None, SessionMode::Missing).await;

    let h1 = request_once(
        gateway.address,
        "GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_status(&h1, 204);

    let (mut sender, client_task) = open_h2(gateway.address).await;
    let request = h2_request("/healthz", &[], Bytes::new());
    let response = send_h2(&mut sender, request).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.version(), Version::HTTP_2);
    response
        .into_body()
        .collect()
        .await
        .expect("collect H2 health response");

    drop(sender);
    client_task.abort();
    gateway.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_authority_split_cookie_auth_and_generated_headers_are_stream_local() {
    let fixture = start_fixture().await;
    let gateway = start_gateway(Some(fixture.address), SessionMode::Allowed).await;
    let cookie = gateway.cookie.as_deref().expect("allowed session cookie");
    let (mut sender, client_task) = open_h2(gateway.address).await;

    let split_cookie = format!("amg_session={cookie}");
    let local_auth = send_h2(
        &mut sender,
        h2_request(
            "/auth/check",
            &["theme=dark", split_cookie.as_str()],
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(local_auth.status(), StatusCode::NO_CONTENT);
    local_auth
        .into_body()
        .collect()
        .await
        .expect("local split-Cookie auth response");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 0);

    let allowed = h2_request(
        "/allowed",
        &["theme=dark", split_cookie.as_str()],
        Bytes::new(),
    );
    assert!(!allowed.headers().contains_key("host"));
    assert_eq!(allowed.headers().get_all("cookie").iter().count(), 2);
    let response = send_h2(&mut sender, allowed).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_2);
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .expect("allowed H2 body")
            .to_bytes(),
        Bytes::from_static(b"0")
    );
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);
    {
        let observed = fixture.state.observed.lock().expect("observed requests");
        let allowed = observed
            .last()
            .expect("allowed request reached H1 upstream");
        assert_eq!(allowed.target, "/base/allowed");
        assert_eq!(allowed.headers["host"], "public.example");
        assert_eq!(allowed.headers["x-forwarded-host"], "public.example");
        assert!(!allowed.headers.contains_key("cookie"));
    }

    let anonymous = h2_request("/anonymous", &[], Bytes::from_static(b"not-forwarded"));
    let anonymous = send_h2(&mut sender, anonymous).await;
    assert_eq!(anonymous.status(), StatusCode::FOUND);
    assert_h2_has_no_h1_hop_headers(anonymous.headers());
    anonymous
        .into_body()
        .collect()
        .await
        .expect("anonymous H2 body");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    let mut mismatched = h2_request(
        "/authority-mismatch",
        &[split_cookie.as_str()],
        Bytes::new(),
    );
    mismatched
        .headers_mut()
        .insert("host", HeaderValue::from_static("attacker.example"));
    let mismatched = send_h2(&mut sender, mismatched).await;
    assert_eq!(mismatched.status(), StatusCode::BAD_REQUEST);
    assert_h2_has_no_h1_hop_headers(mismatched.headers());
    mismatched
        .into_body()
        .collect()
        .await
        .expect("mismatched authority body");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    let mut opaque_cookie = h2_request("/opaque-cookie", &[], Bytes::new());
    opaque_cookie.headers_mut().append(
        http::header::COOKIE,
        HeaderValue::from_bytes(&[0x80]).expect("opaque HeaderValue"),
    );
    let opaque_cookie = send_h2(&mut sender, opaque_cookie).await;
    assert_eq!(opaque_cookie.status(), StatusCode::BAD_REQUEST);
    assert_h2_has_no_h1_hop_headers(opaque_cookie.headers());
    opaque_cookie
        .into_body()
        .collect()
        .await
        .expect("opaque Cookie response");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    let connect = Request::builder()
        .method("CONNECT")
        .version(Version::HTTP_2)
        .uri("public.example:443")
        .body(Full::new(Bytes::new()))
        .expect("ordinary H2 CONNECT request");
    let connect = send_h2(&mut sender, connect).await;
    assert_eq!(connect.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_h2_has_no_h1_hop_headers(connect.headers());
    connect
        .into_body()
        .collect()
        .await
        .expect("ordinary CONNECT response");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    let mut extended = Request::builder()
        .method("CONNECT")
        .version(Version::HTTP_2)
        .uri("https://public.example/websocket")
        .body(Full::new(Bytes::new()))
        .expect("extended H2 CONNECT request");
    extended
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    let extended = send_h2(&mut sender, extended).await;
    assert_eq!(extended.status(), StatusCode::BAD_REQUEST);
    assert_h2_has_no_h1_hop_headers(extended.headers());
    extended
        .into_body()
        .collect()
        .await
        .expect("extended CONNECT response");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    drop(sender);
    client_task.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_proxy_stream_admission_preserves_gateway_owned_reserve_until_body_end() {
    let fixture = start_fixture().await;
    let gateway = start_gateway_with_options(
        Some(
            parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
                .expect("valid fixture URL")
                .expect("fixture upstream"),
        ),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_downstream_connections: 17,
            max_active_upstreams: 1,
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = format!(
        "amg_session={}",
        gateway.cookie.as_deref().expect("allowed session cookie")
    );
    let (mut sender, client_task) = open_h2(gateway.address).await;

    let events = send_h2(
        &mut sender,
        h2_request("/events", &[cookie.as_str()], Bytes::new()),
    )
    .await;
    assert_eq!(events.status(), StatusCode::OK);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    let saturated = send_h2(
        &mut sender,
        h2_request("/while-events", &[cookie.as_str()], Bytes::new()),
    )
    .await;
    assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(saturated.headers()[http::header::RETRY_AFTER], "5");
    assert_h2_has_no_h1_hop_headers(saturated.headers());
    saturated
        .into_body()
        .collect()
        .await
        .expect("capacity response body");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    let health = send_h2(&mut sender, h2_request("/healthz", &[], Bytes::new())).await;
    assert_eq!(health.status(), StatusCode::NO_CONTENT);
    health
        .into_body()
        .collect()
        .await
        .expect("reserved health response");

    fixture.state.sse_release.add_permits(1);
    let events_body = events
        .into_body()
        .collect()
        .await
        .expect("complete events response")
        .to_bytes();
    assert_eq!(
        events_body,
        Bytes::from_static(b"data: one\n\ndata: two\n\n")
    );

    let after = send_h2(
        &mut sender,
        h2_request("/after-events", &[cookie.as_str()], Bytes::new()),
    )
    .await;
    assert_eq!(after.status(), StatusCode::OK);
    after
        .into_body()
        .collect()
        .await
        .expect("post-release response");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 2);

    drop(sender);
    client_task.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_h2c_proxies_ordinary_h1_and_h2_requests_without_host_or_ws_fallback() {
    let fixture = start_h2_fixture(100).await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("H2 fixture URL")
        .expect("H2 fixture upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("H2 fixture cookie");

    let h1 = request_once(
        gateway.address,
        &format!(
            "GET /from-h1 HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&h1, 200);

    let (mut sender, client_task) = open_h2(gateway.address).await;
    let auth_cookie = format!("amg_session={cookie}");
    let h2 = send_h2(
        &mut sender,
        h2_request(
            "/from-h2",
            &["theme=dark", auth_cookie.as_str()],
            Bytes::from_static(b"payload"),
        ),
    )
    .await;
    assert_eq!(h2.status(), StatusCode::OK);
    assert_eq!(
        h2.into_body()
            .collect()
            .await
            .expect("H2 ordinary response")
            .to_bytes(),
        Bytes::from_static(b"7")
    );

    for (method, body) in [
        ("PUT", Bytes::from_static(b"put")),
        ("PATCH", Bytes::from_static(b"patch")),
        ("DELETE", Bytes::new()),
    ] {
        let mut request = h2_request(
            &format!("/method-{}", method.to_ascii_lowercase()),
            &[auth_cookie.as_str()],
            body,
        );
        *request.method_mut() = method.parse().expect("required method");
        let response = send_h2(&mut sender, request).await;
        assert_eq!(response.status(), StatusCode::OK, "method={method}");
        response
            .into_body()
            .collect()
            .await
            .expect("required method response");
    }

    let mut websocket = TcpStream::connect(gateway.address)
        .await
        .expect("h1->h2 websocket connect");
    websocket
        .write_all(
            format!(
                "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nAuthorization: Bearer browser-secret\r\nProxy-Authorization: Basic proxy-secret\r\nX-Auth-Mini-User-Id: forged\r\nX-Forwarded-Host: attacker.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nOrigin: https://public.example\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("h1->h2 websocket handshake");
    let websocket_head = timeout(TokioDuration::from_secs(2), read_head(&mut websocket))
        .await
        .expect("h1->h2 websocket response");
    assert!(
        websocket_head.starts_with("HTTP/1.1 101"),
        "{websocket_head}"
    );
    assert!(websocket_head
        .to_ascii_lowercase()
        .contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="));
    websocket.write_all(b"ping").await.expect("h1->h2 ping");
    let mut pong = [0_u8; 4];
    websocket.read_exact(&mut pong).await.expect("h1->h2 pong");
    assert_eq!(&pong, b"pong");
    websocket.shutdown().await.expect("h1->h2 shutdown");

    let after_tunnel = send_h2(
        &mut sender,
        h2_request("/after-ws-tunnel", &[auth_cookie.as_str()], Bytes::new()),
    )
    .await;
    assert_eq!(after_tunnel.status(), StatusCode::OK);
    after_tunnel
        .into_body()
        .collect()
        .await
        .expect("generation survives H2 WebSocket tunnel");

    let observed = fixture.state.observed.lock().expect("H2 observations");
    assert_eq!(observed.len(), 6);
    for request in observed.iter() {
        assert_eq!(request.version, Version::HTTP_2);
        assert!(request
            .target
            .starts_with(&format!("http://{}/base/", fixture.address)));
        assert!(!request.headers.contains_key("host"));
        assert!(!request.headers.contains_key("cookie"));
        assert_eq!(request.headers["x-forwarded-host"], "public.example");
    }
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);
    drop(observed);
    let websocket_observed = fixture
        .state
        .websocket_observed
        .lock()
        .expect("H2 websocket observation");
    assert_eq!(websocket_observed.len(), 1);
    let websocket_request = &websocket_observed[0];
    assert_eq!(websocket_request.method, "CONNECT");
    assert_eq!(websocket_request.version, Version::HTTP_2);
    assert_eq!(
        websocket_request.target,
        format!("http://{}/base/ws", fixture.address)
    );
    for removed in [
        "host",
        "cookie",
        "authorization",
        "proxy-authorization",
        "connection",
        "upgrade",
        "sec-websocket-key",
    ] {
        assert!(
            !websocket_request.headers.contains_key(removed),
            "{removed}"
        );
    }
    assert_eq!(websocket_request.headers["x-auth-mini-user-id"], "user-1");
    assert_eq!(
        websocket_request.headers["x-forwarded-host"],
        "public.example"
    );
    drop(websocket_observed);

    drop(sender);
    client_task.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_h2c_handshake_failure_never_falls_back_or_replays() {
    let fixture = start_fixture().await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("H1-only fixture URL")
        .expect("H1-only fixture upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("h2c failure cookie");
    let response = request_once(
        gateway.address,
        &format!(
            "POST /one-attempt HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nonce"
        ),
    )
    .await;
    assert_status(&response, 502);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.state.connections.load(Ordering::SeqCst),
        1,
        "failed explicit h2c opened a fallback connection"
    );

    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_downstream_websocket_bridges_to_h1_and_h2_with_exact_translation() {
    for upstream_h2 in [false, true] {
        let fixture = if upstream_h2 {
            start_h2_fixture(100).await
        } else {
            start_fixture().await
        };
        let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
            .expect("websocket matrix URL")
            .expect("websocket matrix upstream");
        let gateway = start_gateway_with_options(
            Some(upstream),
            SessionMode::Allowed,
            None,
            GatewayOptions {
                upstream_protocol: Some(if upstream_h2 {
                    UpstreamProtocol::Http2
                } else {
                    UpstreamProtocol::Http1
                }),
                ..GatewayOptions::default()
            },
        )
        .await;
        let cookie = gateway.cookie.as_deref().expect("websocket matrix cookie");
        let (mut sender, client_task) = open_h2(gateway.address).await;
        let mut response = send_h2(
            &mut sender,
            h2_websocket_request("/ws-framed", cookie, Some("chat")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), Version::HTTP_2);
        assert_h2_has_no_h1_hop_headers(response.headers());
        assert!(!response.headers().contains_key("sec-websocket-key"));
        assert!(!response.headers().contains_key("sec-websocket-accept"));
        assert_eq!(response.headers()["sec-websocket-protocol"], "chat");
        let upgrade = hyper::upgrade::on(&mut response);
        let upgraded = timeout(TokioDuration::from_secs(2), upgrade)
            .await
            .expect("downstream H2 upgrade timeout")
            .expect("downstream H2 upgrade");
        let mut tunnel = TokioIo::new(upgraded);
        tunnel
            .write_all(&masked_ping_frame())
            .await
            .expect("H2 tunnel framed ping");
        let mut pong = [0_u8; 6];
        tunnel
            .read_exact(&mut pong)
            .await
            .expect("H2 tunnel framed pong");
        assert_eq!(pong, text_pong_frame());
        tunnel.shutdown().await.expect("H2 tunnel shutdown");

        let observed = fixture
            .state
            .websocket_observed
            .lock()
            .expect("websocket matrix observation");
        assert_eq!(observed.len(), 1);
        let request = &observed[0];
        assert!(!request.headers.contains_key("cookie"));
        assert!(!request.headers.contains_key("authorization"));
        assert!(!request.headers.contains_key("proxy-authorization"));
        assert_eq!(request.headers["x-auth-mini-user-id"], "user-1");
        assert_eq!(request.headers["x-forwarded-host"], "public.example");
        assert_eq!(request.headers["origin"], "https://public.example");
        assert_eq!(request.headers["sec-websocket-version"], "13");
        assert_eq!(request.headers["sec-websocket-protocol"], "chat");
        if upstream_h2 {
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.version, Version::HTTP_2);
            assert!(!request.headers.contains_key("host"));
            assert!(!request.headers.contains_key("sec-websocket-key"));
            assert_eq!(
                request.target,
                format!("http://{}/base/ws-framed", fixture.address)
            );
        } else {
            assert_eq!(request.method, "GET");
            assert_eq!(request.version, Version::HTTP_11);
            assert_eq!(request.headers["host"], "public.example");
            let key = request.headers["sec-websocket-key"]
                .to_str()
                .expect("generated websocket key");
            let decoded = STANDARD.decode(key).expect("canonical generated key");
            assert_eq!(decoded.len(), 16);
            assert_eq!(STANDARD.encode(decoded), key);
            assert_eq!(request.target, "/base/ws-framed");
        }
        drop(observed);

        drop(tunnel);
        drop(sender);
        client_task.abort();
        gateway.task.abort();
        fixture.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_connect_classification_is_stream_local_and_zero_hit_until_valid() {
    let fixture = start_fixture().await;
    let gateway = start_gateway(Some(fixture.address), SessionMode::Allowed).await;
    let cookie = gateway.cookie.as_deref().expect("H2 CONNECT cookie");
    let (mut sender, client_task) = open_h2(gateway.address).await;

    let ordinary = Request::builder()
        .method("CONNECT")
        .version(Version::HTTP_2)
        .uri("public.example:443")
        .body(Full::new(Bytes::new()))
        .expect("ordinary CONNECT");
    let ordinary = send_h2(&mut sender, ordinary).await;
    assert_eq!(ordinary.status(), StatusCode::METHOD_NOT_ALLOWED);
    ordinary
        .into_body()
        .collect()
        .await
        .expect("ordinary CONNECT response");

    let mut other_protocol = h2_websocket_request("/ws", cookie, None);
    other_protocol
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("not-websocket"));
    let other_protocol = send_h2(&mut sender, other_protocol).await;
    assert_eq!(other_protocol.status(), StatusCode::METHOD_NOT_ALLOWED);
    other_protocol
        .into_body()
        .collect()
        .await
        .expect("other protocol response");

    let mut malformed = Vec::new();
    let mut wrong_version = h2_websocket_request("/ws", cookie, None);
    wrong_version
        .headers_mut()
        .insert("sec-websocket-version", HeaderValue::from_static("12"));
    malformed.push(wrong_version);
    let mut host = h2_websocket_request("/ws", cookie, None);
    host.headers_mut()
        .insert("host", HeaderValue::from_static("attacker.example"));
    malformed.push(host);
    let mut key = h2_websocket_request("/ws", cookie, None);
    key.headers_mut().insert(
        "sec-websocket-key",
        HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
    );
    malformed.push(key);
    let mut origin = h2_websocket_request("/ws", cookie, None);
    origin.headers_mut().insert(
        "origin",
        HeaderValue::from_static("https://public.example/not-an-origin"),
    );
    malformed.push(origin);
    let mut protocols = h2_websocket_request("/ws", cookie, None);
    protocols.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static("chat, chat"),
    );
    malformed.push(protocols);
    let mut extensions = h2_websocket_request("/ws", cookie, None);
    extensions.headers_mut().insert(
        "sec-websocket-extensions",
        HeaderValue::from_static("permessage-deflate; =bad"),
    );
    malformed.push(extensions);

    for request in malformed {
        let response = send_h2(&mut sender, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_h2_has_no_h1_hop_headers(response.headers());
        response
            .into_body()
            .collect()
            .await
            .expect("malformed H2 websocket response");
    }
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 0);

    let mut zero_length = h2_websocket_request("/ws", cookie, None);
    zero_length
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    let mut zero_length = send_h2(&mut sender, zero_length).await;
    assert_eq!(zero_length.status(), StatusCode::OK);
    let zero_upgrade = hyper::upgrade::on(&mut zero_length);
    let zero_upgraded = timeout(TokioDuration::from_secs(2), zero_upgrade)
        .await
        .expect("zero-length H2 CONNECT timeout")
        .expect("zero-length H2 CONNECT upgrade");
    drop(zero_upgraded);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    let mut valid = send_h2(&mut sender, h2_websocket_request("/ws", cookie, None)).await;
    assert_eq!(valid.status(), StatusCode::OK);
    let upgrade = hyper::upgrade::on(&mut valid);
    let upgraded = timeout(TokioDuration::from_secs(2), upgrade)
        .await
        .expect("valid H2 CONNECT timeout")
        .expect("valid H2 CONNECT upgrade");
    let mut tunnel = TokioIo::new(upgraded);
    tunnel.write_all(b"ping").await.expect("valid H2 ping");
    let mut pong = [0_u8; 4];
    tunnel.read_exact(&mut pong).await.expect("valid H2 pong");
    assert_eq!(&pong, b"pong");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 2);

    drop(tunnel);
    drop(sender);
    client_task.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_h2_consistent_nonzero_connect_is_pre_service_fail_closed_with_required_eof() {
    let fixture = start_fixture().await;
    let service_calls = Arc::new(AtomicUsize::new(0));
    let auth_decisions = Arc::new(AtomicUsize::new(0));
    let upstream_admissions = Arc::new(AtomicUsize::new(0));
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("raw H2 upstream URL")
        .expect("raw H2 upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_active_upstreams: 1,
            upstream_protocol: Some(UpstreamProtocol::Http1),
            service_call_counter: Some(Arc::clone(&service_calls)),
            auth_decision_counter: Some(Arc::clone(&auth_decisions)),
            upstream_admission_counter: Some(Arc::clone(&upstream_admissions)),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = format!(
        "amg_session={}",
        gateway.cookie.as_deref().expect("raw H2 session")
    );

    // Control: the exact Extended CONNECT block without Content-Length must
    // reach Service::call, authenticate, dispatch, receive response HEADERS,
    // and leave the physical H2 connection alive.
    let mut control = raw_h2_connection(gateway.address).await;
    send_raw_extended_connect(&mut control, &cookie, None).await;
    let control_response = timeout(TokioDuration::from_secs(5), async {
        loop {
            let frame = read_raw_h2_frame(&mut control)
                .await
                .expect("raw control frame")
                .expect("raw control EOF before response");
            if frame.frame_type == 0x3 && frame.stream_id == 1 {
                panic!("valid raw Extended CONNECT was reset");
            }
            if frame.frame_type == 0x1 && frame.stream_id == 1 {
                break frame;
            }
        }
    })
    .await
    .expect("raw control response timeout");
    assert_ne!(
        control_response.flags & 0x1,
        0x1,
        "valid Extended CONNECT response ended the tunnel stream"
    );
    timeout(TokioDuration::from_secs(2), async {
        while service_calls.load(Ordering::SeqCst) != 1
            || auth_decisions.load(Ordering::SeqCst) != 1
            || upstream_admissions.load(Ordering::SeqCst) != 1
            || fixture.state.hits.load(Ordering::SeqCst) != 1
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("raw control did not reach gateway/upstream");
    let ping_payload = *b"raw-open";
    control
        .write_all(&raw_h2_frame(0x6, 0, 0, &ping_payload))
        .await
        .expect("raw control PING");
    timeout(TokioDuration::from_secs(2), async {
        loop {
            let frame = read_raw_h2_frame(&mut control)
                .await
                .expect("raw control post-response frame")
                .expect("raw control connection closed");
            if frame.frame_type == 0x6 && frame.flags & 0x1 != 0 {
                assert_eq!(frame.stream_id, 0);
                assert_eq!(frame.payload, ping_payload);
                break;
            }
        }
    })
    .await
    .expect("raw control connection did not remain open");
    drop(control);

    let service_before = service_calls.load(Ordering::SeqCst);
    let auth_before = auth_decisions.load(Ordering::SeqCst);
    let upstream_admission_before = upstream_admissions.load(Ordering::SeqCst);
    let upstream_before = fixture.state.hits.load(Ordering::SeqCst);

    // Exception case: the same valid block plus a consistently parsed
    // Content-Length: 1 is intercepted by pinned Hyper before Service::call.
    let mut malformed = raw_h2_connection(gateway.address).await;
    send_raw_extended_connect(&mut malformed, &cookie, Some(1)).await;
    let observed_frames = timeout(TokioDuration::from_secs(2), async {
        let mut frames = Vec::new();
        loop {
            match read_raw_h2_frame(&mut malformed).await {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => break,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("raw malformed H2 read failed: {error}"),
            }
        }
        frames
    })
    .await
    .expect("pinned Hyper connection did not complete/close");

    for reset in observed_frames
        .iter()
        .filter(|frame| frame.frame_type == 0x3)
    {
        assert_eq!(reset.stream_id, 1);
        assert_eq!(reset.payload.len(), 4);
        assert_eq!(
            u32::from_be_bytes(reset.payload.clone().try_into().expect("RST payload")),
            0x2,
            "optional reset was not INTERNAL_ERROR"
        );
    }
    assert_eq!(service_calls.load(Ordering::SeqCst), service_before);
    assert_eq!(auth_decisions.load(Ordering::SeqCst), auth_before);
    assert_eq!(
        upstream_admissions.load(Ordering::SeqCst),
        upstream_admission_before
    );
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), upstream_before);

    // This exception is only the pinned pre-service non-zero-length branch;
    // ordinary CONNECT and service-observed RFC8441 isolation remain covered
    // by the dedicated CONNECT/WebSocket sibling tests.
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selected_h2_without_extended_connect_fails_before_dispatch_and_stays_ordinary_usable() {
    let fixture = start_h2_fixture_with_connect(100, false).await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("no-connect H2 URL")
        .expect("no-connect H2 upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("no-connect cookie");
    let rejected = request_once(
        gateway.address,
        &format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        ),
    )
    .await;
    assert_status(&rejected, 502);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 0);
    assert!(fixture
        .state
        .websocket_observed
        .lock()
        .expect("no-connect websocket observations")
        .is_empty());

    let ordinary = request_once(
        gateway.address,
        &format!(
            "GET /after-no-connect HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&ordinary, 200);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);

    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_auto_pool_does_not_downgrade_ineligible_selected_h2_websocket() {
    let fixture = start_mixed_tls_fixture().await;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(fixture.certificate.clone())
        .expect("trust mixed TLS fixture");
    let upstream = parse_upstream_url(Some(&format!(
        "https://localhost:{}/base",
        fixture.address.port()
    )))
    .expect("mixed TLS URL")
    .expect("mixed TLS upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        Some(roots),
        GatewayOptions {
            max_active_upstreams: 3,
            upstream_protocol: Some(UpstreamProtocol::Auto),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("mixed pool cookie");

    let h1_events_request = format!(
        "GET /events HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
    );
    let gateway_address = gateway.address;
    let h1_events =
        tokio::spawn(async move { request_once(gateway_address, &h1_events_request).await });
    timeout(TokioDuration::from_secs(2), async {
        while fixture.state.hits.load(Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("mixed H1 SSE started");

    let seed_h2 = request_once(
        gateway.address,
        &format!(
            "GET /seed-h2 HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&seed_h2, 200);
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 2);

    fixture.state.sse_release.add_permits(1);
    let h1_events = h1_events.await.expect("mixed H1 SSE task");
    assert_status(&h1_events, 200);
    tokio::time::sleep(TokioDuration::from_millis(25)).await;

    let websocket = request_once(
        gateway.address,
        &format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        ),
    )
    .await;
    assert_status(&websocket, 502);
    assert_eq!(
        fixture.state.hits.load(Ordering::SeqCst),
        2,
        "selected H2 websocket fell through to idle H1"
    );

    let h2_events_request = format!(
        "GET /events HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
    );
    let gateway_address = gateway.address;
    let h2_events =
        tokio::spawn(async move { request_once(gateway_address, &h2_events_request).await });
    timeout(TokioDuration::from_secs(2), async {
        while fixture.state.hits.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("mixed H2 SSE started");

    let fallback_h1 = request_once(
        gateway.address,
        &format!(
            "GET /idle-h1-still-present HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&fallback_h1, 200);
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 2);
    {
        let observed = fixture.state.observed.lock().expect("mixed observations");
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0].version, Version::HTTP_2);
        assert_eq!(observed[1].version, Version::HTTP_11);
    }

    fixture.state.sse_release.add_permits(1);
    let h2_events = h2_events.await.expect("mixed H2 SSE task");
    assert_status(&h2_events, 200);

    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn later_settings_revocation_after_enqueue_retires_generation_without_replay() {
    let fixture = start_h2_revocation_fixture().await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("revocation upstream URL")
        .expect("revocation upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_active_upstreams: 4,
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("revocation cookie");

    let warm = request_once(
        gateway.address,
        &format!(
            "GET /revocation-warm HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&warm, 200);

    let (mut sender, downstream_driver) = open_h2(gateway.address).await;
    let sibling = send_h2(
        &mut sender,
        h2_request(
            "/revocation-sibling",
            &[&format!("amg_session={cookie}")],
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(sibling.status(), StatusCode::OK);
    let sibling_seen = timeout(
        TokioDuration::from_secs(2),
        fixture.state.sibling_seen.acquire(),
    )
    .await
    .expect("revocation sibling was not dispatched")
    .expect("revocation sibling semaphore");
    sibling_seen.forget();

    let websocket = {
        let address = gateway.address;
        let cookie = cookie.to_string();
        tokio::spawn(async move {
            request_once(
                address,
                &format!(
                    "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
                ),
            )
            .await
        })
    };
    let candidate_seen = timeout(
        TokioDuration::from_secs(2),
        fixture.state.candidate_seen.acquire(),
    )
    .await
    .expect("revocation candidate was not enqueued")
    .expect("revocation candidate semaphore");
    candidate_seen.forget();
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.request_headers.load(Ordering::SeqCst), 3);

    fixture.state.release_revocation.add_permits(1);
    let websocket = timeout(TokioDuration::from_secs(2), websocket)
        .await
        .expect("revoked websocket timeout")
        .expect("revoked websocket task");
    assert_status(&websocket, 502);
    assert!(
        sibling.into_body().collect().await.is_err(),
        "revocation did not fail a controlled generation sibling"
    );
    let closed = timeout(
        TokioDuration::from_secs(2),
        fixture.state.transport_closed.acquire(),
    )
    .await
    .expect("revoked generation transport did not close")
    .expect("revoked transport semaphore");
    closed.forget();
    assert_eq!(fixture.state.request_headers.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);

    let replacement = request_once(
        gateway.address,
        &format!(
            "GET /replacement-generation HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&replacement, 200);
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.state.request_headers.load(Ordering::SeqCst), 4);

    drop(sender);
    downstream_driver.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_h2_upgrade_is_reset_before_capacity_release_and_sibling_reuses_generation() {
    let fixture = start_h2_fixture(100).await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("rejected upgrade URL")
        .expect("rejected upgrade upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_active_upstreams: 2,
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("rejected upgrade cookie");
    let auth_cookie = format!("amg_session={cookie}");
    let (mut sender, client_task) = open_h2(gateway.address).await;

    let sibling = send_h2(
        &mut sender,
        h2_request("/events", &[auth_cookie.as_str()], Bytes::new()),
    )
    .await;
    assert_eq!(sibling.status(), StatusCode::OK);

    let rejected = send_h2(&mut sender, h2_websocket_request("/bad-ws", cookie, None)).await;
    assert_eq!(rejected.status(), StatusCode::BAD_GATEWAY);
    assert_h2_has_no_h1_hop_headers(rejected.headers());
    rejected
        .into_body()
        .collect()
        .await
        .expect("rejected H2 upgrade response");

    timeout(
        TokioDuration::from_secs(2),
        fixture.state.rejected_upgrade_dropped.acquire(),
    )
    .await
    .expect("rejected H2 upgrade reset timeout")
    .expect("rejected H2 upgrade reset signal")
    .forget();

    let after = send_h2(
        &mut sender,
        h2_request(
            "/after-rejected-upgrade",
            &[auth_cookie.as_str()],
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(after.status(), StatusCode::OK);
    after
        .into_body()
        .collect()
        .await
        .expect("generation after rejected upgrade");
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);

    fixture.state.sse_release.add_permits(1);
    sibling
        .into_body()
        .collect()
        .await
        .expect("sibling survives rejected upgrade");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 3);

    drop(sender);
    client_task.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_websocket_tunnel_holds_u_and_downstream_stream_admission_until_eof() {
    let fixture = start_h2_fixture(100).await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("tunnel lifetime URL")
        .expect("tunnel lifetime upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_downstream_connections: 17,
            max_active_upstreams: 1,
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("tunnel lifetime cookie");
    let (mut sender, client_task) = open_h2(gateway.address).await;
    let mut response = send_h2(&mut sender, h2_websocket_request("/ws", cookie, None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let upgrade = hyper::upgrade::on(&mut response);
    let upgraded = timeout(TokioDuration::from_secs(2), upgrade)
        .await
        .expect("lifetime tunnel upgrade timeout")
        .expect("lifetime tunnel upgrade");
    let mut tunnel = TokioIo::new(upgraded);

    let stream_saturated = send_h2(
        &mut sender,
        h2_request(
            "/while-tunnel",
            &[&format!("amg_session={cookie}")],
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(stream_saturated.status(), StatusCode::SERVICE_UNAVAILABLE);
    stream_saturated
        .into_body()
        .collect()
        .await
        .expect("downstream stream saturation body");

    let u_saturated = request_once(
        gateway.address,
        &format!(
            "GET /while-tunnel-h1 HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&u_saturated, 503);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);

    tunnel.write_all(b"ping").await.expect("lifetime ping");
    let mut pong = [0_u8; 4];
    tunnel.read_exact(&mut pong).await.expect("lifetime pong");
    assert_eq!(&pong, b"pong");
    drop(tunnel);
    tokio::time::sleep(TokioDuration::from_millis(25)).await;

    let after = request_once(
        gateway.address,
        &format!(
            "GET /after-tunnel HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&after, 200);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);

    drop(sender);
    client_task.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_auto_uses_alpn_h2_and_no_alpn_h1_while_forced_h2_fails_closed() {
    let h2_fixture = start_tls_h2_fixture().await;
    let mut h2_roots = rustls::RootCertStore::empty();
    h2_roots
        .add(h2_fixture.certificate.clone())
        .expect("trust H2 fixture");
    let h2_upstream = parse_upstream_url(Some(&format!(
        "https://localhost:{}/base",
        h2_fixture.address.port()
    )))
    .expect("TLS H2 URL")
    .expect("TLS H2 upstream");
    let h2_gateway = start_gateway_with_options(
        Some(h2_upstream),
        SessionMode::Allowed,
        Some(h2_roots),
        GatewayOptions {
            upstream_protocol: Some(UpstreamProtocol::Auto),
            ..GatewayOptions::default()
        },
    )
    .await;
    let h2_cookie = h2_gateway.cookie.as_deref().expect("TLS H2 cookie");
    let h2_response = request_once(
        h2_gateway.address,
        &format!(
            "GET /tls-h2 HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={h2_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&h2_response, 200);
    assert_eq!(
        h2_fixture
            .state
            .observed
            .lock()
            .expect("TLS H2 observation")[0]
            .version,
        Version::HTTP_2
    );

    let h1_fixture = start_tls_fixture().await;
    let mut h1_roots = rustls::RootCertStore::empty();
    h1_roots
        .add(h1_fixture.certificate.clone())
        .expect("trust H1 fixture");
    let h1_upstream = parse_upstream_url(Some(&format!(
        "https://localhost:{}/base",
        h1_fixture.address.port()
    )))
    .expect("TLS H1 URL")
    .expect("TLS H1 upstream");
    let auto_h1 = start_gateway_with_options(
        Some(h1_upstream.clone()),
        SessionMode::Allowed,
        Some(h1_roots.clone()),
        GatewayOptions {
            upstream_protocol: Some(UpstreamProtocol::Auto),
            ..GatewayOptions::default()
        },
    )
    .await;
    let h1_cookie = auto_h1.cookie.as_deref().expect("TLS H1 cookie");
    let h1_response = request_once(
        auto_h1.address,
        &format!(
            "GET /tls-h1 HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={h1_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&h1_response, 200);
    assert_eq!(
        h1_fixture
            .state
            .observed
            .lock()
            .expect("TLS H1 observation")[0]
            .version,
        Version::HTTP_11
    );

    let forced_h2 = start_gateway_with_options(
        Some(h1_upstream),
        SessionMode::Allowed,
        Some(h1_roots),
        GatewayOptions {
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let forced_cookie = forced_h2.cookie.as_deref().expect("forced H2 cookie");
    let failed = request_once(
        forced_h2.address,
        &format!(
            "POST /must-not-fallback HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={forced_cookie}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nonce"
        ),
    )
    .await;
    assert_status(&failed, 502);
    assert_eq!(
        h1_fixture.state.hits.load(Ordering::SeqCst),
        1,
        "forced H2 fell back and replayed over H1"
    );

    forced_h2.task.abort();
    auto_h1.task.abort();
    h1_fixture.task.abort();
    h2_gateway.task.abort();
    h2_fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_forced_http2_succeeds_with_h2_and_strict_tls_identity() {
    let fixture = start_tls_h2_fixture().await;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(fixture.certificate.clone())
        .expect("trust forced-H2 fixture");
    let upstream = parse_upstream_url(Some(&format!(
        "https://localhost:{}/base",
        fixture.address.port()
    )))
    .expect("forced-H2 URL")
    .expect("forced-H2 upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        Some(roots.clone()),
        GatewayOptions {
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("forced-H2 cookie");
    let response = request_once(
        gateway.address,
        &format!(
            "GET /forced-tls-h2 HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&response, 200);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);
    {
        let observed = fixture
            .state
            .observed
            .lock()
            .expect("forced-H2 observation");
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].version, Version::HTTP_2);
    }

    let mismatched_upstream = parse_upstream_url(Some(&format!(
        "https://127.0.0.1:{}/base",
        fixture.address.port()
    )))
    .expect("forced-H2 mismatched URL")
    .expect("forced-H2 mismatched upstream");
    let mismatched_gateway = start_gateway_with_options(
        Some(mismatched_upstream),
        SessionMode::Allowed,
        Some(roots),
        GatewayOptions {
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let mismatched_cookie = mismatched_gateway
        .cookie
        .as_deref()
        .expect("forced-H2 mismatched cookie");
    let rejected = request_once(
        mismatched_gateway.address,
        &format!(
            "GET /forced-tls-identity-mismatch HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={mismatched_cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&rejected, 502);
    assert_eq!(
        fixture.state.hits.load(Ordering::SeqCst),
        1,
        "forced H2 accepted a certificate without the requested IP SAN"
    );

    mismatched_gateway.task.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_multiplexing_holds_u_for_both_halves_and_saturates_without_extra_connections() {
    let fixture = start_h2_fixture(100).await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("multiplex URL")
        .expect("multiplex upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_active_upstreams: 2,
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = format!(
        "amg_session={}",
        gateway.cookie.as_deref().expect("multiplex cookie")
    );
    let (mut sender, client_task) = open_h2(gateway.address).await;

    let first = send_h2(
        &mut sender,
        h2_request("/events", &[cookie.as_str()], Bytes::new()),
    )
    .await;
    let second = send_h2(
        &mut sender,
        h2_request("/events", &[cookie.as_str()], Bytes::new()),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);

    let saturated = send_h2(
        &mut sender,
        h2_request("/capacity", &[cookie.as_str()], Bytes::new()),
    )
    .await;
    assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(saturated.headers()[http::header::RETRY_AFTER], "5");
    saturated
        .into_body()
        .collect()
        .await
        .expect("H2 capacity body");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);

    fixture.state.sse_release.add_permits(2);
    first
        .into_body()
        .collect()
        .await
        .expect("first multiplexed body");
    second
        .into_body()
        .collect()
        .await
        .expect("second multiplexed body");
    let after = send_h2(
        &mut sender,
        h2_request("/after-capacity", &[cookie.as_str()], Bytes::new()),
    )
    .await;
    assert_eq!(after.status(), StatusCode::OK);
    after
        .into_body()
        .collect()
        .await
        .expect("post-capacity body");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);

    drop(sender);
    client_task.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_limit_one_reserves_creator_before_publication() {
    let fixture = start_h2_fixture(1).await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("peer-limit URL")
        .expect("peer-limit upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_active_upstreams: 2,
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = format!(
        "amg_session={}",
        gateway.cookie.as_deref().expect("peer-limit cookie")
    );
    let (mut sender, client_task) = open_h2(gateway.address).await;

    let creator = send_h2(
        &mut sender,
        h2_request("/events", &[cookie.as_str()], Bytes::new()),
    )
    .await;
    assert_eq!(creator.status(), StatusCode::OK);
    let second = send_h2(
        &mut sender,
        h2_request("/second-generation", &[cookie.as_str()], Bytes::new()),
    )
    .await;
    assert_eq!(second.status(), StatusCode::OK);
    second
        .into_body()
        .collect()
        .await
        .expect("second generation response");
    assert_eq!(
        fixture.state.connections.load(Ordering::SeqCst),
        2,
        "creator's only peer permit was visible before creator reservation"
    );

    fixture.state.sse_release.add_permits(1);
    creator
        .into_body()
        .collect()
        .await
        .expect("creator response");
    drop(sender);
    client_task.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_limit_zero_fails_before_dispatch_and_never_publishes() {
    let fixture = start_h2_fixture(0).await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("zero-limit URL")
        .expect("zero-limit upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_active_upstreams: 2,
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("zero-limit cookie");
    for attempt in 1..=2 {
        let response = request_once(
            gateway.address,
            &format!(
                "POST /zero-{attempt} HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nonce"
            ),
        )
        .await;
        assert_status(&response, 502);
        assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.state.connections.load(Ordering::SeqCst),
            attempt,
            "zero-limit H2 generation became pool-visible"
        );
    }

    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_stream_reset_is_not_replayed_and_does_not_kill_a_sibling() {
    let fixture = start_h2_fixture(100).await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("reset URL")
        .expect("reset upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_active_upstreams: 3,
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = format!(
        "amg_session={}",
        gateway.cookie.as_deref().expect("reset cookie")
    );
    let (mut sender, client_task) = open_h2(gateway.address).await;

    let sibling = send_h2(
        &mut sender,
        h2_request("/events", &[cookie.as_str()], Bytes::new()),
    )
    .await;
    let reset = send_h2(
        &mut sender,
        h2_request(
            "/reset",
            &[cookie.as_str()],
            Bytes::from_static(b"one-attempt"),
        ),
    )
    .await;
    assert_eq!(reset.status(), StatusCode::OK);
    assert!(
        reset.into_body().collect().await.is_err(),
        "upstream body reset was hidden"
    );

    let after = send_h2(
        &mut sender,
        h2_request("/after-reset", &[cookie.as_str()], Bytes::new()),
    )
    .await;
    assert_eq!(after.status(), StatusCode::OK);
    after
        .into_body()
        .collect()
        .await
        .expect("sibling generation survived reset");
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);
    {
        let observations = fixture.state.observed.lock().expect("reset observations");
        assert_eq!(
            observations
                .iter()
                .filter(|request| request.target.ends_with("/base/reset"))
                .count(),
            1,
            "non-idempotent reset request was replayed"
        );
        assert_eq!(
            observations
                .iter()
                .find(|request| request.target.ends_with("/base/reset"))
                .expect("reset observation")
                .body,
            b"one-attempt"
        );
    }

    fixture.state.sse_release.add_permits(1);
    sibling
        .into_body()
        .collect()
        .await
        .expect("sibling body completed");
    drop(sender);
    client_task.abort();
    gateway.task.abort();
    fixture.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn goaway_and_refused_stream_before_and_after_dispatch_never_replay_request_body() {
    for mode in [
        H2NoReplayFailure::GoawayBeforeDispatch,
        H2NoReplayFailure::GoawayAfterDispatch,
        H2NoReplayFailure::RefusedBeforeBody,
        H2NoReplayFailure::RefusedAfterBody,
    ] {
        let fixture = start_h2_no_replay_fixture(mode).await;
        let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
            .expect("no-replay upstream URL")
            .expect("no-replay upstream");
        let gateway = start_gateway_with_options(
            Some(upstream),
            SessionMode::Allowed,
            None,
            GatewayOptions {
                max_active_upstreams: 1,
                upstream_protocol: Some(UpstreamProtocol::Http2),
                ..GatewayOptions::default()
            },
        )
        .await;
        let cookie = gateway.cookie.as_deref().expect("no-replay cookie");
        let body = vec![b'x'; 4096];
        let request = format!(
            "POST /no-replay HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let response = request_once(
            gateway.address,
            &format!("{request}{}", String::from_utf8_lossy(&body)),
        )
        .await;
        assert!(!response.is_empty(), "empty gateway response for {mode:?}");
        assert_status(&response, 502);
        tokio::time::sleep(TokioDuration::from_millis(100)).await;
        assert_eq!(
            fixture.state.connections.load(Ordering::SeqCst),
            1,
            "request was retried on a new connection for {mode:?}"
        );
        assert_eq!(
            fixture.state.request_headers.load(Ordering::SeqCst),
            usize::from(!matches!(mode, H2NoReplayFailure::GoawayBeforeDispatch)),
            "unexpected dispatch count for {mode:?}"
        );
        if matches!(mode, H2NoReplayFailure::RefusedAfterBody) {
            assert_eq!(fixture.state.data_frames.load(Ordering::SeqCst), 1);
            assert!(fixture.state.body_bytes.load(Ordering::SeqCst) > 0);
            assert!(fixture.state.body_bytes.load(Ordering::SeqCst) <= body.len());
        } else {
            assert_eq!(fixture.state.data_frames.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.state.body_bytes.load(Ordering::SeqCst), 0);
        }
        gateway.task.abort();
        fixture.task.abort();
    }
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
async fn h2_early_final_flow_control_holds_two_half_ownership_until_body_drop() {
    let fixture = start_h2_early_final_flow_control_fixture().await;
    let upstream = parse_upstream_url(Some(&format!("http://{}/base", fixture.address)))
        .expect("H2 early-final URL")
        .expect("H2 early-final upstream");
    let gateway = start_gateway_with_options(
        Some(upstream),
        SessionMode::Allowed,
        None,
        GatewayOptions {
            max_downstream_connections: 17,
            max_active_upstreams: 1,
            max_blocking_resolvers: 1,
            upstream_protocol: Some(UpstreamProtocol::Http2),
            ..GatewayOptions::default()
        },
    )
    .await;
    let cookie = gateway.cookie.as_deref().expect("H2 early-final cookie");
    let (mut sender, client_task) = open_h2(gateway.address).await;
    sender.ready().await.expect("H2 early-final ready");
    let response = sender.send_request(h2_request(
        "/early-flow-control",
        &[&format!("amg_session={cookie}")],
        Bytes::from(vec![0x5a; 32 * 1024]),
    ));
    let held = timeout(
        TokioDuration::from_secs(2),
        fixture.state.body_held.acquire(),
    )
    .await
    .expect("upstream request body was not held")
    .expect("body-held semaphore");
    held.forget();
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    fixture.state.allow_response.add_permits(1);
    let response = response.await.expect("H2 early-final response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    response
        .into_body()
        .collect()
        .await
        .expect("H2 early-final response body");

    let u_saturated = request_once(
        gateway.address,
        &format!(
            "GET /while-h2-body-buffered HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_status(&u_saturated, 503);
    let downstream_saturated = send_h2(
        &mut sender,
        h2_request(
            "/while-downstream-request-half-held",
            &[&format!("amg_session={cookie}")],
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(
        downstream_saturated.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    downstream_saturated
        .into_body()
        .collect()
        .await
        .expect("downstream saturation body");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);

    fixture.state.release_body.add_permits(1);
    let dropped = timeout(
        TokioDuration::from_secs(2),
        fixture.state.body_dropped.acquire(),
    )
    .await
    .expect("upstream body drop timeout")
    .expect("body-dropped semaphore");
    dropped.forget();
    let after = timeout(TokioDuration::from_secs(2), async {
        loop {
            let response = request_once(
                gateway.address,
                &format!(
                    "GET /after-h2-body-drop HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
                ),
            )
            .await;
            if !response.starts_with(b"HTTP/1.1 503") {
                break response;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("H2 body-drop ownership did not release");
    assert_status(&after, 413);
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.state.connections.load(Ordering::SeqCst), 1);

    drop(sender);
    client_task.abort();
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
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nOrigin: https://public.example/not-an-origin\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        ),
        format!(
            "GET /ws HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Accept: forbidden\r\n\r\n"
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
            upstream_protocol: None,
            service_call_counter: None,
            auth_decision_counter: None,
            upstream_admission_counter: None,
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
            upstream_protocol: None,
            service_call_counter: None,
            auth_decision_counter: None,
            upstream_admission_counter: None,
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
fn upstream_protocol_startup_failures_are_value_neutral() {
    const SECRET: &str = "startup-protocol-secret-at-least-32-characters";
    const INVALID_PROTOCOL: &str = "raw-invalid-protocol-marker";
    let invalid = Command::new(env!("CARGO_BIN_EXE_auth-mini-gateway"))
        .env("GATEWAY_COOKIE_SECRET", SECRET)
        .env("UPSTREAM_PROTOCOL", INVALID_PROTOCOL)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .expect("run invalid protocol startup");
    assert!(!invalid.status.success());
    let stderr = String::from_utf8(invalid.stderr).expect("invalid protocol stderr");
    assert_eq!(stderr.matches("process_exit").count(), 1, "{stderr}");
    assert!(stderr.contains("upstream_protocol_invalid"));
    assert!(!stderr.contains(INVALID_PROTOCOL));

    const RAW_URL_MARKER: &str = "raw-cleartext-origin-marker.invalid";
    for protocol in [None, Some("")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_auth-mini-gateway"));
        command
            .env("GATEWAY_COOKIE_SECRET", SECRET)
            .env("UPSTREAM_URL", format!("http://{RAW_URL_MARKER}:4096/base"))
            .stderr(Stdio::piped())
            .stdout(Stdio::piped());
        match protocol {
            Some(value) => {
                command.env("UPSTREAM_PROTOCOL", value);
            }
            None => {
                command.env_remove("UPSTREAM_PROTOCOL");
            }
        }
        let output = command.output().expect("run cleartext auto startup");
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).expect("cleartext auto stderr");
        assert_eq!(stderr.matches("process_exit").count(), 1, "{stderr}");
        assert!(stderr.contains("upstream_protocol_cleartext_auto"));
        assert!(!stderr.contains(RAW_URL_MARKER));
    }
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
        .env("UPSTREAM_PROTOCOL", "http1")
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
        .env("UPSTREAM_PROTOCOL", "http1")
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
async fn successful_selected_h2_logs_are_exact_and_secret_free() {
    const COOKIE_SECRET: &str = "selected-log-cookie-secret-never-emit-32";
    const AUTH_SESSION_ID: &str = "selected-log-auth-session-never-emit";
    const ACCESS_TOKEN: &str = "selected-log-access-token-never-emit";
    const REFRESH_TOKEN: &str = "selected-log-refresh-token-never-emit";
    const COOKIE_MARKER: &str = "selected-cookie-header-marker-never-emit";
    const TOKEN_MARKER: &str = "selected-browser-token-marker-never-emit";
    const AUTHORITY_MARKER: &str = "selected-authority-marker.example";

    let fixture = start_h2_fixture(100).await;
    let dir = tempfile::tempdir().expect("selected-log tempdir");
    let database = dir.path().join("gateway.sqlite");
    Store::initialize(&database).expect("selected-log store");
    let session = Store::new(database.clone())
        .create_session(NewSession {
            auth_session_id: AUTH_SESSION_ID.to_string(),
            access_token: ACCESS_TOKEN.to_string(),
            refresh_token: REFRESH_TOKEN.to_string(),
            user_id: "selected-log-user".to_string(),
            email: Some("selected-log-user@example.com".to_string()),
            amr: vec!["test".to_string()],
            access_expires_at: Utc::now() + Duration::hours(2),
            idle_ttl_seconds: 604_800,
            absolute_ttl_seconds: 2_592_000,
        })
        .expect("selected-log session");
    let signed_cookie = sign_value(&session.id, COOKIE_SECRET);
    let key_marker = STANDARD.encode(b"log-key-marker!!");
    let address = unused_address().await;
    let mut child = Command::new(env!("CARGO_BIN_EXE_auth-mini-gateway"))
        .env("HOST", "127.0.0.1")
        .env("PORT", address.port().to_string())
        .env(
            "GATEWAY_PUBLIC_BASE_URL",
            format!("http://{AUTHORITY_MARKER}"),
        )
        .env("AUTH_MINI_ISSUER", "http://127.0.0.1:9")
        .env("AUTH_MINI_PUBLIC_BASE_URL", "http://127.0.0.1:9")
        .env("GATEWAY_DB", &database)
        .env("GATEWAY_COOKIE_SECRET", COOKIE_SECRET)
        .env("COOKIE_SECURE", "false")
        .env("ALLOW_USER_IDS", "selected-log-user")
        .env("UPSTREAM_URL", format!("http://{}/base", fixture.address))
        .env("UPSTREAM_PROTOCOL", "http2")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn selected-log gateway");
    wait_for_gateway_at_authority(address, AUTHORITY_MARKER).await;

    let mut socket = TcpStream::connect(address)
        .await
        .expect("selected-log websocket connect");
    socket
        .write_all(
            format!(
                "GET /ws HTTP/1.1\r\nHost: {AUTHORITY_MARKER}\r\nCookie: marker={COOKIE_MARKER}; amg_session={signed_cookie}\r\nAuthorization: Bearer {TOKEN_MARKER}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key_marker}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("selected-log websocket request");
    let response = timeout(TokioDuration::from_secs(2), read_head(&mut socket))
        .await
        .expect("selected-log websocket response timeout");
    assert!(response.starts_with("HTTP/1.1 101"), "{response}");
    socket
        .write_all(b"ping")
        .await
        .expect("selected-log websocket ping");
    let mut pong = [0_u8; 4];
    socket
        .read_exact(&mut pong)
        .await
        .expect("selected-log websocket pong");
    assert_eq!(&pong, b"pong");
    assert_eq!(fixture.state.hits.load(Ordering::SeqCst), 1);
    {
        let observed = fixture
            .state
            .websocket_observed
            .lock()
            .expect("selected-log observation");
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].version, Version::HTTP_2);
        assert!(!observed[0].headers.contains_key("cookie"));
        assert!(!observed[0].headers.contains_key("authorization"));
        assert!(!observed[0].headers.contains_key("sec-websocket-key"));
    }
    drop(socket);

    child.kill().expect("stop selected-log gateway");
    let output = child
        .wait_with_output()
        .expect("capture selected-log gateway output");
    let mut raw_logs = output.stdout;
    raw_logs.extend_from_slice(&output.stderr);
    let logs = strip_ansi(&String::from_utf8_lossy(&raw_logs));
    let protocol_events: Vec<_> = logs
        .lines()
        .filter(|line| log_field(line, "event") == Some("upstream_protocol_selected"))
        .collect();
    let dispatch_events: Vec<_> = logs
        .lines()
        .filter(|line| log_field(line, "event") == Some("upstream_dispatch_selected"))
        .collect();
    assert_eq!(protocol_events.len(), 1, "{logs}");
    assert_eq!(dispatch_events.len(), 1, "{logs}");

    let protocol = protocol_events[0];
    assert_log_field_names(
        protocol,
        &[
            "configured",
            "event",
            "extended_connect",
            "generation",
            "protocol",
            "source",
            "transport",
        ],
    );
    assert_eq!(log_field(protocol, "configured"), Some("http2"));
    assert_eq!(log_field(protocol, "transport"), Some("cleartext"));
    assert_eq!(log_field(protocol, "protocol"), Some("http2"));
    assert_eq!(log_field(protocol, "source"), Some("forced"));
    assert_eq!(log_field(protocol, "extended_connect"), Some("true"));
    let generation = log_field(protocol, "generation")
        .expect("selected protocol generation")
        .parse::<u64>()
        .expect("numeric selected protocol generation");
    assert_ne!(generation, 0);

    let dispatch = dispatch_events[0];
    assert_log_field_names(
        dispatch,
        &["event", "generation", "generation_present", "protocol"],
    );
    assert_eq!(log_field(dispatch, "protocol"), Some("http2"));
    assert_eq!(log_field(dispatch, "generation_present"), Some("true"));
    assert_eq!(
        log_field(dispatch, "generation")
            .expect("dispatch generation")
            .parse::<u64>()
            .expect("numeric dispatch generation"),
        generation
    );

    for marker in [
        COOKIE_SECRET,
        AUTH_SESSION_ID,
        ACCESS_TOKEN,
        REFRESH_TOKEN,
        COOKIE_MARKER,
        TOKEN_MARKER,
        AUTHORITY_MARKER,
        signed_cookie.as_str(),
        key_marker.as_str(),
    ] {
        assert!(!logs.contains(marker), "selected log leaked marker");
    }

    fixture.task.abort();
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
    let service_call_counter = options.service_call_counter.clone();
    let auth_decision_counter = options.auth_decision_counter.clone();
    let upstream_admission_counter = options.upstream_admission_counter.clone();
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
    let upstream_protocol = options.upstream_protocol.unwrap_or_else(|| {
        if upstream.is_some() {
            UpstreamProtocol::Http1
        } else {
            UpstreamProtocol::Auto
        }
    });
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
        upstream_protocol,
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
    let before_service_call: Arc<dyn Fn() + Send + Sync> = match service_call_counter {
        Some(counter) => Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }),
        None => Arc::new(|| {}),
    };
    let before_auth_decision: Arc<dyn Fn() + Send + Sync> = match auth_decision_counter {
        Some(counter) => Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }),
        None => Arc::new(|| {}),
    };
    let before_upstream_admission: Arc<dyn Fn() + Send + Sync> = match upstream_admission_counter {
        Some(counter) => Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }),
        None => Arc::new(|| {}),
    };
    let task = tokio::spawn(async move {
        let _ = run_server_with_listener_and_roots_and_hooks(
            config,
            Arc::new(NoopAuth),
            listener,
            roots,
            before_service_call,
            before_auth_decision,
            before_upstream_admission,
        )
        .await;
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

async fn start_h2_fixture(max_concurrent_streams: u32) -> RunningFixture {
    start_h2_fixture_with_connect(max_concurrent_streams, true).await
}

async fn start_h2_fixture_with_connect(
    max_concurrent_streams: u32,
    enable_connect_protocol: bool,
) -> RunningFixture {
    let state = Arc::new(FixtureState::default());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("H2 fixture bind");
    let address = listener.local_addr().expect("H2 fixture address");
    let task_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            task_state.connections.fetch_add(1, Ordering::SeqCst);
            let state = Arc::clone(&task_state);
            tokio::spawn(async move {
                let service =
                    service_fn(move |request| fixture_response(request, Arc::clone(&state)));
                let mut builder = server_http2::Builder::new(TokioExecutor::new());
                builder
                    .max_concurrent_streams(max_concurrent_streams)
                    .max_header_list_size(16_384);
                if enable_connect_protocol {
                    builder.enable_connect_protocol();
                }
                let _ = builder
                    .serve_connection(TokioIo::new(stream), service)
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

async fn start_h2_early_final_flow_control_fixture() -> RunningH2EarlyFinalFixture {
    let state = Arc::new(H2EarlyFinalState {
        hits: AtomicUsize::new(0),
        connections: AtomicUsize::new(0),
        body_held: Semaphore::new(0),
        allow_response: Semaphore::new(0),
        release_body: Semaphore::new(0),
        body_dropped: Semaphore::new(0),
    });
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("H2 early-final fixture bind");
    let address = listener
        .local_addr()
        .expect("H2 early-final fixture address");
    let task_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            task_state.connections.fetch_add(1, Ordering::SeqCst);
            let state = Arc::clone(&task_state);
            tokio::spawn(async move {
                let mut stream = stream;
                let mut preface = [0_u8; 24];
                if stream.read_exact(&mut preface).await.is_err()
                    || &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                {
                    return;
                }
                loop {
                    let Ok(Some(frame)) = read_raw_h2_frame(&mut stream).await else {
                        return;
                    };
                    if frame.frame_type == 0x4 && frame.flags & 0x1 == 0 {
                        break;
                    }
                }
                let settings = [
                    0, 3, 0, 0, 0, 1, // one concurrent stream
                    0, 4, 0, 0, 0, 0, // zero initial stream window
                    0, 8, 0, 0, 0, 1, // extended CONNECT enabled
                ];
                if stream
                    .write_all(&raw_h2_frame(0x4, 0, 0, &settings))
                    .await
                    .is_err()
                {
                    return;
                }
                loop {
                    let Ok(Some(frame)) = read_raw_h2_frame(&mut stream).await else {
                        return;
                    };
                    if frame.frame_type == 0x4 && frame.flags & 0x1 != 0 {
                        break;
                    }
                }
                let first_stream = loop {
                    let Ok(Some(frame)) = read_raw_h2_frame(&mut stream).await else {
                        return;
                    };
                    if frame.frame_type == 0x1 && frame.stream_id != 0 {
                        break frame.stream_id;
                    }
                };
                state.hits.fetch_add(1, Ordering::SeqCst);
                state.body_held.add_permits(1);
                if let Ok(permit) = state.allow_response.acquire().await {
                    permit.forget();
                }
                let status_413 = [0x08, 0x03, b'4', b'1', b'3'];
                if stream
                    .write_all(&raw_h2_frame(0x1, 0x5, first_stream, &status_413))
                    .await
                    .is_err()
                {
                    return;
                }
                if let Ok(permit) = state.release_body.acquire().await {
                    permit.forget();
                }
                if stream
                    .write_all(&raw_h2_frame(
                        0x8,
                        0,
                        first_stream,
                        &65_535_u32.to_be_bytes(),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
                loop {
                    let Ok(Some(frame)) = read_raw_h2_frame(&mut stream).await else {
                        return;
                    };
                    if frame.frame_type == 0x0
                        && frame.stream_id == first_stream
                        && frame.flags & 0x1 != 0
                    {
                        break;
                    }
                }
                state.body_dropped.add_permits(1);
                loop {
                    let Ok(Some(frame)) = read_raw_h2_frame(&mut stream).await else {
                        return;
                    };
                    if frame.frame_type == 0x1 && frame.stream_id != first_stream {
                        state.hits.fetch_add(1, Ordering::SeqCst);
                        let _ = stream
                            .write_all(&raw_h2_frame(0x1, 0x5, frame.stream_id, &status_413))
                            .await;
                        break;
                    }
                }
            });
        }
    });
    RunningH2EarlyFinalFixture {
        address,
        state,
        task,
    }
}

async fn raw_h2_server_handshake(stream: &mut TcpStream, settings: &[u8]) -> bool {
    let mut preface = [0_u8; 24];
    if stream.read_exact(&mut preface).await.is_err()
        || &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    {
        return false;
    }
    loop {
        let Ok(Some(frame)) = read_raw_h2_frame(stream).await else {
            return false;
        };
        if frame.frame_type == 0x4 && frame.flags & 0x1 == 0 {
            break;
        }
    }
    if stream
        .write_all(&raw_h2_frame(0x4, 0, 0, settings))
        .await
        .is_err()
    {
        return false;
    }
    loop {
        let Ok(Some(frame)) = read_raw_h2_frame(stream).await else {
            return false;
        };
        if frame.frame_type == 0x4 && frame.flags & 0x1 != 0 {
            return true;
        }
    }
}

async fn next_raw_h2_headers(stream: &mut TcpStream) -> Option<u32> {
    loop {
        let Ok(Some(frame)) = read_raw_h2_frame(stream).await else {
            return None;
        };
        if frame.frame_type == 0x1 && frame.stream_id != 0 {
            return Some(frame.stream_id);
        }
    }
}

async fn start_h2_revocation_fixture() -> RunningH2RevocationFixture {
    let state = Arc::new(H2RevocationState {
        connections: AtomicUsize::new(0),
        request_headers: AtomicUsize::new(0),
        sibling_seen: Semaphore::new(0),
        candidate_seen: Semaphore::new(0),
        release_revocation: Semaphore::new(0),
        transport_closed: Semaphore::new(0),
    });
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("H2 revocation fixture bind");
    let address = listener
        .local_addr()
        .expect("H2 revocation fixture address");
    let task_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let connection_number = task_state.connections.fetch_add(1, Ordering::SeqCst) + 1;
            let state = Arc::clone(&task_state);
            tokio::spawn(async move {
                let settings = [
                    0, 3, 0, 0, 0, 8, // concurrent streams
                    0, 8, 0, 0, 0, 1, // extended CONNECT enabled
                ];
                if !raw_h2_server_handshake(&mut stream, &settings).await {
                    return;
                }
                if connection_number != 1 {
                    let Some(stream_id) = next_raw_h2_headers(&mut stream).await else {
                        return;
                    };
                    state.request_headers.fetch_add(1, Ordering::SeqCst);
                    let _ = stream
                        .write_all(&raw_h2_frame(0x1, 0x5, stream_id, &[0x88]))
                        .await;
                    return;
                }

                let Some(warm_stream) = next_raw_h2_headers(&mut stream).await else {
                    return;
                };
                state.request_headers.fetch_add(1, Ordering::SeqCst);
                if stream
                    .write_all(&raw_h2_frame(0x1, 0x5, warm_stream, &[0x88]))
                    .await
                    .is_err()
                {
                    return;
                }

                let Some(sibling_stream) = next_raw_h2_headers(&mut stream).await else {
                    return;
                };
                state.request_headers.fetch_add(1, Ordering::SeqCst);
                if stream
                    .write_all(&raw_h2_frame(0x1, 0x4, sibling_stream, &[0x88]))
                    .await
                    .is_err()
                    || stream
                        .write_all(&raw_h2_frame(0x0, 0, sibling_stream, b"held"))
                        .await
                        .is_err()
                {
                    return;
                }
                state.sibling_seen.add_permits(1);

                let Some(candidate_stream) = next_raw_h2_headers(&mut stream).await else {
                    return;
                };
                state.request_headers.fetch_add(1, Ordering::SeqCst);
                state.candidate_seen.add_permits(1);
                if let Ok(permit) = state.release_revocation.acquire().await {
                    permit.forget();
                }
                let revoke = raw_h2_frame(0x4, 0, 0, &[0, 8, 0, 0, 0, 0]);
                for byte in revoke.chunks(1) {
                    if stream.write_all(byte).await.is_err() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }

                let mut byte = [0_u8; 1];
                let _ = timeout(TokioDuration::from_secs(2), async {
                    loop {
                        match stream.read(&mut byte).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                })
                .await;
                state.transport_closed.add_permits(1);
                let _ = candidate_stream;
            });
        }
    });
    RunningH2RevocationFixture {
        address,
        state,
        task,
    }
}

async fn start_h2_no_replay_fixture(mode: H2NoReplayFailure) -> RunningH2NoReplayFixture {
    let state = Arc::new(H2NoReplayState {
        connections: AtomicUsize::new(0),
        request_headers: AtomicUsize::new(0),
        data_frames: AtomicUsize::new(0),
        body_bytes: AtomicUsize::new(0),
    });
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("H2 no-replay fixture bind");
    let address = listener.local_addr().expect("H2 no-replay fixture address");
    let task_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            task_state.connections.fetch_add(1, Ordering::SeqCst);
            let state = Arc::clone(&task_state);
            tokio::spawn(async move {
                let settings = [0, 3, 0, 0, 0, 8];
                if matches!(mode, H2NoReplayFailure::GoawayBeforeDispatch) {
                    let mut preface = [0_u8; 24];
                    if stream.read_exact(&mut preface).await.is_err() {
                        return;
                    }
                    loop {
                        let Ok(Some(frame)) = read_raw_h2_frame(&mut stream).await else {
                            return;
                        };
                        if frame.frame_type == 0x4 && frame.flags & 0x1 == 0 {
                            break;
                        }
                    }
                    let mut frames = raw_h2_frame(0x4, 0, 0, &settings);
                    frames.extend_from_slice(&raw_h2_frame(0x7, 0, 0, &[0; 8]));
                    let _ = stream.write_all(&frames).await;
                } else {
                    if !raw_h2_server_handshake(&mut stream, &settings).await {
                        return;
                    }
                    let Some(stream_id) = next_raw_h2_headers(&mut stream).await else {
                        return;
                    };
                    state.request_headers.fetch_add(1, Ordering::SeqCst);
                    match mode {
                        H2NoReplayFailure::GoawayAfterDispatch => {
                            let _ = stream.write_all(&raw_h2_frame(0x7, 0, 0, &[0; 8])).await;
                        }
                        H2NoReplayFailure::RefusedBeforeBody => {
                            let _ = stream
                                .write_all(&raw_h2_frame(0x3, 0, stream_id, &7_u32.to_be_bytes()))
                                .await;
                        }
                        H2NoReplayFailure::RefusedAfterBody => loop {
                            let Ok(Some(frame)) = read_raw_h2_frame(&mut stream).await else {
                                return;
                            };
                            if frame.frame_type == 0x0 && frame.stream_id == stream_id {
                                state.data_frames.fetch_add(1, Ordering::SeqCst);
                                state
                                    .body_bytes
                                    .fetch_add(frame.payload.len(), Ordering::SeqCst);
                                let _ = stream
                                    .write_all(&raw_h2_frame(
                                        0x3,
                                        0,
                                        stream_id,
                                        &7_u32.to_be_bytes(),
                                    ))
                                    .await;
                                break;
                            }
                        },
                        H2NoReplayFailure::GoawayBeforeDispatch => unreachable!(),
                    }
                }
                let mut byte = [0_u8; 1];
                let _ = timeout(TokioDuration::from_millis(250), async {
                    loop {
                        match stream.read(&mut byte).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                })
                .await;
            });
        }
    });
    RunningH2NoReplayFixture {
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
        command
            .env("UPSTREAM_URL", upstream)
            .env("UPSTREAM_PROTOCOL", "http1");
    } else {
        command
            .env_remove("UPSTREAM_URL")
            .env_remove("UPSTREAM_PROTOCOL");
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

async fn start_tls_h2_fixture() -> RunningTlsFixture {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("H2 test certificate");
    let certificate = cert.der().clone();
    let private_key = PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into();
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], private_key)
        .expect("H2 TLS server config");
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let state = Arc::new(FixtureState::default());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TLS H2 fixture bind");
    let address = listener.local_addr().expect("TLS H2 fixture address");
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
                let mut builder = server_http2::Builder::new(TokioExecutor::new());
                builder
                    .max_concurrent_streams(100_u32)
                    .max_header_list_size(16_384)
                    .enable_connect_protocol();
                let _ = builder
                    .serve_connection(TokioIo::new(stream), service)
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

async fn start_mixed_tls_fixture() -> RunningTlsFixture {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("mixed certificate");
    let certificate = cert.der().clone();
    let key_der = signing_key.serialize_der();
    let mut h1_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            PrivatePkcs8KeyDer::from(key_der.clone()).into(),
        )
        .expect("mixed H1 TLS config");
    h1_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut h2_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            PrivatePkcs8KeyDer::from(key_der).into(),
        )
        .expect("mixed H2 TLS config");
    h2_config.alpn_protocols = vec![b"h2".to_vec()];
    let h1_acceptor = TlsAcceptor::from(Arc::new(h1_config));
    let h2_acceptor = TlsAcceptor::from(Arc::new(h2_config));
    let state = Arc::new(FixtureState::default());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mixed TLS fixture bind");
    let address = listener.local_addr().expect("mixed TLS fixture address");
    let task_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        let mut accepted = 0_usize;
        while let Ok((stream, _)) = listener.accept().await {
            let use_h1 = accepted == 0;
            accepted += 1;
            let acceptor = if use_h1 {
                h1_acceptor.clone()
            } else {
                h2_acceptor.clone()
            };
            let state = Arc::clone(&task_state);
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                state.connections.fetch_add(1, Ordering::SeqCst);
                let service =
                    service_fn(move |request| fixture_response(request, Arc::clone(&state)));
                if use_h1 {
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .with_upgrades()
                        .await;
                } else {
                    let mut builder = server_http2::Builder::new(TokioExecutor::new());
                    builder
                        .max_concurrent_streams(1_u32)
                        .max_header_list_size(16_384);
                    let _ = builder
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                }
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
    let websocket_path = matches!(
        request.uri().path(),
        "/base/ws"
            | "/base/ws-framed"
            | "/base/bad-ws"
            | "/base/bad-protocol-ws"
            | "/base/bad-extension-ws"
            | "/base/nominated-accept-ws"
            | "/base/nominated-protocol-ws"
            | "/base/nominated-extension-ws"
    );
    let h2_websocket = request.version() == Version::HTTP_2
        && request.method() == http::Method::CONNECT
        && request
            .extensions()
            .get::<hyper::ext::Protocol>()
            .is_some_and(|protocol| protocol.as_ref() == b"websocket");
    let h1_websocket = request.version() == Version::HTTP_11
        && request.method() == http::Method::GET
        && request
            .headers()
            .get(UPGRADE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if websocket_path && (h1_websocket || h2_websocket) {
        let path = request.uri().path().to_string();
        let invalid_accept = path == "/base/bad-ws";
        state
            .websocket_observed
            .lock()
            .expect("websocket observed")
            .push(Observed {
                method: request.method().to_string(),
                target: request.uri().to_string(),
                version: request.version(),
                headers: request.headers().clone(),
                body_len: 0,
                body: Vec::new(),
            });
        let key = request
            .headers()
            .get("sec-websocket-key")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if matches!(path.as_str(), "/base/ws" | "/base/ws-framed") || h2_websocket {
            let upgrade = hyper::upgrade::on(&mut request);
            let upgrade_path = path.clone();
            let upgrade_state = Arc::clone(&state);
            tokio::spawn(async move {
                if let Ok(upgraded) = upgrade.await {
                    let mut upgraded = TokioIo::new(upgraded);
                    if upgrade_path == "/base/ws" {
                        let mut ping = [0u8; 4];
                        if upgraded.read_exact(&mut ping).await.is_ok() && &ping == b"ping" {
                            let _ = upgraded.write_all(b"pong").await;
                        }
                    } else if upgrade_path == "/base/ws-framed" {
                        let mut frame = [0_u8; 10];
                        if upgraded.read_exact(&mut frame).await.is_ok()
                            && frame == masked_ping_frame()
                        {
                            let _ = upgraded.write_all(&text_pong_frame()).await;
                        }
                    } else {
                        let mut byte = [0_u8; 1];
                        let _ = upgraded.read(&mut byte).await;
                        upgrade_state.rejected_upgrade_dropped.add_permits(1);
                    }
                }
            });
        }
        let mut response = Response::new(empty_body());
        *response.status_mut() = if h2_websocket {
            StatusCode::OK
        } else {
            StatusCode::SWITCHING_PROTOCOLS
        };
        if h1_websocket {
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
        } else if invalid_accept {
            response.headers_mut().insert(
                "sec-websocket-accept",
                HeaderValue::from_static("forbidden-on-h2"),
            );
        }
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
    let version = request.version();
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
        version,
        headers,
        body_len,
        body: body_bytes,
    });
    if request.uri().path() == "/base/reset" {
        return Ok(Response::new(
            ResetBody {
                stage: 0,
                delay: None,
            }
            .boxed_unsync(),
        ));
    }
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

struct ResetBody {
    stage: u8,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Body for ResetBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.stage {
            0 => {
                self.stage = 1;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"partial")))))
            }
            1 => {
                let delay = self.delay.get_or_insert_with(|| {
                    Box::pin(tokio::time::sleep(TokioDuration::from_millis(50)))
                });
                if std::future::Future::poll(delay.as_mut(), _context).is_pending() {
                    Poll::Pending
                } else {
                    self.stage = 2;
                    Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                        "allowlisted H2 stream reset fixture",
                    )))))
                }
            }
            _ => Poll::Ready(None),
        }
    }
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

#[derive(Debug)]
struct RawH2Frame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

async fn raw_h2_connection(address: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("raw H2 connection");
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .expect("raw H2 preface");
    stream
        .write_all(&raw_h2_frame(0x4, 0, 0, &[]))
        .await
        .expect("raw H2 client SETTINGS");
    timeout(TokioDuration::from_secs(2), async {
        loop {
            let frame = read_raw_h2_frame(&mut stream)
                .await
                .expect("raw H2 handshake frame")
                .expect("raw H2 handshake EOF");
            if frame.frame_type == 0x4 && frame.flags & 0x1 == 0 {
                assert_eq!(frame.stream_id, 0);
                stream
                    .write_all(&raw_h2_frame(0x4, 0x1, 0, &[]))
                    .await
                    .expect("raw H2 SETTINGS ACK");
                break;
            }
        }
    })
    .await
    .expect("raw H2 server SETTINGS timeout");
    stream
}

async fn send_raw_extended_connect(
    stream: &mut TcpStream,
    cookie: &str,
    content_length: Option<u64>,
) {
    let mut block = Vec::new();
    for (name, value) in [
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":scheme", "https"),
        (":authority", "public.example"),
        (":path", "/ws"),
        ("sec-websocket-version", "13"),
        ("cookie", cookie),
    ] {
        raw_hpack_literal(&mut block, name, value);
    }
    if let Some(content_length) = content_length {
        raw_hpack_literal(&mut block, "content-length", &content_length.to_string());
    }
    stream
        .write_all(&raw_h2_frame(0x1, 0x4, 1, &block))
        .await
        .expect("raw H2 Extended CONNECT HEADERS");
}

fn raw_hpack_literal(block: &mut Vec<u8>, name: &str, value: &str) {
    block.push(0x00);
    raw_hpack_string(block, name.as_bytes());
    raw_hpack_string(block, value.as_bytes());
}

fn raw_hpack_string(block: &mut Vec<u8>, value: &[u8]) {
    raw_hpack_integer(block, value.len(), 7, 0);
    block.extend_from_slice(value);
}

fn raw_hpack_integer(block: &mut Vec<u8>, value: usize, prefix_bits: u8, marker: u8) {
    let prefix_max = (1_usize << prefix_bits) - 1;
    if value < prefix_max {
        block.push(marker | value as u8);
        return;
    }
    block.push(marker | prefix_max as u8);
    let mut remaining = value - prefix_max;
    while remaining >= 128 {
        block.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    block.push(remaining as u8);
}

fn raw_h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 0x00ff_ffff);
    let length = payload.len();
    let stream_id = stream_id & 0x7fff_ffff;
    let mut frame = Vec::with_capacity(9 + length);
    frame.extend_from_slice(&[
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
        frame_type,
        flags,
    ]);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn read_raw_h2_frame(stream: &mut TcpStream) -> std::io::Result<Option<RawH2Frame>> {
    let mut header = [0_u8; 9];
    let first = stream.read(&mut header[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await?;
    let length = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    Ok(Some(RawH2Frame {
        frame_type: header[3],
        flags: header[4],
        stream_id: u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff,
        payload,
    }))
}

async fn open_h2(address: SocketAddr) -> (http2::SendRequest<Full<Bytes>>, JoinHandle<()>) {
    let stream = TcpStream::connect(address)
        .await
        .expect("connect H2 client");
    let (sender, connection) = http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
        .await
        .expect("H2 prior-knowledge handshake");
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, task)
}

fn h2_request(path: &str, cookies: &[&str], body: Bytes) -> Request<Full<Bytes>> {
    let mut request = Request::builder()
        .method(if body.is_empty() { "GET" } else { "POST" })
        .version(Version::HTTP_2)
        .uri(format!("https://public.example{path}"))
        .body(Full::new(body))
        .expect("valid H2 request");
    for cookie in cookies {
        request.headers_mut().append(
            http::header::COOKIE,
            HeaderValue::from_str(cookie).expect("valid fixture Cookie"),
        );
    }
    request
}

fn h2_websocket_request(
    path: &str,
    session_cookie: &str,
    protocol: Option<&str>,
) -> Request<Full<Bytes>> {
    let mut request = Request::builder()
        .method("CONNECT")
        .version(Version::HTTP_2)
        .uri(format!("https://public.example{path}"))
        .header("sec-websocket-version", "13")
        .header("origin", "https://public.example")
        .header("authorization", "Bearer browser-secret")
        .header("proxy-authorization", "Basic proxy-secret")
        .header("x-auth-mini-user-id", "forged")
        .header("x-forwarded-host", "attacker.example")
        .body(Full::new(Bytes::new()))
        .expect("valid H2 websocket request");
    request
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    request
        .headers_mut()
        .append(http::header::COOKIE, HeaderValue::from_static("theme=dark"));
    request.headers_mut().append(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("amg_session={session_cookie}"))
            .expect("websocket session Cookie"),
    );
    if let Some(protocol) = protocol {
        request.headers_mut().insert(
            "sec-websocket-protocol",
            HeaderValue::from_str(protocol).expect("websocket protocol"),
        );
    }
    request
}

async fn send_h2(
    sender: &mut http2::SendRequest<Full<Bytes>>,
    request: Request<Full<Bytes>>,
) -> Response<Incoming> {
    sender.ready().await.expect("H2 sender ready");
    timeout(TokioDuration::from_secs(5), sender.send_request(request))
        .await
        .expect("H2 response timeout")
        .expect("H2 response")
}

fn assert_h2_has_no_h1_hop_headers(headers: &HeaderMap) {
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        assert!(!headers.contains_key(name), "unexpected H1 field: {name}");
    }
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
    wait_for_gateway_at_authority(address, "public.example").await;
}

async fn wait_for_gateway_at_authority(address: SocketAddr, authority: &str) {
    for _ in 0..80 {
        if let Ok(mut stream) = TcpStream::connect(address).await {
            if stream
                .write_all(
                    format!(
                        "GET /healthz HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
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

fn strip_ansi(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'[') {
            index += 2;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if (0x40..=0x7e).contains(&byte) {
                    break;
                }
            }
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn log_field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.split_ascii_whitespace().find_map(|field| {
        let (field_name, value) = field.split_once('=')?;
        (field_name == name).then(|| value.trim_matches('"'))
    })
}

fn assert_log_field_names(line: &str, expected: &[&str]) {
    let mut actual: Vec<_> = line
        .split_ascii_whitespace()
        .filter_map(|field| field.split_once('=').map(|(name, _)| name))
        .collect();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected, "unexpected selected-protocol log fields");
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

fn masked_ping_frame() -> [u8; 10] {
    let mask = [1_u8, 2, 3, 4];
    let payload = *b"ping";
    [
        0x81,
        0x84,
        mask[0],
        mask[1],
        mask[2],
        mask[3],
        payload[0] ^ mask[0],
        payload[1] ^ mask[1],
        payload[2] ^ mask[2],
        payload[3] ^ mask[3],
    ]
}

fn text_pong_frame() -> [u8; 6] {
    [0x81, 0x04, b'p', b'o', b'n', b'g']
}

async fn unused_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("unused bind");
    let address = listener.local_addr().expect("unused address");
    drop(listener);
    address
}
