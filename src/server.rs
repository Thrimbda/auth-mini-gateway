use std::convert::Infallible;
use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use bytes::Bytes;
use chrono::{DateTime, Duration, TimeZone, Utc};
use http::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, EXPECT, HOST, SET_COOKIE};
use http::{HeaderValue, Method, StatusCode, Version};
use http_body_util::{BodyExt as _, Limited};
use hyper::body::{Body as _, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request as HyperRequest, Response as HyperResponse};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use url::{form_urlencoded, Url};

use crate::auth_mini::{
    AuthMini, AuthMiniClient, IdentityFetchOutcome, IdentityUnavailable, IndeterminateClass,
    RefreshError,
};
use crate::config::Config;
use crate::cookies::{
    clear_cookie, read_signed_cookie, serialize_signed_cookie, LOGIN_STATE_COOKIE, SESSION_COOKIE,
};
use crate::db::{
    CasResult, GatewaySession, IdentityState, NewSession, ObservedVersion, PendingTokens,
    SessionLookup, Store, TouchResult,
};
use crate::flight::{Acquire, FlightCoordinator, FlightLeader, FlightOutcome, RejectedReason};
use crate::http::{is_safe_header_value, Request, Response};
use crate::policy::{evaluate, Identity, PolicyDecision};
use crate::proxy::{
    empty_body, full_body, parse_websocket_request, GatewayBody, Proxy, ProxyError, ProxyIdentity,
};
use crate::return_target::{normalize_return_target, ReturnTargetMode};

const MAX_LOCAL_BODY: usize = 64 * 1024;
const OWNED_PATHS: [&str; 6] = [
    "/healthz",
    "/login",
    "/auth/callback",
    "/auth/callback/session",
    "/auth/check",
    "/logout",
];

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    store: Arc<Store>,
    auth_mini: Arc<dyn AuthMini>,
    flights: Arc<FlightCoordinator>,
    executor: AuthExecutor,
    proxy: Option<Proxy>,
    public_proto: String,
}

#[derive(Clone)]
struct AuthExecutor {
    admission: Arc<Semaphore>,
    work: Arc<Semaphore>,
}

#[derive(Debug)]
enum AuthExecutionError {
    Overloaded,
    Internal,
}

impl AuthExecutor {
    fn new() -> Self {
        Self::with_limits(64, 128)
    }

    fn with_limits(work: usize, admission: usize) -> Self {
        Self {
            admission: Arc::new(Semaphore::new(admission)),
            work: Arc::new(Semaphore::new(work)),
        }
    }

    async fn run<T, F>(&self, operation: F) -> Result<T, AuthExecutionError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let admission = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| AuthExecutionError::Overloaded)?;
        let work = Arc::clone(&self.work)
            .acquire_owned()
            .await
            .map_err(|_| AuthExecutionError::Internal)?;
        tokio::task::spawn_blocking(move || {
            let _permits = (admission, work);
            operation()
        })
        .await
        .map_err(|_| AuthExecutionError::Internal)
    }
}

pub async fn run_server(
    config: Config,
    auth_mini: Arc<AuthMiniClient>,
) -> Result<(), Box<dyn std::error::Error>> {
    let address = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(address).await?;
    let auth_mini: Arc<dyn AuthMini> = auth_mini;
    run_server_with_listener(config, auth_mini, listener).await
}

pub async fn run_server_with_listener(
    config: Config,
    auth_mini: Arc<dyn AuthMini>,
    listener: TcpListener,
) -> Result<(), Box<dyn std::error::Error>> {
    run_server_with_listener_and_roots(config, auth_mini, listener, None).await
}

pub async fn run_server_with_listener_and_roots(
    config: Config,
    auth_mini: Arc<dyn AuthMini>,
    listener: TcpListener,
    test_roots: Option<rustls::RootCertStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    let proxy = match (config.upstream.clone(), test_roots) {
        (Some(upstream), Some(roots)) => Some(Proxy::with_root_store(upstream, roots)),
        (Some(upstream), None) => Some(Proxy::new(upstream)),
        (None, _) => None,
    }
    .transpose()
    .map_err(|_| "failed to initialize UPSTREAM_URL transport")?;
    let public_proto = Url::parse(&config.public_base_url)?.scheme().to_string();
    tracing::info!(
        event = "server_start",
        mode = if proxy.is_some() { "proxy" } else { "adapter" }
    );
    let config = Arc::new(config);
    let state = AppState {
        store: Arc::new(Store::new(config.database_path.clone())),
        config,
        auth_mini,
        flights: Arc::new(FlightCoordinator::default()),
        executor: AuthExecutor::new(),
        proxy,
        public_proto,
    };

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle_hyper_request(request, peer, state).await) }
            });
            let mut builder = http1::Builder::new();
            builder
                .keep_alive(true)
                .max_headers(100)
                .header_read_timeout(StdDuration::from_secs(10))
                .timer(TokioTimer::new())
                .ignore_invalid_headers(false);
            let connection = builder
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            if connection.await.is_err() {
                tracing::debug!(event = "downstream_connection", outcome = "closed");
            }
        });
    }
}

async fn handle_hyper_request(
    request: HyperRequest<Incoming>,
    peer: SocketAddr,
    state: AppState,
) -> HyperResponse<GatewayBody> {
    let path = request.uri().path().to_string();
    if OWNED_PATHS.contains(&path.as_str()) {
        return handle_local_request(request, state, false).await;
    }
    if state.proxy.is_none() {
        return handle_local_request(request, state, true).await;
    }
    handle_proxy_fallback(request, peer, state).await
}

async fn handle_local_request(
    request: HyperRequest<Incoming>,
    state: AppState,
    adapter_fallback: bool,
) -> HyperResponse<GatewayBody> {
    let body_bearing = request_has_body(&request);
    if validate_expect(&request, body_bearing).is_err() {
        return generated_response(417, "Expectation failed", true, None);
    }
    let transfer_encoded = request
        .headers()
        .contains_key(http::header::TRANSFER_ENCODING);
    let declared_length = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared_length.is_some_and(|length| length > MAX_LOCAL_BODY) {
        return generated_response(400, "Bad request", true, None);
    }

    let (parts, body) = request.into_parts();
    let body = if transfer_encoded {
        Vec::new()
    } else {
        match Limited::new(body, MAX_LOCAL_BODY).collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(_) => return generated_response(400, "Bad request", true, None),
        }
    };
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let local_request = Request::new(
        parts.method.as_str().to_string(),
        parts.uri.to_string(),
        headers,
        body,
    );
    if adapter_fallback {
        return local_into_hyper(
            no_store(Response::text(404, "Not found")),
            body_bearing || transfer_encoded,
        );
    }

    let blocking = matches!(
        (local_request.method.as_str(), local_request.path.as_str()),
        ("GET", "/login")
            | ("POST", "/auth/callback/session")
            | ("GET", "/auth/check")
            | ("GET" | "POST", "/logout")
    );
    let response = if blocking {
        let config = Arc::clone(&state.config);
        let store = Arc::clone(&state.store);
        let auth_mini = Arc::clone(&state.auth_mini);
        let flights = Arc::clone(&state.flights);
        match state
            .executor
            .run(move || {
                handle_request(local_request, &config, &store, auth_mini.as_ref(), &flights)
                    .map_err(|_| ())
            })
            .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(AuthExecutionError::Internal) => {
                no_store(Response::text(500, "Internal server error"))
            }
            Err(AuthExecutionError::Overloaded) => auth_unavailable(),
        }
    } else {
        handle_request(
            local_request,
            &state.config,
            &state.store,
            state.auth_mini.as_ref(),
            &state.flights,
        )
        .unwrap_or_else(|_| no_store(Response::text(500, "Internal server error")))
    };
    local_into_hyper(response, body_bearing || transfer_encoded)
}

async fn handle_proxy_fallback(
    request: HyperRequest<Incoming>,
    peer: SocketAddr,
    state: AppState,
) -> HyperResponse<GatewayBody> {
    let body_bearing = request_has_body(&request);
    let path_and_query = match classify_fallback_target(&request) {
        Ok(value) => value,
        Err((status, body)) => return generated_response(status, body, true, None),
    };
    let Some(path_and_query) = normalize_return_target(
        Some(&path_and_query),
        &state.config.public_base_url,
        ReturnTargetMode::ProxyFallback,
    ) else {
        return generated_response(400, "Bad request", body_bearing, None);
    };
    if validate_expect(&request, body_bearing).is_err() {
        return generated_response(417, "Expectation failed", true, None);
    }
    if request.headers().get_all(HOST).iter().count() != 1 {
        return generated_response(400, "Bad request", true, None);
    }
    let websocket = match parse_websocket_request(&request) {
        Ok(websocket) => websocket,
        Err(_) => return generated_response(400, "Bad request", true, None),
    };
    let cookie = request
        .headers()
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let config = Arc::clone(&state.config);
    let store = Arc::clone(&state.store);
    let auth_mini = Arc::clone(&state.auth_mini);
    let flights = Arc::clone(&state.flights);
    let decision = match state
        .executor
        .run(move || {
            auth_decision(
                cookie.as_deref(),
                &config,
                &store,
                auth_mini.as_ref(),
                &flights,
            )
        })
        .await
    {
        Ok(decision) => decision,
        Err(AuthExecutionError::Overloaded) => return auth_unavailable_hyper(body_bearing, None),
        Err(AuthExecutionError::Internal) => {
            return generated_response(500, "Internal server error", body_bearing, None)
        }
    };

    let (identity, renewal) = match decision {
        AuthDecision::Allow {
            identity,
            session_renewal,
        } => (identity, session_renewal),
        AuthDecision::Unauthenticated { clear_session } => {
            let config = Arc::clone(&state.config);
            let store = Arc::clone(&state.store);
            let return_to = path_and_query.clone();
            let login = state
                .executor
                .run(move || create_login_response(&return_to, &config, &store).map_err(|_| ()))
                .await;
            return match login {
                Ok(Ok(response)) => {
                    local_into_hyper(response.prepend_cookie(clear_session), body_bearing)
                }
                Ok(Err(_)) | Err(_) => generated_response(
                    500,
                    "Internal server error",
                    body_bearing,
                    Some(clear_session),
                ),
            };
        }
        AuthDecision::Forbidden => return generated_response(403, "Forbidden", body_bearing, None),
        AuthDecision::Unavailable => return auth_unavailable_hyper(body_bearing, None),
    };

    let proxy = state.proxy.as_ref().expect("proxy mode");
    let result = proxy
        .forward(
            request,
            &path_and_query,
            peer,
            &state.public_proto,
            ProxyIdentity {
                user_id: identity.user_id,
                email: identity.email,
            },
            renewal.clone(),
            body_bearing,
            websocket,
        )
        .await;
    match result {
        Ok(response) => response,
        Err(ProxyError::BadRequest) => generated_response(400, "Bad request", true, renewal),
        Err(ProxyError::BadGateway) => {
            generated_response(502, "Bad gateway", body_bearing, renewal)
        }
        Err(ProxyError::Internal) => {
            generated_response(500, "Internal server error", body_bearing, renewal)
        }
    }
}

fn classify_fallback_target(
    request: &HyperRequest<Incoming>,
) -> Result<String, (u16, &'static str)> {
    if request.method() == Method::CONNECT {
        return Err((405, "Method not allowed"));
    }
    if request.uri().path() == "*" {
        return Err((400, "Bad request"));
    }
    if request.uri().scheme().is_some() {
        if !matches!(request.uri().scheme_str(), Some("http" | "https")) {
            return Err((400, "Bad request"));
        }
        return request
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .filter(|value| value.starts_with('/'))
            .ok_or((400, "Bad request"));
    }
    if request.uri().authority().is_some() {
        return Err((400, "Bad request"));
    }
    request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .filter(|value| value.starts_with('/'))
        .ok_or((400, "Bad request"))
}

fn validate_expect(request: &HyperRequest<Incoming>, body_bearing: bool) -> Result<(), ()> {
    let values: Vec<_> = request.headers().get_all(EXPECT).iter().collect();
    if values.is_empty() {
        return Ok(());
    }
    if values.len() != 1
        || request.version() != Version::HTTP_11
        || !body_bearing
        || !values[0]
            .to_str()
            .is_ok_and(|value| value.eq_ignore_ascii_case("100-continue"))
    {
        return Err(());
    }
    Ok(())
}

fn request_has_body(request: &HyperRequest<Incoming>) -> bool {
    !request.body().is_end_stream()
        || request
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > 0)
        || request
            .headers()
            .contains_key(http::header::TRANSFER_ENCODING)
}

fn generated_response(
    status: u16,
    text: &'static str,
    close: bool,
    cookie: Option<String>,
) -> HyperResponse<GatewayBody> {
    let mut response = HyperResponse::new(full_body(Bytes::from_static(text.as_bytes())));
    *response.status_mut() = StatusCode::from_u16(status).expect("fixed status");
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    if close {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    if let Some(cookie) = cookie {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(SET_COOKIE, value);
        }
    }
    response
}

fn auth_unavailable_hyper(close: bool, cookie: Option<String>) -> HyperResponse<GatewayBody> {
    let mut response = generated_response(
        503,
        "Authentication service temporarily unavailable",
        close,
        cookie,
    );
    response
        .headers_mut()
        .insert(http::header::RETRY_AFTER, HeaderValue::from_static("5"));
    response
}

fn local_into_hyper(response: Response, close: bool) -> HyperResponse<GatewayBody> {
    let (status, content_type, headers, body) = response.into_parts();
    let mut response = HyperResponse::new(if body.is_empty() {
        empty_body()
    } else {
        full_body(body)
    });
    *response.status_mut() =
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if let Ok(value) = HeaderValue::from_str(&content_type) {
        response.headers_mut().insert(CONTENT_TYPE, value);
    }
    for (name, value) in headers {
        if let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) {
            let value = HeaderValue::from_bytes(value.as_bytes())
                .expect("Response stores only validated header bytes");
            response.headers_mut().append(name, value);
        }
    }
    if close {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

fn handle_request(
    request: Request,
    config: &Config,
    store: &Store,
    auth_mini: &dyn AuthMini,
    flights: &FlightCoordinator,
) -> Result<Response, Box<dyn std::error::Error>> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => Ok(Response::empty(204)),
        ("GET", "/login") => handle_login(&request, config, store),
        ("GET", "/auth/callback") => Ok(callback_page()),
        ("POST", "/auth/callback/session") => {
            handle_callback_session(&request, config, store, auth_mini)
        }
        ("GET", "/auth/check") => Ok(handle_auth_check(
            &request, config, store, auth_mini, flights,
        )),
        ("GET" | "POST", "/logout") => handle_logout(&request, config, store, auth_mini),
        _ => Ok(no_store(Response::text(404, "Not found"))),
    }
}

fn handle_login(
    request: &Request,
    config: &Config,
    store: &Store,
) -> Result<Response, Box<dyn std::error::Error>> {
    let original_uri = request.header("X-Original-URI");
    let Some(return_to) = normalize_return_to(
        request
            .query
            .get("return_to")
            .map(String::as_str)
            .or(original_uri),
        config,
    ) else {
        return Ok(no_store(Response::text(400, "Invalid return_to")));
    };
    create_login_response(&return_to, config, store)
}

fn create_login_response(
    return_to: &str,
    config: &Config,
    store: &Store,
) -> Result<Response, Box<dyn std::error::Error>> {
    let state = store.create_login_state(return_to, config.login_state_ttl_seconds)?;
    Ok(
        Response::redirect(&build_auth_mini_login_url(&state.id, config)).with_cookie(
            serialize_signed_cookie(LOGIN_STATE_COOKIE, &state.id, state.expires_at, config),
        ),
    )
}

fn handle_callback_session(
    request: &Request,
    config: &Config,
    store: &Store,
    auth_mini: &dyn AuthMini,
) -> Result<Response, Box<dyn std::error::Error>> {
    let clear_state = clear_cookie(LOGIN_STATE_COOKIE, config);
    let Some(state_id) = read_signed_cookie(
        request.header("Cookie"),
        LOGIN_STATE_COOKIE,
        &config.cookie_secret,
    ) else {
        return Ok(no_store(Response::text(400, "Invalid login state")).with_cookie(clear_state));
    };

    let body: CallbackBody = match serde_json::from_slice(&request.body) {
        Ok(body) => body,
        Err(_) => return Ok(no_store(Response::text(400, "Invalid JSON")).with_cookie(clear_state)),
    };
    let consumed_state = store.consume_login_state(&state_id)?;
    if consumed_state.is_none() || body.state.as_deref() != Some(&state_id) {
        return Ok(no_store(Response::text(400, "Invalid login state")).with_cookie(clear_state));
    }

    let Some(tokens) = body.into_tokens() else {
        return Ok(no_store(Response::text(400, "Invalid login callback")).with_cookie(clear_state));
    };

    let session = match create_session_from_tokens(tokens, config, store, auth_mini) {
        Ok(session) => session,
        Err(_) => {
            return Ok(
                no_store(Response::text(401, "Invalid auth-mini session")).with_cookie(clear_state)
            )
        }
    };

    let session_cookie =
        serialize_signed_cookie(SESSION_COOKIE, &session.id, session.idle_expires_at, config);
    let response = no_store(match evaluate_session_policy(&session, config) {
        PolicyDecision::Allow => Response::json(
            200,
            json!({ "returnTo": consumed_state.expect("checked state").return_to }),
        ),
        PolicyDecision::Deny => Response::text(403, "Forbidden"),
    })
    .with_cookie(clear_state)
    .with_cookie(session_cookie);
    Ok(response)
}

fn create_session_from_tokens(
    tokens: TokenInput,
    config: &Config,
    store: &Store,
    auth_mini: &dyn AuthMini,
) -> Result<GatewaySession, Box<dyn std::error::Error>> {
    let verified = auth_mini
        .verify_initial_access(&tokens.access_token)
        .map_err(|_| "access verification failed")?;
    if verified.auth_session_id != tokens.session_id {
        return Err("session id mismatch".into());
    }

    let me = match auth_mini.fetch_identity(&tokens.access_token) {
        IdentityFetchOutcome::Fresh(me) => me,
        IdentityFetchOutcome::Unavailable(_) => return Err("identity unavailable".into()),
    };
    if me.user_id != verified.user_id {
        return Err("user mismatch".into());
    }

    Ok(store.create_session(NewSession {
        auth_session_id: tokens.session_id,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        user_id: verified.user_id,
        email: me.email,
        amr: verified.amr,
        access_expires_at: unix_to_time(verified.exp)?,
        idle_ttl_seconds: config.session_ttl_seconds,
        absolute_ttl_seconds: config.session_absolute_ttl_seconds,
    })?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedIdentity {
    user_id: String,
    email: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AuthDecision {
    Allow {
        identity: VerifiedIdentity,
        session_renewal: Option<String>,
    },
    Unauthenticated {
        clear_session: String,
    },
    Forbidden,
    Unavailable,
}

fn handle_auth_check(
    request: &Request,
    config: &Config,
    store: &Store,
    auth_mini: &dyn AuthMini,
    flights: &FlightCoordinator,
) -> Response {
    match auth_decision(request.header("Cookie"), config, store, auth_mini, flights) {
        AuthDecision::Allow {
            identity,
            session_renewal,
        } => {
            let mut response =
                Response::empty(204).with_header("X-Auth-Mini-User-Id", &identity.user_id);
            if let Some(email) = identity.email.as_deref() {
                response = response.with_header("X-Auth-Mini-Email", email);
            }
            if let Some(cookie) = session_renewal {
                response = response.with_cookie(cookie);
            }
            no_store(response)
        }
        AuthDecision::Unauthenticated { clear_session } => {
            no_store(Response::text(401, "Unauthenticated")).with_cookie(clear_session)
        }
        AuthDecision::Forbidden => no_store(Response::text(403, "Forbidden")),
        AuthDecision::Unavailable => auth_unavailable(),
    }
}

fn auth_decision(
    cookie_header: Option<&str>,
    config: &Config,
    store: &Store,
    auth_mini: &dyn AuthMini,
    flights: &FlightCoordinator,
) -> AuthDecision {
    let Some(session_id) = read_signed_cookie(cookie_header, SESSION_COOKIE, &config.cookie_secret)
    else {
        return AuthDecision::Unauthenticated {
            clear_session: clear_cookie(SESSION_COOKIE, config),
        };
    };

    for _ in 0..8 {
        let session = match store.lookup_session(&session_id) {
            Ok(SessionLookup::Active(session)) => session,
            Ok(SessionLookup::Inactive) => {
                return AuthDecision::Unauthenticated {
                    clear_session: clear_cookie(SESSION_COOKIE, config),
                }
            }
            Err(_) => return AuthDecision::Unavailable,
        };

        if session.identity_state == IdentityState::Pending
            || session_needs_refresh(&session, config, store.now())
        {
            let outcome = match flights.acquire(&session.id, session.observed_version()) {
                Acquire::Leader(mut leader) => {
                    eprintln!("event=refresh_flight outcome=flight_leader");
                    let outcome = catch_unwind(AssertUnwindSafe(|| {
                        execute_flight(&session, config, store, auth_mini, &mut leader)
                    }))
                    .unwrap_or(FlightOutcome::Indeterminate {
                        class: IndeterminateClass::LeaderAborted,
                    });
                    leader.complete(outcome)
                }
                Acquire::Joined(waiter) => {
                    eprintln!("event=refresh_flight outcome=flight_joined");
                    waiter.wait_outcome()
                }
                Acquire::WaitForClose(waiter) => {
                    waiter.wait_closed();
                    continue;
                }
            };
            match *outcome {
                FlightOutcome::Ready { .. } => {
                    eprintln!("event=refresh_flight outcome=ready");
                    continue;
                }
                FlightOutcome::Rejected { .. } => {
                    eprintln!("event=refresh_flight outcome=rejected");
                    return AuthDecision::Unauthenticated {
                        clear_session: clear_cookie(SESSION_COOKIE, config),
                    };
                }
                FlightOutcome::Temporary { .. } => {
                    eprintln!("event=refresh_flight outcome=temporary");
                    return AuthDecision::Unavailable;
                }
                FlightOutcome::Indeterminate { .. } => {
                    eprintln!("event=refresh_flight outcome=indeterminate");
                    return AuthDecision::Unavailable;
                }
            }
        }

        if evaluate_session_policy(&session, config) == PolicyDecision::Deny {
            return AuthDecision::Forbidden;
        }
        if !identity_headers_are_safe(&session) {
            return AuthDecision::Forbidden;
        }

        let touched = match store.touch_ready(
            &session,
            config.session_ttl_seconds,
            config.session_touch_interval_seconds,
        ) {
            Ok(TouchResult::NotDue(session)) => (session, false),
            Ok(TouchResult::Advanced(session)) => (session, true),
            Ok(TouchResult::Lost) => continue,
            Err(_) => return AuthDecision::Unavailable,
        };
        let session_renewal = if touched.1 {
            eprintln!("event=session_touch outcome=advanced");
            Some(serialize_signed_cookie(
                SESSION_COOKIE,
                &touched.0.id,
                touched.0.idle_expires_at,
                config,
            ))
        } else {
            None
        };
        return AuthDecision::Allow {
            identity: VerifiedIdentity {
                user_id: touched.0.user_id,
                email: touched.0.email,
            },
            session_renewal,
        };
    }
    AuthDecision::Unavailable
}

fn execute_flight(
    session: &GatewaySession,
    config: &Config,
    store: &Store,
    auth_mini: &dyn AuthMini,
    leader: &mut FlightLeader,
) -> FlightOutcome {
    if session_needs_refresh(session, config, store.now()) {
        refresh_gateway_session(session, config, store, auth_mini, leader)
    } else if session.identity_state == IdentityState::Pending {
        recover_pending_identity(session, store, auth_mini)
    } else {
        FlightOutcome::Ready {
            generation: session.refresh_generation,
        }
    }
}

fn refresh_gateway_session(
    session: &GatewaySession,
    config: &Config,
    store: &Store,
    auth_mini: &dyn AuthMini,
    leader: &mut FlightLeader,
) -> FlightOutcome {
    let jwks = match auth_mini.prepare_refresh_verifier() {
        Ok(jwks) => jwks,
        Err(error) => return refresh_error_outcome(error),
    };
    let refreshed = match auth_mini.refresh(&session.auth_session_id, &session.refresh_token) {
        Ok(refreshed) => refreshed,
        Err(RefreshError::Rejected(reason)) => {
            return handle_refresh_rejection(session, reason, store, auth_mini)
        }
        Err(error) => return refresh_error_outcome(error),
    };
    if refreshed.session_id != session.auth_session_id {
        return FlightOutcome::Indeterminate {
            class: IndeterminateClass::ContractDrift,
        };
    }
    let verified = match auth_mini.verify_refreshed_access(&refreshed.access_token, &jwks) {
        Ok(verified) => verified,
        Err(error) => return refresh_error_outcome(error),
    };
    if verified.auth_session_id != session.auth_session_id || verified.user_id != session.user_id {
        return FlightOutcome::Indeterminate {
            class: IndeterminateClass::IdentityMismatch,
        };
    }
    let access_expires_at = match unix_to_time(verified.exp) {
        Ok(value) => value,
        Err(_) => {
            return FlightOutcome::Indeterminate {
                class: IndeterminateClass::TokenVerification,
            }
        }
    };
    leader.add_alias(ObservedVersion {
        generation: session.refresh_generation + 1,
        identity_state: IdentityState::Pending,
    });
    match store.persist_pending(
        session,
        PendingTokens {
            access_token: &refreshed.access_token,
            refresh_token: &refreshed.refresh_token,
            user_id: &verified.user_id,
            amr: &verified.amr,
            access_expires_at,
        },
    ) {
        Ok(CasResult::Updated(pending)) => {
            eprintln!("event=identity_pending outcome=pending_entered");
            recover_pending_identity(&pending, store, auth_mini)
        }
        Ok(CasResult::Current(current))
            if current.observed_version() != session.observed_version()
                || current.refresh_token != session.refresh_token =>
        {
            use_current_session(current, config, store, auth_mini)
        }
        Ok(CasResult::Current(_)) | Err(_) => FlightOutcome::Indeterminate {
            class: IndeterminateClass::Persistence,
        },
        Ok(CasResult::Inactive) => FlightOutcome::Rejected {
            reason: RejectedReason::LocalInactive,
        },
    }
}

fn handle_refresh_rejection(
    expected: &GatewaySession,
    reason: crate::auth_mini::RefreshRejected,
    store: &Store,
    auth_mini: &dyn AuthMini,
) -> FlightOutcome {
    match reason {
        crate::auth_mini::RefreshRejected::Invalidated => {
            eprintln!("event=refresh_flight outcome=rejected_invalidated");
        }
        crate::auth_mini::RefreshRejected::Superseded => {
            eprintln!("event=refresh_flight outcome=rejected_superseded");
        }
    }
    match store.lookup_session(&expected.id) {
        Ok(SessionLookup::Active(current))
            if current.observed_version() != expected.observed_version()
                || current.refresh_token != expected.refresh_token =>
        {
            return use_current_session_without_refresh(current, store, auth_mini)
        }
        Ok(SessionLookup::Inactive) => {
            return FlightOutcome::Rejected {
                reason: RejectedReason::LocalInactive,
            }
        }
        Err(_) => {
            return FlightOutcome::Indeterminate {
                class: IndeterminateClass::Persistence,
            }
        }
        Ok(SessionLookup::Active(_)) => {}
    }
    match store.conditional_revoke(expected) {
        Ok(true) => FlightOutcome::Rejected {
            reason: RejectedReason::Remote(reason),
        },
        Ok(false) => match store.lookup_session(&expected.id) {
            Ok(SessionLookup::Active(current))
                if current.observed_version() != expected.observed_version()
                    || current.refresh_token != expected.refresh_token =>
            {
                use_current_session_without_refresh(current, store, auth_mini)
            }
            Ok(SessionLookup::Inactive) => FlightOutcome::Rejected {
                reason: RejectedReason::LocalInactive,
            },
            Ok(SessionLookup::Active(_)) | Err(_) => FlightOutcome::Indeterminate {
                class: IndeterminateClass::Persistence,
            },
        },
        Err(_) => FlightOutcome::Indeterminate {
            class: IndeterminateClass::Persistence,
        },
    }
}

fn use_current_session(
    current: GatewaySession,
    config: &Config,
    store: &Store,
    auth_mini: &dyn AuthMini,
) -> FlightOutcome {
    if current.identity_state == IdentityState::Pending {
        if session_needs_refresh(&current, config, store.now()) {
            return FlightOutcome::Indeterminate {
                class: IndeterminateClass::ContractDrift,
            };
        }
        recover_pending_identity(&current, store, auth_mini)
    } else {
        FlightOutcome::Ready {
            generation: current.refresh_generation,
        }
    }
}

fn use_current_session_without_refresh(
    current: GatewaySession,
    store: &Store,
    auth_mini: &dyn AuthMini,
) -> FlightOutcome {
    if current.identity_state == IdentityState::Pending {
        recover_pending_identity(&current, store, auth_mini)
    } else {
        FlightOutcome::Ready {
            generation: current.refresh_generation,
        }
    }
}

fn recover_pending_identity(
    pending: &GatewaySession,
    store: &Store,
    auth_mini: &dyn AuthMini,
) -> FlightOutcome {
    debug_assert_eq!(pending.identity_state, IdentityState::Pending);
    let me = match auth_mini.fetch_identity(&pending.access_token) {
        IdentityFetchOutcome::Fresh(me) if me.user_id == pending.user_id => me,
        IdentityFetchOutcome::Fresh(_) => {
            eprintln!("event=identity_finalize outcome=pending_identity_mismatch");
            return FlightOutcome::Indeterminate {
                class: IndeterminateClass::IdentityMismatch,
            };
        }
        IdentityFetchOutcome::Unavailable(IdentityUnavailable::Temporary(class)) => {
            return FlightOutcome::Temporary { class }
        }
        IdentityFetchOutcome::Unavailable(IdentityUnavailable::HttpStatus(401)) => {
            eprintln!("event=identity_pending outcome=pending_me_401");
            return FlightOutcome::Indeterminate {
                class: IndeterminateClass::ContractDrift,
            };
        }
        IdentityFetchOutcome::Unavailable(_) => {
            return FlightOutcome::Indeterminate {
                class: IndeterminateClass::ContractDrift,
            }
        }
    };
    match store.finalize_pending(pending, me.email.as_deref()) {
        Ok(CasResult::Updated(ready)) if ready.identity_state == IdentityState::Ready => {
            eprintln!("event=identity_finalize outcome=pending_ready");
            FlightOutcome::Ready {
                generation: ready.refresh_generation,
            }
        }
        Ok(CasResult::Current(current))
            if current.identity_state == IdentityState::Ready
                && current.refresh_generation == pending.refresh_generation =>
        {
            FlightOutcome::Ready {
                generation: current.refresh_generation,
            }
        }
        Ok(CasResult::Inactive) => FlightOutcome::Rejected {
            reason: RejectedReason::LocalInactive,
        },
        Ok(_) | Err(_) => FlightOutcome::Indeterminate {
            class: IndeterminateClass::Persistence,
        },
    }
}

fn refresh_error_outcome(error: RefreshError) -> FlightOutcome {
    match error {
        RefreshError::Rejected(reason) => FlightOutcome::Rejected {
            reason: RejectedReason::Remote(reason),
        },
        RefreshError::Temporary(class) => FlightOutcome::Temporary { class },
        RefreshError::Indeterminate(class) => FlightOutcome::Indeterminate { class },
    }
}

fn handle_logout(
    request: &Request,
    config: &Config,
    store: &Store,
    auth_mini: &dyn AuthMini,
) -> Result<Response, Box<dyn std::error::Error>> {
    let session_id = read_signed_cookie(
        request.header("Cookie"),
        SESSION_COOKIE,
        &config.cookie_secret,
    );
    let access_snapshot = match session_id.as_deref() {
        Some(id) => store.logout_access_snapshot(id).ok().flatten(),
        None => None,
    };
    if let Some(id) = session_id.as_deref() {
        store.revoke_session(id)?;
        eprintln!("event=session_logout outcome=local_revoked");
    }
    if let Some(access_token) = access_snapshot {
        let _ = auth_mini.logout(&access_token);
    }

    let return_to = normalize_return_to(
        request
            .query
            .get("return_to")
            .map(String::as_str)
            .or(Some(config.logout_redirect.as_str())),
        config,
    )
    .unwrap_or_else(|| "/".to_string());
    Ok(Response::redirect(&return_to).with_cookie(clear_cookie(SESSION_COOKIE, config)))
}

fn auth_unavailable() -> Response {
    no_store(Response::text(
        503,
        "Authentication service temporarily unavailable",
    ))
    .with_header("Retry-After", "5")
}

fn callback_page() -> Response {
    Response::html(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Completing login</title></head>
<body>
<p>Completing login...</p>
<script>
(async () => {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const payload = Object.fromEntries(params.entries());
  window.history.replaceState(null, '', '/auth/callback');
  const response = await fetch('/auth/callback/session', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error('Login failed');
  const body = await response.json();
  window.location.assign(body.returnTo || '/');
})().catch(() => {
  document.body.textContent = 'Login failed. Please try again.';
});
</script>
</body>
</html>"#,
    )
}

pub fn normalize_return_to(input: Option<&str>, config: &Config) -> Option<String> {
    normalize_return_target(
        input,
        &config.public_base_url,
        ReturnTargetMode::DirectLogin,
    )
}

pub fn build_auth_mini_login_url(state: &str, config: &Config) -> String {
    let redirect_uri = Url::parse(&config.public_base_url)
        .and_then(|base| base.join("/auth/callback"))
        .expect("validated public base url")
        .to_string();
    let params = form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("state", state)
        .finish();

    if let Some(login_url) = config.auth_mini_login_url.as_deref() {
        let separator = if login_url.contains('?') { '&' } else { '?' };
        return format!("{login_url}{separator}{params}");
    }

    format!(
        "{}/web/#/login?{}",
        config.auth_mini_public_base_url, params
    )
}

fn evaluate_session_policy(session: &GatewaySession, config: &Config) -> PolicyDecision {
    evaluate(
        Identity {
            user_id: &session.user_id,
            email: session.email.as_deref(),
        },
        config,
    )
}

fn identity_headers_are_safe(session: &GatewaySession) -> bool {
    is_safe_header_value(&session.user_id)
        && session
            .email
            .as_deref()
            .map(is_safe_header_value)
            .unwrap_or(true)
}

fn session_needs_refresh(session: &GatewaySession, config: &Config, now: DateTime<Utc>) -> bool {
    session.access_expires_at <= now + Duration::seconds(config.refresh_skew_seconds)
}

fn unix_to_time(exp: i64) -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
    Ok(Utc.timestamp_opt(exp, 0).single().ok_or("invalid exp")?)
}

fn no_store(response: Response) -> Response {
    response.with_header("Cache-Control", "no-store")
}

#[derive(Deserialize)]
struct CallbackBody {
    access_token: Option<String>,
    refresh_token: Option<String>,
    session_id: Option<String>,
    token_type: Option<String>,
    state: Option<String>,
}

impl CallbackBody {
    fn into_tokens(self) -> Option<TokenInput> {
        if self.token_type.as_deref()? != "Bearer" {
            return None;
        }
        Some(TokenInput {
            access_token: self.access_token?,
            refresh_token: self.refresh_token?,
            session_id: self.session_id?,
        })
    }
}

struct TokenInput {
    session_id: String,
    access_token: String,
    refresh_token: String,
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::collections::VecDeque;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    use chrono::TimeZone;
    use tempfile::tempdir;

    use crate::auth_mini::{
        AuthMiniClient, AuthMiniOperationError, IdentityUnavailable, MeResponse, RefreshRejected,
        TokenResponse,
    };
    use crate::config::SameSite;
    use crate::jwt::{Jwks, VerifiedAccessToken};
    use crate::util::ManualClock;

    use super::*;

    #[test]
    fn normalizes_safe_return_targets() {
        let config = test_config();
        assert_eq!(
            normalize_return_to(Some("/app?x=1#frag"), &config),
            Some("/app?x=1#frag".to_string())
        );
        assert_eq!(
            normalize_return_to(Some("http://localhost:8080/app"), &config),
            Some("/app".to_string())
        );
        assert_eq!(normalize_return_to(None, &config), Some("/".to_string()));
    }

    #[test]
    fn rejects_unsafe_return_targets() {
        let config = test_config();
        assert_eq!(
            normalize_return_to(Some("https://evil.example/app"), &config),
            None
        );
        assert_eq!(
            normalize_return_to(Some("//evil.example/app"), &config),
            None
        );
        assert_eq!(
            normalize_return_to(Some("/app\r\nlocation: https://evil.example"), &config),
            None
        );
    }

    #[test]
    fn builds_auth_mini_login_url_with_redirect_and_state() {
        let config = test_config();
        let login_url = build_auth_mini_login_url("state-1", &config);
        assert!(login_url.starts_with("http://localhost:7777/web/#/login?"));
        assert!(login_url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fcallback"));
        assert!(login_url.contains("state=state-1"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blocking_executor_bounds_admission_and_releases_permits_after_panic() {
        let executor = AuthExecutor::with_limits(2, 4);
        let gate = Arc::new(Barrier::new(3));
        let entered = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let executor = executor.clone();
            let gate = Arc::clone(&gate);
            let entered = Arc::clone(&entered);
            tasks.push(tokio::spawn(async move {
                executor
                    .run(move || {
                        entered.fetch_add(1, Ordering::SeqCst);
                        gate.wait();
                        1usize
                    })
                    .await
            }));
        }
        while entered.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
        for _ in 0..2 {
            let executor = executor.clone();
            tasks.push(tokio::spawn(async move { executor.run(|| 1usize).await }));
        }
        while executor.admission.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        assert!(matches!(
            executor.run(|| 1usize).await,
            Err(AuthExecutionError::Overloaded)
        ));
        gate.wait();
        for task in tasks {
            assert_eq!(task.await.expect("executor task").expect("admitted"), 1);
        }
        assert_eq!(executor.admission.available_permits(), 4);
        assert_eq!(executor.work.available_permits(), 2);

        assert!(matches!(
            executor.run(|| -> usize { panic!("test panic") }).await,
            Err(AuthExecutionError::Internal)
        ));
        assert_eq!(executor.admission.available_permits(), 4);
        assert_eq!(executor.work.available_permits(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blocking_executor_enforces_full_64_active_64_queued_contract() {
        let executor = AuthExecutor::with_limits(64, 128);
        let gate = Arc::new(Barrier::new(65));
        let entered = Arc::new(AtomicUsize::new(0));
        let mut active = Vec::new();
        for _ in 0..64 {
            let executor = executor.clone();
            let gate = Arc::clone(&gate);
            let entered = Arc::clone(&entered);
            active.push(tokio::spawn(async move {
                executor
                    .run(move || {
                        entered.fetch_add(1, Ordering::SeqCst);
                        gate.wait();
                        1usize
                    })
                    .await
            }));
        }
        while entered.load(Ordering::SeqCst) != 64 {
            tokio::task::yield_now().await;
        }

        let mut queued = Vec::new();
        for _ in 0..64 {
            let executor = executor.clone();
            queued.push(tokio::spawn(async move { executor.run(|| 2usize).await }));
        }
        while executor.admission.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        assert!(matches!(
            executor.run(|| 3usize).await,
            Err(AuthExecutionError::Overloaded)
        ));

        // Cancellation after spawn_blocking starts cannot release its owned
        // permits while the blocking closure is still running.
        active[0].abort();
        tokio::task::yield_now().await;
        assert_eq!(executor.admission.available_permits(), 0);
        assert_eq!(executor.work.available_permits(), 0);

        // Queued cancellation starts no blocking work and releases admission.
        for task in queued.iter().take(8) {
            task.abort();
        }
        while executor.admission.available_permits() != 8 {
            tokio::task::yield_now().await;
        }

        gate.wait();
        for (index, task) in active.into_iter().enumerate() {
            let result = task.await;
            if index == 0 {
                assert!(result.expect_err("aborted active task").is_cancelled());
            } else {
                assert_eq!(result.expect("active task").expect("active admitted"), 1);
            }
        }
        for (index, task) in queued.into_iter().enumerate() {
            let result = task.await;
            if index < 8 {
                assert!(result.expect_err("aborted queued task").is_cancelled());
            } else {
                assert_eq!(result.expect("queued task").expect("queued admitted"), 2);
            }
        }
        assert_eq!(executor.admission.available_permits(), 128);
        assert_eq!(executor.work.available_permits(), 64);

        assert!(matches!(
            executor
                .run(|| -> usize { panic!("full-contract panic") })
                .await,
            Err(AuthExecutionError::Internal)
        ));
        assert_eq!(executor.admission.available_permits(), 128);
        assert_eq!(executor.work.available_permits(), 64);
    }

    #[test]
    fn me_http_failure_keeps_pending_and_later_identity_flight_recovers() {
        let (_dir, store, session, config, _clock) = test_store_session();
        let auth = MockAuthMini::new(
            vec![Ok(TokenResponse {
                session_id: session.auth_session_id.clone(),
                access_token: "rotated-access".to_string(),
                refresh_token: "rotated-refresh".to_string(),
            })],
            vec![
                IdentityFetchOutcome::Unavailable(IdentityUnavailable::HttpStatus(401)),
                IdentityFetchOutcome::Fresh(MeResponse {
                    user_id: session.user_id.clone(),
                    email: Some("fresh@example.com".to_string()),
                }),
            ],
            session.user_id.clone(),
            session.auth_session_id.clone(),
        );
        let coordinator = FlightCoordinator::default();
        let mut first_leader = match coordinator.acquire(&session.id, session.observed_version()) {
            Acquire::Leader(leader) => leader,
            _ => panic!("first leader"),
        };
        let first = execute_flight(&session, &config, &store, &auth, &mut first_leader);
        first_leader.complete(first);
        assert!(matches!(first, FlightOutcome::Indeterminate { .. }));
        let pending = match store.lookup_session(&session.id).expect("pending lookup") {
            SessionLookup::Active(session) => session,
            _ => panic!("pending remains active"),
        };
        assert_eq!(pending.identity_state, IdentityState::Pending);
        assert!(pending.revoked_at.is_none());

        let mut second_leader = match coordinator.acquire(&pending.id, pending.observed_version()) {
            Acquire::Leader(leader) => leader,
            _ => panic!("second independent leader"),
        };
        let second = execute_flight(&pending, &config, &store, &auth, &mut second_leader);
        second_leader.complete(second);
        assert!(matches!(second, FlightOutcome::Ready { generation: 1 }));
        let ready = match store.lookup_session(&session.id).expect("ready lookup") {
            SessionLookup::Active(session) => session,
            _ => panic!("ready active"),
        };
        assert_eq!(ready.identity_state, IdentityState::Ready);
        assert_eq!(ready.email.as_deref(), Some("fresh@example.com"));
        assert_eq!(auth.refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(auth.identity_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn exact_refresh_rejection_conditionally_revokes_local_generation() {
        let (_dir, store, session, config, _clock) = test_store_session();
        let auth = MockAuthMini::new(
            vec![Err(RefreshError::Rejected(RefreshRejected::Superseded))],
            vec![],
            session.user_id.clone(),
            session.auth_session_id.clone(),
        );
        let coordinator = FlightCoordinator::default();
        let mut leader = match coordinator.acquire(&session.id, session.observed_version()) {
            Acquire::Leader(leader) => leader,
            _ => panic!("leader"),
        };
        let outcome = execute_flight(&session, &config, &store, &auth, &mut leader);
        leader.complete(outcome);
        assert_eq!(
            outcome,
            FlightOutcome::Rejected {
                reason: RejectedReason::Remote(RefreshRejected::Superseded)
            }
        );
        assert!(matches!(
            store.lookup_session(&session.id).expect("lookup"),
            SessionLookup::Inactive
        ));
        assert_eq!(auth.refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(auth.identity_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn lost_rotation_result_is_shared_before_later_superseded_revoke() {
        let (_dir, store, session, config, _clock) = test_store_session();
        let auth = MockAuthMini::new(
            vec![
                Err(RefreshError::Indeterminate(
                    IndeterminateClass::ContractDrift,
                )),
                Err(RefreshError::Rejected(RefreshRejected::Superseded)),
            ],
            vec![],
            session.user_id.clone(),
            session.auth_session_id.clone(),
        );
        let coordinator = FlightCoordinator::default();
        let mut leader = match coordinator.acquire(&session.id, session.observed_version()) {
            Acquire::Leader(leader) => leader,
            _ => panic!("leader"),
        };
        let joiner = match coordinator.acquire(&session.id, session.observed_version()) {
            Acquire::Joined(waiter) => waiter,
            _ => panic!("same-version joiner"),
        };
        let first = execute_flight(&session, &config, &store, &auth, &mut leader);
        leader.complete(first);
        assert_eq!(*joiner.wait_outcome(), first);
        assert!(matches!(first, FlightOutcome::Indeterminate { .. }));
        assert_eq!(auth.refresh_calls.load(Ordering::SeqCst), 1);
        let unchanged = match store.lookup_session(&session.id).expect("lookup") {
            SessionLookup::Active(session) => session,
            _ => panic!("row preserved"),
        };
        assert_eq!(unchanged.observed_version(), session.observed_version());

        let mut third = match coordinator.acquire(&unchanged.id, unchanged.observed_version()) {
            Acquire::Leader(leader) => leader,
            _ => panic!("later request is independent"),
        };
        let third_outcome = execute_flight(&unchanged, &config, &store, &auth, &mut third);
        third.complete(third_outcome);
        assert!(matches!(
            third_outcome,
            FlightOutcome::Rejected {
                reason: RejectedReason::Remote(RefreshRejected::Superseded)
            }
        ));
        assert_eq!(auth.refresh_calls.load(Ordering::SeqCst), 2);
        assert!(matches!(
            store.lookup_session(&session.id).expect("lookup"),
            SessionLookup::Inactive
        ));
    }

    #[test]
    fn refresh_persistence_failure_cannot_claim_ready() {
        let (dir, store, session, config, _clock) = test_store_session();
        let auth = MockAuthMini::new(
            vec![Ok(TokenResponse {
                session_id: session.auth_session_id.clone(),
                access_token: "rotated-access".to_string(),
                refresh_token: "rotated-refresh".to_string(),
            })],
            vec![],
            session.user_id.clone(),
            session.auth_session_id.clone(),
        );
        drop(dir);
        let coordinator = FlightCoordinator::default();
        let mut leader = match coordinator.acquire(&session.id, session.observed_version()) {
            Acquire::Leader(leader) => leader,
            _ => panic!("leader"),
        };
        let outcome = execute_flight(&session, &config, &store, &auth, &mut leader);
        leader.complete(outcome);
        assert_eq!(
            outcome,
            FlightOutcome::Indeterminate {
                class: IndeterminateClass::Persistence
            }
        );
        assert_eq!(auth.identity_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn identity_finalize_and_touch_fail_closed_on_persistence_errors() {
        let (dir, store, session, config, _clock) = test_store_session();
        let pending = match store
            .persist_pending(
                &session,
                PendingTokens {
                    access_token: "rotated-access",
                    refresh_token: "rotated-refresh",
                    user_id: &session.user_id,
                    amr: &session.amr,
                    access_expires_at: store.now() + Duration::hours(2),
                },
            )
            .expect("pending")
        {
            CasResult::Updated(session) => session,
            _ => panic!("pending update"),
        };
        let auth = MockAuthMini::new(
            vec![],
            vec![IdentityFetchOutcome::Fresh(MeResponse {
                user_id: pending.user_id.clone(),
                email: Some("fresh@example.com".to_string()),
            })],
            pending.user_id.clone(),
            pending.auth_session_id.clone(),
        );
        drop(dir);
        let coordinator = FlightCoordinator::default();
        let mut leader = match coordinator.acquire(&pending.id, pending.observed_version()) {
            Acquire::Leader(leader) => leader,
            _ => panic!("leader"),
        };
        let outcome = execute_flight(&pending, &config, &store, &auth, &mut leader);
        leader.complete(outcome);
        assert_eq!(
            outcome,
            FlightOutcome::Indeterminate {
                class: IndeterminateClass::Persistence
            }
        );
        let mut due = session.clone();
        due.last_touched_at = store.now() - Duration::hours(2);
        due.idle_expires_at = store.now() + Duration::days(6);
        due.session_expires_at = due.idle_expires_at;
        assert!(store.touch_ready(&due, 604_800, 3_600).is_err());
    }

    #[test]
    fn handle_auth_check_shares_all_refresh_outcomes_with_joiners() {
        for (scenario, expected_status) in [
            (RefreshScenario::Success, 204),
            (RefreshScenario::Rejected, 401),
            (RefreshScenario::Temporary, 503),
            (RefreshScenario::Indeterminate, 503),
        ] {
            let (_dir, store, session, mut config, _clock) = test_store_session();
            config.allow_user_ids.insert(session.user_id.clone());
            let store = Arc::new(store);
            let config = Arc::new(config);
            let flights = Arc::new(FlightCoordinator::default());
            let gate = RemoteGate::new();
            let auth = Arc::new(ScenarioAuth::new(
                scenario,
                session.user_id.clone(),
                session.auth_session_id.clone(),
                Some(gate.clone()),
                None,
                Vec::new(),
            ));

            let leader = spawn_auth_check(
                Arc::clone(&config),
                Arc::clone(&store),
                Arc::clone(&auth),
                Arc::clone(&flights),
                &session.id,
            );
            gate.wait_until_entered();
            let joiner_one = spawn_auth_check(
                Arc::clone(&config),
                Arc::clone(&store),
                Arc::clone(&auth),
                Arc::clone(&flights),
                &session.id,
            );
            let joiner_two = spawn_auth_check(
                Arc::clone(&config),
                Arc::clone(&store),
                Arc::clone(&auth),
                Arc::clone(&flights),
                &session.id,
            );
            flights.wait_for_joiners(&session.id, 2);
            gate.release();

            let responses = [leader, joiner_one, joiner_two].map(|handle| {
                handle
                    .join()
                    .expect("auth check thread must return fail-closed")
            });
            for response in &responses {
                assert_eq!(response.status(), expected_status);
                match scenario {
                    RefreshScenario::Success => {
                        assert_eq!(response.header_values("X-Auth-Mini-User-Id").count(), 1);
                    }
                    RefreshScenario::Rejected => assert!(response
                        .header_values("Set-Cookie")
                        .any(|value| value.contains("Max-Age=0"))),
                    RefreshScenario::Temporary | RefreshScenario::Indeterminate => {
                        assert_eq!(response.header_values("Set-Cookie").count(), 0);
                    }
                }
            }
            assert_eq!(auth.refresh_calls.load(Ordering::SeqCst), 1);
            if scenario == RefreshScenario::Success {
                assert_eq!(auth.identity_calls.load(Ordering::SeqCst), 1);
                let ready = active_session(&store, &session.id);
                assert_eq!(ready.identity_state, IdentityState::Ready);
                assert_eq!(ready.refresh_generation, 1);
            } else if scenario == RefreshScenario::Rejected {
                assert!(matches!(
                    store.lookup_session(&session.id).expect("lookup"),
                    SessionLookup::Inactive
                ));
            } else {
                let unchanged = active_session(&store, &session.id);
                assert_eq!(unchanged.identity_state, IdentityState::Ready);
                assert_eq!(unchanged.refresh_generation, 0);
            }
        }
    }

    #[test]
    fn pending_alias_joins_the_running_refresh_identity_flight() {
        let (_dir, store, session, mut config, _clock) = test_store_session();
        config.allow_user_ids.insert(session.user_id.clone());
        let store = Arc::new(store);
        let config = Arc::new(config);
        let flights = Arc::new(FlightCoordinator::default());
        let identity_gate = RemoteGate::new();
        let auth = Arc::new(ScenarioAuth::new(
            RefreshScenario::Success,
            session.user_id.clone(),
            session.auth_session_id.clone(),
            None,
            Some(identity_gate.clone()),
            Vec::new(),
        ));

        let leader = spawn_auth_check(
            Arc::clone(&config),
            Arc::clone(&store),
            Arc::clone(&auth),
            Arc::clone(&flights),
            &session.id,
        );
        identity_gate.wait_until_entered();
        let pending = active_session(&store, &session.id);
        assert_eq!(pending.identity_state, IdentityState::Pending);
        assert_eq!(pending.refresh_generation, 1);

        let alias_joiner = spawn_auth_check(
            Arc::clone(&config),
            Arc::clone(&store),
            Arc::clone(&auth),
            Arc::clone(&flights),
            &session.id,
        );
        flights.wait_for_joiners(&session.id, 1);
        identity_gate.release();
        assert_eq!(leader.join().expect("leader").status(), 204);
        assert_eq!(alias_joiner.join().expect("alias joiner").status(), 204);
        assert_eq!(auth.refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(auth.identity_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pending_identity_failure_matrix_retries_without_revocation() {
        let (_dir, store, session, mut config, _clock) = test_store_session();
        config.allow_user_ids.insert(session.user_id.clone());
        let pending = make_pending(&store, &session, store.now() + Duration::hours(2));
        let auth = ScenarioAuth::new(
            RefreshScenario::Success,
            session.user_id.clone(),
            session.auth_session_id.clone(),
            None,
            None,
            vec![
                IdentityFetchOutcome::Unavailable(IdentityUnavailable::HttpStatus(401)),
                IdentityFetchOutcome::Unavailable(IdentityUnavailable::HttpStatus(404)),
                IdentityFetchOutcome::Unavailable(IdentityUnavailable::Temporary(
                    crate::auth_mini::TemporaryClass::Upstream,
                )),
                IdentityFetchOutcome::Unavailable(IdentityUnavailable::InvalidBody),
                IdentityFetchOutcome::Fresh(MeResponse {
                    user_id: "mismatched-user".to_string(),
                    email: None,
                }),
                IdentityFetchOutcome::Fresh(MeResponse {
                    user_id: session.user_id.clone(),
                    email: Some("fresh@example.com".to_string()),
                }),
            ],
        );
        let flights = FlightCoordinator::default();
        for _ in 0..5 {
            let response = handle_auth_check(
                &auth_check_request(&pending.id, &config),
                &config,
                &store,
                &auth,
                &flights,
            );
            assert_eq!(response.status(), 503);
            assert_eq!(response.header_values("Set-Cookie").count(), 0);
            let current = active_session(&store, &pending.id);
            assert_eq!(current.identity_state, IdentityState::Pending);
            assert_eq!(current.refresh_generation, pending.refresh_generation);
            assert!(current.revoked_at.is_none());
        }
        let recovered = handle_auth_check(
            &auth_check_request(&pending.id, &config),
            &config,
            &store,
            &auth,
            &flights,
        );
        assert_eq!(recovered.status(), 204);
        let ready = active_session(&store, &pending.id);
        assert_eq!(ready.identity_state, IdentityState::Ready);
        assert_eq!(ready.refresh_generation, pending.refresh_generation);
        assert_eq!(ready.email.as_deref(), Some("fresh@example.com"));
        assert_eq!(auth.refresh_calls.load(Ordering::SeqCst), 0);
        assert_eq!(auth.identity_calls.load(Ordering::SeqCst), 6);
    }

    #[test]
    fn fresh_identity_replaces_policy_input_including_null_email() {
        let (_dir, store, session, mut config, _clock) = test_store_session();
        config.allow_emails.insert("old@example.com".to_string());
        let pending = make_pending(&store, &session, store.now() + Duration::hours(2));
        let denied_auth = ScenarioAuth::new(
            RefreshScenario::Success,
            session.user_id.clone(),
            session.auth_session_id.clone(),
            None,
            None,
            vec![IdentityFetchOutcome::Fresh(MeResponse {
                user_id: session.user_id.clone(),
                email: Some("new-denied@example.com".to_string()),
            })],
        );
        let response = handle_auth_check(
            &auth_check_request(&pending.id, &config),
            &config,
            &store,
            &denied_auth,
            &FlightCoordinator::default(),
        );
        assert_eq!(response.status(), 403);
        assert_eq!(response.header_values("X-Auth-Mini-Email").count(), 0);
        assert_eq!(
            active_session(&store, &pending.id).email.as_deref(),
            Some("new-denied@example.com")
        );

        let (_dir, store, session, mut config, _clock) = test_store_session();
        config.allow_user_ids.insert(session.user_id.clone());
        let pending = make_pending(&store, &session, store.now() + Duration::hours(2));
        let null_auth = ScenarioAuth::new(
            RefreshScenario::Success,
            session.user_id.clone(),
            session.auth_session_id.clone(),
            None,
            None,
            vec![IdentityFetchOutcome::Fresh(MeResponse {
                user_id: session.user_id.clone(),
                email: None,
            })],
        );
        let response = handle_auth_check(
            &auth_check_request(&pending.id, &config),
            &config,
            &store,
            &null_auth,
            &FlightCoordinator::default(),
        );
        assert_eq!(response.status(), 204);
        assert_eq!(response.header_values("X-Auth-Mini-Email").count(), 0);
        assert!(active_session(&store, &pending.id).email.is_none());
    }

    #[test]
    fn pending_to_pending_refresh_has_no_intermediate_ready_state() {
        let (_dir, store, session, mut config, _clock) = test_store_session();
        config.allow_user_ids.insert(session.user_id.clone());
        let pending = make_pending(&store, &session, store.now() + Duration::seconds(30));
        let store = Arc::new(store);
        let config = Arc::new(config);
        let flights = Arc::new(FlightCoordinator::default());
        let identity_gate = RemoteGate::new();
        let auth = Arc::new(ScenarioAuth::new(
            RefreshScenario::Success,
            session.user_id.clone(),
            session.auth_session_id.clone(),
            None,
            Some(identity_gate.clone()),
            Vec::new(),
        ));
        let leader = spawn_auth_check(
            Arc::clone(&config),
            Arc::clone(&store),
            Arc::clone(&auth),
            Arc::clone(&flights),
            &pending.id,
        );
        identity_gate.wait_until_entered();
        let rotated_pending = active_session(&store, &pending.id);
        assert_eq!(rotated_pending.identity_state, IdentityState::Pending);
        assert_eq!(
            rotated_pending.refresh_generation,
            pending.refresh_generation + 1
        );
        let joiner = spawn_auth_check(
            Arc::clone(&config),
            Arc::clone(&store),
            Arc::clone(&auth),
            Arc::clone(&flights),
            &pending.id,
        );
        flights.wait_for_joiners(&pending.id, 1);
        identity_gate.release();
        assert_eq!(leader.join().expect("leader").status(), 204);
        assert_eq!(joiner.join().expect("joiner").status(), 204);
        assert_eq!(auth.refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(auth.identity_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            active_session(&store, &pending.id).refresh_generation,
            pending.refresh_generation + 1
        );
    }

    #[test]
    fn logout_idle_and_absolute_expiry_win_during_pending_identity_fetch() {
        run_pending_terminal_race(TerminalRace::Logout);
        run_pending_terminal_race(TerminalRace::IdleExpiry);
        run_pending_terminal_race(TerminalRace::AbsoluteExpiry);
    }

    #[test]
    fn valid_looking_non_200_wire_results_do_not_advance_database_state() {
        let token_body = r#"{"session_id":"auth-session","access_token":"wire-access","refresh_token":"wire-refresh","token_type":"Bearer"}"#;
        let (issuer, server) = one_response_server("201 Created", token_body, None);
        let wire_auth = WireAuth::new(issuer, "user".to_string(), "auth-session".to_string());
        let (_dir, store, session, config, _clock) = test_store_session();
        let mut leader =
            match FlightCoordinator::default().acquire(&session.id, session.observed_version()) {
                Acquire::Leader(leader) => leader,
                _ => panic!("leader"),
            };
        let outcome = execute_flight(&session, &config, &store, &wire_auth, &mut leader);
        leader.complete(outcome);
        server.join().expect("wire server");
        assert!(matches!(outcome, FlightOutcome::Indeterminate { .. }));
        let unchanged = active_session(&store, &session.id);
        assert_eq!(unchanged.identity_state, IdentityState::Ready);
        assert_eq!(unchanged.refresh_generation, 0);

        let (_dir, store, session, config, _clock) = test_store_session();
        let pending = make_pending(&store, &session, store.now() + Duration::hours(2));
        let (issuer, server) = one_response_server(
            "206 Partial Content",
            r#"{"user_id":"user","email":"fresh@example.com"}"#,
            None,
        );
        let wire_auth = WireAuth::new(
            issuer,
            session.user_id.clone(),
            session.auth_session_id.clone(),
        );
        let mut leader =
            match FlightCoordinator::default().acquire(&pending.id, pending.observed_version()) {
                Acquire::Leader(leader) => leader,
                _ => panic!("leader"),
            };
        let outcome = execute_flight(&pending, &config, &store, &wire_auth, &mut leader);
        leader.complete(outcome);
        server.join().expect("wire server");
        assert!(matches!(outcome, FlightOutcome::Indeterminate { .. }));
        let unchanged = active_session(&store, &pending.id);
        assert_eq!(unchanged.identity_state, IdentityState::Pending);
        assert_eq!(unchanged.refresh_generation, pending.refresh_generation);
    }

    #[test]
    fn redirect_wire_results_return_503_without_target_hit_or_state_change() {
        for status in [
            "302 Found",
            "307 Temporary Redirect",
            "308 Permanent Redirect",
        ] {
            let target = TcpListener::bind("127.0.0.1:0").expect("target");
            target.set_nonblocking(true).expect("nonblocking target");
            let location = format!(
                "http://{}/must-not-receive-refresh",
                target.local_addr().expect("target address")
            );
            let (issuer, server) = one_response_server(status, "", Some(location));
            let wire_auth = WireAuth::new(issuer, "user".to_string(), "auth-session".to_string());
            let (_dir, store, session, mut config, _clock) = test_store_session();
            config.allow_user_ids.insert(session.user_id.clone());
            let response = handle_auth_check(
                &auth_check_request(&session.id, &config),
                &config,
                &store,
                &wire_auth,
                &FlightCoordinator::default(),
            );
            server.join().expect("redirect source");
            assert_eq!(response.status(), 503);
            assert_eq!(response.header_values("Set-Cookie").count(), 0);
            assert!(matches!(
                target.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
            let unchanged = active_session(&store, &session.id);
            assert_eq!(unchanged.identity_state, IdentityState::Ready);
            assert_eq!(unchanged.refresh_generation, 0);
        }
    }

    fn test_store_session() -> (
        tempfile::TempDir,
        Store,
        GatewaySession,
        Config,
        ManualClock,
    ) {
        test_store_session_with_ttls(604_800, 2_592_000)
    }

    fn test_store_session_with_ttls(
        idle_ttl_seconds: i64,
        absolute_ttl_seconds: i64,
    ) -> (
        tempfile::TempDir,
        Store,
        GatewaySession,
        Config,
        ManualClock,
    ) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("gateway.sqlite");
        Store::initialize(&path).expect("initialize");
        let now = Utc
            .with_ymd_and_hms(2026, 7, 13, 12, 0, 0)
            .single()
            .expect("time");
        let clock = ManualClock::new(now);
        let store = Store::with_clock(path, Arc::new(clock.clone()));
        let session = store
            .create_session(NewSession {
                auth_session_id: "auth-session".to_string(),
                access_token: "initial-access".to_string(),
                refresh_token: "initial-refresh".to_string(),
                user_id: "user".to_string(),
                email: Some("old@example.com".to_string()),
                amr: vec!["test".to_string()],
                access_expires_at: now + Duration::seconds(30),
                idle_ttl_seconds,
                absolute_ttl_seconds,
            })
            .expect("session");
        (dir, store, session, test_config(), clock)
    }

    struct MockAuthMini {
        refreshes: Mutex<VecDeque<Result<TokenResponse, RefreshError>>>,
        identities: Mutex<VecDeque<IdentityFetchOutcome>>,
        user_id: String,
        session_id: String,
        refresh_calls: AtomicUsize,
        identity_calls: AtomicUsize,
    }

    impl MockAuthMini {
        fn new(
            refreshes: Vec<Result<TokenResponse, RefreshError>>,
            identities: Vec<IdentityFetchOutcome>,
            user_id: String,
            session_id: String,
        ) -> Self {
            Self {
                refreshes: Mutex::new(refreshes.into()),
                identities: Mutex::new(identities.into()),
                user_id,
                session_id,
                refresh_calls: AtomicUsize::new(0),
                identity_calls: AtomicUsize::new(0),
            }
        }
    }

    impl AuthMini for MockAuthMini {
        fn verify_initial_access(
            &self,
            _token: &str,
        ) -> Result<VerifiedAccessToken, AuthMiniOperationError> {
            Err(AuthMiniOperationError)
        }

        fn prepare_refresh_verifier(&self) -> Result<Jwks, RefreshError> {
            Ok(Jwks { keys: Vec::new() })
        }

        fn verify_refreshed_access(
            &self,
            _token: &str,
            _jwks: &Jwks,
        ) -> Result<VerifiedAccessToken, RefreshError> {
            Ok(VerifiedAccessToken {
                user_id: self.user_id.clone(),
                auth_session_id: self.session_id.clone(),
                amr: vec!["test".to_string()],
                exp: Utc
                    .with_ymd_and_hms(2026, 7, 13, 14, 0, 0)
                    .single()
                    .expect("time")
                    .timestamp(),
            })
        }

        fn fetch_identity(&self, _access_token: &str) -> IdentityFetchOutcome {
            self.identity_calls.fetch_add(1, Ordering::SeqCst);
            self.identities
                .lock()
                .expect("identity queue")
                .pop_front()
                .expect("identity fixture")
        }

        fn refresh(
            &self,
            _session_id: &str,
            _refresh_token: &str,
        ) -> Result<TokenResponse, RefreshError> {
            self.refresh_calls.fetch_add(1, Ordering::SeqCst);
            self.refreshes
                .lock()
                .expect("refresh queue")
                .pop_front()
                .expect("refresh fixture")
        }

        fn logout(&self, _access_token: &str) -> Result<(), AuthMiniOperationError> {
            Ok(())
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RefreshScenario {
        Success,
        Rejected,
        Temporary,
        Indeterminate,
    }

    #[derive(Clone)]
    struct RemoteGate {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    impl RemoteGate {
        fn new() -> Self {
            Self {
                entered: Arc::new(Barrier::new(2)),
                release: Arc::new(Barrier::new(2)),
            }
        }

        fn block_remote(&self) {
            self.entered.wait();
            self.release.wait();
        }

        fn wait_until_entered(&self) {
            self.entered.wait();
        }

        fn release(&self) {
            self.release.wait();
        }
    }

    struct ScenarioAuth {
        scenario: RefreshScenario,
        user_id: String,
        session_id: String,
        refresh_gate: Option<RemoteGate>,
        identity_gate: Option<RemoteGate>,
        identities: Mutex<VecDeque<IdentityFetchOutcome>>,
        refresh_calls: AtomicUsize,
        identity_calls: AtomicUsize,
    }

    impl ScenarioAuth {
        fn new(
            scenario: RefreshScenario,
            user_id: String,
            session_id: String,
            refresh_gate: Option<RemoteGate>,
            identity_gate: Option<RemoteGate>,
            identities: Vec<IdentityFetchOutcome>,
        ) -> Self {
            Self {
                scenario,
                user_id,
                session_id,
                refresh_gate,
                identity_gate,
                identities: Mutex::new(identities.into()),
                refresh_calls: AtomicUsize::new(0),
                identity_calls: AtomicUsize::new(0),
            }
        }
    }

    impl AuthMini for ScenarioAuth {
        fn verify_initial_access(
            &self,
            _token: &str,
        ) -> Result<VerifiedAccessToken, AuthMiniOperationError> {
            Err(AuthMiniOperationError)
        }

        fn prepare_refresh_verifier(&self) -> Result<Jwks, RefreshError> {
            Ok(Jwks { keys: Vec::new() })
        }

        fn verify_refreshed_access(
            &self,
            _token: &str,
            _jwks: &Jwks,
        ) -> Result<VerifiedAccessToken, RefreshError> {
            Ok(VerifiedAccessToken {
                user_id: self.user_id.clone(),
                auth_session_id: self.session_id.clone(),
                amr: vec!["fixture".to_string()],
                exp: Utc
                    .with_ymd_and_hms(2026, 7, 13, 14, 0, 0)
                    .single()
                    .expect("time")
                    .timestamp(),
            })
        }

        fn fetch_identity(&self, _access_token: &str) -> IdentityFetchOutcome {
            self.identity_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = self.identity_gate.as_ref() {
                gate.block_remote();
            }
            self.identities
                .lock()
                .expect("identity queue")
                .pop_front()
                .unwrap_or_else(|| {
                    IdentityFetchOutcome::Fresh(MeResponse {
                        user_id: self.user_id.clone(),
                        email: Some("fresh@example.com".to_string()),
                    })
                })
        }

        fn refresh(
            &self,
            _session_id: &str,
            _refresh_token: &str,
        ) -> Result<TokenResponse, RefreshError> {
            self.refresh_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = self.refresh_gate.as_ref() {
                gate.block_remote();
            }
            match self.scenario {
                RefreshScenario::Success => Ok(TokenResponse {
                    session_id: self.session_id.clone(),
                    access_token: "rotated-access".to_string(),
                    refresh_token: "rotated-refresh".to_string(),
                }),
                RefreshScenario::Rejected => {
                    Err(RefreshError::Rejected(RefreshRejected::Invalidated))
                }
                RefreshScenario::Temporary => Err(RefreshError::Temporary(
                    crate::auth_mini::TemporaryClass::Upstream,
                )),
                RefreshScenario::Indeterminate => Err(RefreshError::Indeterminate(
                    IndeterminateClass::UnexpectedStatus,
                )),
            }
        }

        fn logout(&self, _access_token: &str) -> Result<(), AuthMiniOperationError> {
            Ok(())
        }
    }

    struct WireAuth {
        client: AuthMiniClient,
        user_id: String,
        session_id: String,
    }

    impl WireAuth {
        fn new(issuer: String, user_id: String, session_id: String) -> Self {
            Self {
                client: AuthMiniClient::new(issuer),
                user_id,
                session_id,
            }
        }
    }

    impl AuthMini for WireAuth {
        fn verify_initial_access(
            &self,
            _token: &str,
        ) -> Result<VerifiedAccessToken, AuthMiniOperationError> {
            Err(AuthMiniOperationError)
        }

        fn prepare_refresh_verifier(&self) -> Result<Jwks, RefreshError> {
            Ok(Jwks { keys: Vec::new() })
        }

        fn verify_refreshed_access(
            &self,
            _token: &str,
            _jwks: &Jwks,
        ) -> Result<VerifiedAccessToken, RefreshError> {
            Ok(VerifiedAccessToken {
                user_id: self.user_id.clone(),
                auth_session_id: self.session_id.clone(),
                amr: vec!["fixture".to_string()],
                exp: Utc
                    .with_ymd_and_hms(2026, 7, 13, 14, 0, 0)
                    .single()
                    .expect("time")
                    .timestamp(),
            })
        }

        fn fetch_identity(&self, access_token: &str) -> IdentityFetchOutcome {
            self.client.fetch_identity(access_token)
        }

        fn refresh(
            &self,
            session_id: &str,
            refresh_token: &str,
        ) -> Result<TokenResponse, RefreshError> {
            self.client.refresh(session_id, refresh_token)
        }

        fn logout(&self, _access_token: &str) -> Result<(), AuthMiniOperationError> {
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum TerminalRace {
        Logout,
        IdleExpiry,
        AbsoluteExpiry,
    }

    fn run_pending_terminal_race(race: TerminalRace) {
        let lifetimes = match race {
            TerminalRace::AbsoluteExpiry => (2_592_000, 2_592_000),
            _ => (604_800, 2_592_000),
        };
        let (_dir, store, session, mut config, clock) =
            test_store_session_with_ttls(lifetimes.0, lifetimes.1);
        config.allow_user_ids.insert(session.user_id.clone());
        let store = Arc::new(store);
        let config = Arc::new(config);
        let flights = Arc::new(FlightCoordinator::default());
        let identity_gate = RemoteGate::new();
        let auth = Arc::new(ScenarioAuth::new(
            RefreshScenario::Success,
            session.user_id.clone(),
            session.auth_session_id.clone(),
            None,
            Some(identity_gate.clone()),
            Vec::new(),
        ));
        let check = spawn_auth_check(
            Arc::clone(&config),
            Arc::clone(&store),
            Arc::clone(&auth),
            Arc::clone(&flights),
            &session.id,
        );
        identity_gate.wait_until_entered();
        assert_eq!(
            active_session(&store, &session.id).identity_state,
            IdentityState::Pending
        );
        match race {
            TerminalRace::Logout => {
                let mut request = auth_check_request(&session.id, &config);
                request.path = "/logout".to_string();
                request.target = "/logout".to_string();
                let response = handle_logout(&request, &config, &store, auth.as_ref())
                    .expect("logout response");
                assert_eq!(response.status(), 302);
            }
            TerminalRace::IdleExpiry => clock.set(session.idle_expires_at),
            TerminalRace::AbsoluteExpiry => clock.set(session.absolute_expires_at),
        }
        identity_gate.release();
        let response = check.join().expect("auth check");
        assert_eq!(response.status(), 401);
        assert!(response
            .header_values("Set-Cookie")
            .any(|value| value.contains("Max-Age=0")));
        assert!(matches!(
            store.lookup_session(&session.id).expect("lookup"),
            SessionLookup::Inactive
        ));
    }

    fn spawn_auth_check<A: AuthMini + 'static>(
        config: Arc<Config>,
        store: Arc<Store>,
        auth: Arc<A>,
        flights: Arc<FlightCoordinator>,
        session_id: &str,
    ) -> thread::JoinHandle<Response> {
        let request = auth_check_request(session_id, &config);
        thread::spawn(move || handle_auth_check(&request, &config, &store, auth.as_ref(), &flights))
    }

    fn auth_check_request(session_id: &str, config: &Config) -> Request {
        let signed = crate::cookies::sign_value(session_id, &config.cookie_secret);
        Request {
            method: "GET".to_string(),
            target: "/auth/check".to_string(),
            path: "/auth/check".to_string(),
            query: std::collections::HashMap::new(),
            headers: vec![("Cookie".to_string(), format!("amg_session={signed}"))],
            body: Vec::new(),
        }
    }

    fn active_session(store: &Store, session_id: &str) -> GatewaySession {
        match store.lookup_session(session_id).expect("lookup") {
            SessionLookup::Active(session) => session,
            SessionLookup::Inactive => panic!("session must remain active"),
        }
    }

    fn make_pending(
        store: &Store,
        session: &GatewaySession,
        access_expires_at: DateTime<Utc>,
    ) -> GatewaySession {
        match store
            .persist_pending(
                session,
                PendingTokens {
                    access_token: "pending-access",
                    refresh_token: "pending-refresh",
                    user_id: &session.user_id,
                    amr: &session.amr,
                    access_expires_at,
                },
            )
            .expect("persist pending")
        {
            CasResult::Updated(pending) => pending,
            _ => panic!("pending transition"),
        }
    }

    fn one_response_server(
        status: &'static str,
        body: &'static str,
        location: Option<String>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let location = location
                .as_deref()
                .map(|value| format!("Location: {value}\r\n"))
                .unwrap_or_default();
            write!(
                stream,
                "HTTP/1.1 {status}\r\n{location}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("response");
        });
        (format!("http://{address}"), server)
    }

    fn test_config() -> Config {
        Config {
            host: "127.0.0.1".to_string(),
            port: 3000,
            public_base_url: "http://localhost:8080".to_string(),
            auth_mini_issuer: "http://127.0.0.1:7777".to_string(),
            auth_mini_public_base_url: "http://localhost:7777".to_string(),
            auth_mini_login_url: None,
            database_path: PathBuf::from(":memory:"),
            cookie_secret: "test-cookie-secret-that-is-long-enough".to_string(),
            cookie_secure: false,
            cookie_same_site: SameSite::Lax,
            session_ttl_seconds: 604_800,
            session_absolute_ttl_seconds: 2_592_000,
            session_touch_interval_seconds: 3_600,
            login_state_ttl_seconds: 600,
            refresh_skew_seconds: 60,
            allow_emails: HashSet::new(),
            allow_user_ids: HashSet::new(),
            logout_redirect: "/".to_string(),
            upstream: None,
        }
    }
}
