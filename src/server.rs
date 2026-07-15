use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant as StdInstant};

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
use crate::capacity::DownstreamLease;
use crate::config::Config;
use crate::cookies::{
    clear_cookie, read_signed_cookie, serialize_signed_cookie, LOGIN_STATE_COOKIE, SESSION_COOKIE,
};
use crate::db::{
    CasResult, GatewaySession, IdentityState, NewSession, ObservedVersion, PendingTokens,
    SessionLookup, Store, TouchResult,
};
use crate::exit::{ListenerErrnoClass, SanitizedExit};
use crate::flight::{Acquire, FlightCoordinator, FlightLeader, FlightOutcome, RejectedReason};
use crate::http::{is_safe_header_value, Request, Response};
use crate::policy::{evaluate, Identity, PolicyDecision};
use crate::proxy::{
    derive_client_ip, empty_body, full_body, parse_websocket_request, CapacityClass, GatewayBody,
    Proxy, ProxyError, ProxyIdentity,
};
use crate::return_target::{normalize_return_target, ReturnTargetMode};
use crate::runtime_plan::{AUTH_BLOCKING_ADMISSION, AUTH_BLOCKING_WORKERS};

const MAX_LOCAL_BODY: usize = 64 * 1024;
#[cfg(debug_assertions)]
const PROCESS_TEST_TERMINAL_ENV: &str = "AMG_TEST_FATAL_ACCEPT_WITH_UNFINISHABLE_RESOLVER";
#[cfg(debug_assertions)]
static PROCESS_TEST_RESOLVER_STARTED: AtomicBool = AtomicBool::new(false);

#[cfg(debug_assertions)]
struct ProcessTestUnfinishableResolver;

#[cfg(debug_assertions)]
struct ProcessTestResolverReleaseProbe;

#[cfg(debug_assertions)]
impl Drop for ProcessTestResolverReleaseProbe {
    fn drop(&mut self) {
        const RELEASE_MARKER: &[u8] = b"raw-unfinishable-resolver-release-marker\n";
        // SAFETY: immutable static bytes are written only by this debug-only
        // negative probe if the deliberately unfinishable resolver is released.
        unsafe {
            libc::write(
                libc::STDERR_FILENO,
                RELEASE_MARKER.as_ptr().cast(),
                RELEASE_MARKER.len(),
            );
        }
    }
}

#[cfg(debug_assertions)]
impl crate::proxy::HostResolver for ProcessTestUnfinishableResolver {
    fn resolve(&self, _domain: Box<str>, _port: u16) -> io::Result<Vec<SocketAddr>> {
        let _release_probe = ProcessTestResolverReleaseProbe;
        PROCESS_TEST_RESOLVER_STARTED.store(true, AtomicOrdering::Release);
        loop {
            std::thread::park();
        }
    }
}
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
    login_builder: Arc<dyn LoginStateBuilder>,
    before_auth_decision: Arc<dyn Fn() + Send + Sync>,
    proxy: Option<Proxy>,
    public_proto: String,
}

trait LoginStateBuilder: Send + Sync {
    fn build(&self, return_to: &str, config: &Config, store: &Store) -> Result<Response, ()>;
}

struct StoreLoginStateBuilder;

impl LoginStateBuilder for StoreLoginStateBuilder {
    fn build(&self, return_to: &str, config: &Config, store: &Store) -> Result<Response, ()> {
        create_login_response(return_to, config, store).map_err(|_| ())
    }
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
        Self::with_limits(AUTH_BLOCKING_WORKERS, AUTH_BLOCKING_ADMISSION)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoverableAcceptClass {
    ResourceFd,
    ResourceMemory,
    Transient,
}

impl RecoverableAcceptClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ResourceFd => "resource_fd",
            Self::ResourceMemory => "resource_memory",
            Self::Transient => "transient",
        }
    }

    const fn is_resource(self) -> bool {
        matches!(self, Self::ResourceFd | Self::ResourceMemory)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptErrorClass {
    Recoverable(RecoverableAcceptClass),
    Fatal(ListenerErrnoClass),
}

#[derive(Default)]
struct AcceptBackoff {
    class: Option<RecoverableAcceptClass>,
    same_class_streak: usize,
}

impl AcceptBackoff {
    fn next_delay(&mut self, class: RecoverableAcceptClass) -> StdDuration {
        if self.class == Some(class) {
            self.same_class_streak = self.same_class_streak.saturating_add(1);
        } else {
            self.class = Some(class);
            self.same_class_streak = 1;
        }
        let milliseconds = if class.is_resource() {
            const RESOURCE: [u64; 7] = [100, 200, 400, 800, 1_600, 3_200, 5_000];
            RESOURCE[(self.same_class_streak - 1).min(RESOURCE.len() - 1)]
        } else {
            const TRANSIENT: [u64; 6] = [10, 20, 40, 80, 160, 250];
            TRANSIENT[(self.same_class_streak - 1).min(TRANSIENT.len() - 1)]
        };
        StdDuration::from_millis(milliseconds)
    }

    fn reset(&mut self) {
        self.class = None;
        self.same_class_streak = 0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AcceptFailureEvent {
    failures: u64,
    suppressed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AcceptRecoveryEvent {
    failures: u64,
    suppressed: u64,
    duration: StdDuration,
}

#[derive(Default)]
struct AcceptFailureLogState {
    failures: u64,
    first_failure_at: Option<StdDuration>,
    last_emission_at: Option<StdDuration>,
    suppressed_since_last: u64,
}

impl AcceptFailureLogState {
    fn failure(&mut self, now: StdDuration) -> Option<AcceptFailureEvent> {
        self.failures = self.failures.saturating_add(1);
        self.first_failure_at.get_or_insert(now);
        let scheduled_power = matches!(self.failures, 1 | 2 | 4 | 8 | 16 | 32);
        let periodic = self.failures > 32
            && self
                .last_emission_at
                .is_none_or(|last| now.saturating_sub(last) >= StdDuration::from_secs(60));
        if scheduled_power || periodic {
            let event = AcceptFailureEvent {
                failures: self.failures,
                suppressed: self.suppressed_since_last,
            };
            self.suppressed_since_last = 0;
            self.last_emission_at = Some(now);
            Some(event)
        } else {
            self.suppressed_since_last = self.suppressed_since_last.saturating_add(1);
            None
        }
    }

    fn recovered(&mut self, now: StdDuration) -> Option<AcceptRecoveryEvent> {
        if self.failures == 0 {
            return None;
        }
        let event = AcceptRecoveryEvent {
            failures: self.failures,
            suppressed: self.suppressed_since_last,
            duration: now.saturating_sub(self.first_failure_at.unwrap_or(now)),
        };
        *self = Self::default();
        Some(event)
    }

    const fn summary(&self) -> (u64, u64) {
        (self.failures, self.suppressed_since_last)
    }
}

fn classify_accept_error(error: &io::Error) -> AcceptErrorClass {
    #[cfg(target_os = "linux")]
    if let Some(code) = error.raw_os_error() {
        if [libc::EMFILE, libc::ENFILE].contains(&code) {
            return AcceptErrorClass::Recoverable(RecoverableAcceptClass::ResourceFd);
        }
        if [libc::ENOBUFS, libc::ENOMEM].contains(&code) {
            return AcceptErrorClass::Recoverable(RecoverableAcceptClass::ResourceMemory);
        }
        if [
            libc::EINTR,
            libc::ECONNABORTED,
            libc::EAGAIN,
            libc::EWOULDBLOCK,
            libc::ENETDOWN,
            libc::EPROTO,
            libc::ENOPROTOOPT,
            libc::EHOSTDOWN,
            libc::ENONET,
            libc::EHOSTUNREACH,
            libc::EOPNOTSUPP,
            libc::ENETUNREACH,
            libc::EPERM,
            libc::ENOSR,
            libc::ESOCKTNOSUPPORT,
            libc::EPROTONOSUPPORT,
            libc::ETIMEDOUT,
        ]
        .contains(&code)
        {
            return AcceptErrorClass::Recoverable(RecoverableAcceptClass::Transient);
        }
        return AcceptErrorClass::Fatal(match code {
            libc::EBADF => ListenerErrnoClass::BadFd,
            libc::EFAULT => ListenerErrnoClass::Fault,
            libc::EINVAL => ListenerErrnoClass::Invalid,
            libc::ENOTSOCK => ListenerErrnoClass::NotSocket,
            _ => ListenerErrnoClass::Unknown,
        });
    }

    match error.kind() {
        io::ErrorKind::Interrupted
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::WouldBlock
        | io::ErrorKind::TimedOut => {
            AcceptErrorClass::Recoverable(RecoverableAcceptClass::Transient)
        }
        io::ErrorKind::OutOfMemory => {
            AcceptErrorClass::Recoverable(RecoverableAcceptClass::ResourceMemory)
        }
        _ => AcceptErrorClass::Fatal(ListenerErrnoClass::Unknown),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptLoopEvent {
    Recoverable {
        class: RecoverableAcceptClass,
        delay: StdDuration,
        failures: u64,
        suppressed: u64,
    },
    Recovered(AcceptRecoveryEvent),
}

type BoxAcceptFuture<'a, T> =
    Pin<Box<dyn Future<Output = io::Result<(T, SocketAddr)>> + Send + 'a>>;

trait AcceptSource {
    type Connection: Send + 'static;

    fn accept(&self) -> BoxAcceptFuture<'_, Self::Connection>;
}

trait AcceptSleeper {
    fn sleep(&self, delay: StdDuration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

trait AcceptClock {
    fn elapsed(&self) -> StdDuration;
}

struct TcpAcceptSource {
    listener: TcpListener,
    #[cfg(debug_assertions)]
    fatal_after_unfinishable_resolver: bool,
    #[cfg(debug_assertions)]
    accepted_once: AtomicBool,
}

impl AcceptSource for TcpAcceptSource {
    type Connection = tokio::net::TcpStream;

    fn accept(&self) -> BoxAcceptFuture<'_, Self::Connection> {
        Box::pin(async move {
            #[cfg(debug_assertions)]
            if self.fatal_after_unfinishable_resolver
                && self.accepted_once.load(AtomicOrdering::Acquire)
            {
                while !PROCESS_TEST_RESOLVER_STARTED.load(AtomicOrdering::Acquire) {
                    tokio::task::yield_now().await;
                }
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }

            let result = self.listener.accept().await;
            #[cfg(debug_assertions)]
            if self.fatal_after_unfinishable_resolver && result.is_ok() {
                self.accepted_once.store(true, AtomicOrdering::Release);
            }
            result
        })
    }
}

struct TokioAcceptSleeper;

impl AcceptSleeper for TokioAcceptSleeper {
    fn sleep(&self, delay: StdDuration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(delay))
    }
}

struct MonotonicAcceptClock(StdInstant);

impl MonotonicAcceptClock {
    fn new() -> Self {
        Self(StdInstant::now())
    }
}

impl AcceptClock for MonotonicAcceptClock {
    fn elapsed(&self) -> StdDuration {
        self.0.elapsed()
    }
}

async fn drive_accept_loop<S, L, C, E, A>(
    downstream: Arc<Semaphore>,
    source: &S,
    sleeper: &L,
    clock: &C,
    mut event_sink: E,
    mut accepted: A,
) -> Result<(), SanitizedExit>
where
    S: AcceptSource,
    L: AcceptSleeper,
    C: AcceptClock,
    E: FnMut(AcceptLoopEvent),
    A: FnMut(S::Connection, SocketAddr, DownstreamLease),
{
    let mut backoff = AcceptBackoff::default();
    let mut failure_log = AcceptFailureLogState::default();
    loop {
        let permit = Arc::clone(&downstream).acquire_owned().await.map_err(|_| {
            SanitizedExit::RuntimeInvariant {
                class: "downstream_semaphore_closed",
            }
        })?;
        match source.accept().await {
            Ok((connection, peer)) => {
                if let Some(recovered) = failure_log.recovered(clock.elapsed()) {
                    event_sink(AcceptLoopEvent::Recovered(recovered));
                }
                backoff.reset();
                accepted(connection, peer, DownstreamLease::new(permit));
            }
            Err(error) => {
                drop(permit);
                match classify_accept_error(&error) {
                    AcceptErrorClass::Recoverable(class) => {
                        let delay = backoff.next_delay(class);
                        if let Some(event) = failure_log.failure(clock.elapsed()) {
                            event_sink(AcceptLoopEvent::Recoverable {
                                class,
                                delay,
                                failures: event.failures,
                                suppressed: event.suppressed,
                            });
                        }
                        sleeper.sleep(delay).await;
                    }
                    AcceptErrorClass::Fatal(errno_class) => {
                        let (failures, suppressed) = failure_log.summary();
                        return Err(SanitizedExit::ListenerFatal {
                            errno_class,
                            errno_code: error.raw_os_error(),
                            prior_recoverable_failures: failures,
                            suppressed_failures: suppressed,
                        });
                    }
                }
            }
        }
    }
}

fn emit_accept_loop_event(event: AcceptLoopEvent) {
    match event {
        AcceptLoopEvent::Recoverable {
            class,
            delay,
            failures,
            suppressed,
        } => tracing::warn!(
            event = "accept_error",
            class = class.as_str(),
            backoff_ms = delay.as_millis() as u64,
            failures,
            suppressed_since_last = suppressed
        ),
        AcceptLoopEvent::Recovered(recovered) => tracing::info!(
            event = "accept_recovered",
            failures = recovered.failures,
            suppressed_since_last = recovered.suppressed,
            duration_ms = recovered.duration.as_millis() as u64
        ),
    }
}

pub async fn run_server(
    config: Config,
    auth_mini: Arc<AuthMiniClient>,
) -> Result<(), SanitizedExit> {
    let address = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(address)
        .await
        .map_err(|_| SanitizedExit::ListenerBindFailed)?;
    let auth_mini: Arc<dyn AuthMini> = auth_mini;
    run_server_with_listener(config, auth_mini, listener).await
}

pub async fn run_server_with_listener(
    config: Config,
    auth_mini: Arc<dyn AuthMini>,
    listener: TcpListener,
) -> Result<(), SanitizedExit> {
    run_server_with_listener_and_roots(config, auth_mini, listener, None).await
}

pub async fn run_server_with_listener_and_roots(
    config: Config,
    auth_mini: Arc<dyn AuthMini>,
    listener: TcpListener,
    test_roots: Option<rustls::RootCertStore>,
) -> Result<(), SanitizedExit> {
    config
        .validate()
        .map_err(|error| SanitizedExit::ConfigurationInvalid {
            class: error.class(),
        })?;
    let max_active_upstreams = config.max_active_upstreams;
    let max_blocking_resolvers = config.max_blocking_resolvers;
    #[cfg(not(debug_assertions))]
    let proxy = match (config.upstream.clone(), test_roots) {
        (Some(upstream), Some(roots)) => Some(Proxy::with_root_store(
            upstream,
            roots,
            max_active_upstreams,
            max_blocking_resolvers,
        )),
        (Some(upstream), None) => Some(Proxy::new(
            upstream,
            max_active_upstreams,
            max_blocking_resolvers,
        )),
        (None, _) => None,
    }
    .transpose()
    .map_err(|_| SanitizedExit::ProxyInitializeFailed)?;
    #[cfg(debug_assertions)]
    let proxy = if std::env::var_os(PROCESS_TEST_TERMINAL_ENV).is_some() {
        PROCESS_TEST_RESOLVER_STARTED.store(false, AtomicOrdering::Release);
        let upstream = config
            .upstream
            .clone()
            .ok_or(SanitizedExit::ProxyInitializeFailed)?;
        let roots = test_roots.unwrap_or_else(rustls::RootCertStore::empty);
        Some(
            Proxy::with_root_store_and_resolver(
                upstream,
                roots,
                max_active_upstreams,
                max_blocking_resolvers,
                Arc::new(ProcessTestUnfinishableResolver),
                Arc::new(crate::proxy::ResolverAccounting::default()),
            )
            .map_err(|_| SanitizedExit::ProxyInitializeFailed)?,
        )
    } else {
        match (config.upstream.clone(), test_roots) {
            (Some(upstream), Some(roots)) => Some(Proxy::with_root_store(
                upstream,
                roots,
                max_active_upstreams,
                max_blocking_resolvers,
            )),
            (Some(upstream), None) => Some(Proxy::new(
                upstream,
                max_active_upstreams,
                max_blocking_resolvers,
            )),
            (None, _) => None,
        }
        .transpose()
        .map_err(|_| SanitizedExit::ProxyInitializeFailed)?
    };
    serve_with_components(
        config,
        auth_mini,
        listener,
        proxy,
        AuthExecutor::new(),
        Arc::new(StoreLoginStateBuilder),
        Arc::new(|| {}),
    )
    .await
}

async fn serve_with_components(
    config: Config,
    auth_mini: Arc<dyn AuthMini>,
    listener: TcpListener,
    proxy: Option<Proxy>,
    executor: AuthExecutor,
    login_builder: Arc<dyn LoginStateBuilder>,
    before_auth_decision: Arc<dyn Fn() + Send + Sync>,
) -> Result<(), SanitizedExit> {
    let public_proto = Url::parse(&config.public_base_url)
        .map_err(|_| SanitizedExit::PublicBaseInvalid)?
        .scheme()
        .to_string();
    tracing::info!(
        event = "server_start",
        mode = if proxy.is_some() { "proxy" } else { "adapter" }
    );
    tracing::info!(
        event = "capacity_start",
        downstream_limit = config.max_downstream_connections,
        active_upstream_limit = config.max_active_upstreams,
        blocking_resolver_limit = config.max_blocking_resolvers,
        effective_domain_resolvers = config
            .max_active_upstreams
            .min(config.max_blocking_resolvers)
    );
    let downstream = Arc::new(Semaphore::new(config.max_downstream_connections));
    let config = Arc::new(config);
    let state = AppState {
        store: Arc::new(Store::new(config.database_path.clone())),
        config,
        auth_mini,
        flights: Arc::new(FlightCoordinator::default()),
        executor,
        login_builder,
        before_auth_decision,
        proxy,
        public_proto,
    };

    let source = TcpAcceptSource {
        listener,
        #[cfg(debug_assertions)]
        fatal_after_unfinishable_resolver: std::env::var_os(PROCESS_TEST_TERMINAL_ENV).is_some(),
        #[cfg(debug_assertions)]
        accepted_once: AtomicBool::new(false),
    };
    let sleeper = TokioAcceptSleeper;
    let clock = MonotonicAcceptClock::new();
    drive_accept_loop(
        downstream,
        &source,
        &sleeper,
        &clock,
        emit_accept_loop_event,
        move |stream, peer, lease| spawn_downstream_connection(stream, peer, state.clone(), lease),
    )
    .await
}

fn spawn_downstream_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    state: AppState,
    lease: DownstreamLease,
) {
    let service_lease = lease.clone();
    tokio::spawn(async move {
        let service = service_fn(move |request| {
            let state = state.clone();
            let lease = service_lease.clone();
            async move { Ok::<_, Infallible>(handle_hyper_request(request, peer, state, lease).await) }
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
        drop(lease);
    });
}

async fn handle_hyper_request(
    request: HyperRequest<Incoming>,
    peer: SocketAddr,
    state: AppState,
    downstream_lease: DownstreamLease,
) -> HyperResponse<GatewayBody> {
    let path = request.uri().path().to_string();
    if OWNED_PATHS.contains(&path.as_str()) {
        return handle_local_request(request, state, false).await;
    }
    if state.proxy.is_none() {
        return handle_local_request(request, state, true).await;
    }
    handle_proxy_fallback(request, peer, state, downstream_lease).await
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
    downstream_lease: DownstreamLease,
) -> HyperResponse<GatewayBody> {
    let body_bearing = request_has_body(&request);
    if request
        .headers()
        .keys()
        .any(|name| name.as_str().as_bytes().contains(&b'_'))
    {
        return generated_response(400, "Bad request", true, None);
    }
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
    let client_ip = match derive_client_ip(
        peer.ip(),
        request.headers(),
        &state.config.trusted_proxy_cidrs,
    ) {
        Ok(client_ip) => client_ip,
        Err(_) => return generated_response(400, "Bad request", true, None),
    };
    let websocket = match parse_websocket_request(&request) {
        Ok(websocket) => websocket,
        Err(_) => return generated_response(400, "Bad request", true, None),
    };
    let cookie = request
        .headers()
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let auth_result = match run_proxy_auth_operation(&state, cookie, path_and_query.clone()).await {
        Ok(result) => result,
        Err(error) => return proxy_auth_execution_error_response(error, body_bearing),
    };

    let (identity, renewal) = match proxy_auth_result_outcome(auth_result, body_bearing) {
        ProxyAuthOutcome::Allowed(identity, renewal) => (identity, renewal),
        ProxyAuthOutcome::Response(response) => return response,
    };

    let proxy = state.proxy.as_ref().expect("proxy mode");
    let result = proxy
        .forward(
            request,
            &path_and_query,
            client_ip,
            &state.public_proto,
            ProxyIdentity {
                user_id: identity.user_id,
                email: identity.email,
            },
            renewal.clone(),
            body_bearing,
            websocket,
            downstream_lease,
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
        Err(ProxyError::Capacity(class)) => {
            tracing::info!(
                event = "proxy_capacity",
                class = match class {
                    CapacityClass::ActiveUpstream => "active_upstream",
                    CapacityClass::BlockingResolver => "blocking_resolver",
                },
                outcome = "saturated"
            );
            service_capacity_hyper(body_bearing, renewal)
        }
    }
}

fn proxy_auth_execution_error_response(
    error: AuthExecutionError,
    body_bearing: bool,
) -> HyperResponse<GatewayBody> {
    match error {
        AuthExecutionError::Overloaded => auth_unavailable_hyper(body_bearing, None),
        AuthExecutionError::Internal => {
            generated_response(500, "Internal server error", body_bearing, None)
        }
    }
}

enum ProxyAuthOutcome {
    Allowed(VerifiedIdentity, Option<String>),
    Response(HyperResponse<GatewayBody>),
}

fn proxy_auth_result_outcome(auth_result: ProxyAuthResult, body_bearing: bool) -> ProxyAuthOutcome {
    match auth_result {
        ProxyAuthResult::Decision(AuthDecision::Allow {
            identity,
            session_renewal,
        }) => ProxyAuthOutcome::Allowed(identity, session_renewal),
        ProxyAuthResult::Decision(AuthDecision::Forbidden) => {
            ProxyAuthOutcome::Response(generated_response(403, "Forbidden", body_bearing, None))
        }
        ProxyAuthResult::Decision(AuthDecision::Unavailable) => {
            ProxyAuthOutcome::Response(auth_unavailable_hyper(body_bearing, None))
        }
        ProxyAuthResult::Decision(AuthDecision::Unauthenticated { .. }) => {
            ProxyAuthOutcome::Response(generated_response(
                500,
                "Internal server error",
                body_bearing,
                None,
            ))
        }
        ProxyAuthResult::LoginReady {
            clear_session,
            login_response,
        } => ProxyAuthOutcome::Response(local_into_hyper(
            login_response.prepend_cookie(clear_session),
            body_bearing,
        )),
        ProxyAuthResult::LoginInternal { clear_session } => {
            ProxyAuthOutcome::Response(generated_response(
                500,
                "Internal server error",
                body_bearing,
                Some(clear_session),
            ))
        }
    }
}

async fn run_proxy_auth_operation(
    state: &AppState,
    cookie: Option<String>,
    return_to: String,
) -> Result<ProxyAuthResult, AuthExecutionError> {
    let config = Arc::clone(&state.config);
    let store = Arc::clone(&state.store);
    let auth_mini = Arc::clone(&state.auth_mini);
    let flights = Arc::clone(&state.flights);
    let login_builder = Arc::clone(&state.login_builder);
    let before_auth_decision = Arc::clone(&state.before_auth_decision);
    state
        .executor
        .run(move || {
            execute_proxy_auth(
                || {
                    before_auth_decision();
                    auth_decision(
                        cookie.as_deref(),
                        &config,
                        &store,
                        auth_mini.as_ref(),
                        &flights,
                    )
                },
                || login_builder.build(&return_to, &config, &store),
            )
        })
        .await
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

fn service_capacity_hyper(close: bool, renewal: Option<String>) -> HyperResponse<GatewayBody> {
    let mut response = generated_response(503, "Service temporarily unavailable", close, renewal);
    response
        .headers_mut()
        .insert(http::header::RETRY_AFTER, HeaderValue::from_static("5"));
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("31"));
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

enum ProxyAuthResult {
    Decision(AuthDecision),
    LoginReady {
        clear_session: String,
        login_response: Response,
    },
    LoginInternal {
        clear_session: String,
    },
}

fn execute_proxy_auth<D, L, E>(decide: D, build_login: L) -> ProxyAuthResult
where
    D: FnOnce() -> AuthDecision,
    L: FnOnce() -> Result<Response, E>,
{
    // Deliberately outside the unwind catcher: a panic before the shared
    // decision exists has no trustworthy cookie-cleanup metadata.
    let decision = decide();
    let AuthDecision::Unauthenticated { clear_session } = decision else {
        return ProxyAuthResult::Decision(decision);
    };
    match catch_unwind(AssertUnwindSafe(build_login)) {
        Ok(Ok(login_response)) => ProxyAuthResult::LoginReady {
            clear_session,
            login_response,
        },
        Ok(Err(_)) | Err(_) => ProxyAuthResult::LoginInternal { clear_session },
    }
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
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Condvar, Mutex};
    use std::thread;

    use chrono::TimeZone;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use crate::auth_mini::{
        AuthMiniClient, AuthMiniOperationError, IdentityUnavailable, MeResponse, RefreshRejected,
        TokenResponse,
    };
    use crate::config::SameSite;
    use crate::jwt::{Jwks, VerifiedAccessToken};
    use crate::runtime_plan::RuntimePlan;
    use crate::util::ManualClock;

    use super::*;

    struct ScriptedAcceptSource {
        results: Mutex<VecDeque<io::Result<(usize, SocketAddr)>>>,
    }

    impl AcceptSource for ScriptedAcceptSource {
        type Connection = usize;

        fn accept(&self) -> BoxAcceptFuture<'_, Self::Connection> {
            let result = self
                .results
                .lock()
                .expect("scripted accepts")
                .pop_front()
                .expect("scripted accept exhausted");
            Box::pin(async move { result })
        }
    }

    struct ManualAcceptClock {
        millis: AtomicU64,
    }

    impl AcceptClock for ManualAcceptClock {
        fn elapsed(&self) -> StdDuration {
            StdDuration::from_millis(self.millis.load(Ordering::Acquire))
        }
    }

    struct RecordingAcceptSleeper {
        clock: Arc<ManualAcceptClock>,
        downstream: Arc<Semaphore>,
        delays: Mutex<Vec<StdDuration>>,
        available_during_sleep: Mutex<Vec<usize>>,
    }

    #[derive(Clone, Copy)]
    enum TestLoginBehavior {
        Success,
        Error,
        Panic,
    }

    struct ObservingLoginBuilder {
        behavior: TestLoginBehavior,
        calls: Arc<AtomicUsize>,
        observed_admission_available: Arc<AtomicUsize>,
        admission: Arc<Semaphore>,
    }

    struct BlockingTestResolver {
        address: SocketAddr,
        submissions: Arc<AtomicUsize>,
        started: Arc<AtomicBool>,
        gate: Arc<(Mutex<bool>, Condvar)>,
    }

    struct CountingTestResolver {
        address: SocketAddr,
        submissions: Arc<AtomicUsize>,
    }

    impl crate::proxy::HostResolver for CountingTestResolver {
        fn resolve(&self, _domain: Box<str>, _port: u16) -> io::Result<Vec<SocketAddr>> {
            self.submissions.fetch_add(1, Ordering::SeqCst);
            Ok(vec![self.address])
        }
    }

    impl crate::proxy::HostResolver for BlockingTestResolver {
        fn resolve(&self, _domain: Box<str>, _port: u16) -> io::Result<Vec<SocketAddr>> {
            self.submissions.fetch_add(1, Ordering::SeqCst);
            self.started.store(true, Ordering::Release);
            let (lock, condition) = &*self.gate;
            let mut released = lock.lock().expect("resolver gate");
            while !*released {
                released = condition.wait(released).expect("resolver wait");
            }
            Ok(vec![self.address])
        }
    }

    impl LoginStateBuilder for ObservingLoginBuilder {
        fn build(&self, return_to: &str, config: &Config, store: &Store) -> Result<Response, ()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.observed_admission_available
                .store(self.admission.available_permits(), Ordering::SeqCst);
            match self.behavior {
                TestLoginBehavior::Success => {
                    create_login_response(return_to, config, store).map_err(|_| ())
                }
                TestLoginBehavior::Error => Err(()),
                TestLoginBehavior::Panic => {
                    std::panic::panic_any("post-unauth-login-payload-marker")
                }
            }
        }
    }

    impl AcceptSleeper for RecordingAcceptSleeper {
        fn sleep(&self, delay: StdDuration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.delays.lock().expect("delays").push(delay);
            self.available_during_sleep
                .lock()
                .expect("sleep permits")
                .push(self.downstream.available_permits());
            self.clock
                .millis
                .fetch_add(delay.as_millis() as u64, Ordering::AcqRel);
            Box::pin(async {})
        }
    }

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

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_accept_errors_have_exact_recoverable_and_fatal_classes() {
        for (errno, expected) in [
            (
                libc::EMFILE,
                AcceptErrorClass::Recoverable(RecoverableAcceptClass::ResourceFd),
            ),
            (
                libc::ENFILE,
                AcceptErrorClass::Recoverable(RecoverableAcceptClass::ResourceFd),
            ),
            (
                libc::ENOMEM,
                AcceptErrorClass::Recoverable(RecoverableAcceptClass::ResourceMemory),
            ),
            (
                libc::ECONNABORTED,
                AcceptErrorClass::Recoverable(RecoverableAcceptClass::Transient),
            ),
            (
                libc::ENETUNREACH,
                AcceptErrorClass::Recoverable(RecoverableAcceptClass::Transient),
            ),
            (
                libc::EBADF,
                AcceptErrorClass::Fatal(ListenerErrnoClass::BadFd),
            ),
            (
                libc::EFAULT,
                AcceptErrorClass::Fatal(ListenerErrnoClass::Fault),
            ),
            (
                libc::EINVAL,
                AcceptErrorClass::Fatal(ListenerErrnoClass::Invalid),
            ),
            (
                libc::ENOTSOCK,
                AcceptErrorClass::Fatal(ListenerErrnoClass::NotSocket),
            ),
            (
                1_000_000,
                AcceptErrorClass::Fatal(ListenerErrnoClass::Unknown),
            ),
        ] {
            assert_eq!(
                classify_accept_error(&io::Error::from_raw_os_error(errno)),
                expected
            );
        }
    }

    #[test]
    fn accept_backoff_is_bounded_class_local_and_success_resettable() {
        let mut backoff = AcceptBackoff::default();
        let transient: Vec<_> = (0..8)
            .map(|_| {
                backoff
                    .next_delay(RecoverableAcceptClass::Transient)
                    .as_millis()
            })
            .collect();
        assert_eq!(transient, [10, 20, 40, 80, 160, 250, 250, 250]);
        assert_eq!(
            backoff
                .next_delay(RecoverableAcceptClass::ResourceFd)
                .as_millis(),
            100
        );
        let resource_tail: Vec<_> = (0..8)
            .map(|_| {
                backoff
                    .next_delay(RecoverableAcceptClass::ResourceFd)
                    .as_millis()
            })
            .collect();
        assert_eq!(
            resource_tail,
            [200, 400, 800, 1_600, 3_200, 5_000, 5_000, 5_000]
        );
        assert_eq!(
            backoff
                .next_delay(RecoverableAcceptClass::ResourceMemory)
                .as_millis(),
            100
        );
        backoff.reset();
        assert_eq!(
            backoff
                .next_delay(RecoverableAcceptClass::Transient)
                .as_millis(),
            10
        );
    }

    #[test]
    fn accept_logging_is_global_across_classes_and_rate_limited() {
        let mut state = AcceptFailureLogState::default();
        let mut emitted = Vec::new();
        for index in 0..100u64 {
            if let Some(event) = state.failure(StdDuration::from_secs(index)) {
                emitted.push((event.failures, event.suppressed));
            }
        }
        assert_eq!(
            emitted.iter().map(|event| event.0).collect::<Vec<_>>(),
            [1, 2, 4, 8, 16, 32, 92]
        );
        assert_eq!(emitted[3], (8, 3));
        let recovered = state
            .recovered(StdDuration::from_secs(100))
            .expect("recovery summary");
        assert_eq!(recovered.failures, 100);
        assert_eq!(recovered.suppressed, 8);
        assert_eq!(recovered.duration, StdDuration::from_secs(100));
        assert_eq!(state.summary(), (0, 0));
        assert_eq!(
            state
                .failure(StdDuration::from_secs(101))
                .expect("fresh first event")
                .failures,
            1
        );
    }

    #[tokio::test]
    async fn injected_accept_loop_retries_recovers_resets_and_fails_sanitized() {
        let peer = "127.0.0.1:12345".parse().expect("peer");
        let mut script = VecDeque::new();
        for index in 0..40 {
            let errno = if index % 2 == 0 {
                libc::ECONNABORTED
            } else {
                libc::EMFILE
            };
            script.push_back(Err(io::Error::from_raw_os_error(errno)));
        }
        script.push_back(Ok((7, peer)));
        script.push_back(Err(io::Error::from_raw_os_error(libc::EINTR)));
        script.push_back(Err(io::Error::from_raw_os_error(libc::EBADF)));
        let source = ScriptedAcceptSource {
            results: Mutex::new(script),
        };
        let downstream = Arc::new(Semaphore::new(1));
        let clock = Arc::new(ManualAcceptClock {
            millis: AtomicU64::new(0),
        });
        let sleeper = RecordingAcceptSleeper {
            clock: Arc::clone(&clock),
            downstream: Arc::clone(&downstream),
            delays: Mutex::new(Vec::new()),
            available_during_sleep: Mutex::new(Vec::new()),
        };
        let events = Arc::new(Mutex::new(Vec::new()));
        let event_capture = Arc::clone(&events);
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let accepted_capture = Arc::clone(&accepted);
        let result = drive_accept_loop(
            Arc::clone(&downstream),
            &source,
            &sleeper,
            clock.as_ref(),
            move |event| event_capture.lock().expect("events").push(event),
            move |connection, accepted_peer, lease| {
                accepted_capture
                    .lock()
                    .expect("accepted")
                    .push((connection, accepted_peer));
                drop(lease);
            },
        )
        .await;
        assert_eq!(
            result,
            Err(SanitizedExit::ListenerFatal {
                errno_class: ListenerErrnoClass::BadFd,
                errno_code: Some(libc::EBADF),
                prior_recoverable_failures: 1,
                suppressed_failures: 0,
            })
        );
        assert_eq!(*accepted.lock().expect("accepted result"), [(7, peer)]);
        assert_eq!(downstream.available_permits(), 1);
        let delays = sleeper.delays.lock().expect("recorded delays");
        assert_eq!(delays.len(), 41);
        for (index, delay) in delays[..40].iter().enumerate() {
            assert_eq!(delay.as_millis(), if index % 2 == 0 { 10 } else { 100 });
        }
        assert_eq!(delays[40], StdDuration::from_millis(10));
        assert!(sleeper
            .available_during_sleep
            .lock()
            .expect("sleep reservations")
            .iter()
            .all(|available| *available == 1));

        let events = events.lock().expect("captured events");
        let failures: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                AcceptLoopEvent::Recoverable { failures, .. } => Some(*failures),
                AcceptLoopEvent::Recovered(_) => None,
            })
            .collect();
        assert_eq!(failures, [1, 2, 4, 8, 16, 32, 1]);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, AcceptLoopEvent::Recovered(_)))
                .count(),
            1
        );
        let recovered = events
            .iter()
            .find_map(|event| match event {
                AcceptLoopEvent::Recovered(event) => Some(*event),
                _ => None,
            })
            .expect("recovery event");
        assert_eq!(recovered.failures, 40);
        assert_eq!(recovered.suppressed, 8);
    }

    #[test]
    fn proxy_auth_phase_maps_login_errors_and_panics_without_catching_decision_panics() {
        crate::exit::install_sanitized_panic_hook();
        let clear = "amg_session=; Max-Age=0".to_string();
        let ready = execute_proxy_auth(
            || AuthDecision::Unauthenticated {
                clear_session: clear.clone(),
            },
            || Ok::<_, ()>(Response::redirect("/login")),
        );
        assert!(matches!(
            ready,
            ProxyAuthResult::LoginReady { clear_session, .. } if clear_session == clear
        ));

        let failed = execute_proxy_auth(
            || AuthDecision::Unauthenticated {
                clear_session: clear.clone(),
            },
            || Err::<Response, _>("database failure marker"),
        );
        assert!(matches!(
            failed,
            ProxyAuthResult::LoginInternal { clear_session } if clear_session == clear
        ));

        let panicked = execute_proxy_auth(
            || AuthDecision::Unauthenticated {
                clear_session: clear.clone(),
            },
            || -> Result<Response, ()> { panic!("post-decision marker") },
        );
        assert!(matches!(
            panicked,
            ProxyAuthResult::LoginInternal { clear_session } if clear_session == clear
        ));

        let pre_decision = catch_unwind(AssertUnwindSafe(|| {
            execute_proxy_auth(
                || -> AuthDecision { panic!("pre-decision marker") },
                || Ok::<_, ()>(Response::empty(204)),
            )
        }));
        assert!(pre_decision.is_err());
    }

    #[tokio::test]
    async fn service_capacity_response_is_exact_and_cookie_optional() {
        let response = service_capacity_hyper(true, None);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[http::header::RETRY_AFTER], "5");
        assert_eq!(response.headers()[CONTENT_LENGTH], "31");
        assert_eq!(response.headers()[CONNECTION], "close");
        assert!(!response.headers().contains_key(SET_COOKIE));
        let body = response
            .into_body()
            .collect()
            .await
            .expect("capacity body")
            .to_bytes();
        assert_eq!(body, Bytes::from_static(b"Service temporarily unavailable"));

        let renewed = service_capacity_hyper(false, Some("amg_session=renewed".to_string()));
        assert_eq!(renewed.headers().get_all(SET_COOKIE).iter().count(), 1);
        assert!(!renewed.headers().contains_key(CONNECTION));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn raw_resolver_saturation_is_immediate_no_wait_and_control_plane_safe() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("resolver upstream bind");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let upstream_hits = Arc::new(AtomicUsize::new(0));
        let task_hits = Arc::clone(&upstream_hits);
        let upstream_task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = upstream_listener.accept().await {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                task_hits.fetch_add(1, Ordering::SeqCst);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            }
        });

        let dir = tempdir().expect("resolver gateway tempdir");
        let database = dir.path().join("gateway.sqlite");
        Store::initialize(&database).expect("resolver gateway store");
        let mut config = test_config();
        config.database_path = database.clone();
        config.port = 0;
        config.public_base_url = "http://public.example".to_string();
        config.upstream = crate::config::parse_upstream_url(Some(&format!(
            "http://blocked-resolver.example:{}/base",
            upstream_address.port()
        )))
        .expect("domain upstream URL");
        config.max_downstream_connections = 18;
        config.max_active_upstreams = 2;
        config.max_blocking_resolvers = 1;
        config.allow_user_ids.insert("resolver-user".to_string());
        config.validate().expect("resolver test config");
        let store = Store::new(database);
        let session = store
            .create_session(NewSession {
                auth_session_id: "resolver-auth-session".to_string(),
                access_token: "resolver-access".to_string(),
                refresh_token: "resolver-refresh".to_string(),
                user_id: "resolver-user".to_string(),
                email: None,
                amr: vec!["fixture".to_string()],
                access_expires_at: Utc::now() + Duration::hours(2),
                idle_ttl_seconds: config.session_ttl_seconds,
                absolute_ttl_seconds: config.session_absolute_ttl_seconds,
            })
            .expect("resolver session");
        let cookie = crate::cookies::sign_value(&session.id, &config.cookie_secret);

        let submissions = Arc::new(AtomicUsize::new(0));
        let resolver_started = Arc::new(AtomicBool::new(false));
        let resolver_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let accounting = Arc::new(crate::proxy::ResolverAccounting::default());
        let resolver = Arc::new(BlockingTestResolver {
            address: upstream_address,
            submissions: Arc::clone(&submissions),
            started: Arc::clone(&resolver_started),
            gate: Arc::clone(&resolver_gate),
        });
        let proxy = Proxy::with_root_store_and_resolver(
            config.upstream.clone().expect("upstream"),
            rustls::RootCertStore::empty(),
            2,
            1,
            resolver,
            Arc::clone(&accounting),
        )
        .expect("resolver proxy");
        let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("resolver gateway bind");
        let gateway_address = gateway_listener.local_addr().expect("gateway address");
        let gateway_task = tokio::spawn(serve_with_components(
            config,
            Arc::new(MockAuthMini::new(
                Vec::new(),
                Vec::new(),
                "unused-user".to_string(),
                "unused-session".to_string(),
            )),
            gateway_listener,
            Some(proxy),
            AuthExecutor::new(),
            Arc::new(StoreLoginStateBuilder),
            Arc::new(|| {}),
        ));

        let mut first = tokio::net::TcpStream::connect(gateway_address)
            .await
            .expect("first resolver request");
        first
            .write_all(
                format!(
                    "GET /first HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("first resolver head");
        tokio::time::timeout(StdDuration::from_secs(5), async {
            while !resolver_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first resolver started");
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
        let snapshot = accounting.snapshot();
        assert_eq!(snapshot.held_r, 1);
        assert_eq!(snapshot.submitted_unobserved, 1);
        assert_eq!(snapshot.request_owned, 1);
        assert_eq!(snapshot.cleanup_owned, 0);
        assert_eq!(snapshot.live_blocking, 1);

        let mut second = tokio::net::TcpStream::connect(gateway_address)
            .await
            .expect("second resolver request");
        second
            .write_all(
                format!(
                    "POST /second HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nContent-Length: 24\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("second resolver head");
        let marker = b"never-send-resolver-body";
        let mut response = Vec::new();
        tokio::time::timeout(StdDuration::from_secs(2), async {
            let mut byte = [0u8; 1];
            while !response.ends_with(b"\r\n\r\n") {
                second
                    .read_exact(&mut byte)
                    .await
                    .expect("capacity response head");
                response.push(byte[0]);
            }
        })
        .await
        .expect("resolver saturation head was immediate");
        let marker_sent = response.starts_with(b"HTTP/1.1 100");
        if marker_sent {
            second
                .write_all(marker)
                .await
                .expect("send marker only after 100");
        }
        tokio::time::timeout(StdDuration::from_secs(2), second.read_to_end(&mut response))
            .await
            .expect("resolver saturation EOF")
            .expect("resolver saturation response");
        let split = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("capacity response delimiter");
        let head = String::from_utf8_lossy(&response[..split + 4]).to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 503 service unavailable"));
        assert!(!head.contains("100 continue"));
        assert!(!marker_sent);
        assert!(head.contains("content-length: 31"));
        assert!(head.contains("content-type: text/plain; charset=utf-8"));
        assert!(head.contains("cache-control: no-store"));
        assert!(head.contains("retry-after: 5"));
        assert!(head.contains("connection: close"));
        assert!(!head.contains("set-cookie:"));
        assert_eq!(&response[split + 4..], b"Service temporarily unavailable");
        assert!(!response
            .windows(marker.len())
            .any(|window| window == marker));
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
        assert_eq!(accounting.snapshot(), snapshot);

        let mut canceled = tokio::net::TcpStream::connect(gateway_address)
            .await
            .expect("canceled R+1 request");
        canceled
            .write_all(
                format!(
                    "GET /canceled-r-plus-one HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("canceled request head");
        drop(canceled);
        tokio::task::yield_now().await;
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
        assert_eq!(accounting.snapshot(), snapshot);

        let mut health = tokio::net::TcpStream::connect(gateway_address)
            .await
            .expect("health connection");
        health
            .write_all(
                b"GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("health request");
        let mut health_response = Vec::new();
        health
            .read_to_end(&mut health_response)
            .await
            .expect("health response");
        assert!(health_response.starts_with(b"HTTP/1.1 204"));

        {
            let (lock, condition) = &*resolver_gate;
            *lock.lock().expect("resolver release") = true;
            condition.notify_all();
        }
        let mut first_response = Vec::new();
        first
            .read_to_end(&mut first_response)
            .await
            .expect("first resolver response");
        assert!(first_response.starts_with(b"HTTP/1.1 200"));
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
        tokio::time::timeout(StdDuration::from_secs(5), async {
            loop {
                let snapshot = accounting.snapshot();
                if snapshot.held_r == 0
                    && snapshot.submitted_unobserved == 0
                    && snapshot.request_owned == 0
                    && snapshot.cleanup_owned == 0
                    && snapshot.live_blocking == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("resolver accounting drained");
        assert_eq!(accounting.snapshot().total_submitted, 1);

        gateway_task.abort();
        upstream_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn warm_domain_pool_reuse_bypasses_occupied_r_without_accounting_change() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("pooled domain upstream bind");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("pooled upstream address");
        let upstream_connections = Arc::new(AtomicUsize::new(0));
        let upstream_hits = Arc::new(AtomicUsize::new(0));
        let task_connections = Arc::clone(&upstream_connections);
        let task_hits = Arc::clone(&upstream_hits);
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.expect("pooled accept");
            task_connections.fetch_add(1, Ordering::SeqCst);
            let service = service_fn(move |_request: HyperRequest<Incoming>| {
                let hits = Arc::clone(&task_hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, Infallible>(HyperResponse::new(full_body("ok")))
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let dir = tempdir().expect("pooled domain tempdir");
        let database = dir.path().join("gateway.sqlite");
        Store::initialize(&database).expect("pooled domain store");
        let mut config = test_config();
        config.database_path = database.clone();
        config.public_base_url = "http://public.example".to_string();
        config.upstream = crate::config::parse_upstream_url(Some(&format!(
            "http://pooled-domain.example:{}/base",
            upstream_address.port()
        )))
        .expect("pooled domain URL");
        config.max_downstream_connections = 18;
        config.max_active_upstreams = 2;
        config.max_blocking_resolvers = 1;
        config.allow_user_ids.insert("pooled-user".to_string());
        config.validate().expect("pooled domain config");
        let session = Store::new(database)
            .create_session(NewSession {
                auth_session_id: "pooled-auth-session".to_string(),
                access_token: "pooled-access".to_string(),
                refresh_token: "pooled-refresh".to_string(),
                user_id: "pooled-user".to_string(),
                email: None,
                amr: vec!["fixture".to_string()],
                access_expires_at: Utc::now() + Duration::hours(2),
                idle_ttl_seconds: config.session_ttl_seconds,
                absolute_ttl_seconds: config.session_absolute_ttl_seconds,
            })
            .expect("pooled domain session");
        let cookie = crate::cookies::sign_value(&session.id, &config.cookie_secret);
        let resolver_submissions = Arc::new(AtomicUsize::new(0));
        let accounting = Arc::new(crate::proxy::ResolverAccounting::default());
        let proxy = Proxy::with_root_store_and_resolver(
            config.upstream.clone().expect("pooled upstream"),
            rustls::RootCertStore::empty(),
            2,
            1,
            Arc::new(CountingTestResolver {
                address: upstream_address,
                submissions: Arc::clone(&resolver_submissions),
            }),
            Arc::clone(&accounting),
        )
        .expect("pooled domain proxy");
        let proxy_probe = proxy.clone();
        let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("pooled gateway bind");
        let gateway_address = gateway_listener
            .local_addr()
            .expect("pooled gateway address");
        let gateway_task = tokio::spawn(serve_with_components(
            config,
            Arc::new(MockAuthMini::new(
                Vec::new(),
                Vec::new(),
                "unused-user".to_string(),
                "unused-session".to_string(),
            )),
            gateway_listener,
            Some(proxy),
            AuthExecutor::new(),
            Arc::new(StoreLoginStateBuilder),
            Arc::new(|| {}),
        ));

        let mut first = tokio::net::TcpStream::connect(gateway_address)
            .await
            .expect("first pooled request");
        first
            .write_all(
                format!(
                    "GET /first HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("first pooled request head");
        let mut first_response = Vec::new();
        first
            .read_to_end(&mut first_response)
            .await
            .expect("first pooled response");
        assert!(first_response.starts_with(b"HTTP/1.1 200"));
        tokio::time::timeout(StdDuration::from_secs(5), async {
            while proxy_probe.idle_owner_count() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("domain owner parked");
        assert_eq!(resolver_submissions.load(Ordering::SeqCst), 1);
        assert_eq!(upstream_connections.load(Ordering::SeqCst), 1);
        let drained = accounting.snapshot();
        assert_eq!(
            drained,
            crate::proxy::ResolverSnapshot {
                total_submitted: 1,
                ..crate::proxy::ResolverSnapshot::default()
            }
        );

        let resolver_occupancy = proxy_probe.occupy_resolver_for_test();
        let occupied = accounting.snapshot();
        assert_eq!(occupied.held_r, 1);
        assert_eq!(occupied.total_submitted, 1);
        assert_eq!(occupied.submitted_unobserved, 0);
        let mut second = tokio::net::TcpStream::connect(gateway_address)
            .await
            .expect("second pooled request");
        second
            .write_all(
                format!(
                    "GET /second HTTP/1.1\r\nHost: public.example\r\nCookie: amg_session={cookie}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("second pooled request head");
        let mut second_response = Vec::new();
        second
            .read_to_end(&mut second_response)
            .await
            .expect("second pooled response");
        assert!(second_response.starts_with(b"HTTP/1.1 200"));
        tokio::time::timeout(StdDuration::from_secs(5), async {
            while proxy_probe.idle_owner_count() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reused domain owner reparked");
        assert_eq!(resolver_submissions.load(Ordering::SeqCst), 1);
        assert_eq!(upstream_connections.load(Ordering::SeqCst), 1);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 2);
        assert_eq!(accounting.snapshot(), occupied);
        drop(resolver_occupancy);
        assert_eq!(accounting.snapshot(), drained);

        gateway_task.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn predecision_overload_and_internal_responses_are_cookie_neutral() {
        let overloaded = auth_unavailable_hyper(true, None);
        assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(overloaded.headers()[http::header::RETRY_AFTER], "5");
        assert!(!overloaded.headers().contains_key(SET_COOKIE));
        let body = overloaded
            .into_body()
            .collect()
            .await
            .expect("auth overload body")
            .to_bytes();
        assert_eq!(
            body,
            Bytes::from_static(b"Authentication service temporarily unavailable")
        );

        let internal = generated_response(500, "Internal server error", true, None);
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!internal.headers().contains_key(SET_COOKIE));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handler_auth_login_seams_pin_single_admission_and_cookie_phases() {
        crate::exit::install_sanitized_panic_hook();
        let dir = tempdir().expect("handler auth tempdir");
        let database = dir.path().join("gateway.sqlite");
        Store::initialize(&database).expect("handler auth store");
        let mut config = test_config();
        config.database_path = database.clone();
        let config = Arc::new(config);
        let store = Arc::new(Store::new(database.clone()));
        let count_login_states = || {
            rusqlite::Connection::open(&database)
                .expect("open handler auth database")
                .query_row("SELECT COUNT(*) FROM login_states", [], |row| {
                    row.get::<_, usize>(0)
                })
                .expect("count login states")
        };
        assert_eq!(count_login_states(), 0);
        let auth: Arc<dyn AuthMini> = Arc::new(MockAuthMini::new(
            Vec::new(),
            Vec::new(),
            "unused-user".to_string(),
            "unused-session".to_string(),
        ));

        let make_state = |executor: AuthExecutor,
                          behavior: TestLoginBehavior,
                          before_auth_decision: Arc<dyn Fn() + Send + Sync>,
                          calls: Arc<AtomicUsize>,
                          observed: Arc<AtomicUsize>| {
            let builder = Arc::new(ObservingLoginBuilder {
                behavior,
                calls,
                observed_admission_available: observed,
                admission: Arc::clone(&executor.admission),
            });
            AppState {
                config: Arc::clone(&config),
                store: Arc::clone(&store),
                auth_mini: Arc::clone(&auth),
                flights: Arc::new(FlightCoordinator::default()),
                executor,
                login_builder: builder,
                before_auth_decision,
                proxy: None,
                public_proto: "http".to_string(),
            }
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(AtomicUsize::new(usize::MAX));
        let state = make_state(
            AuthExecutor::with_limits(1, 1),
            TestLoginBehavior::Success,
            Arc::new(|| {}),
            Arc::clone(&calls),
            Arc::clone(&observed),
        );
        let ready = run_proxy_auth_operation(&state, None, "/private".to_string())
            .await
            .expect("single admitted login");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(observed.load(Ordering::SeqCst), 0);
        let ProxyAuthOutcome::Response(response) = proxy_auth_result_outcome(ready, false) else {
            panic!("login unexpectedly allowed upstream");
        };
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(response.headers().get_all(SET_COOKIE).iter().count(), 2);
        let cookies: Vec<_> = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| value.to_str().expect("cookie"))
            .collect();
        assert!(cookies[0].contains("amg_session="));
        assert!(cookies[0].contains("Max-Age=0"));
        assert!(cookies[1].contains("amg_login_state="));
        assert_eq!(count_login_states(), 1);

        let calls = Arc::new(AtomicUsize::new(0));
        let overloaded = make_state(
            AuthExecutor::with_limits(1, 0),
            TestLoginBehavior::Success,
            Arc::new(|| {}),
            Arc::clone(&calls),
            Arc::new(AtomicUsize::new(usize::MAX)),
        );
        let error =
            match run_proxy_auth_operation(&overloaded, None, "/overloaded".to_string()).await {
                Err(error) => error,
                Ok(_) => panic!("admission unexpectedly succeeded"),
            };
        assert!(matches!(error, AuthExecutionError::Overloaded));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let response = proxy_auth_execution_error_response(error, true);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[http::header::RETRY_AFTER], "5");
        assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[CONNECTION], "close");
        assert!(!response.headers().contains_key(SET_COOKIE));
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("overload body")
                .to_bytes(),
            Bytes::from_static(b"Authentication service temporarily unavailable")
        );
        assert_eq!(count_login_states(), 1);

        for behavior in [TestLoginBehavior::Error, TestLoginBehavior::Panic] {
            let calls = Arc::new(AtomicUsize::new(0));
            let state = make_state(
                AuthExecutor::with_limits(1, 1),
                behavior,
                Arc::new(|| {}),
                Arc::clone(&calls),
                Arc::new(AtomicUsize::new(usize::MAX)),
            );
            let result = run_proxy_auth_operation(&state, None, "/failure".to_string())
                .await
                .expect("post-decision failure contained");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let ProxyAuthOutcome::Response(response) = proxy_auth_result_outcome(result, true)
            else {
                panic!("post-decision failure unexpectedly allowed upstream");
            };
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let cookies: Vec<_> = response.headers().get_all(SET_COOKIE).iter().collect();
            assert_eq!(cookies.len(), 1);
            assert!(cookies[0]
                .to_str()
                .expect("clear cookie")
                .contains("amg_session="));
            assert!(!cookies[0]
                .to_str()
                .expect("clear cookie")
                .contains("amg_login_state"));
            assert_eq!(
                response
                    .into_body()
                    .collect()
                    .await
                    .expect("post-Unauth body")
                    .to_bytes(),
                Bytes::from_static(b"Internal server error")
            );
            assert_eq!(count_login_states(), 1);
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let predecision = make_state(
            AuthExecutor::with_limits(1, 1),
            TestLoginBehavior::Success,
            Arc::new(|| std::panic::panic_any("pre-decision-payload-marker")),
            Arc::clone(&calls),
            Arc::new(AtomicUsize::new(usize::MAX)),
        );
        let error =
            match run_proxy_auth_operation(&predecision, None, "/prepanic".to_string()).await {
                Err(error) => error,
                Ok(_) => panic!("pre-decision panic unexpectedly succeeded"),
            };
        assert!(matches!(error, AuthExecutionError::Internal));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let response = proxy_auth_execution_error_response(error, true);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!response.headers().contains_key(SET_COOKIE));
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("pre-decision panic body")
                .to_bytes(),
            Bytes::from_static(b"Internal server error")
        );
        assert_eq!(count_login_states(), 1);
    }

    #[test]
    fn budgeted_blocking_runtime_keeps_all_64_auth_workers_available() {
        let plan = RuntimePlan::new(8).expect("runtime plan");
        assert_eq!(plan.max_blocking_threads, 88);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .max_blocking_threads(plan.max_blocking_threads)
            .enable_all()
            .build()
            .expect("dedicated runtime");
        runtime.block_on(async {
            let blocker_gate = Arc::new((Mutex::new(false), Condvar::new()));
            let resolver_started = Arc::new(AtomicUsize::new(0));
            let margin_started = Arc::new(AtomicUsize::new(0));
            let blockers_completed = Arc::new(AtomicUsize::new(0));
            let mut blockers = Vec::new();
            for (count, started) in [
                (8, Arc::clone(&resolver_started)),
                (16, Arc::clone(&margin_started)),
            ] {
                for _ in 0..count {
                    let gate = Arc::clone(&blocker_gate);
                    let started = Arc::clone(&started);
                    let completed = Arc::clone(&blockers_completed);
                    blockers.push(tokio::task::spawn_blocking(move || {
                        started.fetch_add(1, Ordering::SeqCst);
                        let (lock, condition) = &*gate;
                        let mut released = lock.lock().expect("blocker lock");
                        while !*released {
                            released = condition.wait(released).expect("blocker wait");
                        }
                        completed.fetch_add(1, Ordering::SeqCst);
                    }));
                }
            }
            tokio::time::timeout(StdDuration::from_secs(5), async {
                while resolver_started.load(Ordering::SeqCst) != 8
                    || margin_started.load(Ordering::SeqCst) != 16
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("all resolver and margin fixtures started");

            let executor = AuthExecutor::new();
            let auth_gate = Arc::new((Mutex::new(false), Condvar::new()));
            let auth_entered = Arc::new(AtomicUsize::new(0));
            let mut auth_tasks = Vec::new();
            for _ in 0..63 {
                let executor = executor.clone();
                let gate = Arc::clone(&auth_gate);
                let entered = Arc::clone(&auth_entered);
                auth_tasks.push(tokio::spawn(async move {
                    executor
                        .run(move || {
                            entered.fetch_add(1, Ordering::SeqCst);
                            let (lock, condition) = &*gate;
                            let mut released = lock.lock().expect("auth gate");
                            while !*released {
                                released = condition.wait(released).expect("auth wait");
                            }
                            204u16
                        })
                        .await
                }));
            }
            let dir = tempdir().expect("auth isolation tempdir");
            let database = dir.path().join("gateway.sqlite");
            Store::initialize(&database).expect("auth isolation store");
            let mut config = test_config();
            config.database_path = database.clone();
            let config = Arc::new(config);
            let store = Arc::new(Store::new(database));
            let flights = Arc::new(FlightCoordinator::default());
            let auth = Arc::new(MockAuthMini::new(
                Vec::new(),
                Vec::new(),
                "unused-user".to_string(),
                "unused-session".to_string(),
            ));
            let control_executor = executor.clone();
            let control_gate = Arc::clone(&auth_gate);
            let control_entered = Arc::clone(&auth_entered);
            auth_tasks.push(tokio::spawn(async move {
                control_executor
                    .run(move || {
                        control_entered.fetch_add(1, Ordering::SeqCst);
                        let (lock, condition) = &*control_gate;
                        let mut released = lock.lock().expect("control auth gate");
                        while !*released {
                            released = condition.wait(released).expect("control auth wait");
                        }
                        let request = Request::new(
                            "GET".to_string(),
                            "/auth/check".to_string(),
                            Vec::new(),
                            Vec::new(),
                        );
                        handle_auth_check(&request, &config, &store, auth.as_ref(), &flights)
                            .status()
                    })
                    .await
            }));

            let all_auth_entered = tokio::time::timeout(StdDuration::from_secs(5), async {
                while auth_entered.load(Ordering::SeqCst) != 64 {
                    tokio::task::yield_now().await;
                }
            })
            .await;
            if all_auth_entered.is_err() {
                for gate in [&auth_gate, &blocker_gate] {
                    let (lock, condition) = &**gate;
                    *lock.lock().expect("failure release") = true;
                    condition.notify_all();
                }
                panic!("all 64 auth closures did not enter under R+16 load");
            }
            assert_eq!(auth_entered.load(Ordering::SeqCst), 64);
            assert_eq!(resolver_started.load(Ordering::SeqCst), 8);
            assert_eq!(margin_started.load(Ordering::SeqCst), 16);
            assert_eq!(blockers_completed.load(Ordering::SeqCst), 0);

            {
                let (lock, condition) = &*auth_gate;
                *lock.lock().expect("release auth lock") = true;
                condition.notify_all();
            }
            let auth_outcome = tokio::time::timeout(StdDuration::from_secs(5), async {
                let mut statuses = Vec::new();
                for task in auth_tasks {
                    statuses.push(task.await.expect("auth task").expect("auth admitted"));
                }
                statuses
            })
            .await;
            if auth_outcome.is_err() {
                let (lock, condition) = &*blocker_gate;
                *lock.lock().expect("failure blocker release") = true;
                condition.notify_all();
                panic!("64 entered auth closures did not complete after auth release");
            }
            let statuses = auth_outcome.expect("checked auth outcome");
            assert_eq!(blockers_completed.load(Ordering::SeqCst), 0);
            assert_eq!(statuses.len(), 64);
            assert_eq!(statuses.iter().filter(|status| **status == 204).count(), 63);
            assert_eq!(statuses.iter().filter(|status| **status == 401).count(), 1);

            {
                let (lock, condition) = &*blocker_gate;
                *lock.lock().expect("release lock") = true;
                condition.notify_all();
            }
            for blocker in blockers {
                blocker.await.expect("blocking fixture");
            }
            assert_eq!(blockers_completed.load(Ordering::SeqCst), 24);
        });
    }

    #[test]
    fn production_blocking_and_dial_sites_are_source_budgeted() {
        let server = include_str!("server.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("server production source");
        let proxy = include_str!("proxy.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("proxy production source");
        assert_eq!(server.matches("spawn_blocking").count(), 1);
        assert_eq!(proxy.matches("spawn_blocking").count(), 1);
        assert!(!server.contains("block_in_place"));
        assert!(!proxy.contains("block_in_place"));
        for forbidden in [
            "lookup_host",
            "HttpConnector",
            "Url::socket_addrs",
            "connect_uri.host()",
            "TcpStream::connect((",
        ] {
            assert!(
                !proxy.contains(forbidden),
                "forbidden dial API: {forbidden}"
            );
        }
        let main_source = include_str!("main.rs");
        assert!(main_source.contains(".max_blocking_threads(runtime_plan.max_blocking_threads)"));
        assert!(
            main_source
                .find("install_sanitized_panic_hook()")
                .expect("panic hook")
                < main_source
                    .find("tracing_subscriber::fmt()")
                    .expect("logging init")
        );
        let block_on = main_source
            .find("let terminal_result = runtime.block_on")
            .expect("terminal result preservation");
        let background_shutdown = main_source
            .find("runtime.shutdown_background()")
            .expect("non-waiting runtime shutdown");
        assert!(block_on < background_shutdown);
        let exit_source = include_str!("exit.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("exit production source");
        let panic_hook = exit_source
            .split("pub fn install_sanitized_panic_hook")
            .nth(1)
            .expect("panic hook source")
            .split("#[cfg(test)]")
            .next()
            .expect("panic hook boundary");
        assert!(panic_hook.contains("libc::write"));
        assert!(!panic_hook.contains("stderr().lock"));
        assert!(!panic_hook.contains("writeln!"));
        assert!(!panic_hook.contains("tracing::"));

        let fallback = server
            .split("async fn handle_proxy_fallback")
            .nth(1)
            .expect("proxy fallback source")
            .split("fn classify_fallback_target")
            .next()
            .expect("proxy fallback boundary");
        assert_eq!(fallback.matches(".executor").count(), 1);
        assert_eq!(fallback.matches("execute_proxy_auth").count(), 1);
        assert_eq!(fallback.matches("login_builder.build").count(), 1);
        let underscore = fallback.find("contains(&b'_')").expect("underscore gate");
        let forwarding = fallback.find("derive_client_ip").expect("forwarding gate");
        let auth_admission = fallback.find(".executor").expect("auth admission");
        assert!(underscore < auth_admission);
        assert!(forwarding < auth_admission);

        let connect = proxy
            .split("async fn connect")
            .nth(1)
            .expect("connect source")
            .split("struct ActivePhase")
            .next()
            .expect("connect boundary");
        assert!(!connect.contains("ClientIp"));
        assert!(!connect.contains("x-forwarded"));
        assert!(!connect.contains("request.headers"));
        for reason in [
            "RequestCancellation",
            "ReadyFailure",
            "SendFailure",
            "InvalidUpgrade",
            "ResponseBodyError",
            "ResponseBodyDrop",
            "NonReusableResponse",
            "PoolReadyTimeout",
            "PoolReadyFailure",
            "PoolFull",
            "PoolPoisoned",
            "UpgradeFailure",
            "WebSocketClosed",
            "WebSocketError",
            "WebSocketCancellation",
            "IdleOwnerDrop",
        ] {
            assert!(
                proxy
                    .matches(&format!("RetirementReason::{reason}"))
                    .count()
                    >= 1,
                "terminal reason is not wired: {reason}"
            );
        }
    }

    #[test]
    fn proxy_capacity_validation_requires_exact_headroom_but_not_r_u_ordering() {
        let mut config = test_config();
        config.upstream = crate::config::parse_upstream_url(Some("http://127.0.0.1:4096"))
            .expect("valid upstream");
        config.max_active_upstreams = 128;
        config.max_downstream_connections = 143;
        assert_eq!(
            config.validate().expect_err("missing headroom").class(),
            "proxy_capacity_headroom_invalid"
        );
        config.max_downstream_connections = 144;
        config.max_blocking_resolvers = 1;
        assert!(config.validate().is_ok(), "U may exceed R");
        config.max_active_upstreams = 1;
        config.max_downstream_connections = 17;
        config.max_blocking_resolvers = 32;
        assert!(config.validate().is_ok(), "R may exceed U");
        config.max_blocking_resolvers = 33;
        assert_eq!(
            config.validate().expect_err("R above maximum").class(),
            "blocking_resolver_limit_invalid"
        );
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
            max_downstream_connections: 256,
            max_active_upstreams: 128,
            max_blocking_resolvers: 8,
            trusted_proxy_cidrs: crate::config::TrustedProxySet::default(),
        }
    }
}
