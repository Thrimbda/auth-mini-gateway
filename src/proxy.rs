use std::collections::HashSet;
use std::error::Error;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, COOKIE, HOST, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, SET_COOKIE, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::{self, SendRequest};
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use sha1::{Digest as _, Sha1};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout, timeout_at, Instant};
use tower_service::Service;

use crate::capacity::DownstreamLease;
use crate::config::{DialHost, TrustedProxySet, UpstreamBase};
use crate::http::is_safe_header_value;
use crate::runtime_plan::UPSTREAM_IDLE_POOL_CAPACITY;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type GatewayBody = UnsyncBoxBody<Bytes, BoxError>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SENDER_READY_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub struct ProxyIdentity {
    pub user_id: String,
    pub email: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WebSocketRequest {
    pub key: String,
    pub protocols: Vec<String>,
    pub extension_names: HashSet<String>,
}

#[derive(Debug)]
pub enum ProxyError {
    BadRequest,
    BadGateway,
    Internal,
    Capacity(CapacityClass),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityClass {
    ActiveUpstream,
    BlockingResolver,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientIp(IpAddr);

pub(crate) fn derive_client_ip(
    direct_peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &TrustedProxySet,
) -> Result<ClientIp, ProxyError> {
    if !trusted_proxies.contains(direct_peer) {
        return Ok(ClientIp(direct_peer));
    }
    let values: Vec<_> = headers.get_all("x-forwarded-for").iter().collect();
    if values.is_empty() {
        return Ok(ClientIp(direct_peer));
    }
    if values.len() != 1 {
        return Err(ProxyError::BadRequest);
    }
    let value = values[0].to_str().map_err(|_| ProxyError::BadRequest)?;
    if value.is_empty()
        || value.contains(',')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ProxyError::BadRequest);
    }
    value
        .parse::<IpAddr>()
        .map(ClientIp)
        .map_err(|_| ProxyError::BadRequest)
}

type RequestBody = DropTrailers<Incoming>;
type Sender = SendRequest<RequestBody>;
type SenderPool = Arc<Mutex<Vec<CompleteOwner>>>;

#[derive(Clone)]
pub struct Proxy {
    upstream: UpstreamBase,
    connect_uri: Uri,
    tls: rustls::ClientConfig,
    idle: SenderPool,
    active: Arc<Semaphore>,
    resolvers: Arc<Semaphore>,
    resolver: Arc<dyn HostResolver>,
    resolver_accounting: Arc<ResolverAccounting>,
    connect_timeout: Duration,
    driver_accounting: Arc<DriverRetirementAccounting>,
}

impl Proxy {
    pub fn new(
        upstream: UpstreamBase,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
    ) -> Result<Self, BoxError> {
        Self::new_with_native_root_loader(
            upstream,
            max_active_upstreams,
            max_blocking_resolvers,
            || {
                let native = rustls_native_certs::load_native_certs();
                let mut roots = RootCertStore::empty();
                let (added, _) = roots.add_parsable_certificates(native.certs);
                if added == 0 {
                    return Err("no native TLS roots available".into());
                }
                Ok(roots)
            },
        )
    }

    fn new_with_native_root_loader<F>(
        upstream: UpstreamBase,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
        load_native_roots: F,
    ) -> Result<Self, BoxError>
    where
        F: FnOnce() -> Result<RootCertStore, BoxError>,
    {
        if upstream.scheme() == "http" {
            return Self::with_root_store(
                upstream,
                RootCertStore::empty(),
                max_active_upstreams,
                max_blocking_resolvers,
            );
        }
        let roots = load_native_roots()?;
        Self::with_root_store(
            upstream,
            roots,
            max_active_upstreams,
            max_blocking_resolvers,
        )
    }

    pub fn with_root_store(
        upstream: UpstreamBase,
        roots: RootCertStore,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
    ) -> Result<Self, BoxError> {
        Self::with_root_store_and_resolver(
            upstream,
            roots,
            max_active_upstreams,
            max_blocking_resolvers,
            Arc::new(SystemHostResolver),
            Arc::new(ResolverAccounting::default()),
        )
    }

    pub(crate) fn with_root_store_and_resolver(
        upstream: UpstreamBase,
        roots: RootCertStore,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
        resolver: Arc<dyn HostResolver>,
        resolver_accounting: Arc<ResolverAccounting>,
    ) -> Result<Self, BoxError> {
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connect_uri = format!("{}://{}/", upstream.scheme(), upstream.authority()).parse()?;
        Ok(Self {
            upstream,
            connect_uri,
            tls,
            idle: Arc::new(Mutex::new(Vec::new())),
            active: Arc::new(Semaphore::new(max_active_upstreams)),
            resolvers: Arc::new(Semaphore::new(max_blocking_resolvers)),
            resolver,
            resolver_accounting,
            connect_timeout: CONNECT_TIMEOUT,
            driver_accounting: Arc::new(DriverRetirementAccounting::default()),
        })
    }

    #[cfg(test)]
    pub(crate) fn resolver_accounting(&self) -> Arc<ResolverAccounting> {
        Arc::clone(&self.resolver_accounting)
    }

    #[cfg(test)]
    pub(crate) fn idle_owner_count(&self) -> usize {
        self.idle.lock().expect("idle owner pool").len()
    }

    #[cfg(test)]
    pub(crate) fn occupy_resolver_for_test(&self) -> ResolverOccupancy {
        let permit = Arc::clone(&self.resolvers)
            .try_acquire_owned()
            .expect("resolver fixture capacity");
        ResolverOccupancy {
            _permit: TrackedResolverPermit::new(permit, Arc::clone(&self.resolver_accounting)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn forward(
        &self,
        mut request: Request<Incoming>,
        path_and_query: &str,
        client_ip: ClientIp,
        public_proto: &str,
        identity: ProxyIdentity,
        renewal: Option<String>,
        close_downstream: bool,
        websocket: Option<WebSocketRequest>,
        downstream_lease: DownstreamLease,
    ) -> Result<Response<GatewayBody>, ProxyError> {
        let active_permit = Arc::clone(&self.active)
            .try_acquire_owned()
            .map_err(|_| ProxyError::Capacity(CapacityClass::ActiveUpstream))?;
        let downstream_upgrade = websocket.as_ref().map(|_| hyper::upgrade::on(&mut request));
        let upstream_path = compose_path(self.upstream.path_prefix(), path_and_query)?;
        *request.uri_mut() = upstream_path.parse().map_err(|_| ProxyError::Internal)?;
        *request.version_mut() = Version::HTTP_11;
        sanitize_request_headers(
            request.headers_mut(),
            client_ip,
            public_proto,
            &identity,
            websocket.is_some(),
        )?;

        let (parts, body) = request.into_parts();
        let upload = Arc::new(UploadState::default());
        let upstream_request =
            Request::from_parts(parts, DropTrailers::new(body, Arc::clone(&upload)));
        let (mut upstream_response, mut owner, upload_complete) = self
            .send_once(upstream_request, &upload, active_permit)
            .await?;

        if upstream_response.status() == StatusCode::SWITCHING_PROTOCOLS {
            owner.set_retirement_reason(RetirementReason::InvalidUpgrade);
            let Some(metadata) = websocket.as_ref() else {
                return Err(ProxyError::BadGateway);
            };
            validate_websocket_response(&upstream_response, metadata)?;
            let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
            let response = sanitize_response_head(upstream_response, renewal.as_deref(), true)?;
            let (parts, _) = response.into_parts();
            let response = Response::from_parts(parts, empty_body());
            let downstream_upgrade = downstream_upgrade.ok_or(ProxyError::Internal)?;
            owner.drop_sender();
            let bridge = PendingBridgeGuard::new(
                downstream_upgrade,
                upstream_upgrade,
                owner,
                downstream_lease,
            );
            tokio::spawn(bridge_upgrades(bridge));
            return Ok(response);
        }

        let reusable = upstream_response.version() == Version::HTTP_11
            && !header_has_token(upstream_response.headers(), CONNECTION, "close")
            && upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS
            && upload_complete;
        let response = sanitize_response_head(upstream_response, renewal.as_deref(), false)?;
        let (parts, body) = response.into_parts();
        let body = PooledResponseBody::new(body, owner, Arc::clone(&self.idle), reusable)
            .map_err(|error| -> BoxError { Box::new(error) })
            .boxed_unsync();
        let mut response = Response::from_parts(parts, body);
        if close_downstream || !upload_complete {
            response
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }
        Ok(response)
    }

    async fn send_once(
        &self,
        request: Request<RequestBody>,
        upload: &UploadState,
        active_permit: OwnedSemaphorePermit,
    ) -> Result<(Response<Incoming>, ActiveOwner, bool), ProxyError> {
        let pooled = self.idle.lock().map_err(|_| ProxyError::Internal)?.pop();
        let mut owner = match pooled {
            Some(complete) => ActiveOwner::new(complete, active_permit),
            None => self.connect(active_permit).await?,
        };
        let ready = match owner.sender_mut() {
            Some(sender) => sender.ready().await,
            None => {
                owner.set_retirement_reason(RetirementReason::ReadyFailure);
                return Err(ProxyError::Internal);
            }
        };
        if ready.is_err() {
            owner.set_retirement_reason(RetirementReason::ReadyFailure);
            return Err(ProxyError::BadGateway);
        }
        let response = match owner.sender_mut() {
            Some(sender) => sender.send_request(request).await,
            None => {
                owner.set_retirement_reason(RetirementReason::SendFailure);
                return Err(ProxyError::Internal);
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(_) => {
                owner.set_retirement_reason(RetirementReason::SendFailure);
                return Err(ProxyError::BadGateway);
            }
        };
        let upload_complete = upload.is_complete();
        if !upload_complete {
            upload.cancel();
        }
        Ok((response, owner, upload_complete))
    }

    async fn connect(
        &self,
        active_permit: OwnedSemaphorePermit,
    ) -> Result<ActiveOwner, ProxyError> {
        let deadline = Instant::now() + self.connect_timeout;
        let (candidates, active_permit) = match self.upstream.dial_target().host() {
            DialHost::Ip(address) => (
                vec![SocketAddr::new(
                    *address,
                    self.upstream.dial_target().port(),
                )],
                active_permit,
            ),
            DialHost::Domain(domain) => {
                let resolver_permit = match Arc::clone(&self.resolvers).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        self.resolver_accounting.trace("saturated");
                        return Err(ProxyError::Capacity(CapacityClass::BlockingResolver));
                    }
                };
                let resolver_permit = TrackedResolverPermit::new(
                    resolver_permit,
                    Arc::clone(&self.resolver_accounting),
                );
                self.resolver_accounting.trace("admitted");
                resolve_domain(
                    domain.clone(),
                    self.upstream.dial_target().port(),
                    active_permit,
                    resolver_permit,
                    deadline,
                    Arc::clone(&self.resolver),
                    Arc::clone(&self.resolver_accounting),
                )
                .await?
            }
        };
        let inner = ResolvedTcpConnector::new(candidates);
        let mut connector: HttpsConnector<ResolvedTcpConnector> = HttpsConnectorBuilder::new()
            .with_tls_config(self.tls.clone())
            .https_or_http()
            .enable_http1()
            .wrap_connector(inner);
        let connect = timeout_at(deadline, connector.call(self.connect_uri.clone()));
        let (result, active_permit) = ActivePhase::new(connect, active_permit).await;
        let io = result
            .map_err(|_| ProxyError::BadGateway)?
            .map_err(|_| ProxyError::BadGateway)?;
        let handshake = timeout_at(deadline, http1::handshake::<_, RequestBody>(io));
        let (result, active_permit) = ActivePhase::new(handshake, active_permit).await;
        let (sender, connection) = result
            .map_err(|_| ProxyError::BadGateway)?
            .map_err(|_| ProxyError::BadGateway)?;
        let driver = tokio::spawn(async move {
            if connection.with_upgrades().await.is_err() {
                tracing::debug!(event = "upstream_connection", outcome = "closed");
            }
        });
        Ok(ActiveOwner::new(
            CompleteOwner::new(sender, driver, Arc::clone(&self.driver_accounting)),
            active_permit,
        ))
    }
}

struct ActivePhase<F> {
    future: Option<Pin<Box<F>>>,
    permit: Option<OwnedSemaphorePermit>,
}

impl<F> ActivePhase<F> {
    fn new(future: F, permit: OwnedSemaphorePermit) -> Self {
        Self {
            future: Some(Box::pin(future)),
            permit: Some(permit),
        }
    }
}

impl<F> Future for ActivePhase<F>
where
    F: Future,
{
    type Output = (F::Output, OwnedSemaphorePermit);

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let output = match this.future.as_mut() {
            Some(future) => match future.as_mut().poll(context) {
                Poll::Ready(output) => output,
                Poll::Pending => return Poll::Pending,
            },
            None => panic!("active phase polled after completion"),
        };
        this.future.take();
        Poll::Ready((
            output,
            this.permit.take().expect("active phase owns permit"),
        ))
    }
}

impl<F> Drop for ActivePhase<F> {
    fn drop(&mut self) {
        // Explicit field order: cancel/drop current I/O before returning U.
        self.future.take();
        self.permit.take();
    }
}

const RESOLVER_QUEUED: u8 = 0;
const RESOLVER_STARTED: u8 = 1;
const RESOLVER_FINISHED: u8 = 2;

type ResolverOutput = io::Result<Vec<SocketAddr>>;

pub(crate) trait HostResolver: Send + Sync {
    fn resolve(&self, domain: Box<str>, port: u16) -> ResolverOutput;
}

struct SystemHostResolver;

impl HostResolver for SystemHostResolver {
    fn resolve(&self, domain: Box<str>, port: u16) -> ResolverOutput {
        (domain.as_ref(), port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect::<Vec<_>>())
    }
}

#[derive(Default)]
pub(crate) struct ResolverAccounting {
    held_r: AtomicUsize,
    submitted_unobserved: AtomicUsize,
    request_owned: AtomicUsize,
    cleanup_owned: AtomicUsize,
    live_blocking: AtomicUsize,
    total_submitted: AtomicUsize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResolverSnapshot {
    pub held_r: usize,
    pub submitted_unobserved: usize,
    pub request_owned: usize,
    pub cleanup_owned: usize,
    pub live_blocking: usize,
    pub total_submitted: usize,
}

impl ResolverAccounting {
    pub(crate) fn snapshot(&self) -> ResolverSnapshot {
        ResolverSnapshot {
            held_r: self.held_r.load(Ordering::Acquire),
            submitted_unobserved: self.submitted_unobserved.load(Ordering::Acquire),
            request_owned: self.request_owned.load(Ordering::Acquire),
            cleanup_owned: self.cleanup_owned.load(Ordering::Acquire),
            live_blocking: self.live_blocking.load(Ordering::Acquire),
            total_submitted: self.total_submitted.load(Ordering::Acquire),
        }
    }

    fn resolver_acquired(&self) {
        self.held_r.fetch_add(1, Ordering::AcqRel);
    }

    fn resolver_released(&self) {
        self.held_r.fetch_sub(1, Ordering::AcqRel);
    }

    fn submitted(&self) {
        self.submitted_unobserved.fetch_add(1, Ordering::AcqRel);
        self.request_owned.fetch_add(1, Ordering::AcqRel);
        self.total_submitted.fetch_add(1, Ordering::AcqRel);
    }

    fn request_to_cleanup(&self) {
        self.request_owned.fetch_sub(1, Ordering::AcqRel);
        self.cleanup_owned.fetch_add(1, Ordering::AcqRel);
    }

    fn request_joined(&self) {
        self.request_owned.fetch_sub(1, Ordering::AcqRel);
        self.submitted_unobserved.fetch_sub(1, Ordering::AcqRel);
    }

    fn cleanup_joined(&self) {
        self.cleanup_owned.fetch_sub(1, Ordering::AcqRel);
        self.submitted_unobserved.fetch_sub(1, Ordering::AcqRel);
    }

    fn blocking_started(&self) {
        self.live_blocking.fetch_add(1, Ordering::AcqRel);
    }

    fn blocking_finished(&self) {
        self.live_blocking.fetch_sub(1, Ordering::AcqRel);
    }

    fn trace(&self, outcome: &'static str) {
        let snapshot = self.snapshot();
        tracing::debug!(
            event = "resolver_accounting",
            outcome,
            held_r = snapshot.held_r,
            submitted_unobserved = snapshot.submitted_unobserved,
            request_owned = snapshot.request_owned,
            cleanup_owned = snapshot.cleanup_owned,
            live_blocking = snapshot.live_blocking,
            total_submitted = snapshot.total_submitted
        );
    }
}

struct TrackedResolverPermit {
    _permit: OwnedSemaphorePermit,
    accounting: Arc<ResolverAccounting>,
}

#[cfg(test)]
pub(crate) struct ResolverOccupancy {
    _permit: TrackedResolverPermit,
}

impl TrackedResolverPermit {
    fn new(permit: OwnedSemaphorePermit, accounting: Arc<ResolverAccounting>) -> Self {
        accounting.resolver_acquired();
        Self {
            _permit: permit,
            accounting,
        }
    }
}

impl Drop for TrackedResolverPermit {
    fn drop(&mut self) {
        self.accounting.resolver_released();
    }
}

struct LiveResolverGuard {
    accounting: Arc<ResolverAccounting>,
}

impl Drop for LiveResolverGuard {
    fn drop(&mut self) {
        self.accounting.blocking_finished();
    }
}

struct ResolutionParts {
    active_permit: OwnedSemaphorePermit,
    resolver_permit: TrackedResolverPermit,
    handle: JoinHandle<ResolverOutput>,
    state: Arc<AtomicU8>,
    accounting: Arc<ResolverAccounting>,
}

struct ResolutionAttempt {
    parts: Option<ResolutionParts>,
}

impl ResolutionAttempt {
    fn new(parts: ResolutionParts) -> Self {
        Self { parts: Some(parts) }
    }

    fn handle_mut(&mut self) -> &mut JoinHandle<ResolverOutput> {
        &mut self.parts.as_mut().expect("resolution parts").handle
    }

    fn observed(mut self) -> OwnedSemaphorePermit {
        let parts = self.parts.take().expect("observed resolution parts");
        parts.accounting.request_joined();
        parts.accounting.trace("request_joined");
        tracing::debug!(
            event = "resolver_lifecycle",
            outcome = "joined",
            state = resolver_state(parts.state.load(Ordering::Acquire))
        );
        drop(parts.handle);
        drop(parts.resolver_permit);
        parts.active_permit
    }
}

impl Drop for ResolutionAttempt {
    fn drop(&mut self) {
        if let Some(parts) = self.parts.take() {
            schedule_resolver_cleanup(parts);
        }
    }
}

async fn resolve_domain(
    domain: Box<str>,
    port: u16,
    active_permit: OwnedSemaphorePermit,
    resolver_permit: TrackedResolverPermit,
    deadline: Instant,
    resolver: Arc<dyn HostResolver>,
    accounting: Arc<ResolverAccounting>,
) -> Result<(Vec<SocketAddr>, OwnedSemaphorePermit), ProxyError> {
    let mut attempt = submit_resolution_tracked(
        active_permit,
        resolver_permit,
        Arc::clone(&accounting),
        move || resolver.resolve(domain, port),
    );
    let joined = match timeout_at(deadline, attempt.handle_mut()).await {
        Ok(joined) => joined,
        Err(_) => return Err(ProxyError::BadGateway),
    };
    let active_permit = attempt.observed();
    let addresses = joined
        .map_err(|_| ProxyError::BadGateway)?
        .map_err(|_| ProxyError::BadGateway)?;
    if addresses.is_empty() {
        return Err(ProxyError::BadGateway);
    }
    Ok((addresses, active_permit))
}

#[cfg(test)]
fn submit_resolution<F>(
    active_permit: OwnedSemaphorePermit,
    resolver_permit: OwnedSemaphorePermit,
    operation: F,
) -> ResolutionAttempt
where
    F: FnOnce() -> ResolverOutput + Send + 'static,
{
    let accounting = Arc::new(ResolverAccounting::default());
    let resolver_permit = TrackedResolverPermit::new(resolver_permit, Arc::clone(&accounting));
    submit_resolution_tracked(active_permit, resolver_permit, accounting, operation)
}

fn submit_resolution_tracked<F>(
    active_permit: OwnedSemaphorePermit,
    resolver_permit: TrackedResolverPermit,
    accounting: Arc<ResolverAccounting>,
    operation: F,
) -> ResolutionAttempt
where
    F: FnOnce() -> ResolverOutput + Send + 'static,
{
    let state = Arc::new(AtomicU8::new(RESOLVER_QUEUED));
    let task_state = Arc::clone(&state);
    accounting.submitted();
    accounting.trace("submitted");
    let task_accounting = Arc::clone(&accounting);
    let handle = tokio::task::spawn_blocking(move || {
        task_state.store(RESOLVER_STARTED, Ordering::Release);
        task_accounting.blocking_started();
        let _live = LiveResolverGuard {
            accounting: Arc::clone(&task_accounting),
        };
        let result = operation();
        task_state.store(RESOLVER_FINISHED, Ordering::Release);
        result
    });
    tracing::debug!(event = "resolver_lifecycle", outcome = "submitted");
    ResolutionAttempt::new(ResolutionParts {
        active_permit,
        resolver_permit,
        handle,
        state,
        accounting,
    })
}

fn resolver_state(state: u8) -> &'static str {
    match state {
        RESOLVER_QUEUED => "queued",
        RESOLVER_STARTED => "started",
        RESOLVER_FINISHED => "finished",
        _ => "unknown",
    }
}

fn schedule_resolver_cleanup(parts: ResolutionParts) {
    parts.accounting.request_to_cleanup();
    parts.accounting.trace("cleanup_owned");
    parts.handle.abort();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // The returned JoinHandle is intentionally private and detached.
            // No request or bridge can cancel this bounded cleanup task; the
            // only remaining cancellation boundary is runtime/process exit.
            handle.spawn(async move {
                let mut parts = parts;
                let _ = (&mut parts.handle).await;
                parts.accounting.cleanup_joined();
                parts.accounting.trace("cleanup_joined");
                tracing::debug!(
                    event = "resolver_lifecycle",
                    outcome = "cleanup_joined",
                    state = resolver_state(parts.state.load(Ordering::Acquire))
                );
                // Field order is explicit: handle observation precedes R/U.
                drop(parts.handle);
                drop(parts.resolver_permit);
                drop(parts.active_permit);
            });
        }
        Err(_) => {
            // Runtime teardown is fail-closed: never release U/R without join
            // observation. Process exit will reclaim the bounded resources.
            std::mem::forget(parts);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
enum RetirementReason {
    RequestCancellation,
    ReadyFailure,
    SendFailure,
    InvalidUpgrade,
    ResponseBodyError,
    ResponseBodyDrop,
    NonReusableResponse,
    PoolReadyTimeout,
    PoolReadyFailure,
    PoolFull,
    PoolPoisoned,
    UpgradeFailure,
    WebSocketClosed,
    WebSocketError,
    WebSocketCancellation,
    IdleOwnerDrop,
}

const RETIREMENT_REASON_COUNT: usize = RetirementReason::IdleOwnerDrop as usize + 1;

impl RetirementReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RequestCancellation => "request_cancellation",
            Self::ReadyFailure => "ready_failure",
            Self::SendFailure => "send_failure",
            Self::InvalidUpgrade => "invalid_upgrade",
            Self::ResponseBodyError => "response_body_error",
            Self::ResponseBodyDrop => "response_body_drop",
            Self::NonReusableResponse => "non_reusable_response",
            Self::PoolReadyTimeout => "pool_ready_timeout",
            Self::PoolReadyFailure => "pool_ready_failure",
            Self::PoolFull => "pool_full",
            Self::PoolPoisoned => "pool_poisoned",
            Self::UpgradeFailure => "upgrade_failure",
            Self::WebSocketClosed => "websocket_closed",
            Self::WebSocketError => "websocket_error",
            Self::WebSocketCancellation => "websocket_cancellation",
            Self::IdleOwnerDrop => "idle_owner_drop",
        }
    }
}

struct DriverRetirementAccounting {
    started: [AtomicUsize; RETIREMENT_REASON_COUNT],
    joined: [AtomicUsize; RETIREMENT_REASON_COUNT],
    active_cleanups: AtomicUsize,
}

impl Default for DriverRetirementAccounting {
    fn default() -> Self {
        Self {
            started: std::array::from_fn(|_| AtomicUsize::new(0)),
            joined: std::array::from_fn(|_| AtomicUsize::new(0)),
            active_cleanups: AtomicUsize::new(0),
        }
    }
}

impl DriverRetirementAccounting {
    fn started(&self, reason: RetirementReason) {
        self.started[reason as usize].fetch_add(1, Ordering::AcqRel);
        self.active_cleanups.fetch_add(1, Ordering::AcqRel);
        tracing::debug!(
            event = "driver_retirement",
            reason = reason.as_str(),
            outcome = "started",
            active_cleanups = self.active_cleanups.load(Ordering::Acquire)
        );
    }

    fn joined(&self, reason: RetirementReason) {
        self.joined[reason as usize].fetch_add(1, Ordering::AcqRel);
        self.active_cleanups.fetch_sub(1, Ordering::AcqRel);
        tracing::debug!(
            event = "driver_retirement",
            reason = reason.as_str(),
            outcome = "joined",
            active_cleanups = self.active_cleanups.load(Ordering::Acquire)
        );
    }

    #[cfg(test)]
    fn counts(&self, reason: RetirementReason) -> (usize, usize) {
        (
            self.started[reason as usize].load(Ordering::Acquire),
            self.joined[reason as usize].load(Ordering::Acquire),
        )
    }
}

struct CompleteOwner {
    sender: Option<Sender>,
    driver: Option<JoinHandle<()>>,
    accounting: Arc<DriverRetirementAccounting>,
}

impl CompleteOwner {
    fn new(
        sender: Sender,
        driver: JoinHandle<()>,
        accounting: Arc<DriverRetirementAccounting>,
    ) -> Self {
        Self {
            sender: Some(sender),
            driver: Some(driver),
            accounting,
        }
    }

    fn retirement_parts(
        mut self,
        permit: Option<OwnedSemaphorePermit>,
        reason: RetirementReason,
    ) -> RetirementParts {
        RetirementParts {
            sender: self.sender.take(),
            driver: self.driver.take().expect("complete owner driver"),
            _permit: permit,
            reason,
            accounting: Arc::clone(&self.accounting),
            started: false,
        }
    }
}

impl Drop for CompleteOwner {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            schedule_retirement(RetirementParts {
                sender: self.sender.take(),
                driver,
                _permit: None,
                reason: RetirementReason::IdleOwnerDrop,
                accounting: Arc::clone(&self.accounting),
                started: false,
            });
        }
    }
}

struct ActiveOwner {
    complete: Option<CompleteOwner>,
    permit: Option<OwnedSemaphorePermit>,
    retirement_reason: RetirementReason,
}

impl ActiveOwner {
    fn new(complete: CompleteOwner, permit: OwnedSemaphorePermit) -> Self {
        Self {
            complete: Some(complete),
            permit: Some(permit),
            retirement_reason: RetirementReason::RequestCancellation,
        }
    }

    fn sender_mut(&mut self) -> Option<&mut Sender> {
        self.complete.as_mut()?.sender.as_mut()
    }

    fn drop_sender(&mut self) {
        if let Some(complete) = self.complete.as_mut() {
            complete.sender.take();
        }
    }

    fn set_retirement_reason(&mut self, reason: RetirementReason) {
        self.retirement_reason = reason;
    }

    fn retirement_parts(mut self, reason: RetirementReason) -> RetirementParts {
        let permit = self.permit.take().expect("active owner permit");
        self.complete
            .take()
            .expect("active complete owner")
            .retirement_parts(Some(permit), reason)
    }

    fn idle_parts(mut self) -> (CompleteOwner, OwnedSemaphorePermit) {
        (
            self.complete.take().expect("active complete owner"),
            self.permit.take().expect("active owner permit"),
        )
    }
}

impl Drop for ActiveOwner {
    fn drop(&mut self) {
        if let (Some(complete), Some(permit)) = (self.complete.take(), self.permit.take()) {
            schedule_retirement(complete.retirement_parts(Some(permit), self.retirement_reason));
        }
    }
}

struct RetirementParts {
    sender: Option<Sender>,
    driver: JoinHandle<()>,
    _permit: Option<OwnedSemaphorePermit>,
    reason: RetirementReason,
    accounting: Arc<DriverRetirementAccounting>,
    started: bool,
}

impl RetirementParts {
    fn mark_started(&mut self) {
        if !self.started {
            self.accounting.started(self.reason);
            self.started = true;
        }
    }

    fn mark_joined(&self) {
        self.accounting.joined(self.reason);
    }
}

struct RetirementGuard {
    parts: Option<RetirementParts>,
}

impl RetirementGuard {
    fn new(parts: RetirementParts) -> Self {
        Self { parts: Some(parts) }
    }

    fn finish(mut self) {
        self.parts.take();
    }
}

impl Drop for RetirementGuard {
    fn drop(&mut self) {
        if let Some(parts) = self.parts.take() {
            schedule_retirement(parts);
        }
    }
}

fn schedule_retirement(mut parts: RetirementParts) {
    parts.mark_started();
    parts.sender.take();
    parts.driver.abort();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // This cleanup handle is never exposed, so request/bridge
            // cancellation cannot abort it. Runtime exit is the fail-stop
            // boundary and reclaims the process transport.
            handle.spawn(async move {
                let _ = (&mut parts.driver).await;
                parts.mark_joined();
                drop(parts.driver);
                drop(parts._permit);
            });
        }
        Err(_) => {
            // Preserve fail-closed capacity during runtime teardown rather than
            // releasing a permit before driver observation.
            std::mem::forget(parts);
        }
    }
}

fn retire_parts(parts: RetirementParts) -> impl Future<Output = ()> + Send {
    // As with resolver cleanup, make cancellation safe even before first poll.
    let mut parts = parts;
    parts.mark_started();
    let mut guard = RetirementGuard::new(parts);
    async move {
        let parts = guard.parts.as_mut().expect("retirement parts");
        parts.sender.take();
        parts.driver.abort();
        let _ = (&mut parts.driver).await;
        parts.mark_joined();
        guard.finish();
    }
}

async fn retire_active_owner(owner: ActiveOwner, reason: RetirementReason) {
    retire_parts(owner.retirement_parts(reason)).await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PoolReadinessOutcome {
    Ready,
    Timeout,
    Failure,
}

impl PoolReadinessOutcome {
    const fn retirement_reason(self) -> Option<RetirementReason> {
        match self {
            Self::Ready => None,
            Self::Timeout => Some(RetirementReason::PoolReadyTimeout),
            Self::Failure => Some(RetirementReason::PoolReadyFailure),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PoolPlacementOutcome {
    Parked,
    Full,
    Poisoned,
}

impl PoolPlacementOutcome {
    const fn retirement_reason(self) -> Option<RetirementReason> {
        match self {
            Self::Parked => None,
            Self::Full => Some(RetirementReason::PoolFull),
            Self::Poisoned => Some(RetirementReason::PoolPoisoned),
        }
    }
}

async fn park_or_retire(mut owner: ActiveOwner, pool: SenderPool) {
    let readiness = match owner.sender_mut() {
        Some(sender) => match timeout(SENDER_READY_TIMEOUT, sender.ready()).await {
            Ok(Ok(())) => PoolReadinessOutcome::Ready,
            Ok(Err(_)) => PoolReadinessOutcome::Failure,
            Err(_) => PoolReadinessOutcome::Timeout,
        },
        None => PoolReadinessOutcome::Failure,
    };
    if let Some(reason) = readiness.retirement_reason() {
        retire_active_owner(owner, reason).await;
        return;
    }

    let (complete, permit) = owner.idle_parts();
    let mut complete = Some(complete);
    let placement = {
        match pool.lock() {
            Ok(mut idle) if idle.len() < UPSTREAM_IDLE_POOL_CAPACITY => {
                idle.push(complete.take().expect("complete owner available"));
                PoolPlacementOutcome::Parked
            }
            Ok(_) => PoolPlacementOutcome::Full,
            Err(_) => PoolPlacementOutcome::Poisoned,
        }
    };
    if placement == PoolPlacementOutcome::Parked {
        // Atomic park: the complete owner is visible in the pool before U is
        // returned, and no await occurs while the pool is locked.
        drop(permit);
    } else {
        let reason = placement
            .retirement_reason()
            .expect("unparked retirement reason");
        retire_parts(
            complete
                .take()
                .expect("unparked complete owner")
                .retirement_parts(Some(permit), reason),
        )
        .await;
    }
}

pub fn full_body(bytes: impl Into<Bytes>) -> GatewayBody {
    Full::new(bytes.into())
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

pub fn empty_body() -> GatewayBody {
    Empty::<Bytes>::new()
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

pub fn parse_connection_tokens(headers: &HeaderMap) -> Result<HashSet<HeaderName>, ProxyError> {
    let mut names = HashSet::new();
    for value in headers.get_all(CONNECTION) {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return Err(ProxyError::BadRequest);
            }
            names.insert(
                HeaderName::from_bytes(token.as_bytes()).map_err(|_| ProxyError::BadRequest)?,
            );
        }
    }
    Ok(names)
}

pub fn parse_websocket_request(
    request: &Request<Incoming>,
) -> Result<Option<WebSocketRequest>, ProxyError> {
    let upgrade_values: Vec<_> = request.headers().get_all(UPGRADE).iter().collect();
    let connection_tokens = parse_connection_tokens(request.headers())?;
    let has_upgrade_token = connection_tokens.contains(&UPGRADE);
    if !has_upgrade_token && upgrade_values.is_empty() {
        return Ok(None);
    }
    if !has_upgrade_token || upgrade_values.len() != 1 {
        return Err(ProxyError::BadRequest);
    }
    for required in [
        HeaderName::from_static("sec-websocket-key"),
        HeaderName::from_static("sec-websocket-version"),
    ] {
        if connection_tokens.contains(&required) {
            return Err(ProxyError::BadRequest);
        }
    }
    for optional in [
        HeaderName::from_static("sec-websocket-protocol"),
        HeaderName::from_static("sec-websocket-extensions"),
    ] {
        if request.headers().contains_key(&optional) && connection_tokens.contains(&optional) {
            return Err(ProxyError::BadRequest);
        }
    }
    if !upgrade_values[0]
        .to_str()
        .is_ok_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
    {
        return Err(ProxyError::BadRequest);
    }
    if request.method() != http::Method::GET
        || request.version() != Version::HTTP_11
        || !request.body().is_end_stream()
    {
        return Err(ProxyError::BadRequest);
    }
    let version = exactly_one(request.headers(), "sec-websocket-version")?;
    if version.as_bytes() != b"13" {
        return Err(ProxyError::BadRequest);
    }
    let key = exactly_one(request.headers(), "sec-websocket-key")?
        .to_str()
        .map_err(|_| ProxyError::BadRequest)?
        .trim()
        .to_string();
    let decoded = STANDARD
        .decode(key.as_bytes())
        .map_err(|_| ProxyError::BadRequest)?;
    if decoded.len() != 16 || STANDARD.encode(decoded) != key {
        return Err(ProxyError::BadRequest);
    }
    let protocols = parse_protocols(request.headers())?;
    let extension_names = parse_extensions(request.headers())?;
    Ok(Some(WebSocketRequest {
        key,
        protocols,
        extension_names,
    }))
}

fn compose_path(prefix: &str, path_and_query: &str) -> Result<String, ProxyError> {
    if !path_and_query.starts_with('/') {
        return Err(ProxyError::BadRequest);
    }
    Ok(format!("{prefix}{path_and_query}"))
}

fn sanitize_request_headers(
    headers: &mut HeaderMap,
    client_ip: ClientIp,
    public_proto: &str,
    identity: &ProxyIdentity,
    websocket: bool,
) -> Result<(), ProxyError> {
    let hosts: Vec<_> = headers.get_all(HOST).iter().cloned().collect();
    if hosts.len() != 1 {
        return Err(ProxyError::BadRequest);
    }
    let external_host = hosts[0].clone();
    let nominated = parse_connection_tokens(headers)?;
    for name in nominated {
        headers.remove(name);
    }
    remove_fixed_hop_headers(headers);
    headers.remove(CONTENT_LENGTH);
    headers.remove(COOKIE);
    headers.remove(AUTHORIZATION);
    headers.remove(PROXY_AUTHORIZATION);
    headers.remove("forwarded");
    headers.remove("x-real-ip");
    headers.remove("expect");
    remove_prefixed(headers, "x-auth-mini-");
    remove_prefixed(headers, "x-forwarded-");

    headers.insert(HOST, external_host.clone());
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&client_ip.0.to_string()).map_err(|_| ProxyError::Internal)?,
    );
    headers.insert(
        "x-forwarded-proto",
        HeaderValue::from_str(public_proto).map_err(|_| ProxyError::Internal)?,
    );
    headers.insert("x-forwarded-host", external_host);
    headers.insert(
        "x-auth-mini-user-id",
        identity_header_value(&identity.user_id)?,
    );
    if let Some(email) = identity.email.as_deref() {
        headers.insert("x-auth-mini-email", identity_header_value(email)?);
    }
    if websocket {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    }
    Ok(())
}

fn identity_header_value(value: &str) -> Result<HeaderValue, ProxyError> {
    if !is_safe_header_value(value) {
        return Err(ProxyError::Internal);
    }
    HeaderValue::from_bytes(value.as_bytes()).map_err(|_| ProxyError::Internal)
}

fn sanitize_response_head(
    response: Response<Incoming>,
    renewal: Option<&str>,
    websocket: bool,
) -> Result<Response<Incoming>, ProxyError> {
    let (mut parts, body) = response.into_parts();
    let nominated = parse_response_connection_tokens(&parts.headers)?;
    for name in nominated {
        parts.headers.remove(name);
    }
    remove_fixed_hop_headers(&mut parts.headers);
    parts.headers.remove(CONTENT_LENGTH);
    remove_prefixed(&mut parts.headers, "x-auth-mini-");
    filter_application_cookies(&mut parts.headers);
    if websocket {
        parts
            .headers
            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
        parts
            .headers
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
    }
    if let Some(cookie) = renewal {
        parts.headers.append(
            SET_COOKIE,
            HeaderValue::from_str(cookie).map_err(|_| ProxyError::Internal)?,
        );
    }
    Ok(Response::from_parts(parts, body))
}

fn parse_response_connection_tokens(
    headers: &HeaderMap,
) -> Result<HashSet<HeaderName>, ProxyError> {
    parse_connection_tokens(headers).map_err(|_| ProxyError::BadGateway)
}

fn remove_fixed_hop_headers(headers: &mut HeaderMap) {
    for name in [
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn remove_prefixed(headers: &mut HeaderMap, prefix: &str) {
    let names: Vec<_> = headers
        .keys()
        .filter(|name| name.as_str().starts_with(prefix))
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
}

fn filter_application_cookies(headers: &mut HeaderMap) {
    let values: Vec<_> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    headers.remove(SET_COOKIE);
    for value in values {
        if is_allowed_application_cookie(&value) {
            headers.append(SET_COOKIE, value);
        }
    }
}

fn is_allowed_application_cookie(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();
    let bytes = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .map(|start| &bytes[start..])
        .unwrap_or_default();
    let pair = bytes.split(|byte| *byte == b';').next().unwrap_or_default();
    let Some(equal) = pair.iter().position(|byte| *byte == b'=') else {
        return false;
    };
    let name = &pair[..equal];
    if name.is_empty() || !name.iter().copied().all(is_token_byte) {
        return false;
    }
    name != b"amg_session" && name != b"amg_login_state"
}

fn validate_websocket_response(
    response: &Response<Incoming>,
    request: &WebSocketRequest,
) -> Result<(), ProxyError> {
    let connection = parse_response_connection_tokens(response.headers())?;
    if !connection.contains(&UPGRADE) {
        return Err(ProxyError::BadGateway);
    }
    if connection.contains(&HeaderName::from_static("sec-websocket-accept")) {
        return Err(ProxyError::BadGateway);
    }
    for selected in [
        HeaderName::from_static("sec-websocket-protocol"),
        HeaderName::from_static("sec-websocket-extensions"),
    ] {
        if response.headers().contains_key(&selected) && connection.contains(&selected) {
            return Err(ProxyError::BadGateway);
        }
    }
    let upgrades: Vec<_> = response.headers().get_all(UPGRADE).iter().collect();
    if upgrades.len() != 1
        || !upgrades[0]
            .to_str()
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
    {
        return Err(ProxyError::BadGateway);
    }
    let accept = exactly_one(response.headers(), "sec-websocket-accept")
        .map_err(|_| ProxyError::BadGateway)?;
    if accept.as_bytes() != websocket_accept(&request.key).as_bytes() {
        return Err(ProxyError::BadGateway);
    }
    let selected: Vec<_> = response
        .headers()
        .get_all("sec-websocket-protocol")
        .iter()
        .collect();
    if selected.len() > 1 {
        return Err(ProxyError::BadGateway);
    }
    if let Some(selected) = selected.first() {
        let selected = selected.to_str().map_err(|_| ProxyError::BadGateway)?;
        if !request.protocols.iter().any(|offered| offered == selected) {
            return Err(ProxyError::BadGateway);
        }
    }
    let selected_extensions =
        parse_extensions(response.headers()).map_err(|_| ProxyError::BadGateway)?;
    if !selected_extensions.is_subset(&request.extension_names) {
        return Err(ProxyError::BadGateway);
    }
    Ok(())
}

fn websocket_accept(key: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(digest.finalize())
}

fn parse_protocols(headers: &HeaderMap) -> Result<Vec<String>, ProxyError> {
    let mut protocols = Vec::new();
    let mut seen = HashSet::new();
    for value in headers.get_all("sec-websocket-protocol") {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
        for protocol in value.split(',') {
            let protocol = protocol.trim();
            if protocol.is_empty()
                || !protocol.bytes().all(is_token_byte)
                || !seen.insert(protocol.to_string())
            {
                return Err(ProxyError::BadRequest);
            }
            protocols.push(protocol.to_string());
        }
    }
    Ok(protocols)
}

fn parse_extensions(headers: &HeaderMap) -> Result<HashSet<String>, ProxyError> {
    let mut names = HashSet::new();
    for value in headers.get_all("sec-websocket-extensions") {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
        for extension in value.split(',') {
            let mut pieces = extension.split(';');
            let name = pieces.next().unwrap_or_default().trim();
            if name.is_empty() || !name.bytes().all(is_token_byte) {
                return Err(ProxyError::BadRequest);
            }
            for parameter in pieces {
                let parameter = parameter.trim();
                if parameter.is_empty() {
                    return Err(ProxyError::BadRequest);
                }
                let (param_name, param_value) = parameter
                    .split_once('=')
                    .map_or((parameter, None), |(name, value)| {
                        (name.trim(), Some(value.trim()))
                    });
                if param_name.is_empty() || !param_name.bytes().all(is_token_byte) {
                    return Err(ProxyError::BadRequest);
                }
                if let Some(value) = param_value {
                    let valid = value.bytes().all(is_token_byte)
                        || (value.len() >= 2
                            && value.starts_with('"')
                            && value.ends_with('"')
                            && value[1..value.len() - 1]
                                .bytes()
                                .all(|byte| byte >= 0x20 && byte != 0x7f));
                    if !valid {
                        return Err(ProxyError::BadRequest);
                    }
                }
            }
            names.insert(name.to_ascii_lowercase());
        }
    }
    Ok(names)
}

fn exactly_one<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a HeaderValue, ProxyError> {
    let values: Vec<_> = headers.get_all(name).iter().collect();
    if values.len() == 1 {
        Ok(values[0])
    } else {
        Err(ProxyError::BadRequest)
    }
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

struct PendingBridgeGuard {
    downstream: Option<OnUpgrade>,
    upstream: Option<OnUpgrade>,
    owner: Option<ActiveOwner>,
    downstream_lease: Option<DownstreamLease>,
}

impl PendingBridgeGuard {
    fn new(
        downstream: OnUpgrade,
        upstream: OnUpgrade,
        mut owner: ActiveOwner,
        downstream_lease: DownstreamLease,
    ) -> Self {
        owner.set_retirement_reason(RetirementReason::WebSocketCancellation);
        Self {
            downstream: Some(downstream),
            upstream: Some(upstream),
            owner: Some(owner),
            downstream_lease: Some(downstream_lease),
        }
    }

    async fn wait_for_upgrades(&mut self) -> Result<(Upgraded, Upgraded), hyper::Error> {
        let (downstream, upstream) = (&mut self.downstream, &mut self.upstream);
        tokio::try_join!(
            downstream.as_mut().expect("downstream upgrade"),
            upstream.as_mut().expect("upstream upgrade")
        )
    }

    fn mark_upgrade_failure(&mut self) {
        if let Some(owner) = self.owner.as_mut() {
            owner.set_retirement_reason(RetirementReason::UpgradeFailure);
        }
    }

    fn into_active(mut self, downstream: Upgraded, upstream: Upgraded) -> ActiveBridgeGuard {
        self.downstream.take();
        self.upstream.take();
        ActiveBridgeGuard {
            downstream: Some(TokioIo::new(downstream)),
            upstream: Some(TokioIo::new(upstream)),
            owner: self.owner.take(),
            downstream_lease: self.downstream_lease.take(),
        }
    }
}

impl Drop for PendingBridgeGuard {
    fn drop(&mut self) {
        // On cancellation, discard both upgrade futures before transport
        // retirement and release the downstream lease last.
        self.downstream.take();
        self.upstream.take();
        self.owner.take();
        self.downstream_lease.take();
    }
}

struct ActiveBridgeGuard {
    downstream: Option<TokioIo<Upgraded>>,
    upstream: Option<TokioIo<Upgraded>>,
    owner: Option<ActiveOwner>,
    downstream_lease: Option<DownstreamLease>,
}

impl ActiveBridgeGuard {
    fn streams(&mut self) -> (&mut TokioIo<Upgraded>, &mut TokioIo<Upgraded>) {
        (
            self.downstream.as_mut().expect("downstream bridge I/O"),
            self.upstream.as_mut().expect("upstream bridge I/O"),
        )
    }

    fn drop_streams(&mut self) {
        self.downstream.take();
        self.upstream.take();
    }

    fn take_owner(&mut self) -> ActiveOwner {
        self.owner.take().expect("bridge active owner")
    }
}

impl Drop for ActiveBridgeGuard {
    fn drop(&mut self) {
        // This ordering also applies when copy_bidirectional or its parent task
        // is canceled: upgraded I/O closes before U retirement and D release.
        self.drop_streams();
        self.owner.take();
        self.downstream_lease.take();
    }
}

async fn bridge_upgrades(mut pending: PendingBridgeGuard) {
    let upgraded = pending.wait_for_upgrades().await;
    let Ok((downstream, upstream)) = upgraded else {
        pending.mark_upgrade_failure();
        tracing::info!(event = "websocket_tunnel", outcome = "upgrade_failed");
        return;
    };
    let mut bridge = pending.into_active(downstream, upstream);
    let outcome = {
        let (downstream, upstream) = bridge.streams();
        tokio::io::copy_bidirectional(downstream, upstream).await
    };
    bridge.drop_streams();
    let owner = bridge.take_owner();
    let reason = if outcome.is_ok() {
        RetirementReason::WebSocketClosed
    } else {
        RetirementReason::WebSocketError
    };
    retire_active_owner(owner, reason).await;
    tracing::info!(
        event = "websocket_tunnel",
        outcome = if outcome.is_ok() {
            "closed"
        } else {
            "io_error"
        }
    );
    drop(bridge);
}

#[derive(Default)]
struct UploadState {
    complete: AtomicBool,
    cancelled: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl UploadState {
    fn is_complete(&self) -> bool {
        self.complete.load(Ordering::Acquire)
    }

    fn mark_complete(&self) {
        self.complete.store(true, Ordering::Release);
        if let Ok(mut slot) = self.waker.lock() {
            slot.take();
        }
    }

    fn cancel(&self) {
        if self.is_complete() {
            return;
        }
        self.cancelled.store(true, Ordering::Release);
        if let Ok(mut slot) = self.waker.lock() {
            if let Some(waker) = slot.take() {
                waker.wake();
            }
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn register(&self, waker: &Waker) {
        if let Ok(mut slot) = self.waker.lock() {
            if slot
                .as_ref()
                .is_none_or(|registered| !registered.will_wake(waker))
            {
                *slot = Some(waker.clone());
            }
        }
    }
}

struct DropTrailers<B> {
    inner: Option<B>,
    upload: Arc<UploadState>,
}

impl<B> DropTrailers<B> {
    fn new(inner: B, upload: Arc<UploadState>) -> Self
    where
        B: Body,
    {
        if inner.is_end_stream() {
            upload.mark_complete();
        }
        Self {
            inner: Some(inner),
            upload,
        }
    }
}

impl<B> Body for DropTrailers<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            if self.upload.is_cancelled() {
                self.inner.take();
                return Poll::Ready(None);
            }
            self.upload.register(context.waker());
            if self.upload.is_cancelled() {
                self.inner.take();
                return Poll::Ready(None);
            }
            let Some(inner) = self.inner.as_mut() else {
                return Poll::Ready(None);
            };
            match Pin::new(inner).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => continue,
                Poll::Ready(Some(Ok(frame))) => {
                    if self.inner.as_ref().is_some_and(Body::is_end_stream) {
                        self.upload.mark_complete();
                    }
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(None) => {
                    self.upload.mark_complete();
                    self.inner.take();
                    return Poll::Ready(None);
                }
                other => return other,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.upload.is_cancelled() || self.inner.as_ref().is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        if self.is_end_stream() {
            SizeHint::with_exact(0)
        } else {
            SizeHint::new()
        }
    }
}

struct PooledResponseBody {
    inner: Incoming,
    owner: Option<ActiveOwner>,
    pool: SenderPool,
    reusable: bool,
    completed: bool,
}

impl PooledResponseBody {
    fn new(inner: Incoming, owner: ActiveOwner, pool: SenderPool, reusable: bool) -> Self {
        let mut body = Self {
            inner,
            owner: Some(owner),
            pool,
            reusable,
            completed: false,
        };
        if body.inner.is_end_stream() {
            body.complete();
        }
        body
    }

    fn complete(&mut self) {
        if self.completed {
            return;
        }
        self.completed = true;
        let Some(owner) = self.owner.take() else {
            return;
        };
        if self.reusable {
            let pool = Arc::clone(&self.pool);
            tokio::spawn(park_or_retire(owner, pool));
        } else {
            schedule_retirement(owner.retirement_parts(RetirementReason::NonReusableResponse));
        }
    }
}

impl Drop for PooledResponseBody {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            schedule_retirement(owner.retirement_parts(RetirementReason::ResponseBodyDrop));
        }
    }
}

impl Body for PooledResponseBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            match Pin::new(&mut self.inner).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => continue,
                Poll::Ready(Some(Ok(frame))) => {
                    if self.inner.is_end_stream() {
                        self.complete();
                    }
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(None) => {
                    self.complete();
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Err(error))) => {
                    if let Some(owner) = self.owner.take() {
                        schedule_retirement(
                            owner.retirement_parts(RetirementReason::ResponseBodyError),
                        );
                    }
                    return Poll::Ready(Some(Err(error)));
                }
                other => return other,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        if self.inner.is_end_stream() {
            SizeHint::with_exact(0)
        } else {
            SizeHint::new()
        }
    }
}

struct ResolvedTcpConnector {
    candidates: Option<Vec<SocketAddr>>,
}

impl ResolvedTcpConnector {
    fn new(candidates: Vec<SocketAddr>) -> Self {
        Self {
            candidates: Some(candidates),
        }
    }
}

impl Service<Uri> for ResolvedTcpConnector {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let candidates = self.candidates.take();
        Box::pin(async move {
            let candidates = candidates.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "connector already used")
            })?;
            let mut last_kind = io::ErrorKind::NotConnected;
            for address in candidates {
                match TcpStream::connect(address).await {
                    Ok(stream) => {
                        // A TCP success ends address fallback. NODELAY, TLS,
                        // handshake, and HTTP failures never choose another IP.
                        stream.set_nodelay(true)?;
                        return Ok(TokioIo::new(stream));
                    }
                    Err(error) => last_kind = error.kind(),
                }
            }
            Err(io::Error::new(last_kind, "no resolved address connected"))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Condvar;

    use super::*;

    fn assert_resolver_accounting(snapshot: ResolverSnapshot, limit: usize) {
        assert_eq!(
            snapshot.submitted_unobserved,
            snapshot.request_owned + snapshot.cleanup_owned
        );
        assert!(snapshot.submitted_unobserved <= snapshot.held_r);
        assert!(snapshot.held_r <= limit);
        assert!(snapshot.live_blocking <= snapshot.submitted_unobserved);
        assert!(snapshot.live_blocking <= limit);
    }

    type ResolverOperation = Box<dyn FnOnce() -> ResolverOutput + Send>;

    struct OneShotResolver {
        operation: Mutex<Option<ResolverOperation>>,
    }

    impl OneShotResolver {
        fn new(operation: impl FnOnce() -> ResolverOutput + Send + 'static) -> Self {
            Self {
                operation: Mutex::new(Some(Box::new(operation))),
            }
        }
    }

    impl HostResolver for OneShotResolver {
        fn resolve(&self, _domain: Box<str>, _port: u16) -> ResolverOutput {
            self.operation
                .lock()
                .expect("resolver operation")
                .take()
                .expect("one resolver call")()
        }
    }

    #[test]
    fn set_cookie_filter_is_exact_and_fail_closed() {
        for value in [
            "amg_session=x; Path=/",
            "amg_login_state=x",
            "amg_session =x",
            "no-equals",
        ] {
            assert!(!is_allowed_application_cookie(
                &HeaderValue::from_str(value).expect("header")
            ));
        }
        for value in ["amg_session2=x", "AMG_SESSION=x", "app=x; Path=/"] {
            assert!(is_allowed_application_cookie(
                &HeaderValue::from_str(value).expect("header")
            ));
        }
    }

    #[test]
    fn websocket_accept_matches_rfc_example() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn http_upstream_initialization_does_not_load_native_tls_roots() {
        let upstream = crate::config::parse_upstream_url(Some("http://127.0.0.1:4096"))
            .expect("valid")
            .expect("configured");
        let proxy = Proxy::new_with_native_root_loader(upstream, 128, 8, || {
            panic!("HTTP initialization must not load TLS roots")
        });
        assert!(proxy.is_ok());
    }

    #[test]
    fn https_upstream_initialization_requires_native_tls_roots() {
        let upstream = crate::config::parse_upstream_url(Some("https://app.example"))
            .expect("valid")
            .expect("configured");
        let proxy = Proxy::new_with_native_root_loader(upstream, 128, 8, || {
            Err("test native roots unavailable".into())
        });
        assert!(proxy.is_err());
    }

    #[test]
    fn trusted_forwarding_accepts_only_one_strict_bare_ip() {
        let trusted =
            crate::config::parse_trusted_proxy_cidrs(Some("127.0.0.1/32")).expect("trusted peer");
        let peer = "127.0.0.1".parse::<IpAddr>().expect("peer");

        assert_eq!(
            derive_client_ip(peer, &HeaderMap::new(), &trusted).expect("missing fallback"),
            ClientIp(peer)
        );
        let mut valid = HeaderMap::new();
        valid.insert("x-forwarded-for", HeaderValue::from_static("2001:db8::7"));
        assert_eq!(
            derive_client_ip(peer, &valid, &trusted).expect("valid IPv6"),
            ClientIp("2001:db8::7".parse().expect("IPv6"))
        );

        for malformed in [
            "192.0.2.1, 192.0.2.2",
            "192.0.2.1:443",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "192.0.2.1 ",
            "opaque",
            "",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(malformed).expect("legal header bytes"),
            );
            assert!(matches!(
                derive_client_ip(peer, &headers, &trusted),
                Err(ProxyError::BadRequest)
            ));
        }
        let mut repeated = HeaderMap::new();
        repeated.append("x-forwarded-for", HeaderValue::from_static("192.0.2.1"));
        repeated.append("x-forwarded-for", HeaderValue::from_static("192.0.2.2"));
        assert!(matches!(
            derive_client_ip(peer, &repeated, &trusted),
            Err(ProxyError::BadRequest)
        ));
        let mut opaque = HeaderMap::new();
        opaque.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(&[0xff]).expect("opaque header"),
        );
        assert!(matches!(
            derive_client_ip(peer, &opaque, &trusted),
            Err(ProxyError::BadRequest)
        ));
    }

    #[test]
    fn untrusted_forwarding_is_never_parsed_and_mapped_families_are_distinct() {
        let trusted_v4 =
            crate::config::parse_trusted_proxy_cidrs(Some("127.0.0.1/32")).expect("trusted v4");
        let mapped = "::ffff:127.0.0.1".parse::<IpAddr>().expect("mapped peer");
        let mut opaque = HeaderMap::new();
        opaque.append(
            "x-forwarded-for",
            HeaderValue::from_bytes(&[0xff]).expect("opaque header"),
        );
        opaque.append(
            "x-forwarded-for",
            HeaderValue::from_static("attacker, invalid"),
        );
        assert_eq!(
            derive_client_ip(mapped, &opaque, &trusted_v4).expect("ignored XFF"),
            ClientIp(mapped)
        );

        let trusted_mapped = crate::config::parse_trusted_proxy_cidrs(Some("::ffff:127.0.0.1/128"))
            .expect("trusted mapped peer");
        let mut canonical = HeaderMap::new();
        canonical.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.9"));
        assert_eq!(
            derive_client_ip(mapped, &canonical, &trusted_mapped).expect("mapped trust"),
            ClientIp("192.0.2.9".parse().expect("client"))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn started_resolver_cleanup_retains_both_permits_until_join() {
        let active = Arc::new(Semaphore::new(1));
        let resolvers = Arc::new(Semaphore::new(1));
        let active_permit = Arc::clone(&active)
            .acquire_owned()
            .await
            .expect("active permit");
        let resolver_permit = Arc::clone(&resolvers)
            .acquire_owned()
            .await
            .expect("resolver permit");
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let started = Arc::new(AtomicBool::new(false));
        let operation_gate = Arc::clone(&gate);
        let operation_started = Arc::clone(&started);
        let attempt = submit_resolution(active_permit, resolver_permit, move || {
            operation_started.store(true, Ordering::Release);
            let (lock, condition) = &*operation_gate;
            let mut released = lock.lock().expect("resolver gate");
            while !*released {
                released = condition.wait(released).expect("resolver wait");
            }
            Ok(vec!["127.0.0.1:80".parse().expect("address")])
        });
        let accounting = Arc::clone(
            &attempt
                .parts
                .as_ref()
                .expect("started accounting")
                .accounting,
        );
        let waiter = tokio::spawn(async move {
            let mut attempt = attempt;
            let _ = attempt.handle_mut().await;
            attempt.observed()
        });
        timeout(Duration::from_secs(5), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("resolver started");
        assert_resolver_accounting(accounting.snapshot(), 1);
        assert_eq!(accounting.snapshot().request_owned, 1);
        waiter.abort();
        assert!(waiter.await.expect_err("request canceled").is_cancelled());
        assert_eq!(active.available_permits(), 0);
        assert_eq!(resolvers.available_permits(), 0);
        assert!(Arc::clone(&resolvers).try_acquire_owned().is_err());
        assert_resolver_accounting(accounting.snapshot(), 1);
        assert_eq!(accounting.snapshot().cleanup_owned, 1);

        {
            let (lock, condition) = &*gate;
            *lock.lock().expect("resolver release") = true;
            condition.notify_all();
        }
        timeout(Duration::from_secs(5), async {
            while active.available_permits() != 1 || resolvers.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("resolver cleanup joined before permit release");
        assert_eq!(
            accounting.snapshot(),
            ResolverSnapshot {
                total_submitted: 1,
                ..ResolverSnapshot::default()
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolver_saturation_is_immediate_and_ip_literals_bypass_r() {
        let domain = crate::config::parse_upstream_url(Some("http://localhost:9"))
            .expect("domain URL")
            .expect("domain upstream");
        let domain_proxy =
            Proxy::with_root_store(domain, RootCertStore::empty(), 1, 1).expect("domain proxy");
        let resolver_lease = Arc::clone(&domain_proxy.resolvers)
            .acquire_owned()
            .await
            .expect("occupy R");
        let active = Arc::clone(&domain_proxy.active)
            .try_acquire_owned()
            .expect("U available");
        assert!(matches!(
            domain_proxy.connect(active).await,
            Err(ProxyError::Capacity(CapacityClass::BlockingResolver))
        ));
        assert_eq!(domain_proxy.active.available_permits(), 1);
        assert_eq!(domain_proxy.resolvers.available_permits(), 0);
        drop(resolver_lease);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("unused IP address");
        let address = listener.local_addr().expect("unused address");
        drop(listener);
        let ip = crate::config::parse_upstream_url(Some(&format!("http://{address}")))
            .expect("IP URL")
            .expect("IP upstream");
        let ip_proxy = Proxy::with_root_store(ip, RootCertStore::empty(), 1, 1).expect("IP proxy");
        let resolver_lease = Arc::clone(&ip_proxy.resolvers)
            .acquire_owned()
            .await
            .expect("occupy IP proxy R");
        let active = Arc::clone(&ip_proxy.active)
            .try_acquire_owned()
            .expect("IP proxy U");
        let result = timeout(Duration::from_secs(2), ip_proxy.connect(active))
            .await
            .expect("direct IP connect did not wait for R");
        assert!(matches!(result, Err(ProxyError::BadGateway)));
        assert_eq!(ip_proxy.active.available_permits(), 1);
        assert_eq!(ip_proxy.resolvers.available_permits(), 0);
        drop(resolver_lease);

        let ipv6 = crate::config::parse_upstream_url(Some("http://[2001:db8::1]:9"))
            .expect("IPv6 URL")
            .expect("IPv6 upstream");
        assert_eq!(
            ipv6.dial_target().host(),
            &DialHost::Ip("2001:db8::1".parse().expect("IPv6 literal"))
        );
        assert_eq!(
            SocketAddr::new(
                match ipv6.dial_target().host() {
                    DialHost::Ip(ip) => *ip,
                    DialHost::Domain(_) => panic!("typed IPv6 became domain"),
                },
                ipv6.dial_target().port(),
            ),
            "[2001:db8::1]:9".parse().expect("exact IPv6 SocketAddr")
        );
        let mut ipv6_proxy =
            Proxy::with_root_store(ipv6, RootCertStore::empty(), 1, 1).expect("IPv6 proxy");
        ipv6_proxy.connect_timeout = Duration::from_millis(100);
        let resolver_lease = Arc::clone(&ipv6_proxy.resolvers)
            .acquire_owned()
            .await
            .expect("occupy IPv6 proxy R");
        let active = Arc::clone(&ipv6_proxy.active)
            .try_acquire_owned()
            .expect("IPv6 proxy U");
        let result = timeout(Duration::from_secs(2), ipv6_proxy.connect(active))
            .await
            .expect("IPv6 literal did not wait for resolver");
        assert!(matches!(result, Err(ProxyError::BadGateway)));
        assert_eq!(
            ipv6_proxy.resolver_accounting().snapshot().total_submitted,
            0
        );
        assert_eq!(ipv6_proxy.resolvers.available_permits(), 0);
        drop(resolver_lease);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn resolver_success_failure_empty_and_join_error_all_drain_accounting() {
        crate::exit::install_sanitized_panic_hook();
        let unused = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("unused address");
        let unused_address = unused.local_addr().expect("unused address value");
        drop(unused);
        let operations: Vec<ResolverOperation> = vec![
            Box::new(move || Ok(vec![unused_address])),
            Box::new(|| Err(io::Error::new(io::ErrorKind::NotFound, "resolver fixture"))),
            Box::new(|| Ok(Vec::new())),
            Box::new(|| std::panic::panic_any("resolver-join-payload-marker")),
        ];
        for operation in operations {
            let upstream = crate::config::parse_upstream_url(Some("http://resolver.example:80"))
                .expect("resolver URL")
                .expect("resolver upstream");
            let accounting = Arc::new(ResolverAccounting::default());
            let resolver = Arc::new(OneShotResolver {
                operation: Mutex::new(Some(operation)),
            });
            let proxy = Proxy::with_root_store_and_resolver(
                upstream,
                RootCertStore::empty(),
                1,
                1,
                resolver,
                Arc::clone(&accounting),
            )
            .expect("resolver proxy");
            let active = Arc::clone(&proxy.active)
                .acquire_owned()
                .await
                .expect("active permit");
            assert!(matches!(
                proxy.connect(active).await,
                Err(ProxyError::BadGateway)
            ));
            assert_eq!(proxy.active.available_permits(), 1);
            assert_eq!(proxy.resolvers.available_permits(), 1);
            assert_eq!(
                accounting.snapshot(),
                ResolverSnapshot {
                    total_submitted: 1,
                    ..ResolverSnapshot::default()
                }
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn resolver_timeout_returns_502_phase_but_keeps_u_r_through_cleanup_join() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let started = Arc::new(AtomicBool::new(false));
        let resolver_gate = Arc::clone(&gate);
        let resolver_started = Arc::clone(&started);
        let resolver = Arc::new(OneShotResolver::new(move || {
            resolver_started.store(true, Ordering::Release);
            let (lock, condition) = &*resolver_gate;
            let mut released = lock.lock().expect("timeout gate");
            while !*released {
                released = condition.wait(released).expect("timeout wait");
            }
            Ok(vec!["127.0.0.1:9".parse().expect("timeout address")])
        }));
        let accounting = Arc::new(ResolverAccounting::default());
        let upstream = crate::config::parse_upstream_url(Some("http://resolver.example:80"))
            .expect("timeout URL")
            .expect("timeout upstream");
        let mut proxy = Proxy::with_root_store_and_resolver(
            upstream,
            RootCertStore::empty(),
            1,
            1,
            resolver,
            Arc::clone(&accounting),
        )
        .expect("timeout proxy");
        proxy.connect_timeout = Duration::from_millis(100);
        let active = Arc::clone(&proxy.active)
            .acquire_owned()
            .await
            .expect("timeout active");
        let proxy_for_task = proxy.clone();
        let request = tokio::spawn(async move { proxy_for_task.connect(active).await });
        timeout(Duration::from_secs(5), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timeout resolver started");
        assert!(matches!(
            timeout(Duration::from_secs(2), request)
                .await
                .expect("request timeout response")
                .expect("request task"),
            Err(ProxyError::BadGateway)
        ));
        assert_eq!(proxy.active.available_permits(), 0);
        assert_eq!(proxy.resolvers.available_permits(), 0);
        let snapshot = accounting.snapshot();
        assert_resolver_accounting(snapshot, 1);
        assert_eq!(snapshot.cleanup_owned, 1);
        assert_eq!(snapshot.live_blocking, 1);
        {
            let (lock, condition) = &*gate;
            *lock.lock().expect("timeout release") = true;
            condition.notify_all();
        }
        timeout(Duration::from_secs(5), async {
            while proxy.active.available_permits() != 1 || proxy.resolvers.available_permits() != 1
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timeout cleanup joined");
        assert_eq!(
            accounting.snapshot(),
            ResolverSnapshot {
                total_submitted: 1,
                ..ResolverSnapshot::default()
            }
        );
    }

    #[tokio::test]
    async fn resolved_connector_uses_ordered_socketaddr_tcp_fallback_only() {
        let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("unavailable candidate");
        let unavailable_address = unavailable.local_addr().expect("unavailable address");
        drop(unavailable);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fallback listener");
        let available_address = listener.local_addr().expect("available address");
        let accepted =
            tokio::spawn(async move { listener.accept().await.expect("fallback accept") });
        let mut connector = ResolvedTcpConnector::new(vec![unavailable_address, available_address]);
        let io = connector
            .call(
                "http://fixed-authority.example/"
                    .parse()
                    .expect("connector URI"),
            )
            .await
            .expect("second SocketAddr connected");
        let (_, peer) = accepted.await.expect("accept task");
        assert_eq!(peer.ip(), available_address.ip());
        drop(io);
        assert!(connector
            .call(
                "http://fixed-authority.example/"
                    .parse()
                    .expect("second URI")
            )
            .await
            .is_err());
    }

    #[test]
    fn queued_resolver_cancellation_aborts_without_running_or_leaking_permits() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("queued resolver runtime");
        runtime.block_on(async {
            let blocker_gate = Arc::new((Mutex::new(false), Condvar::new()));
            let blocker_started = Arc::new(AtomicBool::new(false));
            let task_gate = Arc::clone(&blocker_gate);
            let task_started = Arc::clone(&blocker_started);
            let blocker = tokio::task::spawn_blocking(move || {
                task_started.store(true, Ordering::Release);
                let (lock, condition) = &*task_gate;
                let mut released = lock.lock().expect("blocker gate");
                while !*released {
                    released = condition.wait(released).expect("blocker wait");
                }
            });
            timeout(Duration::from_secs(5), async {
                while !blocker_started.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("blocking lane occupied");

            let active = Arc::new(Semaphore::new(1));
            let resolvers = Arc::new(Semaphore::new(1));
            let ran = Arc::new(AtomicUsize::new(0));
            let ran_job = Arc::clone(&ran);
            let attempt = submit_resolution(
                Arc::clone(&active).acquire_owned().await.expect("active"),
                Arc::clone(&resolvers)
                    .acquire_owned()
                    .await
                    .expect("resolver"),
                move || {
                    ran_job.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::new())
                },
            );
            let accounting = Arc::clone(
                &attempt
                    .parts
                    .as_ref()
                    .expect("queued accounting")
                    .accounting,
            );
            assert_eq!(
                attempt
                    .parts
                    .as_ref()
                    .expect("queued attempt")
                    .state
                    .load(Ordering::Acquire),
                RESOLVER_QUEUED
            );
            let waiter = tokio::spawn(async move {
                let mut attempt = attempt;
                let _ = attempt.handle_mut().await;
                attempt.observed()
            });
            tokio::task::yield_now().await;
            waiter.abort();
            assert!(waiter
                .await
                .expect_err("queued request canceled")
                .is_cancelled());
            assert_eq!(active.available_permits(), 0);
            assert_eq!(resolvers.available_permits(), 0);
            assert!(Arc::clone(&resolvers).try_acquire_owned().is_err());
            assert_resolver_accounting(accounting.snapshot(), 1);
            assert_eq!(accounting.snapshot().cleanup_owned, 1);

            {
                let (lock, condition) = &*blocker_gate;
                *lock.lock().expect("blocker release") = true;
                condition.notify_all();
            }
            blocker.await.expect("blocker completion");
            timeout(Duration::from_secs(5), async {
                while active.available_permits() != 1 || resolvers.available_permits() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("queued handle observed");
            assert_eq!(ran.load(Ordering::SeqCst), 0);
            assert_eq!(
                accounting.snapshot(),
                ResolverSnapshot {
                    total_submitted: 1,
                    ..ResolverSnapshot::default()
                }
            );
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_terminal_reason_observes_driver_before_returning_active_permit() {
        struct BlockingDrop {
            entered: Arc<AtomicBool>,
            gate: Arc<(Mutex<bool>, Condvar)>,
        }

        impl Drop for BlockingDrop {
            fn drop(&mut self) {
                self.entered.store(true, Ordering::Release);
                let (lock, condition) = &*self.gate;
                let mut released = lock.lock().expect("driver drop gate");
                while !*released {
                    released = condition.wait(released).expect("driver drop wait");
                }
            }
        }

        for reason in [
            RetirementReason::RequestCancellation,
            RetirementReason::ReadyFailure,
            RetirementReason::SendFailure,
            RetirementReason::InvalidUpgrade,
            RetirementReason::ResponseBodyError,
            RetirementReason::ResponseBodyDrop,
            RetirementReason::NonReusableResponse,
            RetirementReason::PoolReadyTimeout,
            RetirementReason::PoolReadyFailure,
            RetirementReason::PoolFull,
            RetirementReason::PoolPoisoned,
            RetirementReason::UpgradeFailure,
            RetirementReason::WebSocketClosed,
            RetirementReason::WebSocketError,
            RetirementReason::WebSocketCancellation,
            RetirementReason::IdleOwnerDrop,
        ] {
            let (client, server) = tokio::io::duplex(1024);
            let (sender, connection) = http1::handshake::<_, RequestBody>(TokioIo::new(client))
                .await
                .expect("test sender");
            drop(connection);
            let active = Arc::new(Semaphore::new(1));
            let permit = Arc::clone(&active)
                .acquire_owned()
                .await
                .expect("active permit");
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            let created = Arc::new(AtomicBool::new(false));
            let drop_entered = Arc::new(AtomicBool::new(false));
            let driver_gate = Arc::clone(&gate);
            let driver_created = Arc::clone(&created);
            let driver_drop = Arc::clone(&drop_entered);
            let driver = tokio::spawn(async move {
                let _guard = BlockingDrop {
                    entered: driver_drop,
                    gate: driver_gate,
                };
                driver_created.store(true, Ordering::Release);
                pending::<()>().await;
            });
            timeout(Duration::from_secs(5), async {
                while !created.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("driver task started");

            let accounting = Arc::new(DriverRetirementAccounting::default());
            let owner = ActiveOwner::new(
                CompleteOwner::new(sender, driver, Arc::clone(&accounting)),
                permit,
            );
            schedule_retirement(owner.retirement_parts(reason));
            timeout(Duration::from_secs(5), async {
                while !drop_entered.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("driver abort began");
            assert_eq!(active.available_permits(), 0, "reason={reason:?}");
            assert!(Arc::clone(&active).try_acquire_owned().is_err());
            assert_eq!(accounting.counts(reason), (1, 0));
            assert_eq!(accounting.active_cleanups.load(Ordering::Acquire), 1);
            {
                let (lock, condition) = &*gate;
                *lock.lock().expect("driver release") = true;
                condition.notify_all();
            }
            timeout(Duration::from_secs(5), async {
                while active.available_permits() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("driver joined before active release");
            assert_eq!(accounting.counts(reason), (1, 1));
            assert_eq!(accounting.active_cleanups.load(Ordering::Acquire), 0);
            drop(server);
        }
    }

    #[test]
    fn connect_and_handshake_cancellation_drop_io_before_u() {
        struct PendingIo {
            dropped: Arc<AtomicBool>,
            active: Arc<Semaphore>,
        }

        impl Future for PendingIo {
            type Output = io::Result<()>;

            fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
                Poll::Pending
            }
        }

        impl Drop for PendingIo {
            fn drop(&mut self) {
                assert_eq!(self.active.available_permits(), 0);
                self.dropped.store(true, Ordering::Release);
            }
        }

        for phase in ["connect", "handshake"] {
            let active = Arc::new(Semaphore::new(1));
            let permit = Arc::clone(&active)
                .try_acquire_owned()
                .expect("phase permit");
            let dropped = Arc::new(AtomicBool::new(false));
            let future = PendingIo {
                dropped: Arc::clone(&dropped),
                active: Arc::clone(&active),
            };
            let phase_guard = ActivePhase::new(future, permit);
            drop(phase_guard);
            assert!(dropped.load(Ordering::Acquire), "phase={phase}");
            assert_eq!(active.available_permits(), 1, "phase={phase}");
        }
    }

    #[tokio::test]
    async fn connect_and_handshake_error_drop_io_before_returning_u() {
        struct ErrorIoDrop {
            dropped: Arc<AtomicBool>,
            active: Arc<Semaphore>,
        }

        impl Drop for ErrorIoDrop {
            fn drop(&mut self) {
                assert_eq!(self.active.available_permits(), 0);
                self.dropped.store(true, Ordering::Release);
            }
        }

        for phase in ["connect", "handshake"] {
            let active = Arc::new(Semaphore::new(1));
            let permit = Arc::clone(&active)
                .acquire_owned()
                .await
                .expect("error phase permit");
            let dropped = Arc::new(AtomicBool::new(false));
            let probe = ErrorIoDrop {
                dropped: Arc::clone(&dropped),
                active: Arc::clone(&active),
            };
            let operation = async move {
                drop(probe);
                Err::<(), io::Error>(io::Error::other("allowlisted fixture failure"))
            };
            let (result, permit) = ActivePhase::new(operation, permit).await;
            assert!(result.is_err(), "phase={phase}");
            assert!(dropped.load(Ordering::Acquire), "phase={phase}");
            assert_eq!(active.available_permits(), 0, "phase={phase}");
            drop(permit);
            assert_eq!(active.available_permits(), 1, "phase={phase}");
        }
    }

    #[test]
    fn pool_timeout_failure_full_and_poison_map_to_central_retirement_reasons() {
        assert_eq!(PoolReadinessOutcome::Ready.retirement_reason(), None);
        assert_eq!(
            PoolReadinessOutcome::Timeout.retirement_reason(),
            Some(RetirementReason::PoolReadyTimeout)
        );
        assert_eq!(
            PoolReadinessOutcome::Failure.retirement_reason(),
            Some(RetirementReason::PoolReadyFailure)
        );
        assert_eq!(PoolPlacementOutcome::Parked.retirement_reason(), None);
        assert_eq!(
            PoolPlacementOutcome::Full.retirement_reason(),
            Some(RetirementReason::PoolFull)
        );
        assert_eq!(
            PoolPlacementOutcome::Poisoned.retirement_reason(),
            Some(RetirementReason::PoolPoisoned)
        );
    }
}
