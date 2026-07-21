//! Dual cleartext H1/H2-prior-knowledge fixture and auth-mini tripwire role.

use crate::control::{
    ControlBody, ControlContext, EndpointObservation, FixtureResult, FramedControl, LoadTarget,
    Role, RoleErrorCode, RoleErrorStage,
};
use crate::linux::process_identity;
use crate::schema::Workload;
use crate::session::{USER_EMAIL, USER_ID};
use crate::topology::{
    parse_masked_ping, parse_operation_id, unmasked_pong, websocket_accept, Corpus, Protocol,
    CORPUS_BYTES,
};
use crate::wire::{H2FrameObserver, ObservedH2Io};
use crate::{Error, Result, ResultContext};
use bytes::Bytes;
use http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_TYPE, COOKIE, PROXY_AUTHORIZATION, SEC_WEBSOCKET_ACCEPT,
    SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION, SET_COOKIE, UPGRADE,
};
use http::{HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body_util::BodyExt as _;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone)]
struct FixtureConfig {
    target: LoadTarget,
    workload: Workload,
    expected_protocol: Protocol,
    corpus_sha256: String,
}

struct FixtureState {
    corpus: Corpus,
    config: RwLock<Option<FixtureConfig>>,
    next_connection_id: AtomicU64,
    physical_connections: AtomicU64,
    active_connections: AtomicU64,
    max_active_connections: AtomicU64,
    tripwire_connections: AtomicU64,
    tripwire_bytes: AtomicU64,
    duplicate_operations: AtomicU64,
    unknown_requests: AtomicU64,
    operation_ids: Mutex<BTreeSet<String>>,
    requests_per_connection: Mutex<BTreeMap<u64, u64>>,
    observations: Mutex<Vec<EndpointObservation>>,
    h2_wire: Mutex<BTreeMap<u64, H2FrameObserver>>,
}

impl FixtureState {
    fn new() -> Self {
        Self {
            corpus: Corpus::fixed(),
            config: RwLock::new(None),
            next_connection_id: AtomicU64::new(0),
            physical_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            max_active_connections: AtomicU64::new(0),
            tripwire_connections: AtomicU64::new(0),
            tripwire_bytes: AtomicU64::new(0),
            duplicate_operations: AtomicU64::new(0),
            unknown_requests: AtomicU64::new(0),
            operation_ids: Mutex::new(BTreeSet::new()),
            requests_per_connection: Mutex::new(BTreeMap::new()),
            observations: Mutex::new(Vec::new()),
            h2_wire: Mutex::new(BTreeMap::new()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BenchBody {
    chunks: VecDeque<Bytes>,
    remaining: u64,
}

impl BenchBody {
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        Self::from_chunks([bytes.into()])
    }

    #[must_use]
    pub fn from_chunks(chunks: impl IntoIterator<Item = Bytes>) -> Self {
        let chunks: VecDeque<_> = chunks.into_iter().collect();
        let remaining = chunks.iter().map(|chunk| chunk.len() as u64).sum();
        Self { chunks, remaining }
    }
}

impl Body for BenchBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let Some(chunk) = self.chunks.pop_front() else {
            return Poll::Ready(None);
        };
        self.remaining = self.remaining.saturating_sub(chunk.len() as u64);
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.chunks.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

pub async fn run_fixture_role(_context: ControlContext, control: &mut FramedControl) -> Result<()> {
    control
        .authenticate_inherited_role(Role::Fixture, process_identity(std::process::id())?)
        .await?;
    control.mark_failure_stage(RoleErrorStage::Startup);
    let data_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind fixture data listener")?;
    let tripwire_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind auth-mini tripwire")?;
    let data_address = data_listener.local_addr()?;
    let tripwire_address = tripwire_listener.local_addr()?;
    if !data_address.ip().is_loopback() || !tripwire_address.ip().is_loopback() {
        return Err(Error::new("fixture listener escaped loopback"));
    }
    let state = Arc::new(FixtureState::new());
    let data_task = tokio::spawn(run_data_listener(data_listener, Arc::clone(&state)));
    let tripwire_task = tokio::spawn(run_tripwire(tripwire_listener, Arc::clone(&state)));
    control
        .send(ControlBody::Ready {
            role: Role::Fixture,
            data_address: Some(data_address.to_string()),
            tripwire_address: Some(tripwire_address.to_string()),
        })
        .await?;
    loop {
        control.mark_failure_stage(RoleErrorStage::Prepare);
        match control.receive().await? {
            ControlBody::ConfigureFixture {
                target,
                workload,
                expected_protocol,
                corpus_sha256,
            } => {
                control.mark_failure_stage(RoleErrorStage::Prepare);
                let expected = state.corpus.sha256();
                if corpus_sha256 != expected {
                    return Err(Error::new("fixture corpus hash mismatch"));
                }
                {
                    let mut config = state
                        .config
                        .write()
                        .map_err(|_| Error::new("fixture config poisoned"))?;
                    if config.is_some() {
                        return Err(Error::new("fixture was configured more than once"));
                    }
                    *config = Some(FixtureConfig {
                        target,
                        workload,
                        expected_protocol,
                        corpus_sha256,
                    });
                }
                control.send(ControlBody::FixtureConfigured).await?;
            }
            message @ (ControlBody::FixtureSnapshot | ControlBody::FixtureCompactSnapshot) => {
                control.mark_failure_stage(RoleErrorStage::Drain);
                let compact = matches!(message, ControlBody::FixtureCompactSnapshot);
                control
                    .send(ControlBody::FixtureObserved {
                        result: snapshot(&state, compact)?,
                    })
                    .await?;
            }
            ControlBody::Stop => {
                control.mark_failure_stage(RoleErrorStage::Exit);
                data_task.abort();
                tripwire_task.abort();
                control
                    .send(ControlBody::Stopped {
                        role: Role::Fixture,
                    })
                    .await?;
                return Ok(());
            }
            other => {
                return Err(Error::new(format!(
                    "fixture received unexpected control message: {other:?}"
                ))
                .with_role_diagnostic(control.failure_stage(), RoleErrorCode::ControlProtocol))
            }
        }
    }
}

async fn run_data_listener(listener: TcpListener, state: Arc<FixtureState>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            return;
        };
        if !peer.ip().is_loopback() {
            state.unknown_requests.fetch_add(1, Ordering::SeqCst);
            continue;
        }
        let connection_id = state.next_connection_id.fetch_add(1, Ordering::SeqCst) + 1;
        state.physical_connections.fetch_add(1, Ordering::SeqCst);
        let active = state.active_connections.fetch_add(1, Ordering::SeqCst) + 1;
        update_max(&state.max_active_connections, active);
        let connection_state = Arc::clone(&state);
        tokio::spawn(async move {
            let result = serve_auto(stream, connection_id, Arc::clone(&connection_state)).await;
            if let Err(error) = result {
                eprintln!("fixture-role: connection {connection_id} ended: {error}");
                connection_state
                    .unknown_requests
                    .fetch_add(1, Ordering::SeqCst);
            }
            connection_state
                .active_connections
                .fetch_sub(1, Ordering::SeqCst);
        });
    }
}

async fn detect_h2(stream: &TcpStream) -> Result<bool> {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut buffer = [0_u8; 24];
    loop {
        let count = stream.peek(&mut buffer).await?;
        if count == 0 {
            return Err(Error::new("fixture peer closed before protocol detection"));
        }
        if buffer[..count] != PREFACE[..count.min(PREFACE.len())] {
            return Ok(false);
        }
        if count >= PREFACE.len() {
            return Ok(true);
        }
        tokio::task::yield_now().await;
    }
}

async fn serve_auto(stream: TcpStream, connection_id: u64, state: Arc<FixtureState>) -> Result<()> {
    let h2 = detect_h2(&stream).await?;
    let actual = if h2 { Protocol::H2 } else { Protocol::H1 };
    let config = state
        .config
        .read()
        .map_err(|_| Error::new("fixture config poisoned"))?
        .clone()
        .ok_or_else(|| Error::new("fixture data arrived before configuration"))?;
    if actual != config.expected_protocol {
        return Err(Error::new(format!(
            "fixture expected {:?}, received {:?}",
            config.expected_protocol, actual
        )));
    }
    let observer = if h2 {
        let observer = H2FrameObserver::server(connection_id)?;
        state
            .h2_wire
            .lock()
            .map_err(|_| Error::new("fixture H2 observer map poisoned"))?
            .insert(connection_id, observer.clone());
        Some(observer)
    } else {
        None
    };
    let service_observer = observer.clone();
    let service = service_fn(move |request| {
        fixture_response(
            request,
            connection_id,
            service_observer.clone(),
            Arc::clone(&state),
        )
    });
    if h2 {
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder
            .max_concurrent_streams(100)
            .max_header_list_size(16_384)
            .enable_connect_protocol()
            .auto_date_header(false);
        let observer = observer.ok_or_else(|| Error::new("fixture H2 observer missing"))?;
        builder
            .serve_connection(
                TokioIo::new(ObservedH2Io::server(stream, observer)),
                service,
            )
            .await
            .context("serve fixture H2 connection")?;
    } else {
        let mut builder = http1::Builder::new();
        builder.keep_alive(true).auto_date_header(false);
        builder
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await
            .context("serve fixture H1 connection")?;
    }
    Ok(())
}

async fn fixture_response(
    mut request: Request<Incoming>,
    connection_id: u64,
    observer: Option<H2FrameObserver>,
    state: Arc<FixtureState>,
) -> std::result::Result<Response<BenchBody>, Infallible> {
    let response = fixture_response_inner(&mut request, connection_id, observer, state)
        .await
        .unwrap_or_else(error_response);
    Ok(response)
}

async fn fixture_response_inner(
    request: &mut Request<Incoming>,
    connection_id: u64,
    observer: Option<H2FrameObserver>,
    state: Arc<FixtureState>,
) -> Result<Response<BenchBody>> {
    let protocol = match request.version() {
        Version::HTTP_11 => Protocol::H1,
        Version::HTTP_2 => Protocol::H2,
        other => {
            return Err(Error::new(format!(
                "unsupported fixture HTTP version {other:?}"
            )))
        }
    };
    let wire_stream_id = if protocol == Protocol::H2 {
        Some(
            observer
                .as_ref()
                .ok_or_else(|| Error::new("H2 request has no frame observer"))?
                .claim_stream_now()?,
        )
    } else {
        if observer.is_some() {
            return Err(Error::new("H1 request unexpectedly has an H2 observer"));
        }
        None
    };
    let stream_id = wire_stream_id.map(u64::from);
    let operation_id = request
        .headers()
        .get("x-amg-bench-op")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| Error::new("missing operation ID"))?
        .to_owned();
    parse_operation_id(&operation_id)?;
    register_operation(&state, &operation_id)?;
    let path = request.uri().path().to_owned();
    let config = state
        .config
        .read()
        .map_err(|_| Error::new("fixture config poisoned"))?
        .clone()
        .ok_or_else(|| Error::new("fixture is not configured"))?;
    if protocol != config.expected_protocol || config.corpus_sha256 != state.corpus.sha256() {
        return Err(Error::new("fixture protocol or corpus changed"));
    }
    {
        let mut counts = state
            .requests_per_connection
            .lock()
            .map_err(|_| Error::new("fixture connection counts poisoned"))?;
        let count = counts.entry(connection_id).or_insert(0);
        *count = count
            .checked_add(1)
            .ok_or_else(|| Error::new("fixture per-connection request count overflow"))?;
    }
    if path != crate::topology::workload_path(config.workload) {
        state.unknown_requests.fetch_add(1, Ordering::SeqCst);
        return Err(Error::new("fixture path does not match frozen workload"));
    }
    let headers_ok = request_headers_sanitized(request);
    let identity_ok = request
        .headers()
        .get("x-auth-mini-user-id")
        .is_some_and(|value| value == USER_ID)
        && request
            .headers()
            .get("x-auth-mini-email")
            .is_some_and(|value| value == USER_EMAIL);
    if !headers_ok || !identity_ok {
        return Err(Error::new(
            "gateway request identity/header sanitation failed",
        ));
    }
    if config.workload == Workload::WebSocket {
        if let (Some(observer), Some(stream_id)) = (observer.as_ref(), wire_stream_id) {
            observer.mark_observed_stream_as_extended_connect(stream_id)?;
        }
        return websocket_response(
            request,
            protocol,
            connection_id,
            stream_id,
            operation_id,
            state,
        )
        .await;
    }
    let corpus = &state.corpus;
    let mut request_bytes = 0_u64;
    let mut payload_ok = true;
    let mut offset = 0_usize;
    while let Some(frame) = request.body_mut().frame().await {
        let frame = frame.map_err(|error| Error::new(format!("request body error: {error}")))?;
        if let Ok(data) = frame.into_data() {
            let end = offset
                .checked_add(data.len())
                .ok_or_else(|| Error::new("upload offset overflow"))?;
            if end > corpus.bytes().len() || data.as_ref() != &corpus.bytes()[offset..end] {
                payload_ok = false;
            }
            offset = end;
            request_bytes = request_bytes
                .checked_add(data.len() as u64)
                .ok_or_else(|| Error::new("request byte count overflow"))?;
        }
    }
    let (method_ok, body) = match config.workload {
        Workload::Get => (
            request.method() == Method::GET && request_bytes == 0,
            BenchBody::from_bytes(Bytes::copy_from_slice(corpus.get_body())),
        ),
        Workload::Upload1Mib => {
            let ok = request.method() == Method::POST
                && request_bytes == CORPUS_BYTES as u64
                && offset == CORPUS_BYTES
                && payload_ok;
            let response = format!("{operation_id}:{request_bytes}");
            (ok, BenchBody::from_bytes(Bytes::from(response)))
        }
        Workload::Download1Mib => (
            request.method() == Method::GET && request_bytes == 0,
            BenchBody::from_chunks(corpus.chunks().map(Bytes::copy_from_slice)),
        ),
        Workload::Sse => (
            request.method() == Method::GET && request_bytes == 0,
            BenchBody::from_chunks((0..crate::topology::SSE_EVENTS).map(|event| {
                let mut bytes = Vec::with_capacity(crate::topology::SSE_DATA_BYTES + 16);
                bytes.extend_from_slice(format!("id: {event}\n").as_bytes());
                bytes.extend_from_slice(b"data: ");
                bytes.extend_from_slice(&corpus.sse_data(event));
                bytes.extend_from_slice(b"\n\n");
                Bytes::from(bytes)
            })),
        ),
        Workload::WebSocket => unreachable!("WebSocket handled above"),
    };
    if !method_ok || !payload_ok {
        return Err(Error::new("fixture method or payload mismatch"));
    }
    let response_bytes = body.remaining;
    state
        .observations
        .lock()
        .map_err(|_| Error::new("fixture observations poisoned"))?
        .push(EndpointObservation {
            operation_id,
            protocol,
            connection_id,
            stream_id,
            method: request.method().to_string(),
            path,
            request_bytes,
            response_bytes,
            status: 200,
            request_eos: true,
            response_eos: true,
            payload_ok: true,
            identity_ok,
            request_headers_sanitized: headers_ok,
        });
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert("x-fixture-marker", HeaderValue::from_static("present"));
    if config.target == LoadTarget::Gateway {
        response.headers_mut().insert(
            "x-auth-mini-fixture-secret",
            HeaderValue::from_static("must-be-stripped"),
        );
        response.headers_mut().append(
            SET_COOKIE,
            HeaderValue::from_static("amg_session=must-be-stripped; Path=/"),
        );
    }
    if config.workload == Workload::Sse {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    }
    if config.target == LoadTarget::Direct
        && config.workload == Workload::Upload1Mib
        && protocol == Protocol::H1
    {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    Ok(response)
}

async fn websocket_response(
    request: &mut Request<Incoming>,
    protocol: Protocol,
    connection_id: u64,
    stream_id: Option<u64>,
    operation_id: String,
    state: Arc<FixtureState>,
) -> Result<Response<BenchBody>> {
    let h1 = protocol == Protocol::H1
        && request.method() == Method::GET
        && request
            .headers()
            .get(UPGRADE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"));
    let h2 = protocol == Protocol::H2
        && request.method() == Method::CONNECT
        && request
            .extensions()
            .get::<hyper::ext::Protocol>()
            .is_some_and(|value| value.as_str() == "websocket");
    if !h1 && !h2 {
        return Err(Error::new(
            "fixture did not receive RFC6455 Upgrade or RFC8441 CONNECT",
        ));
    }
    if request
        .headers()
        .get(SEC_WEBSOCKET_VERSION)
        .is_none_or(|value| value != "13")
    {
        return Err(Error::new("WebSocket version is not 13"));
    }
    let key = request
        .headers()
        .get(SEC_WEBSOCKET_KEY)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if h1 && key.is_none() {
        return Err(Error::new("H1 WebSocket key missing"));
    }
    if h2 && key.is_some() {
        return Err(Error::new(
            "H2 WebSocket must not carry Sec-WebSocket-Key upstream",
        ));
    }
    let upgrade = hyper::upgrade::on(&mut *request);
    let tunnel_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Ok(upgraded) = upgrade.await {
            let mut io = TokioIo::new(upgraded);
            loop {
                let mut frame = [0_u8; 14];
                match io.read_exact(&mut frame).await {
                    Ok(_) => {}
                    Err(_) => return,
                }
                let Ok(payload) = parse_masked_ping(&frame) else {
                    tunnel_state.unknown_requests.fetch_add(1, Ordering::SeqCst);
                    return;
                };
                let lane = u16::from_be_bytes([payload[0], payload[1]]);
                let packed = u64::from_be_bytes([
                    0, 0, payload[2], payload[3], payload[4], payload[5], payload[6], payload[7],
                ]);
                let phase = (packed >> 32) as u16;
                let sequence = packed & 0xffff_ffff;
                let value = crate::topology::operation_id(phase, lane, sequence);
                let operation_text = crate::topology::operation_id_text(value);
                if register_operation(&tunnel_state, &operation_text).is_err() {
                    return;
                }
                if io.write_all(&unmasked_pong(payload)).await.is_err() {
                    return;
                }
                let mut observations = match tunnel_state.observations.lock() {
                    Ok(value) => value,
                    Err(_) => return,
                };
                observations.push(EndpointObservation {
                    operation_id: operation_text,
                    protocol,
                    connection_id,
                    stream_id,
                    method: "PING".to_owned(),
                    path: "/bench/websocket".to_owned(),
                    request_bytes: 8,
                    response_bytes: 8,
                    status: 200,
                    request_eos: true,
                    response_eos: true,
                    payload_ok: true,
                    identity_ok: true,
                    request_headers_sanitized: true,
                });
            }
        }
    });
    state
        .observations
        .lock()
        .map_err(|_| Error::new("fixture observations poisoned"))?
        .push(EndpointObservation {
            operation_id,
            protocol,
            connection_id,
            stream_id,
            method: request.method().to_string(),
            path: "/bench/websocket".to_owned(),
            request_bytes: 0,
            response_bytes: 0,
            status: if h1 { 101 } else { 200 },
            request_eos: true,
            response_eos: false,
            payload_ok: true,
            identity_ok: true,
            request_headers_sanitized: true,
        });
    let mut response = Response::new(BenchBody::empty());
    if h1 {
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
        response
            .headers_mut()
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
        response.headers_mut().insert(
            SEC_WEBSOCKET_ACCEPT,
            HeaderValue::from_str(&websocket_accept(key.as_deref().unwrap_or_default()))
                .map_err(|_| Error::new("invalid generated WebSocket accept"))?,
        );
    } else {
        *response.status_mut() = StatusCode::OK;
    }
    Ok(response)
}

fn request_headers_sanitized(request: &Request<Incoming>) -> bool {
    !request.headers().contains_key(COOKIE)
        && !request.headers().contains_key(AUTHORIZATION)
        && !request.headers().contains_key(PROXY_AUTHORIZATION)
        && !request.headers().contains_key("x-auth-mini-forged")
        && request
            .headers()
            .get("x-forwarded-host")
            .is_some_and(|value| value == "public.example")
        && request
            .headers()
            .get("x-forwarded-proto")
            .is_some_and(|value| value == "http")
}

fn register_operation(state: &FixtureState, operation_id: &str) -> Result<()> {
    let mut operations = state
        .operation_ids
        .lock()
        .map_err(|_| Error::new("fixture operations poisoned"))?;
    if !operations.insert(operation_id.to_owned()) {
        state.duplicate_operations.fetch_add(1, Ordering::SeqCst);
        return Err(Error::new("replayed operation ID"));
    }
    Ok(())
}

fn error_response(error: Error) -> Response<BenchBody> {
    let mut response = Response::new(BenchBody::from_bytes(Bytes::from(error.to_string())));
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

async fn run_tripwire(listener: TcpListener, state: Arc<FixtureState>) {
    loop {
        let Ok((mut stream, peer)) = listener.accept().await else {
            return;
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        state.tripwire_connections.fetch_add(1, Ordering::SeqCst);
        let tripwire_state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut bytes = [0_u8; 4096];
            if let Ok(count) = stream.read(&mut bytes).await {
                tripwire_state
                    .tripwire_bytes
                    .fetch_add(count as u64, Ordering::SeqCst);
            }
        });
    }
}

fn snapshot(state: &FixtureState, compact: bool) -> Result<FixtureResult> {
    let config = state
        .config
        .read()
        .map_err(|_| Error::new("fixture config poisoned"))?
        .clone()
        .ok_or_else(|| Error::new("fixture snapshot before configuration"))?;
    let mut observations = state
        .observations
        .lock()
        .map_err(|_| Error::new("fixture observations poisoned"))?
        .clone();
    observations.sort_by(|left, right| {
        left.operation_id
            .as_bytes()
            .cmp(right.operation_id.as_bytes())
            .then(left.method.as_bytes().cmp(right.method.as_bytes()))
    });
    let mut hasher = Sha256::new();
    let mut phases = std::collections::BTreeMap::<u16, Vec<&EndpointObservation>>::new();
    for observation in &observations {
        hasher.update(observation.operation_id.as_bytes());
        hasher.update(observation.request_bytes.to_be_bytes());
        hasher.update(observation.response_bytes.to_be_bytes());
        let operation = parse_operation_id(&observation.operation_id)?;
        phases
            .entry((operation >> 112) as u16)
            .or_default()
            .push(observation);
    }
    let phase_aggregates = phases
        .into_iter()
        .map(|(phase, observations)| fixture_phase_aggregate(phase, &observations, &config))
        .collect::<Result<Vec<_>>>()?;
    let max_requests_per_connection = state
        .requests_per_connection
        .lock()
        .map_err(|_| Error::new("fixture connection counts poisoned"))?
        .values()
        .copied()
        .max()
        .unwrap_or(0);
    let mut h2_wire = state
        .h2_wire
        .lock()
        .map_err(|_| Error::new("fixture H2 observer map poisoned"))?
        .values()
        .map(H2FrameObserver::snapshot)
        .collect::<Result<Vec<_>>>()?;
    h2_wire.sort_by_key(|evidence| evidence.connection_id);
    let observation_count = observations.len() as u64;
    Ok(FixtureResult {
        target: config.target,
        expected_protocol: config.expected_protocol,
        physical_connections: state.physical_connections.load(Ordering::SeqCst),
        active_connections: state.active_connections.load(Ordering::SeqCst),
        max_active_connections: state.max_active_connections.load(Ordering::SeqCst),
        max_requests_per_connection,
        tripwire_connections: state.tripwire_connections.load(Ordering::SeqCst),
        tripwire_bytes: state.tripwire_bytes.load(Ordering::SeqCst),
        duplicate_operations: state.duplicate_operations.load(Ordering::SeqCst),
        unknown_requests: state.unknown_requests.load(Ordering::SeqCst),
        compacted: compact,
        observation_count,
        observations: if compact { Vec::new() } else { observations },
        phase_aggregates,
        operation_hash_sha256: format!("{:x}", hasher.finalize()),
        h2_wire,
    })
}

fn fixture_phase_aggregate(
    phase: u16,
    observations: &[&EndpointObservation],
    config: &FixtureConfig,
) -> Result<crate::control::FixturePhaseAggregate> {
    let mut hasher = Sha256::new();
    let mut request_bytes = 0_u64;
    let mut response_bytes = 0_u64;
    for observation in observations {
        hasher.update(observation.operation_id.as_bytes());
        hasher.update(observation.request_bytes.to_be_bytes());
        hasher.update(observation.response_bytes.to_be_bytes());
        request_bytes = request_bytes
            .checked_add(observation.request_bytes)
            .ok_or_else(|| Error::new("fixture phase request-byte overflow"))?;
        response_bytes = response_bytes
            .checked_add(observation.response_bytes)
            .ok_or_else(|| Error::new("fixture phase response-byte overflow"))?;
    }
    Ok(crate::control::FixturePhaseAggregate {
        phase,
        operations: observations.len() as u64,
        http_requests: observations
            .iter()
            .filter(|observation| observation.method != "PING")
            .count() as u64,
        request_bytes,
        response_bytes,
        operation_hash_sha256: format!("{:x}", hasher.finalize()),
        protocol_correct: observations
            .iter()
            .all(|observation| observation.protocol == config.expected_protocol),
        payload_correct: observations
            .iter()
            .all(|observation| observation.payload_ok),
        identity_correct: observations
            .iter()
            .all(|observation| observation.identity_ok),
        headers_sanitized: observations
            .iter()
            .all(|observation| observation.request_headers_sanitized),
        request_eos: observations
            .iter()
            .all(|observation| observation.request_eos),
        response_semantics_correct: observations.iter().all(|observation| {
            (observation.method == "PING" || observation.status == 200 || observation.status == 101)
                && (observation.method == "PING"
                    || config.workload == Workload::WebSocket
                    || observation.response_eos)
        }),
        observed_protocol: observations
            .first()
            .map(|observation| observation.protocol)
            .filter(|protocol| {
                observations
                    .iter()
                    .all(|observation| observation.protocol == *protocol)
            }),
    })
}

fn update_max(value: &AtomicU64, candidate: u64) {
    let mut current = value.load(Ordering::SeqCst);
    while candidate > current {
        match value.compare_exchange(current, candidate, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureSelfTest {
    pub corpus_sha256: String,
    pub protocols: Vec<Protocol>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_body_preserves_exact_chunk_boundaries_and_size_hint() {
        let body = BenchBody::from_chunks([Bytes::from_static(b"abc"), Bytes::from_static(b"de")]);
        assert_eq!(body.size_hint().exact(), Some(5));
        assert!(!body.is_end_stream());
    }

    #[test]
    fn response_sanitation_probe_names_reserved_gateway_fields() {
        assert_eq!(SEC_WEBSOCKET_VERSION.as_str(), "sec-websocket-version");
        assert_eq!(SET_COOKIE.as_str(), "set-cookie");
    }
}
