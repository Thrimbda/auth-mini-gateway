//! Persistent H1/H2 load role with exact closed-loop workload validation.

use crate::control::{
    AttemptEvidence, ConnectionLedger, ConnectionPolicy, ControlBody, ControlContext,
    FramedControl, LoadProof, LoadResult, LoadTarget, ProtocolDateObservation, Role,
    RoleErrorClass, RoleErrorCode, RoleErrorStage,
};
use crate::fixture::BenchBody;
use crate::linux::{clock_ns, process_identity, ClockKind};
use crate::schema::Workload;
use crate::session::{USER_EMAIL, USER_ID};
use crate::topology::{
    masked_ping, operation_id, operation_id_text, parse_unmasked_pong, planned_connection_id,
    websocket_accept, Corpus, Protocol, CORPUS_BYTES, SSE_EVENTS,
};
use crate::wire::{H2FrameObserver, H2WireEvidence, ObservedH2Io};
use crate::{Error, Result, ResultContext};
use bytes::Bytes;
use http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, COOKIE, DATE, HOST, ORIGIN, PROXY_AUTHORIZATION,
    SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION, SET_COOKIE, TRANSFER_ENCODING,
    UPGRADE,
};
use http::{HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;

trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> TunnelIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

enum HttpSender {
    H1 {
        sender: http1::SendRequest<BenchBody>,
        connection_id: u64,
    },
    H2 {
        sender: http2::SendRequest<BenchBody>,
        observer: H2FrameObserver,
    },
}

impl HttpSender {
    async fn send(
        &mut self,
        request: Request<BenchBody>,
        extended_connect: bool,
    ) -> Result<(Response<Incoming>, u64, Option<u32>)> {
        match self {
            Self::H1 {
                sender,
                connection_id,
            } => {
                sender.ready().await.context("H1 sender ready")?;
                let response = sender
                    .send_request(request)
                    .await
                    .context("send H1 request")?;
                Ok((response, *connection_id, None))
            }
            Self::H2 { sender, observer } => {
                let request_lock = observer.request_lock();
                let _guard = request_lock.lock().await;
                sender.ready().await.context("H2 sender ready")?;
                if extended_connect {
                    observer.mark_next_headers_as_extended_connect()?;
                }
                let response = sender.send_request(request);
                let stream_id = observer.claim_stream(Duration::from_secs(2)).await?;
                let connection_id = observer.snapshot()?.connection_id;
                drop(_guard);
                Ok((
                    response.await.context("send H2 request")?,
                    connection_id,
                    Some(stream_id),
                ))
            }
        }
    }
}

enum LaneTransport {
    Http(HttpSender),
    FreshH1 {
        endpoint: SocketAddr,
        tracker: Arc<FreshConnectionTracker>,
    },
    WebSocket(Pin<Box<dyn TunnelIo>>),
}

#[derive(Debug, Default)]
struct FreshConnectionTracker {
    active: AtomicU64,
    maximum: AtomicU64,
}

impl FreshConnectionTracker {
    fn reset_phase(&self) -> Result<()> {
        if self.active.load(Ordering::SeqCst) != 0 {
            return Err(Error::new(
                "fresh-H1 phase began with active downstream connections",
            ));
        }
        self.maximum.store(0, Ordering::SeqCst);
        Ok(())
    }

    fn acquire(self: &Arc<Self>) -> FreshConnectionGuard {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        let mut maximum = self.maximum.load(Ordering::SeqCst);
        while active > maximum {
            match self
                .maximum
                .compare_exchange(maximum, active, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(actual) => maximum = actual,
            }
        }
        FreshConnectionGuard {
            tracker: Arc::clone(self),
        }
    }
}

struct FreshConnectionGuard {
    tracker: Arc<FreshConnectionTracker>,
}

impl Drop for FreshConnectionGuard {
    fn drop(&mut self) {
        self.tracker.active.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Lane {
    id: u16,
    target: LoadTarget,
    protocol: Protocol,
    workload: Workload,
    cookie_header: Option<String>,
    authority: String,
    corpus: Arc<Corpus>,
    transport: LaneTransport,
    physical_connection_id: Option<u64>,
    tunnel_stream_id: Option<u32>,
    websocket_masks: VecDeque<PreparedWebSocketFrame>,
    attempts: Arc<OperationAttemptTracker>,
    h2_stream_tracker: Option<Arc<ActiveStreamTracker>>,
    phase_sequences: BTreeMap<u16, u64>,
    observed_protocol: Option<Protocol>,
}

#[derive(Clone, Copy)]
struct PreparedWebSocketFrame {
    phase: u16,
    sequence: u64,
    frame: [u8; 14],
    expected_payload: [u8; 8],
}

struct LoadSession {
    lanes: Vec<Lane>,
    protocol: Protocol,
    workload: Workload,
    physical_connections: u64,
    fresh_tracker: Option<Arc<FreshConnectionTracker>>,
    base_connection_ledger: ConnectionLedger,
    h2_observers: Vec<H2FrameObserver>,
    websocket_open_ledger: Option<ConnectionLedger>,
    attempts: Arc<OperationAttemptTracker>,
    h2_stream_tracker: Option<Arc<ActiveStreamTracker>>,
    drivers: Vec<JoinHandle<()>>,
}

#[derive(Debug)]
struct OperationOutcome {
    operation_id: String,
    request_bytes: u64,
    response_bytes: u64,
    latency_ns: u64,
    start_ns: u64,
    completed_ns: u64,
    status_ok: bool,
    eos_ok: bool,
    payload_ok: bool,
    sse_content_type_ok: bool,
    response_headers_sanitized: bool,
    observed_protocol: Protocol,
    protocol_date: Option<ProtocolDateObservation>,
    connection: OperationConnection,
}

struct ResultWindow {
    start_ns: u64,
    deadline_ns: Option<u64>,
    end_ns: u64,
    retain_latencies: bool,
}

struct LaneResultSummary {
    count: u64,
    quotas: Vec<u64>,
    completions: Vec<u64>,
}

#[derive(Debug, Default)]
struct OperationConnection {
    connection_id: Option<u64>,
    stream_id: Option<u32>,
    planned_id: Option<String>,
    socket_creations: u64,
    connect_attempts: u64,
    connect_successes: u64,
    cumulative_connections: u64,
    requests: u64,
    responses: u64,
    close_tokens: u64,
    keep_alive_tokens: u64,
    response_eos: u64,
    transport_eof: u64,
    h2_streams: u64,
}

#[derive(Debug, Default)]
struct OperationAttemptTracker {
    starts: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    reconnects: AtomicU64,
    retries: AtomicU64,
}

#[derive(Debug, Default)]
struct ActiveStreamTracker {
    active: AtomicU64,
    maximum: AtomicU64,
}

impl ActiveStreamTracker {
    fn reset_phase(&self) -> Result<()> {
        if self.active.load(Ordering::SeqCst) != 0 {
            return Err(Error::new("H2 phase began with active request streams"));
        }
        self.maximum.store(0, Ordering::SeqCst);
        Ok(())
    }

    fn acquire(self: &Arc<Self>) -> ActiveStreamGuard {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        let mut maximum = self.maximum.load(Ordering::SeqCst);
        while active > maximum {
            match self
                .maximum
                .compare_exchange(maximum, active, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(actual) => maximum = actual,
            }
        }
        ActiveStreamGuard {
            tracker: Arc::clone(self),
        }
    }
}

struct ActiveStreamGuard {
    tracker: Arc<ActiveStreamTracker>,
}

impl Drop for ActiveStreamGuard {
    fn drop(&mut self) {
        self.tracker.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl OperationAttemptTracker {
    fn begin(self: &Arc<Self>) -> OperationAttemptGuard {
        self.starts.fetch_add(1, Ordering::SeqCst);
        OperationAttemptGuard {
            tracker: Arc::clone(self),
            completed: false,
        }
    }

    fn snapshot(&self) -> AttemptEvidence {
        AttemptEvidence {
            starts: self.starts.load(Ordering::SeqCst),
            successes: self.successes.load(Ordering::SeqCst),
            failures: self.failures.load(Ordering::SeqCst),
            reconnects: self.reconnects.load(Ordering::SeqCst),
            retries: self.retries.load(Ordering::SeqCst),
        }
    }
}

struct OperationAttemptGuard {
    tracker: Arc<OperationAttemptTracker>,
    completed: bool,
}

impl OperationAttemptGuard {
    fn success(mut self) {
        self.tracker.successes.fetch_add(1, Ordering::SeqCst);
        self.completed = true;
    }
}

impl Drop for OperationAttemptGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.tracker.failures.fetch_add(1, Ordering::SeqCst);
        }
    }
}

pub async fn run_load_role(context: ControlContext, control: &mut FramedControl) -> Result<()> {
    control
        .authenticate_inherited_role(Role::Load, process_identity(std::process::id())?)
        .await?;
    control.mark_failure_stage(RoleErrorStage::Startup);
    control
        .send(ControlBody::Ready {
            role: Role::Load,
            data_address: None,
            tripwire_address: None,
        })
        .await?;
    let mut session: Option<LoadSession> = None;
    loop {
        match control.receive().await? {
            ControlBody::PrepareLoad {
                target,
                workload,
                protocol,
                gateway_address,
                fixture_address,
                cookie_header,
                warmup_operations,
                websocket_settle: _,
            } => {
                control.mark_failure_stage(RoleErrorStage::Prepare);
                if session.is_some() || workload != context.cell.workload {
                    return Err(Error::new("load session duplicate or cell mismatch"));
                }
                let endpoint = match target {
                    LoadTarget::Gateway => gateway_address
                        .as_deref()
                        .ok_or_else(|| Error::new("gateway load target has no gateway address")),
                    LoadTarget::Direct => Ok(fixture_address.as_str()),
                }
                .and_then(crate::control::parse_loopback_address);
                let endpoint = match endpoint {
                    Ok(value) => value,
                    Err(error) => {
                        send_load_terminal(
                            control,
                            RoleErrorStage::Prepare,
                            RoleErrorCode::InvalidConfiguration,
                            &error,
                            None,
                        )
                        .await?;
                        return Err(error);
                    }
                };
                let prepared = LoadSession::connect(
                    target,
                    protocol,
                    workload,
                    endpoint,
                    cookie_header,
                    context.cell.concurrency,
                )
                .await;
                let mut prepared = match prepared {
                    Ok(value) => value,
                    Err(error) => {
                        send_load_terminal(
                            control,
                            RoleErrorStage::Prepare,
                            RoleErrorCode::PrepareFailed,
                            &error,
                            None,
                        )
                        .await?;
                        return Err(error);
                    }
                };
                control.mark_failure_stage(RoleErrorStage::Proof);
                match prepared.prepare(warmup_operations).await {
                    Ok(proof) => {
                        session = Some(prepared);
                        control.send(ControlBody::Prepared { proof }).await?;
                    }
                    Err(error) => {
                        send_load_terminal(
                            control,
                            RoleErrorStage::Proof,
                            RoleErrorCode::PrepareFailed,
                            &error,
                            Some(prepared.attempts.snapshot()),
                        )
                        .await?;
                        return Err(error);
                    }
                }
            }
            ControlBody::Measure { phase, operations } => {
                control.mark_failure_stage(RoleErrorStage::Measure);
                let prepared = session
                    .as_mut()
                    .ok_or_else(|| Error::new("load Measure before Prepare"))?;
                match prepared.run_batch(phase, operations).await {
                    Ok(result) => control.send(ControlBody::Measured { result }).await?,
                    Err(error) => {
                        send_load_terminal(
                            control,
                            RoleErrorStage::Measure,
                            RoleErrorCode::MeasureFailed,
                            &error,
                            Some(prepared.attempts.snapshot()),
                        )
                        .await?;
                        return Err(error);
                    }
                }
            }
            ControlBody::PrepareOperationCorpus {
                phase,
                operation_ceiling,
            } => {
                control.mark_failure_stage(RoleErrorStage::Prepare);
                let prepared = session
                    .as_mut()
                    .ok_or_else(|| Error::new("load corpus preparation before Prepare"))?;
                if let Err(error) = prepared.prepare_operation_corpus(phase, operation_ceiling) {
                    send_load_terminal(
                        control,
                        RoleErrorStage::Prepare,
                        RoleErrorCode::PrepareFailed,
                        &error,
                        Some(prepared.attempts.snapshot()),
                    )
                    .await?;
                    return Err(error);
                }
                control
                    .send(ControlBody::OperationCorpusPrepared {
                        phase,
                        operation_ceiling,
                    })
                    .await?;
            }
            ControlBody::MeasureCount {
                phase,
                operations,
                retain_latencies,
            } => {
                control.mark_failure_stage(RoleErrorStage::Measure);
                let prepared = session
                    .as_mut()
                    .ok_or_else(|| Error::new("load MeasureCount before Prepare"))?;
                match prepared
                    .run_batch_with_latencies(phase, operations, retain_latencies)
                    .await
                {
                    Ok(result) => control.send(ControlBody::Measured { result }).await?,
                    Err(error) => {
                        send_load_terminal(
                            control,
                            RoleErrorStage::Measure,
                            RoleErrorCode::MeasureFailed,
                            &error,
                            Some(prepared.attempts.snapshot()),
                        )
                        .await?;
                        return Err(error);
                    }
                }
            }
            ControlBody::MeasureDuration {
                phase,
                duration_ns,
                retain_latencies,
            } => {
                control.mark_failure_stage(RoleErrorStage::Measure);
                let prepared = session
                    .as_mut()
                    .ok_or_else(|| Error::new("load MeasureDuration before Prepare"))?;
                match prepared
                    .run_duration(phase, duration_ns, retain_latencies)
                    .await
                {
                    Ok(result) => control.send(ControlBody::Measured { result }).await?,
                    Err(error) => {
                        send_load_terminal(
                            control,
                            RoleErrorStage::Measure,
                            RoleErrorCode::MeasureFailed,
                            &error,
                            Some(prepared.attempts.snapshot()),
                        )
                        .await?;
                        return Err(error);
                    }
                }
            }
            ControlBody::MaterializeDuration { phase, duration_ns } => {
                control.mark_failure_stage(RoleErrorStage::Materialize);
                let prepared = session
                    .as_mut()
                    .ok_or_else(|| Error::new("load MaterializeDuration before Prepare"))?;
                match prepared
                    .run_duration_with_bounds(
                        phase,
                        duration_ns,
                        false,
                        3_000_000_000,
                        10_000_000_000,
                    )
                    .await
                {
                    Ok(result) => control.send(ControlBody::Measured { result }).await?,
                    Err(error) => {
                        send_load_terminal(
                            control,
                            RoleErrorStage::Materialize,
                            RoleErrorCode::MaterializeFailed,
                            &error,
                            Some(prepared.attempts.snapshot()),
                        )
                        .await?;
                        return Err(error);
                    }
                }
            }
            ControlBody::MaterializeWave { phase, operations } => {
                control.mark_failure_stage(RoleErrorStage::Materialize);
                let prepared = session
                    .as_mut()
                    .ok_or_else(|| Error::new("load MaterializeWave before Prepare"))?;
                match prepared.run_materialization_wave(phase, operations).await {
                    Ok(result) => control.send(ControlBody::Measured { result }).await?,
                    Err(error) => {
                        send_load_terminal(
                            control,
                            RoleErrorStage::Materialize,
                            RoleErrorCode::MaterializeFailed,
                            &error,
                            Some(prepared.attempts.snapshot()),
                        )
                        .await?;
                        return Err(error);
                    }
                }
            }
            ControlBody::Stop => {
                control.mark_failure_stage(RoleErrorStage::Exit);
                drop(session.take());
                control
                    .send(ControlBody::Stopped { role: Role::Load })
                    .await?;
                return Ok(());
            }
            other => {
                return Err(Error::new(format!(
                    "load received unexpected control message: {other:?}"
                ))
                .with_role_diagnostic(control.failure_stage(), RoleErrorCode::ControlProtocol))
            }
        }
    }
}

async fn send_load_terminal(
    control: &mut FramedControl,
    stage: RoleErrorStage,
    fallback_code: RoleErrorCode,
    error: &Error,
    attempt: Option<AttemptEvidence>,
) -> Result<()> {
    let diagnostic = error.role_diagnostic();
    control
        .send_terminal_error(
            RoleErrorClass::Command,
            diagnostic.map_or(stage, |value| value.stage),
            diagnostic.map_or_else(
                || error.role_code().unwrap_or(fallback_code),
                |value| value.code,
            ),
            &error.to_string(),
            attempt,
        )
        .await
}

impl LoadSession {
    fn prepare_operation_corpus(&mut self, phase: u16, operations: u64) -> Result<()> {
        if operations == 0 {
            return Err(Error::new("operation corpus ceiling must be nonzero"));
        }
        let lane_count =
            u64::try_from(self.lanes.len()).map_err(|_| Error::new("lane count overflow"))?;
        for lane in &mut self.lanes {
            let lane_index = u64::from(lane.id);
            let quota = operations / lane_count + u64::from(lane_index < operations % lane_count);
            lane.precompute_websocket_masks(phase, quota)?;
        }
        Ok(())
    }

    async fn connect(
        target: LoadTarget,
        protocol: Protocol,
        workload: Workload,
        endpoint: SocketAddr,
        cookie_header: Option<String>,
        concurrency: u16,
    ) -> Result<Self> {
        if concurrency == 0 || concurrency > 64 {
            return Err(Error::new("load concurrency must be 1..=64"));
        }
        let mut lanes = Vec::with_capacity(usize::from(concurrency));
        let mut drivers = Vec::new();
        let mut base_connection_ledger = empty_connection_ledger(protocol, workload);
        let mut h2_observers = Vec::new();
        let attempts = Arc::new(OperationAttemptTracker::default());
        let h2_stream_tracker = (protocol == Protocol::H2 && workload != Workload::WebSocket)
            .then(|| Arc::new(ActiveStreamTracker::default()));
        let fresh_tracker = (protocol == Protocol::H1 && workload == Workload::Upload1Mib)
            .then(|| Arc::new(FreshConnectionTracker::default()));
        let authority = "public.example".to_owned();
        // Corpus hashing/materialization is deliberately complete before the
        // first data connection or operation timestamp.
        let corpus = Arc::new(Corpus::fixed());
        match protocol {
            Protocol::H1 => {
                for lane in 0..concurrency {
                    let transport = if let Some(tracker) = &fresh_tracker {
                        LaneTransport::FreshH1 {
                            endpoint,
                            tracker: Arc::clone(tracker),
                        }
                    } else {
                        let connection_id = u64::from(lane) + 1;
                        record_connection_start(&mut base_connection_ledger, connection_id)?;
                        let (sender, driver) = open_h1(endpoint, connection_id).await?;
                        drivers.push(driver);
                        record_connection_success(&mut base_connection_ledger, connection_id)?;
                        LaneTransport::Http(sender)
                    };
                    lanes.push(Lane {
                        id: lane,
                        target,
                        protocol,
                        workload,
                        cookie_header: cookie_header.clone(),
                        authority: authority.clone(),
                        corpus: Arc::clone(&corpus),
                        transport,
                        physical_connection_id: (fresh_tracker.is_none())
                            .then_some(u64::from(lane) + 1),
                        tunnel_stream_id: None,
                        websocket_masks: VecDeque::new(),
                        attempts: Arc::clone(&attempts),
                        h2_stream_tracker: h2_stream_tracker.clone(),
                        phase_sequences: BTreeMap::new(),
                        observed_protocol: None,
                    });
                }
            }
            Protocol::H2 => {
                record_connection_start(&mut base_connection_ledger, 1)?;
                let (sender, driver, observer) =
                    open_h2(endpoint, 1, workload == Workload::WebSocket).await?;
                drivers.push(driver);
                record_connection_success(&mut base_connection_ledger, 1)?;
                h2_observers.push(observer.clone());
                for lane in 0..concurrency {
                    lanes.push(Lane {
                        id: lane,
                        target,
                        protocol,
                        workload,
                        cookie_header: cookie_header.clone(),
                        authority: authority.clone(),
                        corpus: Arc::clone(&corpus),
                        transport: LaneTransport::Http(HttpSender::H2 {
                            sender: sender.clone(),
                            observer: observer.clone(),
                        }),
                        physical_connection_id: Some(1),
                        tunnel_stream_id: None,
                        websocket_masks: VecDeque::new(),
                        attempts: Arc::clone(&attempts),
                        h2_stream_tracker: h2_stream_tracker.clone(),
                        phase_sequences: BTreeMap::new(),
                        observed_protocol: None,
                    });
                }
            }
        }
        Ok(Self {
            lanes,
            protocol,
            workload,
            physical_connections: if protocol == Protocol::H1 {
                if workload == Workload::Upload1Mib {
                    0
                } else {
                    u64::from(concurrency)
                }
            } else {
                1
            },
            fresh_tracker,
            base_connection_ledger,
            h2_observers,
            websocket_open_ledger: None,
            attempts,
            h2_stream_tracker,
            drivers,
        })
    }

    async fn prepare(&mut self, warmup_operations: u64) -> Result<LoadProof> {
        if self.workload == Workload::WebSocket {
            let (
                open_ledger,
                first_operation_id,
                last_operation_id,
                operation_hash_sha256,
                attempts,
                protocol_dates,
            ) = self.open_all_websockets().await?;
            self.websocket_open_ledger = Some(open_ledger.clone());
            let h2_wire = self.h2_wire_evidence()?;
            return Ok(LoadProof {
                downstream_protocol: self.protocol,
                observed_protocol: self
                    .lanes
                    .iter()
                    .map(|lane| lane.observed_protocol)
                    .reduce(|left, right| (left == right).then_some(left).flatten())
                    .flatten(),
                physical_connections: self.physical_connections,
                h2_settings_proved: self.protocol == Protocol::H1
                    || h2_wire.iter().all(initial_h2_exchange_proved),
                extended_connect_proved: self.protocol == Protocol::H1
                    || h2_wire.iter().all(|wire| {
                        wire.enable_connect_protocol_seen
                            && wire.extended_connect_headers > 0
                            && wire.early_extended_connect_headers == 0
                    }),
                warmup_operations: 0,
                warmup_end_ns: clock_ns(ClockKind::Monotonic)?,
                tunnels: self.lanes.len() as u64,
                first_operation_id,
                last_operation_id,
                operation_hash_sha256,
                request_bytes: 0,
                response_bytes: 0,
                connection_ledger: open_ledger,
                h2_wire,
                attempts,
                lane_quotas: vec![1; self.lanes.len()],
                lane_completions: vec![1; self.lanes.len()],
                response_headers_sanitized: true,
                protocol_dates,
            });
        }
        if warmup_operations == 0 {
            return Err(Error::new("protocol proof requires at least one operation"));
        }
        let count = warmup_operations;
        let result = self.run_batch(1, count).await?;
        Ok(LoadProof {
            downstream_protocol: self.protocol,
            observed_protocol: result.observed_protocol,
            physical_connections: if self.fresh_tracker.is_some() {
                result.connection_ledger.cumulative_connections
            } else {
                self.physical_connections
            },
            h2_settings_proved: self.protocol == Protocol::H1
                || self
                    .h2_wire_evidence()?
                    .iter()
                    .all(initial_h2_exchange_proved),
            extended_connect_proved: false,
            warmup_operations: result.operations_completed,
            warmup_end_ns: result.window_end_ns,
            tunnels: 0,
            first_operation_id: result.first_operation_id,
            last_operation_id: result.last_operation_id,
            operation_hash_sha256: result.operation_hash_sha256,
            request_bytes: result.request_bytes,
            response_bytes: result.response_bytes,
            connection_ledger: result.connection_ledger,
            h2_wire: result.h2_wire,
            attempts: result.attempts,
            lane_quotas: result.lane_quotas,
            lane_completions: result.lane_completions,
            response_headers_sanitized: result.response_headers_sanitized,
            protocol_dates: result.protocol_dates,
        })
    }

    async fn open_all_websockets(
        &mut self,
    ) -> Result<(
        ConnectionLedger,
        String,
        String,
        String,
        AttemptEvidence,
        Vec<ProtocolDateObservation>,
    )> {
        let attempts_before = self.attempts.snapshot();
        let lanes = std::mem::take(&mut self.lanes);
        let mut lanes = lanes.into_iter();
        let first_lane = lanes
            .next()
            .ok_or_else(|| Error::new("WebSocket tunnel lane inventory is empty"))?;
        let (first_lane, first_outcome) = open_websocket(first_lane).await?;
        let mut tasks = Vec::with_capacity(lanes.len());
        for lane in lanes {
            tasks.push(tokio::spawn(async move { open_websocket(lane).await }));
        }
        let mut restored = Vec::with_capacity(tasks.len() + 1);
        let mut outcomes = Vec::with_capacity(tasks.len() + 1);
        restored.push(first_lane);
        outcomes.push(first_outcome);
        for task in tasks {
            let (lane, outcome) = task.await.context("join WebSocket handshake lane")??;
            restored.push(lane);
            outcomes.push(outcome);
        }
        let attempts = reconcile_attempt_delta(
            attempts_before,
            self.attempts.snapshot(),
            u64::try_from(outcomes.len()).map_err(|_| Error::new("tunnel count overflow"))?,
        )?;
        restored.sort_by_key(|lane| lane.id);
        outcomes.sort_by(|left, right| {
            left.operation_id
                .as_bytes()
                .cmp(right.operation_id.as_bytes())
        });
        self.lanes = restored;
        let mut ledger = self.base_connection_ledger.clone();
        let mut hasher = Sha256::new();
        let mut per_connection = BTreeMap::<u64, u64>::new();
        for outcome in &outcomes {
            let connection_id = outcome
                .connection
                .connection_id
                .ok_or_else(|| Error::new("tunnel handshake lacks physical connection ID"))?;
            let count = per_connection.entry(connection_id).or_insert(0);
            *count = count
                .checked_add(outcome.connection.requests)
                .ok_or_else(|| Error::new("tunnel requests-per-connection overflow"))?;
            add_connection_outcome(&mut ledger, &mut hasher, outcome)?;
        }
        if self.protocol == Protocol::H2 {
            set_h2_stream_identity(&mut ledger, &outcomes)?;
        }
        ledger.max_requests_per_connection = per_connection.values().copied().max().unwrap_or(0);
        ledger.operation_connection_hash_sha256 = format!("{:x}", hasher.finalize());
        if self.protocol == Protocol::H2 {
            ledger.active_h2_streams = u64::try_from(outcomes.len())
                .map_err(|_| Error::new("tunnel stream count overflow"))?;
            ledger.max_active_h2_streams = ledger.active_h2_streams;
        }
        validate_connection_ledger(
            &ledger,
            u64::try_from(outcomes.len()).map_err(|_| Error::new("tunnel count overflow"))?,
            u64::try_from(self.lanes.len()).map_err(|_| Error::new("lane count overflow"))?,
        )?;
        let first = outcomes
            .first()
            .ok_or_else(|| Error::new("WebSocket tunnel outcome inventory is empty"))?
            .operation_id
            .clone();
        let last = outcomes
            .last()
            .ok_or_else(|| Error::new("WebSocket tunnel outcome inventory is empty"))?
            .operation_id
            .clone();
        let mut operation_hasher = Sha256::new();
        for outcome in &outcomes {
            operation_hasher.update(outcome.operation_id.as_bytes());
            operation_hasher.update(outcome.request_bytes.to_be_bytes());
            operation_hasher.update(outcome.response_bytes.to_be_bytes());
        }
        let protocol_dates = bounded_protocol_dates(&outcomes);
        Ok((
            ledger,
            first,
            last,
            format!("{:x}", operation_hasher.finalize()),
            attempts,
            protocol_dates,
        ))
    }

    fn h2_wire_evidence(&self) -> Result<Vec<H2WireEvidence>> {
        let mut evidence = self
            .h2_observers
            .iter()
            .map(H2FrameObserver::snapshot)
            .collect::<Result<Vec<_>>>()?;
        evidence.sort_by_key(|wire| wire.connection_id);
        Ok(evidence)
    }

    async fn run_batch(&mut self, phase: u16, operations: u64) -> Result<LoadResult> {
        self.run_batch_with_latencies(phase, operations, true).await
    }

    async fn run_materialization_wave(
        &mut self,
        phase: u16,
        operations: u64,
    ) -> Result<LoadResult> {
        let lanes =
            u64::try_from(self.lanes.len()).map_err(|_| Error::new("lane count overflow"))?;
        if operations != lanes {
            return Err(Error::new(
                "materialization wave must issue exactly one operation per lane",
            ));
        }
        self.run_batch_with_latencies(phase, operations, false)
            .await
    }

    async fn run_batch_with_latencies(
        &mut self,
        phase: u16,
        operations: u64,
        retain_latencies: bool,
    ) -> Result<LoadResult> {
        if operations == 0 {
            return Err(Error::new("load batch must contain at least one operation"));
        }
        let lane_count =
            u64::try_from(self.lanes.len()).map_err(|_| Error::new("lane count overflow"))?;
        if let Some(tracker) = &self.fresh_tracker {
            tracker.reset_phase()?;
        }
        if let Some(tracker) = &self.h2_stream_tracker {
            tracker.reset_phase()?;
        }
        let attempts_before = self.attempts.snapshot();
        let lanes = std::mem::take(&mut self.lanes);
        let lane_quotas = lanes
            .iter()
            .map(|lane| {
                let lane_index = u64::from(lane.id);
                operations / lane_count + u64::from(lane_index < operations % lane_count)
            })
            .collect::<Vec<_>>();
        validate_precomputed_websocket_masks(&lanes, phase, &lane_quotas)?;
        let mut tasks = Vec::with_capacity(lanes.len());
        let barrier = Arc::new(tokio::sync::Barrier::new(lanes.len() + 1));
        for lane in lanes {
            let lane_index = u64::from(lane.id);
            let quota = operations / lane_count + u64::from(lane_index < operations % lane_count);
            let task_barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                let mut lane = lane;
                let mut outcomes = Vec::with_capacity(quota as usize);
                task_barrier.wait().await;
                for _ in 0..quota {
                    outcomes.push(lane.run_operation(phase).await?);
                }
                Ok::<_, Error>((lane, outcomes))
            }));
        }
        let window_start_ns = clock_ns(ClockKind::Monotonic)?;
        barrier.wait().await;
        let mut restored = Vec::with_capacity(tasks.len());
        let mut outcomes = Vec::new();
        let mut lane_completions = vec![0_u64; usize::try_from(lane_count).unwrap_or(0)];
        for task in tasks {
            let (lane, mut lane_outcomes) = task.await.context("join load lane")??;
            let lane_index = usize::from(lane.id);
            lane_completions[lane_index] = u64::try_from(lane_outcomes.len())
                .map_err(|_| Error::new("lane completion count overflow"))?;
            restored.push(lane);
            outcomes.append(&mut lane_outcomes);
        }
        let window_end_ns = clock_ns(ClockKind::Monotonic)?;
        restored.sort_by_key(|lane| lane.id);
        self.lanes = restored;
        if outcomes.len() as u64 != operations {
            return Err(Error::new("load batch quota/completion mismatch"));
        }
        let attempts =
            reconcile_attempt_delta(attempts_before, self.attempts.snapshot(), operations)?;
        self.finish_result(
            outcomes,
            ResultWindow {
                start_ns: window_start_ns,
                deadline_ns: None,
                end_ns: window_end_ns,
                retain_latencies,
            },
            attempts,
            LaneResultSummary {
                count: lane_count,
                quotas: lane_quotas,
                completions: lane_completions,
            },
        )
    }

    async fn run_duration(
        &mut self,
        phase: u16,
        duration_ns: u64,
        retain_latencies: bool,
    ) -> Result<LoadResult> {
        self.run_duration_with_bounds(
            phase,
            duration_ns,
            retain_latencies,
            5_000_000_000,
            30_000_000_000,
        )
        .await
    }

    async fn run_duration_with_bounds(
        &mut self,
        phase: u16,
        duration_ns: u64,
        retain_latencies: bool,
        minimum_ns: u64,
        maximum_ns: u64,
    ) -> Result<LoadResult> {
        if !(minimum_ns..=maximum_ns).contains(&duration_ns) {
            return Err(Error::new(
                "fixed operation duration is outside its sealed bounds",
            ));
        }
        let lane_count =
            u64::try_from(self.lanes.len()).map_err(|_| Error::new("lane count overflow"))?;
        if let Some(tracker) = &self.fresh_tracker {
            tracker.reset_phase()?;
        }
        if let Some(tracker) = &self.h2_stream_tracker {
            tracker.reset_phase()?;
        }
        let attempts_before = self.attempts.snapshot();
        let lanes = std::mem::take(&mut self.lanes);
        // This is a writer/precomputation ceiling, never an operation quota.
        // Reaching it before the frozen deadline is a terminal BLOCKED error;
        // the load path never drops a started operation or computes a mask in
        // the timed region.
        const MAX_DURATION_OPERATIONS: u64 = 2_000_000;
        let mask_quotas = lanes
            .iter()
            .map(|lane| {
                let lane_index = u64::from(lane.id);
                MAX_DURATION_OPERATIONS / lane_count
                    + u64::from(lane_index < MAX_DURATION_OPERATIONS % lane_count)
            })
            .collect::<Vec<_>>();
        validate_precomputed_websocket_masks(&lanes, phase, &mask_quotas)?;
        let barrier = Arc::new(tokio::sync::Barrier::new(lanes.len() + 1));
        let shared_deadline = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::with_capacity(lanes.len());
        for lane in lanes {
            let task_barrier = Arc::clone(&barrier);
            let task_deadline = Arc::clone(&shared_deadline);
            tasks.push(tokio::spawn(async move {
                let mut lane = lane;
                let mut outcomes = Vec::new();
                task_barrier.wait().await;
                let window_deadline_ns = task_deadline.load(Ordering::SeqCst);
                while let Some(outcome) =
                    lane.run_operation_before(phase, window_deadline_ns).await?
                {
                    outcomes.push(outcome);
                }
                lane.discard_websocket_masks(phase)?;
                Ok::<_, Error>((lane, outcomes))
            }));
        }
        let window_start_ns = clock_ns(ClockKind::Monotonic)?;
        let window_deadline_ns = window_start_ns
            .checked_add(duration_ns)
            .ok_or_else(|| Error::new("fixed measurement deadline overflow"))?;
        shared_deadline.store(window_deadline_ns, Ordering::SeqCst);
        barrier.wait().await;
        let mut restored = Vec::with_capacity(tasks.len());
        let mut outcomes = Vec::new();
        let mut lane_completions = vec![0_u64; usize::try_from(lane_count).unwrap_or(0)];
        for task in tasks {
            let (lane, mut lane_outcomes) = task.await.context("join fixed-window load lane")??;
            let lane_index = usize::from(lane.id);
            lane_completions[lane_index] = u64::try_from(lane_outcomes.len())
                .map_err(|_| Error::new("lane completion count overflow"))?;
            restored.push(lane);
            outcomes.append(&mut lane_outcomes);
        }
        let window_end_ns = clock_ns(ClockKind::Monotonic)?;
        restored.sort_by_key(|lane| lane.id);
        self.lanes = restored;
        if outcomes.is_empty() {
            return Err(Error::new("fixed measurement completed zero operations"));
        }
        let attempts = reconcile_attempt_delta(
            attempts_before,
            self.attempts.snapshot(),
            outcomes.len() as u64,
        )?;
        let lane_quotas = lane_completions.clone();
        self.finish_result(
            outcomes,
            ResultWindow {
                start_ns: window_start_ns,
                deadline_ns: Some(window_deadline_ns),
                end_ns: window_end_ns,
                retain_latencies,
            },
            attempts,
            LaneResultSummary {
                count: lane_count,
                quotas: lane_quotas,
                completions: lane_completions,
            },
        )
    }

    fn finish_result(
        &self,
        mut outcomes: Vec<OperationOutcome>,
        window: ResultWindow,
        attempts: AttemptEvidence,
        lanes: LaneResultSummary,
    ) -> Result<LoadResult> {
        let ResultWindow {
            start_ns: window_start_ns,
            deadline_ns: window_deadline_ns,
            end_ns: window_end_ns,
            retain_latencies,
        } = window;
        if window_deadline_ns
            .is_some_and(|deadline| outcomes.iter().any(|outcome| outcome.start_ns >= deadline))
        {
            return Err(Error::new(
                "fixed-window operation started at or after its common deadline",
            ));
        }
        let LaneResultSummary {
            count: lane_count,
            quotas: lane_quotas,
            completions: lane_completions,
        } = lanes;
        outcomes.sort_by(|left, right| {
            left.operation_id
                .as_bytes()
                .cmp(right.operation_id.as_bytes())
        });
        let operations = outcomes.len() as u64;
        let mut hasher = Sha256::new();
        let mut request_bytes = 0_u64;
        let mut response_bytes = 0_u64;
        let mut latencies = Vec::with_capacity(outcomes.len());
        let mut connection_hasher = Sha256::new();
        let mut requests_per_connection = BTreeMap::<String, u64>::new();
        let mut ledger = if self.fresh_tracker.is_some() {
            empty_connection_ledger(self.protocol, self.workload)
        } else if self.workload == Workload::WebSocket {
            let mut base = self
                .websocket_open_ledger
                .clone()
                .ok_or_else(|| Error::new("WebSocket phase has no observed tunnel ledger"))?;
            base.requests = 0;
            base.responses = 0;
            base.response_eos = 0;
            base.operation_connection_hash_sha256.clear();
            base
        } else {
            self.base_connection_ledger.clone()
        };
        for outcome in &outcomes {
            hasher.update(outcome.operation_id.as_bytes());
            hasher.update(outcome.request_bytes.to_be_bytes());
            hasher.update(outcome.response_bytes.to_be_bytes());
            request_bytes = request_bytes
                .checked_add(outcome.request_bytes)
                .ok_or_else(|| Error::new("load request-byte overflow"))?;
            response_bytes = response_bytes
                .checked_add(outcome.response_bytes)
                .ok_or_else(|| Error::new("load response-byte overflow"))?;
            if retain_latencies {
                latencies.push(outcome.latency_ns);
            }
            let connection_key = outcome
                .connection
                .planned_id
                .clone()
                .or_else(|| {
                    outcome
                        .connection
                        .connection_id
                        .map(|value| format!("physical-{value}"))
                })
                .ok_or_else(|| Error::new("operation has no actual/planned connection identity"))?;
            let requests = requests_per_connection.entry(connection_key).or_insert(0);
            *requests = requests
                .checked_add(outcome.connection.requests)
                .ok_or_else(|| Error::new("requests-per-connection overflow"))?;
            add_connection_outcome(&mut ledger, &mut connection_hasher, outcome)?;
        }
        if self.protocol == Protocol::H2 && self.workload != Workload::WebSocket {
            set_h2_stream_identity(&mut ledger, &outcomes)?;
            let tracker = self
                .h2_stream_tracker
                .as_ref()
                .ok_or_else(|| Error::new("persistent H2 arm lacks active-stream tracker"))?;
            ledger.active_h2_streams = tracker.active.load(Ordering::SeqCst);
            ledger.max_active_h2_streams = tracker.maximum.load(Ordering::SeqCst);
        }
        ledger.max_requests_per_connection =
            requests_per_connection.values().copied().max().unwrap_or(0);
        if let Some(tracker) = &self.fresh_tracker {
            ledger.active_connections = tracker.active.load(Ordering::SeqCst);
            ledger.max_active_connections = tracker.maximum.load(Ordering::SeqCst);
            if ledger.active_connections != 0 {
                return Err(Error::new(
                    "fresh-H1 batch ended with active downstream connections",
                ));
            }
        }
        ledger.operation_connection_hash_sha256 = format!("{:x}", connection_hasher.finalize());
        validate_connection_ledger(&ledger, operations, lane_count)?;
        let observed_retries = ledger.retry_attempts;
        let operations_completed_by_deadline = window_deadline_ns.map_or(operations, |deadline| {
            outcomes
                .iter()
                .filter(|outcome| outcome.completed_ns <= deadline)
                .count() as u64
        });
        let first = outcomes
            .first()
            .ok_or_else(|| Error::new("empty outcomes"))?;
        let last = outcomes
            .last()
            .ok_or_else(|| Error::new("empty outcomes"))?;
        let observed_protocol = outcomes
            .iter()
            .map(|outcome| outcome.observed_protocol)
            .reduce(|left, right| if left == right { left } else { self.protocol });
        if observed_protocol != Some(outcomes[0].observed_protocol)
            || outcomes
                .iter()
                .any(|outcome| outcome.observed_protocol != outcomes[0].observed_protocol)
        {
            return Err(Error::new("load operations observed mixed HTTP protocols"));
        }
        let protocol_dates = bounded_protocol_dates(&outcomes);
        Ok(LoadResult {
            protocol: self.protocol,
            observed_protocol,
            operations_started: operations,
            operations_completed: operations,
            operations_completed_by_deadline,
            window_start_ns,
            window_deadline_ns,
            window_end_ns,
            request_bytes,
            response_bytes,
            first_operation_id: first.operation_id.clone(),
            last_operation_id: last.operation_id.clone(),
            operation_hash_sha256: format!("{:x}", hasher.finalize()),
            status_ok: outcomes.iter().all(|outcome| outcome.status_ok),
            eos_ok: outcomes.iter().all(|outcome| outcome.eos_ok),
            payload_ok: outcomes.iter().all(|outcome| outcome.payload_ok),
            sse_content_type_ok: outcomes.iter().all(|outcome| outcome.sse_content_type_ok),
            response_headers_sanitized: outcomes
                .iter()
                .all(|outcome| outcome.response_headers_sanitized),
            retries: observed_retries,
            latencies_ns: latencies,
            connection_ledger: ledger,
            h2_wire: self.h2_wire_evidence()?,
            attempts,
            lane_quotas,
            lane_completions,
            protocol_dates,
        })
    }
}

fn bounded_protocol_dates(outcomes: &[OperationOutcome]) -> Vec<ProtocolDateObservation> {
    let mut observed = outcomes
        .iter()
        .filter_map(|outcome| outcome.protocol_date.as_ref());
    let Some(first) = observed.next() else {
        return Vec::new();
    };
    let last = observed.next_back();
    let mut retained = vec![first.clone()];
    if let Some(last) = last {
        retained.push(last.clone());
    }
    retained
}

fn connection_policy(protocol: Protocol, workload: Workload) -> ConnectionPolicy {
    match (protocol, workload) {
        (Protocol::H1, Workload::Upload1Mib) => ConnectionPolicy::FreshH1PerOperation,
        (Protocol::H1, Workload::WebSocket) => ConnectionPolicy::H1UpgradeTunnels,
        (Protocol::H1, _) => ConnectionPolicy::PersistentH1,
        (Protocol::H2, Workload::WebSocket) => ConnectionPolicy::H2ExtendedConnectStreams,
        (Protocol::H2, _) => ConnectionPolicy::PersistentH2,
    }
}

fn empty_connection_ledger(protocol: Protocol, workload: Workload) -> ConnectionLedger {
    ConnectionLedger {
        policy: connection_policy(protocol, workload),
        planned_connections: 0,
        socket_creations: 0,
        connect_attempts: 0,
        connect_successes: 0,
        failed_connect_attempts: 0,
        cumulative_connections: 0,
        requests: 0,
        responses: 0,
        close_tokens: 0,
        keep_alive_tokens: 0,
        response_eos: 0,
        transport_eof: 0,
        active_connections: 0,
        max_active_connections: 0,
        max_requests_per_connection: 0,
        h2_streams: 0,
        active_h2_streams: 0,
        max_active_h2_streams: 0,
        first_h2_stream_id: None,
        last_h2_stream_id: None,
        h2_stream_sequence_sha256: crate::wire::request_stream_sequence_sha256(0)
            .expect("empty H2 stream sequence is infallible"),
        reuse_attempts: 0,
        reconnect_attempts: 0,
        retry_attempts: 0,
        operation_connection_hash_sha256: String::new(),
    }
}

fn record_connection_start(ledger: &mut ConnectionLedger, connection_id: u64) -> Result<()> {
    if connection_id == 0 {
        return Err(Error::new("physical connection ID must be nonzero"));
    }
    for field in [
        &mut ledger.planned_connections,
        &mut ledger.socket_creations,
        &mut ledger.connect_attempts,
        &mut ledger.active_connections,
    ] {
        *field = field
            .checked_add(1)
            .ok_or_else(|| Error::new("physical connection ledger overflow"))?;
    }
    ledger.max_active_connections = ledger.max_active_connections.max(ledger.active_connections);
    Ok(())
}

fn record_connection_success(ledger: &mut ConnectionLedger, connection_id: u64) -> Result<()> {
    if connection_id == 0 || ledger.connect_successes >= ledger.connect_attempts {
        return Err(Error::new(
            "physical connection success has no prior attempt",
        ));
    }
    ledger.connect_successes = ledger
        .connect_successes
        .checked_add(1)
        .ok_or_else(|| Error::new("connect-success ledger overflow"))?;
    ledger.cumulative_connections = ledger
        .cumulative_connections
        .checked_add(1)
        .ok_or_else(|| Error::new("cumulative-connection ledger overflow"))?;
    Ok(())
}

fn initial_h2_exchange_proved(wire: &H2WireEvidence) -> bool {
    wire.validate(false).is_ok()
}

fn reconcile_attempt_delta(
    before: AttemptEvidence,
    after: AttemptEvidence,
    expected: u64,
) -> Result<AttemptEvidence> {
    let delta = |end: u64, start: u64, name: &str| {
        end.checked_sub(start)
            .ok_or_else(|| Error::new(format!("operation {name} counter decreased")))
    };
    let evidence = AttemptEvidence {
        starts: delta(after.starts, before.starts, "start")?,
        successes: delta(after.successes, before.successes, "success")?,
        failures: delta(after.failures, before.failures, "failure")?,
        reconnects: delta(after.reconnects, before.reconnects, "reconnect")?,
        retries: delta(after.retries, before.retries, "retry")?,
    };
    if evidence.starts != expected
        || evidence.successes != expected
        || evidence.failures != 0
        || evidence.reconnects != 0
        || evidence.retries != 0
    {
        return Err(Error::new(
            "operation start/success/failure/reconnect/retry ledger is not an exact complete set",
        ));
    }
    Ok(evidence)
}

fn set_h2_stream_identity(
    ledger: &mut ConnectionLedger,
    outcomes: &[OperationOutcome],
) -> Result<()> {
    let mut stream_ids = outcomes
        .iter()
        .map(|outcome| {
            outcome
                .connection
                .stream_id
                .ok_or_else(|| Error::new("H2 operation lacks an observed stream ID"))
        })
        .collect::<Result<Vec<_>>>()?;
    stream_ids.sort_unstable();
    if stream_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::new(
            "H2 operation stream IDs are duplicate or unordered",
        ));
    }
    ledger.first_h2_stream_id = stream_ids.first().copied();
    ledger.last_h2_stream_id = stream_ids.last().copied();
    let mut hasher = Sha256::new();
    hasher.update(b"amg-http2-perf/h2-phase-streams/v1\0");
    for stream_id in &stream_ids {
        hasher.update(stream_id.to_be_bytes());
    }
    ledger.h2_stream_sequence_sha256 = format!("{:x}", hasher.finalize());
    if stream_ids.len() as u64 != ledger.h2_streams {
        return Err(Error::new(
            "H2 operation and connection stream ledgers differ",
        ));
    }
    Ok(())
}

fn add_connection_outcome(
    ledger: &mut ConnectionLedger,
    hasher: &mut Sha256,
    outcome: &OperationOutcome,
) -> Result<()> {
    let connection = &outcome.connection;
    macro_rules! checked_add {
        ($field:ident) => {
            ledger.$field = ledger
                .$field
                .checked_add(connection.$field)
                .ok_or_else(|| {
                    Error::new(concat!("connection ledger overflow: ", stringify!($field)))
                })?;
        };
    }
    if let Some(planned) = &connection.planned_id {
        ledger.planned_connections = ledger
            .planned_connections
            .checked_add(1)
            .ok_or_else(|| Error::new("connection ledger overflow: planned_connections"))?;
        hasher.update(outcome.operation_id.as_bytes());
        hasher.update(planned.as_bytes());
    } else {
        hasher.update(outcome.operation_id.as_bytes());
        hasher.update(ledger.policy_label().as_bytes());
    }
    match connection.connection_id {
        Some(connection_id) => hasher.update(connection_id.to_be_bytes()),
        None => hasher.update(0_u64.to_be_bytes()),
    }
    match connection.stream_id {
        Some(stream_id) => hasher.update(stream_id.to_be_bytes()),
        None => hasher.update(0_u32.to_be_bytes()),
    }
    checked_add!(socket_creations);
    checked_add!(connect_attempts);
    checked_add!(connect_successes);
    checked_add!(cumulative_connections);
    checked_add!(requests);
    checked_add!(responses);
    checked_add!(close_tokens);
    checked_add!(keep_alive_tokens);
    checked_add!(response_eos);
    checked_add!(transport_eof);
    checked_add!(h2_streams);
    Ok(())
}

trait ConnectionPolicyLabel {
    fn policy_label(&self) -> &'static str;
}

impl ConnectionPolicyLabel for ConnectionLedger {
    fn policy_label(&self) -> &'static str {
        match self.policy {
            ConnectionPolicy::PersistentH1 => "persistent-h1",
            ConnectionPolicy::FreshH1PerOperation => "fresh-h1-per-operation",
            ConnectionPolicy::PersistentH2 => "persistent-h2",
            ConnectionPolicy::H1UpgradeTunnels => "h1-upgrade-tunnels",
            ConnectionPolicy::H2ExtendedConnectStreams => "h2-extended-connect-streams",
        }
    }
}

fn validate_connection_ledger(
    ledger: &ConnectionLedger,
    operations: u64,
    concurrency: u64,
) -> Result<()> {
    crate::schema::validate_sha256(
        "connection H2 stream sequence",
        &ledger.h2_stream_sequence_sha256,
    )?;
    if ledger.failed_connect_attempts != 0
        || ledger
            .connect_successes
            .checked_add(ledger.failed_connect_attempts)
            != Some(ledger.connect_attempts)
    {
        return Err(Error::new("connection attempt ledger is incomplete"));
    }
    match ledger.policy {
        ConnectionPolicy::FreshH1PerOperation => {
            let exact = [
                ledger.planned_connections,
                ledger.socket_creations,
                ledger.connect_attempts,
                ledger.connect_successes,
                ledger.cumulative_connections,
                ledger.requests,
                ledger.responses,
                ledger.close_tokens,
                ledger.response_eos,
                ledger.transport_eof,
            ];
            if exact.iter().any(|count| *count != operations)
                || ledger.keep_alive_tokens != 0
                || ledger.active_connections != 0
                || ledger.max_active_connections == 0
                || ledger.max_active_connections > concurrency
                || ledger.max_requests_per_connection != 1
                || ledger.reuse_attempts != 0
                || ledger.reconnect_attempts != 0
                || ledger.retry_attempts != 0
                || ledger.h2_streams != 0
                || ledger.active_h2_streams != 0
                || ledger.max_active_h2_streams != 0
                || ledger.first_h2_stream_id.is_some()
                || ledger.last_h2_stream_id.is_some()
            {
                return Err(Error::new(
                    "fresh-H1 connection ledger failed exact cumulative reconciliation",
                ));
            }
        }
        ConnectionPolicy::PersistentH1 => {
            if [
                ledger.planned_connections,
                ledger.socket_creations,
                ledger.connect_attempts,
                ledger.connect_successes,
                ledger.cumulative_connections,
                ledger.active_connections,
                ledger.max_active_connections,
            ]
            .iter()
            .any(|count| *count != concurrency)
                || ledger.max_requests_per_connection != operations.div_ceil(concurrency)
                || ledger.requests != operations
                || ledger.responses != operations
                || ledger.close_tokens != 0
                || ledger.keep_alive_tokens != 0
                || ledger.response_eos != operations
                || ledger.transport_eof != 0
                || ledger.h2_streams != 0
                || ledger.active_h2_streams != 0
                || ledger.max_active_h2_streams != 0
            {
                return Err(Error::new("persistent-H1 operation ledger mismatch"));
            }
        }
        ConnectionPolicy::H1UpgradeTunnels => {
            if [
                ledger.planned_connections,
                ledger.socket_creations,
                ledger.connect_attempts,
                ledger.connect_successes,
                ledger.cumulative_connections,
                ledger.active_connections,
                ledger.max_active_connections,
            ]
            .iter()
            .any(|count| *count != concurrency)
                || ledger.requests != operations
                || ledger.responses != operations
                || ledger.close_tokens != 0
                || ledger.keep_alive_tokens != 0
                || ledger.transport_eof != 0
                || ledger.h2_streams != 0
                || ledger.active_h2_streams != 0
                || ledger.max_active_h2_streams != 0
            {
                return Err(Error::new("H1 Upgrade tunnel ledger mismatch"));
            }
        }
        ConnectionPolicy::PersistentH2 => {
            if [
                ledger.planned_connections,
                ledger.socket_creations,
                ledger.connect_attempts,
                ledger.connect_successes,
                ledger.cumulative_connections,
                ledger.active_connections,
                ledger.max_active_connections,
            ]
            .iter()
            .any(|count| *count != 1)
                || ledger.max_requests_per_connection != operations
                || ledger.requests != operations
                || ledger.responses != operations
                || ledger.response_eos != operations
                || ledger.h2_streams != operations
                || ledger.close_tokens != 0
                || ledger.transport_eof != 0
                || ledger.active_h2_streams != 0
                || ledger.max_active_h2_streams == 0
                || ledger.max_active_h2_streams > concurrency
                || ledger.first_h2_stream_id.is_none()
                || ledger.last_h2_stream_id.is_none()
            {
                return Err(Error::new("persistent-H2 operation ledger mismatch"));
            }
        }
        ConnectionPolicy::H2ExtendedConnectStreams => {
            if [
                ledger.planned_connections,
                ledger.socket_creations,
                ledger.connect_attempts,
                ledger.connect_successes,
                ledger.cumulative_connections,
                ledger.active_connections,
                ledger.max_active_connections,
            ]
            .iter()
            .any(|count| *count != 1)
                || ledger.h2_streams != concurrency
                || ledger.requests != operations
                || ledger.responses != operations
                || ledger.active_h2_streams != concurrency
                || ledger.max_active_h2_streams != concurrency
                || ledger.first_h2_stream_id.is_none()
                || ledger.last_h2_stream_id.is_none()
            {
                return Err(Error::new("RFC8441 Ping/Pong operation ledger mismatch"));
            }
        }
    }
    Ok(())
}

impl Drop for LoadSession {
    fn drop(&mut self) {
        for driver in &self.drivers {
            driver.abort();
        }
    }
}

fn validate_precomputed_websocket_masks(
    lanes: &[Lane],
    phase: u16,
    expected_per_lane: &[u64],
) -> Result<()> {
    if lanes.len() != expected_per_lane.len() {
        return Err(Error::new(
            "WebSocket precomputed-mask lane inventory differs from execution",
        ));
    }
    for (lane, expected) in lanes.iter().zip(expected_per_lane) {
        if lane.workload == Workload::WebSocket {
            if lane.websocket_masks.len() as u64 != *expected
                || lane
                    .websocket_masks
                    .iter()
                    .any(|prepared| prepared.phase != phase)
            {
                return Err(Error::new(
                    "WebSocket phase lacks its complete precomputed mask table",
                ));
            }
        } else if !lane.websocket_masks.is_empty() {
            return Err(Error::new(
                "non-WebSocket lane unexpectedly carries a mask table",
            ));
        }
    }
    Ok(())
}

impl Lane {
    fn precompute_websocket_masks(&mut self, phase: u16, count: u64) -> Result<()> {
        if self.workload != Workload::WebSocket {
            return Ok(());
        }
        if !self.websocket_masks.is_empty() {
            return Err(Error::new(
                "WebSocket mask table from a previous phase was not retired",
            ));
        }
        let first = self.phase_sequences.get(&phase).copied().unwrap_or(0);
        let count = usize::try_from(count)
            .map_err(|_| Error::new("WebSocket mask table count exceeds usize"))?;
        self.websocket_masks.reserve(count);
        for offset in 0..count {
            let sequence = first
                .checked_add(offset as u64)
                .ok_or_else(|| Error::new("WebSocket mask sequence overflow"))?;
            if sequence > u64::from(u32::MAX) {
                return Err(Error::new(
                    "WebSocket mask sequence exceeds the sealed payload width",
                ));
            }
            let packed = (u64::from(phase) << 32) | (sequence & 0xffff_ffff);
            let id = operation_id(phase, self.id, sequence);
            let frame: [u8; 14] = masked_ping(&self.corpus, id, self.id, packed)
                .try_into()
                .map_err(|_| Error::new("precomputed WebSocket frame width changed"))?;
            let expected_payload = crate::topology::parse_masked_ping(&frame)?;
            self.websocket_masks.push_back(PreparedWebSocketFrame {
                phase,
                sequence,
                frame,
                expected_payload,
            });
        }
        Ok(())
    }

    fn discard_websocket_masks(&mut self, phase: u16) -> Result<()> {
        if self
            .websocket_masks
            .iter()
            .any(|prepared| prepared.phase != phase)
        {
            return Err(Error::new("WebSocket mask table contains another phase"));
        }
        self.websocket_masks.clear();
        Ok(())
    }

    fn next_operation(&mut self, phase: u16) -> Result<(u64, String)> {
        let sequence = self.phase_sequences.entry(phase).or_insert(0);
        let current = *sequence;
        *sequence = sequence
            .checked_add(1)
            .ok_or_else(|| Error::new("lane operation sequence overflow"))?;
        let id = operation_id(phase, self.id, current);
        Ok((current, operation_id_text(id)))
    }

    async fn run_operation(&mut self, phase: u16) -> Result<OperationOutcome> {
        self.run_operation_inner(phase, None)
            .await?
            .ok_or_else(|| Error::new("unbounded operation was not started"))
    }

    async fn run_operation_before(
        &mut self,
        phase: u16,
        deadline_ns: u64,
    ) -> Result<Option<OperationOutcome>> {
        self.run_operation_inner(phase, Some(deadline_ns)).await
    }

    async fn run_operation_inner(
        &mut self,
        phase: u16,
        deadline_ns: Option<u64>,
    ) -> Result<Option<OperationOutcome>> {
        let sequence = self.phase_sequences.get(&phase).copied().unwrap_or(0);
        let operation_text = operation_id_text(operation_id(phase, self.id, sequence));
        let connection_text = planned_connection_id(phase, self.id, sequence);
        let request = if self.workload == Workload::WebSocket {
            None
        } else {
            Some(self.build_http_request(&operation_text)?)
        };
        let websocket_frame = if self.workload == Workload::WebSocket {
            let prepared = self
                .websocket_masks
                .front()
                .copied()
                .ok_or_else(|| Error::new("WebSocket operation lacks a precomputed mask"))?;
            if prepared.phase != phase || prepared.sequence != sequence {
                return Err(Error::new(
                    "precomputed WebSocket mask identity differs from operation",
                ));
            }
            Some(prepared)
        } else {
            None
        };
        let start = clock_ns(ClockKind::Monotonic)?;
        if deadline_ns.is_some_and(|deadline| start >= deadline) {
            return Ok(None);
        }
        if websocket_frame.is_some() {
            self.websocket_masks.pop_front();
        }
        let stored = self.phase_sequences.entry(phase).or_insert(0);
        if *stored != sequence {
            return Err(Error::new("lane operation sequence changed before start"));
        }
        *stored = stored
            .checked_add(1)
            .ok_or_else(|| Error::new("lane operation sequence overflow"))?;
        let attempt = self.attempts.begin();
        let mut outcome = if self.workload == Workload::WebSocket {
            let prepared =
                websocket_frame.ok_or_else(|| Error::new("precomputed WebSocket frame missing"))?;
            self.run_websocket_operation(operation_text, prepared.frame, prepared.expected_payload)
                .await?
        } else {
            self.run_http_operation(
                operation_text,
                connection_text,
                request.ok_or_else(|| Error::new("prepared HTTP request missing"))?,
            )
            .await?
        };
        let end = clock_ns(ClockKind::Monotonic)?;
        outcome.latency_ns = end
            .checked_sub(start)
            .ok_or_else(|| Error::new("MONOTONIC operation clock moved backwards"))?;
        outcome.start_ns = start;
        outcome.completed_ns = end;
        attempt.success();
        Ok(Some(outcome))
    }

    fn build_http_request(&self, operation_text: &str) -> Result<Request<BenchBody>> {
        let corpus = Arc::clone(&self.corpus);
        let body = if self.workload == Workload::Upload1Mib {
            BenchBody::from_chunks(corpus.chunks().map(Bytes::copy_from_slice))
        } else {
            BenchBody::empty()
        };
        let method = if self.workload == Workload::Upload1Mib {
            Method::POST
        } else {
            Method::GET
        };
        let path = crate::topology::workload_path(self.workload);
        let uri = if self.protocol == Protocol::H1 {
            path.to_owned()
        } else {
            format!("http://{}{path}", self.authority)
        };
        let mut request = Request::builder()
            .method(method)
            .version(if self.protocol == Protocol::H1 {
                Version::HTTP_11
            } else {
                Version::HTTP_2
            })
            .uri(uri)
            .header(HOST, &self.authority)
            .header("x-amg-bench-op", operation_text)
            .header(AUTHORIZATION, "Bearer browser-secret-must-strip")
            .header(PROXY_AUTHORIZATION, "Basic proxy-secret-must-strip")
            .header("x-auth-mini-forged", "must-strip")
            .header("x-forwarded-host", "attacker.invalid")
            .body(body)
            .map_err(|error| Error::new(format!("build request: {error}")))?;
        if self.workload == Workload::Upload1Mib {
            request
                .headers_mut()
                .insert(CONTENT_LENGTH, HeaderValue::from_static("1048576"));
        }
        apply_target_headers(&mut request, self.target, self.cookie_header.as_deref())?;
        Ok(request)
    }

    async fn run_http_operation(
        &mut self,
        operation_text: String,
        connection_text: String,
        request: Request<BenchBody>,
    ) -> Result<OperationOutcome> {
        let corpus = Arc::clone(&self.corpus);
        let _active_h2_stream = self
            .h2_stream_tracker
            .as_ref()
            .map(ActiveStreamTracker::acquire);
        let mut outcome = match &mut self.transport {
            LaneTransport::Http(sender) => {
                let (response, connection_id, stream_id) = sender.send(request, false).await?;
                let mut outcome = validate_response(
                    self.workload,
                    self.protocol,
                    &operation_text,
                    response,
                    &corpus,
                    false,
                )
                .await?;
                outcome.connection.requests = 1;
                outcome.connection.responses = 1;
                outcome.connection.response_eos = 1;
                outcome.connection.connection_id = Some(connection_id);
                outcome.connection.stream_id = stream_id;
                if self.protocol == Protocol::H2 {
                    outcome.connection.h2_streams = 1;
                }
                outcome
            }
            LaneTransport::FreshH1 { endpoint, tracker } => {
                run_fresh_h1_upload(
                    *endpoint,
                    Arc::clone(tracker),
                    request,
                    self.workload,
                    &operation_text,
                    connection_text,
                    &corpus,
                )
                .await?
            }
            LaneTransport::WebSocket(_) => return Err(Error::new("HTTP operation on tunnel")),
        };
        outcome.request_bytes = if self.workload == Workload::Upload1Mib {
            CORPUS_BYTES as u64
        } else {
            0
        };
        Ok(outcome)
    }

    async fn run_websocket_operation(
        &mut self,
        operation_text: String,
        frame: [u8; 14],
        expected_payload: [u8; 8],
    ) -> Result<OperationOutcome> {
        let io = match &mut self.transport {
            LaneTransport::WebSocket(io) => io,
            LaneTransport::Http(_) | LaneTransport::FreshH1 { .. } => {
                return Err(Error::new("WebSocket operation before tunnel"))
            }
        };
        io.write_all(&frame).await?;
        io.flush().await?;
        let mut pong = [0_u8; 10];
        io.read_exact(&mut pong).await?;
        let payload = parse_unmasked_pong(&pong)?;
        Ok(OperationOutcome {
            operation_id: operation_text,
            request_bytes: 8,
            response_bytes: 8,
            latency_ns: 0,
            start_ns: 0,
            completed_ns: 0,
            status_ok: true,
            eos_ok: true,
            payload_ok: payload == expected_payload,
            sse_content_type_ok: true,
            response_headers_sanitized: true,
            observed_protocol: self
                .observed_protocol
                .ok_or_else(|| Error::new("WebSocket lane lacks observed handshake protocol"))?,
            protocol_date: None,
            connection: OperationConnection {
                connection_id: self.physical_connection_id,
                stream_id: self.tunnel_stream_id,
                requests: 1,
                responses: 1,
                response_eos: 1,
                ..OperationConnection::default()
            },
        })
    }
}

async fn open_websocket(mut lane: Lane) -> Result<(Lane, OperationOutcome)> {
    let (_, operation_text) = lane.next_operation(0)?;
    // Canonical 16-byte RFC 6455 nonce (the RFC example value).
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let uri = if lane.protocol == Protocol::H1 {
        "/bench/websocket".to_owned()
    } else {
        format!("http://{}/bench/websocket", lane.authority)
    };
    let mut builder = Request::builder()
        .method(if lane.protocol == Protocol::H1 {
            Method::GET
        } else {
            Method::CONNECT
        })
        .version(if lane.protocol == Protocol::H1 {
            Version::HTTP_11
        } else {
            Version::HTTP_2
        })
        .uri(uri)
        .header("x-amg-bench-op", &operation_text)
        .header(SEC_WEBSOCKET_VERSION, "13")
        .header(ORIGIN, "http://public.example")
        .header(AUTHORIZATION, "Bearer browser-secret-must-strip")
        .header(PROXY_AUTHORIZATION, "Basic proxy-secret-must-strip")
        .header("x-auth-mini-forged", "must-strip")
        .header("x-forwarded-host", "attacker.invalid");
    if lane.protocol == Protocol::H1 {
        builder = builder
            .header(HOST, &lane.authority)
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "websocket")
            .header(SEC_WEBSOCKET_KEY, key);
    }
    let mut request = builder
        .body(BenchBody::empty())
        .map_err(|error| Error::new(format!("build WebSocket request: {error}")))?;
    if lane.protocol == Protocol::H2 {
        request
            .extensions_mut()
            .insert(hyper::ext::Protocol::from_static("websocket"));
    }
    apply_target_headers(&mut request, lane.target, lane.cookie_header.as_deref())?;
    let attempt = lane.attempts.begin();
    let sender = match &mut lane.transport {
        LaneTransport::Http(sender) => sender,
        LaneTransport::FreshH1 { .. } => {
            return Err(Error::new("WebSocket cannot use fresh-H1 upload transport"))
        }
        LaneTransport::WebSocket(_) => return Err(Error::new("duplicate WebSocket open")),
    };
    let (mut response, connection_id, stream_id) =
        sender.send(request, lane.protocol == Protocol::H2).await?;
    let observed_protocol = protocol_from_version(response.version())?;
    let protocol_date = observe_protocol_date(response.headers())?;
    match lane.protocol {
        Protocol::H1 => {
            if response.status() != StatusCode::SWITCHING_PROTOCOLS
                || response
                    .headers()
                    .get(SEC_WEBSOCKET_ACCEPT)
                    .and_then(|value| value.to_str().ok())
                    .is_none_or(|value| value != websocket_accept(key))
            {
                return Err(Error::new("invalid H1 WebSocket Upgrade response"));
            }
        }
        Protocol::H2 => {
            if response.status() != StatusCode::OK
                || response.headers().contains_key(SEC_WEBSOCKET_ACCEPT)
                || response.headers().contains_key(CONNECTION)
                || response.headers().contains_key(UPGRADE)
            {
                return Err(Error::new(format!(
                    "invalid RFC8441 Extended CONNECT response: status={} accept={} connection={} upgrade={}",
                    response.status(),
                    response.headers().contains_key(SEC_WEBSOCKET_ACCEPT),
                    response.headers().contains_key(CONNECTION),
                    response.headers().contains_key(UPGRADE)
                )));
            }
        }
    }
    if response
        .headers()
        .contains_key("x-auth-mini-fixture-secret")
        || has_gateway_session_set_cookie(response.headers())
    {
        return Err(Error::new("WebSocket response header sanitation failed"));
    }
    let upgraded = hyper::upgrade::on(&mut response)
        .await
        .context("obtain WebSocket upgraded tunnel")?;
    lane.transport = LaneTransport::WebSocket(Box::pin(TokioIo::new(upgraded)));
    lane.physical_connection_id = Some(connection_id);
    lane.tunnel_stream_id = stream_id;
    lane.observed_protocol = Some(observed_protocol);
    let outcome = OperationOutcome {
        operation_id: operation_text,
        request_bytes: 0,
        response_bytes: 0,
        latency_ns: 0,
        start_ns: 0,
        completed_ns: 0,
        status_ok: true,
        eos_ok: true,
        payload_ok: true,
        sse_content_type_ok: true,
        response_headers_sanitized: true,
        observed_protocol,
        protocol_date,
        connection: OperationConnection {
            connection_id: Some(connection_id),
            stream_id,
            requests: 1,
            responses: 1,
            h2_streams: u64::from(stream_id.is_some()),
            ..OperationConnection::default()
        },
    };
    attempt.success();
    Ok((lane, outcome))
}

fn apply_target_headers(
    request: &mut Request<BenchBody>,
    target: LoadTarget,
    cookie_header: Option<&str>,
) -> Result<()> {
    match target {
        LoadTarget::Gateway => {
            let cookie =
                cookie_header.ok_or_else(|| Error::new("gateway request has no cookie"))?;
            request.headers_mut().append(
                COOKIE,
                HeaderValue::from_str(cookie)
                    .map_err(|_| Error::new("invalid synthetic cookie"))?,
            );
        }
        LoadTarget::Direct => {
            request
                .headers_mut()
                .insert("x-auth-mini-user-id", HeaderValue::from_static(USER_ID));
            request
                .headers_mut()
                .insert("x-auth-mini-email", HeaderValue::from_static(USER_EMAIL));
            request.headers_mut().insert(
                "x-forwarded-host",
                HeaderValue::from_static("public.example"),
            );
            request
                .headers_mut()
                .insert("x-forwarded-proto", HeaderValue::from_static("http"));
            request.headers_mut().remove(AUTHORIZATION);
            request.headers_mut().remove(PROXY_AUTHORIZATION);
            request.headers_mut().remove("x-auth-mini-forged");
        }
    }
    Ok(())
}

async fn validate_response(
    workload: Workload,
    protocol: Protocol,
    operation_id: &str,
    mut response: Response<Incoming>,
    corpus: &Corpus,
    require_h1_close: bool,
) -> Result<OperationOutcome> {
    let observed_protocol = protocol_from_version(response.version())?;
    let protocol_date = observe_protocol_date(response.headers())?;
    let close = has_connection_token(response.headers(), "close");
    let keep_alive = has_connection_token(response.headers(), "keep-alive")
        || response.headers().contains_key("keep-alive");
    if protocol == Protocol::H1 {
        if require_h1_close {
            if !close || keep_alive {
                return Err(Error::new(
                    "fresh downstream H1 upload requires Connection: close and forbids keep-alive",
                ));
            }
        } else if close {
            return Err(Error::new(
                "persistent downstream H1 topology violated: gateway returned Connection: close",
            ));
        }
    }
    let status_ok = response.status() == StatusCode::OK;
    let sse_content_type_ok =
        workload != Workload::Sse || exact_sse_content_type(response.headers());
    let headers_sanitized = !response
        .headers()
        .contains_key("x-auth-mini-fixture-secret")
        && !has_gateway_session_set_cookie(response.headers())
        && response
            .headers()
            .get("x-fixture-marker")
            .is_some_and(|value| value == "present");
    let mut offset = 0_usize;
    let mut collected = Vec::new();
    let mut payload_ok = true;
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|error| Error::new(format!("response body error: {error}")))?;
        if let Ok(data) = frame.into_data() {
            match workload {
                Workload::Download1Mib => {
                    let end = offset
                        .checked_add(data.len())
                        .ok_or_else(|| Error::new("download offset overflow"))?;
                    if end > corpus.bytes().len() || data.as_ref() != &corpus.bytes()[offset..end] {
                        payload_ok = false;
                    }
                    offset = end;
                }
                _ => collected.extend_from_slice(&data),
            }
        }
    }
    let response_bytes = match workload {
        Workload::Get => {
            payload_ok &= collected == corpus.get_body();
            collected.len() as u64
        }
        Workload::Upload1Mib => {
            payload_ok &= collected == format!("{operation_id}:{}", CORPUS_BYTES).as_bytes();
            collected.len() as u64
        }
        Workload::Download1Mib => {
            payload_ok &= offset == CORPUS_BYTES;
            offset as u64
        }
        Workload::Sse => {
            payload_ok &= validate_sse(&collected, corpus);
            collected.len() as u64
        }
        Workload::WebSocket => {
            return Err(Error::new("HTTP response validator received WebSocket"))
        }
    };
    Ok(OperationOutcome {
        operation_id: operation_id.to_owned(),
        request_bytes: 0,
        response_bytes,
        latency_ns: 0,
        start_ns: 0,
        completed_ns: 0,
        status_ok,
        eos_ok: true,
        payload_ok,
        sse_content_type_ok,
        response_headers_sanitized: headers_sanitized,
        observed_protocol,
        protocol_date,
        connection: OperationConnection {
            close_tokens: u64::from(close),
            keep_alive_tokens: u64::from(keep_alive),
            ..OperationConnection::default()
        },
    })
}

fn has_connection_token(headers: &http::HeaderMap, expected: &str) -> bool {
    headers.get_all(CONNECTION).iter().any(|value| {
        value.to_str().ok().is_some_and(|text| {
            text.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

fn exact_sse_content_type(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::CONTENT_TYPE)
        .iter()
        .map(HeaderValue::as_bytes)
        .eq([b"text/event-stream".as_slice()])
}

fn validate_sse(bytes: &[u8], corpus: &Corpus) -> bool {
    let mut cursor = 0_usize;
    for event in 0..SSE_EVENTS {
        let prefix = format!("id: {event}\ndata: ");
        if bytes.get(cursor..cursor + prefix.len()) != Some(prefix.as_bytes()) {
            return false;
        }
        cursor += prefix.len();
        let data = corpus.sse_data(event);
        if bytes.get(cursor..cursor + data.len()) != Some(data.as_slice()) {
            return false;
        }
        cursor += data.len();
        if bytes.get(cursor..cursor + 2) != Some(b"\n\n") {
            return false;
        }
        cursor += 2;
    }
    cursor == bytes.len()
}

fn has_gateway_session_set_cookie(headers: &http::HeaderMap) -> bool {
    headers.get_all(SET_COOKIE).iter().any(|value| {
        value
            .to_str()
            .ok()
            .is_some_and(|text| text.trim_start().starts_with("amg_session="))
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_fresh_h1_upload(
    endpoint: SocketAddr,
    tracker: Arc<FreshConnectionTracker>,
    request: Request<BenchBody>,
    workload: Workload,
    operation_text: &str,
    connection_text: String,
    corpus: &Corpus,
) -> Result<OperationOutcome> {
    if workload != Workload::Upload1Mib {
        return Err(Error::new(
            "fresh downstream H1 transport is restricted to upload",
        ));
    }
    if !endpoint.ip().is_loopback() {
        return Err(Error::new("fresh H1 client target is not loopback"));
    }
    if request.headers().contains_key(CONNECTION) {
        return Err(Error::new(
            "fresh H1 upload request must not inject a Connection header",
        ));
    }

    // Socket creation, the sole connect attempt, request/response, and terminal
    // peer EOF all happen inside the caller's operation timer.  This path does
    // not call shutdown and does not hand ownership to Hyper, so a local close
    // cannot masquerade as peer EOF.
    let socket = if endpoint.is_ipv4() {
        TcpSocket::new_v4()
            .context("create fresh H1 socket")
            .map_err(|error| error.with_role_code(RoleErrorCode::ConnectFailed))?
    } else {
        TcpSocket::new_v6()
            .context("create fresh H1 socket")
            .map_err(|error| error.with_role_code(RoleErrorCode::ConnectFailed))?
    };
    let _active = tracker.acquire();
    let stream = socket
        .connect(endpoint)
        .await
        .context("sole fresh H1 connect attempt")
        .map_err(|error| error.with_role_code(RoleErrorCode::ConnectFailed))?;
    stream
        .set_nodelay(true)
        .map_err(|error| Error::from(error).with_role_code(RoleErrorCode::ConnectFailed))?;
    let mut outcome = raw_h1_upload_exchange(stream, request, operation_text, corpus).await?;
    outcome.connection.planned_id = Some(connection_text);
    outcome.connection.socket_creations = 1;
    outcome.connection.connect_attempts = 1;
    outcome.connection.connect_successes = 1;
    outcome.connection.cumulative_connections = 1;
    outcome.connection.requests = 1;
    outcome.connection.responses = 1;
    outcome.connection.response_eos = 1;
    outcome.connection.transport_eof = 1;
    Ok(outcome)
}

async fn raw_h1_upload_exchange(
    stream: TcpStream,
    request: Request<BenchBody>,
    operation_text: &str,
    corpus: &Corpus,
) -> Result<OperationOutcome> {
    raw_h1_upload_exchange_with_eof_cap(
        stream,
        request,
        operation_text,
        corpus,
        Duration::from_secs(2),
    )
    .await
}

async fn raw_h1_upload_exchange_with_eof_cap(
    mut stream: TcpStream,
    request: Request<BenchBody>,
    operation_text: &str,
    corpus: &Corpus,
    eof_cap: Duration,
) -> Result<OperationOutcome> {
    let (parts, _) = request.into_parts();
    if parts.method != Method::POST
        || parts.version != Version::HTTP_11
        || parts.headers.contains_key(CONNECTION)
        || parts
            .headers
            .get(CONTENT_LENGTH)
            .is_none_or(|value| value != "1048576")
    {
        return Err(Error::new("fresh H1 upload request framing changed")
            .with_role_code(RoleErrorCode::InvalidConfiguration));
    }
    let mut head = Vec::with_capacity(2_048);
    head.extend_from_slice(format!("{} {} HTTP/1.1\r\n", parts.method, parts.uri).as_bytes());
    for (name, value) in &parts.headers {
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    stream
        .write_all(&head)
        .await
        .map_err(|error| Error::from(error).with_role_code(RoleErrorCode::RequestWriteFailed))?;
    for chunk in corpus.chunks() {
        stream.write_all(chunk).await.map_err(|error| {
            Error::from(error).with_role_code(RoleErrorCode::RequestWriteFailed)
        })?;
    }
    stream
        .flush()
        .await
        .map_err(|error| Error::from(error).with_role_code(RoleErrorCode::RequestWriteFailed))?;

    let mut received = Vec::with_capacity(2_048);
    let header_end = loop {
        if let Some(offset) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break offset + 4;
        }
        if received.len() >= 16_384 {
            return Err(Error::new("fresh H1 response header exceeds 16 KiB")
                .with_role_code(RoleErrorCode::ResponseHeadInvalid));
        }
        let mut bytes = [0_u8; 1_024];
        let count = stream.read(&mut bytes).await.map_err(|error| {
            Error::from(error).with_role_code(RoleErrorCode::ResponseHeadReadFailed)
        })?;
        if count == 0 {
            return Err(
                Error::new("peer EOF arrived before the complete H1 response header")
                    .with_role_code(RoleErrorCode::ResponseHeadReadFailed),
            );
        }
        received.extend_from_slice(&bytes[..count]);
    };
    let header_text = std::str::from_utf8(&received[..header_end]).map_err(|_| {
        Error::new("fresh H1 response header is not UTF-8")
            .with_role_code(RoleErrorCode::ResponseHeadInvalid)
    })?;
    let mut lines = header_text[..header_text.len() - 4].split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        Error::new("fresh H1 response status line missing")
            .with_role_code(RoleErrorCode::ResponseHeadInvalid)
    })?;
    let status_ok = status_line.starts_with("HTTP/1.1 200 ") || status_line == "HTTP/1.1 200";
    let exact_version = status_line.starts_with("HTTP/1.1 ");
    let mut headers = http::HeaderMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            Error::new("malformed fresh H1 response header")
                .with_role_code(RoleErrorCode::ResponseHeadInvalid)
        })?;
        let name = http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            Error::new("invalid fresh H1 response header name")
                .with_role_code(RoleErrorCode::ResponseHeadInvalid)
        })?;
        let value = HeaderValue::from_str(value.trim()).map_err(|_| {
            Error::new("invalid fresh H1 response header value")
                .with_role_code(RoleErrorCode::ResponseHeadInvalid)
        })?;
        headers.append(name, value);
    }
    let close = has_connection_token(&headers, "close");
    let keep_alive =
        has_connection_token(&headers, "keep-alive") || headers.contains_key("keep-alive");
    if !close || keep_alive {
        return Err(Error::new(
            "fresh downstream H1 upload requires observed Connection: close and no keep-alive",
        )
        .with_role_code(RoleErrorCode::ConnectionCloseMissing));
    }
    let body = read_fresh_h1_response_body(&mut stream, &headers, &received[header_end..]).await?;
    let mut eof_probe = [0_u8; 1];
    let eof = tokio::time::timeout(eof_cap, stream.read(&mut eof_probe))
        .await
        .map_err(|_| {
            Error::new("peer did not produce EOF within the bounded close wait")
                .with_role_code(RoleErrorCode::PeerEofMissing)
        })?
        .map_err(|error| Error::from(error).with_role_code(RoleErrorCode::PeerEofMissing))?;
    if eof != 0 {
        return Err(
            Error::new("fresh H1 response carried bytes after response EOS")
                .with_role_code(RoleErrorCode::PeerEofMissing),
        );
    }
    let expected = format!("{operation_text}:{}", CORPUS_BYTES);
    let payload_ok = body == expected.as_bytes();
    let headers_sanitized = !headers.contains_key("x-auth-mini-fixture-secret")
        && !has_gateway_session_set_cookie(&headers)
        && headers
            .get("x-fixture-marker")
            .is_some_and(|value| value == "present");
    Ok(OperationOutcome {
        operation_id: operation_text.to_owned(),
        request_bytes: CORPUS_BYTES as u64,
        response_bytes: body.len() as u64,
        latency_ns: 0,
        start_ns: 0,
        completed_ns: 0,
        status_ok: status_ok && exact_version,
        eos_ok: true,
        payload_ok,
        sse_content_type_ok: true,
        response_headers_sanitized: headers_sanitized,
        observed_protocol: Protocol::H1,
        protocol_date: observe_protocol_date(&headers)?,
        connection: OperationConnection {
            close_tokens: 1,
            transport_eof: 1,
            ..OperationConnection::default()
        },
    })
}

fn protocol_from_version(version: Version) -> Result<Protocol> {
    match version {
        Version::HTTP_11 => Ok(Protocol::H1),
        Version::HTTP_2 => Ok(Protocol::H2),
        _ => Err(Error::new(
            "response used an unsupported observed HTTP version",
        )),
    }
}

fn observe_protocol_date(headers: &http::HeaderMap) -> Result<Option<ProtocolDateObservation>> {
    let mut values = headers.get_all(DATE).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::new("response contains multiple Date headers"));
    }
    let boottime_before_ns = clock_ns(ClockKind::Boottime)?;
    let value = value
        .to_str()
        .map_err(|_| Error::new("response Date header is not visible ASCII"))?
        .to_owned();
    let unix_seconds = parse_http_date_seconds(&value)?;
    let boottime_after_ns = clock_ns(ClockKind::Boottime)?;
    if boottime_after_ns < boottime_before_ns {
        return Err(Error::new(
            "BOOTTIME moved backwards around Date observation",
        ));
    }
    Ok(Some(ProtocolDateObservation {
        value,
        unix_seconds,
        boottime_before_ns,
        boottime_after_ns,
    }))
}

pub(crate) fn parse_http_date_seconds(value: &str) -> Result<u64> {
    let bytes = value.as_bytes();
    if bytes.len() != 29
        || bytes[3..5] != *b", "
        || bytes[7] != b' '
        || bytes[11] != b' '
        || bytes[16] != b' '
        || bytes[19] != b':'
        || bytes[22] != b':'
        || bytes[25..29] != *b" GMT"
    {
        return Err(Error::new("response Date header is not IMF-fixdate"));
    }
    let decimal = |range: std::ops::Range<usize>| -> Result<i64> {
        std::str::from_utf8(&bytes[range])
            .map_err(|_| Error::new("response Date header is not ASCII"))?
            .parse::<i64>()
            .map_err(|_| Error::new("response Date header has a non-decimal component"))
    };
    let day = decimal(5..7)?;
    let month = match &bytes[8..11] {
        b"Jan" => 1,
        b"Feb" => 2,
        b"Mar" => 3,
        b"Apr" => 4,
        b"May" => 5,
        b"Jun" => 6,
        b"Jul" => 7,
        b"Aug" => 8,
        b"Sep" => 9,
        b"Oct" => 10,
        b"Nov" => 11,
        b"Dec" => 12,
        _ => return Err(Error::new("response Date header has an invalid month")),
    };
    let year = decimal(12..16)?;
    let hour = decimal(17..19)?;
    let minute = decimal(20..22)?;
    let second = decimal(23..25)?;
    if !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return Err(Error::new(
            "response Date header has an out-of-range component",
        ));
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let unix_days = era * 146_097 + day_of_era - 719_468;
    if unix_days < 0 {
        return Err(Error::new("response Date header predates the Unix epoch"));
    }
    u64::try_from(unix_days)
        .ok()
        .and_then(|days| days.checked_mul(86_400))
        .and_then(|base| base.checked_add(u64::try_from(hour * 3_600 + minute * 60 + second).ok()?))
        .ok_or_else(|| Error::new("response Date header overflows Unix seconds"))
}

const FRESH_H1_RESPONSE_BODY_MAX: usize = 4_096;
const FRESH_H1_RESPONSE_ENCODED_MAX: usize = 16_384;

async fn read_fresh_h1_response_body(
    stream: &mut TcpStream,
    headers: &http::HeaderMap,
    initial: &[u8],
) -> Result<Vec<u8>> {
    let content_lengths = headers.get_all(CONTENT_LENGTH).iter().collect::<Vec<_>>();
    let transfer_encodings = headers
        .get_all(TRANSFER_ENCODING)
        .iter()
        .collect::<Vec<_>>();
    if !content_lengths.is_empty() && !transfer_encodings.is_empty() {
        return Err(
            Error::new("fresh H1 response has both Content-Length and Transfer-Encoding")
                .with_role_code(RoleErrorCode::ResponseHeadInvalid),
        );
    }
    if content_lengths.len() == 1 {
        let content_length = content_lengths[0]
            .to_str()
            .map_err(|_| {
                Error::new("fresh H1 response Content-Length is not ASCII")
                    .with_role_code(RoleErrorCode::ResponseHeadInvalid)
            })?
            .parse::<usize>()
            .context("parse fresh H1 response Content-Length")
            .map_err(|error| error.with_role_code(RoleErrorCode::ResponseHeadInvalid))?;
        if content_length > FRESH_H1_RESPONSE_BODY_MAX {
            return Err(
                Error::new("fresh H1 upload response body exceeds fixed bound")
                    .with_role_code(RoleErrorCode::ResponseBodyInvalid),
            );
        }
        let mut body = initial.to_vec();
        if body.len() > content_length {
            return Err(
                Error::new("fresh H1 response has bytes after its declared body")
                    .with_role_code(RoleErrorCode::ResponseBodyInvalid),
            );
        }
        while body.len() < content_length {
            let remaining = content_length - body.len();
            read_bounded_response_bytes(stream, &mut body, remaining).await?;
        }
        return Ok(body);
    }
    if content_lengths.len() > 1 {
        return Err(
            Error::new("fresh H1 response has multiple Content-Length fields")
                .with_role_code(RoleErrorCode::ResponseHeadInvalid),
        );
    }
    if transfer_encodings.len() != 1
        || transfer_encodings[0].to_str().ok().is_none_or(|value| {
            let mut tokens = value.split(',').map(str::trim);
            !tokens
                .next()
                .is_some_and(|token| token.eq_ignore_ascii_case("chunked"))
                || tokens.next().is_some()
        })
    {
        return Err(
            Error::new("fresh H1 response lacks one supported body framing")
                .with_role_code(RoleErrorCode::ResponseHeadInvalid),
        );
    }
    decode_chunked_response_body(stream, initial).await
}

async fn decode_chunked_response_body(stream: &mut TcpStream, initial: &[u8]) -> Result<Vec<u8>> {
    let mut encoded = initial.to_vec();
    let mut cursor = 0_usize;
    let mut decoded = Vec::new();
    loop {
        let line_end = loop {
            if let Some(relative) = encoded[cursor..]
                .windows(2)
                .position(|bytes| bytes == b"\r\n")
            {
                break cursor + relative;
            }
            read_chunked_response_bytes(stream, &mut encoded).await?;
        };
        let line = std::str::from_utf8(&encoded[cursor..line_end]).map_err(|_| {
            Error::new("fresh H1 chunk size is not ASCII")
                .with_role_code(RoleErrorCode::ResponseBodyInvalid)
        })?;
        let size_text = line.split_once(';').map_or(line, |(size, _)| size).trim();
        if size_text.is_empty() || size_text.len() > 16 {
            return Err(Error::new("fresh H1 chunk size is malformed")
                .with_role_code(RoleErrorCode::ResponseBodyInvalid));
        }
        let chunk_size = usize::from_str_radix(size_text, 16).map_err(|_| {
            Error::new("fresh H1 chunk size is malformed")
                .with_role_code(RoleErrorCode::ResponseBodyInvalid)
        })?;
        cursor = line_end
            .checked_add(2)
            .ok_or_else(|| Error::new("fresh H1 chunk cursor overflow"))?;
        if chunk_size == 0 {
            while encoded.len() < cursor + 2 {
                read_chunked_response_bytes(stream, &mut encoded).await?;
            }
            if encoded.get(cursor..cursor + 2) != Some(b"\r\n") {
                return Err(
                    Error::new("fresh H1 chunked response trailers are forbidden")
                        .with_role_code(RoleErrorCode::ResponseBodyInvalid),
                );
            }
            cursor += 2;
            if encoded.len() != cursor {
                return Err(
                    Error::new("fresh H1 chunked response has bytes after response EOS")
                        .with_role_code(RoleErrorCode::ResponseBodyInvalid),
                );
            }
            return Ok(decoded);
        }
        if decoded
            .len()
            .checked_add(chunk_size)
            .is_none_or(|total| total > FRESH_H1_RESPONSE_BODY_MAX)
        {
            return Err(
                Error::new("fresh H1 upload response body exceeds fixed bound")
                    .with_role_code(RoleErrorCode::ResponseBodyInvalid),
            );
        }
        let chunk_end = cursor
            .checked_add(chunk_size)
            .ok_or_else(|| Error::new("fresh H1 chunk length overflow"))?;
        let framed_end = chunk_end
            .checked_add(2)
            .ok_or_else(|| Error::new("fresh H1 chunk framing overflow"))?;
        while encoded.len() < framed_end {
            read_chunked_response_bytes(stream, &mut encoded).await?;
        }
        if encoded.get(chunk_end..framed_end) != Some(b"\r\n") {
            return Err(Error::new("fresh H1 chunk data lacks its terminal CRLF")
                .with_role_code(RoleErrorCode::ResponseBodyInvalid));
        }
        decoded.extend_from_slice(&encoded[cursor..chunk_end]);
        cursor = framed_end;
    }
}

async fn read_chunked_response_bytes(stream: &mut TcpStream, encoded: &mut Vec<u8>) -> Result<()> {
    if encoded.len() >= FRESH_H1_RESPONSE_ENCODED_MAX {
        return Err(
            Error::new("fresh H1 chunked response exceeds encoded bound")
                .with_role_code(RoleErrorCode::ResponseBodyInvalid),
        );
    }
    let mut bytes = [0_u8; 1_024];
    let capacity = (FRESH_H1_RESPONSE_ENCODED_MAX - encoded.len()).min(bytes.len());
    let count = stream.read(&mut bytes[..capacity]).await.map_err(|error| {
        Error::from(error).with_role_code(RoleErrorCode::ResponseBodyReadFailed)
    })?;
    if count == 0 {
        return Err(Error::new("peer EOF arrived before response EOS")
            .with_role_code(RoleErrorCode::ResponseBodyReadFailed));
    }
    encoded.extend_from_slice(&bytes[..count]);
    Ok(())
}

async fn read_bounded_response_bytes(
    stream: &mut TcpStream,
    body: &mut Vec<u8>,
    remaining: usize,
) -> Result<()> {
    let mut bytes = [0_u8; 1_024];
    let read_len = remaining.min(bytes.len());
    let count = stream.read(&mut bytes[..read_len]).await.map_err(|error| {
        Error::from(error).with_role_code(RoleErrorCode::ResponseBodyReadFailed)
    })?;
    if count == 0 {
        return Err(Error::new("peer EOF arrived before response EOS")
            .with_role_code(RoleErrorCode::ResponseBodyReadFailed));
    }
    body.extend_from_slice(&bytes[..count]);
    Ok(())
}

async fn open_h1(endpoint: SocketAddr, connection_id: u64) -> Result<(HttpSender, JoinHandle<()>)> {
    if !endpoint.ip().is_loopback() {
        return Err(Error::new("H1 client target is not loopback"));
    }
    let stream = TcpStream::connect(endpoint)
        .await
        .context("connect H1 endpoint")?;
    stream.set_nodelay(true)?;
    let (sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .context("H1 client handshake")?;
    let driver = tokio::spawn(async move {
        match connection.with_upgrades().await {
            Ok(()) => {}
            Err(error) => eprintln!("load-role: H1 connection ended: {error}"),
        }
    });
    Ok((
        HttpSender::H1 {
            sender,
            connection_id,
        },
        driver,
    ))
}

async fn open_h2(
    endpoint: SocketAddr,
    connection_id: u64,
    require_enable_connect: bool,
) -> Result<(
    http2::SendRequest<BenchBody>,
    JoinHandle<()>,
    H2FrameObserver,
)> {
    if !endpoint.ip().is_loopback() {
        return Err(Error::new("H2 client target is not loopback"));
    }
    let stream = TcpStream::connect(endpoint)
        .await
        .context("connect H2 endpoint")?;
    stream.set_nodelay(true)?;
    let observer = H2FrameObserver::client(connection_id)?;
    let (sender, connection) = http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(ObservedH2Io::client(stream, observer.clone())))
        .await
        .context("H2 prior-knowledge handshake")?;
    let driver = tokio::spawn(async move {
        match connection.await {
            Ok(()) => {}
            Err(error) => eprintln!("load-role: H2 connection ended: {error}"),
        }
    });
    observer
        .wait_initial_exchange(require_enable_connect, Duration::from_secs(2))
        .await?;
    Ok((sender, driver, observer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_sse_parser_rejects_trailing_reordered_and_short_data() {
        let corpus = Corpus::fixed();
        let exact = corpus.sse_stream();
        assert!(validate_sse(&exact, &corpus));
        let mut trailing = exact.clone();
        trailing.push(b'x');
        assert!(!validate_sse(&trailing, &corpus));
        let mut wrong = exact;
        wrong[0] = b'x';
        assert!(!validate_sse(&wrong, &corpus));
    }

    #[test]
    fn sse_media_type_is_one_exact_header_without_parameters() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        assert!(exact_sse_content_type(&headers));
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream; charset=utf-8"),
        );
        assert!(!exact_sse_content_type(&headers));
        headers.remove(http::header::CONTENT_TYPE);
        assert!(!exact_sse_content_type(&headers));
        headers.append(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        headers.append(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        assert!(!exact_sse_content_type(&headers));
    }

    #[test]
    fn upload_uses_exact_sixty_four_source_chunks() {
        let corpus = Corpus::fixed();
        let chunks = corpus.chunks().collect::<Vec<_>>();
        assert_eq!(chunks.len(), 64);
        assert!(chunks
            .iter()
            .all(|chunk| chunk.len() == crate::topology::CHUNK_BYTES));
        assert_eq!(
            chunks.iter().map(|chunk| chunk.len()).sum::<usize>(),
            CORPUS_BYTES
        );
    }

    #[test]
    fn connection_tokens_and_fresh_upload_ledger_fail_closed() {
        let mut headers = http::HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade, CLOSE"));
        assert!(has_connection_token(&headers, "close"));
        assert!(!has_connection_token(&headers, "keep-alive"));

        let mut ledger = empty_connection_ledger(Protocol::H1, Workload::Upload1Mib);
        ledger.planned_connections = 2;
        ledger.socket_creations = 2;
        ledger.connect_attempts = 2;
        ledger.connect_successes = 2;
        ledger.cumulative_connections = 2;
        ledger.requests = 2;
        ledger.responses = 2;
        ledger.close_tokens = 2;
        ledger.response_eos = 2;
        ledger.transport_eof = 2;
        ledger.max_active_connections = 1;
        ledger.max_requests_per_connection = 1;
        validate_connection_ledger(&ledger, 2, 1).expect("exact fresh ledger");
        assert_eq!(ledger.max_requests_per_connection, 1);

        let mut missing_eof = ledger.clone();
        missing_eof.transport_eof = 1;
        assert!(validate_connection_ledger(&missing_eof, 2, 1).is_err());
        let mut hidden_retry = ledger.clone();
        hidden_retry.retry_attempts = 1;
        assert!(validate_connection_ledger(&hidden_retry, 2, 1).is_err());
        let mut reused = ledger;
        reused.cumulative_connections = 1;
        assert!(validate_connection_ledger(&reused, 2, 1).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fresh_h1_upload_accepts_gateway_chunked_response_through_peer_eof() {
        assert_eq!(
            crate::control::role_error_detail_sha256(
                Role::Load,
                RoleErrorClass::Command,
                "fresh H1 response lacks exact Content-Length",
            ),
            "ce137486024aac087e3a522cdb31433c73e92ec473be89ce092e3bafcf572ce5"
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind chunked fixture");
        let address = listener.local_addr().expect("chunked fixture address");
        let operation = operation_id_text(operation_id(1, 0, 0));
        let expected_body = format!("{operation}:{}", CORPUS_BYTES);
        let server_body = expected_body.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept upload");
            let mut received = Vec::new();
            let mut body_start = None;
            while body_start.is_none()
                || received.len() - body_start.unwrap_or(received.len()) < CORPUS_BYTES
            {
                let mut bytes = [0_u8; 16_384];
                let count = stream.read(&mut bytes).await.expect("read upload");
                assert_ne!(count, 0, "upload reached request EOS");
                received.extend_from_slice(&bytes[..count]);
                if body_start.is_none() {
                    body_start = received
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|offset| offset + 4);
                }
            }
            let split = server_body.len() / 2;
            let first = &server_body.as_bytes()[..split];
            let second = &server_body.as_bytes()[split..];
            let head = "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nx-fixture-marker: present\r\n\r\n";
            stream.write_all(head.as_bytes()).await.expect("write head");
            stream
                .write_all(format!("{:x}\r\n", first.len()).as_bytes())
                .await
                .expect("write first size");
            stream.write_all(first).await.expect("write first chunk");
            stream.write_all(b"\r\n").await.expect("end first chunk");
            stream
                .write_all(format!("{:x}\r\n", second.len()).as_bytes())
                .await
                .expect("write second size");
            stream.write_all(second).await.expect("write second chunk");
            stream
                .write_all(b"\r\n0\r\n\r\n")
                .await
                .expect("write response EOS");
            stream.flush().await.expect("flush response");
        });
        let stream = TcpStream::connect(address).await.expect("connect fixture");
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_11)
            .uri("/bench/upload")
            .header(HOST, "public.example")
            .header(CONTENT_LENGTH, "1048576")
            .body(BenchBody::empty())
            .expect("build chunked regression request");
        let outcome = raw_h1_upload_exchange_with_eof_cap(
            stream,
            request,
            &operation,
            &Corpus::fixed(),
            Duration::from_secs(1),
        )
        .await
        .expect("chunked response and peer EOF accepted");
        server.await.expect("chunked fixture task");
        assert!(outcome.status_ok);
        assert!(outcome.eos_ok);
        assert!(outcome.payload_ok);
        assert!(outcome.response_headers_sanitized);
        assert_eq!(outcome.response_bytes, expected_body.len() as u64);
        assert_eq!(outcome.connection.close_tokens, 1);
        assert_eq!(outcome.connection.transport_eof, 1);
    }

    async fn eof_negative(delay: Duration) -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let operation = operation_id_text(operation_id(2, 0, 0));
        let response_body = format!("{operation}:{}", CORPUS_BYTES);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut body_start = None;
            while body_start.is_none()
                || received.len() - body_start.unwrap_or(received.len()) < CORPUS_BYTES
            {
                let mut bytes = [0_u8; 16_384];
                let count = stream.read(&mut bytes).await.unwrap();
                if count == 0 {
                    return;
                }
                received.extend_from_slice(&bytes[..count]);
                if body_start.is_none() {
                    body_start = received
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|offset| offset + 4);
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\nx-fixture-marker: present\r\n\r\n",
                response_body.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(response_body.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(delay).await;
        });
        let stream = TcpStream::connect(address).await?;
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_11)
            .uri("/bench/upload")
            .header(HOST, "public.example")
            .header(CONTENT_LENGTH, "1048576")
            .body(BenchBody::empty())
            .map_err(|error| Error::new(format!("build EOF test request: {error}")))?;
        let result = raw_h1_upload_exchange_with_eof_cap(
            stream,
            request,
            &operation,
            &Corpus::fixed(),
            Duration::from_millis(1),
        )
        .await;
        server.abort();
        if result.is_ok() {
            return Err(Error::new("delayed/no peer EOF was accepted"));
        }
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fresh_h1_rejects_delayed_and_absent_peer_eof_without_local_shutdown() {
        eof_negative(Duration::from_millis(25))
            .await
            .expect("delayed EOF rejected");
        eof_negative(Duration::from_secs(60))
            .await
            .expect("absent EOF rejected");
    }
}
