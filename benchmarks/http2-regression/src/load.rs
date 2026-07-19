//! Persistent H1/H2 load role with exact closed-loop workload validation.

use crate::control::{
    connect_loopback, ConnectionLedger, ConnectionPolicy, ControlBody, ControlContext, LoadProof,
    LoadResult, LoadTarget, Role,
};
use crate::fixture::BenchBody;
use crate::linux::{clock_ns, process_identity, ClockKind};
use crate::schema::Workload;
use crate::session::{USER_EMAIL, USER_ID};
use crate::topology::{
    masked_ping, operation_id, operation_id_text, parse_unmasked_pong, planned_connection_id,
    websocket_accept, Corpus, Protocol, CORPUS_BYTES, SSE_EVENTS,
};
use crate::{Error, Result, ResultContext};
use bytes::Bytes;
use http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, COOKIE, HOST, ORIGIN, PROXY_AUTHORIZATION,
    SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION, SET_COOKIE, UPGRADE,
};
use http::{HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;

trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> TunnelIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

enum HttpSender {
    H1(http1::SendRequest<BenchBody>),
    H2(http2::SendRequest<BenchBody>),
}

impl HttpSender {
    async fn send(&mut self, request: Request<BenchBody>) -> Result<Response<Incoming>> {
        match self {
            Self::H1(sender) => {
                sender.ready().await.context("H1 sender ready")?;
                sender
                    .send_request(request)
                    .await
                    .context("send H1 request")
            }
            Self::H2(sender) => {
                sender.ready().await.context("H2 sender ready")?;
                sender
                    .send_request(request)
                    .await
                    .context("send H2 request")
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
    phase_sequences: BTreeMap<u16, u64>,
}

struct LoadSession {
    lanes: Vec<Lane>,
    protocol: Protocol,
    workload: Workload,
    physical_connections: u64,
    fresh_tracker: Option<Arc<FreshConnectionTracker>>,
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
    response_headers_sanitized: bool,
    connection: OperationConnection,
}

#[derive(Debug, Default)]
struct OperationConnection {
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

pub async fn run_load_role(context: ControlContext, control_address: SocketAddr) -> Result<()> {
    let mut control = connect_loopback(control_address, context.clone()).await?;
    control
        .send(ControlBody::Hello {
            role: Role::Load,
            identity: process_identity(std::process::id())?,
        })
        .await?;
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
                if session.is_some() || workload != context.cell.workload {
                    return Err(Error::new("load session duplicate or cell mismatch"));
                }
                let preparation = async {
                    let endpoint = match target {
                        LoadTarget::Gateway => gateway_address.as_deref().ok_or_else(|| {
                            Error::new("gateway load target has no gateway address")
                        })?,
                        LoadTarget::Direct => &fixture_address,
                    };
                    let endpoint = crate::control::parse_loopback_address(endpoint)?;
                    let mut prepared = LoadSession::connect(
                        target,
                        protocol,
                        workload,
                        endpoint,
                        cookie_header,
                        context.cell.concurrency,
                    )
                    .await?;
                    let proof = prepared.prepare(warmup_operations).await?;
                    Ok::<_, Error>((prepared, proof))
                }
                .await;
                match preparation {
                    Ok((prepared, proof)) => {
                        session = Some(prepared);
                        control.send(ControlBody::Prepared { proof }).await?;
                    }
                    Err(error) => {
                        control
                            .send(ControlBody::RoleError {
                                class: "load-preparation-blocked".to_owned(),
                                message: error.to_string(),
                            })
                            .await?;
                        return Err(error);
                    }
                }
            }
            ControlBody::Measure { phase, operations } => {
                let prepared = session
                    .as_mut()
                    .ok_or_else(|| Error::new("load Measure before Prepare"))?;
                match prepared.run_batch(phase, operations).await {
                    Ok(result) => control.send(ControlBody::Measured { result }).await?,
                    Err(error) => {
                        control
                            .send(ControlBody::RoleError {
                                class: "load-measurement-blocked".to_owned(),
                                message: error.to_string(),
                            })
                            .await?;
                        return Err(error);
                    }
                }
            }
            ControlBody::MeasureCount {
                phase,
                operations,
                retain_latencies,
            } => {
                let prepared = session
                    .as_mut()
                    .ok_or_else(|| Error::new("load MeasureCount before Prepare"))?;
                match prepared
                    .run_batch_with_latencies(phase, operations, retain_latencies)
                    .await
                {
                    Ok(result) => control.send(ControlBody::Measured { result }).await?,
                    Err(error) => {
                        control
                            .send(ControlBody::RoleError {
                                class: "load-count-window-blocked".to_owned(),
                                message: error.to_string(),
                            })
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
                let prepared = session
                    .as_mut()
                    .ok_or_else(|| Error::new("load MeasureDuration before Prepare"))?;
                match prepared
                    .run_duration(phase, duration_ns, retain_latencies)
                    .await
                {
                    Ok(result) => control.send(ControlBody::Measured { result }).await?,
                    Err(error) => {
                        control
                            .send(ControlBody::RoleError {
                                class: "load-fixed-window-blocked".to_owned(),
                                message: error.to_string(),
                            })
                            .await?;
                        return Err(error);
                    }
                }
            }
            ControlBody::Stop => {
                drop(session.take());
                control
                    .send(ControlBody::Stopped { role: Role::Load })
                    .await?;
                return Ok(());
            }
            other => {
                return Err(Error::new(format!(
                    "load received unexpected control message: {other:?}"
                )))
            }
        }
    }
}

impl LoadSession {
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
                        let (sender, driver) = open_h1(endpoint).await?;
                        drivers.push(driver);
                        LaneTransport::Http(HttpSender::H1(sender))
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
                        phase_sequences: BTreeMap::new(),
                    });
                }
            }
            Protocol::H2 => {
                let (sender, driver) = open_h2(endpoint).await?;
                drivers.push(driver);
                for lane in 0..concurrency {
                    lanes.push(Lane {
                        id: lane,
                        target,
                        protocol,
                        workload,
                        cookie_header: cookie_header.clone(),
                        authority: authority.clone(),
                        corpus: Arc::clone(&corpus),
                        transport: LaneTransport::Http(HttpSender::H2(sender.clone())),
                        phase_sequences: BTreeMap::new(),
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
            drivers,
        })
    }

    async fn prepare(&mut self, warmup_operations: u64) -> Result<LoadProof> {
        if self.workload == Workload::WebSocket {
            self.open_all_websockets().await?;
            return Ok(LoadProof {
                downstream_protocol: self.protocol,
                physical_connections: self.physical_connections,
                h2_settings_proved: self.protocol == Protocol::H2,
                extended_connect_proved: self.protocol == Protocol::H2,
                warmup_operations: 0,
                tunnels: self.lanes.len() as u64,
                last_operation_id: operation_id_text(operation_id(0, 0, 0)),
                request_bytes: 0,
                response_bytes: 0,
                connection_ledger: websocket_connection_ledger(
                    self.protocol,
                    self.physical_connections,
                    self.lanes.len() as u64,
                ),
            });
        }
        let count = warmup_operations.max(u64::try_from(self.lanes.len()).unwrap_or(u64::MAX));
        let result = self.run_batch(1, count).await?;
        Ok(LoadProof {
            downstream_protocol: self.protocol,
            physical_connections: if self.fresh_tracker.is_some() {
                result.connection_ledger.cumulative_connections
            } else {
                self.physical_connections
            },
            h2_settings_proved: self.protocol == Protocol::H2,
            extended_connect_proved: false,
            warmup_operations: result.operations_completed,
            tunnels: 0,
            last_operation_id: result.last_operation_id,
            request_bytes: result.request_bytes,
            response_bytes: result.response_bytes,
            connection_ledger: result.connection_ledger,
        })
    }

    async fn open_all_websockets(&mut self) -> Result<()> {
        let lanes = std::mem::take(&mut self.lanes);
        let mut tasks = Vec::with_capacity(lanes.len());
        for lane in lanes {
            tasks.push(tokio::spawn(async move { open_websocket(lane).await }));
        }
        let mut restored = Vec::with_capacity(tasks.len());
        for task in tasks {
            restored.push(task.await.context("join WebSocket handshake lane")??);
        }
        restored.sort_by_key(|lane| lane.id);
        self.lanes = restored;
        Ok(())
    }

    async fn run_batch(&mut self, phase: u16, operations: u64) -> Result<LoadResult> {
        self.run_batch_with_latencies(phase, operations, true).await
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
        let lanes = std::mem::take(&mut self.lanes);
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
        for task in tasks {
            let (lane, mut lane_outcomes) = task.await.context("join load lane")??;
            restored.push(lane);
            outcomes.append(&mut lane_outcomes);
        }
        let window_end_ns = clock_ns(ClockKind::Monotonic)?;
        restored.sort_by_key(|lane| lane.id);
        self.lanes = restored;
        if outcomes.len() as u64 != operations {
            return Err(Error::new("load batch quota/completion mismatch"));
        }
        self.finish_result(
            outcomes,
            lane_count,
            window_start_ns,
            None,
            window_end_ns,
            retain_latencies,
        )
    }

    async fn run_duration(
        &mut self,
        phase: u16,
        duration_ns: u64,
        retain_latencies: bool,
    ) -> Result<LoadResult> {
        if !(5_000_000_000..=30_000_000_000).contains(&duration_ns) {
            return Err(Error::new(
                "fixed measurement duration must be within 5..=30 seconds",
            ));
        }
        let lane_count =
            u64::try_from(self.lanes.len()).map_err(|_| Error::new("lane count overflow"))?;
        if let Some(tracker) = &self.fresh_tracker {
            tracker.reset_phase()?;
        }
        let lanes = std::mem::take(&mut self.lanes);
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
        for task in tasks {
            let (lane, mut lane_outcomes) = task.await.context("join fixed-window load lane")??;
            restored.push(lane);
            outcomes.append(&mut lane_outcomes);
        }
        let window_end_ns = clock_ns(ClockKind::Monotonic)?;
        restored.sort_by_key(|lane| lane.id);
        self.lanes = restored;
        if outcomes.is_empty() {
            return Err(Error::new("fixed measurement completed zero operations"));
        }
        self.finish_result(
            outcomes,
            lane_count,
            window_start_ns,
            Some(window_deadline_ns),
            window_end_ns,
            retain_latencies,
        )
    }

    fn finish_result(
        &self,
        mut outcomes: Vec<OperationOutcome>,
        lane_count: u64,
        window_start_ns: u64,
        window_deadline_ns: Option<u64>,
        window_end_ns: u64,
        retain_latencies: bool,
    ) -> Result<LoadResult> {
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
        let mut ledger = empty_connection_ledger(self.protocol, self.workload);
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
            add_connection_outcome(&mut ledger, &mut connection_hasher, outcome)?;
        }
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
        validate_connection_ledger(&mut ledger, operations, lane_count)?;
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
        Ok(LoadResult {
            protocol: self.protocol,
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
            response_headers_sanitized: outcomes
                .iter()
                .all(|outcome| outcome.response_headers_sanitized),
            retries: 0,
            latencies_ns: latencies,
            connection_ledger: ledger,
        })
    }
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
        reuse_attempts: 0,
        reconnect_attempts: 0,
        retry_attempts: 0,
        operation_connection_hash_sha256: String::new(),
    }
}

fn websocket_connection_ledger(
    protocol: Protocol,
    physical_connections: u64,
    tunnels: u64,
) -> ConnectionLedger {
    let mut ledger = empty_connection_ledger(protocol, Workload::WebSocket);
    ledger.planned_connections = physical_connections;
    ledger.socket_creations = physical_connections;
    ledger.connect_attempts = physical_connections;
    ledger.connect_successes = physical_connections;
    ledger.cumulative_connections = physical_connections;
    ledger.requests = tunnels;
    ledger.responses = tunnels;
    ledger.active_connections = physical_connections;
    ledger.max_active_connections = physical_connections;
    ledger.max_requests_per_connection = if protocol == Protocol::H1 { 1 } else { tunnels };
    ledger.h2_streams = if protocol == Protocol::H2 { tunnels } else { 0 };
    let mut hasher = Sha256::new();
    hasher.update(protocol.label().as_bytes());
    hasher.update(physical_connections.to_be_bytes());
    hasher.update(tunnels.to_be_bytes());
    ledger.operation_connection_hash_sha256 = format!("{:x}", hasher.finalize());
    ledger
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
    ledger: &mut ConnectionLedger,
    operations: u64,
    concurrency: u64,
) -> Result<()> {
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
            ledger.max_requests_per_connection = 1;
            if exact.iter().any(|count| *count != operations)
                || ledger.keep_alive_tokens != 0
                || ledger.active_connections != 0
                || ledger.max_active_connections == 0
                || ledger.max_active_connections > concurrency
                || ledger.reuse_attempts != 0
                || ledger.reconnect_attempts != 0
                || ledger.retry_attempts != 0
            {
                return Err(Error::new(
                    "fresh-H1 connection ledger failed exact cumulative reconciliation",
                ));
            }
        }
        ConnectionPolicy::PersistentH1 | ConnectionPolicy::H1UpgradeTunnels => {
            ledger.planned_connections = concurrency;
            ledger.socket_creations = concurrency;
            ledger.connect_attempts = concurrency;
            ledger.connect_successes = concurrency;
            ledger.cumulative_connections = concurrency;
            ledger.active_connections = concurrency;
            ledger.max_active_connections = concurrency;
            ledger.max_requests_per_connection = operations.div_ceil(concurrency);
            if ledger.requests != operations
                || ledger.responses != operations
                || ledger.close_tokens != 0
                || ledger.keep_alive_tokens != 0
                || ledger.response_eos != operations
                || ledger.transport_eof != 0
            {
                return Err(Error::new("persistent-H1 operation ledger mismatch"));
            }
        }
        ConnectionPolicy::PersistentH2 => {
            ledger.planned_connections = 1;
            ledger.socket_creations = 1;
            ledger.connect_attempts = 1;
            ledger.connect_successes = 1;
            ledger.cumulative_connections = 1;
            ledger.active_connections = 1;
            ledger.max_active_connections = 1;
            ledger.max_requests_per_connection = operations;
            if ledger.requests != operations
                || ledger.responses != operations
                || ledger.response_eos != operations
                || ledger.h2_streams != operations
                || ledger.close_tokens != 0
                || ledger.transport_eof != 0
            {
                return Err(Error::new("persistent-H2 operation ledger mismatch"));
            }
        }
        ConnectionPolicy::H2ExtendedConnectStreams => {
            ledger.planned_connections = 1;
            ledger.socket_creations = 1;
            ledger.connect_attempts = 1;
            ledger.connect_successes = 1;
            ledger.cumulative_connections = 1;
            ledger.active_connections = 1;
            ledger.max_active_connections = 1;
            ledger.max_requests_per_connection = operations;
            ledger.h2_streams = concurrency;
            if ledger.requests != operations || ledger.responses != operations {
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

impl Lane {
    fn next_operation(&mut self, phase: u16) -> (u64, String) {
        let sequence = self.phase_sequences.entry(phase).or_insert(0);
        let current = *sequence;
        *sequence = sequence.saturating_add(1);
        let id = operation_id(phase, self.id, current);
        (current, operation_id_text(id))
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
        let start = clock_ns(ClockKind::Monotonic)?;
        if deadline_ns.is_some_and(|deadline| start >= deadline) {
            return Ok(None);
        }
        let stored = self.phase_sequences.entry(phase).or_insert(0);
        if *stored != sequence {
            return Err(Error::new("lane operation sequence changed before start"));
        }
        *stored = stored
            .checked_add(1)
            .ok_or_else(|| Error::new("lane operation sequence overflow"))?;
        let mut outcome = if self.workload == Workload::WebSocket {
            self.run_websocket_operation(phase, sequence, operation_text)
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
        let mut outcome = match &mut self.transport {
            LaneTransport::Http(sender) => {
                let response = sender.send(request).await?;
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
        phase: u16,
        sequence: u64,
        operation_text: String,
    ) -> Result<OperationOutcome> {
        let packed = (u64::from(phase) << 32) | (sequence & 0xffff_ffff);
        let id = operation_id(phase, self.id, sequence);
        let frame = masked_ping(&self.corpus, id, self.id, packed);
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
        let expected_payload = crate::topology::parse_masked_ping(&frame)?;
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
            response_headers_sanitized: true,
            connection: OperationConnection {
                requests: 1,
                responses: 1,
                response_eos: 1,
                ..OperationConnection::default()
            },
        })
    }
}

async fn open_websocket(mut lane: Lane) -> Result<Lane> {
    let (_, operation_text) = lane.next_operation(0);
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
        .header("x-amg-bench-op", operation_text)
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
    let sender = match &mut lane.transport {
        LaneTransport::Http(sender) => sender,
        LaneTransport::FreshH1 { .. } => {
            return Err(Error::new("WebSocket cannot use fresh-H1 upload transport"))
        }
        LaneTransport::WebSocket(_) => return Err(Error::new("duplicate WebSocket open")),
    };
    let mut response = sender.send(request).await?;
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
    Ok(lane)
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
        response_headers_sanitized: headers_sanitized,
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
    // EOF all happen inside the caller's operation timer.
    let socket = if endpoint.is_ipv4() {
        TcpSocket::new_v4().context("create fresh H1 socket")?
    } else {
        TcpSocket::new_v6().context("create fresh H1 socket")?
    };
    let _active = tracker.acquire();
    let stream = socket
        .connect(endpoint)
        .await
        .context("sole fresh H1 connect attempt")?;
    stream.set_nodelay(true)?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .context("fresh H1 client handshake")?;
    let driver = tokio::spawn(async move {
        connection
            .await
            .map_err(|error| Error::new(format!("fresh H1 connection driver: {error}")))
    });
    sender.ready().await.context("fresh H1 sender ready")?;
    let response = sender
        .send_request(request)
        .await
        .context("send sole fresh H1 upload request")?;
    let mut outcome = validate_response(
        workload,
        Protocol::H1,
        operation_text,
        response,
        corpus,
        true,
    )
    .await?;
    drop(sender);
    driver.await.context("join fresh H1 connection driver")??;
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

async fn open_h1(endpoint: SocketAddr) -> Result<(http1::SendRequest<BenchBody>, JoinHandle<()>)> {
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
    Ok((sender, driver))
}

async fn open_h2(endpoint: SocketAddr) -> Result<(http2::SendRequest<BenchBody>, JoinHandle<()>)> {
    if !endpoint.ip().is_loopback() {
        return Err(Error::new("H2 client target is not loopback"));
    }
    let stream = TcpStream::connect(endpoint)
        .await
        .context("connect H2 endpoint")?;
    stream.set_nodelay(true)?;
    let (sender, connection) = http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(stream))
        .await
        .context("H2 prior-knowledge handshake")?;
    let driver = tokio::spawn(async move {
        match connection.await {
            Ok(()) => {}
            Err(error) => eprintln!("load-role: H2 connection ended: {error}"),
        }
    });
    Ok((sender, driver))
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
        validate_connection_ledger(&mut ledger, 2, 1).expect("exact fresh ledger");
        assert_eq!(ledger.max_requests_per_connection, 1);

        let mut missing_eof = ledger.clone();
        missing_eof.transport_eof = 1;
        assert!(validate_connection_ledger(&mut missing_eof, 2, 1).is_err());
        let mut hidden_retry = ledger.clone();
        hidden_retry.retry_attempts = 1;
        assert!(validate_connection_ledger(&mut hidden_retry, 2, 1).is_err());
        let mut reused = ledger;
        reused.cumulative_connections = 1;
        assert!(validate_connection_ledger(&mut reused, 2, 1).is_err());
    }
}
