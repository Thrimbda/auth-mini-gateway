//! Versioned control protocol over inherited Unix socket capabilities.

#![allow(unsafe_code)]

pub use crate::error::{RoleErrorCode, RoleErrorStage};
use crate::json;
use crate::linux::{process_identity, validate_identity, ProcessIdentity};
use crate::schema::{Arm, Cell, Workload};
use crate::topology::Protocol;
use crate::wire::H2WireEvidence;
use crate::{Error, Result, ResultContext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::os::fd::{AsFd as _, AsRawFd as _, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

pub const CONTROL_SCHEMA: &str = "amg-http2-perf/control/v2";
pub const CONTROL_MAX_BYTES: usize = 1_048_576;
pub const CONTROL_IO_CAP: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Orchestrator,
    Fixture,
    Load,
    Sampler,
    Gateway,
}

impl Role {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Orchestrator => "orchestrator",
            Self::Fixture => "fixture",
            Self::Load => "load",
            Self::Sampler => "sampler",
            Self::Gateway => "gateway",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlContext {
    pub run_id: String,
    pub cell: Cell,
    pub arm: Arm,
    pub block: u64,
    pub orchestrator: ProcessIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEnvelope {
    pub schema: String,
    pub run_id: String,
    pub cell: Cell,
    pub arm: Arm,
    pub block: u64,
    pub sequence: u64,
    pub body: ControlBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ControlBody {
    Hello {
        role: Role,
        identity: ProcessIdentity,
    },
    Authenticate {
        challenge_sha256: String,
    },
    Authenticated {
        role: Role,
        identity: ProcessIdentity,
        response_sha256: String,
    },
    AuthenticationAccepted {
        role: Role,
        identity: ProcessIdentity,
    },
    Ready {
        role: Role,
        data_address: Option<String>,
        tripwire_address: Option<String>,
    },
    ConfigureFixture {
        target: LoadTarget,
        workload: Workload,
        expected_protocol: Protocol,
        corpus_sha256: String,
    },
    FixtureConfigured,
    PrepareLoad {
        target: LoadTarget,
        workload: Workload,
        protocol: Protocol,
        gateway_address: Option<String>,
        fixture_address: String,
        cookie_header: Option<String>,
        warmup_operations: u64,
        websocket_settle: bool,
    },
    Prepared {
        proof: LoadProof,
    },
    PrepareOperationCorpus {
        phase: u16,
        operation_ceiling: u64,
    },
    OperationCorpusPrepared {
        phase: u16,
        operation_ceiling: u64,
    },
    Measure {
        phase: u16,
        operations: u64,
    },
    MeasureCount {
        phase: u16,
        operations: u64,
        retain_latencies: bool,
    },
    MeasureDuration {
        phase: u16,
        duration_ns: u64,
        retain_latencies: bool,
    },
    MaterializeDuration {
        phase: u16,
        duration_ns: u64,
    },
    MaterializeWave {
        phase: u16,
        operations: u64,
    },
    Measured {
        result: LoadResult,
    },
    FixtureSnapshot,
    FixtureObserved {
        result: FixtureResult,
    },
    RegisterProcesses {
        processes: Vec<ObservedProcess>,
        evidence_root: Option<String>,
    },
    ProcessesRegistered,
    Inventory,
    InventoryObserved {
        inventories: Vec<ThreadInventory>,
    },
    MaterializationInventory,
    MaterializationInventoryObserved {
        checkpoint: InventoryCheckpoint,
    },
    ObserveInventoryStability {
        expected_inventory_signature_sha256: String,
        expected_tid_signature_sha256: String,
        duration_ns: u64,
    },
    InventoryStabilityObserved {
        observation: InventoryStabilityObservation,
    },
    WaitWebsocketRetirement {
        gateway_pre_auth_tids: Vec<ThreadIdentity>,
        keepalive_ns: u64,
        stability_ns: u64,
        cap_ns: u64,
    },
    WebsocketRetired {
        elapsed_ns: u64,
        inventories: Vec<ThreadInventory>,
    },
    Freeze,
    Frozen {
        report: SamplerReport,
    },
    Release,
    Released {
        monotonic_ns: u64,
    },
    FinalSample,
    Sampled {
        report: SamplerReport,
    },
    Stop,
    Stopped {
        role: Role,
    },
    RoleError {
        role: Role,
        class: RoleErrorClass,
        stage: RoleErrorStage,
        code: RoleErrorCode,
        detail_sha256: String,
        attempt: Option<AttemptEvidence>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoleErrorClass {
    Startup,
    Command,
    Panic,
}

impl RoleErrorClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Command => "command",
            Self::Panic => "panic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptEvidence {
    pub starts: u64,
    pub successes: u64,
    pub failures: u64,
    pub reconnects: u64,
    pub retries: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadTarget {
    Gateway,
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionPolicy {
    PersistentH1,
    FreshH1PerOperation,
    PersistentH2,
    H1UpgradeTunnels,
    H2ExtendedConnectStreams,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionLedger {
    pub policy: ConnectionPolicy,
    pub planned_connections: u64,
    pub socket_creations: u64,
    pub connect_attempts: u64,
    pub connect_successes: u64,
    pub failed_connect_attempts: u64,
    pub cumulative_connections: u64,
    pub requests: u64,
    pub responses: u64,
    pub close_tokens: u64,
    pub keep_alive_tokens: u64,
    pub response_eos: u64,
    pub transport_eof: u64,
    pub active_connections: u64,
    pub max_active_connections: u64,
    pub max_requests_per_connection: u64,
    pub h2_streams: u64,
    pub active_h2_streams: u64,
    pub max_active_h2_streams: u64,
    pub first_h2_stream_id: Option<u32>,
    pub last_h2_stream_id: Option<u32>,
    pub h2_stream_sequence_sha256: String,
    pub reuse_attempts: u64,
    pub reconnect_attempts: u64,
    pub retry_attempts: u64,
    pub operation_connection_hash_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedProcess {
    pub role: Role,
    pub identity: ProcessIdentity,
    pub executable_sha256: String,
    pub broad_cpus: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadIdentity {
    pub pid: u32,
    pub tid: u32,
    pub start_time_ticks: u64,
    pub comm: String,
    pub assigned_cpu: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadInventory {
    pub role: Role,
    pub executable_sha256: String,
    pub threads: Vec<ThreadIdentity>,
    pub semantic_signature_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryCheckpoint {
    pub monotonic_ns: u64,
    pub lifecycle_events: u64,
    pub inventory_signature_sha256: String,
    pub tid_signature_sha256: String,
    pub inventories: Vec<ThreadInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryStabilityObservation {
    pub start_ns: u64,
    pub end_ns: u64,
    pub requested_duration_ns: u64,
    pub polls: u64,
    pub stable: bool,
    pub initial: InventoryCheckpoint,
    pub final_checkpoint: InventoryCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePoint {
    pub role: Role,
    pub pid: u32,
    pub start_time_ticks: u64,
    pub user_ticks: u64,
    pub system_ticks: u64,
    pub major_faults: u64,
    pub vm_hwm_kib: Option<u64>,
    pub vm_rss_kib: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuAttribution {
    pub cpu: u16,
    pub start_ns: u64,
    pub end_ns: u64,
    pub capacity_ticks: u64,
    pub scheduled_ticks: u64,
    pub role_runtime_lower_ticks: u64,
    pub role_runtime_upper_ticks: u64,
    pub attribution_uncertainty_ticks: u64,
    pub external_upper_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResidual {
    pub role: Role,
    pub start_ns: u64,
    pub end_ns: u64,
    pub process_runtime_lower_ticks: u64,
    pub process_runtime_upper_ticks: u64,
    pub known_tid_runtime_lower_ticks: u64,
    pub known_tid_runtime_upper_ticks: u64,
    pub u_role_lower_ticks: u64,
    pub u_role_upper_ticks: u64,
    pub signed_residual_lower_ticks: i64,
    pub signed_residual_upper_ticks: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoiseScopeEvidence {
    pub attribution_phase: String,
    pub interval_kind: String,
    pub scope: String,
    pub role: String,
    pub cpus: Vec<u16>,
    pub start_ns: u64,
    pub end_ns: u64,
    pub capacity_ticks: u64,
    pub external_upper_ticks: u64,
    pub limit_basis_points: u16,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplerReport {
    pub monotonic_ns: u64,
    pub boottime_ns: u64,
    pub frozen: bool,
    pub inventories: Vec<ThreadInventory>,
    pub resources: Vec<ResourcePoint>,
    pub attribution: Vec<CpuAttribution>,
    pub bracket_attribution: Vec<CpuAttribution>,
    pub dynamic_attribution: Vec<CpuAttribution>,
    pub bracket_samples_100ms: u64,
    pub boundary_interval_max_ns: u64,
    pub residuals: Vec<RuntimeResidual>,
    pub dynamic_residuals: Vec<RuntimeResidual>,
    pub noise_scopes: Vec<NoiseScopeEvidence>,
    pub lifecycle_events: u64,
    pub births_before_freeze: u64,
    pub deaths_before_freeze: u64,
    pub births_after_freeze: u64,
    pub deaths_after_freeze: u64,
    pub migrations_after_freeze: u64,
    pub lifecycle_poll_max_ns: u64,
    pub post_freeze_change: Option<String>,
    pub tctl_millidegrees: Option<u64>,
    pub tctl_start_millidegrees: Option<u64>,
    pub tctl_max_millidegrees: Option<u64>,
    pub median_frequency_khz: Option<u64>,
    pub major_faults_delta: u64,
    pub swap_in: u64,
    pub swap_out: u64,
    pub cpu_psi_some_us: u64,
    pub memory_psi_full_us: u64,
    pub io_psi_full_us: u64,
    pub realtime_samples: u64,
    pub realtime_discontinuities: u64,
    pub realtime_comparable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadProof {
    pub downstream_protocol: Protocol,
    pub physical_connections: u64,
    pub h2_settings_proved: bool,
    pub extended_connect_proved: bool,
    pub warmup_operations: u64,
    pub warmup_end_ns: u64,
    pub tunnels: u64,
    pub first_operation_id: String,
    pub last_operation_id: String,
    pub operation_hash_sha256: String,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub connection_ledger: ConnectionLedger,
    pub h2_wire: Vec<H2WireEvidence>,
    pub attempts: AttemptEvidence,
    pub lane_quotas: Vec<u64>,
    pub lane_completions: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadResult {
    pub protocol: Protocol,
    pub operations_started: u64,
    pub operations_completed: u64,
    pub operations_completed_by_deadline: u64,
    pub window_start_ns: u64,
    pub window_deadline_ns: Option<u64>,
    pub window_end_ns: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub first_operation_id: String,
    pub last_operation_id: String,
    pub operation_hash_sha256: String,
    pub status_ok: bool,
    pub eos_ok: bool,
    pub payload_ok: bool,
    pub sse_content_type_ok: bool,
    pub response_headers_sanitized: bool,
    pub retries: u64,
    pub latencies_ns: Vec<u64>,
    pub connection_ledger: ConnectionLedger,
    pub h2_wire: Vec<H2WireEvidence>,
    pub attempts: AttemptEvidence,
    pub lane_quotas: Vec<u64>,
    pub lane_completions: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointObservation {
    pub operation_id: String,
    pub protocol: Protocol,
    pub connection_id: u64,
    pub stream_id: Option<u64>,
    pub method: String,
    pub path: String,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub status: u16,
    pub request_eos: bool,
    pub response_eos: bool,
    pub payload_ok: bool,
    pub identity_ok: bool,
    pub request_headers_sanitized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureResult {
    pub target: LoadTarget,
    pub expected_protocol: Protocol,
    pub physical_connections: u64,
    pub active_connections: u64,
    pub max_active_connections: u64,
    pub max_requests_per_connection: u64,
    pub tripwire_connections: u64,
    pub tripwire_bytes: u64,
    pub duplicate_operations: u64,
    pub unknown_requests: u64,
    pub observations: Vec<EndpointObservation>,
    pub operation_hash_sha256: String,
    pub h2_wire: Vec<H2WireEvidence>,
}

pub struct FramedControl {
    stream: UnixStream,
    context: ControlContext,
    next_send: u64,
    next_receive: u64,
    local_role: Option<Role>,
    authenticated: bool,
    ready_sent: bool,
    terminal_sent: bool,
    failure_stage: RoleErrorStage,
}

impl FramedControl {
    pub fn new(stream: UnixStream, context: ControlContext) -> Result<Self> {
        // Linux socketpair credentials are captured when the pair is created,
        // before fork/exec. Both endpoints must therefore name the exact
        // orchestrator creator; the child PID is authenticated separately by
        // the challenge and exact /proc identity checks.
        let credentials = stream.peer_cred()?;
        let expected_pid = i32::try_from(context.orchestrator.pid)
            .map_err(|_| Error::new("orchestrator PID does not fit peer credentials"))?;
        // SAFETY: these libc calls have no preconditions and only read process
        // credentials.
        let (effective_uid, effective_gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        if credentials.uid() != effective_uid
            || credentials.gid() != effective_gid
            || credentials.pid() != Some(expected_pid)
        {
            return Err(Error::new(
                "inherited control peer credentials differ from the orchestrator creator",
            ));
        }
        validate_identity(&context.orchestrator)?;
        let current = process_identity(std::process::id())?;
        if current.pid != context.orchestrator.pid && current.parent_pid != context.orchestrator.pid
        {
            return Err(Error::new(
                "inherited control process is neither orchestrator nor direct role child",
            ));
        }
        context.cell.validate()?;
        if context.run_id.is_empty() || context.run_id.len() > 128 {
            return Err(Error::new("invalid control run ID"));
        }
        Ok(Self {
            stream,
            context,
            next_send: 0,
            next_receive: 0,
            local_role: None,
            authenticated: false,
            ready_sent: false,
            terminal_sent: false,
            failure_stage: RoleErrorStage::Startup,
        })
    }

    pub async fn send(&mut self, body: ControlBody) -> Result<()> {
        if self.terminal_sent {
            return Err(Error::new(
                "control send attempted after terminal role frame",
            ));
        }
        if matches!(&body, ControlBody::RoleError { .. }) && !self.authenticated {
            return Err(Error::new(
                "unauthenticated terminal role frame is forbidden",
            ));
        }
        match &body {
            ControlBody::Ready { role, .. }
                if self.local_role != Some(*role) || !self.authenticated || self.ready_sent =>
            {
                return Err(Error::new("role Ready lifecycle is invalid"));
            }
            ControlBody::RoleError { role, .. } if self.local_role != Some(*role) => {
                return Err(Error::new("terminal role frame role differs"));
            }
            _ => {}
        }
        let envelope = ControlEnvelope {
            schema: CONTROL_SCHEMA.to_owned(),
            run_id: self.context.run_id.clone(),
            cell: self.context.cell,
            arm: self.context.arm,
            block: self.context.block,
            sequence: self.next_send,
            body,
        };
        let bytes = json::canonical_bytes(&envelope)?;
        if bytes.len() > CONTROL_MAX_BYTES {
            return Err(Error::new("control frame exceeds 1 MiB"));
        }
        let length =
            u32::try_from(bytes.len()).map_err(|_| Error::new("control length overflow"))?;
        timeout(CONTROL_IO_CAP, async {
            self.stream.write_all(&length.to_be_bytes()).await?;
            self.stream.write_all(&bytes).await?;
            self.stream.flush().await
        })
        .await
        .map_err(|_| Error::new("bounded control send timed out"))??;
        self.next_send = self
            .next_send
            .checked_add(1)
            .ok_or_else(|| Error::new("control send sequence overflow"))?;
        match &envelope.body {
            ControlBody::Ready { role, .. } => {
                debug_assert_eq!(self.local_role, Some(*role));
                self.ready_sent = true;
            }
            ControlBody::RoleError { role, .. } => {
                debug_assert_eq!(self.local_role, Some(*role));
                self.terminal_sent = true;
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<ControlBody> {
        let length = timeout(CONTROL_IO_CAP, self.stream.read_u32())
            .await
            .map_err(|_| Error::new("bounded control receive timed out"))??
            as usize;
        if length == 0 || length > CONTROL_MAX_BYTES {
            return Err(Error::new("invalid control frame length"));
        }
        let mut bytes = vec![0_u8; length];
        timeout(CONTROL_IO_CAP, self.stream.read_exact(&mut bytes))
            .await
            .map_err(|_| Error::new("bounded control payload receive timed out"))??;
        let envelope: ControlEnvelope = json::from_slice_strict(&bytes)?;
        if envelope.schema != CONTROL_SCHEMA
            || envelope.run_id != self.context.run_id
            || envelope.cell != self.context.cell
            || envelope.arm != self.context.arm
            || envelope.block != self.context.block
        {
            return Err(Error::new("stale or cross-run control envelope"));
        }
        if envelope.sequence != self.next_receive {
            return Err(Error::new(format!(
                "control sequence mismatch: expected {}, got {}",
                self.next_receive, envelope.sequence
            )));
        }
        self.next_receive = self
            .next_receive
            .checked_add(1)
            .ok_or_else(|| Error::new("control receive sequence overflow"))?;
        Ok(envelope.body)
    }

    pub async fn authenticate_inherited_role(
        &mut self,
        role: Role,
        identity: ProcessIdentity,
    ) -> Result<()> {
        self.failure_stage = RoleErrorStage::Authenticate;
        self.send(ControlBody::Hello {
            role,
            identity: identity.clone(),
        })
        .await?;
        let challenge_sha256 = match self.receive().await? {
            ControlBody::Authenticate { challenge_sha256 } => challenge_sha256,
            other => {
                return Err(Error::new(format!(
                    "inherited control expected authentication challenge, got {other:?}"
                )))
            }
        };
        let response_sha256 =
            authentication_response(&challenge_sha256, &self.context, role, &identity)?;
        self.send(ControlBody::Authenticated {
            role,
            identity: identity.clone(),
            response_sha256,
        })
        .await?;
        match self.receive().await? {
            ControlBody::AuthenticationAccepted {
                role: accepted_role,
                identity: accepted_identity,
            } if accepted_role == role && accepted_identity == identity => {
                self.local_role = Some(role);
                self.authenticated = true;
                self.failure_stage = RoleErrorStage::Startup;
                Ok(())
            }
            other => Err(Error::new(format!(
                "inherited control expected authentication acceptance, got {other:?}"
            ))),
        }
    }

    pub async fn send_terminal_error(
        &mut self,
        class: RoleErrorClass,
        stage: RoleErrorStage,
        code: RoleErrorCode,
        detail: &str,
        attempt: Option<AttemptEvidence>,
    ) -> Result<()> {
        let role = self
            .local_role
            .ok_or_else(|| Error::new("terminal role frame lacks authenticated role"))?;
        self.send(ControlBody::RoleError {
            role,
            class,
            stage,
            code,
            detail_sha256: role_error_detail_sha256(role, class, detail),
            attempt,
        })
        .await
    }

    #[must_use]
    pub const fn can_send_terminal_error(&self) -> bool {
        self.authenticated && !self.terminal_sent
    }

    #[must_use]
    pub const fn failure_class(&self) -> RoleErrorClass {
        if self.ready_sent {
            RoleErrorClass::Command
        } else {
            RoleErrorClass::Startup
        }
    }

    pub fn mark_failure_stage(&mut self, stage: RoleErrorStage) {
        self.failure_stage = stage;
    }

    #[must_use]
    pub const fn failure_stage(&self) -> RoleErrorStage {
        self.failure_stage
    }

    pub(crate) fn context_clone(&self) -> Result<ControlContext> {
        self.context.cell.validate()?;
        if self.context.run_id.is_empty() || self.context.run_id.len() > 128 {
            return Err(Error::new("invalid control context"));
        }
        Ok(self.context.clone())
    }
}

#[must_use]
pub fn role_error_detail_sha256(role: Role, class: RoleErrorClass, detail: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"amg-http2-perf/role-error-detail/v1\0");
    hasher.update(role.label().as_bytes());
    hasher.update([0]);
    hasher.update(class.label().as_bytes());
    hasher.update([0]);
    hasher.update(detail.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn authentication_response(
    challenge_sha256: &str,
    context: &ControlContext,
    role: Role,
    identity: &ProcessIdentity,
) -> Result<String> {
    crate::schema::validate_non_placeholder_sha256(
        "inherited control challenge",
        challenge_sha256,
    )?;
    context.cell.validate()?;
    if context.run_id.is_empty() || context.run_id.len() > 128 {
        return Err(Error::new("invalid authentication control run ID"));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"amg-http2-perf/inherited-control-auth/v1\0");
    hasher.update(challenge_sha256.as_bytes());
    hasher.update(json::canonical_bytes(context)?);
    hasher.update(role.label().as_bytes());
    hasher.update(identity.pid.to_be_bytes());
    hasher.update(identity.start_time_ticks.to_be_bytes());
    hasher.update(identity.parent_pid.to_be_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn inherited_pair(context: ControlContext) -> Result<(FramedControl, StdUnixStream)> {
    let (parent, child) = StdUnixStream::pair().context("create inherited Unix socketpair")?;
    let parent = move_above_standard_descriptors(parent)?;
    let child = move_above_standard_descriptors(child)?;
    set_cloexec(parent.as_raw_fd(), true)?;
    set_cloexec(child.as_raw_fd(), true)?;
    parent.set_nonblocking(true)?;
    let parent = UnixStream::from_std(parent).context("adopt parent Unix control socket")?;
    Ok((FramedControl::new(parent, context)?, child))
}

fn move_above_standard_descriptors(stream: StdUnixStream) -> Result<StdUnixStream> {
    if stream.as_raw_fd() > libc::STDERR_FILENO {
        return Ok(stream);
    }
    let descriptor = stream
        .as_fd()
        .try_clone_to_owned()
        .context("move inherited control capability above standard descriptors")?;
    drop(stream);
    Ok(StdUnixStream::from(descriptor))
}

pub fn inherited_stdin(context: ControlContext) -> Result<FramedControl> {
    if cloexec(std::io::stdin().as_raw_fd())? {
        return Err(Error::new(
            "inherited control stdin unexpectedly retained CLOEXEC after exec",
        ));
    }
    let descriptor = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .context("clone inherited control capability from stdin")?;
    if !cloexec(descriptor.as_raw_fd())? {
        return Err(Error::new(
            "cloned inherited control capability lacks CLOEXEC",
        ));
    }
    // The duplicate is the only capability used by the role. Mark descriptor
    // zero close-on-exec immediately so a future role descendant cannot inherit
    // the control channel accidentally.
    set_cloexec(std::io::stdin().as_raw_fd(), true)?;
    let stream = StdUnixStream::from(descriptor);
    stream.set_nonblocking(true)?;
    let stream = UnixStream::from_std(stream).context("adopt inherited child control socket")?;
    FramedControl::new(stream, context)
}

pub fn cloexec(fd: RawFd) -> Result<bool> {
    // SAFETY: F_GETFD reads flags for a live descriptor and does not access
    // memory through pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(flags & libc::FD_CLOEXEC != 0)
}

pub fn set_cloexec(fd: RawFd, enabled: bool) -> Result<()> {
    // SAFETY: F_GETFD/F_SETFD operate on a live descriptor and integer flags.
    let current = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if current < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let updated = if enabled {
        current | libc::FD_CLOEXEC
    } else {
        current & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, updated) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub fn parse_loopback_address(value: &str) -> Result<SocketAddr> {
    let address = value
        .parse::<SocketAddr>()
        .context("parse literal loopback socket address")?;
    if !address.ip().is_loopback() {
        return Err(Error::new("non-loopback socket address rejected"));
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::process_identity;
    use crate::schema::Workload;

    fn context() -> ControlContext {
        ControlContext {
            run_id: "test-run".to_owned(),
            cell: Cell {
                workload: Workload::Get,
                concurrency: 1,
            },
            arm: Arm::C22,
            block: 7,
            orchestrator: process_identity(std::process::id()).unwrap(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn framed_control_rejects_cross_run_and_sequence_aliases() {
        let (mut client, server_stream) = inherited_pair(context()).expect("socketpair");
        server_stream.set_nonblocking(true).unwrap();
        let server_stream = UnixStream::from_std(server_stream).unwrap();
        let mut server_control = FramedControl::new(server_stream, context()).unwrap();
        let server = tokio::spawn(async move { server_control.receive().await });
        client.send(ControlBody::Inventory).await.expect("send");
        assert!(matches!(
            server.await.unwrap().unwrap(),
            ControlBody::Inventory
        ));

        let (mut client, server_stream) = inherited_pair(context()).expect("socketpair");
        server_stream.set_nonblocking(true).unwrap();
        let server_stream = UnixStream::from_std(server_stream).unwrap();
        let mut server_control = FramedControl::new(server_stream, context()).unwrap();
        client.next_send = 1;
        client.send(ControlBody::Inventory).await.unwrap();
        assert!(server_control.receive().await.is_err());

        let (mut client, server_stream) = inherited_pair(context()).expect("socketpair");
        server_stream.set_nonblocking(true).unwrap();
        let server_stream = UnixStream::from_std(server_stream).unwrap();
        let mut server_control = FramedControl::new(server_stream, context()).unwrap();
        client.context.run_id = "cross-run".to_owned();
        client.send(ControlBody::Inventory).await.unwrap();
        assert!(server_control.receive().await.is_err());
    }

    #[test]
    fn rejects_non_loopback_control_addresses() {
        assert!(parse_loopback_address("8.8.8.8:53").is_err());
        assert!(parse_loopback_address("127.0.0.1:1234").is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inherited_control_has_no_listener_or_reconnect_surface() {
        let (mut parent, child) = inherited_pair(context()).expect("socketpair");
        assert!(parent.stream.as_raw_fd() > libc::STDERR_FILENO);
        assert!(child.as_raw_fd() > libc::STDERR_FILENO);
        assert!(cloexec(parent.stream.as_raw_fd()).unwrap());
        assert!(cloexec(child.as_raw_fd()).unwrap());
        child.set_nonblocking(true).unwrap();
        let child = UnixStream::from_std(child).unwrap();
        let mut child = FramedControl::new(child, context()).unwrap();
        parent.send(ControlBody::Inventory).await.unwrap();
        assert!(matches!(
            child.receive().await.unwrap(),
            ControlBody::Inventory
        ));
        assert!(child
            .send_terminal_error(
                RoleErrorClass::Startup,
                RoleErrorStage::Startup,
                RoleErrorCode::Authentication,
                "not-authenticated",
                None,
            )
            .await
            .is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inherited_control_authentication_binds_challenge_context_and_process() {
        let (mut parent, child) = inherited_pair(context()).expect("socketpair");
        child.set_nonblocking(true).unwrap();
        let child = UnixStream::from_std(child).unwrap();
        let mut child = FramedControl::new(child, context()).unwrap();
        let identity = process_identity(std::process::id()).unwrap();
        let expected_identity = identity.clone();
        let child_task = tokio::spawn(async move {
            child
                .authenticate_inherited_role(Role::Load, identity)
                .await?;
            child
                .send_terminal_error(
                    RoleErrorClass::Command,
                    RoleErrorStage::Measure,
                    RoleErrorCode::ResponseBodyInvalid,
                    "raw-detail-not-on-wire",
                    None,
                )
                .await
        });
        assert!(matches!(
            parent.receive().await.unwrap(),
            ControlBody::Hello {
                role: Role::Load,
                identity: ref actual,
            } if actual == &expected_identity
        ));
        let challenge = crate::seal::sha256_hex(b"bounded-test-challenge");
        parent
            .send(ControlBody::Authenticate {
                challenge_sha256: challenge.clone(),
            })
            .await
            .unwrap();
        let expected =
            authentication_response(&challenge, &context(), Role::Load, &expected_identity)
                .unwrap();
        assert!(matches!(
            parent.receive().await.unwrap(),
            ControlBody::Authenticated {
                role: Role::Load,
                identity: ref actual,
                ref response_sha256,
            } if actual == &expected_identity && response_sha256 == &expected
        ));
        parent
            .send(ControlBody::AuthenticationAccepted {
                role: Role::Load,
                identity: expected_identity.clone(),
            })
            .await
            .unwrap();
        assert!(matches!(
            parent.receive().await.unwrap(),
            ControlBody::RoleError {
                role: Role::Load,
                class: RoleErrorClass::Command,
                stage: RoleErrorStage::Measure,
                code: RoleErrorCode::ResponseBodyInvalid,
                ref detail_sha256,
                attempt: None,
            } if detail_sha256 == &role_error_detail_sha256(
                Role::Load,
                RoleErrorClass::Command,
                "raw-detail-not-on-wire",
            )
        ));
        child_task.await.unwrap().unwrap();

        let mut wrong_context = context();
        wrong_context.block += 1;
        assert_ne!(
            authentication_response(&challenge, &wrong_context, Role::Load, &expected_identity)
                .unwrap(),
            expected
        );
    }
}
