//! Fresh-process arm orchestration and bounded all-topology correctness smoke.

#![allow(unsafe_code)]

use crate::build::{build_pair, BuildSet};
use crate::control::{
    inherited_pair, ConnectionPolicy, ControlBody, ControlContext, FixtureResult, FramedControl,
    LoadProof, LoadResult, LoadTarget, ObservedProcess, Role, RoleErrorClass, RoleErrorCode,
    RoleErrorStage, SamplerReport, ThreadIdentity,
};
use crate::error::{SafeRoleAttempt, SafeRoleFailure, ROLE_FAILURE_SCHEMA};
use crate::evidence::{
    B11UploadDiagnosticEvidence, DiagnosticFailure, DiagnosticOutcome, ExecutionPhase,
    ExecutionStateEvidence, MachineEvidence, ProjectionEvidence, RetainedSmokeFailure,
    SmokeCaseEvidence, SmokeCaseKey, SmokeKind, SmokePhaseSeparationEvidence,
    TopologySmokeEvidence, DIAGNOSTIC_SCHEMA, EXECUTION_STATE_SCHEMA, PROJECTION_SCHEMA,
    SMOKE_FAILURE_SCHEMA, SMOKE_PHASE_SEPARATION_SCHEMA,
};
use crate::json;
use crate::linux::{
    clock_ns, preflight, process_identity, realtime_triplet, set_affinity, utc_rfc3339,
    verify_listening_socket_owner, ClockKind, HostPreflight, ProcessIdentity, CONTROL_CPUS,
    FIXTURE_CPUS, GATEWAY_CPUS, LOAD_CPUS,
};
use crate::materialization::{
    checkpoints_match, inventory_signatures, phase_hash_root, MaterializationEvidence,
    MaterializationOutcome, MaterializationWaveEvidence, FREEZE_HANDOFF_CAP_NS,
    INVENTORY_STABILITY_NS, MATERIALIZATION_PHASE_BASE, MAX_FULL_WAVES, MEASURE_HANDOFF_CAP_NS,
    MIN_UNCHANGED_FULL_WAVES, PROCESS_STABILITY_CAP_NS, SMOKE_STABILITY_CAP_NS,
};
use crate::process_plan::{
    execution_primitive, LifecycleEvent, LifecycleStage, PlannedArm, WEBSOCKET_KEEPALIVE_NS,
    WEBSOCKET_SETTLE_CAP_NS, WEBSOCKET_STABILITY_NS,
};
use crate::raw::SemanticClass;
use crate::raw::{
    self, ClockSample, CpuBucketEvidence, EndpointEvidence, EndpointPhaseEvidence, FrozenThread,
    LifecycleStageEvidence, NoiseScopeDecisionEvidence, OperationSummaryEvidence, QuietEvidence,
    RawPhase, ResourceEvidence, RoleUtilizationEvidence, RuntimeResidualEvidence,
    SessionClockEvidence, ThreadLifecycleEvidence, ThreadMapEvidence,
};
use crate::schema::{
    Arm, CalibrationPhase, CalibrationRecord, Cell, EvidenceClass, EvidenceKind, Intent,
    RawArmMetadata, RawLimits, RawProtocol, TerminalState, TrustBoundaryManifest, Workload,
    ZstdParameterProgram, ACCEPTED_SIGNATURE_SCHEMA, ARM_SCHEMA, BASELINE_COMMIT, EXECUTION_SCHEMA,
    INTENT_SCHEMA, TASK_CAP_BYTES,
};
use crate::seal::{create_seal, sha256_hex};
use crate::session::{
    create_ready_session, ready_predicates_at, ReadySessionEvidence, COOKIE_SECRET,
    SESSION_TTL_SECONDS, TOUCH_INTERVAL_SECONDS, USER_ID,
};
use crate::topology::{ArmTopology, GatewayObject, Protocol};
use crate::{Error, Result, ResultContext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::CommandExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const SMOKE_SCHEMA: &str = "amg-http2-perf/smoke/v1";
pub const SMOKE_CAP_NS: u64 = 300_000_000_000;
pub const B11_UPLOAD_DIAGNOSTIC_CAP_NS: u64 = 30_000_000_000;
pub const ARM_FAILURE_SCHEMA: &str = "amg-http2-perf/arm-failure/v1";

pub use crate::calibration_coordinator::{run_calibration, CalibrationOutcome};
pub use crate::campaign_coordinator::{run_campaign, CampaignOutcome};
pub use crate::schema::AcceptedSignatureRecord;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B11UploadDiagnosticSummary {
    pub schema: String,
    pub diagnostic_id: String,
    pub cell: Cell,
    pub authoritative: bool,
    pub topology_smoke: bool,
    pub case_succeeded: bool,
    pub stage: Option<RoleErrorStage>,
    pub code: Option<RoleErrorCode>,
    pub detail_sha256: Option<String>,
    pub evidence_root: String,
    pub seal_root_sha256: String,
    pub bundle_index_path: String,
    pub bundle_index_sha256: String,
    pub bundle_verified: bool,
    pub materialization_lanes: Option<u64>,
    pub materialization_operations: Option<u64>,
    pub materialization_waves: Option<u16>,
    pub materialization_stable: Option<bool>,
    pub measured_operations: Option<u64>,
    pub post_freeze_tid_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeSummary {
    pub schema: String,
    pub authoritative: bool,
    pub run_id: String,
    pub baseline_commit: String,
    pub candidate_commit: String,
    pub baseline_binary_sha256: String,
    pub candidate_binary_sha256: String,
    pub harness_binary_sha256: String,
    pub started_utc: String,
    pub boottime_start_ns: u64,
    pub boottime_end_ns: u64,
    pub arms: Vec<SmokeArmOutcome>,
    pub protocol_correct_arms: u64,
    pub direct_upload_controls: Vec<DirectSmokeOutcome>,
    pub direct_protocol_correct_cases: u64,
    pub host_quality_blockers: Vec<String>,
    pub bundle_index_path: String,
    pub bundle_index_sha256: String,
    pub bundle_terminal_state: TerminalState,
    pub bundle_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSmokeOutcome {
    pub ordinal: u64,
    pub cell: Cell,
    pub protocol: Protocol,
    pub proof: LoadProof,
    pub measured: LoadResult,
    pub fixture_physical_connections: u64,
    pub fixture_active_connections: u64,
    pub fixture_max_active_connections: u64,
    pub fixture_max_requests_per_connection: u64,
    pub fixture_connection_ids: Vec<u64>,
    pub fixture_stream_ids: Vec<u64>,
    pub frozen_thread_counts: BTreeMap<String, u64>,
    pub sampler_lifecycle_events: u64,
    pub sampler_attribution_cpus: u64,
    pub quality_blockers: Vec<String>,
    #[serde(skip)]
    pub fixture_evidence: Option<FixtureResult>,
    #[serde(skip)]
    pub sampler_freeze: Option<SamplerReport>,
    #[serde(skip)]
    pub sampler_final: Option<SamplerReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeArmOutcome {
    pub ordinal: u64,
    pub cell: Cell,
    pub arm: Arm,
    pub downstream: Protocol,
    pub upstream: Protocol,
    pub gateway_binary_sha256: String,
    pub ready_session: ReadySessionEvidence,
    pub proof: LoadProof,
    pub websocket_warmup: Option<LoadResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordinary_materialization: Option<MaterializationEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase_separation: Option<SmokePhaseSeparationEvidence>,
    pub measured: LoadResult,
    pub fixture_physical_connections: u64,
    pub fixture_max_active_connections: u64,
    pub fixture_max_requests_per_connection: u64,
    pub fixture_connection_ids: Vec<u64>,
    pub fixture_stream_ids: Vec<u64>,
    pub fixture_observations: u64,
    pub fixture_operation_hash_sha256: String,
    pub frozen_thread_counts: BTreeMap<String, u64>,
    pub sampler_lifecycle_events: u64,
    pub sampler_attribution_cpus: u64,
    pub ordinary_handoff_ns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_release_handoff_ns: Option<u64>,
    pub websocket_retirement_ns: Option<u64>,
    pub quality_blockers: Vec<String>,
    #[serde(skip)]
    pub fixture_evidence: Option<FixtureResult>,
    #[serde(skip)]
    pub sampler_freeze: Option<SamplerReport>,
    #[serde(skip)]
    pub sampler_final: Option<SamplerReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessArmOutcome {
    pub metadata: RawArmMetadata,
    pub calibration_record: Option<CalibrationRecord>,
    pub raw_leaf: String,
    pub thread_signature_sha256: String,
    pub lifecycle: Vec<LifecycleEvent>,
    pub quality_blockers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProcessArmRequest<'a> {
    pub evidence_id: &'a str,
    pub run_id: &'a str,
    pub planned: &'a PlannedArm,
    pub raw_ordinal: u64,
    pub warmup_seconds: u64,
    pub measure_seconds: Option<u64>,
    pub calibration_plan_sha256: Option<&'a str>,
    pub signature_policy: PreMeasureSignaturePolicy<'a>,
    pub trust_boundary: TrustBoundaryManifest,
    pub frequency_gate: FrequencyGate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrequencyGate {
    CalibrationAbsolute,
    AuthoritativeRelative { calibration_p05_khz: u64 },
}

#[derive(Debug, Clone)]
pub enum PreMeasureSignaturePolicy<'a> {
    Observe,
    Establish { accepted_record: &'a Path },
    Require { accepted_record: &'a Path },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmFailureRecord {
    pub schema: String,
    pub evidence_id_sha256: String,
    pub run_id_sha256: String,
    pub class: EvidenceClass,
    pub cell: Cell,
    pub arm: Option<Arm>,
    pub direct_protocol: Option<RawProtocol>,
    pub raw_ordinal: u64,
    pub stage: RoleErrorStage,
    pub code: RoleErrorCode,
    pub measured_work_started: bool,
    pub final_leaf: String,
    pub runtime_cleaned: bool,
    pub staging_cleaned: bool,
}

enum ProcessGateway<'a> {
    Exact(&'a BuildSet),
    #[cfg(debug_assertions)]
    Test(&'a Path),
}

impl AcceptedSignatureRecord {
    fn validate_for(&self, planned: &PlannedArm, calibration_plan_sha256: &str) -> Result<()> {
        self.validate()?;
        let expected_source = if planned.evidence_class == EvidenceClass::D {
            EvidenceClass::D
        } else {
            EvidenceClass::C
        };
        let direct_protocol = planned.direct_protocol.map(raw_protocol);
        if self.cell != planned.cell
            || self.arm != planned.arm
            || self.direct_protocol != direct_protocol
            || self.establishment_class != expected_source
            || self.calibration_plan_sha256 != calibration_plan_sha256
        {
            return Err(Error::new(
                "accepted signature key differs from the planned process arm",
            ));
        }
        Ok(())
    }
}

impl ArmFailureRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema != ARM_FAILURE_SCHEMA
            || self.final_leaf.is_empty()
            || self.final_leaf.len() > 256
            || Path::new(&self.final_leaf).is_absolute()
            || Path::new(&self.final_leaf)
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(Error::new("invalid bounded arm-failure record"));
        }
        self.cell.validate()?;
        crate::schema::validate_non_placeholder_sha256(
            "arm-failure evidence ID",
            &self.evidence_id_sha256,
        )?;
        crate::schema::validate_non_placeholder_sha256("arm-failure run ID", &self.run_id_sha256)?;
        match self.class {
            EvidenceClass::S | EvidenceClass::C | EvidenceClass::A
                if self.arm.is_some() && self.direct_protocol.is_none() => {}
            EvidenceClass::D if self.arm.is_none() && self.direct_protocol.is_some() => {}
            _ => return Err(Error::new("arm-failure class key is invalid")),
        }
        Ok(())
    }
}

struct SmokeStaticEvidence<'a> {
    calibration_id: &'a str,
    candidate: &'a str,
    host: &'a HostPreflight,
    build_set_bytes: &'a [u8],
    harness_binary_sha256: &'a str,
}

struct GatewaySmokeRequest<'a> {
    run_id: &'a str,
    ordinal: u64,
    cell: Cell,
    arm: Arm,
    arm_root: &'a Path,
}

struct FixtureExpectation {
    target: LoadTarget,
    protocol: Protocol,
    workload: Workload,
    concurrency: u64,
}

struct FixturePhaseResults<'a> {
    proof: &'a LoadProof,
    websocket_warmup: Option<&'a LoadResult>,
    ordinary_materialization: Option<&'a MaterializationEvidence>,
    measured: &'a LoadResult,
}

impl SmokeArmOutcome {
    pub fn smoke_case(&self) -> Result<SmokeCaseEvidence> {
        if let Some(materialization) = &self.ordinary_materialization {
            return self.ordinary_materialized_smoke_case(materialization);
        }
        let concurrency = u64::from(self.cell.concurrency);
        let (first, second) = if self.cell.workload == Workload::WebSocket {
            (
                self.websocket_warmup
                    .as_ref()
                    .ok_or_else(|| Error::new("WebSocket smoke warmup evidence missing"))?,
                &self.measured,
            )
        } else {
            // The non-WebSocket proof is represented by LoadProof rather than
            // LoadResult, so its hashes/counters are combined explicitly below.
            (&self.measured, &self.measured)
        };
        let protocol = self.downstream;
        let operation_hashes = if self.cell.workload == Workload::WebSocket {
            vec![
                first.operation_hash_sha256.as_str(),
                second.operation_hash_sha256.as_str(),
            ]
        } else {
            vec![
                self.proof.operation_hash_sha256.as_str(),
                self.measured.operation_hash_sha256.as_str(),
            ]
        };
        let connection_hashes = if self.cell.workload == Workload::WebSocket {
            vec![
                first
                    .connection_ledger
                    .operation_connection_hash_sha256
                    .as_str(),
                second
                    .connection_ledger
                    .operation_connection_hash_sha256
                    .as_str(),
            ]
        } else {
            vec![
                self.proof
                    .connection_ledger
                    .operation_connection_hash_sha256
                    .as_str(),
                self.measured
                    .connection_ledger
                    .operation_connection_hash_sha256
                    .as_str(),
            ]
        };
        let stream_ids = smoke_stream_ids(&self.measured.h2_wire)?;
        let physical_connections = match (protocol, self.cell.workload) {
            (Protocol::H1, Workload::Upload1Mib) => self
                .proof
                .connection_ledger
                .cumulative_connections
                .checked_add(self.measured.connection_ledger.cumulative_connections)
                .ok_or_else(|| Error::new("smoke H1 connection count overflow"))?,
            (Protocol::H1, _) => concurrency,
            (Protocol::H2, _) => 1,
        };
        let mut case = SmokeCaseEvidence {
            key: SmokeCaseKey {
                kind: SmokeKind::Gateway,
                concurrency: self.cell.concurrency,
                workload: self.cell.workload,
                arm: Some(self.arm),
                direct_protocol: None,
            },
            started_operations: concurrency * 2,
            completed_operations: if self.cell.workload == Workload::WebSocket {
                first
                    .operations_completed
                    .checked_add(second.operations_completed)
                    .ok_or_else(|| Error::new("smoke completion count overflow"))?
            } else {
                self.proof
                    .warmup_operations
                    .checked_add(self.measured.operations_completed)
                    .ok_or_else(|| Error::new("smoke completion count overflow"))?
            },
            physical_connections,
            stream_ids,
            close_tokens: self
                .proof
                .connection_ledger
                .close_tokens
                .checked_add(self.measured.connection_ledger.close_tokens)
                .ok_or_else(|| Error::new("smoke close count overflow"))?,
            transport_eof: self
                .proof
                .connection_ledger
                .transport_eof
                .checked_add(self.measured.connection_ledger.transport_eof)
                .ok_or_else(|| Error::new("smoke EOF count overflow"))?,
            retries: self
                .proof
                .connection_ledger
                .retry_attempts
                .checked_add(self.measured.connection_ledger.retry_attempts)
                .ok_or_else(|| Error::new("smoke retry count overflow"))?,
            reconnects: self
                .proof
                .connection_ledger
                .reconnect_attempts
                .checked_add(self.measured.connection_ledger.reconnect_attempts)
                .ok_or_else(|| Error::new("smoke reconnect count overflow"))?,
            reuse_attempts: self
                .proof
                .connection_ledger
                .reuse_attempts
                .checked_add(self.measured.connection_ledger.reuse_attempts)
                .ok_or_else(|| Error::new("smoke reuse count overflow"))?,
            evidence_integrity_failure: false,
            operation_hash_sha256: combine_smoke_hashes(b"operation", &operation_hashes),
            connection_hash_sha256: combine_smoke_hashes(b"connection", &connection_hashes),
            semantic_class: SemanticClass::Ok,
            semantic_detail: String::new(),
            phase_separation: None,
        };
        case.semantic_class = case.derived_semantic_class();
        case.semantic_detail = case.semantic_violations().join(", ");
        case.validate()?;
        Ok(case)
    }

    fn ordinary_materialized_smoke_case(
        &self,
        materialization: &MaterializationEvidence,
    ) -> Result<SmokeCaseEvidence> {
        materialization.validate()?;
        if self.cell.workload == Workload::WebSocket
            || materialization.prelude.is_some()
            || materialization.cell != self.cell
            || materialization.protocol != self.downstream
        {
            return Err(Error::new(
                "ordinary smoke materialization identity is inconsistent",
            ));
        }
        let separation = self.phase_separation.clone().ok_or_else(|| {
            Error::new("ordinary materialized smoke lacks phase-separation evidence")
        })?;
        let mut operation_hashes = vec![self.proof.operation_hash_sha256.as_str()];
        let mut connection_hashes = vec![self
            .proof
            .connection_ledger
            .operation_connection_hash_sha256
            .as_str()];
        let mut close_tokens = self.proof.connection_ledger.close_tokens;
        let mut transport_eof = self.proof.connection_ledger.transport_eof;
        let mut retries = self.proof.connection_ledger.retry_attempts;
        let mut reconnects = self.proof.connection_ledger.reconnect_attempts;
        let mut reuse_attempts = self.proof.connection_ledger.reuse_attempts;
        let mut fresh_connections = self.proof.connection_ledger.cumulative_connections;
        for wave in &materialization.waves {
            operation_hashes.push(wave.result.operation_hash_sha256.as_str());
            connection_hashes.push(
                wave.result
                    .connection_ledger
                    .operation_connection_hash_sha256
                    .as_str(),
            );
            close_tokens = close_tokens
                .checked_add(wave.result.connection_ledger.close_tokens)
                .ok_or_else(|| Error::new("smoke close count overflow"))?;
            transport_eof = transport_eof
                .checked_add(wave.result.connection_ledger.transport_eof)
                .ok_or_else(|| Error::new("smoke EOF count overflow"))?;
            retries = retries
                .checked_add(wave.result.connection_ledger.retry_attempts)
                .ok_or_else(|| Error::new("smoke retry count overflow"))?;
            reconnects = reconnects
                .checked_add(wave.result.connection_ledger.reconnect_attempts)
                .ok_or_else(|| Error::new("smoke reconnect count overflow"))?;
            reuse_attempts = reuse_attempts
                .checked_add(wave.result.connection_ledger.reuse_attempts)
                .ok_or_else(|| Error::new("smoke reuse count overflow"))?;
            fresh_connections = fresh_connections
                .checked_add(wave.result.connection_ledger.cumulative_connections)
                .ok_or_else(|| Error::new("smoke connection count overflow"))?;
        }
        operation_hashes.push(self.measured.operation_hash_sha256.as_str());
        connection_hashes.push(
            self.measured
                .connection_ledger
                .operation_connection_hash_sha256
                .as_str(),
        );
        close_tokens = close_tokens
            .checked_add(self.measured.connection_ledger.close_tokens)
            .ok_or_else(|| Error::new("smoke close count overflow"))?;
        transport_eof = transport_eof
            .checked_add(self.measured.connection_ledger.transport_eof)
            .ok_or_else(|| Error::new("smoke EOF count overflow"))?;
        retries = retries
            .checked_add(self.measured.connection_ledger.retry_attempts)
            .ok_or_else(|| Error::new("smoke retry count overflow"))?;
        reconnects = reconnects
            .checked_add(self.measured.connection_ledger.reconnect_attempts)
            .ok_or_else(|| Error::new("smoke reconnect count overflow"))?;
        reuse_attempts = reuse_attempts
            .checked_add(self.measured.connection_ledger.reuse_attempts)
            .ok_or_else(|| Error::new("smoke reuse count overflow"))?;
        fresh_connections = fresh_connections
            .checked_add(self.measured.connection_ledger.cumulative_connections)
            .ok_or_else(|| Error::new("smoke connection count overflow"))?;
        let started_operations = self
            .proof
            .warmup_operations
            .checked_add(materialization.operations_started)
            .and_then(|value| value.checked_add(self.measured.operations_started))
            .ok_or_else(|| Error::new("smoke operation count overflow"))?;
        let completed_operations = self
            .proof
            .warmup_operations
            .checked_add(materialization.operations_completed)
            .and_then(|value| value.checked_add(self.measured.operations_completed))
            .ok_or_else(|| Error::new("smoke completion count overflow"))?;
        let mut case = SmokeCaseEvidence {
            key: SmokeCaseKey {
                kind: SmokeKind::Gateway,
                concurrency: self.cell.concurrency,
                workload: self.cell.workload,
                arm: Some(self.arm),
                direct_protocol: None,
            },
            started_operations,
            completed_operations,
            physical_connections: match (self.downstream, self.cell.workload) {
                (Protocol::H1, Workload::Upload1Mib) => fresh_connections,
                (Protocol::H1, _) => u64::from(self.cell.concurrency),
                (Protocol::H2, _) => 1,
            },
            stream_ids: smoke_stream_ids(&self.measured.h2_wire)?,
            close_tokens,
            transport_eof,
            retries,
            reconnects,
            reuse_attempts,
            evidence_integrity_failure: false,
            operation_hash_sha256: combine_smoke_hashes(b"operation", &operation_hashes),
            connection_hash_sha256: combine_smoke_hashes(b"connection", &connection_hashes),
            semantic_class: SemanticClass::Ok,
            semantic_detail: String::new(),
            phase_separation: Some(separation),
        };
        case.semantic_class = case.derived_semantic_class();
        case.semantic_detail = case.semantic_violations().join(", ");
        case.validate()?;
        Ok(case)
    }
}

impl DirectSmokeOutcome {
    pub fn smoke_case(&self) -> Result<SmokeCaseEvidence> {
        let concurrency = u64::from(self.cell.concurrency);
        let stream_ids = smoke_stream_ids(&self.measured.h2_wire)?;
        let mut case = SmokeCaseEvidence {
            key: SmokeCaseKey {
                kind: SmokeKind::Direct,
                concurrency: self.cell.concurrency,
                workload: Workload::Upload1Mib,
                arm: None,
                direct_protocol: Some(match self.protocol {
                    Protocol::H1 => RawProtocol::H1,
                    Protocol::H2 => RawProtocol::H2,
                }),
            },
            started_operations: concurrency * 2,
            completed_operations: self
                .proof
                .warmup_operations
                .checked_add(self.measured.operations_completed)
                .ok_or_else(|| Error::new("direct smoke completion count overflow"))?,
            physical_connections: if self.protocol == Protocol::H1 {
                self.proof
                    .connection_ledger
                    .cumulative_connections
                    .checked_add(self.measured.connection_ledger.cumulative_connections)
                    .ok_or_else(|| Error::new("direct H1 connection count overflow"))?
            } else {
                1
            },
            stream_ids,
            close_tokens: self
                .proof
                .connection_ledger
                .close_tokens
                .checked_add(self.measured.connection_ledger.close_tokens)
                .ok_or_else(|| Error::new("direct close count overflow"))?,
            transport_eof: self
                .proof
                .connection_ledger
                .transport_eof
                .checked_add(self.measured.connection_ledger.transport_eof)
                .ok_or_else(|| Error::new("direct EOF count overflow"))?,
            retries: self
                .proof
                .connection_ledger
                .retry_attempts
                .checked_add(self.measured.connection_ledger.retry_attempts)
                .ok_or_else(|| Error::new("direct retry count overflow"))?,
            reconnects: self
                .proof
                .connection_ledger
                .reconnect_attempts
                .checked_add(self.measured.connection_ledger.reconnect_attempts)
                .ok_or_else(|| Error::new("direct reconnect count overflow"))?,
            reuse_attempts: self
                .proof
                .connection_ledger
                .reuse_attempts
                .checked_add(self.measured.connection_ledger.reuse_attempts)
                .ok_or_else(|| Error::new("direct reuse count overflow"))?,
            evidence_integrity_failure: false,
            operation_hash_sha256: combine_smoke_hashes(
                b"operation",
                &[
                    self.proof.operation_hash_sha256.as_str(),
                    self.measured.operation_hash_sha256.as_str(),
                ],
            ),
            connection_hash_sha256: combine_smoke_hashes(
                b"connection",
                &[
                    self.proof
                        .connection_ledger
                        .operation_connection_hash_sha256
                        .as_str(),
                    self.measured
                        .connection_ledger
                        .operation_connection_hash_sha256
                        .as_str(),
                ],
            ),
            semantic_class: SemanticClass::Ok,
            semantic_detail: String::new(),
            phase_separation: None,
        };
        case.semantic_class = case.derived_semantic_class();
        case.semantic_detail = case.semantic_violations().join(", ");
        case.validate()?;
        Ok(case)
    }
}

fn smoke_stream_ids(wire: &[crate::wire::H2WireEvidence]) -> Result<Vec<u32>> {
    if wire.is_empty() {
        return Ok(Vec::new());
    }
    if wire.len() != 1 || !wire[0].request_stream_ids_complete {
        return Err(Error::new(
            "smoke H2 stream IDs exceed or differ from the fixed observer inventory",
        ));
    }
    Ok(wire[0].request_stream_ids.clone())
}

fn combine_smoke_hashes(domain: &[u8], hashes: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"amg-http2-perf/smoke-complete-set/v1\0");
    hasher.update(domain);
    for hash in hashes {
        hasher.update(hash.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn smoke_phase_separation(
    proof: &LoadProof,
    materialization: &MaterializationEvidence,
    measured: &LoadResult,
    frozen: &SamplerReport,
    sampled: &SamplerReport,
    freeze_handoff_ns: u64,
    measure_handoff_ns: u64,
) -> Result<SmokePhaseSeparationEvidence> {
    materialization.validate()?;
    ensure_materialization_matches_freeze(materialization, frozen)?;
    ensure_post_freeze_unchanged(sampled, Some(frozen))?;
    let observation = materialization
        .stability_observations
        .last()
        .ok_or_else(|| Error::new("stable materialization has no final observation"))?;
    let (_, freeze_tid_signature_sha256) = inventory_signatures(&frozen.inventories)?;
    let (_, final_tid_signature_sha256) = inventory_signatures(&sampled.inventories)?;
    let evidence = SmokePhaseSeparationEvidence {
        schema: SMOKE_PHASE_SEPARATION_SCHEMA.to_owned(),
        proof_operations: proof.warmup_operations,
        materialization_operations: materialization.operations_started,
        materialization_waves: u16::try_from(materialization.waves.len())
            .map_err(|_| Error::new("smoke materialization wave count overflow"))?,
        materialization_lane_completions: materialization.lane_completions.clone(),
        materialization_operation_root_sha256: materialization.operation_root_sha256.clone(),
        materialization_connection_root_sha256: materialization.connection_root_sha256.clone(),
        stable_inventory_signature_sha256: materialization
            .stable_inventory_signature_sha256
            .clone()
            .ok_or_else(|| Error::new("stable inventory signature missing"))?,
        stable_tid_signature_sha256: materialization
            .stable_tid_signature_sha256
            .clone()
            .ok_or_else(|| Error::new("stable TID signature missing"))?,
        freeze_tid_signature_sha256,
        final_tid_signature_sha256,
        stability_observation_ns: observation.end_ns.saturating_sub(observation.start_ns),
        measured_operations: measured.operations_started,
        measured_operation_hash_sha256: measured.operation_hash_sha256.clone(),
        measured_connection_hash_sha256: measured
            .connection_ledger
            .operation_connection_hash_sha256
            .clone(),
        materialization_latency_records: materialization
            .waves
            .iter()
            .map(|wave| wave.result.latencies_ns.len() as u64)
            .sum(),
        measured_latency_records: measured.latencies_ns.len() as u64,
        births_after_freeze: sampled.births_after_freeze,
        deaths_after_freeze: sampled.deaths_after_freeze,
        migrations_after_freeze: sampled.migrations_after_freeze,
        freeze_handoff_ns,
        measure_handoff_ns,
    };
    Ok(evidence)
}

struct ManagedChild {
    role: Role,
    child: Child,
    identity: ProcessIdentity,
    reaped: bool,
}

struct ManagedRole {
    child: ManagedChild,
    control: FramedControl,
    authenticated: bool,
    evidence_root: Option<PathBuf>,
    failure_stage: RoleErrorStage,
}

impl ManagedRole {
    fn identity(&self) -> &ProcessIdentity {
        &self.child.identity
    }

    fn set_evidence_root(&mut self, root: &Path) {
        self.evidence_root = Some(root.to_path_buf());
    }

    fn mark_failure_stage(&mut self, stage: RoleErrorStage) {
        self.failure_stage = stage;
    }

    async fn send(&mut self, body: ControlBody) -> Result<()> {
        if let Err(error) = self.child.validate() {
            let mut detail = b"amg-http2-perf/control-send-identity/v1\0".to_vec();
            detail.extend_from_slice(error.to_string().as_bytes());
            return self
                .fail_control(
                    if self.authenticated {
                        "authenticated-control-send-failure"
                    } else {
                        "startup-control-send-failure"
                    },
                    None,
                    self.failure_stage,
                    RoleErrorCode::ProcessIdentity,
                    sha256_hex(&detail),
                    None,
                )
                .map(|_| ());
        }
        if let Err(error) = self.control.send(body).await {
            if self.authenticated {
                if let Err(terminal) = self.receive().await {
                    if terminal.role_failure().is_some() {
                        return Err(terminal);
                    }
                }
            }
            let mut detail = b"amg-http2-perf/control-send-io/v1\0".to_vec();
            detail.extend_from_slice(error.to_string().as_bytes());
            return self
                .fail_control(
                    if self.authenticated {
                        "authenticated-control-send-failure"
                    } else {
                        "startup-control-send-failure"
                    },
                    None,
                    self.failure_stage,
                    RoleErrorCode::ControlIo,
                    sha256_hex(&detail),
                    None,
                )
                .map(|_| ());
        }
        Ok(())
    }

    async fn receive(&mut self) -> Result<ControlBody> {
        match self.control.receive().await {
            Ok(ControlBody::RoleError {
                role,
                class,
                stage,
                code,
                detail_sha256,
                attempt,
            }) => {
                if role != self.child.role {
                    return self.fail_control(
                        "authenticated-terminal-role-mismatch",
                        None,
                        stage,
                        RoleErrorCode::ControlProtocol,
                        sha256_hex(b"amg-http2-perf/terminal-role-mismatch/v1"),
                        None,
                    );
                }
                crate::schema::validate_non_placeholder_sha256(
                    "terminal role detail",
                    &detail_sha256,
                )?;
                self.fail_control(
                    "authenticated-terminal-error",
                    Some(class),
                    stage,
                    code,
                    detail_sha256,
                    attempt.map(|value| SafeRoleAttempt {
                        starts: value.starts,
                        successes: value.successes,
                        failures: value.failures,
                        reconnects: value.reconnects,
                        retries: value.retries,
                    }),
                )
            }
            Ok(body) => Ok(body),
            Err(error) => {
                let class = if self.authenticated {
                    "authenticated-control-eof"
                } else {
                    "startup-control-eof"
                };
                let mut detail = Vec::new();
                detail.extend_from_slice(b"amg-http2-perf/control-receive-failure/v1\0");
                detail.extend_from_slice(error.to_string().as_bytes());
                self.fail_control(
                    class,
                    None,
                    self.failure_stage,
                    RoleErrorCode::ControlIo,
                    sha256_hex(&detail),
                    None,
                )
            }
        }
    }

    fn fail_control(
        &mut self,
        class: &str,
        terminal_class: Option<RoleErrorClass>,
        stage: RoleErrorStage,
        code: RoleErrorCode,
        detail_sha256: String,
        attempt: Option<SafeRoleAttempt>,
    ) -> Result<ControlBody> {
        let status = self.child.wait_for_failure_status(Duration::from_secs(1))?;
        let failure = SafeRoleFailure {
            schema: ROLE_FAILURE_SCHEMA.to_owned(),
            role: self.child.role.label().to_owned(),
            pid: self.child.identity.pid,
            start_time_ticks: self.child.identity.start_time_ticks,
            parent_pid: self.child.identity.parent_pid,
            class: class.to_owned(),
            terminal_class: terminal_class.map(|value| value.label().to_owned()),
            stage: Some(stage),
            code: Some(code),
            detail_sha256,
            attempt,
            exit_code: status.code(),
            signal: status.signal(),
            core_dumped: status.core_dumped(),
        };
        failure.validate()?;
        if let Some(root) = &self.evidence_root {
            json::write_new_canonical(
                &root.join(format!("role-failure-{}.json", self.child.role.label())),
                &failure,
            )?;
        }
        let summary = failure.summary();
        Err(Error::new(summary).with_role_failure(failure))
    }

    fn wait_clean(self, cap: Duration) -> Result<()> {
        self.child.wait_clean(cap)
    }
}

impl ManagedChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn validate(&self) -> Result<()> {
        let current = process_identity(self.pid())?;
        if current != self.identity || current.parent_pid != std::process::id() {
            return Err(Error::new(format!(
                "{} child PID/start-time/parent validation failed",
                self.role.label()
            )));
        }
        Ok(())
    }

    fn wait_for_failure_status(&mut self, cap: Duration) -> Result<std::process::ExitStatus> {
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                return Ok(status);
            }
            if start.elapsed() >= cap {
                self.validate()?;
                validated_signal(&self.identity, libc::SIGKILL)?;
                let status = self.child.wait()?;
                self.reaped = true;
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_clean(mut self, cap: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                if status.success() {
                    return Ok(());
                }
                return Err(Error::new(format!(
                    "{} child exited with {status}",
                    self.role.label()
                )));
            }
            if start.elapsed() >= cap {
                self.validate()?;
                validated_signal(&self.identity, libc::SIGKILL)?;
                let _ = self.child.wait();
                self.reaped = true;
                return Err(Error::new(format!(
                    "{} child exceeded clean-exit cap",
                    self.role.label()
                )));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn terminate(mut self, cap: Duration) -> Result<()> {
        self.validate()?;
        validated_signal(&self.identity, libc::SIGTERM)?;
        let start = std::time::Instant::now();
        loop {
            if self.child.try_wait()?.is_some() {
                self.reaped = true;
                return Ok(());
            }
            if start.elapsed() >= cap {
                self.validate()?;
                validated_signal(&self.identity, libc::SIGKILL)?;
                let _ = self.child.wait();
                self.reaped = true;
                return Err(Error::new(format!(
                    "{} child required emergency KILL",
                    self.role.label()
                )));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.reaped || self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        if self.validate().is_ok() {
            let _ = validated_signal(&self.identity, libc::SIGKILL);
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}

pub fn execution_root(repository: &Path) -> PathBuf {
    repository.join(".perf/prove-http2-performance-regression")
}

async fn run_ordinary_materialization(
    load: &mut ManagedRole,
    sampler: &mut ManagedRole,
    cell: Cell,
    protocol: Protocol,
    prelude: Option<LoadResult>,
    cap_ns: u64,
    retained_path: &Path,
) -> Result<MaterializationEvidence> {
    if cell.workload == Workload::WebSocket
        || !matches!(cap_ns, PROCESS_STABILITY_CAP_NS | SMOKE_STABILITY_CAP_NS)
    {
        return Err(Error::new("invalid ordinary materialization request"));
    }
    if retained_path.exists() {
        return Err(Error::new(
            "ordinary materialization evidence path already exists",
        ));
    }
    let mut before = materialization_checkpoint(sampler).await?;
    let start_ns = before.monotonic_ns;
    let deadline_ns = start_ns
        .checked_add(cap_ns)
        .ok_or_else(|| Error::new("materialization stability deadline overflow"))?;
    let mut waves = Vec::new();
    let mut stability_observations = Vec::new();
    let mut unchanged_waves = 0_u16;
    let mut stable_checkpoint = None;

    while waves.len() < usize::from(MAX_FULL_WAVES) {
        let now = clock_ns(ClockKind::Monotonic)?;
        if now >= deadline_ns {
            break;
        }
        let ordinal = u16::try_from(waves.len())
            .map_err(|_| Error::new("materialization wave ordinal overflow"))?;
        let phase = MATERIALIZATION_PHASE_BASE
            .checked_add(ordinal)
            .ok_or_else(|| Error::new("materialization phase overflow"))?;
        load.send(ControlBody::MaterializeWave {
            phase,
            operations: u64::from(cell.concurrency),
        })
        .await?;
        let remaining_ns = deadline_ns.saturating_sub(clock_ns(ClockKind::Monotonic)?);
        if remaining_ns == 0 {
            return Err(
                Error::new("materialization wave reached its fixed cap before completion")
                    .with_role_diagnostic(RoleErrorStage::Materialize, RoleErrorCode::Timeout),
            );
        }
        let result =
            tokio::time::timeout(Duration::from_nanos(remaining_ns), expect_measured(load))
                .await
                .map_err(|_| {
                    Error::new("materialization wave exceeded its fixed cap")
                        .with_role_diagnostic(RoleErrorStage::Materialize, RoleErrorCode::Timeout)
                })??;
        validate_materialization_wave_result(&result, cell, protocol, phase)?;
        let after = materialization_checkpoint(sampler).await?;
        if checkpoints_match(&before, &after) {
            unchanged_waves = unchanged_waves
                .checked_add(1)
                .ok_or_else(|| Error::new("materialization stability counter overflow"))?;
        } else {
            unchanged_waves = 0;
        }
        waves.push(MaterializationWaveEvidence {
            ordinal,
            phase,
            before: before.clone(),
            result,
            after: after.clone(),
        });
        before = after;

        if unchanged_waves >= MIN_UNCHANGED_FULL_WAVES {
            let remaining_ns = deadline_ns.saturating_sub(clock_ns(ClockKind::Monotonic)?);
            if remaining_ns < INVENTORY_STABILITY_NS {
                break;
            }
            sampler
                .send(ControlBody::ObserveInventoryStability {
                    expected_inventory_signature_sha256: before.inventory_signature_sha256.clone(),
                    expected_tid_signature_sha256: before.tid_signature_sha256.clone(),
                    duration_ns: INVENTORY_STABILITY_NS,
                })
                .await?;
            let observation = expect_inventory_stability(sampler).await?;
            let observation_stable = observation.stable
                && checkpoints_match(&observation.initial, &before)
                && checkpoints_match(&observation.initial, &observation.final_checkpoint);
            before = observation.final_checkpoint.clone();
            stability_observations.push(observation);
            if observation_stable {
                stable_checkpoint = Some(before.clone());
                break;
            }
            unchanged_waves = 0;
        }
    }

    let outcome = if stable_checkpoint.is_some() {
        MaterializationOutcome::Stable
    } else {
        MaterializationOutcome::CapExhausted
    };
    let end_ns = stable_checkpoint.as_ref().map_or_else(
        || clock_ns(ClockKind::Monotonic),
        |_| {
            stability_observations
                .last()
                .map(|observation| observation.end_ns)
                .ok_or_else(|| Error::new("stable materialization observation disappeared"))
        },
    )?;
    let evidence = build_materialization_evidence(
        cell,
        protocol,
        cap_ns,
        start_ns,
        end_ns,
        outcome,
        prelude,
        waves,
        stability_observations,
        stable_checkpoint.as_ref(),
    )?;
    json::write_new_canonical(retained_path, &evidence)?;
    if evidence.stable() {
        Ok(evidence)
    } else {
        Err(Error::new(format!(
            "ordinary materialization did not stabilize within {} waves/{}ns; evidence={}",
            MAX_FULL_WAVES,
            cap_ns,
            retained_path.display()
        ))
        .with_role_diagnostic(
            RoleErrorStage::Materialize,
            RoleErrorCode::MaterializeFailed,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn build_materialization_evidence(
    cell: Cell,
    protocol: Protocol,
    cap_ns: u64,
    start_ns: u64,
    end_ns: u64,
    outcome: MaterializationOutcome,
    prelude: Option<LoadResult>,
    waves: Vec<MaterializationWaveEvidence>,
    stability_observations: Vec<crate::control::InventoryStabilityObservation>,
    stable_checkpoint: Option<&crate::control::InventoryCheckpoint>,
) -> Result<MaterializationEvidence> {
    let mut operations_started = 0_u64;
    let mut operations_completed = 0_u64;
    let mut lane_starts = vec![0_u64; usize::from(cell.concurrency)];
    let mut lane_completions = vec![0_u64; usize::from(cell.concurrency)];
    let mut operation_hashes = Vec::new();
    let mut connection_hashes = Vec::new();
    if let Some(result) = &prelude {
        accumulate_materialization_result(
            result,
            &mut operations_started,
            &mut operations_completed,
            &mut lane_starts,
            &mut lane_completions,
        )?;
        operation_hashes.push((2_u16, result.operation_hash_sha256.as_str()));
        connection_hashes.push((
            2_u16,
            result
                .connection_ledger
                .operation_connection_hash_sha256
                .as_str(),
        ));
    }
    for wave in &waves {
        accumulate_materialization_result(
            &wave.result,
            &mut operations_started,
            &mut operations_completed,
            &mut lane_starts,
            &mut lane_completions,
        )?;
        operation_hashes.push((wave.phase, wave.result.operation_hash_sha256.as_str()));
        connection_hashes.push((
            wave.phase,
            wave.result
                .connection_ledger
                .operation_connection_hash_sha256
                .as_str(),
        ));
    }
    let operation_root_sha256 = phase_hash_root(b"operation", &operation_hashes);
    let connection_root_sha256 = phase_hash_root(b"connection", &connection_hashes);
    let evidence = MaterializationEvidence {
        schema: crate::materialization::MATERIALIZATION_SCHEMA.to_owned(),
        cell,
        protocol,
        authenticated: true,
        minimum_unchanged_full_waves: MIN_UNCHANGED_FULL_WAVES,
        maximum_full_waves: MAX_FULL_WAVES,
        cap_ns,
        start_ns,
        end_ns,
        outcome,
        prelude,
        waves,
        stability_observations,
        operations_started,
        operations_completed,
        lane_starts,
        lane_completions,
        operation_root_sha256,
        connection_root_sha256,
        stable_inventory_signature_sha256: stable_checkpoint
            .map(|checkpoint| checkpoint.inventory_signature_sha256.clone()),
        stable_tid_signature_sha256: stable_checkpoint
            .map(|checkpoint| checkpoint.tid_signature_sha256.clone()),
    };
    evidence.validate()?;
    Ok(evidence)
}

fn accumulate_materialization_result(
    result: &LoadResult,
    operations_started: &mut u64,
    operations_completed: &mut u64,
    lane_starts: &mut [u64],
    lane_completions: &mut [u64],
) -> Result<()> {
    *operations_started = operations_started
        .checked_add(result.operations_started)
        .ok_or_else(|| Error::new("materialization start aggregate overflow"))?;
    *operations_completed = operations_completed
        .checked_add(result.operations_completed)
        .ok_or_else(|| Error::new("materialization completion aggregate overflow"))?;
    if lane_starts.len() != result.lane_quotas.len()
        || lane_completions.len() != result.lane_completions.len()
    {
        return Err(Error::new("materialization lane aggregate width changed"));
    }
    for ((started, completed), (result_started, result_completed)) in lane_starts
        .iter_mut()
        .zip(lane_completions.iter_mut())
        .zip(result.lane_quotas.iter().zip(&result.lane_completions))
    {
        *started = started
            .checked_add(*result_started)
            .ok_or_else(|| Error::new("materialization lane start aggregate overflow"))?;
        *completed = completed
            .checked_add(*result_completed)
            .ok_or_else(|| Error::new("materialization lane completion aggregate overflow"))?;
    }
    Ok(())
}

async fn materialization_checkpoint(
    sampler: &mut ManagedRole,
) -> Result<crate::control::InventoryCheckpoint> {
    sampler.send(ControlBody::MaterializationInventory).await?;
    match sampler.receive().await? {
        ControlBody::MaterializationInventoryObserved { checkpoint } => {
            checkpoint.validate()?;
            Ok(checkpoint)
        }
        other => Err(Error::new(format!(
            "expected MaterializationInventoryObserved, got {other:?}"
        ))),
    }
}

async fn expect_inventory_stability(
    sampler: &mut ManagedRole,
) -> Result<crate::control::InventoryStabilityObservation> {
    match sampler.receive().await? {
        ControlBody::InventoryStabilityObserved { observation } => {
            observation.validate()?;
            Ok(observation)
        }
        other => Err(Error::new(format!(
            "expected InventoryStabilityObserved, got {other:?}"
        ))),
    }
}

fn validate_materialization_wave_result(
    result: &LoadResult,
    cell: Cell,
    protocol: Protocol,
    phase: u16,
) -> Result<()> {
    validate_process_load_result(
        result,
        cell.workload,
        protocol,
        u64::from(cell.concurrency),
        false,
    )?;
    if result.operations_started != u64::from(cell.concurrency)
        || result.lane_quotas != vec![1; usize::from(cell.concurrency)]
        || result.window_deadline_ns.is_some()
        || [
            result.first_operation_id.as_str(),
            result.last_operation_id.as_str(),
        ]
        .into_iter()
        .any(|operation_id| {
            crate::topology::parse_operation_id(operation_id)
                .map(|operation| (operation >> 112) as u16 != phase)
                .unwrap_or(true)
        })
    {
        return Err(Error::new(
            "materialization wave did not release exactly all C lanes",
        ));
    }
    Ok(())
}

fn ensure_materialization_matches_freeze(
    materialization: &MaterializationEvidence,
    frozen: &SamplerReport,
) -> Result<()> {
    materialization.validate()?;
    let (_, frozen_tid_signature) = inventory_signatures(&frozen.inventories)?;
    if !materialization.stable()
        || materialization.stable_tid_signature_sha256.as_deref()
            != Some(frozen_tid_signature.as_str())
        || frozen.monotonic_ns.saturating_sub(materialization.end_ns) > FREEZE_HANDOFF_CAP_NS
    {
        return Err(Error::new(
            "authoritative freeze differs from the stable materialized TID inventory or handoff cap",
        ));
    }
    Ok(())
}

fn ensure_post_freeze_unchanged(
    report: &SamplerReport,
    frozen: Option<&SamplerReport>,
) -> Result<()> {
    if let Some(blocker) = &report.post_freeze_change {
        return Err(Error::new(format!(
            "post-freeze TID integrity failure: {blocker}"
        )));
    }
    if report.births_after_freeze != 0
        || report.deaths_after_freeze != 0
        || report.migrations_after_freeze != 0
    {
        return Err(Error::new(format!(
            "post-freeze TID counters changed: births={} deaths={} migrations={}",
            report.births_after_freeze, report.deaths_after_freeze, report.migrations_after_freeze
        )));
    }
    if let Some(frozen) = frozen {
        let (frozen_inventory, frozen_tids) = inventory_signatures(&frozen.inventories)?;
        let (current_inventory, current_tids) = inventory_signatures(&report.inventories)?;
        if frozen_inventory != current_inventory || frozen_tids != current_tids {
            return Err(Error::new(
                "post-freeze inventory/TID signature changed without a permitted retry",
            ));
        }
    }
    Ok(())
}

pub fn run_preflight(repository: &Path) -> Result<HostPreflight> {
    preflight(repository, Duration::from_secs(1))
}

pub fn build_exact_pair(repository: &Path, candidate: &str) -> Result<BuildSet> {
    let root = execution_root(repository);
    fs::create_dir_all(&root)?;
    build_pair(repository, &root, candidate)
}

pub async fn execute_process_arm(
    repository: &Path,
    builds: &BuildSet,
    evidence_root: &Path,
    request: ProcessArmRequest<'_>,
) -> Result<ProcessArmOutcome> {
    let executable = std::env::current_exe()?;
    execute_process_arm_with(
        repository,
        evidence_root,
        request,
        &executable,
        ProcessGateway::Exact(builds),
    )
    .await
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub async fn execute_process_arm_for_test(
    repository: &Path,
    evidence_root: &Path,
    request: ProcessArmRequest<'_>,
    role_executable: &Path,
    gateway_executable: &Path,
) -> Result<ProcessArmOutcome> {
    require_repository_executable(repository, role_executable)?;
    require_repository_executable(repository, gateway_executable)?;
    execute_process_arm_with(
        repository,
        evidence_root,
        request,
        role_executable,
        ProcessGateway::Test(gateway_executable),
    )
    .await
}

async fn execute_process_arm_with(
    repository: &Path,
    evidence_root: &Path,
    request: ProcessArmRequest<'_>,
    role_executable: &Path,
    gateway: ProcessGateway<'_>,
) -> Result<ProcessArmOutcome> {
    require_repository_directory(repository, evidence_root)?;
    request.planned.validate()?;
    if request.raw_ordinal != request.planned.ordinal {
        return Err(Error::new(
            "process arm raw ordinal differs from its frozen plan ordinal",
        ));
    }
    validate_signature_policy(&request.signature_policy, request.planned.evidence_class)?;
    match request.planned.evidence_class {
        EvidenceClass::S if request.calibration_plan_sha256.is_none() => {}
        EvidenceClass::C | EvidenceClass::D | EvidenceClass::A
            if request.calibration_plan_sha256.is_some() =>
        {
            crate::schema::validate_non_placeholder_sha256(
                "process-arm calibration plan",
                request.calibration_plan_sha256.unwrap_or_default(),
            )?;
        }
        _ => {
            return Err(Error::new(
                "process arm calibration-plan binding differs from its class",
            ))
        }
    }
    if !(3..=10).contains(&request.warmup_seconds) {
        return Err(Error::new("process arm warmup must be 3..=10 seconds"));
    }
    let leaf = raw_leaf_path(evidence_root, request.planned)?;
    if leaf.exists() {
        return Err(Error::new(format!(
            "process arm raw leaf already exists: {}",
            leaf.display()
        )));
    }
    let expected_relative = leaf
        .strip_prefix(evidence_root)
        .map_err(|_| Error::new("process arm leaf escaped its evidence root"))?
        .to_path_buf();
    let staging_leaf = process_arm_staging_path(evidence_root, request.planned);
    let runtime_root = evidence_root.join(format!(
        ".arm-runtime-{:06}-{}",
        request.raw_ordinal,
        request.planned.cell.id()
    ));
    if runtime_root.exists() || staging_leaf.exists() {
        return Err(Error::new(
            "process arm runtime or staging namespace already exists",
        ));
    }

    let mut stage = RoleErrorStage::Startup;
    let mut measured_work_started = false;
    let result = execute_process_arm_inner(
        repository,
        &leaf,
        &expected_relative,
        &staging_leaf,
        &runtime_root,
        request.clone(),
        role_executable,
        &gateway,
        &mut stage,
        &mut measured_work_started,
    )
    .await;

    match result {
        Ok(outcome) => {
            if let Err(error) = cleanup_arm_path(&runtime_root) {
                let error = error
                    .with_role_diagnostic(RoleErrorStage::Finalize, RoleErrorCode::RuntimeCleanup);
                let staging_cleaned = cleanup_arm_path(&staging_leaf).is_ok();
                retain_arm_failure(
                    repository,
                    evidence_root,
                    &expected_relative,
                    &request,
                    &error,
                    stage,
                    measured_work_started,
                    !runtime_root.exists(),
                    staging_cleaned && !staging_leaf.exists(),
                )?;
                return Err(error);
            }
            if let Err(error) = rename_directory_noreplace(&staging_leaf, &leaf) {
                let error = error
                    .with_role_diagnostic(RoleErrorStage::Finalize, RoleErrorCode::AtomicPublish);
                let staging_cleaned = cleanup_arm_path(&staging_leaf).is_ok();
                retain_arm_failure(
                    repository,
                    evidence_root,
                    &expected_relative,
                    &request,
                    &error,
                    stage,
                    measured_work_started,
                    true,
                    staging_cleaned && !staging_leaf.exists(),
                )?;
                return Err(error);
            }
            Ok(outcome)
        }
        Err(error) => {
            let staging_cleaned = cleanup_arm_path(&staging_leaf).is_ok();
            let runtime_cleaned = cleanup_arm_path(&runtime_root).is_ok();
            retain_arm_failure(
                repository,
                evidence_root,
                &expected_relative,
                &request,
                &error,
                stage,
                measured_work_started,
                runtime_cleaned && !runtime_root.exists(),
                staging_cleaned && !staging_leaf.exists(),
            )?;
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_process_arm_inner(
    repository: &Path,
    leaf: &Path,
    expected_relative: &Path,
    staging_leaf: &Path,
    runtime_root: &Path,
    request: ProcessArmRequest<'_>,
    role_executable: &Path,
    gateway: &ProcessGateway<'_>,
    stage: &mut RoleErrorStage,
    measured_work_started: &mut bool,
) -> Result<ProcessArmOutcome> {
    let primitive = execution_primitive(request.planned, request.measure_seconds)?;

    #[cfg(debug_assertions)]
    let quiet = if matches!(gateway, &ProcessGateway::Test(_)) {
        test_quiet_evidence()?
    } else {
        crate::linux::observe_quiet_exact()?
    };
    #[cfg(not(debug_assertions))]
    let quiet = crate::linux::observe_quiet_exact()?;
    quiet.validate()?;
    *stage = RoleErrorStage::Prepare;
    let setup_start_ns = quiet.end_ns;
    fs::create_dir_all(runtime_root)?;
    set_mode(runtime_root, 0o700)?;
    let sampler_root = runtime_root.join("sampler");
    fs::create_dir(&sampler_root)?;
    set_mode(&sampler_root, 0o700)?;

    let cell = request.planned.cell;
    let context_arm = request
        .planned
        .arm
        .unwrap_or(match primitive.load_protocol {
            Protocol::H1 => Arm::B11,
            Protocol::H2 => Arm::C22,
        });
    let context = ControlContext {
        run_id: format!("{}-{:06}", request.run_id, request.raw_ordinal),
        cell,
        arm: context_arm,
        block: request.raw_ordinal,
        orchestrator: process_identity(std::process::id())?,
    };
    let role_executable_sha256 = sha256_hex(&fs::read(role_executable)?);
    let orchestrator_executable_sha256 = sha256_hex(&fs::read(std::env::current_exe()?)?);
    let mut fixture = spawn_role(
        role_executable,
        repository,
        Role::Fixture,
        FIXTURE_CPUS,
        &context,
    )?;
    let mut load = spawn_role(role_executable, repository, Role::Load, LOAD_CPUS, &context)?;
    let mut sampler = spawn_role(
        role_executable,
        repository,
        Role::Sampler,
        CONTROL_CPUS,
        &context,
    )?;
    fixture.set_evidence_root(runtime_root);
    load.set_evidence_root(runtime_root);
    sampler.set_evidence_root(runtime_root);
    authenticate_role(&mut fixture).await?;
    authenticate_role(&mut load).await?;
    authenticate_role(&mut sampler).await?;
    let (fixture_address, tripwire_address) = role_ready_fixture(&mut fixture).await?;
    role_ready(&mut load, Role::Load).await?;
    role_ready(&mut sampler, Role::Sampler).await?;
    fixture
        .send(ControlBody::ConfigureFixture {
            target: primitive.target,
            workload: cell.workload,
            expected_protocol: primitive.fixture_protocol,
            corpus_sha256: crate::topology::Corpus::fixed().sha256(),
        })
        .await?;
    expect(&mut fixture, |body| {
        matches!(body, ControlBody::FixtureConfigured)
    })
    .await?;

    let mut ready_session = None;
    let mut gateway_child = None;
    let gateway_address = if primitive.target == LoadTarget::Gateway {
        let planned_arm = request
            .planned
            .arm
            .ok_or_else(|| Error::new("gateway process arm has no treatment"))?;
        let topology = ArmTopology::for_arm(planned_arm);
        let (binary, binary_sha256) =
            process_gateway_binary(repository, gateway, topology.gateway)?;
        let session = create_ready_session(&runtime_root.join("gateway.sqlite"))?;
        let address = reserve_loopback_address().await?;
        let child = spawn_gateway(
            &binary,
            repository,
            GATEWAY_CPUS,
            address,
            fixture_address,
            tripwire_address,
            primitive.fixture_protocol,
            &session.database_path,
            runtime_root,
        )?;
        wait_gateway_owned(address, &child.identity).await?;
        ready_session = Some(session);
        gateway_child = Some((child, binary_sha256));
        Some(address)
    } else {
        None
    };
    let setup_end_ns = clock_ns(ClockKind::Monotonic)?;
    if setup_end_ns.saturating_sub(setup_start_ns) > 2_000_000_000 {
        return Err(Error::new(format!(
            "process arm setup/readiness exceeded two seconds: {}ns",
            setup_end_ns.saturating_sub(setup_start_ns)
        )));
    }

    let mut observed_processes = vec![
        observed(
            Role::Orchestrator,
            process_identity(std::process::id())?,
            &orchestrator_executable_sha256,
            CONTROL_CPUS,
        ),
        observed(
            Role::Fixture,
            fixture.identity().clone(),
            &role_executable_sha256,
            FIXTURE_CPUS,
        ),
        observed(
            Role::Load,
            load.identity().clone(),
            &role_executable_sha256,
            LOAD_CPUS,
        ),
        observed(
            Role::Sampler,
            sampler.identity().clone(),
            &role_executable_sha256,
            CONTROL_CPUS,
        ),
    ];
    if let Some((child, hash)) = &gateway_child {
        observed_processes.push(observed(
            Role::Gateway,
            child.identity.clone(),
            hash,
            GATEWAY_CPUS,
        ));
    }
    sampler
        .send(ControlBody::RegisterProcesses {
            processes: observed_processes,
            evidence_root: Some(sampler_root.display().to_string()),
        })
        .await?;
    expect(&mut sampler, |body| {
        matches!(body, ControlBody::ProcessesRegistered)
    })
    .await?;

    *stage = RoleErrorStage::Proof;
    let pre_auth_tids =
        if cell.workload == Workload::WebSocket && primitive.target == LoadTarget::Gateway {
            sampler.send(ControlBody::Inventory).await?;
            gateway_threads(expect_inventory(&mut sampler).await?)?
        } else {
            Vec::new()
        };
    let proof_start_ns = clock_ns(ClockKind::Monotonic)?;
    load.send(ControlBody::PrepareLoad {
        target: primitive.target,
        workload: cell.workload,
        protocol: primitive.load_protocol,
        gateway_address: gateway_address.map(|address| address.to_string()),
        fixture_address: fixture_address.to_string(),
        cookie_header: ready_session
            .as_ref()
            .map(|session| session.cookie_header.clone()),
        warmup_operations: if cell.workload == Workload::WebSocket {
            u64::from(cell.concurrency)
        } else {
            1
        },
        websocket_settle: cell.workload == Workload::WebSocket,
    })
    .await?;
    let proof = expect_prepared(&mut load).await?;
    validate_proof(
        &proof,
        primitive.load_protocol,
        cell.workload,
        u64::from(cell.concurrency),
    )?;
    let proof_end_ns = clock_ns(ClockKind::Monotonic)?;
    if proof_end_ns.saturating_sub(proof_start_ns) > 2_000_000_000 {
        return Err(Error::new(
            "process arm protocol proof exceeded two seconds",
        ));
    }

    *stage = RoleErrorStage::Materialize;
    let mut websocket_retirement = None;
    if cell.workload == Workload::WebSocket {
        let retirement_start = clock_ns(ClockKind::Monotonic)?;
        sampler
            .send(ControlBody::WaitWebsocketRetirement {
                gateway_pre_auth_tids: pre_auth_tids,
                keepalive_ns: WEBSOCKET_KEEPALIVE_NS,
                stability_ns: WEBSOCKET_STABILITY_NS,
                cap_ns: WEBSOCKET_SETTLE_CAP_NS,
            })
            .await?;
        let elapsed_ns = match sampler.receive().await? {
            ControlBody::WebsocketRetired { elapsed_ns, .. } => elapsed_ns,
            other => {
                return Err(Error::new(format!(
                    "expected WebsocketRetired, got {other:?}"
                )))
            }
        };
        let retirement_end = clock_ns(ClockKind::Monotonic)?;
        if retirement_end.saturating_sub(retirement_start) > WEBSOCKET_SETTLE_CAP_NS
            || elapsed_ns < WEBSOCKET_KEEPALIVE_NS + WEBSOCKET_STABILITY_NS
        {
            return Err(Error::new(
                "WebSocket retirement lifecycle is outside its caps",
            ));
        }
        websocket_retirement = Some((retirement_start, retirement_end, elapsed_ns));
        prepare_operation_corpus(&mut load, 2, 2_000_000).await?;
    }

    load.send(ControlBody::MaterializeDuration {
        phase: 2,
        duration_ns: request
            .warmup_seconds
            .checked_mul(1_000_000_000)
            .ok_or_else(|| Error::new("warmup duration overflow"))?,
    })
    .await?;
    let materialized = expect_measured(&mut load).await?;
    validate_process_load_result(
        &materialized,
        cell.workload,
        primitive.load_protocol,
        u64::from(cell.concurrency),
        false,
    )?;
    let ordinary_materialization: Option<MaterializationEvidence> = None;
    let measured_operation_ceiling = match primitive.measurement {
        ControlBody::MeasureCount { operations, .. } => operations,
        ControlBody::MeasureDuration { .. } => 2_000_000,
        _ => return Err(Error::new("process arm has a non-measurement primitive")),
    };
    if cell.workload == Workload::WebSocket {
        prepare_operation_corpus(&mut load, 3, measured_operation_ceiling).await?;
    }

    *stage = RoleErrorStage::Freeze;
    let freeze_start_ns = clock_ns(ClockKind::Monotonic)?;
    sampler.send(ControlBody::Freeze).await?;
    let frozen = expect_frozen(&mut sampler).await?;
    ensure_post_freeze_unchanged(&frozen, None)?;
    let thread_map = process_thread_map(&frozen)?;
    apply_signature_policy(repository, &request, &thread_map)?;
    sampler.send(ControlBody::Release).await?;
    let release_ns = match sampler.receive().await? {
        ControlBody::Released { monotonic_ns } => monotonic_ns,
        other => return Err(Error::new(format!("expected Released, got {other:?}"))),
    };
    if release_ns.saturating_sub(freeze_start_ns) > 1_000_000_000 {
        return Err(Error::new("process arm freeze exceeded one second"));
    }

    *stage = RoleErrorStage::Measure;
    *measured_work_started = true;
    load.send(primitive.measurement.clone()).await?;
    let measured = expect_measured(&mut load).await?;
    if measured.window_start_ns.saturating_sub(release_ns) > MEASURE_HANDOFF_CAP_NS {
        return Err(Error::new(
            "process arm did not begin measured work immediately after release",
        ));
    }
    validate_process_load_result(
        &measured,
        cell.workload,
        primitive.load_protocol,
        u64::from(cell.concurrency),
        primitive.retain_latencies,
    )?;
    sampler.send(ControlBody::FinalSample).await?;
    let sampled = expect_sampled(&mut sampler).await?;
    ensure_post_freeze_unchanged(&sampled, Some(&frozen))?;
    fixture.send(ControlBody::FixtureCompactSnapshot).await?;
    let fixture_result = expect_fixture(&mut fixture).await?;
    validate_process_fixture(
        &fixture_result,
        primitive.target,
        primitive.fixture_protocol,
        cell.workload,
        FixturePhaseResults {
            proof: &proof,
            websocket_warmup: Some(&materialized),
            ordinary_materialization: ordinary_materialization.as_ref(),
            measured: &measured,
        },
    )?;
    sampler.send(ControlBody::Stop).await?;
    expect_stopped(&mut sampler, Role::Sampler).await?;
    sampler.wait_clean(Duration::from_secs(1))?;
    load.send(ControlBody::Stop).await?;
    expect_stopped(&mut load, Role::Load).await?;
    load.wait_clean(Duration::from_secs(1))?;
    if let Some((child, _)) = gateway_child.take() {
        child.terminate(Duration::from_secs(1))?;
    }
    fixture.send(ControlBody::Stop).await?;
    expect_stopped(&mut fixture, Role::Fixture).await?;
    fixture.wait_clean(Duration::from_secs(1))?;
    let exit_end_ns = clock_ns(ClockKind::Monotonic)?;

    let sampler_evidence =
        crate::sampler::read_persistent(&sampler_root.join("sampler-final.bin"))?;
    let quality_blockers =
        sampler_quality_blockers_for(&sampler_evidence.report, request.frequency_gate);
    *stage = RoleErrorStage::Finalize;
    fs::create_dir_all(
        leaf.parent()
            .ok_or_else(|| Error::new("raw leaf has no parent"))?,
    )?;
    fs::create_dir_all(
        staging_leaf
            .parent()
            .ok_or_else(|| Error::new("raw staging leaf has no parent"))?,
    )?;
    fs::create_dir(staging_leaf)?;
    set_mode(staging_leaf, 0o700)?;
    let outcome = write_process_raw_arm(
        repository,
        staging_leaf,
        leaf,
        expected_relative,
        request,
        &quiet,
        &proof,
        &materialized,
        ordinary_materialization.as_ref(),
        &measured,
        &fixture_result,
        ready_session.as_ref().map(|session| &session.evidence),
        &thread_map,
        &frozen,
        &sampled,
        &sampler_evidence,
        primitive.load_protocol,
        primitive.fixture_protocol,
        setup_start_ns,
        setup_end_ns,
        proof_start_ns,
        proof_end_ns,
        websocket_retirement,
        freeze_start_ns,
        release_ns,
        exit_end_ns,
        &quality_blockers,
    )?;
    Ok(outcome)
}

#[cfg(debug_assertions)]
fn test_quiet_evidence() -> Result<QuietEvidence> {
    let end_ns = clock_ns(ClockKind::Monotonic)?;
    let start_ns = end_ns
        .checked_sub(10_000_000_000)
        .ok_or_else(|| Error::new("test Q_obs requires ten seconds of monotonic uptime"))?;
    Ok(QuietEvidence {
        schema: "amg-http2-perf/quiet/v1".to_owned(),
        clock: "CLOCK_MONOTONIC".to_owned(),
        start_ns,
        end_ns,
        q_extra_ns: 0,
        cpu_psi_some_us: 0,
        memory_psi_full_us: 0,
        io_psi_full_us: 0,
        swap_in_delta: 0,
        swap_out_delta: 0,
        steal_ticks_delta: 0,
        external_time_clean: true,
        search_start_ns: 0,
        orchestrator_threads: Vec::new(),
        candidates: Vec::new(),
    })
}

fn validate_signature_policy(
    policy: &PreMeasureSignaturePolicy<'_>,
    class: EvidenceClass,
) -> Result<()> {
    let valid = matches!(
        (class, policy),
        (EvidenceClass::S, PreMeasureSignaturePolicy::Observe)
            | (
                EvidenceClass::C | EvidenceClass::D,
                PreMeasureSignaturePolicy::Establish { .. }
            )
            | (
                EvidenceClass::C | EvidenceClass::D | EvidenceClass::A,
                PreMeasureSignaturePolicy::Require { .. }
            )
    );
    if valid {
        Ok(())
    } else {
        Err(Error::new(
            "process arm signature policy does not match its evidence class",
        ))
    }
}

fn process_observation_id(request: &ProcessArmRequest<'_>) -> String {
    format!(
        "{}-{}-{:06}",
        request.run_id,
        request.planned.cell.id(),
        request.raw_ordinal
    )
}

fn process_thread_map(frozen: &SamplerReport) -> Result<ThreadMapEvidence> {
    let mut frozen_threads = Vec::new();
    let mut signature_hasher = Sha256::new();
    signature_hasher.update(b"amg-http2-perf/all-role-thread-signature/v1\0");
    for inventory in &frozen.inventories {
        signature_hasher.update(inventory.role.label().as_bytes());
        signature_hasher.update(inventory.semantic_signature_sha256.as_bytes());
        for thread in &inventory.threads {
            frozen_threads.push(FrozenThread {
                role: inventory.role.label().to_owned(),
                pid: thread.pid,
                tid: thread.tid,
                start_time_ticks: thread.start_time_ticks,
                comm: thread.comm.clone(),
                assigned_cpu: thread.assigned_cpu,
                allowed_cpu: thread.assigned_cpu,
                observed_last_cpu: thread.assigned_cpu,
            });
        }
    }
    frozen_threads.sort_by_key(|thread| {
        (
            thread.role.clone(),
            thread.comm.clone(),
            thread.start_time_ticks,
            thread.tid,
        )
    });
    let thread_map = ThreadMapEvidence {
        schema: "amg-http2-perf/thread-map/v1".to_owned(),
        signature_sha256: format!("{:x}", signature_hasher.finalize()),
        threads: frozen_threads,
    };
    thread_map.validate()?;
    Ok(thread_map)
}

fn apply_signature_policy(
    repository: &Path,
    request: &ProcessArmRequest<'_>,
    thread_map: &ThreadMapEvidence,
) -> Result<()> {
    match &request.signature_policy {
        PreMeasureSignaturePolicy::Observe => Ok(()),
        PreMeasureSignaturePolicy::Establish { accepted_record } => {
            let accepted_record = repository_output_path(repository, accepted_record, false)?;
            let parent = accepted_record
                .parent()
                .ok_or_else(|| Error::new("accepted signature path has no parent"))?;
            fs::create_dir_all(parent)?;
            repository_output_path(repository, &accepted_record, false)?;
            let record = AcceptedSignatureRecord {
                schema: ACCEPTED_SIGNATURE_SCHEMA.to_owned(),
                calibration_id: request.evidence_id.to_owned(),
                calibration_plan_sha256: request
                    .calibration_plan_sha256
                    .ok_or_else(|| Error::new("signature establishment lacks calibration plan"))?
                    .to_owned(),
                cell: request.planned.cell,
                arm: request.planned.arm,
                direct_protocol: request.planned.direct_protocol.map(raw_protocol),
                establishment_class: request.planned.evidence_class,
                establishment_ordinal: request.raw_ordinal,
                source_observation_id: process_observation_id(request),
                signature_sha256: thread_map.signature_sha256.clone(),
            };
            record.validate()?;
            json::write_new_canonical(&accepted_record, &record).map_err(|error| {
                error.with_role_diagnostic(
                    RoleErrorStage::Freeze,
                    RoleErrorCode::SignatureRecordInvalid,
                )
            })?;
            Ok(())
        }
        PreMeasureSignaturePolicy::Require { accepted_record } => {
            let accepted_record = repository_output_path(repository, accepted_record, true)?;
            let metadata = fs::symlink_metadata(&accepted_record)?;
            if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 65_536 {
                return Err(
                    Error::new("accepted signature record is not a bounded file")
                        .with_role_diagnostic(
                            RoleErrorStage::Freeze,
                            RoleErrorCode::SignatureRecordInvalid,
                        ),
                );
            }
            let record: AcceptedSignatureRecord =
                json::require_canonical(&fs::read(&accepted_record)?).map_err(|error| {
                    error.with_role_diagnostic(
                        RoleErrorStage::Freeze,
                        RoleErrorCode::SignatureRecordInvalid,
                    )
                })?;
            record
                .validate_for(
                    request.planned,
                    request.calibration_plan_sha256.ok_or_else(|| {
                        Error::new("signature requirement lacks calibration plan")
                    })?,
                )
                .map_err(|error| {
                    error.with_role_diagnostic(
                        RoleErrorStage::Freeze,
                        RoleErrorCode::SignatureRecordInvalid,
                    )
                })?;
            if record.signature_sha256 != thread_map.signature_sha256 {
                return Err(Error::new(
                    "post-materialization signature differs from the accepted exact signature",
                )
                .with_role_diagnostic(RoleErrorStage::Freeze, RoleErrorCode::SignatureMismatch));
            }
            Ok(())
        }
    }
}

fn process_gateway_binary(
    repository: &Path,
    gateway: &ProcessGateway<'_>,
    object: GatewayObject,
) -> Result<(PathBuf, String)> {
    match gateway {
        ProcessGateway::Exact(builds) => {
            let build = match object {
                GatewayObject::Baseline => &builds.baseline,
                GatewayObject::Candidate => &builds.candidate,
            };
            Ok((
                build.validate_binary_reuse(repository)?,
                build.binary_sha256.clone(),
            ))
        }
        #[cfg(debug_assertions)]
        ProcessGateway::Test(binary) => {
            Ok(((*binary).to_path_buf(), sha256_hex(&fs::read(binary)?)))
        }
    }
}

#[cfg(debug_assertions)]
fn require_repository_executable(repository: &Path, executable: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let repository = fs::canonicalize(repository)?;
    let executable = fs::canonicalize(executable)?;
    let metadata = fs::symlink_metadata(&executable)?;
    if !executable.starts_with(&repository)
        || !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(Error::new(
            "test process-arm executable is not an executable repository file",
        ));
    }
    Ok(())
}

fn repository_output_path(repository: &Path, path: &Path, must_exist: bool) -> Result<PathBuf> {
    let repository = fs::canonicalize(repository)?;
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        repository.join(path)
    };
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(Error::new(
            "repository output path contains parent traversal",
        ));
    }
    let checked = if must_exist {
        fs::canonicalize(&path)?
    } else {
        let parent = path
            .parent()
            .ok_or_else(|| Error::new("repository output path has no parent"))?;
        if parent.exists() {
            let canonical_parent = fs::canonicalize(parent)?;
            canonical_parent.join(
                path.file_name()
                    .ok_or_else(|| Error::new("repository output path has no file name"))?,
            )
        } else {
            path.clone()
        }
    };
    if !checked.starts_with(&repository) {
        return Err(Error::new("repository output path escaped the repository"));
    }
    Ok(checked)
}

fn require_repository_directory(repository: &Path, path: &Path) -> Result<()> {
    let repository = fs::canonicalize(repository)?;
    let path = fs::canonicalize(path)?;
    let metadata = fs::symlink_metadata(&path)?;
    if !path.starts_with(&repository) || !metadata.file_type().is_dir() {
        return Err(Error::new(
            "process arm evidence root is not a repository-local directory",
        ));
    }
    Ok(())
}

fn process_arm_staging_path(root: &Path, planned: &PlannedArm) -> PathBuf {
    root.join(".arm-staging").join(format!(
        "{}-{:06}-{}-{}",
        evidence_class_label(planned.evidence_class),
        planned.ordinal,
        planned.cell.id(),
        planned
            .arm
            .map(Arm::code)
            .or_else(|| planned.direct_protocol.map(Protocol::label))
            .unwrap_or("unknown")
    ))
}

fn evidence_class_label(class: EvidenceClass) -> &'static str {
    match class {
        EvidenceClass::S => "s",
        EvidenceClass::C => "c",
        EvidenceClass::D => "d",
        EvidenceClass::A => "a",
    }
}

fn cleanup_arm_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    if path.exists() {
        return Err(Error::new(
            "arm runtime/staging cleanup left its path present",
        ));
    }
    Ok(())
}

fn rename_directory_noreplace(source: &Path, target: &Path) -> Result<()> {
    if target.exists() {
        return Err(Error::new(
            "final raw leaf already exists before atomic publish",
        ));
    }
    let source_c = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| Error::new("raw staging path contains NUL"))?;
    let target_c = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| Error::new("final raw path contains NUL"))?;
    // SAFETY: both NUL-terminated paths name repository-local directories and
    // RENAME_NOREPLACE prevents publication from replacing existing evidence.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source_c.as_ptr(),
            libc::AT_FDCWD,
            target_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    File::open(
        target
            .parent()
            .ok_or_else(|| Error::new("final raw leaf has no parent"))?,
    )?
    .sync_all()?;
    File::open(
        source
            .parent()
            .ok_or_else(|| Error::new("raw staging leaf has no parent"))?,
    )?
    .sync_all()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn retain_arm_failure(
    repository: &Path,
    evidence_root: &Path,
    final_leaf: &Path,
    request: &ProcessArmRequest<'_>,
    error: &Error,
    fallback_stage: RoleErrorStage,
    measured_work_started: bool,
    runtime_cleaned: bool,
    staging_cleaned: bool,
) -> Result<()> {
    let diagnostic = error.role_diagnostic();
    let record = ArmFailureRecord {
        schema: ARM_FAILURE_SCHEMA.to_owned(),
        evidence_id_sha256: sha256_hex(request.evidence_id.as_bytes()),
        run_id_sha256: sha256_hex(request.run_id.as_bytes()),
        class: request.planned.evidence_class,
        cell: request.planned.cell,
        arm: request.planned.arm,
        direct_protocol: request.planned.direct_protocol.map(raw_protocol),
        raw_ordinal: request.raw_ordinal,
        stage: diagnostic.map_or(fallback_stage, |value| value.stage),
        code: diagnostic.map_or_else(
            || error.role_code().unwrap_or(RoleErrorCode::Internal),
            |value| value.code,
        ),
        measured_work_started,
        final_leaf: final_leaf.to_string_lossy().into_owned(),
        runtime_cleaned,
        staging_cleaned,
    };
    record.validate()?;
    let path = arm_failure_path(evidence_root, request.planned);
    let directory = path
        .parent()
        .ok_or_else(|| Error::new("arm-failure path has no parent"))?;
    fs::create_dir_all(directory)?;
    repository_output_path(repository, &directory.join("probe"), false)?;
    let bytes = json::write_new_canonical(&path, &record)?;
    if bytes.len() > 65_536 {
        return Err(Error::new("arm-failure record exceeded its fixed bound"));
    }
    Ok(())
}

fn arm_failure_path(evidence_root: &Path, planned: &PlannedArm) -> PathBuf {
    evidence_root
        .join("arm-failures")
        .join(evidence_class_label(planned.evidence_class))
        .join(format!(
            "{:06}-{}-{}.json",
            planned.ordinal,
            planned.cell.id(),
            planned
                .arm
                .map(Arm::code)
                .or_else(|| planned.direct_protocol.map(Protocol::label))
                .unwrap_or("unknown")
        ))
}

pub(crate) fn retain_interrupted_process_arm(
    repository: &Path,
    evidence_root: &Path,
    evidence_id: &str,
    run_id: &str,
    planned: &PlannedArm,
) -> Result<()> {
    let final_leaf = raw_leaf_path(evidence_root, planned)?;
    if final_leaf.exists() {
        return Err(Error::new(
            "interrupted process arm already has a published raw leaf",
        ));
    }
    let staging_leaf = process_arm_staging_path(evidence_root, planned);
    let runtime_root = evidence_root.join(format!(
        ".arm-runtime-{:06}-{}",
        planned.ordinal,
        planned.cell.id()
    ));
    cleanup_arm_path(&staging_leaf)?;
    cleanup_arm_path(&runtime_root)?;

    let path = arm_failure_path(evidence_root, planned);
    if path.exists() {
        let record: ArmFailureRecord = json::read_strict(&path, crate::schema::JSON_MAX_BYTES)?;
        record.validate()?;
        if record.evidence_id_sha256 != sha256_hex(evidence_id.as_bytes())
            || record.run_id_sha256 != sha256_hex(run_id.as_bytes())
            || record.class != planned.evidence_class
            || record.cell != planned.cell
            || record.arm != planned.arm
            || record.direct_protocol != planned.direct_protocol.map(raw_protocol)
            || record.raw_ordinal != planned.ordinal
            || !record.runtime_cleaned
            || !record.staging_cleaned
        {
            return Err(Error::new(
                "retained interrupted-arm failure differs from its journal plan",
            ));
        }
        return Ok(());
    }

    let expected_relative = final_leaf
        .strip_prefix(evidence_root)
        .map_err(|_| Error::new("interrupted arm final leaf escaped evidence root"))?;
    let request = ProcessArmRequest {
        evidence_id,
        run_id,
        planned,
        raw_ordinal: planned.ordinal,
        warmup_seconds: 3,
        measure_seconds: None,
        calibration_plan_sha256: None,
        signature_policy: PreMeasureSignaturePolicy::Observe,
        trust_boundary: TrustBoundaryManifest::coordinated(
            "01".repeat(32),
            BASELINE_COMMIT.to_owned(),
            crate::schema::INITIAL_CANDIDATE_COMMIT.to_owned(),
        )?,
        frequency_gate: FrequencyGate::CalibrationAbsolute,
    };
    let error = Error::new("coordinator interruption left a partially started process arm")
        .with_role_diagnostic(RoleErrorStage::Finalize, RoleErrorCode::Panic);
    retain_arm_failure(
        repository,
        evidence_root,
        expected_relative,
        &request,
        &error,
        RoleErrorStage::Finalize,
        true,
        true,
        true,
    )
}

fn raw_leaf_path(root: &Path, planned: &PlannedArm) -> Result<PathBuf> {
    planned.validate()?;
    let leaf = match planned.evidence_class {
        EvidenceClass::S => root
            .join("scouts")
            .join(planned.cell.id())
            .join(
                planned
                    .target
                    .ok_or_else(|| Error::new("scout path has no target"))?
                    .to_string(),
            )
            .join(
                planned
                    .arm
                    .ok_or_else(|| Error::new("scout path has no treatment"))?
                    .code(),
            ),
        EvidenceClass::C => root
            .join("arms")
            .join(
                planned
                    .row
                    .ok_or_else(|| Error::new("Williams path has no row"))?
                    .to_string(),
            )
            .join(planned.cell.id())
            .join(
                planned
                    .arm
                    .ok_or_else(|| Error::new("Williams path has no treatment"))?
                    .code(),
            ),
        EvidenceClass::D => root
            .join("direct")
            .join(planned.round.unwrap_or(0).to_string())
            .join(planned.cell.id())
            .join(
                planned
                    .direct_protocol
                    .ok_or_else(|| Error::new("direct path has no protocol"))?
                    .label(),
            ),
        EvidenceClass::A => root
            .join("arms")
            .join(
                planned
                    .round
                    .ok_or_else(|| Error::new("authoritative path has no round"))?
                    .to_string(),
            )
            .join(planned.cell.id())
            .join(
                planned
                    .arm
                    .ok_or_else(|| Error::new("authoritative path has no treatment"))?
                    .code(),
            ),
    };
    Ok(leaf)
}

fn validate_process_load_result(
    result: &LoadResult,
    workload: Workload,
    protocol: Protocol,
    concurrency: u64,
    retain_latencies: bool,
) -> Result<()> {
    if result.protocol != protocol
        || result.operations_started == 0
        || result.operations_completed != result.operations_started
        || result.operations_completed_by_deadline == 0
        || result.operations_completed_by_deadline > result.operations_completed
        || result.window_end_ns < result.window_start_ns
        || result.window_deadline_ns.is_some_and(|deadline| {
            deadline <= result.window_start_ns
                || result.window_end_ns < deadline
                || result.window_end_ns.saturating_sub(deadline) > 2_000_000_000
        })
        || !result.status_ok
        || !result.eos_ok
        || !result.payload_ok
        || !result.sse_content_type_ok
        || !result.response_headers_sanitized
        || result.retries != 0
        || (retain_latencies && result.latencies_ns.len() as u64 != result.operations_completed)
        || (!retain_latencies && !result.latencies_ns.is_empty())
    {
        return Err(Error::new(
            "process load result failed count/deadline/correctness/latency reconciliation",
        ));
    }
    validate_attempt_and_lane_ledgers(
        &result.attempts,
        &result.lane_quotas,
        &result.lane_completions,
        result.operations_started,
        concurrency,
    )?;
    validate_load_wire(
        protocol,
        workload,
        &result.h2_wire,
        result.operations_started,
    )?;
    validate_connection_ledger(
        &result.connection_ledger,
        result.operations_started,
        workload,
        protocol,
        concurrency,
    )
}

fn validate_process_fixture(
    fixture: &FixtureResult,
    target: LoadTarget,
    protocol: Protocol,
    workload: Workload,
    phases: FixturePhaseResults<'_>,
) -> Result<()> {
    let FixturePhaseResults {
        proof,
        websocket_warmup: materialized,
        ordinary_materialization,
        measured,
    } = phases;
    let materialized =
        materialized.ok_or_else(|| Error::new("process fixture materialization result missing"))?;
    let proof_phase = if workload == Workload::WebSocket {
        0
    } else {
        1
    };
    let mut expected_phases = std::collections::BTreeSet::from([proof_phase, 2, 3]);
    if let Some(materialization) = ordinary_materialization {
        expected_phases.extend(materialization.waves.iter().map(|wave| wave.phase));
    }
    let aggregate_phases = fixture
        .phase_aggregates
        .iter()
        .map(|phase| phase.phase)
        .collect::<std::collections::BTreeSet<_>>();
    let phase_inventory_valid = aggregate_phases.len() == fixture.phase_aggregates.len()
        && aggregate_phases == expected_phases;
    let compact_valid = if fixture.compacted {
        let mut phases = std::collections::BTreeSet::new();
        let operation_count = fixture
            .phase_aggregates
            .iter()
            .try_fold(0_u64, |total, phase| total.checked_add(phase.operations));
        fixture.observations.is_empty()
            && !fixture.phase_aggregates.is_empty()
            && phase_inventory_valid
            && operation_count == Some(fixture.observation_count)
            && fixture.phase_aggregates.iter().all(|phase| {
                phases.insert(phase.phase)
                    && crate::schema::validate_non_placeholder_sha256(
                        "fixture phase operation hash",
                        &phase.operation_hash_sha256,
                    )
                    .is_ok()
                    && phase.protocol_correct
                    && phase.payload_correct
                    && phase.identity_correct
                    && phase.headers_sanitized
                    && phase.request_eos
                    && phase.response_semantics_correct
            })
    } else {
        phase_inventory_valid
            && fixture.observation_count == fixture.observations.len() as u64
            && fixture.observations.iter().all(|observation| {
                observation.protocol == protocol
                    && observation.payload_ok
                    && observation.identity_ok
                    && observation.request_headers_sanitized
                    && observation.request_eos
                    && (observation.method == "PING"
                        || observation.status == 200
                        || observation.status == 101)
                    && if protocol == Protocol::H2 {
                        observation
                            .stream_id
                            .is_some_and(|stream| !stream.is_multiple_of(2))
                    } else {
                        observation.stream_id.is_none()
                    }
            })
    };
    if fixture.target != target
        || fixture.expected_protocol != protocol
        || fixture.physical_connections == 0
        || fixture.active_connections > fixture.max_active_connections
        || fixture.max_requests_per_connection == 0
        || fixture.tripwire_connections != 0
        || fixture.tripwire_bytes != 0
        || fixture.duplicate_operations != 0
        || fixture.unknown_requests != 0
        || !compact_valid
    {
        return Err(Error::new(
            "process fixture protocol/correctness/tripwire ledger failed",
        ));
    }
    match protocol {
        Protocol::H1 if !fixture.h2_wire.is_empty() => {
            return Err(Error::new("H1 process fixture emitted H2 wire evidence"));
        }
        Protocol::H2 => {
            if fixture.h2_wire.len() != 1 {
                return Err(Error::new(
                    "H2 process fixture lacks one physical wire observer",
                ));
            }
            fixture.h2_wire[0].validate(workload == Workload::WebSocket)?;
            let http_observations = if fixture.compacted {
                fixture
                    .phase_aggregates
                    .iter()
                    .try_fold(0_u64, |total, phase| total.checked_add(phase.http_requests))
                    .ok_or_else(|| Error::new("fixture HTTP request count overflow"))?
            } else {
                fixture
                    .observations
                    .iter()
                    .filter(|observation| observation.method != "PING")
                    .count() as u64
            };
            if fixture.h2_wire[0].request_headers != http_observations {
                return Err(Error::new(
                    "fixture H2 HEADERS and HTTP observation ledgers differ",
                ));
            }
        }
        Protocol::H1 => {}
    }
    let proof_operations = if workload == Workload::WebSocket {
        proof.tunnels
    } else {
        proof.warmup_operations
    };
    reconcile_fixture_phase(
        fixture,
        proof_phase,
        proof_operations,
        &proof.operation_hash_sha256,
        proof.request_bytes,
        proof.response_bytes,
    )?;
    reconcile_fixture_phase(
        fixture,
        2,
        materialized.operations_completed,
        &materialized.operation_hash_sha256,
        materialized.request_bytes,
        materialized.response_bytes,
    )?;
    if let Some(materialization) = ordinary_materialization {
        materialization.validate()?;
        for wave in &materialization.waves {
            reconcile_fixture_phase(
                fixture,
                wave.phase,
                wave.result.operations_completed,
                &wave.result.operation_hash_sha256,
                wave.result.request_bytes,
                wave.result.response_bytes,
            )?;
        }
    }
    reconcile_fixture_phase(
        fixture,
        3,
        measured.operations_completed,
        &measured.operation_hash_sha256,
        measured.request_bytes,
        measured.response_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_process_raw_arm(
    repository: &Path,
    leaf: &Path,
    published_leaf: &Path,
    expected_relative: &Path,
    request: ProcessArmRequest<'_>,
    quiet: &QuietEvidence,
    proof: &LoadProof,
    materialized: &LoadResult,
    ordinary_materialization: Option<&MaterializationEvidence>,
    measured: &LoadResult,
    fixture: &FixtureResult,
    ready_session: Option<&ReadySessionEvidence>,
    thread_map: &ThreadMapEvidence,
    frozen: &SamplerReport,
    sampled: &SamplerReport,
    sampler_evidence: &crate::sampler::SamplerPersistentEvidence,
    downstream: Protocol,
    upstream: Protocol,
    setup_start_ns: u64,
    setup_end_ns: u64,
    proof_start_ns: u64,
    proof_end_ns: u64,
    websocket_retirement: Option<(u64, u64, u64)>,
    freeze_start_ns: u64,
    release_ns: u64,
    exit_end_ns: u64,
    quality_blockers: &[String],
) -> Result<ProcessArmOutcome> {
    let class = request.planned.evidence_class;
    let cell = request.planned.cell;
    let deadline_ns = measured
        .window_deadline_ns
        .unwrap_or(measured.window_end_ns);
    let observation_id = process_observation_id(&request);
    let position = request.planned.row.and_then(|row| {
        crate::schedule::williams_rows()[usize::from(row)]
            .iter()
            .position(|arm| Some(*arm) == request.planned.arm)
            .and_then(|value| u8::try_from(value).ok())
    });
    let materialization_bytes = ordinary_materialization
        .map(json::canonical_bytes)
        .transpose()?;
    let metadata = RawArmMetadata {
        schema: ARM_SCHEMA.to_owned(),
        evidence_id: request.evidence_id.to_owned(),
        run_id: request.run_id.to_owned(),
        class,
        cell,
        arm: request.planned.arm,
        direct_protocol: request
            .planned
            .direct_protocol
            .map(|protocol| match protocol {
                Protocol::H1 => RawProtocol::H1,
                Protocol::H2 => RawProtocol::H2,
            }),
        ordinal: request.raw_ordinal,
        round: (class == EvidenceClass::A)
            .then_some(request.planned.round)
            .flatten(),
        row: matches!(class, EvidenceClass::C | EvidenceClass::A)
            .then_some(request.planned.row)
            .flatten(),
        position: matches!(class, EvidenceClass::C | EvidenceClass::A)
            .then_some(position)
            .flatten(),
        epoch: (class == EvidenceClass::D).then_some(request.planned.round.unwrap_or(0)),
        scout_target: (class == EvidenceClass::S)
            .then_some(request.planned.target)
            .flatten(),
        observation_id: observation_id.clone(),
        started_operations: measured.operations_started,
        deadline_completions: measured.operations_completed_by_deadline,
        drained_operations: measured.operations_completed,
        latency_record_ceiling: if class.has_latencies() {
            measured.operations_completed
        } else {
            0
        },
        materialization_sha256: materialization_bytes
            .as_ref()
            .map(|bytes| sha256_hex(bytes)),
    };
    metadata.validate()?;
    json::write_new_canonical(&leaf.join("metadata.json"), &metadata)?;
    if let Some(bytes) = &materialization_bytes {
        crate::json::write_new_bytes(&leaf.join("materialization.json"), bytes)?;
    }
    json::write_new_canonical(&leaf.join("quiet.json"), quiet)?;

    json::write_new_canonical(&leaf.join("thread-map.json"), thread_map)?;

    let lifecycle = process_lifecycle_events(
        cell.workload,
        quiet,
        setup_start_ns,
        setup_end_ns,
        proof_start_ns,
        proof_end_ns,
        websocket_retirement,
        materialized,
        ordinary_materialization,
        freeze_start_ns,
        release_ns,
        measured,
        exit_end_ns,
    )?;
    crate::process_plan::validate_lifecycle(cell.workload, &lifecycle)?;
    let raw_stages = lifecycle
        .iter()
        .map(|event| LifecycleStageEvidence {
            name: format!("{:?}", event.stage).to_ascii_lowercase(),
            start_ns: event.monotonic_start_ns,
            end_ns: event.monotonic_end_ns,
        })
        .collect();
    let ordinary_handoff_ns = (cell.workload != Workload::WebSocket).then(|| {
        release_ns.saturating_sub(ordinary_materialization.map_or_else(
            || {
                materialized
                    .window_deadline_ns
                    .unwrap_or(materialized.window_end_ns)
            },
            |evidence| evidence.end_ns,
        ))
    });
    let websocket_auth_done_ns = (cell.workload == Workload::WebSocket).then_some(proof_end_ns);
    let websocket_eligible_ns =
        websocket_auth_done_ns.and_then(|value| value.checked_add(WEBSOCKET_KEEPALIVE_NS));
    let websocket_stable_ns = websocket_retirement.map(|(_, end, _)| end);
    let lifecycle_evidence = ThreadLifecycleEvidence {
        schema: "amg-http2-perf/thread-lifecycle/v1".to_owned(),
        stages: raw_stages,
        lifecycle_poll_max_ns: sampled.lifecycle_poll_max_ns,
        births_before_freeze: sampled.births_before_freeze,
        deaths_before_freeze: sampled.deaths_before_freeze,
        births_after_freeze: sampled.births_after_freeze,
        deaths_after_freeze: sampled.deaths_after_freeze,
        migrations_after_freeze: sampled.migrations_after_freeze,
        freeze_ns: release_ns,
        ordinary_handoff_ns,
        websocket_auth_done_ns,
        websocket_eligible_ns,
        websocket_stable_ns,
    };
    lifecycle_evidence.validate(cell.workload)?;
    raw::write_record_new(
        &leaf.join("thread-lifecycle.bin"),
        class,
        "thread-lifecycle.bin",
        &lifecycle_evidence,
    )?;

    let clock_manifest_sha256 = request.trust_boundary.clock_sha256()?;
    let session_clock = if class == EvidenceClass::D {
        SessionClockEvidence {
            schema: "amg-http2-perf/session-clock/v2".to_owned(),
            direct: true,
            comparable: true,
            discontinuities: 0,
            samples: Vec::new(),
            ready_session: None,
            clock_manifest_sha256: Some(clock_manifest_sha256),
            protocol_dates: Vec::new(),
        }
    } else {
        let ready_session = ready_session
            .cloned()
            .ok_or_else(|| Error::new("gateway raw arm lacks ready-session evidence"))?;
        let samples = sampler_evidence
            .realtime_triplets
            .iter()
            .map(|sample| {
                let predicates = ready_predicates_at(&ready_session, sample.realtime_ns)?;
                Ok(ClockSample {
                    boottime_before_ns: sample.boottime_before_ns,
                    realtime_ns: sample.realtime_ns,
                    boottime_after_ns: sample.boottime_after_ns,
                    ready: predicates.ready,
                    active: predicates.active,
                    refresh_due: predicates.access_refresh_due,
                    touch_due: predicates.touch_due,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let discontinuities = raw_clock_discontinuities(&samples)?;
        let mut evidence = SessionClockEvidence {
            schema: "amg-http2-perf/session-clock/v2".to_owned(),
            direct: false,
            comparable: false,
            discontinuities,
            samples,
            ready_session: Some(ready_session),
            clock_manifest_sha256: Some(clock_manifest_sha256),
            protocol_dates: proof
                .protocol_dates
                .iter()
                .chain(&measured.protocol_dates)
                .cloned()
                .collect(),
        };
        evidence.comparable = evidence.derived_comparable()?;
        evidence
    };
    session_clock.validate()?;
    raw::write_record_new(
        &leaf.join("session-clock.bin"),
        class,
        "session-clock.bin",
        &session_clock,
    )?;

    let resources = process_resource_evidence(
        frozen,
        &sampler_evidence.report,
        request.frequency_gate,
        quality_blockers,
    )?;
    resources.validate(class)?;
    raw::write_record_new(
        &leaf.join("resources.bin"),
        class,
        "resources.bin",
        &resources,
    )?;

    let fixture_measured = fixture_phase_summary(fixture, 3)?;
    if fixture_measured.operations != measured.operations_completed
        || fixture_measured.operation_hash_sha256 != measured.operation_hash_sha256
        || fixture_measured.request_bytes != measured.request_bytes
        || fixture_measured.response_bytes != measured.response_bytes
    {
        return Err(Error::new(
            "measured fixture/load operation and byte sets differ before raw emission",
        ));
    }
    let phases = vec![
        endpoint_phase_from_proof(proof, cell.workload)?,
        endpoint_phase_from_result(RawPhase::Warmup, materialized)?,
        endpoint_phase_from_result(RawPhase::Measured, measured)?,
        empty_endpoint_drain_phase()?,
    ];
    let downstream_wire = wire_endpoint_summary(downstream, &measured.h2_wire)?;
    let upstream_wire = wire_endpoint_summary(upstream, &fixture.h2_wire)?;
    let observed_downstream = proof
        .observed_protocol
        .filter(|protocol| measured.observed_protocol == Some(*protocol))
        .ok_or_else(|| {
            Error::new("load proof/measurement lacks one observed downstream protocol")
        })?;
    let observed_upstream = fixture_measured
        .observed_protocol
        .ok_or_else(|| Error::new("fixture lacks one observed upstream protocol"))?;
    let date_values_sha256 =
        protocol_date_values_sha256(proof.protocol_dates.iter().chain(&measured.protocol_dates));
    let endpoints = EndpointEvidence {
        schema: "amg-http2-perf/endpoints/v2".to_owned(),
        downstream_protocol: raw_protocol(observed_downstream),
        upstream_protocol: raw_protocol(observed_upstream),
        downstream_physical_connections: total_downstream_connections(
            downstream,
            cell.workload,
            cell.concurrency,
            proof,
            materialized,
            ordinary_materialization,
            measured,
        )?,
        upstream_physical_connections: fixture.physical_connections,
        h2_settings_seen: downstream_wire.settings,
        h2_settings_ack_seen: downstream_wire.settings_ack,
        enable_connect_seen: downstream_wire.enable_connect,
        upstream_h2_settings_seen: upstream_wire.settings,
        upstream_h2_settings_ack_seen: upstream_wire.settings_ack,
        upstream_enable_connect_seen: upstream_wire.enable_connect,
        downstream_stream_count: downstream_wire.stream_count,
        downstream_first_stream_id: downstream_wire.first_stream_id,
        downstream_last_stream_id: downstream_wire.last_stream_id,
        downstream_stream_sequence_sha256: downstream_wire.stream_hash,
        upstream_stream_count: upstream_wire.stream_count,
        upstream_first_stream_id: upstream_wire.first_stream_id,
        upstream_last_stream_id: upstream_wire.last_stream_id,
        upstream_stream_sequence_sha256: upstream_wire.stream_hash,
        request_bytes: measured.request_bytes,
        response_bytes: measured.response_bytes,
        load_operation_hash_sha256: measured.operation_hash_sha256.clone(),
        fixture_operation_hash_sha256: fixture_measured.operation_hash_sha256,
        tripwire_connections: fixture.tripwire_connections,
        tripwire_bytes: fixture.tripwire_bytes,
        duplicate_operations: fixture.duplicate_operations,
        phases,
        downstream_protocol_observations: proof
            .warmup_operations
            .max(proof.tunnels)
            .saturating_add(measured.operations_completed),
        upstream_protocol_observations: fixture_measured.operations,
        fixture_identity_observations: fixture_measured.operations,
        fixture_identity_correct_observations: if fixture_measured.identity_correct {
            fixture_measured.operations
        } else {
            0
        },
        fixture_identity_correct: fixture_measured.identity_correct,
        request_header_observations: fixture_measured.operations,
        request_headers_sanitized_observations: if fixture_measured.headers_sanitized {
            fixture_measured.operations
        } else {
            0
        },
        request_headers_sanitized: fixture_measured.headers_sanitized,
        response_header_observations: measured.operations_completed,
        response_headers_sanitized_observations: if measured.response_headers_sanitized {
            measured.operations_completed
        } else {
            0
        },
        response_headers_sanitized: measured.response_headers_sanitized,
        gateway_date_observations: if class == EvidenceClass::D {
            0
        } else {
            u64::try_from(proof.protocol_dates.len() + measured.protocol_dates.len())
                .map_err(|_| Error::new("Date observation count overflow"))?
        },
        gateway_date_values_sha256: date_values_sha256,
        config_manifest_sha256: request.trust_boundary.config_sha256()?,
        corpus_manifest_sha256: request.trust_boundary.corpus_sha256()?,
        connection_policy_manifest_sha256: request.trust_boundary.connection_policy_sha256()?,
    };
    let operation = OperationSummaryEvidence {
        schema: "amg-http2-perf/operation-summary/v1".to_owned(),
        window_start_ns: measured.window_start_ns,
        deadline_ns,
        drain_end_ns: measured.window_end_ns,
        started_operations: measured.operations_started,
        deadline_completions: measured.operations_completed_by_deadline,
        drained_operations: measured.operations_completed,
        request_bytes: measured.request_bytes,
        response_bytes: measured.response_bytes,
        first_operation_id: measured.first_operation_id.clone(),
        last_operation_id: measured.last_operation_id.clone(),
        operation_hash_sha256: measured.operation_hash_sha256.clone(),
        exact_status: measured.status_ok,
        exact_version: observed_downstream == downstream,
        exact_payload: measured.payload_ok,
        exact_eos: measured.eos_ok,
        sse_content_type: measured.sse_content_type_ok,
        hidden_retry_count: measured.retries,
        lane_quotas: measured.lane_quotas.clone(),
        lane_starts: measured.lane_quotas.clone(),
        lane_completions: measured.lane_completions.clone(),
    };
    operation.validate(&metadata)?;
    endpoints.validate(&metadata, &operation)?;
    raw::write_record_new(
        &leaf.join("endpoints.bin"),
        class,
        "endpoints.bin",
        &endpoints,
    )?;
    raw::write_record_new(
        &leaf.join("operation-summary.bin"),
        class,
        "operation-summary.bin",
        &operation,
    )?;
    if class.has_latencies() {
        raw::write_latencies_new(&leaf.join("latencies.u64le"), class, &measured.latencies_ns)?;
    } else if !measured.latencies_ns.is_empty() {
        return Err(Error::new(
            "S/D process arm produced forbidden latency data",
        ));
    }
    raw::validate_evidence_leaf(leaf, expected_relative).map_err(|error| {
        error
            .context("strict process raw leaf failed immediate parse")
            .with_role_diagnostic(RoleErrorStage::Finalize, RoleErrorCode::RawValidation)
    })?;

    let calibration_record = match class {
        EvidenceClass::S | EvidenceClass::C | EvidenceClass::D => Some(CalibrationRecord {
            schema: EXECUTION_SCHEMA.to_owned(),
            calibration_id: request.evidence_id.to_owned(),
            phase: match class {
                EvidenceClass::S => CalibrationPhase::Scout,
                EvidenceClass::C => CalibrationPhase::Williams,
                EvidenceClass::D => CalibrationPhase::Direct,
                EvidenceClass::A => unreachable!("matched above"),
            },
            class,
            cell,
            arm: request.planned.arm,
            target: request.planned.target,
            elapsed_ns: deadline_ns.saturating_sub(measured.window_start_ns),
            gateway_ticks: resources
                .gateway_ticks_drain
                .saturating_sub(resources.gateway_ticks_start),
            started_operations: measured.operations_started,
            deadline_completions: measured.operations_completed_by_deadline,
            drained_operations: measured.operations_completed,
            lane_quotas: measured.lane_quotas.clone(),
            lane_completions: measured.lane_completions.clone(),
            endpoint_hashes_match: true,
            process_identity: observation_id,
        }),
        EvidenceClass::A => None,
    };
    if let Some(record) = &calibration_record {
        record.validate()?;
    }
    let raw_leaf = published_leaf
        .strip_prefix(repository)
        .map_err(|_| Error::new("raw process leaf escaped repository"))?
        .to_string_lossy()
        .into_owned();
    Ok(ProcessArmOutcome {
        metadata,
        calibration_record,
        raw_leaf,
        thread_signature_sha256: thread_map.signature_sha256.clone(),
        lifecycle,
        quality_blockers: quality_blockers.to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
fn process_lifecycle_events(
    workload: Workload,
    quiet: &QuietEvidence,
    setup_start_ns: u64,
    setup_end_ns: u64,
    proof_start_ns: u64,
    proof_end_ns: u64,
    websocket_retirement: Option<(u64, u64, u64)>,
    materialized: &LoadResult,
    ordinary_materialization: Option<&MaterializationEvidence>,
    freeze_start_ns: u64,
    release_ns: u64,
    measured: &LoadResult,
    exit_end_ns: u64,
) -> Result<Vec<LifecycleEvent>> {
    let materialization_end_ns =
        ordinary_materialization.map_or(materialized.window_end_ns, |evidence| evidence.end_ns);
    if setup_start_ns != quiet.end_ns
        || setup_end_ns > proof_start_ns
        || proof_start_ns > proof_end_ns
        || proof_end_ns > materialized.window_start_ns
        || materialized.window_end_ns > materialization_end_ns
        || materialization_end_ns > freeze_start_ns
        || freeze_start_ns > release_ns
        || release_ns > measured.window_start_ns
        || measured.window_end_ns > exit_end_ns
    {
        return Err(Error::new(
            "process lifecycle timestamps are non-monotonic or overlap",
        ));
    }
    let material_deadline = materialized
        .window_deadline_ns
        .ok_or_else(|| Error::new("materialization has no fixed deadline"))?;
    let measured_deadline = measured
        .window_deadline_ns
        .unwrap_or(measured.window_end_ns);
    let mut events = vec![LifecycleEvent {
        stage: LifecycleStage::QuietObservation,
        monotonic_start_ns: quiet.start_ns,
        monotonic_end_ns: quiet.end_ns,
    }];
    let mut cursor = quiet.end_ns;
    events.push(LifecycleEvent {
        stage: LifecycleStage::SetupReadiness,
        monotonic_start_ns: cursor,
        monotonic_end_ns: proof_start_ns,
    });
    cursor = proof_start_ns;
    events.push(LifecycleEvent {
        stage: LifecycleStage::ProtocolProof,
        monotonic_start_ns: cursor,
        monotonic_end_ns: proof_end_ns,
    });
    cursor = proof_end_ns;
    if workload == Workload::WebSocket {
        let (retirement_start, retirement_end, elapsed_ns) = websocket_retirement
            .ok_or_else(|| Error::new("WebSocket lifecycle lacks retirement evidence"))?;
        if retirement_start < proof_end_ns
            || retirement_end < retirement_start
            || elapsed_ns < WEBSOCKET_KEEPALIVE_NS + WEBSOCKET_STABILITY_NS
        {
            return Err(Error::new("WebSocket retirement timestamps are invalid"));
        }
        events.push(LifecycleEvent {
            stage: LifecycleStage::WebsocketRetirement,
            monotonic_start_ns: cursor,
            monotonic_end_ns: retirement_end,
        });
        cursor = retirement_end;
    } else if websocket_retirement.is_some() {
        return Err(Error::new(
            "ordinary lifecycle unexpectedly contains WebSocket retirement",
        ));
    }
    events.push(LifecycleEvent {
        stage: LifecycleStage::Materialization,
        monotonic_start_ns: cursor,
        monotonic_end_ns: material_deadline,
    });
    events.push(LifecycleEvent {
        stage: LifecycleStage::WarmupDrain,
        monotonic_start_ns: material_deadline,
        monotonic_end_ns: materialization_end_ns,
    });
    events.push(LifecycleEvent {
        stage: LifecycleStage::Freeze,
        monotonic_start_ns: materialization_end_ns,
        monotonic_end_ns: release_ns,
    });
    events.push(LifecycleEvent {
        stage: LifecycleStage::Steady,
        monotonic_start_ns: release_ns,
        monotonic_end_ns: measured_deadline,
    });
    events.push(LifecycleEvent {
        stage: LifecycleStage::MeasuredDrain,
        monotonic_start_ns: measured_deadline,
        monotonic_end_ns: measured.window_end_ns,
    });
    events.push(LifecycleEvent {
        stage: LifecycleStage::Exit,
        monotonic_start_ns: measured.window_end_ns,
        monotonic_end_ns: exit_end_ns,
    });
    Ok(events)
}

fn process_resource_evidence(
    frozen: &SamplerReport,
    sampled: &SamplerReport,
    frequency_gate: FrequencyGate,
    quality_blockers: &[String],
) -> Result<ResourceEvidence> {
    let start = frozen
        .resources
        .iter()
        .map(|resource| (resource.role, resource))
        .collect::<BTreeMap<_, _>>();
    let end = sampled
        .resources
        .iter()
        .map(|resource| (resource.role, resource))
        .collect::<BTreeMap<_, _>>();
    let gateway_start = start
        .get(&Role::Gateway)
        .map(|resource| resource.user_ticks.saturating_add(resource.system_ticks))
        .unwrap_or(0);
    let gateway_end = end
        .get(&Role::Gateway)
        .map(|resource| resource.user_ticks.saturating_add(resource.system_ticks))
        .unwrap_or(0);
    let vm_hwm_kib = end
        .get(&Role::Gateway)
        .and_then(|resource| resource.vm_hwm_kib)
        .or_else(|| {
            end.values()
                .filter_map(|resource| resource.vm_hwm_kib)
                .max()
        })
        .ok_or_else(|| Error::new("process arm has no final VmHWM evidence"))?;
    let attribution = if sampled.bracket_attribution.is_empty() {
        &sampled.attribution
    } else {
        &sampled.bracket_attribution
    };
    let buckets = attribution
        .iter()
        .map(cpu_bucket_evidence)
        .collect::<Result<Vec<_>>>()?;
    let frozen_whole_buckets = sampled
        .attribution
        .iter()
        .map(cpu_bucket_evidence)
        .collect::<Result<Vec<_>>>()?;
    let frozen_bracket_buckets = sampled
        .bracket_attribution
        .iter()
        .map(cpu_bucket_evidence)
        .collect::<Result<Vec<_>>>()?;
    let dynamic_buckets = sampled
        .dynamic_attribution
        .iter()
        .map(cpu_bucket_evidence)
        .collect::<Result<Vec<_>>>()?;
    let residuals = sampled
        .residuals
        .iter()
        .map(|residual| runtime_residual_evidence(residual, "frozen"))
        .chain(
            sampled
                .dynamic_residuals
                .iter()
                .map(|residual| runtime_residual_evidence(residual, "dynamic")),
        )
        .collect::<Vec<_>>();
    let scope_decisions = sampled
        .noise_scopes
        .iter()
        .map(|scope| NoiseScopeDecisionEvidence {
            attribution_phase: scope.attribution_phase.clone(),
            interval_kind: scope.interval_kind.clone(),
            scope: scope.scope.clone(),
            role: scope.role.clone(),
            cpus: scope.cpus.clone(),
            start_ns: scope.start_ns,
            end_ns: scope.end_ns,
            capacity_ticks: scope.capacity_ticks,
            external_upper_ticks: scope.external_upper_ticks,
            limit_basis_points: scope.limit_basis_points,
            accepted: scope.capacity_ticks > 0
                && u128::from(scope.external_upper_ticks) * 10_000
                    <= u128::from(scope.capacity_ticks) * u128::from(scope.limit_basis_points),
        })
        .collect();
    let mut utilization = Vec::new();
    for (role, label, cpus) in [
        (Role::Fixture, "fixture", FIXTURE_CPUS),
        (Role::Load, "load", LOAD_CPUS),
        (Role::Sampler, "sampler", CONTROL_CPUS),
    ] {
        let Some(start_resource) = start.get(&role) else {
            continue;
        };
        let end_resource = end
            .get(&role)
            .ok_or_else(|| Error::new("sampled role resource disappeared"))?;
        let start_ticks = start_resource
            .user_ticks
            .checked_add(start_resource.system_ticks)
            .ok_or_else(|| Error::new("role start tick overflow"))?;
        let end_ticks = end_resource
            .user_ticks
            .checked_add(end_resource.system_ticks)
            .ok_or_else(|| Error::new("role end tick overflow"))?;
        let capacity_ticks = sampled
            .attribution
            .iter()
            .filter(|sample| cpus.contains(&sample.cpu))
            .try_fold(0_u64, |total, sample| {
                total.checked_add(sample.capacity_ticks)
            })
            .ok_or_else(|| Error::new("role utilization capacity overflow"))?;
        utilization.push(RoleUtilizationEvidence {
            role: label.to_owned(),
            used_ticks: end_ticks
                .checked_sub(start_ticks)
                .ok_or_else(|| Error::new("role utilization ticks decreased"))?,
            capacity_ticks,
        });
    }
    let (frequency_floor_khz, calibration_frequency_p05_khz) = match frequency_gate {
        FrequencyGate::CalibrationAbsolute => (4_000_000, None),
        FrequencyGate::AuthoritativeRelative {
            calibration_p05_khz,
        } => (
            calibration_p05_khz.saturating_mul(95) / 100,
            Some(calibration_p05_khz),
        ),
    };
    Ok(ResourceEvidence {
        schema: "amg-http2-perf/resources/v2".to_owned(),
        gateway_ticks_start: gateway_start,
        gateway_ticks_deadline: gateway_end,
        gateway_ticks_drain: gateway_end,
        vm_hwm_kib,
        major_faults: sampled.major_faults_delta,
        swap_in_delta: sampled.swap_in,
        swap_out_delta: sampled.swap_out,
        steal_ticks_delta: sampled.steal_ticks_delta,
        memory_psi_full_us: sampled.memory_psi_full_us,
        io_psi_full_us: sampled.io_psi_full_us,
        tctl_start_millidegrees: sampled
            .tctl_start_millidegrees
            .ok_or_else(|| Error::new("Tctl start sample missing"))?,
        tctl_max_millidegrees: sampled
            .tctl_max_millidegrees
            .ok_or_else(|| Error::new("Tctl maximum sample missing"))?,
        median_frequency_khz: sampled
            .median_frequency_khz
            .ok_or_else(|| Error::new("median frequency sample missing"))?,
        frequency_floor_khz,
        buckets,
        utilization,
        direct_ceiling_ops: None,
        gateway_ops: None,
        calibration_direct_ops: None,
        frozen_whole_buckets,
        frozen_bracket_buckets,
        dynamic_buckets,
        residuals,
        scope_decisions,
        producer_blockers: quality_blockers.to_vec(),
        calibration_frequency_p05_khz,
    })
}

fn cpu_bucket_evidence(sample: &crate::control::CpuAttribution) -> Result<CpuBucketEvidence> {
    Ok(CpuBucketEvidence {
        cpu: sample.cpu,
        role: sampled_cpu_role(sample.cpu)?.to_owned(),
        start_ns: sample.start_ns,
        end_ns: sample.end_ns,
        process_runtime_lower: sample.role_runtime_lower_ticks,
        process_runtime_upper: sample.role_runtime_upper_ticks,
        tid_runtime_lower: sample.role_runtime_lower_ticks,
        tid_runtime_upper: sample.role_runtime_upper_ticks,
        capacity_ticks: sample.capacity_ticks,
        scheduled_ticks: sample.scheduled_ticks,
        external_upper_ticks: sample.external_upper_ticks,
        attribution_uncertainty_ticks: sample.attribution_uncertainty_ticks,
    })
}

fn runtime_residual_evidence(
    residual: &crate::control::RuntimeResidual,
    phase: &str,
) -> RuntimeResidualEvidence {
    RuntimeResidualEvidence {
        role: residual.role.label().to_owned(),
        phase: phase.to_owned(),
        start_ns: residual.start_ns,
        end_ns: residual.end_ns,
        process_runtime_lower_ticks: residual.process_runtime_lower_ticks,
        process_runtime_upper_ticks: residual.process_runtime_upper_ticks,
        known_tid_runtime_lower_ticks: residual.known_tid_runtime_lower_ticks,
        known_tid_runtime_upper_ticks: residual.known_tid_runtime_upper_ticks,
        u_role_lower_ticks: residual.u_role_lower_ticks,
        u_role_upper_ticks: residual.u_role_upper_ticks,
        signed_residual_lower_ticks: residual.signed_residual_lower_ticks,
        signed_residual_upper_ticks: residual.signed_residual_upper_ticks,
    }
}

fn sampled_cpu_role(cpu: u16) -> Result<&'static str> {
    if GATEWAY_CPUS.contains(&cpu) {
        Ok("gateway")
    } else if FIXTURE_CPUS.contains(&cpu) {
        Ok("fixture")
    } else if LOAD_CPUS.contains(&cpu) {
        Ok("load")
    } else if CONTROL_CPUS.contains(&cpu) {
        Ok("control")
    } else {
        Err(Error::new(format!(
            "sampled CPU {cpu} is outside every role set"
        )))
    }
}

#[derive(Debug)]
struct FixturePhaseSummary {
    operations: u64,
    request_bytes: u64,
    response_bytes: u64,
    operation_hash_sha256: String,
    observed_protocol: Option<Protocol>,
    identity_correct: bool,
    headers_sanitized: bool,
}

fn fixture_phase_summary(fixture: &FixtureResult, phase: u16) -> Result<FixturePhaseSummary> {
    let aggregates = fixture
        .phase_aggregates
        .iter()
        .filter(|aggregate| aggregate.phase == phase)
        .collect::<Vec<_>>();
    if aggregates.len() == 1 {
        let aggregate = aggregates[0];
        return Ok(FixturePhaseSummary {
            operations: aggregate.operations,
            request_bytes: aggregate.request_bytes,
            response_bytes: aggregate.response_bytes,
            operation_hash_sha256: aggregate.operation_hash_sha256.clone(),
            observed_protocol: aggregate.observed_protocol,
            identity_correct: aggregate.identity_correct,
            headers_sanitized: aggregate.headers_sanitized,
        });
    }
    if fixture.compacted || aggregates.len() > 1 {
        return Err(Error::new(
            "compact fixture phase aggregate is missing or duplicated",
        ));
    }
    let mut observations = fixture
        .observations
        .iter()
        .filter_map(|observation| {
            crate::topology::parse_operation_id(&observation.operation_id)
                .ok()
                .filter(|value| (*value >> 112) as u16 == phase)
                .map(|_| observation)
        })
        .collect::<Vec<_>>();
    observations.sort_by(|left, right| {
        left.operation_id
            .as_bytes()
            .cmp(right.operation_id.as_bytes())
    });
    let mut hasher = Sha256::new();
    let mut request_bytes = 0_u64;
    let mut response_bytes = 0_u64;
    for observation in &observations {
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
    Ok(FixturePhaseSummary {
        operations: observations.len() as u64,
        request_bytes,
        response_bytes,
        operation_hash_sha256: format!("{:x}", hasher.finalize()),
        observed_protocol: observations
            .first()
            .map(|observation| observation.protocol)
            .filter(|protocol| {
                observations
                    .iter()
                    .all(|observation| observation.protocol == *protocol)
            }),
        identity_correct: observations
            .iter()
            .all(|observation| observation.identity_ok),
        headers_sanitized: observations
            .iter()
            .all(|observation| observation.request_headers_sanitized),
    })
}

fn raw_clock_discontinuities(samples: &[ClockSample]) -> Result<u64> {
    samples.windows(2).try_fold(0_u64, |count, pair| {
        let previous_boot = pair[0]
            .boottime_before_ns
            .checked_add(pair[0].boottime_after_ns)
            .ok_or_else(|| Error::new("previous clock midpoint overflow"))?
            / 2;
        let current_boot = pair[1]
            .boottime_before_ns
            .checked_add(pair[1].boottime_after_ns)
            .ok_or_else(|| Error::new("current clock midpoint overflow"))?
            / 2;
        let boot_delta = current_boot
            .checked_sub(previous_boot)
            .ok_or_else(|| Error::new("clock BOOTTIME moved backwards"))?;
        let discontinuous = pair[1]
            .realtime_ns
            .checked_sub(pair[0].realtime_ns)
            .is_none_or(|delta| delta.abs_diff(boot_delta) > 100_000_000);
        count
            .checked_add(u64::from(discontinuous))
            .ok_or_else(|| Error::new("clock discontinuity count overflow"))
    })
}

fn protocol_date_values_sha256<'a>(
    dates: impl Iterator<Item = &'a crate::control::ProtocolDateObservation>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"amg-http2-perf/protocol-date-values/v1\0");
    for date in dates {
        hasher.update((date.value.len() as u64).to_be_bytes());
        hasher.update(date.value.as_bytes());
        hasher.update(date.unix_seconds.to_be_bytes());
        hasher.update(date.boottime_before_ns.to_be_bytes());
        hasher.update(date.boottime_after_ns.to_be_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn endpoint_phase_from_proof(
    proof: &LoadProof,
    workload: Workload,
) -> Result<EndpointPhaseEvidence> {
    let started = if workload == Workload::WebSocket {
        proof.tunnels
    } else {
        proof.warmup_operations
    };
    endpoint_phase_from_parts(
        RawPhase::Proof,
        started,
        proof.request_bytes,
        proof.response_bytes,
        &proof.operation_hash_sha256,
        &proof.connection_ledger,
        &proof.attempts,
    )
}

fn endpoint_phase_from_result(
    phase: RawPhase,
    result: &LoadResult,
) -> Result<EndpointPhaseEvidence> {
    endpoint_phase_from_parts(
        phase,
        result.operations_started,
        result.request_bytes,
        result.response_bytes,
        &result.operation_hash_sha256,
        &result.connection_ledger,
        &result.attempts,
    )
}

fn endpoint_phase_from_parts(
    phase: RawPhase,
    started_operations: u64,
    request_bytes: u64,
    response_bytes: u64,
    operation_hash_sha256: &str,
    ledger: &crate::control::ConnectionLedger,
    attempts: &crate::control::AttemptEvidence,
) -> Result<EndpointPhaseEvidence> {
    crate::schema::validate_non_placeholder_sha256("phase operation hash", operation_hash_sha256)?;
    crate::schema::validate_non_placeholder_sha256(
        "phase connection hash",
        &ledger.operation_connection_hash_sha256,
    )?;
    Ok(EndpointPhaseEvidence {
        phase,
        started_operations,
        attempt_starts: attempts.starts,
        attempt_successes: attempts.successes,
        planned_connections: ledger.planned_connections,
        socket_creations: ledger.socket_creations,
        connect_attempts: ledger.connect_attempts,
        connect_successes: ledger.connect_successes,
        failed_attempts: attempts.failures,
        cumulative_connections: ledger.cumulative_connections,
        requests: ledger.requests,
        responses: ledger.responses,
        request_bytes,
        response_bytes,
        close_tokens: ledger.close_tokens,
        keep_alive_tokens: ledger.keep_alive_tokens,
        response_eos: ledger.response_eos,
        transport_eof: ledger.transport_eof,
        active_connections: ledger.active_connections,
        max_active_connections: ledger.max_active_connections,
        max_requests_per_connection: ledger.max_requests_per_connection,
        h2_streams: ledger.h2_streams,
        max_active_h2_streams: ledger.max_active_h2_streams,
        first_h2_stream_id: ledger.first_h2_stream_id,
        last_h2_stream_id: ledger.last_h2_stream_id,
        h2_stream_sequence_sha256: ledger.h2_stream_sequence_sha256.clone(),
        retries: attempts.retries,
        reconnects: attempts.reconnects,
        reuse_attempts: ledger.reuse_attempts,
        operation_hash_sha256: operation_hash_sha256.to_owned(),
        connection_hash_sha256: ledger.operation_connection_hash_sha256.clone(),
    })
}

fn empty_endpoint_drain_phase() -> Result<EndpointPhaseEvidence> {
    let hash = sha256_hex(b"amg-http2-perf/empty-drain-phase/v1");
    Ok(EndpointPhaseEvidence {
        phase: RawPhase::Drain,
        started_operations: 0,
        attempt_starts: 0,
        attempt_successes: 0,
        planned_connections: 0,
        socket_creations: 0,
        connect_attempts: 0,
        connect_successes: 0,
        failed_attempts: 0,
        cumulative_connections: 0,
        requests: 0,
        responses: 0,
        request_bytes: 0,
        response_bytes: 0,
        close_tokens: 0,
        keep_alive_tokens: 0,
        response_eos: 0,
        transport_eof: 0,
        active_connections: 0,
        max_active_connections: 0,
        max_requests_per_connection: 0,
        h2_streams: 0,
        max_active_h2_streams: 0,
        first_h2_stream_id: None,
        last_h2_stream_id: None,
        h2_stream_sequence_sha256: crate::wire::request_stream_sequence_sha256(0)?,
        retries: 0,
        reconnects: 0,
        reuse_attempts: 0,
        operation_hash_sha256: hash.clone(),
        connection_hash_sha256: hash,
    })
}

#[derive(Debug)]
struct WireEndpointSummary {
    settings: bool,
    settings_ack: bool,
    enable_connect: bool,
    stream_count: u64,
    first_stream_id: Option<u32>,
    last_stream_id: Option<u32>,
    stream_hash: String,
}

fn wire_endpoint_summary(
    protocol: Protocol,
    wire: &[crate::wire::H2WireEvidence],
) -> Result<WireEndpointSummary> {
    if protocol == Protocol::H1 {
        if !wire.is_empty() {
            return Err(Error::new("H1 endpoint carries H2 wire evidence"));
        }
        return Ok(WireEndpointSummary {
            settings: false,
            settings_ack: false,
            enable_connect: false,
            stream_count: 0,
            first_stream_id: None,
            last_stream_id: None,
            stream_hash: crate::wire::request_stream_sequence_sha256(0)?,
        });
    }
    if wire.len() != 1 {
        return Err(Error::new("H2 endpoint lacks exactly one wire observer"));
    }
    let evidence = &wire[0];
    evidence.validate(false)?;
    Ok(WireEndpointSummary {
        settings: evidence.local_initial_settings_seen && evidence.peer_initial_settings_seen,
        settings_ack: evidence.local_settings_ack_seen && evidence.peer_settings_ack_seen,
        enable_connect: evidence.enable_connect_protocol_seen,
        stream_count: evidence.request_headers,
        first_stream_id: evidence.first_request_stream_id,
        last_stream_id: evidence.last_request_stream_id,
        stream_hash: evidence.request_stream_sequence_sha256.clone(),
    })
}

fn total_downstream_connections(
    protocol: Protocol,
    workload: Workload,
    concurrency: u16,
    proof: &LoadProof,
    materialized: &LoadResult,
    ordinary_materialization: Option<&MaterializationEvidence>,
    measured: &LoadResult,
) -> Result<u64> {
    if protocol == Protocol::H2 {
        return Ok(1);
    }
    if workload != Workload::Upload1Mib {
        return Ok(u64::from(concurrency));
    }
    let stability_wave_connections = ordinary_materialization
        .map(|evidence| {
            evidence.waves.iter().try_fold(0_u64, |total, wave| {
                total
                    .checked_add(wave.result.connection_ledger.cumulative_connections)
                    .ok_or_else(|| Error::new("materialization connection count overflow"))
            })
        })
        .transpose()?
        .unwrap_or(0);
    proof
        .connection_ledger
        .cumulative_connections
        .checked_add(materialized.connection_ledger.cumulative_connections)
        .and_then(|value| value.checked_add(stability_wave_connections))
        .and_then(|value| value.checked_add(measured.connection_ledger.cumulative_connections))
        .ok_or_else(|| Error::new("fresh-H1 arm cumulative connection count overflow"))
}

const fn raw_protocol(protocol: Protocol) -> RawProtocol {
    match protocol {
        Protocol::H1 => RawProtocol::H1,
        Protocol::H2 => RawProtocol::H2,
    }
}

/// Runs exactly the B11/C1 upload case through the same process implementation
/// as the topology smoke, but stores it as explicitly non-authoritative,
/// separately identified diagnostic evidence.
pub async fn diagnose_b11_c1_upload(
    repository: &Path,
    candidate: &str,
    host: HostPreflight,
) -> Result<B11UploadDiagnosticSummary> {
    if !host.smoke_ready {
        return Err(Error::new(format!(
            "host cannot run bounded B11 upload diagnostic: {}",
            host.blockers.join("; ")
        )));
    }
    let builds = build_exact_pair(repository, candidate)?;
    let harness_binary_sha256 = sha256_hex(&fs::read(std::env::current_exe()?)?);
    let triplet = realtime_triplet()?;
    let diagnostic_id = format!(
        "diag-b11-c1-upload-{}-{}",
        triplet.realtime_ns,
        &harness_binary_sha256[..12]
    );
    let root = execution_root(repository)
        .join("diagnostics")
        .join(&diagnostic_id);
    fs::create_dir_all(
        root.parent()
            .ok_or_else(|| Error::new("diagnostic root has no parent"))?,
    )?;
    fs::create_dir(&root).context("exclusive-create B11 upload diagnostic root")?;
    set_mode(&root, 0o700)?;
    let case_root = root.join("case");
    fs::create_dir(&case_root)?;
    set_mode(&case_root, 0o700)?;

    let build_set_bytes = json::canonical_bytes(&builds)?;
    let build_set_sha256 = sha256_hex(&build_set_bytes);
    write_diagnostic_static_evidence(
        repository,
        &root,
        &diagnostic_id,
        &builds,
        &host,
        &build_set_bytes,
        &harness_binary_sha256,
    )?;
    let quiet = crate::linux::observe_quiet_exact()?;
    quiet.validate()?;
    json::write_new_canonical(&root.join("quiet.json"), &quiet)?;

    let monotonic_start_ns = clock_ns(ClockKind::Monotonic)?;
    let monotonic_deadline_ns = monotonic_start_ns
        .checked_add(B11_UPLOAD_DIAGNOSTIC_CAP_NS)
        .ok_or_else(|| Error::new("diagnostic monotonic deadline overflow"))?;
    let execution = tokio::time::timeout(
        Duration::from_nanos(B11_UPLOAD_DIAGNOSTIC_CAP_NS),
        run_smoke_arm(
            repository,
            &builds,
            GatewaySmokeRequest {
                run_id: &diagnostic_id,
                ordinal: 0,
                cell: Cell {
                    workload: Workload::Upload1Mib,
                    concurrency: 1,
                },
                arm: Arm::B11,
                arm_root: &case_root,
            },
        ),
    )
    .await;

    let (outcome, case, failure) = match execution {
        Ok(Ok(mut value)) => {
            remove_case_runtime_if_present(&case_root)?;
            let case = value.smoke_case()?;
            write_gateway_smoke_case(&case_root, &value)?;
            value.fixture_evidence = None;
            value.sampler_freeze = None;
            value.sampler_final = None;
            (DiagnosticOutcome::Completed, Some(case), None)
        }
        Ok(Err(error)) => {
            remove_case_runtime_if_present(&case_root)?;
            let failure = safe_diagnostic_failure(&error, false);
            (DiagnosticOutcome::Failed, None, Some(failure))
        }
        Err(_) => {
            remove_case_runtime_if_present(&case_root)?;
            let error = Error::new("bounded B11 upload diagnostic timed out")
                .with_role_diagnostic(RoleErrorStage::Proof, RoleErrorCode::Timeout);
            let failure = safe_diagnostic_failure(&error, true);
            (DiagnosticOutcome::Failed, None, Some(failure))
        }
    };
    let monotonic_end_ns = clock_ns(ClockKind::Monotonic)?;
    let diagnostic = B11UploadDiagnosticEvidence {
        schema: DIAGNOSTIC_SCHEMA.to_owned(),
        diagnostic_id: diagnostic_id.clone(),
        authoritative: false,
        topology_smoke: false,
        key: SmokeCaseKey {
            kind: SmokeKind::Gateway,
            concurrency: 1,
            workload: Workload::Upload1Mib,
            arm: Some(Arm::B11),
            direct_protocol: None,
        },
        monotonic_start_ns,
        monotonic_deadline_ns,
        monotonic_end_ns,
        baseline_binary_sha256: builds.baseline.binary_sha256.clone(),
        candidate_binary_sha256: builds.candidate.binary_sha256.clone(),
        harness_binary_sha256,
        build_set_sha256,
        outcome,
        case,
        failure,
    };
    diagnostic.validate()?;
    json::write_new_canonical(&root.join("diagnostic.json"), &diagnostic)?;
    let safe_failure = diagnostic.failure.as_ref().map(|failure| {
        format!(
            "stage={} code={} detail-sha256={}",
            failure.stage.label(),
            failure.code.label(),
            failure.detail_sha256
        )
    });
    json::write_new_canonical(
        &root.join("execution-state.json"),
        &ExecutionStateEvidence {
            schema: EXECUTION_STATE_SCHEMA.to_owned(),
            evidence_id: diagnostic_id.clone(),
            phase: ExecutionPhase::Diagnostic,
            next_ordinal: 0,
            planned_arms: 0,
            completed_arms: 0,
            complete: false,
            crash_detail: safe_failure,
            campaign_boottime_start_ns: None,
            campaign_boottime_end_ns: None,
            machine_sha256: None,
            build_set_sha256: None,
            journal_root_sha256: None,
            partially_started_ordinal: None,
        },
    )?;
    let seal = create_seal(&root)?;
    let staging = execution_root(repository)
        .join("delivery-staging")
        .join(&diagnostic_id);
    let index = crate::bundle::create_bundle_derived(&root, &staging)?;
    if index.evidence_kind != EvidenceKind::Diagnostic
        || index.terminal_state != TerminalState::Blocked
    {
        return Err(Error::new(
            "diagnostic bundle was relabeled as gate evidence",
        ));
    }
    let index_path = staging.join("bundle-index.json");
    let index_sha256 = sha256_hex(&fs::read(&index_path)?);
    let scratch = execution_root(repository)
        .join("bundle-verify")
        .join(&index_sha256);
    let receipt = crate::bundle::verify_bundle(&index_path, &scratch)?;
    receipt.validate()?;
    json::write_new_canonical(&staging.join("verification.json"), &receipt)?;
    let failure = diagnostic.failure.as_ref();
    let phase_separation = diagnostic
        .case
        .as_ref()
        .and_then(|case| case.phase_separation.as_ref());
    let materialization_lanes = phase_separation
        .map(|phase| u64::try_from(phase.materialization_lane_completions.len()))
        .transpose()
        .context("convert diagnostic materialization lane count")?;
    Ok(B11UploadDiagnosticSummary {
        schema: DIAGNOSTIC_SCHEMA.to_owned(),
        diagnostic_id,
        cell: Cell {
            workload: diagnostic.key.workload,
            concurrency: diagnostic.key.concurrency,
        },
        authoritative: false,
        topology_smoke: false,
        case_succeeded: diagnostic.outcome == DiagnosticOutcome::Completed,
        stage: failure.map(|value| value.stage),
        code: failure.map(|value| value.code),
        detail_sha256: failure.map(|value| value.detail_sha256.clone()),
        evidence_root: root.display().to_string(),
        seal_root_sha256: seal.root_sha256,
        bundle_index_path: index_path.display().to_string(),
        bundle_index_sha256: index_sha256,
        bundle_verified: receipt.success && receipt.byte_equal,
        materialization_lanes,
        materialization_operations: phase_separation.map(|phase| phase.materialization_operations),
        materialization_waves: phase_separation.map(|phase| phase.materialization_waves),
        materialization_stable: phase_separation.map(|_| true),
        measured_operations: phase_separation.map(|phase| phase.measured_operations),
        post_freeze_tid_change: phase_separation.map(|phase| {
            phase.births_after_freeze != 0
                || phase.deaths_after_freeze != 0
                || phase.migrations_after_freeze != 0
        }),
    })
}

fn safe_diagnostic_failure(error: &Error, timed_out: bool) -> DiagnosticFailure {
    if let Some(role_failure) = error.role_failure() {
        if let (Some(stage), Some(code)) = (role_failure.stage, role_failure.code) {
            return DiagnosticFailure {
                stage,
                code,
                detail_sha256: role_failure.detail_sha256.clone(),
                role_failure: Some(role_failure.clone()),
            };
        }
    }
    let diagnostic = error.role_diagnostic();
    DiagnosticFailure {
        stage: diagnostic.map_or(RoleErrorStage::Proof, |value| value.stage),
        code: diagnostic.map_or(
            if timed_out {
                RoleErrorCode::Timeout
            } else {
                error.role_code().unwrap_or(RoleErrorCode::Internal)
            },
            |value| value.code,
        ),
        detail_sha256: sha256_hex(error.to_string().as_bytes()),
        role_failure: None,
    }
}

fn remove_case_runtime_if_present(case_root: &Path) -> Result<()> {
    let runtime = case_root.join("runtime");
    if runtime.exists() {
        fs::remove_dir_all(runtime)?;
    }
    Ok(())
}

fn write_diagnostic_static_evidence(
    repository: &Path,
    root: &Path,
    diagnostic_id: &str,
    builds: &BuildSet,
    host: &HostPreflight,
    build_set_bytes: &[u8],
    harness_binary_sha256: &str,
) -> Result<()> {
    let intent = Intent {
        schema: INTENT_SCHEMA.to_owned(),
        evidence_id: diagnostic_id.to_owned(),
        evidence_kind: EvidenceKind::Diagnostic,
        baseline_commit: BASELINE_COMMIT.to_owned(),
        candidate_commit: builds.candidate.commit.clone(),
        campaign_seed: 0x4449_4147_4231_3101,
        encoder: crate::codec::current_identity(),
        producer_executable_sha256: harness_binary_sha256.to_owned(),
        zstd: ZstdParameterProgram::fixed(),
        raw_limits: RawLimits::fixed(),
        trust_boundary: None,
        harness_provenance: None,
    };
    intent.validate()?;
    json::write_new_canonical(&root.join("intent.json"), &intent)?;
    crate::json::write_new_bytes(&root.join("build-set.json"), build_set_bytes)?;

    let host_bytes = json::canonical_bytes(host)?;
    let boot_id = fs::read("/proc/sys/kernel/random/boot_id")?;
    let machine = MachineEvidence {
        schema: crate::schema::MACHINE_SCHEMA.to_owned(),
        fingerprint_sha256: sha256_hex(&host_bytes),
        boot_id_sha256: sha256_hex(&boot_id),
        online_cpus: host
            .observations
            .get("online_cpus")
            .cloned()
            .ok_or_else(|| Error::new("diagnostic preflight online CPU evidence missing"))?,
        clocksource: host
            .observations
            .get("clocksource")
            .cloned()
            .ok_or_else(|| Error::new("diagnostic preflight clocksource evidence missing"))?,
        clock_ticks_per_second: host
            .observations
            .get("clk_tck")
            .ok_or_else(|| Error::new("diagnostic preflight CLK_TCK evidence missing"))?
            .parse::<u64>()
            .context("parse diagnostic preflight CLK_TCK")?,
        math_abi_sha256: crate::statistics::math_target_sha256(),
    };
    machine.validate()?;
    json::write_new_canonical(&root.join("machine.json"), &machine)?;

    let tracked_actual = crate::storage::actual_regular_bytes_if_exists(
        &repository.join(".legion/tasks/prove-http2-performance-regression/artifacts"),
    )?;
    let concurrency = 1_u16;
    let conn_live = 136_u64 + u64::from(concurrency);
    let endpoint_bound = 512_u64 + 160_u64 * conn_live + 512_u64 * u64::from(concurrency);
    let projection = ProjectionEvidence {
        schema: PROJECTION_SCHEMA.to_owned(),
        revision: 0,
        predecessor: None,
        source_arm_root_sha256: None,
        completed_arms: 0,
        runtime_projected_ns: B11_UPLOAD_DIAGNOSTIC_CAP_NS,
        runtime_actual_ns: 0,
        q_extra_ns: 0,
        raw_projected_bytes: TASK_CAP_BYTES,
        raw_actual_bytes: 0,
        tracked_projected_bytes: TASK_CAP_BYTES,
        tracked_actual_bytes: tracked_actual,
        endpoint_bound_bytes: endpoint_bound,
        conn_live,
        concurrency,
        storage_admission: None,
    };
    projection.validate()?;
    json::write_new_canonical(&root.join("projection.json"), &projection)?;
    json::write_new_canonical(&root.join("delivery-projection.json"), &projection)?;
    Ok(())
}

pub async fn direct_upload_probe(repository: &Path) -> Result<Vec<DirectSmokeOutcome>> {
    let run_id = format!("direct-upload-probe-{}", realtime_triplet()?.realtime_ns);
    let mut outcomes = Vec::with_capacity(2);
    for (ordinal, protocol) in [Protocol::H1, Protocol::H2].into_iter().enumerate() {
        outcomes.push(
            run_direct_upload_smoke(repository, &run_id, ordinal as u64, protocol, 1, None)
                .await
                .context(format!("direct upload probe {}", protocol.label()))?,
        );
    }
    Ok(outcomes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnedRoleCycleOutcome {
    pub proof_operations: u64,
    pub measured_operations: u64,
    pub fixture_operations: u64,
    pub fixture_operation_hash_sha256: String,
}

/// Exercises the real exec'd fixture, load, and sampler roles through one B11
/// C1 GET command lifecycle without running the sealed topology smoke.
pub async fn spawned_b11_get_role_cycle(
    repository: &Path,
    executable: &Path,
    evidence_root: &Path,
) -> Result<SpawnedRoleCycleOutcome> {
    let context = ControlContext {
        run_id: format!("spawned-b11-get-cycle-{}", std::process::id()),
        cell: Cell {
            workload: Workload::Get,
            concurrency: 1,
        },
        arm: Arm::B11,
        block: 0,
        orchestrator: process_identity(std::process::id())?,
    };
    let executable_sha256 = sha256_hex(&fs::read(executable)?);
    let orchestrator_sha256 = sha256_hex(&fs::read(std::env::current_exe()?)?);
    let mut fixture = spawn_role(
        executable,
        repository,
        Role::Fixture,
        FIXTURE_CPUS,
        &context,
    )?;
    let mut load = spawn_role(executable, repository, Role::Load, LOAD_CPUS, &context)?;
    let mut sampler = spawn_role(
        executable,
        repository,
        Role::Sampler,
        CONTROL_CPUS,
        &context,
    )?;
    fixture.set_evidence_root(evidence_root);
    load.set_evidence_root(evidence_root);
    sampler.set_evidence_root(evidence_root);
    authenticate_role(&mut fixture).await?;
    authenticate_role(&mut load).await?;
    authenticate_role(&mut sampler)
        .await
        .map_err(|error| error.context("B11 GET sampler authentication"))?;
    let (fixture_address, _) = role_ready_fixture(&mut fixture).await?;
    role_ready(&mut load, Role::Load).await?;
    role_ready(&mut sampler, Role::Sampler)
        .await
        .map_err(|error| error.context("B11 GET sampler readiness"))?;
    fixture
        .send(ControlBody::ConfigureFixture {
            target: LoadTarget::Direct,
            workload: Workload::Get,
            expected_protocol: Protocol::H1,
            corpus_sha256: crate::topology::Corpus::fixed().sha256(),
        })
        .await?;
    expect(&mut fixture, |body| {
        matches!(body, ControlBody::FixtureConfigured)
    })
    .await?;
    sampler
        .send(ControlBody::RegisterProcesses {
            processes: vec![
                observed(
                    Role::Orchestrator,
                    process_identity(std::process::id())?,
                    &orchestrator_sha256,
                    CONTROL_CPUS,
                ),
                observed(
                    Role::Fixture,
                    fixture.identity().clone(),
                    &executable_sha256,
                    FIXTURE_CPUS,
                ),
                observed(
                    Role::Load,
                    load.identity().clone(),
                    &executable_sha256,
                    LOAD_CPUS,
                ),
                observed(
                    Role::Sampler,
                    sampler.identity().clone(),
                    &executable_sha256,
                    CONTROL_CPUS,
                ),
            ],
            evidence_root: Some(evidence_root.display().to_string()),
        })
        .await?;
    expect(&mut sampler, |body| {
        matches!(body, ControlBody::ProcessesRegistered)
    })
    .await
    .map_err(|error| error.context("B11 GET sampler registration"))?;
    load.send(ControlBody::PrepareLoad {
        target: LoadTarget::Direct,
        workload: Workload::Get,
        protocol: Protocol::H1,
        gateway_address: None,
        fixture_address: fixture_address.to_string(),
        cookie_header: None,
        warmup_operations: 1,
        websocket_settle: false,
    })
    .await?;
    let proof = expect_prepared(&mut load).await?;
    validate_proof(&proof, Protocol::H1, Workload::Get, 1)?;
    let materialization = run_ordinary_materialization(
        &mut load,
        &mut sampler,
        context.cell,
        Protocol::H1,
        None,
        SMOKE_STABILITY_CAP_NS,
        &evidence_root.join("materialization.json"),
    )
    .await?;
    sampler.send(ControlBody::Freeze).await?;
    let frozen = expect_frozen(&mut sampler)
        .await
        .map_err(|error| error.context("B11 GET sampler freeze"))?;
    if frozen.post_freeze_change.is_some() {
        return Err(Error::new("spawned role cycle changed at freeze"));
    }
    ensure_materialization_matches_freeze(&materialization, &frozen)?;
    sampler.send(ControlBody::Release).await?;
    match sampler
        .receive()
        .await
        .map_err(|error| error.context("B11 GET sampler release"))?
    {
        ControlBody::Released { .. } => {}
        other => return Err(Error::new(format!("expected Released, got {other:?}"))),
    }
    load.send(ControlBody::Measure {
        phase: 2,
        operations: 1,
    })
    .await?;
    let measured = expect_measured(&mut load).await?;
    validate_load_result(&measured, 1, Workload::Get, Protocol::H1, 1)?;
    sampler.send(ControlBody::FinalSample).await?;
    let sampled = expect_sampled(&mut sampler)
        .await
        .map_err(|error| error.context("B11 GET sampler final sample"))?;
    if sampled.post_freeze_change.is_some() {
        return Err(Error::new("spawned role cycle changed after freeze"));
    }
    fixture.send(ControlBody::FixtureSnapshot).await?;
    let fixture_result = expect_fixture(&mut fixture).await?;
    validate_fixture(
        &fixture_result,
        FixtureExpectation {
            target: LoadTarget::Direct,
            protocol: Protocol::H1,
            workload: Workload::Get,
            concurrency: 1,
        },
        FixturePhaseResults {
            proof: &proof,
            websocket_warmup: None,
            ordinary_materialization: Some(&materialization),
            measured: &measured,
        },
    )?;
    sampler.send(ControlBody::Stop).await?;
    expect_stopped(&mut sampler, Role::Sampler)
        .await
        .map_err(|error| error.context("B11 GET sampler stop"))?;
    sampler.wait_clean(Duration::from_secs(1))?;
    load.send(ControlBody::Stop).await?;
    expect_stopped(&mut load, Role::Load).await?;
    load.wait_clean(Duration::from_secs(1))?;
    fixture.send(ControlBody::Stop).await?;
    expect_stopped(&mut fixture, Role::Fixture).await?;
    fixture.wait_clean(Duration::from_secs(1))?;
    Ok(SpawnedRoleCycleOutcome {
        proof_operations: proof.warmup_operations,
        measured_operations: measured.operations_completed,
        fixture_operations: fixture_result.observations.len() as u64,
        fixture_operation_hash_sha256: fixture_result.operation_hash_sha256,
    })
}

/// Produces retained, secret-free evidence for authenticated command failure,
/// pre-authentication startup EOF, and a signal crash/EOF using real roles.
pub async fn spawned_role_failure_probes(
    repository: &Path,
    executable: &Path,
    evidence_root: &Path,
) -> Result<Vec<SafeRoleFailure>> {
    let context = ControlContext {
        run_id: format!("spawned-role-failure-probes-{}", std::process::id()),
        cell: Cell {
            workload: Workload::Get,
            concurrency: 1,
        },
        arm: Arm::B11,
        block: 0,
        orchestrator: process_identity(std::process::id())?,
    };
    let mut failures = Vec::new();

    let command_root = evidence_root.join("command");
    fs::create_dir(&command_root)?;
    set_mode(&command_root, 0o700)?;
    let mut command = spawn_role(
        executable,
        repository,
        Role::Fixture,
        FIXTURE_CPUS,
        &context,
    )?;
    command.set_evidence_root(&command_root);
    authenticate_role(&mut command).await?;
    role_ready_fixture(&mut command).await?;
    command.send(ControlBody::Inventory).await?;
    failures.push(expect_retained_role_failure(command.receive().await)?);

    let startup_root = evidence_root.join("startup");
    fs::create_dir(&startup_root)?;
    set_mode(&startup_root, 0o700)?;
    let incomplete_arguments = vec![
        "role".to_owned(),
        "--kind".to_owned(),
        "fixture".to_owned(),
        "--run".to_owned(),
        context.run_id.clone(),
    ];
    let mut startup = spawn_role_with_arguments(
        executable,
        repository,
        Role::Fixture,
        FIXTURE_CPUS,
        &context,
        &incomplete_arguments,
    )?;
    startup.set_evidence_root(&startup_root);
    failures.push(expect_retained_role_failure(startup.receive().await)?);

    let crash_root = evidence_root.join("crash");
    fs::create_dir(&crash_root)?;
    set_mode(&crash_root, 0o700)?;
    let mut crash = spawn_role(
        executable,
        repository,
        Role::Fixture,
        FIXTURE_CPUS,
        &context,
    )?;
    crash.set_evidence_root(&crash_root);
    authenticate_role(&mut crash).await?;
    role_ready_fixture(&mut crash).await?;
    crash.mark_failure_stage(RoleErrorStage::Exit);
    crash.child.validate()?;
    validated_signal(&crash.child.identity, libc::SIGKILL)?;
    failures.push(expect_retained_role_failure(crash.receive().await)?);

    for failure in &failures {
        failure.validate()?;
    }
    Ok(failures)
}

fn expect_retained_role_failure(result: Result<ControlBody>) -> Result<SafeRoleFailure> {
    result
        .err()
        .and_then(|error| error.role_failure().cloned())
        .ok_or_else(|| Error::new("real role failure did not retain classified evidence"))
}

struct OpenSmoke<'a> {
    root: &'a Path,
    calibration_id: &'a str,
    builds: &'a BuildSet,
    campaign_boottime_start_ns: u64,
}

pub async fn smoke_all(
    repository: &Path,
    candidate: &str,
    host: HostPreflight,
) -> Result<(SmokeSummary, PathBuf)> {
    smoke_all_mode(repository, candidate, host, None).await
}

pub async fn smoke_into_open_calibration(
    repository: &Path,
    candidate: &str,
    host: HostPreflight,
    builds: &BuildSet,
    root: &Path,
    calibration_id: &str,
    campaign_boottime_start_ns: u64,
) -> Result<SmokeSummary> {
    let (summary, returned_root) = smoke_all_mode(
        repository,
        candidate,
        host,
        Some(OpenSmoke {
            root,
            calibration_id,
            builds,
            campaign_boottime_start_ns,
        }),
    )
    .await?;
    if returned_root != root {
        return Err(Error::new(
            "open smoke returned a different calibration root",
        ));
    }
    Ok(summary)
}

async fn smoke_all_mode(
    repository: &Path,
    candidate: &str,
    host: HostPreflight,
    open: Option<OpenSmoke<'_>>,
) -> Result<(SmokeSummary, PathBuf)> {
    if !host.smoke_ready {
        return Err(Error::new(format!(
            "host cannot run bounded smoke: {}",
            host.blockers.join("; ")
        )));
    }
    let standalone = open.is_none();
    let builds = match &open {
        Some(open) => {
            if open.builds.candidate.commit != candidate {
                return Err(Error::new(
                    "open smoke candidate differs from its initialized build set",
                ));
            }
            open.builds.clone()
        }
        None => build_exact_pair(repository, candidate)?,
    };
    let triplet = realtime_triplet()?;
    let unix_seconds = triplet.realtime_ns / 1_000_000_000;
    let started_utc = utc_rfc3339(unix_seconds)?;
    let harness_binary_sha256 = sha256_hex(&fs::read(std::env::current_exe()?)?);
    let (run_id, root, boottime_start_ns) = match &open {
        Some(open) => (
            open.calibration_id.to_owned(),
            open.root.to_path_buf(),
            open.campaign_boottime_start_ns,
        ),
        None => {
            let run_id = format!(
                "cal-smoke-{}-{}",
                &candidate[..12],
                &harness_binary_sha256[..12]
            );
            let root = execution_root(repository)
                .join("calibrations")
                .join(&run_id);
            fs::create_dir_all(
                root.parent()
                    .ok_or_else(|| Error::new("smoke root has no parent"))?,
            )?;
            fs::create_dir(&root).context("exclusive-create smoke root")?;
            set_mode(&root, 0o700)?;
            (run_id, root, clock_ns(ClockKind::Boottime)?)
        }
    };
    let monotonic_start_ns = clock_ns(ClockKind::Monotonic)?;
    let monotonic_deadline_ns = monotonic_start_ns
        .checked_add(SMOKE_CAP_NS)
        .ok_or_else(|| Error::new("smoke monotonic deadline overflow"))?;
    let build_set_bytes = json::canonical_bytes(&builds)?;
    let build_set_sha256 = sha256_hex(&build_set_bytes);
    if standalone {
        write_smoke_static_evidence(
            repository,
            &root,
            SmokeStaticEvidence {
                calibration_id: &run_id,
                candidate,
                host: &host,
                build_set_bytes: &build_set_bytes,
                harness_binary_sha256: &harness_binary_sha256,
            },
        )?;
    } else {
        verify_open_smoke_static_evidence(
            &root,
            &run_id,
            candidate,
            &build_set_bytes,
            &harness_binary_sha256,
        )?;
    }
    let quiet = crate::linux::observe_quiet_exact()?;
    quiet.validate()?;
    json::write_new_canonical(&root.join("quiet.json"), &quiet)?;
    if !quiet.clean() {
        let error = Error::new("Q_obs did not find a clean interval within 120 seconds of Q_extra");
        retain_failed_smoke(
            repository,
            &root,
            &run_id,
            monotonic_start_ns,
            monotonic_deadline_ns,
            &builds,
            &harness_binary_sha256,
            &build_set_sha256,
            Vec::new(),
            SmokeCaseKey {
                kind: SmokeKind::Gateway,
                concurrency: 1,
                workload: Workload::Get,
                arm: Some(Arm::B11),
                direct_protocol: None,
            },
            &error,
            standalone,
        )?;
        return Err(error);
    }
    let cases_root = root.join("smoke-cases");
    fs::create_dir(&cases_root)?;
    set_mode(&cases_root, 0o700)?;
    let mut arms = Vec::with_capacity(50);
    let mut ordinal = 0_u64;
    for concurrency in [1_u16, 64] {
        for workload in Workload::ALL {
            for arm in Arm::ALL {
                let arm_root = cases_root.join(format!(
                    "arm-{ordinal:02}-c{concurrency}-{}-{}",
                    workload.code(),
                    arm.code()
                ));
                fs::create_dir(&arm_root)?;
                set_mode(&arm_root, 0o700)?;
                let outcome = run_smoke_arm(
                    repository,
                    &builds,
                    GatewaySmokeRequest {
                        run_id: &run_id,
                        ordinal,
                        cell: Cell {
                            workload,
                            concurrency,
                        },
                        arm,
                        arm_root: &arm_root,
                    },
                )
                .await;
                match outcome {
                    Ok(mut value) => {
                        if arm_root.join("runtime").exists() {
                            fs::remove_dir_all(arm_root.join("runtime"))?;
                        }
                        write_gateway_smoke_case(&arm_root, &value)?;
                        value.fixture_evidence = None;
                        value.sampler_freeze = None;
                        value.sampler_final = None;
                        arms.push(value);
                    }
                    Err(error) => {
                        if arm_root.join("runtime").exists() {
                            let _ = fs::remove_dir_all(arm_root.join("runtime"));
                        }
                        let failure_key = SmokeCaseKey {
                            kind: SmokeKind::Gateway,
                            concurrency,
                            workload,
                            arm: Some(arm),
                            direct_protocol: None,
                        };
                        let retained = retain_failed_smoke(
                            repository,
                            &root,
                            &run_id,
                            monotonic_start_ns,
                            monotonic_deadline_ns,
                            &builds,
                            &harness_binary_sha256,
                            &build_set_sha256,
                            collect_smoke_cases(&arms, &[])?,
                            failure_key,
                            &error,
                            standalone,
                        );
                        if let Err(retain_error) = retained {
                            return Err(Error::new(format!(
                                "{error}; additionally failed to retain smoke evidence: {retain_error}"
                            )));
                        }
                        return Err(error.context(format!(
                            "smoke C{concurrency} {} {} (partial evidence retained at {})",
                            workload.code(),
                            arm.code(),
                            root.display()
                        )));
                    }
                }
                let elapsed = clock_ns(ClockKind::Monotonic)?
                    .checked_sub(monotonic_start_ns)
                    .ok_or_else(|| Error::new("smoke enclosing clock moved backwards"))?;
                if elapsed > SMOKE_CAP_NS {
                    let error = Error::new("all-topology smoke exceeded 300-second cap");
                    let failure_key = SmokeCaseKey {
                        kind: SmokeKind::Gateway,
                        concurrency,
                        workload,
                        arm: Some(arm),
                        direct_protocol: None,
                    };
                    retain_failed_smoke(
                        repository,
                        &root,
                        &run_id,
                        monotonic_start_ns,
                        monotonic_deadline_ns,
                        &builds,
                        &harness_binary_sha256,
                        &build_set_sha256,
                        collect_smoke_cases(&arms, &[])?,
                        failure_key,
                        &error,
                        standalone,
                    )?;
                    return Err(error);
                }
                ordinal += 1;
            }
        }
    }
    let mut direct_upload_controls = Vec::with_capacity(4);
    for concurrency in [1_u16, 64] {
        for protocol in [Protocol::H1, Protocol::H2] {
            let direct_ordinal = direct_upload_controls.len() as u64;
            let arm_root =
                cases_root.join(format!("direct-upload-c{concurrency}-{}", protocol.label()));
            fs::create_dir(&arm_root)?;
            set_mode(&arm_root, 0o700)?;
            let outcome = run_direct_upload_smoke(
                repository,
                &run_id,
                direct_ordinal,
                protocol,
                concurrency,
                Some(&arm_root),
            )
            .await;
            match outcome {
                Ok(mut value) => {
                    write_direct_smoke_case(&arm_root, &value)?;
                    value.fixture_evidence = None;
                    value.sampler_freeze = None;
                    value.sampler_final = None;
                    direct_upload_controls.push(value);
                }
                Err(error) => {
                    let failure_key = SmokeCaseKey {
                        kind: SmokeKind::Direct,
                        concurrency,
                        workload: Workload::Upload1Mib,
                        arm: None,
                        direct_protocol: Some(match protocol {
                            Protocol::H1 => RawProtocol::H1,
                            Protocol::H2 => RawProtocol::H2,
                        }),
                    };
                    retain_failed_smoke(
                        repository,
                        &root,
                        &run_id,
                        monotonic_start_ns,
                        monotonic_deadline_ns,
                        &builds,
                        &harness_binary_sha256,
                        &build_set_sha256,
                        collect_smoke_cases(&arms, &direct_upload_controls)?,
                        failure_key,
                        &error,
                        standalone,
                    )?;
                    return Err(error.context(format!(
                        "smoke direct upload C{concurrency} {} (partial evidence retained at {})",
                        protocol.label(),
                        root.display()
                    )));
                }
            }
            let elapsed = clock_ns(ClockKind::Monotonic)?
                .checked_sub(monotonic_start_ns)
                .ok_or_else(|| Error::new("smoke enclosing clock moved backwards"))?;
            if elapsed > SMOKE_CAP_NS {
                let error = Error::new("all-topology smoke exceeded 300-second cap");
                let failure_key = SmokeCaseKey {
                    kind: SmokeKind::Direct,
                    concurrency,
                    workload: Workload::Upload1Mib,
                    arm: None,
                    direct_protocol: Some(match protocol {
                        Protocol::H1 => RawProtocol::H1,
                        Protocol::H2 => RawProtocol::H2,
                    }),
                };
                retain_failed_smoke(
                    repository,
                    &root,
                    &run_id,
                    monotonic_start_ns,
                    monotonic_deadline_ns,
                    &builds,
                    &harness_binary_sha256,
                    &build_set_sha256,
                    collect_smoke_cases(&arms, &direct_upload_controls)?,
                    failure_key,
                    &error,
                    standalone,
                )?;
                return Err(error);
            }
        }
    }
    let boottime_end_ns = clock_ns(ClockKind::Boottime)?;
    let host_quality_blockers = host.blockers;
    let smoke_cases = collect_smoke_cases(&arms, &direct_upload_controls)?;
    let mut summary = SmokeSummary {
        schema: SMOKE_SCHEMA.to_owned(),
        authoritative: false,
        run_id: run_id.clone(),
        baseline_commit: BASELINE_COMMIT.to_owned(),
        candidate_commit: candidate.to_owned(),
        baseline_binary_sha256: builds.baseline.binary_sha256.clone(),
        candidate_binary_sha256: builds.candidate.binary_sha256.clone(),
        harness_binary_sha256: harness_binary_sha256.clone(),
        started_utc,
        boottime_start_ns,
        boottime_end_ns,
        protocol_correct_arms: arms.len() as u64,
        direct_protocol_correct_cases: direct_upload_controls.len() as u64,
        direct_upload_controls,
        host_quality_blockers,
        bundle_index_path: String::new(),
        bundle_index_sha256: String::new(),
        bundle_terminal_state: TerminalState::Blocked,
        bundle_verified: false,
        arms,
    };
    let topology = TopologySmokeEvidence {
        schema: crate::evidence::SMOKE_SCHEMA.to_owned(),
        calibration_id: run_id.clone(),
        attempt_ordinal: 0,
        monotonic_start_ns,
        monotonic_deadline_ns,
        monotonic_end_ns: clock_ns(ClockKind::Monotonic)?,
        baseline_binary_sha256: builds.baseline.binary_sha256.clone(),
        candidate_binary_sha256: builds.candidate.binary_sha256.clone(),
        harness_binary_sha256: harness_binary_sha256.clone(),
        build_set_sha256,
        build_set_required: true,
        raw_cases_required: true,
        terminal_integrity_failure: None,
        cases: smoke_cases,
    };
    topology.validate()?;
    json::write_new_canonical(&root.join("topology-smoke.json"), &topology)?;
    if !standalone {
        return Ok((summary, root));
    }
    json::write_new_canonical(
        &root.join("execution-state.json"),
        &ExecutionStateEvidence {
            schema: EXECUTION_STATE_SCHEMA.to_owned(),
            evidence_id: run_id.clone(),
            phase: ExecutionPhase::Scout,
            next_ordinal: 0,
            planned_arms: 0,
            completed_arms: 0,
            complete: false,
            crash_detail: None,
            campaign_boottime_start_ns: None,
            campaign_boottime_end_ns: None,
            machine_sha256: None,
            build_set_sha256: None,
            journal_root_sha256: None,
            partially_started_ordinal: None,
        },
    )?;
    create_seal(&root)?;
    let staging = execution_root(repository)
        .join("delivery-staging")
        .join(&run_id);
    let index = crate::bundle::create_bundle_derived(&root, &staging)?;
    let index_path = staging.join("bundle-index.json");
    let index_bytes = fs::read(&index_path)?;
    let index_sha256 = sha256_hex(&index_bytes);
    let scratch = execution_root(repository)
        .join("bundle-verify")
        .join(&index_sha256);
    let receipt = crate::bundle::verify_bundle(&index_path, &scratch)?;
    receipt.validate()?;
    json::write_new_canonical(&staging.join("verification.json"), &receipt)?;
    summary.bundle_index_path = index_path
        .strip_prefix(repository)
        .map_err(|_| Error::new("smoke bundle index escaped repository"))?
        .to_string_lossy()
        .into_owned();
    summary.bundle_index_sha256 = index_sha256;
    summary.bundle_terminal_state = index.terminal_state;
    summary.bundle_verified = receipt.success && receipt.byte_equal;
    Ok((summary, root))
}

fn verify_open_smoke_static_evidence(
    root: &Path,
    calibration_id: &str,
    candidate: &str,
    expected_build_set: &[u8],
    harness_binary_sha256: &str,
) -> Result<()> {
    if root.join("seal.json").exists()
        || root.join("topology-smoke.json").exists()
        || root.join("smoke-cases").exists()
        || root.join("quiet.json").exists()
    {
        return Err(Error::new(
            "open calibration root has already started or sealed its smoke",
        ));
    }
    let intent_bytes = fs::read(root.join("intent.json"))?;
    let intent: Intent = json::require_canonical(&intent_bytes)?;
    intent.validate()?;
    if intent.evidence_kind != EvidenceKind::Calibration
        || intent.evidence_id != calibration_id
        || intent.candidate_commit != candidate
        || intent.producer_executable_sha256 != harness_binary_sha256
        || fs::read(root.join("build-set.json"))? != expected_build_set
    {
        return Err(Error::new(
            "open calibration static identity differs from the exact smoke",
        ));
    }
    let machine: MachineEvidence = json::require_canonical(&fs::read(root.join("machine.json"))?)?;
    machine.validate()?;
    Ok(())
}

fn write_smoke_static_evidence(
    repository: &Path,
    root: &Path,
    evidence: SmokeStaticEvidence<'_>,
) -> Result<()> {
    let SmokeStaticEvidence {
        calibration_id,
        candidate,
        host,
        build_set_bytes,
        harness_binary_sha256,
    } = evidence;
    let intent = Intent {
        schema: INTENT_SCHEMA.to_owned(),
        evidence_id: calibration_id.to_owned(),
        evidence_kind: EvidenceKind::Calibration,
        baseline_commit: BASELINE_COMMIT.to_owned(),
        candidate_commit: candidate.to_owned(),
        campaign_seed: 0x534d_4f4b_455f_0001,
        encoder: crate::codec::current_identity(),
        producer_executable_sha256: harness_binary_sha256.to_owned(),
        zstd: ZstdParameterProgram::fixed(),
        raw_limits: RawLimits::fixed(),
        trust_boundary: None,
        harness_provenance: Some(crate::harness::require_exact_committed_harness(repository)?),
    };
    intent.validate()?;
    json::write_new_canonical(&root.join("intent.json"), &intent)?;
    crate::json::write_new_bytes(&root.join("build-set.json"), build_set_bytes)?;

    let host_bytes = json::canonical_bytes(host)?;
    let boot_id = fs::read("/proc/sys/kernel/random/boot_id")?;
    let machine = MachineEvidence {
        schema: crate::schema::MACHINE_SCHEMA.to_owned(),
        fingerprint_sha256: sha256_hex(&host_bytes),
        boot_id_sha256: sha256_hex(&boot_id),
        online_cpus: host
            .observations
            .get("online_cpus")
            .cloned()
            .ok_or_else(|| Error::new("preflight online CPU evidence missing"))?,
        clocksource: host
            .observations
            .get("clocksource")
            .cloned()
            .ok_or_else(|| Error::new("preflight clocksource evidence missing"))?,
        clock_ticks_per_second: host
            .observations
            .get("clk_tck")
            .ok_or_else(|| Error::new("preflight CLK_TCK evidence missing"))?
            .parse::<u64>()
            .context("parse preflight CLK_TCK")?,
        math_abi_sha256: crate::statistics::math_target_sha256(),
    };
    machine.validate()?;
    json::write_new_canonical(&root.join("machine.json"), &machine)?;

    let artifact_root =
        repository.join(".legion/tasks/prove-http2-performance-regression/artifacts");
    let tracked_actual = crate::storage::actual_regular_bytes_if_exists(&artifact_root)?;
    let endpoint_bound = 512_u64 + 160_u64 * 200 + 512_u64 * 64;
    let projection = ProjectionEvidence {
        schema: PROJECTION_SCHEMA.to_owned(),
        revision: 0,
        predecessor: None,
        source_arm_root_sha256: None,
        completed_arms: 0,
        runtime_projected_ns: SMOKE_CAP_NS,
        runtime_actual_ns: 0,
        q_extra_ns: 0,
        raw_projected_bytes: TASK_CAP_BYTES,
        raw_actual_bytes: 0,
        tracked_projected_bytes: TASK_CAP_BYTES,
        tracked_actual_bytes: tracked_actual,
        endpoint_bound_bytes: endpoint_bound,
        conn_live: 200,
        concurrency: 64,
        storage_admission: None,
    };
    projection.validate()?;
    json::write_new_canonical(&root.join("projection.json"), &projection)?;
    json::write_new_canonical(&root.join("delivery-projection.json"), &projection)?;
    Ok(())
}

fn collect_smoke_cases(
    arms: &[SmokeArmOutcome],
    direct: &[DirectSmokeOutcome],
) -> Result<Vec<SmokeCaseEvidence>> {
    let mut cases = arms
        .iter()
        .map(SmokeArmOutcome::smoke_case)
        .chain(direct.iter().map(DirectSmokeOutcome::smoke_case))
        .collect::<Result<Vec<_>>>()?;
    cases.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(cases)
}

fn write_gateway_smoke_case(root: &Path, outcome: &SmokeArmOutcome) -> Result<()> {
    json::write_new_canonical(&root.join("case.json"), outcome)?;
    write_smoke_case_raw_members(
        root,
        outcome
            .fixture_evidence
            .as_ref()
            .ok_or_else(|| Error::new("gateway smoke fixture raw evidence missing"))?,
        outcome
            .sampler_freeze
            .as_ref()
            .ok_or_else(|| Error::new("gateway smoke freeze evidence missing"))?,
        outcome
            .sampler_final
            .as_ref()
            .ok_or_else(|| Error::new("gateway smoke final sampler evidence missing"))?,
    )
}

fn write_direct_smoke_case(root: &Path, outcome: &DirectSmokeOutcome) -> Result<()> {
    json::write_new_canonical(&root.join("case.json"), outcome)?;
    write_smoke_case_raw_members(
        root,
        outcome
            .fixture_evidence
            .as_ref()
            .ok_or_else(|| Error::new("direct smoke fixture raw evidence missing"))?,
        outcome
            .sampler_freeze
            .as_ref()
            .ok_or_else(|| Error::new("direct smoke freeze evidence missing"))?,
        outcome
            .sampler_final
            .as_ref()
            .ok_or_else(|| Error::new("direct smoke final sampler evidence missing"))?,
    )
}

fn write_smoke_case_raw_members(
    root: &Path,
    fixture: &FixtureResult,
    freeze: &SamplerReport,
    final_report: &SamplerReport,
) -> Result<()> {
    let fixture_bytes = json::canonical_bytes(fixture)?;
    json::write_new_bytes(&root.join("fixture.bin"), &fixture_bytes)?;
    for (name, expected) in [
        ("sampler-freeze.bin", freeze),
        ("sampler-final.bin", final_report),
    ] {
        let persisted = crate::sampler::verify_persistent(&root.join(name))?;
        if persisted.monotonic_ns != expected.monotonic_ns
            || persisted.boottime_ns != expected.boottime_ns
            || persisted.inventories != expected.inventories
            || persisted.post_freeze_change != expected.post_freeze_change
        {
            return Err(Error::new(format!(
                "persistent {name} differs from its control-channel summary"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn retain_failed_smoke(
    repository: &Path,
    root: &Path,
    calibration_id: &str,
    monotonic_start_ns: u64,
    monotonic_deadline_ns: u64,
    builds: &BuildSet,
    harness_binary_sha256: &str,
    build_set_sha256: &str,
    mut cases: Vec<SmokeCaseEvidence>,
    failure_key: SmokeCaseKey,
    error: &Error,
    finalize: bool,
) -> Result<()> {
    cases.sort_by(|left, right| left.key.cmp(&right.key));
    let topology = TopologySmokeEvidence {
        schema: crate::evidence::SMOKE_SCHEMA.to_owned(),
        calibration_id: calibration_id.to_owned(),
        attempt_ordinal: 0,
        monotonic_start_ns,
        monotonic_deadline_ns,
        monotonic_end_ns: clock_ns(ClockKind::Monotonic)?,
        baseline_binary_sha256: builds.baseline.binary_sha256.clone(),
        candidate_binary_sha256: builds.candidate.binary_sha256.clone(),
        harness_binary_sha256: harness_binary_sha256.to_owned(),
        build_set_sha256: build_set_sha256.to_owned(),
        build_set_required: true,
        raw_cases_required: true,
        terminal_integrity_failure: Some(error.to_string()),
        cases,
    };
    topology.validate()?;
    json::write_new_canonical(&root.join("topology-smoke.json"), &topology)?;
    let detail = error.to_string();
    json::write_new_canonical(
        &root.join("smoke-failure.json"),
        &RetainedSmokeFailure {
            schema: SMOKE_FAILURE_SCHEMA.to_owned(),
            key: failure_key,
            detail_sha256: sha256_hex(detail.as_bytes()),
            detail,
            role_failure: error.role_failure().cloned(),
        },
    )?;
    if !finalize {
        return Ok(());
    }
    json::write_new_canonical(
        &root.join("execution-state.json"),
        &ExecutionStateEvidence {
            schema: EXECUTION_STATE_SCHEMA.to_owned(),
            evidence_id: calibration_id.to_owned(),
            phase: ExecutionPhase::Smoke,
            next_ordinal: 0,
            planned_arms: 0,
            completed_arms: 0,
            complete: false,
            crash_detail: Some(error.to_string()),
            campaign_boottime_start_ns: None,
            campaign_boottime_end_ns: None,
            machine_sha256: None,
            build_set_sha256: None,
            journal_root_sha256: None,
            partially_started_ordinal: None,
        },
    )?;
    create_seal(root)?;
    let staging = execution_root(repository)
        .join("delivery-staging")
        .join(calibration_id);
    let _index = crate::bundle::create_bundle_derived(root, &staging)?;
    let index_path = staging.join("bundle-index.json");
    let index_sha256 = sha256_hex(&fs::read(&index_path)?);
    let scratch = execution_root(repository)
        .join("bundle-verify")
        .join(index_sha256);
    let receipt = crate::bundle::verify_bundle(&index_path, &scratch)?;
    receipt.validate()?;
    json::write_new_canonical(&staging.join("verification.json"), &receipt)?;
    Ok(())
}

async fn run_smoke_arm(
    repository: &Path,
    builds: &BuildSet,
    request: GatewaySmokeRequest<'_>,
) -> Result<SmokeArmOutcome> {
    let GatewaySmokeRequest {
        run_id,
        ordinal,
        cell,
        arm,
        arm_root,
    } = request;
    let workload = cell.workload;
    let concurrency = cell.concurrency;
    let topology = ArmTopology::for_arm(arm);
    let build = match topology.gateway {
        GatewayObject::Baseline => &builds.baseline,
        GatewayObject::Candidate => &builds.candidate,
    };
    let binary = build.validate_binary_reuse(repository)?;
    let context = ControlContext {
        run_id: format!("{run_id}-{ordinal}"),
        cell,
        arm,
        block: ordinal,
        orchestrator: process_identity(std::process::id())?,
    };
    let executable = std::env::current_exe()?;
    let executable_sha256 = sha256_hex(&fs::read(&executable)?);
    let mut fixture = spawn_role(
        &executable,
        repository,
        Role::Fixture,
        FIXTURE_CPUS,
        &context,
    )?;
    let mut load = spawn_role(&executable, repository, Role::Load, LOAD_CPUS, &context)?;
    let mut sampler = spawn_role(
        &executable,
        repository,
        Role::Sampler,
        CONTROL_CPUS,
        &context,
    )?;
    fixture.set_evidence_root(arm_root);
    load.set_evidence_root(arm_root);
    sampler.set_evidence_root(arm_root);
    authenticate_role(&mut fixture).await?;
    authenticate_role(&mut load).await?;
    authenticate_role(&mut sampler).await?;
    let (fixture_address, tripwire_address) = role_ready_fixture(&mut fixture).await?;
    role_ready(&mut load, Role::Load).await?;
    role_ready(&mut sampler, Role::Sampler).await?;
    fixture
        .send(ControlBody::ConfigureFixture {
            target: LoadTarget::Gateway,
            workload,
            expected_protocol: topology.upstream,
            corpus_sha256: crate::topology::Corpus::fixed().sha256(),
        })
        .await?;
    expect(&mut fixture, |body| {
        matches!(body, ControlBody::FixtureConfigured)
    })
    .await?;

    let session_root = arm_root.join("runtime");
    fs::create_dir(&session_root)?;
    set_mode(&session_root, 0o700)?;
    let session = create_ready_session(&session_root.join("gateway.sqlite"))?;
    let gateway_address = reserve_loopback_address().await?;
    let gateway_child = spawn_gateway(
        &binary,
        repository,
        GATEWAY_CPUS,
        gateway_address,
        fixture_address,
        tripwire_address,
        topology.upstream,
        &session.database_path,
        &session_root,
    )?;
    wait_gateway_owned(gateway_address, &gateway_child.identity).await?;
    sampler
        .send(ControlBody::RegisterProcesses {
            processes: vec![
                observed(
                    Role::Orchestrator,
                    process_identity(std::process::id())?,
                    &executable_sha256,
                    CONTROL_CPUS,
                ),
                observed(
                    Role::Fixture,
                    fixture.identity().clone(),
                    &executable_sha256,
                    FIXTURE_CPUS,
                ),
                observed(
                    Role::Load,
                    load.identity().clone(),
                    &executable_sha256,
                    LOAD_CPUS,
                ),
                observed(
                    Role::Sampler,
                    sampler.identity().clone(),
                    &executable_sha256,
                    CONTROL_CPUS,
                ),
                observed(
                    Role::Gateway,
                    gateway_child.identity.clone(),
                    &build.binary_sha256,
                    GATEWAY_CPUS,
                ),
            ],
            evidence_root: Some(arm_root.display().to_string()),
        })
        .await?;
    expect(&mut sampler, |body| {
        matches!(body, ControlBody::ProcessesRegistered)
    })
    .await?;
    let pre_auth_tids = if workload == Workload::WebSocket {
        sampler.send(ControlBody::Inventory).await?;
        gateway_threads(expect_inventory(&mut sampler).await?)?
    } else {
        Vec::new()
    };
    load.send(ControlBody::PrepareLoad {
        target: LoadTarget::Gateway,
        workload,
        protocol: topology.downstream,
        gateway_address: Some(gateway_address.to_string()),
        fixture_address: fixture_address.to_string(),
        cookie_header: Some(session.cookie_header.clone()),
        warmup_operations: if workload == Workload::WebSocket {
            u64::from(concurrency)
        } else {
            1
        },
        websocket_settle: workload == Workload::WebSocket,
    })
    .await?;
    let proof = expect_prepared(&mut load).await?;
    validate_proof(
        &proof,
        topology.downstream,
        workload,
        u64::from(concurrency),
    )?;
    let (websocket_retirement_ns, websocket_warmup) = if workload == Workload::WebSocket {
        sampler
            .send(ControlBody::WaitWebsocketRetirement {
                gateway_pre_auth_tids: pre_auth_tids,
                keepalive_ns: WEBSOCKET_KEEPALIVE_NS,
                stability_ns: WEBSOCKET_STABILITY_NS,
                cap_ns: WEBSOCKET_SETTLE_CAP_NS,
            })
            .await?;
        let elapsed = match sampler.receive().await? {
            ControlBody::WebsocketRetired { elapsed_ns, .. } => elapsed_ns,
            other => {
                return Err(Error::new(format!(
                    "expected WebsocketRetired, got {other:?}"
                )))
            }
        };
        prepare_operation_corpus(&mut load, 1, u64::from(concurrency)).await?;
        load.send(ControlBody::Measure {
            phase: 1,
            operations: u64::from(concurrency),
        })
        .await?;
        let warm = expect_measured(&mut load).await?;
        validate_load_result(
            &warm,
            u64::from(concurrency),
            workload,
            topology.downstream,
            u64::from(concurrency),
        )?;
        (Some(elapsed), Some(warm))
    } else {
        (None, None)
    };
    let ordinary_materialization = if workload != Workload::WebSocket {
        Some(
            run_ordinary_materialization(
                &mut load,
                &mut sampler,
                cell,
                topology.downstream,
                None,
                SMOKE_STABILITY_CAP_NS,
                &arm_root.join("materialization.json"),
            )
            .await?,
        )
    } else {
        None
    };
    if workload == Workload::WebSocket {
        prepare_operation_corpus(&mut load, 2, u64::from(concurrency)).await?;
    }
    sampler.send(ControlBody::Freeze).await?;
    let frozen = expect_frozen(&mut sampler).await?;
    ensure_post_freeze_unchanged(&frozen, None)?;
    if let Some(materialization) = &ordinary_materialization {
        ensure_materialization_matches_freeze(materialization, &frozen)?;
    }
    sampler.send(ControlBody::Release).await?;
    let release_ns = match sampler.receive().await? {
        ControlBody::Released { monotonic_ns } => monotonic_ns,
        other => return Err(Error::new(format!("expected Released, got {other:?}"))),
    };
    let measured_operations = if workload == Workload::WebSocket {
        u64::from(concurrency)
    } else {
        1
    };
    load.send(ControlBody::MeasureCount {
        phase: 2,
        operations: measured_operations,
        retain_latencies: false,
    })
    .await?;
    let measured = expect_measured(&mut load).await?;
    let measured_release_handoff_ns = measured.window_start_ns.saturating_sub(release_ns);
    if measured_release_handoff_ns > MEASURE_HANDOFF_CAP_NS {
        return Err(Error::new(
            "smoke did not begin measured work immediately after release",
        ));
    }
    validate_process_load_result(
        &measured,
        workload,
        topology.downstream,
        u64::from(concurrency),
        false,
    )?;
    if measured.operations_started != measured_operations {
        return Err(Error::new("smoke measured operation count changed"));
    }
    sampler.send(ControlBody::FinalSample).await?;
    let sampled = expect_sampled(&mut sampler).await?;
    ensure_post_freeze_unchanged(&sampled, Some(&frozen))?;
    fixture.send(ControlBody::FixtureSnapshot).await?;
    let fixture_result = expect_fixture(&mut fixture).await?;
    validate_fixture(
        &fixture_result,
        FixtureExpectation {
            target: LoadTarget::Gateway,
            protocol: topology.upstream,
            workload,
            concurrency: u64::from(concurrency),
        },
        FixturePhaseResults {
            proof: &proof,
            websocket_warmup: websocket_warmup.as_ref(),
            ordinary_materialization: ordinary_materialization.as_ref(),
            measured: &measured,
        },
    )?;
    let quality_blockers = sampler_quality_blockers(&sampled);
    let ordinary_handoff_ns = if workload != Workload::WebSocket {
        Some(
            release_ns
                .checked_sub(
                    ordinary_materialization
                        .as_ref()
                        .ok_or_else(|| Error::new("ordinary materialization disappeared"))?
                        .end_ns,
                )
                .ok_or_else(|| Error::new("ordinary handoff clock moved backwards"))?,
        )
    } else {
        None
    };
    if ordinary_handoff_ns.is_some_and(|handoff| handoff > FREEZE_HANDOFF_CAP_NS) {
        return Err(Error::new(
            "ordinary materialization/freeze handoff exceeded one second",
        ));
    }

    let phase_separation = ordinary_materialization
        .as_ref()
        .map(|materialization| {
            smoke_phase_separation(
                &proof,
                materialization,
                &measured,
                &frozen,
                &sampled,
                ordinary_handoff_ns.unwrap_or(u64::MAX),
                measured_release_handoff_ns,
            )
        })
        .transpose()?;

    sampler.send(ControlBody::Stop).await?;
    expect_stopped(&mut sampler, Role::Sampler).await?;
    sampler.wait_clean(Duration::from_secs(1))?;
    load.send(ControlBody::Stop).await?;
    expect_stopped(&mut load, Role::Load).await?;
    load.wait_clean(Duration::from_secs(1))?;
    gateway_child.terminate(Duration::from_secs(1))?;
    fixture.send(ControlBody::Stop).await?;
    expect_stopped(&mut fixture, Role::Fixture).await?;
    fixture.wait_clean(Duration::from_secs(1))?;

    let frozen_thread_counts = frozen
        .inventories
        .iter()
        .map(|inventory| {
            (
                inventory.role.label().to_owned(),
                inventory.threads.len() as u64,
            )
        })
        .collect();
    let mut fixture_connection_ids = fixture_result
        .observations
        .iter()
        .map(|observation| observation.connection_id)
        .collect::<Vec<_>>();
    fixture_connection_ids.sort_unstable();
    fixture_connection_ids.dedup();
    let mut fixture_stream_ids = fixture_result
        .observations
        .iter()
        .filter_map(|observation| observation.stream_id)
        .collect::<Vec<_>>();
    fixture_stream_ids.sort_unstable();
    fixture_stream_ids.dedup();
    Ok(SmokeArmOutcome {
        ordinal,
        cell,
        arm,
        downstream: topology.downstream,
        upstream: topology.upstream,
        gateway_binary_sha256: build.binary_sha256.clone(),
        ready_session: session.evidence,
        proof,
        websocket_warmup,
        ordinary_materialization,
        phase_separation,
        measured,
        fixture_physical_connections: fixture_result.physical_connections,
        fixture_max_active_connections: fixture_result.max_active_connections,
        fixture_max_requests_per_connection: fixture_result.max_requests_per_connection,
        fixture_connection_ids,
        fixture_stream_ids,
        fixture_observations: fixture_result.observations.len() as u64,
        fixture_operation_hash_sha256: fixture_result.operation_hash_sha256.clone(),
        frozen_thread_counts,
        sampler_lifecycle_events: sampled.lifecycle_events,
        sampler_attribution_cpus: sampled.attribution.len() as u64,
        ordinary_handoff_ns,
        measured_release_handoff_ns: (workload != Workload::WebSocket)
            .then_some(measured_release_handoff_ns),
        websocket_retirement_ns,
        quality_blockers,
        fixture_evidence: Some(fixture_result),
        sampler_freeze: Some(frozen),
        sampler_final: Some(sampled),
    })
}

async fn run_direct_upload_smoke(
    repository: &Path,
    run_id: &str,
    ordinal: u64,
    protocol: Protocol,
    concurrency: u16,
    evidence_root: Option<&Path>,
) -> Result<DirectSmokeOutcome> {
    let cell = Cell {
        workload: Workload::Upload1Mib,
        concurrency,
    };
    let context = ControlContext {
        run_id: format!("{run_id}-direct-upload-{}", protocol.label()),
        cell,
        arm: if protocol == Protocol::H1 {
            Arm::B11
        } else {
            Arm::C22
        },
        block: 50 + ordinal,
        orchestrator: process_identity(std::process::id())?,
    };
    let executable = std::env::current_exe()?;
    let executable_sha256 = sha256_hex(&fs::read(&executable)?);
    let mut fixture = spawn_role(
        &executable,
        repository,
        Role::Fixture,
        FIXTURE_CPUS,
        &context,
    )?;
    let mut load = spawn_role(&executable, repository, Role::Load, LOAD_CPUS, &context)?;
    let mut sampler = spawn_role(
        &executable,
        repository,
        Role::Sampler,
        CONTROL_CPUS,
        &context,
    )?;
    if let Some(root) = evidence_root {
        fixture.set_evidence_root(root);
        load.set_evidence_root(root);
        sampler.set_evidence_root(root);
    }
    authenticate_role(&mut fixture).await?;
    authenticate_role(&mut load).await?;
    authenticate_role(&mut sampler).await?;
    let (fixture_address, _) = role_ready_fixture(&mut fixture)
        .await
        .context("direct fixture readiness")?;
    role_ready(&mut load, Role::Load)
        .await
        .context("direct load readiness")?;
    role_ready(&mut sampler, Role::Sampler)
        .await
        .context("direct sampler readiness")?;
    fixture
        .send(ControlBody::ConfigureFixture {
            target: LoadTarget::Direct,
            workload: Workload::Upload1Mib,
            expected_protocol: protocol,
            corpus_sha256: crate::topology::Corpus::fixed().sha256(),
        })
        .await?;
    expect(&mut fixture, |body| {
        matches!(body, ControlBody::FixtureConfigured)
    })
    .await
    .context("direct fixture configuration")?;
    sampler
        .send(ControlBody::RegisterProcesses {
            processes: vec![
                observed(
                    Role::Orchestrator,
                    process_identity(std::process::id())?,
                    &executable_sha256,
                    CONTROL_CPUS,
                ),
                observed(
                    Role::Fixture,
                    fixture.identity().clone(),
                    &executable_sha256,
                    FIXTURE_CPUS,
                ),
                observed(
                    Role::Load,
                    load.identity().clone(),
                    &executable_sha256,
                    LOAD_CPUS,
                ),
                observed(
                    Role::Sampler,
                    sampler.identity().clone(),
                    &executable_sha256,
                    CONTROL_CPUS,
                ),
            ],
            evidence_root: evidence_root.map(|path| path.display().to_string()),
        })
        .await?;
    expect(&mut sampler, |body| {
        matches!(body, ControlBody::ProcessesRegistered)
    })
    .await
    .context("direct process registration")?;
    load.send(ControlBody::PrepareLoad {
        target: LoadTarget::Direct,
        workload: Workload::Upload1Mib,
        protocol,
        gateway_address: None,
        fixture_address: fixture_address.to_string(),
        cookie_header: None,
        warmup_operations: u64::from(concurrency),
        websocket_settle: false,
    })
    .await?;
    let proof = expect_prepared(&mut load)
        .await
        .context("direct load preparation")?;
    validate_proof(
        &proof,
        protocol,
        Workload::Upload1Mib,
        u64::from(concurrency),
    )?;
    sampler.send(ControlBody::Freeze).await?;
    let frozen = expect_frozen(&mut sampler)
        .await
        .context("direct sampler freeze")?;
    if let Some(blocker) = &frozen.post_freeze_change {
        return Err(Error::new(format!(
            "direct post-freeze change at freeze: {blocker}"
        )));
    }
    sampler.send(ControlBody::Release).await?;
    match sampler.receive().await? {
        ControlBody::Released { .. } => {}
        other => return Err(Error::new(format!("expected Released, got {other:?}"))),
    }
    load.send(ControlBody::Measure {
        phase: 2,
        operations: u64::from(concurrency),
    })
    .await?;
    let measured = expect_measured(&mut load)
        .await
        .context("direct load measurement")?;
    validate_load_result(
        &measured,
        u64::from(concurrency),
        Workload::Upload1Mib,
        protocol,
        u64::from(concurrency),
    )?;
    sampler.send(ControlBody::FinalSample).await?;
    let sampled = expect_sampled(&mut sampler)
        .await
        .context("direct final sample")?;
    if let Some(blocker) = &sampled.post_freeze_change {
        return Err(Error::new(format!(
            "direct post-freeze TID integrity failure: {blocker}"
        )));
    }
    if protocol == Protocol::H1 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    fixture.send(ControlBody::FixtureSnapshot).await?;
    let fixture_result = expect_fixture(&mut fixture)
        .await
        .context("direct fixture snapshot")?;
    validate_direct_upload_fixture(
        &fixture_result,
        protocol,
        &proof,
        &measured,
        u64::from(concurrency),
    )?;

    sampler.send(ControlBody::Stop).await?;
    expect_stopped(&mut sampler, Role::Sampler).await?;
    sampler.wait_clean(Duration::from_secs(1))?;
    load.send(ControlBody::Stop).await?;
    expect_stopped(&mut load, Role::Load).await?;
    load.wait_clean(Duration::from_secs(1))?;
    fixture.send(ControlBody::Stop).await?;
    expect_stopped(&mut fixture, Role::Fixture).await?;
    fixture.wait_clean(Duration::from_secs(1))?;

    let mut fixture_connection_ids = fixture_result
        .observations
        .iter()
        .map(|observation| observation.connection_id)
        .collect::<Vec<_>>();
    fixture_connection_ids.sort_unstable();
    fixture_connection_ids.dedup();
    let mut fixture_stream_ids = fixture_result
        .observations
        .iter()
        .filter_map(|observation| observation.stream_id)
        .collect::<Vec<_>>();
    fixture_stream_ids.sort_unstable();
    fixture_stream_ids.dedup();
    let frozen_thread_counts = frozen
        .inventories
        .iter()
        .map(|inventory| {
            (
                inventory.role.label().to_owned(),
                inventory.threads.len() as u64,
            )
        })
        .collect();
    Ok(DirectSmokeOutcome {
        ordinal,
        cell,
        protocol,
        proof,
        measured,
        fixture_physical_connections: fixture_result.physical_connections,
        fixture_active_connections: fixture_result.active_connections,
        fixture_max_active_connections: fixture_result.max_active_connections,
        fixture_max_requests_per_connection: fixture_result.max_requests_per_connection,
        fixture_connection_ids,
        fixture_stream_ids,
        frozen_thread_counts,
        sampler_lifecycle_events: sampled.lifecycle_events,
        sampler_attribution_cpus: sampled.attribution.len() as u64,
        quality_blockers: sampler_quality_blockers(&sampled),
        fixture_evidence: Some(fixture_result),
        sampler_freeze: Some(frozen),
        sampler_final: Some(sampled),
    })
}

async fn authenticate_role(role_process: &mut ManagedRole) -> Result<()> {
    role_process.mark_failure_stage(RoleErrorStage::Authenticate);
    role_process.child.validate()?;
    let expected_role = role_process.child.role;
    let expected_identity = role_process.child.identity.clone();
    match role_process.receive().await? {
        ControlBody::Hello { role, identity }
            if role == expected_role && identity == expected_identity =>
        {
            let challenge_sha256 = random_control_challenge()?;
            role_process
                .send(ControlBody::Authenticate {
                    challenge_sha256: challenge_sha256.clone(),
                })
                .await?;
            let expected = crate::control::authentication_response(
                &challenge_sha256,
                &control_context_for_child(&role_process.control)?,
                expected_role,
                &expected_identity,
            )?;
            match role_process.receive().await? {
                ControlBody::Authenticated {
                    role,
                    identity,
                    response_sha256,
                } if role == expected_role
                    && identity == expected_identity
                    && response_sha256 == expected =>
                {
                    role_process.child.validate()?;
                    role_process
                        .send(ControlBody::AuthenticationAccepted {
                            role: expected_role,
                            identity: expected_identity,
                        })
                        .await?;
                    role_process.authenticated = true;
                    role_process.mark_failure_stage(RoleErrorStage::Startup);
                    Ok(())
                }
                _ => role_process
                    .fail_control(
                        "authentication-response-mismatch",
                        None,
                        RoleErrorStage::Authenticate,
                        RoleErrorCode::Authentication,
                        sha256_hex(b"amg-http2-perf/authentication-response-mismatch/v1"),
                        None,
                    )
                    .map(|_| ()),
            }
        }
        _ => role_process
            .fail_control(
                "authentication-hello-mismatch",
                None,
                RoleErrorStage::Authenticate,
                RoleErrorCode::Authentication,
                sha256_hex(b"amg-http2-perf/authentication-hello-mismatch/v1"),
                None,
            )
            .map(|_| ()),
    }
}

fn control_context_for_child(control: &FramedControl) -> Result<ControlContext> {
    control.context_clone()
}

fn random_control_challenge() -> Result<String> {
    let mut nonce = [0_u8; 32];
    let mut offset = 0_usize;
    while offset < nonce.len() {
        // SAFETY: `nonce[offset..]` is a live writable slice and getrandom is
        // called without flags. EINTR is retried and zero progress is rejected.
        let read = unsafe {
            libc::getrandom(nonce[offset..].as_mut_ptr().cast(), nonce.len() - offset, 0)
        };
        if read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        let read = usize::try_from(read).map_err(|_| Error::new("getrandom length is negative"))?;
        if read == 0 {
            return Err(Error::new("getrandom returned zero bytes"));
        }
        offset = offset
            .checked_add(read)
            .ok_or_else(|| Error::new("control challenge offset overflow"))?;
    }
    Ok(sha256_hex(&nonce))
}

fn spawn_role(
    executable: &Path,
    repository: &Path,
    role: Role,
    cpus: &[u16],
    context: &ControlContext,
) -> Result<ManagedRole> {
    let arguments = vec![
        "role".to_owned(),
        "--kind".to_owned(),
        role.label().to_owned(),
        "--run".to_owned(),
        context.run_id.clone(),
        "--workload".to_owned(),
        context.cell.workload.code().to_owned(),
        "--concurrency".to_owned(),
        context.cell.concurrency.to_string(),
        "--arm".to_owned(),
        context.arm.code().to_owned(),
        "--block".to_owned(),
        context.block.to_string(),
    ];
    spawn_role_with_arguments(executable, repository, role, cpus, context, &arguments)
}

fn spawn_role_with_arguments(
    executable: &Path,
    repository: &Path,
    role: Role,
    cpus: &[u16],
    context: &ControlContext,
    arguments: &[String],
) -> Result<ManagedRole> {
    let (parent_control, child_control) = inherited_pair(context.clone())?;
    if !crate::control::cloexec(child_control.as_raw_fd())? {
        return Err(Error::new("role control source descriptor lacks CLOEXEC"));
    }
    let mut command = Command::new(executable);
    command
        .current_dir(repository)
        .env_clear()
        .args(arguments)
        .stdin(Stdio::from(OwnedFd::from(child_control)))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let affinity = cpus.to_vec();
    // SAFETY: pre_exec performs only the benchmark process's own affinity call.
    unsafe {
        command.pre_exec(move || {
            set_affinity(0, &affinity).map_err(|error| std::io::Error::other(error.to_string()))
        });
    }
    let child = command
        .spawn()
        .context(format!("spawn {} role", role.label()))?;
    let identity = process_identity(child.id())?;
    if identity.parent_pid != std::process::id() {
        return Err(Error::new("spawned role is not a direct descendant"));
    }
    Ok(ManagedRole {
        child: ManagedChild {
            role,
            child,
            identity,
            reaped: false,
        },
        control: parent_control,
        authenticated: false,
        evidence_root: None,
        failure_stage: RoleErrorStage::Startup,
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_gateway(
    binary: &Path,
    repository: &Path,
    cpus: &[u16],
    address: SocketAddr,
    fixture: SocketAddr,
    tripwire: SocketAddr,
    upstream_protocol: Protocol,
    database: &Path,
    runtime_root: &Path,
) -> Result<ManagedChild> {
    let devnull = File::options().read(true).write(true).open("/dev/null")?;
    let stdout = devnull.try_clone()?;
    let stderr = devnull;
    let mut command = Command::new(binary);
    command
        .current_dir(repository)
        .env_clear()
        .env("HOST", "127.0.0.1")
        .env("PORT", address.port().to_string())
        .env("GATEWAY_PUBLIC_BASE_URL", "http://public.example")
        .env("AUTH_MINI_ISSUER", format!("http://{tripwire}"))
        .env("AUTH_MINI_PUBLIC_BASE_URL", format!("http://{tripwire}"))
        .env("GATEWAY_DB", database)
        .env("GATEWAY_COOKIE_SECRET", COOKIE_SECRET)
        .env("COOKIE_SECURE", "false")
        .env("COOKIE_SAME_SITE", "lax")
        .env("SESSION_TTL_SECONDS", SESSION_TTL_SECONDS.to_string())
        .env("SESSION_ABSOLUTE_TTL_SECONDS", "2592000")
        .env(
            "SESSION_TOUCH_INTERVAL_SECONDS",
            TOUCH_INTERVAL_SECONDS.to_string(),
        )
        .env("REFRESH_SKEW_SECONDS", "60")
        .env("ALLOW_USER_IDS", USER_ID)
        .env("TRUSTED_PROXY_CIDRS", "")
        .env("GATEWAY_MAX_DOWNSTREAM_CONNECTIONS", "256")
        .env("GATEWAY_MAX_ACTIVE_UPSTREAMS", "128")
        .env("GATEWAY_MAX_BLOCKING_RESOLVERS", "8")
        .env("UPSTREAM_URL", format!("http://{fixture}"))
        .env(
            "UPSTREAM_PROTOCOL",
            upstream_protocol.label().replace('h', "http"),
        )
        .env("NO_COLOR", "1")
        .env("TMPDIR", runtime_root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let affinity = cpus.to_vec();
    // SAFETY: pre_exec performs only the soon-to-exec gateway's own affinity call.
    unsafe {
        command.pre_exec(move || {
            set_affinity(0, &affinity).map_err(|error| std::io::Error::other(error.to_string()))
        });
    }
    let child = command.spawn().context("spawn exact archived gateway")?;
    let identity = process_identity(child.id())?;
    if identity.parent_pid != std::process::id() {
        return Err(Error::new("spawned gateway is not a direct descendant"));
    }
    Ok(ManagedChild {
        role: Role::Gateway,
        child,
        identity,
        reaped: false,
    })
}

async fn reserve_loopback_address() -> Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

async fn wait_gateway_owned(address: SocketAddr, identity: &ProcessIdentity) -> Result<()> {
    let deadline_ns = clock_ns(ClockKind::Monotonic)?
        .checked_add(2_000_000_000)
        .ok_or_else(|| Error::new("gateway readiness deadline overflow"))?;
    let listener_inode = loop {
        match verify_listening_socket_owner(identity, address) {
            Ok(inode) => break inode,
            Err(error) => {
                identity_matches_or_fail(identity)?;
                if clock_ns(ClockKind::Monotonic)? >= deadline_ns {
                    return Err(error.context(
                        "gateway bind race/ownership could not be disproved before readiness",
                    ));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    };
    loop {
        let before_inode = verify_listening_socket_owner(identity, address)?;
        if before_inode != listener_inode {
            return Err(Error::new(
                "gateway listener inode changed during readiness",
            ));
        }
        let connected =
            tokio::time::timeout(Duration::from_millis(100), TcpStream::connect(address)).await;
        if let Ok(Ok(mut stream)) = connected {
            if stream.peer_addr()? != address || !stream.local_addr()?.ip().is_loopback() {
                return Err(Error::new("gateway readiness TCP tuple changed"));
            }
            // Close the bind-to-connect race before any request byte is sent:
            // the exact PID/start tuple must still own the same listener inode.
            let connected_inode = verify_listening_socket_owner(identity, address)?;
            if connected_inode != listener_inode {
                return Err(Error::new(
                    "gateway listener ownership changed across readiness connect",
                ));
            }
            stream
                .write_all(
                    b"GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
                )
                .await?;
            let mut bytes = Vec::new();
            if stream.read_to_end(&mut bytes).await.is_ok() && bytes.starts_with(b"HTTP/1.1 204") {
                if verify_listening_socket_owner(identity, address)? != listener_inode {
                    return Err(Error::new(
                        "gateway listener ownership changed after readiness response",
                    ));
                }
                identity_matches_or_fail(identity)?;
                return Ok(());
            }
        }
        identity_matches_or_fail(identity)?;
        if clock_ns(ClockKind::Monotonic)? >= deadline_ns {
            return Err(Error::new("gateway readiness exceeded two-second cap"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn identity_matches_or_fail(identity: &ProcessIdentity) -> Result<()> {
    let current = process_identity(identity.pid)?;
    if &current == identity && current.parent_pid == std::process::id() {
        Ok(())
    } else {
        Err(Error::new(
            "spawned gateway identity changed during bind wait",
        ))
    }
}

async fn role_ready_fixture(control: &mut ManagedRole) -> Result<(SocketAddr, SocketAddr)> {
    match control.receive().await? {
        ControlBody::Ready {
            role: Role::Fixture,
            data_address: Some(data),
            tripwire_address: Some(tripwire),
        } => Ok((
            crate::control::parse_loopback_address(&data)?,
            crate::control::parse_loopback_address(&tripwire)?,
        )),
        other => Err(Error::new(format!("expected fixture Ready, got {other:?}"))),
    }
}

async fn role_ready(control: &mut ManagedRole, role: Role) -> Result<()> {
    match control.receive().await? {
        ControlBody::Ready {
            role: actual,
            data_address: None,
            tripwire_address: None,
        } if actual == role => Ok(()),
        other => Err(Error::new(format!(
            "expected {role:?} Ready, got {other:?}"
        ))),
    }
}

async fn expect(
    control: &mut ManagedRole,
    predicate: impl FnOnce(&ControlBody) -> bool,
) -> Result<()> {
    let body = control.receive().await?;
    if predicate(&body) {
        Ok(())
    } else {
        Err(Error::new(format!("unexpected control response: {body:?}")))
    }
}

async fn expect_prepared(control: &mut ManagedRole) -> Result<LoadProof> {
    match control.receive().await? {
        ControlBody::Prepared { proof } => Ok(proof),
        other => Err(Error::new(format!("expected Prepared, got {other:?}"))),
    }
}

async fn prepare_operation_corpus(
    control: &mut ManagedRole,
    phase: u16,
    operation_ceiling: u64,
) -> Result<()> {
    control
        .send(ControlBody::PrepareOperationCorpus {
            phase,
            operation_ceiling,
        })
        .await?;
    match control.receive().await? {
        ControlBody::OperationCorpusPrepared {
            phase: actual_phase,
            operation_ceiling: actual_ceiling,
        } if actual_phase == phase && actual_ceiling == operation_ceiling => Ok(()),
        other => Err(Error::new(format!(
            "expected OperationCorpusPrepared, got {other:?}"
        ))),
    }
}

async fn expect_measured(control: &mut ManagedRole) -> Result<LoadResult> {
    match control.receive().await? {
        ControlBody::Measured { result } => Ok(result),
        other => Err(Error::new(format!("expected Measured, got {other:?}"))),
    }
}

async fn expect_inventory(
    control: &mut ManagedRole,
) -> Result<Vec<crate::control::ThreadInventory>> {
    match control.receive().await? {
        ControlBody::InventoryObserved { inventories } => Ok(inventories),
        other => Err(Error::new(format!(
            "expected InventoryObserved, got {other:?}"
        ))),
    }
}

async fn expect_frozen(control: &mut ManagedRole) -> Result<SamplerReport> {
    match control.receive().await? {
        ControlBody::Frozen { report } => Ok(report),
        other => Err(Error::new(format!("expected Frozen, got {other:?}"))),
    }
}

async fn expect_sampled(control: &mut ManagedRole) -> Result<SamplerReport> {
    match control.receive().await? {
        ControlBody::Sampled { report } => Ok(report),
        other => Err(Error::new(format!("expected Sampled, got {other:?}"))),
    }
}

async fn expect_fixture(control: &mut ManagedRole) -> Result<FixtureResult> {
    match control.receive().await? {
        ControlBody::FixtureObserved { result } => Ok(result),
        other => Err(Error::new(format!(
            "expected FixtureObserved, got {other:?}"
        ))),
    }
}

async fn expect_stopped(control: &mut ManagedRole, role: Role) -> Result<()> {
    match control.receive().await? {
        ControlBody::Stopped { role: actual } if actual == role => Ok(()),
        other => Err(Error::new(format!(
            "expected {role:?} Stopped, got {other:?}"
        ))),
    }
}

fn gateway_threads(
    inventories: Vec<crate::control::ThreadInventory>,
) -> Result<Vec<ThreadIdentity>> {
    inventories
        .into_iter()
        .find(|inventory| inventory.role == Role::Gateway)
        .map(|inventory| inventory.threads)
        .ok_or_else(|| Error::new("gateway pre-auth inventory missing"))
}

fn validate_proof(
    proof: &LoadProof,
    protocol: Protocol,
    workload: Workload,
    concurrency: u64,
) -> Result<()> {
    let expected_connections = if protocol == Protocol::H1 && workload == Workload::Upload1Mib {
        proof.warmup_operations
    } else if protocol == Protocol::H1 {
        concurrency
    } else {
        1
    };
    if proof.downstream_protocol != protocol
        || proof.physical_connections != expected_connections
        || proof.tunnels != concurrency * u64::from(workload == Workload::WebSocket)
        || (protocol == Protocol::H2 && !proof.h2_settings_proved)
        || (protocol == Protocol::H2
            && workload == Workload::WebSocket
            && !proof.extended_connect_proved)
    {
        return Err(Error::new("load proof protocol/connection/tunnel mismatch"));
    }
    let expected_operations = if workload == Workload::WebSocket {
        concurrency
    } else {
        proof.warmup_operations
    };
    validate_attempt_and_lane_ledgers(
        &proof.attempts,
        &proof.lane_quotas,
        &proof.lane_completions,
        expected_operations,
        concurrency,
    )?;
    validate_load_wire(protocol, workload, &proof.h2_wire, expected_operations)?;
    validate_connection_ledger(
        &proof.connection_ledger,
        expected_operations,
        workload,
        protocol,
        concurrency,
    )?;
    Ok(())
}

fn validate_load_result(
    result: &LoadResult,
    expected_operations: u64,
    workload: Workload,
    protocol: Protocol,
    concurrency: u64,
) -> Result<()> {
    if result.operations_started != expected_operations
        || result.operations_completed != expected_operations
        || result.operations_completed_by_deadline != expected_operations
        || result.window_deadline_ns.is_some()
        || result.window_end_ns < result.window_start_ns
        || !result.status_ok
        || !result.eos_ok
        || !result.payload_ok
        || !result.sse_content_type_ok
        || !result.response_headers_sanitized
        || result.retries != 0
        || result.latencies_ns.len() as u64 != expected_operations
    {
        return Err(Error::new(
            "load correctness/count/no-retry validation failed",
        ));
    }
    validate_attempt_and_lane_ledgers(
        &result.attempts,
        &result.lane_quotas,
        &result.lane_completions,
        expected_operations,
        concurrency,
    )?;
    validate_load_wire(protocol, workload, &result.h2_wire, expected_operations)?;
    validate_connection_ledger(
        &result.connection_ledger,
        expected_operations,
        workload,
        protocol,
        concurrency,
    )?;
    Ok(())
}

fn validate_attempt_and_lane_ledgers(
    attempts: &crate::control::AttemptEvidence,
    lane_quotas: &[u64],
    lane_completions: &[u64],
    expected_operations: u64,
    concurrency: u64,
) -> Result<()> {
    let quota_total = lane_quotas
        .iter()
        .try_fold(0_u64, |total, value| total.checked_add(*value))
        .ok_or_else(|| Error::new("lane quota total overflow"))?;
    let completion_total = lane_completions
        .iter()
        .try_fold(0_u64, |total, value| total.checked_add(*value))
        .ok_or_else(|| Error::new("lane completion total overflow"))?;
    if attempts.starts != expected_operations
        || attempts.successes != expected_operations
        || attempts.failures != 0
        || attempts.reconnects != 0
        || attempts.retries != 0
        || lane_quotas.len() as u64 != concurrency
        || lane_completions.len() as u64 != concurrency
        || lane_quotas != lane_completions
        || quota_total != expected_operations
        || completion_total != expected_operations
    {
        return Err(Error::new(
            "attempt/start/success/failure/retry and per-lane operation ledgers differ",
        ));
    }
    Ok(())
}

fn validate_load_wire(
    protocol: Protocol,
    workload: Workload,
    wire: &[crate::wire::H2WireEvidence],
    minimum_request_headers: u64,
) -> Result<()> {
    match protocol {
        Protocol::H1 if wire.is_empty() => Ok(()),
        Protocol::H1 => Err(Error::new("H1 load path emitted H2 wire proof")),
        Protocol::H2 if wire.len() == 1 => {
            wire[0].validate(workload == Workload::WebSocket)?;
            if wire[0].request_headers < minimum_request_headers {
                return Err(Error::new(
                    "load wire HEADERS inventory is smaller than completed operations",
                ));
            }
            Ok(())
        }
        Protocol::H2 => Err(Error::new(
            "H2 load path does not have exactly one physical wire observer",
        )),
    }
}

fn validate_connection_ledger(
    ledger: &crate::control::ConnectionLedger,
    operations: u64,
    workload: Workload,
    protocol: Protocol,
    concurrency: u64,
) -> Result<()> {
    let expected_policy = match (protocol, workload) {
        (Protocol::H1, Workload::Upload1Mib) => ConnectionPolicy::FreshH1PerOperation,
        (Protocol::H1, Workload::WebSocket) => ConnectionPolicy::H1UpgradeTunnels,
        (Protocol::H1, _) => ConnectionPolicy::PersistentH1,
        (Protocol::H2, Workload::WebSocket) => ConnectionPolicy::H2ExtendedConnectStreams,
        (Protocol::H2, _) => ConnectionPolicy::PersistentH2,
    };
    if ledger.policy != expected_policy
        || ledger.reuse_attempts != 0
        || ledger.reconnect_attempts != 0
        || ledger.retry_attempts != 0
        || ledger.operation_connection_hash_sha256.len() != 64
        || ledger.h2_stream_sequence_sha256.len() != 64
        || ledger.failed_connect_attempts != 0
        || ledger.connect_attempts != ledger.connect_successes
    {
        return Err(Error::new(
            "load connection policy/violation ledger mismatch",
        ));
    }
    match expected_policy {
        ConnectionPolicy::FreshH1PerOperation => {
            if [
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
            ]
            .iter()
            .any(|count| *count != operations)
                || ledger.keep_alive_tokens != 0
                || ledger.active_connections != 0
                || ledger.max_active_connections == 0
                || ledger.max_active_connections > concurrency
                || ledger.max_requests_per_connection != 1
                || ledger.h2_streams != 0
                || ledger.active_h2_streams != 0
                || ledger.max_active_h2_streams != 0
            {
                return Err(Error::new(
                    "fresh-H1 connect/request/close/EOF ledger mismatch",
                ));
            }
        }
        ConnectionPolicy::PersistentH2 if workload == Workload::Upload1Mib => {
            if ledger.cumulative_connections != 1
                || ledger.h2_streams != operations
                || ledger.active_connections != 1
                || ledger.close_tokens != 0
                || ledger.transport_eof != 0
                || ledger.active_h2_streams != 0
                || ledger.max_active_h2_streams == 0
                || ledger.max_active_h2_streams > concurrency
                || ledger.first_h2_stream_id.is_none()
                || ledger.last_h2_stream_id.is_none()
            {
                return Err(Error::new("persistent-H2 upload stream ledger mismatch"));
            }
        }
        ConnectionPolicy::PersistentH1 | ConnectionPolicy::H1UpgradeTunnels => {
            if ledger.cumulative_connections != concurrency
                || ledger.close_tokens != 0
                || ledger.h2_streams != 0
                || ledger.active_h2_streams != 0
                || ledger.max_active_h2_streams != 0
            {
                return Err(Error::new(
                    "persistent-H1/tunnel connection ledger mismatch",
                ));
            }
        }
        ConnectionPolicy::PersistentH2 | ConnectionPolicy::H2ExtendedConnectStreams => {
            if ledger.cumulative_connections != 1
                || ledger.close_tokens != 0
                || ledger.first_h2_stream_id.is_none()
                || ledger.last_h2_stream_id.is_none()
            {
                return Err(Error::new("persistent-H2 connection ledger mismatch"));
            }
        }
    }
    Ok(())
}

fn validate_fixture(
    fixture: &FixtureResult,
    expectation: FixtureExpectation,
    phases: FixturePhaseResults<'_>,
) -> Result<()> {
    let FixtureExpectation {
        target,
        protocol,
        workload,
        concurrency,
    } = expectation;
    let FixturePhaseResults {
        proof,
        websocket_warmup,
        ordinary_materialization,
        measured,
    } = phases;
    let connection_topology_ok = match (protocol, workload) {
        (Protocol::H2, _) => {
            fixture.physical_connections == 1 && fixture.max_active_connections == 1
        }
        (Protocol::H1, Workload::WebSocket) => {
            fixture.physical_connections == concurrency
                && fixture.max_active_connections > 0
                && fixture.max_active_connections <= concurrency
        }
        (Protocol::H1, _) => {
            let idle_connections = concurrency.min(8);
            fixture.physical_connections >= idle_connections
                && fixture.active_connections == idle_connections
                && fixture.max_active_connections >= idle_connections
                && fixture.max_active_connections <= 136
                && fixture.physical_connections >= fixture.max_active_connections
        }
    };
    let expected_observations = if workload == Workload::WebSocket {
        3_u64
            .checked_mul(concurrency)
            .ok_or_else(|| Error::new("fixture smoke observation count overflow"))?
    } else {
        proof
            .warmup_operations
            .checked_add(
                ordinary_materialization
                    .map_or(0, |materialization| materialization.operations_completed),
            )
            .and_then(|value| value.checked_add(measured.operations_completed))
            .ok_or_else(|| Error::new("fixture smoke observation count overflow"))?
    };
    if fixture.target != target
        || fixture.expected_protocol != protocol
        || !connection_topology_ok
        || fixture.max_requests_per_connection == 0
        || fixture.tripwire_connections != 0
        || fixture.tripwire_bytes != 0
        || fixture.duplicate_operations != 0
        || fixture.unknown_requests != 0
        || fixture.observations.len() as u64 != expected_observations
        || !fixture.observations.iter().all(|observation| {
            observation.protocol == protocol
                && observation.payload_ok
                && observation.identity_ok
                && observation.request_headers_sanitized
                && observation.request_eos
                && (observation.method == "PING"
                    || observation.status == 200
                    || observation.status == 101)
                && if protocol == Protocol::H2 {
                    observation.stream_id.is_some_and(|stream| stream % 2 == 1)
                } else {
                    observation.stream_id.is_none()
                }
        })
        || !fixture
            .observations
            .iter()
            .any(|observation| observation.operation_id == measured.first_operation_id)
    {
        return Err(Error::new(format!(
            "fixture endpoint/topology/tripwire reconciliation failed: physical={} active={} max-active={} observations={}/{} tripwire-connections={} tripwire-bytes={} duplicates={} unknown={}",
            fixture.physical_connections,
            fixture.active_connections,
            fixture.max_active_connections,
            fixture.observations.len(),
            expected_observations,
            fixture.tripwire_connections,
            fixture.tripwire_bytes,
            fixture.duplicate_operations,
            fixture.unknown_requests,
        )));
    }
    match protocol {
        Protocol::H1 if !fixture.h2_wire.is_empty() => {
            return Err(Error::new("H1 fixture emitted H2 frame evidence"));
        }
        Protocol::H2 => {
            if fixture.h2_wire.len() != 1 {
                return Err(Error::new("H2 fixture lacks one physical wire observer"));
            }
            let wire = &fixture.h2_wire[0];
            wire.validate(workload == Workload::WebSocket)?;
            let expected_headers = if workload == Workload::WebSocket {
                concurrency
            } else {
                expected_observations
            };
            if wire.request_headers != expected_headers {
                return Err(Error::new(
                    "fixture wire HEADERS count differs from actual request topology",
                ));
            }
        }
        Protocol::H1 => {}
    }
    if workload == Workload::WebSocket {
        reconcile_fixture_phase(
            fixture,
            0,
            proof.tunnels,
            &proof.operation_hash_sha256,
            0,
            0,
        )?;
        let warm = websocket_warmup
            .ok_or_else(|| Error::new("WebSocket fixture reconciliation lacks warmup"))?;
        reconcile_fixture_phase(
            fixture,
            1,
            warm.operations_completed,
            &warm.operation_hash_sha256,
            warm.request_bytes,
            warm.response_bytes,
        )?;
    } else {
        reconcile_fixture_phase(
            fixture,
            1,
            proof.warmup_operations,
            &proof.operation_hash_sha256,
            proof.request_bytes,
            proof.response_bytes,
        )?;
        if let Some(materialization) = ordinary_materialization {
            materialization.validate()?;
            for wave in &materialization.waves {
                reconcile_fixture_phase(
                    fixture,
                    wave.phase,
                    wave.result.operations_completed,
                    &wave.result.operation_hash_sha256,
                    wave.result.request_bytes,
                    wave.result.response_bytes,
                )?;
            }
        }
    }
    reconcile_fixture_phase(
        fixture,
        2,
        measured.operations_completed,
        &measured.operation_hash_sha256,
        measured.request_bytes,
        measured.response_bytes,
    )?;
    Ok(())
}

fn reconcile_fixture_phase(
    fixture: &FixtureResult,
    phase: u16,
    expected_count: u64,
    expected_hash: &str,
    expected_request_bytes: u64,
    expected_response_bytes: u64,
) -> Result<()> {
    let summary = fixture_phase_summary(fixture, phase)?;
    if summary.operations != expected_count
        || summary.request_bytes != expected_request_bytes
        || summary.response_bytes != expected_response_bytes
        || summary.operation_hash_sha256 != expected_hash
    {
        return Err(Error::new(format!(
            "fixture/load phase {phase} complete operation/byte/hash sets do not reconcile"
        )));
    }
    Ok(())
}

fn validate_direct_upload_fixture(
    fixture: &FixtureResult,
    protocol: Protocol,
    proof: &LoadProof,
    measured: &LoadResult,
    concurrency: u64,
) -> Result<()> {
    let expected_operations = concurrency
        .checked_mul(2)
        .ok_or_else(|| Error::new("direct smoke operation count overflow"))?;
    let expected_connections = if protocol == Protocol::H1 {
        expected_operations
    } else {
        1
    };
    let expected_active = if protocol == Protocol::H1 { 0 } else { 1 };
    let expected_max_requests = if protocol == Protocol::H1 {
        1
    } else {
        expected_operations
    };
    let mut connection_ids = fixture
        .observations
        .iter()
        .map(|observation| observation.connection_id)
        .collect::<Vec<_>>();
    connection_ids.sort_unstable();
    connection_ids.dedup();
    if fixture.target != LoadTarget::Direct
        || fixture.expected_protocol != protocol
        || fixture.physical_connections != expected_connections
        || fixture.active_connections != expected_active
        || fixture.max_active_connections == 0
        || fixture.max_active_connections > concurrency
        || fixture.max_requests_per_connection != expected_max_requests
        || connection_ids.len() as u64 != expected_connections
        || fixture.tripwire_connections != 0
        || fixture.tripwire_bytes != 0
        || fixture.duplicate_operations != 0
        || fixture.unknown_requests != 0
        || fixture.observations.len() as u64 != expected_operations
        || !fixture.observations.iter().all(|observation| {
            observation.protocol == protocol
                && observation.payload_ok
                && observation.identity_ok
                && observation.request_headers_sanitized
                && observation.request_eos
                && observation.response_eos
                && observation.status == 200
                && if protocol == Protocol::H2 {
                    observation.stream_id.is_some_and(|stream| stream % 2 == 1)
                } else {
                    observation.stream_id.is_none()
                }
        })
        || !fixture
            .observations
            .iter()
            .any(|observation| observation.operation_id == measured.first_operation_id)
    {
        return Err(Error::new(
            "direct upload fixture connection/stream reconciliation failed",
        ));
    }
    match protocol {
        Protocol::H1 if !fixture.h2_wire.is_empty() => {
            return Err(Error::new("direct H1 fixture emitted H2 wire evidence"));
        }
        Protocol::H2 => {
            if fixture.h2_wire.len() != 1
                || fixture.h2_wire[0].request_headers != expected_operations
            {
                return Err(Error::new(
                    "direct H2 fixture wire HEADERS inventory is incomplete",
                ));
            }
            fixture.h2_wire[0].validate(false)?;
        }
        Protocol::H1 => {}
    }
    reconcile_fixture_phase(
        fixture,
        1,
        proof.warmup_operations,
        &proof.operation_hash_sha256,
        proof.request_bytes,
        proof.response_bytes,
    )?;
    reconcile_fixture_phase(
        fixture,
        2,
        measured.operations_completed,
        &measured.operation_hash_sha256,
        measured.request_bytes,
        measured.response_bytes,
    )?;
    Ok(())
}

fn sampler_quality_blockers(report: &SamplerReport) -> Vec<String> {
    sampler_quality_blockers_for(report, FrequencyGate::CalibrationAbsolute)
}

fn sampler_quality_blockers_for(
    report: &SamplerReport,
    frequency_gate: FrequencyGate,
) -> Vec<String> {
    let mut blockers = Vec::new();
    for bucket in report
        .attribution
        .iter()
        .chain(&report.bracket_attribution)
        .chain(&report.dynamic_attribution)
    {
        if bucket.attribution_uncertainty_ticks > 1 {
            blockers.push(format!(
                "CPU {} attribution uncertainty {} ticks exceeds one",
                bucket.cpu, bucket.attribution_uncertainty_ticks
            ));
        }
        if bucket.capacity_ticks > 0
            && u128::from(bucket.external_upper_ticks) * 100 > u128::from(bucket.capacity_ticks)
        {
            blockers.push(format!(
                "CPU {} whole-window external upper bound exceeds 1%",
                bucket.cpu
            ));
        }
    }
    if report
        .tctl_millidegrees
        .is_some_and(|value| value >= 85_000)
    {
        blockers.push("Tctl reached the 85C immediate-stop threshold".to_owned());
    }
    if report.lifecycle_poll_max_ns > 10_000_000 {
        blockers.push(format!(
            "lifecycle poll spacing {}ns exceeds 10ms",
            report.lifecycle_poll_max_ns
        ));
    }
    if report.boundary_interval_max_ns > 125_000_000 {
        blockers.push(format!(
            "100ms resource sampler spacing {}ns exceeds 125ms fail-closed tolerance",
            report.boundary_interval_max_ns
        ));
    }
    if report.bracket_samples_100ms == 0 {
        blockers.push("frozen interval has no complete 100ms resource bracket".to_owned());
    }
    if report.births_after_freeze != 0
        || report.deaths_after_freeze != 0
        || report.migrations_after_freeze != 0
    {
        blockers.push("post-freeze thread birth/death/migration ledger is nonzero".to_owned());
    }
    for residual in &report.residuals {
        if residual.signed_residual_lower_ticks > 0
            || residual.signed_residual_upper_ticks < 0
            || residual.u_role_lower_ticks != 0
            || residual.u_role_upper_ticks != 0
        {
            blockers.push(format!(
                "{} frozen process/TID runtime residual is not attributable",
                residual.role.label()
            ));
        }
    }
    for residual in &report.dynamic_residuals {
        let known_plus_u_lower = residual
            .known_tid_runtime_lower_ticks
            .checked_add(residual.u_role_lower_ticks);
        let known_plus_u_upper = residual
            .known_tid_runtime_upper_ticks
            .checked_add(residual.u_role_upper_ticks);
        if residual.u_role_lower_ticks > residual.u_role_upper_ticks
            || known_plus_u_lower.is_none()
            || known_plus_u_upper.is_none()
            || known_plus_u_lower.is_some_and(|lower| lower > residual.process_runtime_upper_ticks)
            || known_plus_u_upper.is_some_and(|upper| upper < residual.process_runtime_lower_ticks)
        {
            blockers.push(format!(
                "{} dynamic process/TID/u_role runtime interval does not reconcile",
                residual.role.label()
            ));
        }
    }
    for scope in &report.noise_scopes {
        if !scope.accepted {
            blockers.push(format!(
                "{} {} external-time bound exceeds {} basis points",
                scope.role, scope.scope, scope.limit_basis_points
            ));
        }
    }
    if report.major_faults_delta != 0
        || report.swap_in != 0
        || report.swap_out != 0
        || report.steal_ticks_delta != 0
        || report.memory_psi_full_us != 0
        || report.io_psi_full_us != 0
    {
        blockers.push("fault/swap/full-PSI contamination was observed".to_owned());
    }
    if !report.realtime_comparable || report.realtime_discontinuities != 0 {
        blockers.push("REALTIME continuity evidence is missing or disrupted".to_owned());
    }
    match (report.median_frequency_khz, frequency_gate) {
        (Some(frequency), FrequencyGate::CalibrationAbsolute) if frequency >= 4_000_000 => {}
        (
            Some(frequency),
            FrequencyGate::AuthoritativeRelative {
                calibration_p05_khz,
            },
        ) if u128::from(frequency) * 100 >= u128::from(calibration_p05_khz) * 95 => {}
        (_, FrequencyGate::CalibrationAbsolute) => {
            blockers.push("median gateway-role CPU frequency is below 4GHz".to_owned());
        }
        (
            _,
            FrequencyGate::AuthoritativeRelative {
                calibration_p05_khz,
            },
        ) => {
            blockers.push(format!(
                "median gateway-role CPU frequency is below 95% of calibration p05 {calibration_p05_khz}kHz"
            ));
        }
    }
    blockers
}

fn observed(
    role: Role,
    identity: ProcessIdentity,
    executable_sha256: &str,
    cpus: &[u16],
) -> ObservedProcess {
    ObservedProcess {
        role,
        identity,
        executable_sha256: executable_sha256.to_owned(),
        broad_cpus: cpus.to_vec(),
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[allow(unsafe_code)]
fn validated_signal(identity: &ProcessIdentity, signal: i32) -> Result<()> {
    let current = process_identity(identity.pid)?;
    if &current != identity || current.parent_pid != std::process::id() {
        return Err(Error::new(
            "refusing to signal non-matching descendant identity",
        ));
    }
    let pid = i32::try_from(identity.pid).map_err(|_| Error::new("PID exceeds pid_t"))?;
    // SAFETY: the direct-child PID/start-time tuple was immediately revalidated.
    if unsafe { libc::kill(pid, signal) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn sampler_quality_is_diagnostic_for_non_authoritative_smoke() {
        let report = SamplerReport {
            monotonic_ns: 1,
            boottime_ns: 1,
            frozen: true,
            inventories: Vec::new(),
            resources: Vec::new(),
            attribution: vec![crate::control::CpuAttribution {
                cpu: 0,
                start_ns: 1,
                end_ns: 2,
                capacity_ticks: 100,
                scheduled_ticks: 100,
                role_runtime_lower_ticks: 98,
                role_runtime_upper_ticks: 100,
                attribution_uncertainty_ticks: 2,
                external_upper_ticks: 2,
            }],
            bracket_attribution: Vec::new(),
            dynamic_attribution: Vec::new(),
            bracket_samples_100ms: 0,
            boundary_interval_max_ns: 100_000_000,
            residuals: Vec::new(),
            dynamic_residuals: Vec::new(),
            noise_scopes: Vec::new(),
            lifecycle_events: 0,
            births_before_freeze: 0,
            deaths_before_freeze: 0,
            births_after_freeze: 0,
            deaths_after_freeze: 0,
            migrations_after_freeze: 0,
            lifecycle_poll_max_ns: 10_000_000,
            post_freeze_change: None,
            tctl_millidegrees: Some(70_000),
            tctl_start_millidegrees: Some(70_000),
            tctl_max_millidegrees: Some(70_000),
            median_frequency_khz: Some(4_000_000),
            major_faults_delta: 0,
            swap_in: 0,
            swap_out: 0,
            cpu_psi_some_us: 0,
            memory_psi_full_us: 0,
            io_psi_full_us: 0,
            realtime_samples: 1,
            realtime_discontinuities: 0,
            realtime_comparable: true,
            steal_ticks_delta: 0,
        };
        assert_eq!(
            sampler_quality_blockers(&report),
            vec![
                "CPU 0 attribution uncertainty 2 ticks exceeds one".to_owned(),
                "CPU 0 whole-window external upper bound exceeds 1%".to_owned(),
                "frozen interval has no complete 100ms resource bracket".to_owned(),
            ]
        );
    }

    #[test]
    fn retained_failure_smoke_is_one_shot_sealable_and_can_end_after_cap() {
        let package = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = package
            .join("target")
            .join(format!("retained-smoke-failure-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.parent().unwrap()).unwrap();
        fs::create_dir(&root).expect("first exclusive smoke attempt");
        assert!(fs::create_dir(&root).is_err(), "rerun must be refused");
        let detail = "fixture terminated before EOF";
        let failure = crate::evidence::RetainedSmokeFailure {
            schema: crate::evidence::SMOKE_FAILURE_SCHEMA.to_owned(),
            key: SmokeCaseKey {
                kind: SmokeKind::Gateway,
                concurrency: 64,
                workload: Workload::Upload1Mib,
                arm: Some(Arm::C11),
                direct_protocol: None,
            },
            detail: detail.to_owned(),
            detail_sha256: sha256_hex(detail.as_bytes()),
            role_failure: None,
        };
        failure.validate().expect("failure record");
        json::write_new_canonical(&root.join("smoke-failure.json"), &failure).unwrap();
        let failed_case = SmokeCaseEvidence {
            key: failure.key.clone(),
            started_operations: 128,
            completed_operations: 0,
            physical_connections: 0,
            stream_ids: Vec::new(),
            close_tokens: 0,
            transport_eof: 0,
            retries: 0,
            reconnects: 0,
            reuse_attempts: 0,
            evidence_integrity_failure: true,
            operation_hash_sha256: sha256_hex(b"failed-operation"),
            connection_hash_sha256: sha256_hex(b"failed-connection"),
            semantic_class: SemanticClass::IntegrityFailure,
            semantic_detail: detail.to_owned(),
            phase_separation: None,
        };
        let topology = TopologySmokeEvidence {
            schema: crate::evidence::SMOKE_SCHEMA.to_owned(),
            calibration_id: "cal-retained-failure".to_owned(),
            attempt_ordinal: 0,
            monotonic_start_ns: 1,
            monotonic_deadline_ns: 300_000_000_001,
            monotonic_end_ns: 300_000_000_002,
            baseline_binary_sha256: sha256_hex(b"baseline"),
            candidate_binary_sha256: sha256_hex(b"candidate"),
            harness_binary_sha256: sha256_hex(b"harness"),
            build_set_sha256: sha256_hex(b"build-set"),
            build_set_required: false,
            raw_cases_required: false,
            terminal_integrity_failure: Some(detail.to_owned()),
            cases: vec![failed_case],
        };
        topology.validate().expect("partial over-cap topology");
        json::write_new_canonical(&root.join("topology-smoke.json"), &topology).unwrap();
        create_seal(&root).expect("seal retained failure");
        assert!(
            create_seal(&root).is_err(),
            "sealed failure cannot be replaced"
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for entry in fs::read_dir(&root).unwrap() {
            let path = entry.unwrap().path();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_arm_cleanup_retains_a_non_resumable_failure() {
        let package = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repository = crate::bundle::repository_root(&package).expect("repository");
        let root = package
            .join("target")
            .join(format!("interrupted-process-arm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("evidence root");
        let planned = PlannedArm {
            ordinal: 0,
            evidence_class: EvidenceClass::S,
            cell: Cell {
                workload: Workload::Get,
                concurrency: 1,
            },
            arm: Some(Arm::B11),
            direct_protocol: None,
            round: None,
            row: None,
            target: Some(10),
            lane_quotas: vec![10],
            fresh_process_set: true,
        };
        let staging = process_arm_staging_path(&root, &planned);
        let runtime = root.join(".arm-runtime-000000-get-c1");
        fs::create_dir_all(&staging).expect("staging");
        fs::create_dir_all(&runtime).expect("runtime");
        fs::write(staging.join("partial"), b"partial").expect("staging member");
        fs::write(runtime.join("cookie.sqlite"), b"runtime").expect("runtime member");

        retain_interrupted_process_arm(
            &repository,
            &root,
            "cal-interrupted",
            "cal-interrupted",
            &planned,
        )
        .expect("retain interrupted arm");
        assert!(!staging.exists());
        assert!(!runtime.exists());
        let record: ArmFailureRecord =
            json::read_strict(&arm_failure_path(&root, &planned), 65_536).expect("failure record");
        assert_eq!(record.raw_ordinal, 0);
        assert!(record.measured_work_started);
        assert!(record.runtime_cleaned);
        assert!(record.staging_cleaned);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
