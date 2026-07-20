//! Source-independent raw evidence inventory, schedule binding, and verdict derivation.

use crate::error::{RoleErrorCode, RoleErrorStage, SafeRoleFailure};
use crate::json;
use crate::raw::{self, ParsedArm, SemanticClass};
use crate::schedule::{pair_identity, PairIdentity};
use crate::schema::{
    all_cells, hard_comparisons, validate_identifier, validate_non_placeholder_sha256, Arm,
    AuthoritativeManifest, AuthoritativeRecord, BlockedCode, BlockedReason, ComparisonKind,
    DesignLock, EvidenceClass, EvidenceKind, Intent, QualityEvidence, RawProtocol, TerminalState,
    Workload, DESIGN_LOCK_SCHEMA, EXECUTION_SCHEMA, JSON_MAX_BYTES, MACHINE_SCHEMA, TASK_CAP_BYTES,
};
use crate::seal::{self, sha256_hex, SealManifest};
use crate::statistics::{AnalysisResult, VerdictDecision, VerdictStage};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const PROJECTION_SCHEMA: &str = "amg-http2-perf/projection/v1";
pub const SCHEDULE_SCHEMA: &str = "amg-http2-perf/schedule/v1";
pub const EXECUTION_STATE_SCHEMA: &str = "amg-http2-perf/execution-state/v1";
pub const SMOKE_SCHEMA: &str = "amg-http2-perf/topology-smoke/v1";
pub const SMOKE_FAILURE_SCHEMA: &str = "amg-http2-perf/topology-smoke-failure/v1";
pub const DIAGNOSTIC_SCHEMA: &str = "amg-http2-perf/b11-c1-upload-diagnostic/v1";
pub const C64_GET_DIAGNOSTIC_SCHEMA: &str = "amg-http2-perf/b11-c64-get-diagnostic/v1";
pub const SMOKE_PHASE_SEPARATION_SCHEMA: &str = "amg-http2-perf/smoke-phase-separation/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineEvidence {
    pub schema: String,
    pub fingerprint_sha256: String,
    pub boot_id_sha256: String,
    pub online_cpus: String,
    pub clocksource: String,
    pub clock_ticks_per_second: u64,
    pub math_abi_sha256: String,
}

impl MachineEvidence {
    pub fn validate(&self) -> Result<()> {
        if self.schema != MACHINE_SCHEMA
            || self.online_cpus != "0-31"
            || self.clocksource != "tsc"
            || self.clock_ticks_per_second != 100
        {
            return Err(Error::new(
                "machine evidence differs from the fixed host contract",
            ));
        }
        for hash in [
            &self.fingerprint_sha256,
            &self.boot_id_sha256,
            &self.math_abi_sha256,
        ] {
            validate_non_placeholder_sha256("machine evidence hash", hash)?;
        }
        if self.math_abi_sha256 != crate::statistics::math_target_sha256() {
            return Err(Error::new(
                "machine deterministic-math target identity does not match this verifier",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionEvidence {
    pub schema: String,
    pub runtime_projected_ns: u64,
    pub runtime_actual_ns: u64,
    pub raw_projected_bytes: u64,
    pub raw_actual_bytes: u64,
    pub tracked_projected_bytes: u64,
    pub tracked_actual_bytes: u64,
    pub endpoint_bound_bytes: u64,
    pub conn_live: u64,
    pub concurrency: u16,
}

impl ProjectionEvidence {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.concurrency, 1 | 16 | 64)
            || self.conn_live != 136_u64 + u64::from(self.concurrency)
        {
            return Err(Error::new(
                "projection concurrency/CONN_LIVE does not reserve the RFC endpoint slots",
            ));
        }
        let endpoint_bound = 512_u64
            .checked_add(
                160_u64
                    .checked_mul(self.conn_live)
                    .ok_or_else(|| Error::new("endpoint live-slot bound overflow"))?,
            )
            .and_then(|value| value.checked_add(512_u64 * u64::from(self.concurrency)))
            .ok_or_else(|| Error::new("endpoint bound overflow"))?;
        if self.schema != PROJECTION_SCHEMA || self.endpoint_bound_bytes != endpoint_bound {
            return Err(Error::new(
                "runtime/storage/endpoint projection gate failed",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn blockers(&self) -> Vec<String> {
        let mut blockers = Vec::new();
        if self.runtime_projected_ns > 151_200_000_000_000 {
            blockers.push("runtime projection exceeds 42 hours".to_owned());
        }
        if self.runtime_actual_ns > 172_800_000_000_000 {
            blockers.push("actual campaign runtime exceeds 48 hours".to_owned());
        }
        if self.raw_actual_bytes > self.raw_projected_bytes {
            blockers.push("raw storage projection underpredicted actual bytes".to_owned());
        }
        if self.tracked_actual_bytes > self.tracked_projected_bytes {
            blockers.push("tracked storage projection underpredicted actual bytes".to_owned());
        }
        if self.tracked_projected_bytes > TASK_CAP_BYTES {
            blockers.push("tracked storage projection exceeds 512 MiB".to_owned());
        }
        if self.tracked_actual_bytes > TASK_CAP_BYTES {
            blockers.push("actual tracked evidence exceeds 512 MiB".to_owned());
        }
        blockers
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionPhase {
    Diagnostic,
    Smoke,
    Scout,
    Williams,
    CalibrationDirect,
    DesignFreeze,
    AuthoritativeDirect,
    Authoritative,
    Bundle,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticOutcome {
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticFailure {
    pub stage: RoleErrorStage,
    pub code: RoleErrorCode,
    pub detail_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_failure: Option<SafeRoleFailure>,
}

impl DiagnosticFailure {
    pub fn validate(&self) -> Result<()> {
        validate_non_placeholder_sha256("diagnostic failure detail", &self.detail_sha256)?;
        if let Some(failure) = &self.role_failure {
            failure.validate()?;
            if failure.stage != Some(self.stage)
                || failure.code != Some(self.code)
                || failure.detail_sha256 != self.detail_sha256
            {
                return Err(Error::new(
                    "diagnostic failure differs from retained role failure",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B11UploadDiagnosticEvidence {
    pub schema: String,
    pub diagnostic_id: String,
    pub authoritative: bool,
    pub topology_smoke: bool,
    pub key: SmokeCaseKey,
    pub monotonic_start_ns: u64,
    pub monotonic_deadline_ns: u64,
    pub monotonic_end_ns: u64,
    pub baseline_binary_sha256: String,
    pub candidate_binary_sha256: String,
    pub harness_binary_sha256: String,
    pub build_set_sha256: String,
    pub outcome: DiagnosticOutcome,
    pub case: Option<SmokeCaseEvidence>,
    pub failure: Option<DiagnosticFailure>,
}

impl B11UploadDiagnosticEvidence {
    pub fn validate(&self) -> Result<()> {
        let c1_upload = SmokeCaseKey {
            kind: SmokeKind::Gateway,
            concurrency: 1,
            workload: Workload::Upload1Mib,
            arm: Some(Arm::B11),
            direct_protocol: None,
        };
        let c64_get = SmokeCaseKey {
            kind: SmokeKind::Gateway,
            concurrency: 64,
            workload: Workload::Get,
            arm: Some(Arm::B11),
            direct_protocol: None,
        };
        let exact_contract = (self.schema == DIAGNOSTIC_SCHEMA && self.key == c1_upload)
            || (self.schema == C64_GET_DIAGNOSTIC_SCHEMA && self.key == c64_get);
        if !exact_contract
            || self.authoritative
            || self.topology_smoke
            || self.monotonic_start_ns >= self.monotonic_deadline_ns
            || self.monotonic_deadline_ns - self.monotonic_start_ns != 30_000_000_000
            || self.monotonic_end_ns < self.monotonic_start_ns
        {
            return Err(Error::new(
                "B11 exact-process diagnostic identity/cap is invalid",
            ));
        }
        validate_identifier("diagnostic_id", &self.diagnostic_id)?;
        for (name, hash) in [
            ("diagnostic baseline binary", &self.baseline_binary_sha256),
            ("diagnostic candidate binary", &self.candidate_binary_sha256),
            ("diagnostic harness binary", &self.harness_binary_sha256),
            ("diagnostic build set", &self.build_set_sha256),
        ] {
            validate_non_placeholder_sha256(name, hash)?;
        }
        match (&self.outcome, &self.case, &self.failure) {
            (DiagnosticOutcome::Completed, Some(case), None) => {
                case.validate()?;
                if case.key != self.key || case.derived_semantic_class() != SemanticClass::Ok {
                    return Err(Error::new(
                        "completed diagnostic case is not exact and semantically clean",
                    ));
                }
            }
            (DiagnosticOutcome::Failed, None, Some(failure)) => failure.validate()?,
            _ => {
                return Err(Error::new(
                    "diagnostic outcome/case/failure optionality differs",
                ))
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStateEvidence {
    pub schema: String,
    pub evidence_id: String,
    pub phase: ExecutionPhase,
    pub next_ordinal: u64,
    pub planned_arms: u64,
    pub completed_arms: u64,
    pub complete: bool,
    pub crash_detail: Option<String>,
}

impl ExecutionStateEvidence {
    pub fn validate(&self) -> Result<()> {
        if self.schema != EXECUTION_STATE_SCHEMA
            || self.completed_arms > self.planned_arms
            || self.next_ordinal != self.completed_arms
            || self.complete != (self.phase == ExecutionPhase::Complete)
            || self.crash_detail.as_ref().is_some_and(String::is_empty)
        {
            return Err(Error::new("invalid execution/resume state"));
        }
        validate_identifier("execution evidence_id", &self.evidence_id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleEvidence {
    pub schema: String,
    pub seed: u64,
    pub n: u32,
    pub rounds: Vec<crate::schema::RoundPlan>,
}

impl ScheduleEvidence {
    pub fn validate(&self, design: &DesignLock) -> Result<()> {
        if self.schema != SCHEDULE_SCHEMA
            || self.seed != design.schedule_seed
            || self.n != design.selected_n
            || self.rounds != design.rounds
        {
            return Err(Error::new("schedule evidence differs from design lock"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SmokeKind {
    Gateway,
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeCaseKey {
    pub kind: SmokeKind,
    pub concurrency: u16,
    pub workload: Workload,
    pub arm: Option<Arm>,
    pub direct_protocol: Option<RawProtocol>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeCaseEvidence {
    pub key: SmokeCaseKey,
    pub started_operations: u64,
    pub completed_operations: u64,
    pub physical_connections: u64,
    pub stream_ids: Vec<u32>,
    pub close_tokens: u64,
    pub transport_eof: u64,
    pub retries: u64,
    pub reconnects: u64,
    pub reuse_attempts: u64,
    pub evidence_integrity_failure: bool,
    pub operation_hash_sha256: String,
    pub connection_hash_sha256: String,
    pub semantic_class: SemanticClass,
    pub semantic_detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase_separation: Option<SmokePhaseSeparationEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokePhaseSeparationEvidence {
    pub schema: String,
    pub proof_operations: u64,
    pub materialization_operations: u64,
    pub materialization_waves: u16,
    pub materialization_lane_completions: Vec<u64>,
    pub materialization_operation_root_sha256: String,
    pub materialization_connection_root_sha256: String,
    pub stable_inventory_signature_sha256: String,
    pub stable_tid_signature_sha256: String,
    pub freeze_tid_signature_sha256: String,
    pub final_tid_signature_sha256: String,
    pub stability_observation_ns: u64,
    pub measured_operations: u64,
    pub measured_operation_hash_sha256: String,
    pub measured_connection_hash_sha256: String,
    pub materialization_latency_records: u64,
    pub measured_latency_records: u64,
    pub births_after_freeze: u64,
    pub deaths_after_freeze: u64,
    pub migrations_after_freeze: u64,
    pub freeze_handoff_ns: u64,
    pub measure_handoff_ns: u64,
}

impl SmokePhaseSeparationEvidence {
    fn validate(&self, key: &SmokeCaseKey, total_started: u64) -> Result<()> {
        let concurrency = u64::from(key.concurrency);
        if self.schema != SMOKE_PHASE_SEPARATION_SCHEMA
            || key.kind != SmokeKind::Gateway
            || key.workload == Workload::WebSocket
            || self.proof_operations != 1
            || self.materialization_waves < crate::materialization::MIN_UNCHANGED_FULL_WAVES
            || self.materialization_waves > crate::materialization::MAX_FULL_WAVES
            || self.materialization_operations
                < concurrency * u64::from(crate::materialization::MIN_UNCHANGED_FULL_WAVES)
            || self.materialization_lane_completions.len() != usize::from(key.concurrency)
            || self
                .materialization_lane_completions
                .iter()
                .any(|completed| {
                    *completed < u64::from(crate::materialization::MIN_UNCHANGED_FULL_WAVES)
                })
            || self.materialization_lane_completions.iter().sum::<u64>()
                != self.materialization_operations
            || self.measured_operations == 0
            || self.measured_operations > concurrency
            || self
                .proof_operations
                .checked_add(self.materialization_operations)
                .and_then(|value| value.checked_add(self.measured_operations))
                != Some(total_started)
            || self.materialization_latency_records != 0
            || self.measured_latency_records != 0
            || self.births_after_freeze != 0
            || self.deaths_after_freeze != 0
            || self.migrations_after_freeze != 0
            || self.stability_observation_ns < crate::materialization::INVENTORY_STABILITY_NS
            || self.stability_observation_ns
                > crate::materialization::INVENTORY_STABILITY_NS
                    + crate::materialization::INVENTORY_STABILITY_SLACK_NS
            || self.freeze_handoff_ns > crate::materialization::FREEZE_HANDOFF_CAP_NS
            || self.measure_handoff_ns > crate::materialization::MEASURE_HANDOFF_CAP_NS
            || self.stable_tid_signature_sha256 != self.freeze_tid_signature_sha256
            || self.freeze_tid_signature_sha256 != self.final_tid_signature_sha256
            || self.materialization_operation_root_sha256 == self.measured_operation_hash_sha256
        {
            return Err(Error::new(
                "smoke materialization/measured phase separation is invalid",
            ));
        }
        for (name, hash) in [
            (
                "smoke materialization operation root",
                &self.materialization_operation_root_sha256,
            ),
            (
                "smoke materialization connection root",
                &self.materialization_connection_root_sha256,
            ),
            (
                "smoke stable inventory signature",
                &self.stable_inventory_signature_sha256,
            ),
            (
                "smoke stable TID signature",
                &self.stable_tid_signature_sha256,
            ),
            (
                "smoke freeze TID signature",
                &self.freeze_tid_signature_sha256,
            ),
            (
                "smoke final TID signature",
                &self.final_tid_signature_sha256,
            ),
            (
                "smoke measured operation hash",
                &self.measured_operation_hash_sha256,
            ),
            (
                "smoke measured connection hash",
                &self.measured_connection_hash_sha256,
            ),
        ] {
            validate_non_placeholder_sha256(name, hash)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedSmokeFailure {
    pub schema: String,
    pub key: SmokeCaseKey,
    pub detail: String,
    pub detail_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_failure: Option<SafeRoleFailure>,
}

impl RetainedSmokeFailure {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SMOKE_FAILURE_SCHEMA
            || self.detail.is_empty()
            || self.detail_sha256 != sha256_hex(self.detail.as_bytes())
        {
            return Err(Error::new("retained smoke failure record is invalid"));
        }
        validate_non_placeholder_sha256("smoke failure detail", &self.detail_sha256).and_then(
            |()| {
                self.role_failure
                    .as_ref()
                    .map_or(Ok(()), SafeRoleFailure::validate)
            },
        )
    }
}

impl SmokeCaseEvidence {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.key.concurrency, 1 | 64)
            || self.completed_operations > self.started_operations
        {
            return Err(Error::new("smoke case count evidence is invalid"));
        }
        if let Some(separation) = &self.phase_separation {
            separation.validate(&self.key, self.started_operations)?;
        } else if self.started_operations != 2 * u64::from(self.key.concurrency) {
            return Err(Error::new("legacy smoke case count evidence is invalid"));
        }
        validate_non_placeholder_sha256("smoke operation hash", &self.operation_hash_sha256)?;
        validate_non_placeholder_sha256("smoke connection hash", &self.connection_hash_sha256)?;
        match self.key.kind {
            SmokeKind::Gateway => {
                if self.key.arm.is_none() || self.key.direct_protocol.is_some() {
                    return Err(Error::new("gateway smoke case identity is invalid"));
                }
            }
            SmokeKind::Direct => {
                if self.key.arm.is_some()
                    || self.key.direct_protocol.is_none()
                    || self.key.workload != Workload::Upload1Mib
                {
                    return Err(Error::new("direct smoke case identity is invalid"));
                }
            }
        }
        let protocol = match self.key.kind {
            SmokeKind::Gateway => {
                crate::topology::ArmTopology::for_arm(
                    self.key
                        .arm
                        .ok_or_else(|| Error::new("smoke arm missing"))?,
                )
                .downstream
            }
            SmokeKind::Direct => match self.key.direct_protocol {
                Some(RawProtocol::H1) => crate::topology::Protocol::H1,
                Some(RawProtocol::H2) => crate::topology::Protocol::H2,
                None => return Err(Error::new("direct protocol missing")),
            },
        };
        if protocol == crate::topology::Protocol::H2 {
            let unique: BTreeSet<_> = self.stream_ids.iter().copied().collect();
            if unique.len() != self.stream_ids.len()
                || self
                    .stream_ids
                    .iter()
                    .any(|stream| *stream == 0 || stream % 2 == 0)
            {
                return Err(Error::new(
                    "persistent-H2 smoke stream identities are malformed",
                ));
            }
        }
        let derived = self.derived_semantic_class();
        if self.semantic_class != derived
            || (derived != SemanticClass::Ok && self.semantic_detail.is_empty())
            || (derived == SemanticClass::Ok && !self.semantic_detail.is_empty())
        {
            return Err(Error::new(
                "smoke semantic label does not equal the raw-derived classification",
            ));
        }
        if protocol == crate::topology::Protocol::H1 && !self.stream_ids.is_empty() {
            return Err(Error::new("H1 smoke case contains H2 stream identities"));
        }
        Ok(())
    }

    #[must_use]
    pub fn semantic_violations(&self) -> Vec<String> {
        let mut violations = Vec::new();
        if self.completed_operations != self.started_operations {
            violations.push("smoke completed-operation count is incomplete".to_owned());
        }
        if self.evidence_integrity_failure {
            violations.push("smoke process/raw evidence integrity failure".to_owned());
        }
        if self.retries != 0 || self.reconnects != 0 || self.reuse_attempts != 0 {
            violations.push("smoke contains retry/reconnect/reuse activity".to_owned());
        }
        let protocol = match self.key.kind {
            SmokeKind::Gateway => self
                .key
                .arm
                .map(crate::topology::ArmTopology::for_arm)
                .map(|topology| topology.downstream),
            SmokeKind::Direct => self.key.direct_protocol.map(|protocol| match protocol {
                RawProtocol::H1 => crate::topology::Protocol::H1,
                RawProtocol::H2 => crate::topology::Protocol::H2,
            }),
        };
        match protocol {
            Some(crate::topology::Protocol::H1) if self.key.workload == Workload::Upload1Mib => {
                if self.physical_connections != self.started_operations
                    || self.close_tokens != self.started_operations
                    || self.transport_eof != self.started_operations
                {
                    violations.push("fresh-H1 smoke connection/close/EOF mismatch".to_owned());
                }
            }
            Some(crate::topology::Protocol::H2)
                if self.physical_connections != 1
                    || self.stream_ids.len() as u64
                        != if self.key.workload == Workload::WebSocket {
                            u64::from(self.key.concurrency)
                        } else {
                            self.started_operations
                        }
                    || self.close_tokens != 0
                    || self.transport_eof != 0 =>
            {
                violations.push("persistent-H2 smoke topology mismatch".to_owned());
            }
            _ => {}
        }
        violations
    }

    #[must_use]
    pub fn derived_semantic_class(&self) -> SemanticClass {
        if self.semantic_violations().is_empty() {
            return SemanticClass::Ok;
        }
        if self.evidence_integrity_failure
            || self.retries != 0
            || self.reconnects != 0
            || self.reuse_attempts != 0
        {
            return SemanticClass::IntegrityFailure;
        }
        match (self.key.kind, self.key.arm) {
            (SmokeKind::Direct, _) => SemanticClass::IntegrityFailure,
            (SmokeKind::Gateway, Some(Arm::B11)) => SemanticClass::BaselineFailure,
            (SmokeKind::Gateway, Some(_)) => SemanticClass::CandidateFailure,
            (SmokeKind::Gateway, None) => SemanticClass::IntegrityFailure,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologySmokeEvidence {
    pub schema: String,
    pub calibration_id: String,
    pub attempt_ordinal: u8,
    pub monotonic_start_ns: u64,
    pub monotonic_deadline_ns: u64,
    pub monotonic_end_ns: u64,
    pub baseline_binary_sha256: String,
    pub candidate_binary_sha256: String,
    pub harness_binary_sha256: String,
    pub build_set_sha256: String,
    pub build_set_required: bool,
    pub raw_cases_required: bool,
    pub terminal_integrity_failure: Option<String>,
    pub cases: Vec<SmokeCaseEvidence>,
}

impl TopologySmokeEvidence {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SMOKE_SCHEMA
            || self.attempt_ordinal != 0
            || self.monotonic_start_ns >= self.monotonic_deadline_ns
            || self.monotonic_deadline_ns - self.monotonic_start_ns != 300_000_000_000
            || self.build_set_required != self.raw_cases_required
            || self
                .terminal_integrity_failure
                .as_ref()
                .is_some_and(String::is_empty)
        {
            return Err(Error::new("smoke one-shot/deadline evidence is invalid"));
        }
        validate_identifier("smoke calibration_id", &self.calibration_id)?;
        for (name, hash) in [
            ("smoke baseline binary", &self.baseline_binary_sha256),
            ("smoke candidate binary", &self.candidate_binary_sha256),
            ("smoke harness binary", &self.harness_binary_sha256),
            ("smoke build set", &self.build_set_sha256),
        ] {
            validate_non_placeholder_sha256(name, hash)?;
        }
        let expected = expected_smoke_cases();
        let mut actual = BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            if !actual.insert(case.key.clone()) {
                return Err(Error::new("smoke case identity is duplicated"));
            }
        }
        if self.monotonic_end_ns > self.monotonic_deadline_ns
            && self.terminal_integrity_failure.is_none()
            && self
                .cases
                .iter()
                .all(|case| case.derived_semantic_class() == SemanticClass::Ok)
        {
            return Err(Error::new(
                "passing smoke exceeded its enclosing monotonic deadline",
            ));
        }
        if self.terminal_integrity_failure.is_none()
            && self
                .cases
                .iter()
                .all(|case| case.derived_semantic_class() == SemanticClass::Ok)
            && actual != expected
        {
            return Err(Error::new(
                "passing smoke does not contain the exact C1/C64 inventory",
            ));
        }
        if !actual.is_subset(&expected) {
            return Err(Error::new("smoke contains an unknown case"));
        }
        Ok(())
    }
}

fn expected_smoke_cases() -> BTreeSet<SmokeCaseKey> {
    let mut cases = BTreeSet::new();
    for concurrency in [1_u16, 64] {
        for workload in Workload::ALL {
            for arm in Arm::ALL {
                cases.insert(SmokeCaseKey {
                    kind: SmokeKind::Gateway,
                    concurrency,
                    workload,
                    arm: Some(arm),
                    direct_protocol: None,
                });
            }
        }
        for direct_protocol in [RawProtocol::H1, RawProtocol::H2] {
            cases.insert(SmokeCaseKey {
                kind: SmokeKind::Direct,
                concurrency,
                workload: Workload::Upload1Mib,
                arm: None,
                direct_protocol: Some(direct_protocol),
            });
        }
    }
    cases
}

#[derive(Debug)]
pub struct VerifiedEvidence {
    pub root: PathBuf,
    pub seal: SealManifest,
    pub intent: Intent,
    pub intent_bytes: Vec<u8>,
    pub design: Option<DesignLock>,
    pub arms: Vec<ParsedArm>,
    pub pairs: Vec<PairIdentity>,
    pub authoritative: Option<AuthoritativeManifest>,
    pub analysis: Option<AnalysisResult>,
    pub terminal_state: TerminalState,
    pub reasons: Vec<String>,
}

impl VerifiedEvidence {
    pub fn derived_analysis(&self) -> Result<AnalysisResult> {
        if self.intent.evidence_kind != EvidenceKind::Campaign {
            return Err(Error::new("only campaign evidence has an analysis verdict"));
        }
        if let Some(analysis) = &self.analysis {
            return Ok(analysis.clone());
        }
        let (verdict, stage) = match self.terminal_state {
            TerminalState::Fail => (crate::schema::Verdict::Fail, VerdictStage::CandidateSafety),
            TerminalState::Blocked | TerminalState::Superseded => (
                crate::schema::Verdict::Blocked,
                VerdictStage::EvidenceIntegrity,
            ),
            TerminalState::Pass => {
                return Err(Error::new(
                    "campaign PASS lacks complete source-derived statistical analysis",
                ));
            }
        };
        Ok(AnalysisResult {
            schema: crate::schema::ANALYSIS_SCHEMA.to_owned(),
            run_id: self.intent.evidence_id.clone(),
            math_target_sha256: crate::statistics::math_target_sha256(),
            comparison_count: 0,
            scalar_gate_count: 0,
            comparisons: Vec::new(),
            decision: VerdictDecision {
                verdict,
                stage,
                reasons: self.reasons.clone(),
            },
        })
    }
}

pub fn verify_raw_closure(root: &Path) -> Result<VerifiedEvidence> {
    verify_raw_closure_mode(root, true)
}

pub fn verify_raw_closure_structural(root: &Path) -> Result<VerifiedEvidence> {
    verify_raw_closure_mode(root, false)
}

fn verify_raw_closure_mode(root: &Path, analyze: bool) -> Result<VerifiedEvidence> {
    let seal = seal::verify_seal(root)?;
    let intent_bytes = fs::read(root.join("intent.json"))?;
    let intent: Intent = json::require_canonical(&intent_bytes)?;
    intent.validate()?;
    let state: ExecutionStateEvidence = read_canonical(root, "execution-state.json")?;
    state.validate()?;
    if state.evidence_id != intent.evidence_id {
        return Err(Error::new("execution state identity differs from intent"));
    }
    let machine: MachineEvidence = read_canonical(root, "machine.json")?;
    machine.validate()?;
    let projection: ProjectionEvidence = read_canonical(root, "projection.json")?;
    projection.validate()?;
    let delivery: ProjectionEvidence = read_canonical(root, "delivery-projection.json")?;
    delivery.validate()?;
    let repository = crate::bundle::repository_root(root)?;
    let artifact_root =
        repository.join(".legion/tasks/prove-http2-performance-regression/artifacts");
    let actual_tracked = crate::storage::actual_regular_bytes_if_exists(&artifact_root)?;
    if delivery.tracked_actual_bytes != actual_tracked
        || projection.tracked_actual_bytes > actual_tracked
    {
        return Err(Error::new(
            "sealed tracked-byte checkpoint differs from the fresh artifact-tree walk",
        ));
    }
    let mut raw_inspection = raw::inspect_evidence_tree(root)?;
    if !raw_inspection.blockers.is_empty() {
        return Err(Error::new(format!(
            "raw evidence contains unparseable/missing/opaque members: {}",
            raw_inspection.blockers.join("; ")
        )));
    }
    let arms = std::mem::take(&mut raw_inspection.arms);
    let mut integrity = Vec::new();
    integrity.extend(projection.blockers());
    integrity.extend(delivery.blockers());
    if arms.iter().any(|arm| {
        arm.metadata.evidence_id != intent.evidence_id || arm.metadata.run_id != intent.evidence_id
    }) {
        integrity.push("raw arm identity differs from intent".to_owned());
    }
    integrity.extend(root_inventory_blockers(root, intent.evidence_kind, &state)?);

    match intent.evidence_kind {
        EvidenceKind::Calibration => {
            verify_calibration(root, seal, intent, intent_bytes, state, arms, integrity)
        }
        EvidenceKind::Campaign => verify_campaign(
            root,
            CampaignVerificationInput {
                seal,
                intent,
                intent_bytes,
                state,
                machine,
                arms,
                integrity,
            },
            analyze,
        ),
        EvidenceKind::Diagnostic => {
            verify_diagnostic(root, seal, intent, intent_bytes, state, arms, integrity)
        }
    }
}

fn verify_diagnostic(
    root: &Path,
    seal: SealManifest,
    intent: Intent,
    intent_bytes: Vec<u8>,
    state: ExecutionStateEvidence,
    arms: Vec<ParsedArm>,
    mut integrity: Vec<String>,
) -> Result<VerifiedEvidence> {
    if !arms.is_empty() || state.phase != ExecutionPhase::Diagnostic {
        return Err(Error::new(
            "single-case diagnostic contains benchmark arms or another execution phase",
        ));
    }
    let diagnostic: B11UploadDiagnosticEvidence = read_canonical(root, "diagnostic.json")?;
    diagnostic.validate()?;
    if diagnostic.diagnostic_id != intent.evidence_id {
        return Err(Error::new("diagnostic identity differs from intent"));
    }
    verify_diagnostic_builds_and_case(root, &intent, &diagnostic)?;
    integrity.push("diagnostic evidence is non-authoritative".to_owned());
    if let Some(failure) = &diagnostic.failure {
        integrity.push(format!(
            "diagnostic failed at stage={} code={} detail-sha256={}",
            failure.stage.label(),
            failure.code.label(),
            failure.detail_sha256
        ));
    }
    integrity.sort();
    integrity.dedup();
    Ok(VerifiedEvidence {
        root: root.to_path_buf(),
        seal,
        intent,
        intent_bytes,
        design: None,
        arms,
        pairs: Vec::new(),
        authoritative: None,
        analysis: None,
        terminal_state: TerminalState::Blocked,
        reasons: integrity,
    })
}

fn verify_diagnostic_builds_and_case(
    root: &Path,
    intent: &Intent,
    diagnostic: &B11UploadDiagnosticEvidence,
) -> Result<()> {
    let build_bytes = fs::read(root.join("build-set.json"))?;
    let builds: crate::build::BuildSet = json::require_canonical(&build_bytes)?;
    if builds.schema != "amg-http2-perf/build-set/v1"
        || sha256_hex(&build_bytes) != diagnostic.build_set_sha256
        || builds.baseline.commit != intent.baseline_commit
        || builds.candidate.commit != intent.candidate_commit
        || builds.baseline.binary_sha256 != diagnostic.baseline_binary_sha256
        || builds.candidate.binary_sha256 != diagnostic.candidate_binary_sha256
    {
        return Err(Error::new(
            "diagnostic build set does not bind exact commits/binaries",
        ));
    }
    let repository = crate::bundle::repository_root(root)?;
    builds.baseline.validate_sealed_evidence(&repository)?;
    builds.candidate.validate_sealed_evidence(&repository)?;
    let quiet: crate::raw::QuietEvidence = read_canonical(root, "quiet.json")?;
    quiet.validate()?;

    let case_root = root.join("case");
    let mut retained_role_failures = Vec::new();
    for role in ["fixture", "load", "sampler"] {
        let path = case_root.join(format!("role-failure-{role}.json"));
        if path.exists() {
            let failure: SafeRoleFailure = json::require_canonical(&fs::read(path)?)?;
            failure.validate()?;
            retained_role_failures.push(failure);
        }
    }
    match diagnostic.outcome {
        DiagnosticOutcome::Completed => {
            if !retained_role_failures.is_empty() {
                return Err(Error::new(
                    "completed diagnostic unexpectedly retains a role failure",
                ));
            }
            let outcome: crate::orchestrator::SmokeArmOutcome =
                read_canonical(&case_root, "case.json")?;
            let fixture: crate::control::FixtureResult =
                json::require_canonical(&fs::read(case_root.join("fixture.bin"))?)?;
            let freeze = crate::sampler::verify_persistent(&case_root.join("sampler-freeze.bin"))?;
            let final_report =
                crate::sampler::verify_persistent(&case_root.join("sampler-final.bin"))?;
            if outcome.cell
                != (crate::schema::Cell {
                    workload: Workload::Upload1Mib,
                    concurrency: 1,
                })
                || outcome.arm != Arm::B11
                || outcome.fixture_operation_hash_sha256 != fixture.operation_hash_sha256
                || outcome.fixture_observations != fixture.observations.len() as u64
                || outcome.sampler_lifecycle_events != final_report.lifecycle_events
                || outcome.sampler_attribution_cpus != final_report.attribution.len() as u64
                || outcome.frozen_thread_counts
                    != freeze
                        .inventories
                        .iter()
                        .map(|inventory| {
                            (
                                inventory.role.label().to_owned(),
                                inventory.threads.len() as u64,
                            )
                        })
                        .collect()
                || diagnostic.case.as_ref() != Some(&outcome.smoke_case()?)
            {
                return Err(Error::new(
                    "diagnostic summary differs from its exact raw process case",
                ));
            }
        }
        DiagnosticOutcome::Failed => {
            if [
                "case.json",
                "fixture.bin",
                "sampler-freeze.bin",
                "sampler-final.bin",
            ]
            .iter()
            .any(|member| case_root.join(member).exists())
            {
                return Err(Error::new(
                    "failed diagnostic contains unverified completed-case members",
                ));
            }
            let expected = diagnostic
                .failure
                .as_ref()
                .and_then(|failure| failure.role_failure.as_ref());
            match expected {
                Some(failure)
                    if retained_role_failures.len() == 1
                        && retained_role_failures.first() == Some(failure) => {}
                None if retained_role_failures.is_empty() => {}
                _ => {
                    return Err(Error::new(
                        "diagnostic retained role failure differs from case evidence",
                    ))
                }
            }
        }
    }
    Ok(())
}

fn verify_calibration(
    root: &Path,
    seal: SealManifest,
    intent: Intent,
    intent_bytes: Vec<u8>,
    state: ExecutionStateEvidence,
    arms: Vec<ParsedArm>,
    mut integrity: Vec<String>,
) -> Result<VerifiedEvidence> {
    let smoke: TopologySmokeEvidence = read_canonical(root, "topology-smoke.json")?;
    smoke.validate()?;
    if smoke.calibration_id != intent.evidence_id {
        return Err(Error::new(
            "topology smoke identity differs from calibration",
        ));
    }
    if smoke.build_set_required || smoke.raw_cases_required {
        verify_smoke_raw_cases_and_builds(root, &intent, &smoke)?;
    }
    integrity.extend(calibration_inventory_blockers(&arms, &state));
    if let Some(detail) = &smoke.terminal_integrity_failure {
        integrity.push(format!(
            "topology smoke terminal integrity failure: {detail}"
        ));
    }
    if smoke.calibration_id != intent.evidence_id {
        integrity.push("topology smoke identity differs from calibration".to_owned());
    }
    let mut smoke_candidate = Vec::new();
    for case in &smoke.cases {
        let detail = case.semantic_violations().join(", ");
        match case.derived_semantic_class() {
            SemanticClass::IntegrityFailure => integrity.push(detail),
            SemanticClass::BaselineFailure => integrity.push(detail),
            SemanticClass::CandidateFailure => smoke_candidate.push(detail),
            SemanticClass::Ok => {}
        }
    }
    let (terminal_state, reasons) =
        derive_terminal(&arms, &state, integrity, smoke_candidate, true);
    Ok(VerifiedEvidence {
        root: root.to_path_buf(),
        seal,
        intent,
        intent_bytes,
        design: None,
        arms,
        pairs: Vec::new(),
        authoritative: None,
        analysis: None,
        terminal_state,
        reasons,
    })
}

struct CampaignVerificationInput {
    seal: SealManifest,
    intent: Intent,
    intent_bytes: Vec<u8>,
    state: ExecutionStateEvidence,
    machine: MachineEvidence,
    arms: Vec<ParsedArm>,
    integrity: Vec<String>,
}

fn verify_campaign(
    root: &Path,
    input: CampaignVerificationInput,
    analyze: bool,
) -> Result<VerifiedEvidence> {
    let CampaignVerificationInput {
        seal,
        intent,
        intent_bytes,
        state,
        machine,
        arms,
        mut integrity,
    } = input;
    let design_bytes = fs::read(root.join("design-lock.json"))?;
    let design: DesignLock = json::require_canonical(&design_bytes)?;
    design.validate()?;
    if design.schema != DESIGN_LOCK_SCHEMA || design.intent_sha256 != sha256_hex(&intent_bytes) {
        return Err(Error::new("design lock does not bind the exact intent"));
    }
    let schedule: ScheduleEvidence = read_canonical(root, "schedule.json")?;
    schedule.validate(&design)?;
    integrity.extend(campaign_inventory_blockers(&arms, &state, &design));
    let (mut terminal_state, mut reasons) =
        derive_terminal(&arms, &state, integrity, Vec::new(), true);

    let mut authoritative = None;
    let mut pairs = Vec::new();
    let mut analysis = None;
    if terminal_state == TerminalState::Pass {
        match derive_authoritative(&intent, &design, &design_bytes, &machine, &arms) {
            Ok((manifest, derived_pairs)) => {
                authoritative = Some(manifest);
                pairs = derived_pairs;
                if analyze {
                    let derived_analysis = crate::statistics::analyze_derived_manifest(
                        authoritative
                            .as_ref()
                            .ok_or_else(|| Error::new("derived authoritative manifest vanished"))?,
                        &pairs,
                    )?;
                    terminal_state = terminal_from_verdict(derived_analysis.decision.verdict);
                    reasons = derived_analysis.decision.reasons.clone();
                    analysis = Some(derived_analysis);
                }
            }
            Err(error) => {
                terminal_state = TerminalState::Blocked;
                reasons = vec![format!("authoritative raw derivation failed: {error}")];
            }
        }
    }
    Ok(VerifiedEvidence {
        root: root.to_path_buf(),
        seal,
        intent,
        intent_bytes,
        design: Some(design),
        arms,
        pairs,
        authoritative,
        analysis,
        terminal_state,
        reasons,
    })
}

fn derive_terminal(
    arms: &[ParsedArm],
    state: &ExecutionStateEvidence,
    mut integrity: Vec<String>,
    mut candidate: Vec<String>,
    require_complete: bool,
) -> (TerminalState, Vec<String>) {
    let mut baseline = Vec::new();
    let mut quality = Vec::new();
    for arm in arms {
        let detail = format!(
            "{}: {}",
            arm.metadata.observation_id,
            arm.semantic_violations().join(", ")
        );
        match arm.semantic_class() {
            SemanticClass::IntegrityFailure => integrity.push(detail),
            SemanticClass::CandidateFailure => {
                if arm.quiet.clean() && arm.resources.clean() && arm.session_clock.comparable {
                    candidate.push(detail);
                } else {
                    quality.push(format!(
                        "{} candidate semantic interval lacks a clean guard",
                        arm.metadata.observation_id
                    ));
                }
            }
            SemanticClass::BaselineFailure => baseline.push(detail),
            SemanticClass::Ok => {}
        }
        let measurement = arm.measurement_violations();
        if !arm.quiet.clean()
            || !arm.resources.clean()
            || !arm.session_clock.comparable
            || !measurement.is_empty()
        {
            quality.push(format!(
                "{} failed raw quality gates{}",
                arm.metadata.observation_id,
                if measurement.is_empty() {
                    String::new()
                } else {
                    format!(": {}", measurement.join(", "))
                }
            ));
        }
    }
    integrity.sort();
    integrity.dedup();
    terminal_precedence(
        integrity,
        baseline,
        candidate,
        state.crash_detail.clone(),
        quality,
        require_complete && !state.complete,
    )
}

fn terminal_precedence(
    integrity: Vec<String>,
    baseline: Vec<String>,
    candidate: Vec<String>,
    crash: Option<String>,
    quality: Vec<String>,
    incomplete: bool,
) -> (TerminalState, Vec<String>) {
    if !integrity.is_empty() {
        return (TerminalState::Blocked, integrity);
    }
    if !baseline.is_empty() {
        return (TerminalState::Blocked, baseline);
    }
    if !candidate.is_empty() {
        return (TerminalState::Fail, candidate);
    }
    if let Some(crash) = crash {
        return (TerminalState::Blocked, vec![crash]);
    }
    if !quality.is_empty() {
        return (TerminalState::Blocked, quality);
    }
    if incomplete {
        return (
            TerminalState::Blocked,
            vec!["campaign is incomplete without a candidate semantic failure".to_owned()],
        );
    }
    (TerminalState::Pass, Vec::new())
}

fn derive_authoritative(
    intent: &Intent,
    design: &DesignLock,
    design_bytes: &[u8],
    machine: &MachineEvidence,
    arms: &[ParsedArm],
) -> Result<(AuthoritativeManifest, Vec<PairIdentity>)> {
    let a_arms = arms
        .iter()
        .filter(|arm| arm.metadata.class == EvidenceClass::A)
        .collect::<Vec<_>>();
    let d_arms = arms
        .iter()
        .filter(|arm| arm.metadata.class == EvidenceClass::D)
        .collect::<Vec<_>>();
    if arms
        .iter()
        .any(|arm| !matches!(arm.metadata.class, EvidenceClass::A | EvidenceClass::D))
    {
        return Err(Error::new(
            "campaign contains calibration/scout evidence classes",
        ));
    }
    let expected_a = 75_u64
        .checked_mul(u64::from(design.selected_n))
        .ok_or_else(|| Error::new("authoritative arm count overflow"))?;
    let expected_d = 3_u64
        .checked_mul(u64::from(design.selected_n))
        .ok_or_else(|| Error::new("direct arm count overflow"))?;
    if a_arms.len() as u64 != expected_a || d_arms.len() as u64 != expected_d {
        return Err(Error::new("campaign raw A/D inventory is incomplete"));
    }

    let mut by_key = BTreeMap::new();
    let mut records = Vec::with_capacity(a_arms.len());
    for arm in a_arms {
        let round = arm
            .metadata
            .round
            .ok_or_else(|| Error::new("authoritative round is missing"))?;
        let row = arm
            .metadata
            .row
            .ok_or_else(|| Error::new("authoritative Williams row is missing"))?;
        let position = arm
            .metadata
            .position
            .ok_or_else(|| Error::new("authoritative position is missing"))?;
        let treatment = arm
            .metadata
            .arm
            .ok_or_else(|| Error::new("authoritative treatment is missing"))?;
        let plan = design
            .rounds
            .get(usize::try_from(round).map_err(|_| Error::new("round does not fit usize"))?)
            .ok_or_else(|| Error::new("authoritative round is outside design lock"))?;
        if plan.row != row
            || plan.arm_order.get(usize::from(position)) != Some(&treatment)
            || !plan.cells.contains(&arm.metadata.cell)
            || by_key
                .insert((round, arm.metadata.cell, treatment), arm)
                .is_some()
        {
            return Err(Error::new("authoritative row/position/cell identity drift"));
        }
        records.push(AuthoritativeRecord {
            schema: EXECUTION_SCHEMA.to_owned(),
            run_id: intent.evidence_id.clone(),
            round,
            cell: arm.metadata.cell,
            arm: treatment,
            position,
            observation_id: arm.metadata.observation_id.clone(),
            raw_sha256: arm.raw_sha256.clone(),
            metrics: arm.metrics()?,
        });
    }
    for round in 0..design.selected_n {
        for cell in all_cells() {
            for arm in Arm::ALL {
                if !by_key.contains_key(&(round, cell, arm)) {
                    return Err(Error::new("authoritative matrix key is missing"));
                }
            }
        }
    }
    validate_direct_inventory(design.selected_n, &d_arms)?;

    let mut pairs = Vec::new();
    for round in 0..design.selected_n {
        let plan = &design.rounds[usize::try_from(round).unwrap_or(usize::MAX)];
        for cell in all_cells() {
            let mut ids = BTreeMap::new();
            let mut hashes = BTreeMap::new();
            for arm in Arm::ALL {
                let raw = by_key[&(round, cell, arm)];
                ids.insert(arm, raw.metadata.observation_id.clone());
                hashes.insert(arm, raw.raw_sha256.clone());
            }
            let c11_id = ids[&Arm::C11].clone();
            let c11_hash = hashes[&Arm::C11].clone();
            for kind in [
                ComparisonKind::CandidateH1,
                ComparisonKind::H2ToH1,
                ComparisonKind::H1ToH2,
                ComparisonKind::H2ToH2,
            ] {
                if kind != ComparisonKind::CandidateH1 && cell.concurrency == 1 {
                    continue;
                }
                let identity = pair_identity(round, cell, kind, &ids, &hashes, plan.row)?;
                if kind != ComparisonKind::CandidateH1
                    && (identity.reference_observation_id != c11_id
                        || identity.reference_raw_sha256 != c11_hash)
                {
                    return Err(Error::new(
                        "C11 raw observation is not shared across candidate comparisons",
                    ));
                }
                pairs.push(identity);
            }
        }
    }
    let mut analysis_config = Vec::with_capacity(design_bytes.len() + 96);
    analysis_config.extend_from_slice(b"amg-http2-perf/analysis-config/v1\0");
    analysis_config.extend_from_slice(design_bytes);
    analysis_config.extend_from_slice(machine.math_abi_sha256.as_bytes());
    let analysis_config_sha256 = sha256_hex(&analysis_config);
    let manifest = AuthoritativeManifest {
        schema: EXECUTION_SCHEMA.to_owned(),
        run_id: intent.evidence_id.clone(),
        design_lock_sha256: analysis_config_sha256.clone(),
        analysis_config_sha256,
        math_target_sha256: machine.math_abi_sha256.clone(),
        n: design.selected_n,
        observations: records,
        quality: QualityEvidence {
            integrity_blockers: Vec::new(),
            candidate_semantic_failures: Vec::new(),
            baseline_semantic_failures: Vec::new(),
            measurement_blockers: Vec::new(),
        },
    };
    manifest.validate()?;
    if design.comparisons != hard_comparisons() {
        return Err(Error::new("design comparison matrix drifted"));
    }
    Ok((manifest, pairs))
}

fn validate_direct_inventory(n: u32, direct: &[&ParsedArm]) -> Result<()> {
    let mut keys = BTreeSet::new();
    for arm in direct {
        let epoch = arm
            .metadata
            .epoch
            .ok_or_else(|| Error::new("direct epoch is missing"))?;
        if epoch == 0
            || epoch > n / 10
            || !keys.insert((epoch, arm.metadata.cell, arm.metadata.direct_protocol))
        {
            return Err(Error::new("direct epoch/cell/protocol identity drift"));
        }
    }
    for epoch in 1..=n / 10 {
        for cell in all_cells() {
            for protocol in [Some(RawProtocol::H1), Some(RawProtocol::H2)] {
                if !keys.contains(&(epoch, cell, protocol)) {
                    return Err(Error::new("direct panel inventory is incomplete"));
                }
            }
        }
    }
    Ok(())
}

fn root_inventory_blockers(
    root: &Path,
    kind: EvidenceKind,
    state: &ExecutionStateEvidence,
) -> Result<Vec<String>> {
    let mut blockers = Vec::new();
    reject_unknown_root_members(root, kind)?;
    let raw = raw::inspect_evidence_tree(root)?;
    let parsed = u64::try_from(raw.arms.len()).unwrap_or(u64::MAX);
    if parsed != state.completed_arms {
        blockers.push(format!(
            "execution state records {} completed arms but exactly {parsed} raw arms parse",
            state.completed_arms
        ));
    }
    if state.complete && state.completed_arms != state.planned_arms {
        blockers
            .push("complete execution state does not close its planned arm inventory".to_owned());
    }
    blockers.sort();
    blockers.dedup();
    Ok(blockers)
}

fn calibration_inventory_blockers(
    arms: &[ParsedArm],
    state: &ExecutionStateEvidence,
) -> Vec<String> {
    let mut blockers = Vec::new();
    let mut scout_keys = BTreeSet::new();
    let mut williams_keys = BTreeSet::new();
    let mut direct_keys = BTreeSet::new();
    let mut previous_class_rank = 0_u8;
    for arm in arms {
        let class_rank = match arm.metadata.class {
            EvidenceClass::S => 0,
            EvidenceClass::C => 1,
            EvidenceClass::D => 2,
            EvidenceClass::A => 3,
        };
        if class_rank < previous_class_rank {
            blockers.push("calibration raw classes are not in phase order".to_owned());
        }
        previous_class_rank = class_rank;
        match arm.metadata.class {
            EvidenceClass::S => {
                let target = arm.metadata.scout_target.unwrap_or_default();
                if !matches!(
                    target,
                    5_000 | 10_000 | 20_000 | 40_000 | 80_000 | 160_000 | 320_000
                ) || !scout_keys.insert((arm.metadata.cell, target, arm.metadata.arm))
                {
                    blockers.push("scout target/cell/treatment inventory drift".to_owned());
                }
            }
            EvidenceClass::C => {
                let row = arm.metadata.row.unwrap_or(u8::MAX);
                let position = arm.metadata.position.unwrap_or(u8::MAX);
                let treatment = arm.metadata.arm.unwrap_or(Arm::B11);
                if crate::schedule::williams_rows()
                    .get(usize::from(row))
                    .and_then(|order| order.get(usize::from(position)))
                    != Some(&treatment)
                    || !williams_keys.insert((row, arm.metadata.cell, treatment))
                {
                    blockers
                        .push("Williams row/position/cell/treatment inventory drift".to_owned());
                }
            }
            EvidenceClass::D => {
                if arm.metadata.epoch != Some(0)
                    || !direct_keys.insert((arm.metadata.cell, arm.metadata.direct_protocol))
                {
                    blockers.push("calibration direct inventory drift".to_owned());
                }
            }
            EvidenceClass::A => blockers
                .push("calibration evidence contains authoritative campaign class A".to_owned()),
        }
    }

    let class_allowed = |class: EvidenceClass| match state.phase {
        ExecutionPhase::Diagnostic | ExecutionPhase::Smoke => false,
        ExecutionPhase::Scout => class == EvidenceClass::S,
        ExecutionPhase::Williams => matches!(class, EvidenceClass::S | EvidenceClass::C),
        ExecutionPhase::CalibrationDirect
        | ExecutionPhase::DesignFreeze
        | ExecutionPhase::Bundle
        | ExecutionPhase::Complete => {
            matches!(
                class,
                EvidenceClass::S | EvidenceClass::C | EvidenceClass::D
            )
        }
        ExecutionPhase::AuthoritativeDirect | ExecutionPhase::Authoritative => false,
    };
    if arms.iter().any(|arm| !class_allowed(arm.metadata.class)) {
        blockers.push("raw class appears before or outside its calibration phase".to_owned());
    }
    if matches!(
        state.phase,
        ExecutionPhase::Williams
            | ExecutionPhase::CalibrationDirect
            | ExecutionPhase::DesignFreeze
            | ExecutionPhase::Bundle
            | ExecutionPhase::Complete
    ) {
        let targets = [5_000_u64, 10_000, 20_000, 40_000, 80_000, 160_000, 320_000];
        for cell in all_cells() {
            let reached = targets.iter().rposition(|target| {
                Arm::ALL
                    .iter()
                    .any(|arm| scout_keys.contains(&(cell, *target, Some(*arm))))
            });
            let Some(reached) = reached else {
                blockers.push(format!("post-scout calibration lacks cell {}", cell.id()));
                continue;
            };
            for target in &targets[..=reached] {
                for treatment in Arm::ALL {
                    if !scout_keys.contains(&(cell, *target, Some(treatment))) {
                        blockers.push(format!(
                            "scout panels are not a complete target prefix for {}",
                            cell.id()
                        ));
                    }
                }
            }
        }
    }
    if matches!(
        state.phase,
        ExecutionPhase::CalibrationDirect
            | ExecutionPhase::DesignFreeze
            | ExecutionPhase::Bundle
            | ExecutionPhase::Complete
    ) && williams_keys.len() != 750
    {
        blockers.push("post-Williams calibration lacks exactly 750 C arms".to_owned());
    }
    if matches!(
        state.phase,
        ExecutionPhase::DesignFreeze | ExecutionPhase::Bundle | ExecutionPhase::Complete
    ) && direct_keys.len() != 30
    {
        blockers.push("reached calibration direct panel is not exactly 30 arms".to_owned());
    }
    if state.complete && arms.is_empty() {
        blockers.push("complete calibration contains zero raw arms".to_owned());
    }
    blockers.sort();
    blockers.dedup();
    blockers
}

fn campaign_inventory_blockers(
    arms: &[ParsedArm],
    state: &ExecutionStateEvidence,
    design: &DesignLock,
) -> Vec<String> {
    let mut blockers = Vec::new();
    let expected_a = 75_u64.checked_mul(u64::from(design.selected_n));
    let expected_d = 3_u64.checked_mul(u64::from(design.selected_n));
    let expected_total =
        expected_a.and_then(|left| expected_d.and_then(|right| left.checked_add(right)));
    if expected_total != Some(state.planned_arms) {
        blockers.push("campaign planned-arm inventory is not exactly 78N".to_owned());
    }
    if !matches!(
        state.phase,
        ExecutionPhase::AuthoritativeDirect
            | ExecutionPhase::Authoritative
            | ExecutionPhase::Bundle
            | ExecutionPhase::Complete
    ) {
        blockers.push("campaign execution state names a calibration-only phase".to_owned());
    }
    if arms
        .iter()
        .any(|arm| !matches!(arm.metadata.class, EvidenceClass::A | EvidenceClass::D))
    {
        blockers.push("campaign contains scout or Williams evidence".to_owned());
    }

    let mut expected_a_order = Vec::new();
    for plan in &design.rounds {
        for cell in &plan.cells {
            for (position, treatment) in plan.arm_order.iter().copied().enumerate() {
                expected_a_order.push((
                    plan.round,
                    *cell,
                    treatment,
                    u8::try_from(position).unwrap_or(u8::MAX),
                    plan.row,
                ));
            }
        }
    }
    let actual_a_order = arms
        .iter()
        .filter(|arm| arm.metadata.class == EvidenceClass::A)
        .map(|arm| {
            (
                arm.metadata.round.unwrap_or(u32::MAX),
                arm.metadata.cell,
                arm.metadata.arm.unwrap_or(Arm::B11),
                arm.metadata.position.unwrap_or(u8::MAX),
                arm.metadata.row.unwrap_or(u8::MAX),
            )
        })
        .collect::<Vec<_>>();
    if actual_a_order != expected_a_order[..actual_a_order.len().min(expected_a_order.len())]
        || actual_a_order.len() > expected_a_order.len()
    {
        blockers.push("authoritative raw arms are not an exact design-schedule prefix".to_owned());
    }

    let mut direct_keys = BTreeSet::new();
    let mut direct_ordinals: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    for arm in arms
        .iter()
        .filter(|arm| arm.metadata.class == EvidenceClass::D)
    {
        let key = (
            arm.metadata.epoch.unwrap_or(u32::MAX),
            arm.metadata.cell,
            arm.metadata.direct_protocol,
        );
        if key.0 == 0 || key.0 > design.selected_n / 10 || !direct_keys.insert(key) {
            blockers.push("authoritative direct epoch/cell/protocol inventory drift".to_owned());
        }
        direct_ordinals
            .entry(key.0)
            .or_default()
            .push(arm.metadata.ordinal);
    }
    let mut authoritative_ordinals: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    for arm in arms
        .iter()
        .filter(|arm| arm.metadata.class == EvidenceClass::A)
    {
        if let Some(round) = arm.metadata.round {
            authoritative_ordinals
                .entry(round / 10 + 1)
                .or_default()
                .push(arm.metadata.ordinal);
        }
    }
    for epoch in 1..=design.selected_n / 10 {
        let count = direct_keys.iter().filter(|key| key.0 == epoch).count();
        if count != 0 && count != 30 {
            blockers.push(format!("direct epoch {epoch} is a partial panel"));
        }
        if let Some(authoritative) = authoritative_ordinals.get(&epoch) {
            if count != 30 {
                blockers.push(format!(
                    "authoritative epoch {epoch} started without its exact direct panel"
                ));
            } else if direct_ordinals
                .get(&epoch)
                .and_then(|values| values.iter().max())
                >= authoritative.iter().min()
            {
                blockers.push(format!(
                    "direct epoch {epoch} does not precede its authoritative arms"
                ));
            }
        }
        if epoch > 1 {
            if let (Some(previous), Some(direct)) = (
                authoritative_ordinals.get(&(epoch - 1)),
                direct_ordinals.get(&epoch),
            ) {
                if previous.iter().max() >= direct.iter().min() {
                    blockers.push(format!(
                        "direct epoch {epoch} overlaps the preceding authoritative epoch"
                    ));
                }
            }
        }
    }
    if state.complete
        && (u64::try_from(actual_a_order.len()).ok() != expected_a
            || u64::try_from(direct_keys.len()).ok() != expected_d)
    {
        blockers.push("complete campaign A/D terminal inventory is incomplete".to_owned());
    }
    if state.complete && arms.is_empty() {
        blockers.push("complete campaign contains zero raw arms".to_owned());
    }
    blockers.sort();
    blockers.dedup();
    blockers
}

fn terminal_from_verdict(verdict: crate::schema::Verdict) -> TerminalState {
    match verdict {
        crate::schema::Verdict::Pass => TerminalState::Pass,
        crate::schema::Verdict::Fail => TerminalState::Fail,
        crate::schema::Verdict::Blocked => TerminalState::Blocked,
    }
}

fn reject_unknown_root_members(root: &Path, kind: EvidenceKind) -> Result<()> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    let fixed = match kind {
        EvidenceKind::Calibration => BTreeSet::from([
            "intent.json",
            "execution-state.json",
            "machine.json",
            "projection.json",
            "delivery-projection.json",
            "topology-smoke.json",
            "build-set.json",
            "quiet.json",
            "smoke-failure.json",
            "seal.json",
        ]),
        EvidenceKind::Campaign => BTreeSet::from([
            "intent.json",
            "execution-state.json",
            "machine.json",
            "projection.json",
            "delivery-projection.json",
            "design-lock.json",
            "schedule.json",
            "seal.json",
        ]),
        EvidenceKind::Diagnostic => BTreeSet::from([
            "intent.json",
            "execution-state.json",
            "machine.json",
            "projection.json",
            "delivery-projection.json",
            "diagnostic.json",
            "build-set.json",
            "quiet.json",
            "seal.json",
        ]),
    };
    for relative in files {
        if fixed.contains(relative.as_str())
            || is_raw_arm_path(&relative)
            || (kind == EvidenceKind::Calibration && is_smoke_case_member(&relative))
            || (kind == EvidenceKind::Diagnostic && is_diagnostic_case_member(&relative))
        {
            continue;
        }
        return Err(Error::new(format!("unknown evidence member `{relative}`")));
    }
    Ok(())
}

fn is_diagnostic_case_member(path: &str) -> bool {
    path.starts_with("case/")
        && [
            "case.json",
            "fixture.bin",
            "sampler-freeze.bin",
            "sampler-final.bin",
            "materialization.json",
            "role-failure-fixture.json",
            "role-failure-load.json",
            "role-failure-sampler.json",
        ]
        .contains(&path.trim_start_matches("case/"))
}

fn is_smoke_case_path(path: &str) -> bool {
    path.starts_with("smoke-cases/") && path.ends_with("/case.json")
}

fn is_smoke_case_member(path: &str) -> bool {
    path.starts_with("smoke-cases/")
        && [
            "/case.json",
            "/fixture.bin",
            "/sampler-freeze.bin",
            "/sampler-final.bin",
            "/materialization.json",
            "/role-failure-fixture.json",
            "/role-failure-load.json",
            "/role-failure-sampler.json",
        ]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

fn verify_smoke_raw_cases_and_builds(
    root: &Path,
    intent: &Intent,
    smoke: &TopologySmokeEvidence,
) -> Result<()> {
    let build_bytes = fs::read(root.join("build-set.json"))?;
    let builds: crate::build::BuildSet = json::require_canonical(&build_bytes)?;
    if builds.schema != "amg-http2-perf/build-set/v1"
        || sha256_hex(&build_bytes) != smoke.build_set_sha256
        || builds.baseline.commit != intent.baseline_commit
        || builds.candidate.commit != intent.candidate_commit
        || builds.baseline.binary_sha256 != smoke.baseline_binary_sha256
        || builds.candidate.binary_sha256 != smoke.candidate_binary_sha256
    {
        return Err(Error::new(
            "smoke build set does not bind exact commits/binaries",
        ));
    }
    let repository = crate::bundle::repository_root(root)?;
    builds.baseline.validate_sealed_evidence(&repository)?;
    builds.candidate.validate_sealed_evidence(&repository)?;
    let quiet: crate::raw::QuietEvidence = read_canonical(root, "quiet.json")?;
    quiet.validate()?;

    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    let mut retained_role_failures = Vec::new();
    for relative in files
        .iter()
        .filter(|path| path.contains("/role-failure-") && path.ends_with(".json"))
    {
        let failure: SafeRoleFailure = json::require_canonical(&fs::read(root.join(relative))?)?;
        failure.validate()?;
        retained_role_failures.push(failure);
    }
    let mut raw_cases = BTreeMap::new();
    for relative in files.into_iter().filter(|path| is_smoke_case_path(path)) {
        let bytes = fs::read(root.join(&relative))?;
        let leaf = root
            .join(&relative)
            .parent()
            .ok_or_else(|| Error::new("smoke case path has no parent"))?
            .to_path_buf();
        for member in [
            "case.json",
            "fixture.bin",
            "sampler-freeze.bin",
            "sampler-final.bin",
        ] {
            if !leaf.join(member).is_file() {
                return Err(Error::new(format!(
                    "smoke raw case lacks mandatory member {member}"
                )));
            }
        }
        let fixture_bytes = fs::read(leaf.join("fixture.bin"))?;
        let fixture: crate::control::FixtureResult = json::require_canonical(&fixture_bytes)?;
        let freeze = crate::sampler::verify_persistent(&leaf.join("sampler-freeze.bin"))?;
        let final_report = crate::sampler::verify_persistent(&leaf.join("sampler-final.bin"))?;
        let derived = match json::require_canonical::<crate::orchestrator::SmokeArmOutcome>(&bytes)
        {
            Ok(outcome) => {
                let materialization_path = leaf.join("materialization.json");
                match &outcome.ordinary_materialization {
                    Some(materialization) => {
                        materialization.validate()?;
                        let retained: crate::materialization::MaterializationEvidence =
                            json::require_canonical(&fs::read(&materialization_path)?)?;
                        if &retained != materialization {
                            return Err(Error::new(
                                "gateway smoke materialization member differs from case summary",
                            ));
                        }
                    }
                    None if materialization_path.exists() => {
                        return Err(Error::new(
                            "legacy/non-ordinary smoke case has stray materialization evidence",
                        ));
                    }
                    None => {}
                }
                if outcome.fixture_operation_hash_sha256 != fixture.operation_hash_sha256
                    || outcome.fixture_observations != fixture.observations.len() as u64
                    || outcome.sampler_lifecycle_events != final_report.lifecycle_events
                    || outcome.sampler_attribution_cpus != final_report.attribution.len() as u64
                    || outcome.frozen_thread_counts
                        != freeze
                            .inventories
                            .iter()
                            .map(|inventory| {
                                (
                                    inventory.role.label().to_owned(),
                                    inventory.threads.len() as u64,
                                )
                            })
                            .collect()
                {
                    return Err(Error::new(
                        "gateway smoke case summary differs from raw fixture/sampler members",
                    ));
                }
                outcome.smoke_case()?
            }
            Err(_) => {
                let outcome: crate::orchestrator::DirectSmokeOutcome =
                    json::require_canonical(&bytes)?;
                if outcome.fixture_physical_connections != fixture.physical_connections
                    || outcome.fixture_active_connections != fixture.active_connections
                    || outcome.sampler_lifecycle_events != final_report.lifecycle_events
                    || outcome.sampler_attribution_cpus != final_report.attribution.len() as u64
                {
                    return Err(Error::new(
                        "direct smoke case summary differs from raw fixture/sampler members",
                    ));
                }
                outcome.smoke_case()?
            }
        };
        if raw_cases.insert(derived.key.clone(), derived).is_some() {
            return Err(Error::new("duplicate smoke raw case identity"));
        }
    }
    let topology_cases = smoke
        .cases
        .iter()
        .map(|case| (case.key.clone(), case))
        .collect::<BTreeMap<_, _>>();
    for (key, raw) in &raw_cases {
        if topology_cases.get(key).copied() != Some(raw) {
            return Err(Error::new(
                "smoke unit summary differs from mandatory raw case evidence",
            ));
        }
    }
    let missing_clean = smoke.cases.iter().any(|case| {
        case.derived_semantic_class() == SemanticClass::Ok && !raw_cases.contains_key(&case.key)
    });
    if missing_clean {
        return Err(Error::new(
            "passing smoke case lacks mandatory raw case member",
        ));
    }
    let failure_path = root.join("smoke-failure.json");
    let failed_cases = smoke
        .cases
        .iter()
        .filter(|case| case.derived_semantic_class() != SemanticClass::Ok)
        .collect::<Vec<_>>();
    if failure_path.exists() {
        let failure: RetainedSmokeFailure = read_canonical(root, "smoke-failure.json")?;
        failure.validate()?;
        if smoke.terminal_integrity_failure.is_none()
            || !expected_smoke_cases().contains(&failure.key)
        {
            return Err(Error::new(
                "retained smoke failure key/terminal is not declared by topology evidence",
            ));
        }
        match &failure.role_failure {
            Some(role_failure)
                if retained_role_failures.len() == 1
                    && retained_role_failures.first() == Some(role_failure) => {}
            None if retained_role_failures.is_empty() => {}
            _ => {
                return Err(Error::new(
                    "retained smoke role failure differs from its case-level evidence",
                ))
            }
        }
    } else if !failed_cases.is_empty() || smoke.terminal_integrity_failure.is_some() {
        return Err(Error::new(
            "failed smoke topology lacks retained failure evidence",
        ));
    }
    Ok(())
}

fn is_raw_arm_path(path: &str) -> bool {
    (path.starts_with("arms/") || path.starts_with("direct/") || path.starts_with("scouts/"))
        && raw::COMMON_ARM_MEMBERS
            .iter()
            .any(|member| path.ends_with(&format!("/{member}")))
        || (path.starts_with("arms/") && path.ends_with("/latencies.u64le"))
}

fn collect_files(root: &Path, directory: &Path, output: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::new("evidence member link is forbidden"));
        }
        if metadata.is_dir() {
            collect_files(root, &path, output)?;
        } else if metadata.is_file() {
            output.push(
                path.strip_prefix(root)
                    .map_err(|_| Error::new("evidence path escaped root"))?
                    .to_str()
                    .ok_or_else(|| Error::new("evidence path is not UTF-8"))?
                    .replace('\\', "/"),
            );
        } else {
            return Err(Error::new("non-regular evidence member is forbidden"));
        }
    }
    output.sort();
    Ok(())
}

fn read_canonical<T: serde::de::DeserializeOwned + Serialize>(
    root: &Path,
    name: &str,
) -> Result<T> {
    let bytes = fs::read(root.join(name))?;
    if bytes.len() as u64 > JSON_MAX_BYTES {
        return Err(Error::new(format!("{name} exceeds its JSON cap")));
    }
    json::require_canonical(&bytes)
}

pub fn blocked_reason(detail: impl Into<String>) -> BlockedReason {
    BlockedReason::new(BlockedCode::EvidenceIntegrity, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_terminal_precedence_is_integrity_baseline_candidate_quality_incomplete() {
        let decide =
            |integrity: &[&str], baseline: &[&str], candidate: &[&str], quality: &[&str]| {
                terminal_precedence(
                    integrity.iter().map(|value| (*value).to_owned()).collect(),
                    baseline.iter().map(|value| (*value).to_owned()).collect(),
                    candidate.iter().map(|value| (*value).to_owned()).collect(),
                    None,
                    quality.iter().map(|value| (*value).to_owned()).collect(),
                    true,
                )
                .0
            };
        assert_eq!(
            decide(&["hash"], &["baseline"], &["candidate"], &["noise"]),
            TerminalState::Blocked
        );
        assert_eq!(
            decide(&[], &["baseline"], &["candidate"], &["noise"]),
            TerminalState::Blocked
        );
        assert_eq!(
            decide(&[], &[], &["candidate"], &["noise"]),
            TerminalState::Fail
        );
        assert_eq!(decide(&[], &[], &[], &["noise"]), TerminalState::Blocked);
        assert_eq!(decide(&[], &[], &[], &[]), TerminalState::Blocked);
        assert_eq!(
            terminal_precedence(Vec::new(), Vec::new(), Vec::new(), None, Vec::new(), false).0,
            TerminalState::Pass
        );
    }

    #[test]
    fn endpoint_projection_rejects_storage_underprediction_and_reports_cap_blockers() {
        let mut projection = ProjectionEvidence {
            schema: PROJECTION_SCHEMA.to_owned(),
            runtime_projected_ns: 1,
            runtime_actual_ns: 1,
            raw_projected_bytes: 10,
            raw_actual_bytes: 10,
            tracked_projected_bytes: 10,
            tracked_actual_bytes: 10,
            endpoint_bound_bytes: 512 + 160 * 137 + 512,
            conn_live: 137,
            concurrency: 1,
        };
        projection.validate().expect("exact endpoint bound");
        projection.endpoint_bound_bytes -= 1;
        assert!(projection.validate().is_err());
        projection.endpoint_bound_bytes += 1;
        projection.raw_actual_bytes = 11;
        projection.tracked_actual_bytes = TASK_CAP_BYTES + 1;
        assert_eq!(projection.blockers().len(), 3);
    }

    #[test]
    fn runtime_caps_accept_exact_42h_and_48h_and_reject_one_nanosecond_over() {
        let mut projection = ProjectionEvidence {
            schema: PROJECTION_SCHEMA.to_owned(),
            runtime_projected_ns: 151_200_000_000_000,
            runtime_actual_ns: 172_800_000_000_000,
            raw_projected_bytes: 1,
            raw_actual_bytes: 1,
            tracked_projected_bytes: 1,
            tracked_actual_bytes: 1,
            endpoint_bound_bytes: 512 + 160 * 137 + 512,
            conn_live: 137,
            concurrency: 1,
        };
        assert!(projection.blockers().is_empty());
        projection.runtime_projected_ns += 1;
        assert!(projection
            .blockers()
            .iter()
            .any(|blocker| blocker.contains("42 hours")));
        projection.runtime_projected_ns -= 1;
        projection.runtime_actual_ns += 1;
        assert!(projection
            .blockers()
            .iter()
            .any(|blocker| blocker.contains("48 hours")));
    }

    #[test]
    fn zero_arm_complete_campaign_inventory_can_never_pass() {
        let design = DesignLock {
            schema: DESIGN_LOCK_SCHEMA.to_owned(),
            intent_sha256: "01".repeat(32),
            calibration_plan_sha256: "02".repeat(32),
            selected_n: 30,
            schedule_seed: 9,
            rounds: crate::schedule::generate_rounds(9, 30).expect("schedule"),
            comparisons: hard_comparisons(),
        };
        let state = ExecutionStateEvidence {
            schema: EXECUTION_STATE_SCHEMA.to_owned(),
            evidence_id: "campaign".to_owned(),
            phase: ExecutionPhase::Complete,
            next_ordinal: 0,
            planned_arms: 2_340,
            completed_arms: 0,
            complete: true,
            crash_detail: None,
        };
        let blockers = campaign_inventory_blockers(&[], &state, &design);
        assert!(blockers.iter().any(|value| value.contains("zero raw arms")));
        assert!(blockers
            .iter()
            .any(|value| value.contains("terminal inventory")));
    }
}
