use crate::control::ProtocolDateObservation;
use crate::json;
use crate::schema::{
    validate_sha256, Arm, ArmMetrics, EvidenceClass, RawArmMetadata, RawProtocol, Workload,
    TASK_CAP_BYTES,
};
use crate::session::{ready_predicates_at, ReadySessionEvidence};
use crate::{Error, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const LATENCY_MAGIC: &[u8; 8] = b"AMGLAT01";
const LATENCY_SCHEMA: u16 = 1;
const LATENCY_ENDIAN_LE: u8 = 1;
const LATENCY_RECORD_WIDTH: u32 = 8;
const LATENCY_HEADER_BYTES: usize = 32;
const RECORD_MAGIC: &[u8; 8] = b"AMGRAW01";
const RECORD_SCHEMA: u16 = 1;
const RECORD_HEADER_BYTES: usize = 32;
const OPERATION_BASE_PAYLOAD_BYTES: usize = 192;
const OPERATION_LANE_RECORD_BYTES: usize = 24;

const fn is_zero(value: &u64) -> bool {
    *value == 0
}

const fn is_false(value: &bool) -> bool {
    !*value
}

pub const COMMON_ARM_MEMBERS: [&str; 8] = [
    "metadata.json",
    "quiet.json",
    "thread-map.json",
    "thread-lifecycle.bin",
    "session-clock.bin",
    "resources.bin",
    "endpoints.bin",
    "operation-summary.bin",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum RecordKind {
    ThreadLifecycle = 1,
    SessionClock = 2,
    Resources = 3,
    Endpoints = 4,
    OperationSummary = 5,
}

impl RecordKind {
    fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::ThreadLifecycle),
            2 => Ok(Self::SessionClock),
            3 => Ok(Self::Resources),
            4 => Ok(Self::Endpoints),
            5 => Ok(Self::OperationSummary),
            _ => Err(Error::new(format!("unknown raw record kind {value}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RawPhase {
    Proof,
    Warmup,
    Measured,
    Drain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticClass {
    Ok,
    CandidateFailure,
    BaselineFailure,
    IntegrityFailure,
}

impl SemanticClass {
    #[must_use]
    pub const fn is_failure(self) -> bool {
        !matches!(self, Self::Ok)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuietEvidence {
    pub schema: String,
    pub clock: String,
    pub start_ns: u64,
    pub end_ns: u64,
    pub q_extra_ns: u64,
    pub cpu_psi_some_us: u64,
    pub memory_psi_full_us: u64,
    pub io_psi_full_us: u64,
    pub swap_in_delta: u64,
    pub swap_out_delta: u64,
    pub steal_ticks_delta: u64,
    pub external_time_clean: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub search_start_ns: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orchestrator_threads: Vec<QuietOrchestratorThread>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<QuietCandidateEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuietOrchestratorThread {
    pub pid: u32,
    pub tid: u32,
    pub start_time_ticks: u64,
    pub comm: String,
    pub assigned_cpu: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuietCpuEvidence {
    pub cpu: u16,
    pub scheduled_ticks: u64,
    pub capacity_ticks: u64,
    pub orchestrator_ticks_subtracted: u64,
    pub external_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuietCandidateEvidence {
    pub start_ns: u64,
    pub end_ns: u64,
    pub cpu_psi_some_us: u64,
    pub memory_psi_full_us: u64,
    pub io_psi_full_us: u64,
    pub swap_in_delta: u64,
    pub swap_out_delta: u64,
    pub steal_ticks_delta: u64,
    pub cpus: Vec<QuietCpuEvidence>,
    pub orchestrator_inventory_stable: bool,
    pub accepted: bool,
}

impl QuietEvidence {
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            self.schema.as_str(),
            "amg-http2-perf/quiet/v1" | "amg-http2-perf/quiet/v2"
        ) || self.clock != "CLOCK_MONOTONIC"
            || self.end_ns.checked_sub(self.start_ns) != Some(10_000_000_000)
            || self.q_extra_ns > 120_000_000_000
        {
            return Err(Error::new("invalid exact Q_obs boundary"));
        }
        if self.schema == "amg-http2-perf/quiet/v1" {
            if self.search_start_ns != 0
                || !self.orchestrator_threads.is_empty()
                || !self.candidates.is_empty()
            {
                return Err(Error::new("v1 quiet evidence contains v2 fields"));
            }
            return Ok(());
        }
        if self.search_start_ns == 0
            || self.orchestrator_threads.is_empty()
            || self.candidates.is_empty()
        {
            return Err(Error::new(
                "v2 quiet evidence lacks search/inventory/candidates",
            ));
        }
        let mut identities = BTreeSet::new();
        for thread in &self.orchestrator_threads {
            if thread.pid == 0
                || thread.tid == 0
                || thread.start_time_ticks == 0
                || thread.comm.is_empty()
                || !crate::linux::CONTROL_CPUS.contains(&thread.assigned_cpu)
                || !identities.insert((thread.pid, thread.tid, thread.start_time_ticks))
            {
                return Err(Error::new("quiet orchestrator inventory is malformed"));
            }
        }
        let mut previous_end = self.search_start_ns;
        for (index, candidate) in self.candidates.iter().enumerate() {
            if candidate.start_ns < previous_end
                || candidate.end_ns.checked_sub(candidate.start_ns) != Some(10_000_000_000)
                || candidate.accepted != candidate.recomputed_clean()
                || (index + 1 != self.candidates.len() && candidate.accepted)
            {
                return Err(Error::new(
                    "quiet candidate boundary or independent decision is invalid",
                ));
            }
            previous_end = candidate.end_ns;
        }
        let accepted = self
            .candidates
            .last()
            .ok_or_else(|| Error::new("quiet candidate inventory is empty"))?;
        if !accepted.accepted
            || self.start_ns != accepted.start_ns
            || self.end_ns != accepted.end_ns
            || self.q_extra_ns != accepted.start_ns.saturating_sub(self.search_start_ns)
            || self.cpu_psi_some_us != accepted.cpu_psi_some_us
            || self.memory_psi_full_us != accepted.memory_psi_full_us
            || self.io_psi_full_us != accepted.io_psi_full_us
            || self.swap_in_delta != accepted.swap_in_delta
            || self.swap_out_delta != accepted.swap_out_delta
            || self.steal_ticks_delta != accepted.steal_ticks_delta
            || self.external_time_clean != quiet_external_time_clean(&accepted.cpus)
        {
            return Err(Error::new(
                "final quiet observation differs from retained candidate search",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn clean(&self) -> bool {
        self.cpu_psi_some_us <= 50_000
            && self.memory_psi_full_us == 0
            && self.io_psi_full_us == 0
            && self.swap_in_delta == 0
            && self.swap_out_delta == 0
            && self.steal_ticks_delta == 0
            && self.external_time_clean
    }
}

impl QuietCandidateEvidence {
    #[must_use]
    pub fn recomputed_clean(&self) -> bool {
        self.end_ns.checked_sub(self.start_ns) == Some(10_000_000_000)
            && self.orchestrator_inventory_stable
            && self.cpu_psi_some_us <= 50_000
            && self.memory_psi_full_us == 0
            && self.io_psi_full_us == 0
            && self.swap_in_delta == 0
            && self.swap_out_delta == 0
            && self.steal_ticks_delta == 0
            && quiet_external_time_clean(&self.cpus)
    }

    #[must_use]
    pub fn external_time_clean(&self) -> bool {
        quiet_external_time_clean(&self.cpus)
    }
}

fn quiet_external_time_clean(cpus: &[QuietCpuEvidence]) -> bool {
    if cpus.len() != 32 {
        return false;
    }
    let mut by_cpu = BTreeMap::new();
    for row in cpus {
        if row.capacity_ticks == 0
            || row.scheduled_ticks > row.capacity_ticks
            || row.orchestrator_ticks_subtracted > row.scheduled_ticks
            || row.external_ticks
                != row
                    .scheduled_ticks
                    .saturating_sub(row.orchestrator_ticks_subtracted)
            || (row.orchestrator_ticks_subtracted != 0
                && !crate::linux::CONTROL_CPUS.contains(&row.cpu))
            || u128::from(row.external_ticks) * 100 > u128::from(row.capacity_ticks)
            || by_cpu.insert(row.cpu, row).is_some()
        {
            return false;
        }
    }
    for first in 0_u16..16 {
        let (Some(left), Some(right)) = (by_cpu.get(&first), by_cpu.get(&(first + 16))) else {
            return false;
        };
        let Some(external) = left.external_ticks.checked_add(right.external_ticks) else {
            return false;
        };
        let Some(capacity) = left.capacity_ticks.checked_add(right.capacity_ticks) else {
            return false;
        };
        if u128::from(external) * 200 > u128::from(capacity) {
            return false;
        }
    }
    for role_cpus in [
        crate::linux::GATEWAY_CPUS,
        crate::linux::FIXTURE_CPUS,
        crate::linux::LOAD_CPUS,
        crate::linux::CONTROL_CPUS,
    ] {
        let totals = role_cpus.iter().try_fold((0_u64, 0_u64), |totals, cpu| {
            let row = by_cpu.get(cpu)?;
            Some((
                totals.0.checked_add(row.external_ticks)?,
                totals.1.checked_add(row.capacity_ticks)?,
            ))
        });
        let Some((external, capacity)) = totals else {
            return false;
        };
        if u128::from(external) * 400 > u128::from(capacity) {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenThread {
    pub role: String,
    pub pid: u32,
    pub tid: u32,
    pub start_time_ticks: u64,
    pub comm: String,
    pub assigned_cpu: u16,
    pub allowed_cpu: u16,
    pub observed_last_cpu: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadMapEvidence {
    pub schema: String,
    pub signature_sha256: String,
    pub threads: Vec<FrozenThread>,
}

impl ThreadMapEvidence {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "amg-http2-perf/thread-map/v1"
            || self.threads.is_empty()
            || placeholder_hash(&self.signature_sha256)
        {
            return Err(Error::new("invalid or empty frozen thread map"));
        }
        validate_sha256("thread signature", &self.signature_sha256)?;
        let mut identities = BTreeSet::new();
        for thread in &self.threads {
            if thread.role.is_empty()
                || thread.comm.is_empty()
                || thread.start_time_ticks == 0
                || thread.assigned_cpu != thread.allowed_cpu
                || thread.assigned_cpu != thread.observed_last_cpu
                || !identities.insert((thread.pid, thread.tid, thread.start_time_ticks))
            {
                return Err(Error::new(
                    "thread map has duplicate, migrated, or non-singleton identity",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStageEvidence {
    pub name: String,
    pub start_ns: u64,
    pub end_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadLifecycleEvidence {
    pub schema: String,
    pub stages: Vec<LifecycleStageEvidence>,
    pub lifecycle_poll_max_ns: u64,
    pub births_before_freeze: u64,
    pub deaths_before_freeze: u64,
    pub births_after_freeze: u64,
    pub deaths_after_freeze: u64,
    pub migrations_after_freeze: u64,
    pub freeze_ns: u64,
    pub ordinary_handoff_ns: Option<u64>,
    pub websocket_auth_done_ns: Option<u64>,
    pub websocket_eligible_ns: Option<u64>,
    pub websocket_stable_ns: Option<u64>,
}

impl ThreadLifecycleEvidence {
    pub fn validate(&self, workload: Workload) -> Result<()> {
        if self.schema != "amg-http2-perf/thread-lifecycle/v1"
            || self.stages.is_empty()
            || self.lifecycle_poll_max_ns > 10_000_000
            || self.births_after_freeze != 0
            || self.deaths_after_freeze != 0
            || self.migrations_after_freeze != 0
        {
            return Err(Error::new(format!(
                "invalid thread lifecycle/freeze evidence: poll={} births={} deaths={} migrations={}",
                self.lifecycle_poll_max_ns,
                self.births_after_freeze,
                self.deaths_after_freeze,
                self.migrations_after_freeze
            )));
        }
        let mut previous_end = None;
        for stage in &self.stages {
            if stage.name.is_empty()
                || stage.end_ns < stage.start_ns
                || previous_end.is_some_and(|end| end != stage.start_ns)
            {
                return Err(Error::new(
                    "lifecycle stages are not contiguous monotonic intervals",
                ));
            }
            previous_end = Some(stage.end_ns);
        }
        if workload == Workload::WebSocket {
            let (Some(auth), Some(eligible), Some(stable)) = (
                self.websocket_auth_done_ns,
                self.websocket_eligible_ns,
                self.websocket_stable_ns,
            ) else {
                return Err(Error::new("WebSocket lifecycle timestamps are missing"));
            };
            if eligible < auth.saturating_add(10_000_000_000)
                || stable < eligible.saturating_add(2_000_000_000)
                || self.freeze_ns < stable
                || self.ordinary_handoff_ns.is_some()
            {
                return Err(Error::new(
                    "WebSocket retirement/settle ordering is invalid",
                ));
            }
        } else if self
            .ordinary_handoff_ns
            .is_none_or(|value| value > 3_000_000_000)
            || self.websocket_auth_done_ns.is_some()
            || self.websocket_eligible_ns.is_some()
            || self.websocket_stable_ns.is_some()
        {
            return Err(Error::new("ordinary lifecycle handoff is invalid"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockSample {
    pub boottime_before_ns: u64,
    pub realtime_ns: u64,
    pub boottime_after_ns: u64,
    pub ready: bool,
    pub active: bool,
    pub refresh_due: bool,
    pub touch_due: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionClockEvidence {
    pub schema: String,
    pub direct: bool,
    pub comparable: bool,
    pub discontinuities: u64,
    pub samples: Vec<ClockSample>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_session: Option<ReadySessionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol_dates: Vec<ProtocolDateObservation>,
}

impl SessionClockEvidence {
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            self.schema.as_str(),
            "amg-http2-perf/session-clock/v1" | "amg-http2-perf/session-clock/v2"
        ) {
            return Err(Error::new("unsupported session clock schema"));
        }
        if self.schema == "amg-http2-perf/session-clock/v1" {
            if self.ready_session.is_some()
                || self.clock_manifest_sha256.is_some()
                || !self.protocol_dates.is_empty()
            {
                return Err(Error::new("v1 session clock contains v2 fields"));
            }
            if self.direct {
                if !self.samples.is_empty() || !self.comparable || self.discontinuities != 0 {
                    return Err(Error::new("direct session clock record is not fixed N/A"));
                }
                return Ok(());
            }
            if self.samples.is_empty()
                || self.samples.iter().any(|sample| {
                    sample.boottime_before_ns > sample.boottime_after_ns
                        || !sample.ready
                        || !sample.active
                        || sample.refresh_due
                        || sample.touch_due
                })
            {
                return Err(Error::new("invalid ready-session clock continuity samples"));
            }
            return Ok(());
        }
        let clock_manifest = self
            .clock_manifest_sha256
            .as_ref()
            .ok_or_else(|| Error::new("v2 session clock lacks its clock manifest root"))?;
        validate_sha256("clock boundary manifest", clock_manifest)?;
        if placeholder_hash(clock_manifest) {
            return Err(Error::new("clock boundary manifest is a placeholder"));
        }
        if self.direct {
            if !self.samples.is_empty()
                || !self.comparable
                || self.discontinuities != 0
                || self.ready_session.is_some()
                || !self.protocol_dates.is_empty()
            {
                return Err(Error::new("direct session clock record is not fixed N/A"));
            }
            return Ok(());
        }
        let ready_session = self
            .ready_session
            .as_ref()
            .ok_or_else(|| Error::new("v2 gateway session clock lacks ready-session evidence"))?;
        if self.samples.is_empty() || self.protocol_dates.is_empty() {
            return Err(Error::new(
                "v2 gateway session clock lacks clock or HTTP Date observations",
            ));
        }
        for sample in &self.samples {
            if sample.boottime_before_ns > sample.boottime_after_ns {
                return Err(Error::new("session clock BOOTTIME bracket is inverted"));
            }
            let derived = ready_predicates_at(ready_session, sample.realtime_ns)?;
            if sample.ready != derived.ready
                || sample.active != derived.active
                || sample.refresh_due != derived.access_refresh_due
                || sample.touch_due != derived.touch_due
            {
                return Err(Error::new(
                    "retained session predicate bits differ from independent derivation",
                ));
            }
        }
        let derived_discontinuities = realtime_discontinuities(&self.samples)?;
        if self.discontinuities != derived_discontinuities {
            return Err(Error::new(
                "retained REALTIME discontinuity count differs from bracketed samples",
            ));
        }
        for date in &self.protocol_dates {
            if date.value.is_empty()
                || date.value.len() > 64
                || date.boottime_before_ns > date.boottime_after_ns
                || crate::load::parse_http_date_seconds(&date.value)? != date.unix_seconds
            {
                return Err(Error::new("invalid BOOTTIME-bracketed HTTP Date evidence"));
            }
        }
        let derived_comparable = self.derived_comparable()?;
        if self.comparable != derived_comparable {
            return Err(Error::new(
                "retained session comparability differs from independent derivation",
            ));
        }
        Ok(())
    }

    pub fn derived_comparable(&self) -> Result<bool> {
        if self.direct {
            return Ok(self.schema == "amg-http2-perf/session-clock/v2"
                && self.samples.is_empty()
                && self.protocol_dates.is_empty());
        }
        let Some(ready_session) = &self.ready_session else {
            return Ok(false);
        };
        if self.samples.is_empty() || self.protocol_dates.is_empty() {
            return Ok(false);
        }
        let predicates_clean = self.samples.iter().try_fold(true, |clean, sample| {
            let derived = ready_predicates_at(ready_session, sample.realtime_ns)?;
            Ok::<bool, Error>(
                clean
                    && derived.ready
                    && derived.active
                    && !derived.access_refresh_due
                    && !derived.touch_due,
            )
        })?;
        let minimum_realtime = self
            .samples
            .iter()
            .map(|sample| sample.realtime_ns / 1_000_000_000)
            .min()
            .unwrap_or(0)
            .saturating_sub(1);
        let maximum_realtime = self
            .samples
            .iter()
            .map(|sample| sample.realtime_ns / 1_000_000_000)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let dates_comparable = self.protocol_dates.iter().all(|date| {
            (minimum_realtime..=maximum_realtime).contains(&date.unix_seconds)
                && date.boottime_before_ns <= date.boottime_after_ns
        });
        Ok(predicates_clean && realtime_discontinuities(&self.samples)? == 0 && dates_comparable)
    }
}

fn realtime_discontinuities(samples: &[ClockSample]) -> Result<u64> {
    samples.windows(2).try_fold(0_u64, |count, pair| {
        let previous_boot = pair[0]
            .boottime_before_ns
            .checked_add(pair[0].boottime_after_ns)
            .ok_or_else(|| Error::new("previous BOOTTIME midpoint overflow"))?
            / 2;
        let current_boot = pair[1]
            .boottime_before_ns
            .checked_add(pair[1].boottime_after_ns)
            .ok_or_else(|| Error::new("current BOOTTIME midpoint overflow"))?
            / 2;
        let boot_delta = current_boot
            .checked_sub(previous_boot)
            .ok_or_else(|| Error::new("BOOTTIME continuity moved backwards"))?;
        let discontinuous = pair[1]
            .realtime_ns
            .checked_sub(pair[0].realtime_ns)
            .is_none_or(|delta| delta.abs_diff(boot_delta) > 100_000_000);
        count
            .checked_add(u64::from(discontinuous))
            .ok_or_else(|| Error::new("REALTIME discontinuity count overflow"))
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuBucketEvidence {
    pub cpu: u16,
    pub role: String,
    pub start_ns: u64,
    pub end_ns: u64,
    pub process_runtime_lower: u64,
    pub process_runtime_upper: u64,
    pub tid_runtime_lower: u64,
    pub tid_runtime_upper: u64,
    pub capacity_ticks: u64,
    pub scheduled_ticks: u64,
    pub external_upper_ticks: u64,
    pub attribution_uncertainty_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleUtilizationEvidence {
    pub role: String,
    pub used_ticks: u64,
    pub capacity_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResidualEvidence {
    pub role: String,
    pub phase: String,
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
pub struct NoiseScopeDecisionEvidence {
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
pub struct ResourceEvidence {
    pub schema: String,
    pub gateway_ticks_start: u64,
    pub gateway_ticks_deadline: u64,
    pub gateway_ticks_drain: u64,
    pub vm_hwm_kib: u64,
    pub major_faults: u64,
    pub swap_in_delta: u64,
    pub swap_out_delta: u64,
    pub steal_ticks_delta: u64,
    pub memory_psi_full_us: u64,
    pub io_psi_full_us: u64,
    pub tctl_start_millidegrees: u64,
    pub tctl_max_millidegrees: u64,
    pub median_frequency_khz: u64,
    pub frequency_floor_khz: u64,
    pub buckets: Vec<CpuBucketEvidence>,
    pub utilization: Vec<RoleUtilizationEvidence>,
    pub direct_ceiling_ops: Option<u64>,
    pub gateway_ops: Option<u64>,
    pub calibration_direct_ops: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frozen_whole_buckets: Vec<CpuBucketEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frozen_bracket_buckets: Vec<CpuBucketEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_buckets: Vec<CpuBucketEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residuals: Vec<RuntimeResidualEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_decisions: Vec<NoiseScopeDecisionEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub producer_blockers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration_frequency_p05_khz: Option<u64>,
}

impl ResourceEvidence {
    pub fn validate(&self, class: EvidenceClass) -> Result<()> {
        if !matches!(
            self.schema.as_str(),
            "amg-http2-perf/resources/v1" | "amg-http2-perf/resources/v2"
        ) || self.gateway_ticks_deadline < self.gateway_ticks_start
            || self.gateway_ticks_drain < self.gateway_ticks_deadline
            || self.vm_hwm_kib == 0
            || self.buckets.is_empty()
            || self.utilization.is_empty()
        {
            return Err(Error::new("invalid process resource boundaries"));
        }
        for bucket in &self.buckets {
            let duration = bucket
                .end_ns
                .checked_sub(bucket.start_ns)
                .ok_or_else(|| Error::new("resource bucket clock moved backwards"))?;
            if duration == 0
                || bucket.process_runtime_lower > bucket.process_runtime_upper
                || bucket.tid_runtime_lower > bucket.tid_runtime_upper
                || bucket.process_runtime_upper < bucket.tid_runtime_lower
                || bucket.tid_runtime_upper < bucket.process_runtime_lower
                || bucket.external_upper_ticks > bucket.capacity_ticks
                || bucket.scheduled_ticks > bucket.capacity_ticks
            {
                return Err(Error::new("invalid process/TID/CPU bracket reconciliation"));
            }
        }
        if class != EvidenceClass::D && self.gateway_ticks_drain == self.gateway_ticks_start {
            return Err(Error::new("gateway arm has zero measured gateway ticks"));
        }
        if self.schema == "amg-http2-perf/resources/v2" {
            if self.frozen_whole_buckets.is_empty()
                || self.frozen_bracket_buckets.is_empty()
                || self.dynamic_buckets.is_empty()
                || self.residuals.is_empty()
                || self.scope_decisions.is_empty()
                || self.producer_blockers.iter().any(String::is_empty)
            {
                return Err(Error::new(
                    "v2 resource evidence lacks attribution/residual/scope inventory",
                ));
            }
            for bucket in self
                .frozen_whole_buckets
                .iter()
                .chain(&self.frozen_bracket_buckets)
                .chain(&self.dynamic_buckets)
            {
                validate_cpu_bucket(bucket)?;
            }
            for residual in &self.residuals {
                validate_runtime_residual(residual)?;
            }
            for scope in &self.scope_decisions {
                let recomputed = scope.capacity_ticks > 0
                    && u128::from(scope.external_upper_ticks) * 10_000
                        <= u128::from(scope.capacity_ticks) * u128::from(scope.limit_basis_points);
                if scope.cpus.is_empty()
                    || scope.start_ns >= scope.end_ns
                    || scope.accepted != recomputed
                    || !matches!(scope.attribution_phase.as_str(), "dynamic" | "frozen")
                    || !matches!(scope.interval_kind.as_str(), "whole" | "one-second")
                    || !matches!(scope.scope.as_str(), "logical" | "sibling-pair" | "role")
                {
                    return Err(Error::new(
                        "resource noise scope differs from independent arithmetic",
                    ));
                }
            }
            if self.scope_decisions
                != crate::sampler::recompute_noise_scopes_from_raw(
                    &self.frozen_whole_buckets,
                    &self.frozen_bracket_buckets,
                    &self.dynamic_buckets,
                )?
            {
                return Err(Error::new(
                    "retained noise scopes differ from raw counter-bucket recomputation",
                ));
            }
            match self.calibration_frequency_p05_khz {
                Some(reference) if reference >= 4_000_000 => {
                    if self.frequency_floor_khz != reference.saturating_mul(95) / 100 {
                        return Err(Error::new(
                            "authoritative frequency display floor differs from calibration p05",
                        ));
                    }
                }
                None if self.frequency_floor_khz == 4_000_000 => {}
                _ => {
                    return Err(Error::new(
                        "resource frequency policy is neither calibration-absolute nor authoritative-relative",
                    ))
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn clean(&self) -> bool {
        self.major_faults == 0
            && self.swap_in_delta == 0
            && self.swap_out_delta == 0
            && self.steal_ticks_delta == 0
            && self.memory_psi_full_us == 0
            && self.io_psi_full_us == 0
            && self.tctl_start_millidegrees <= 75_000
            && self.tctl_max_millidegrees < 85_000
            && self.frequency_clean()
            && self
                .frozen_whole_buckets
                .iter()
                .chain(&self.frozen_bracket_buckets)
                .chain(&self.dynamic_buckets)
                .all(|bucket| bucket.attribution_uncertainty_ticks <= 1)
            && resource_noise_clean(&self.buckets)
            && (self.schema != "amg-http2-perf/resources/v2"
                || (self.producer_blockers.is_empty()
                    && crate::sampler::recompute_noise_scopes_from_raw(
                        &self.frozen_whole_buckets,
                        &self.frozen_bracket_buckets,
                        &self.dynamic_buckets,
                    )
                    .is_ok_and(|scopes| scopes == self.scope_decisions)
                    && self.scope_decisions.iter().all(|scope| {
                        scope.accepted
                            && scope.capacity_ticks > 0
                            && u128::from(scope.external_upper_ticks) * 10_000
                                <= u128::from(scope.capacity_ticks)
                                    * u128::from(scope.limit_basis_points)
                    })
                    && self.residuals.iter().all(runtime_residual_clean)))
            && self.utilization.iter().all(|role| {
                role.capacity_ticks > 0
                    && u128::from(role.used_ticks) * 100 <= u128::from(role.capacity_ticks) * 70
            })
            && direct_headroom_drift_clean(
                self.direct_ceiling_ops,
                self.gateway_ops,
                self.calibration_direct_ops,
            )
    }

    fn frequency_clean(&self) -> bool {
        self.calibration_frequency_p05_khz.map_or_else(
            || self.median_frequency_khz >= self.frequency_floor_khz,
            |reference| u128::from(self.median_frequency_khz) * 100 >= u128::from(reference) * 95,
        )
    }
}

fn validate_cpu_bucket(bucket: &CpuBucketEvidence) -> Result<()> {
    if bucket.role.is_empty()
        || bucket.start_ns >= bucket.end_ns
        || bucket.process_runtime_lower > bucket.process_runtime_upper
        || bucket.tid_runtime_lower > bucket.tid_runtime_upper
        || bucket.scheduled_ticks > bucket.capacity_ticks
        || bucket.external_upper_ticks > bucket.capacity_ticks
    {
        return Err(Error::new(format!(
            "invalid retained attribution counter bracket cpu={} role={} start={} end={} capacity={} scheduled={} external={}",
            bucket.cpu,
            bucket.role,
            bucket.start_ns,
            bucket.end_ns,
            bucket.capacity_ticks,
            bucket.scheduled_ticks,
            bucket.external_upper_ticks
        )));
    }
    Ok(())
}

fn validate_runtime_residual(residual: &RuntimeResidualEvidence) -> Result<()> {
    if residual.role.is_empty()
        || !matches!(residual.phase.as_str(), "dynamic" | "frozen")
        || residual.start_ns >= residual.end_ns
        || residual.process_runtime_lower_ticks > residual.process_runtime_upper_ticks
        || residual.known_tid_runtime_lower_ticks > residual.known_tid_runtime_upper_ticks
        || residual.u_role_lower_ticks > residual.u_role_upper_ticks
    {
        return Err(Error::new("invalid retained process/TID residual bracket"));
    }
    let signed_lower = i128::from(residual.process_runtime_lower_ticks)
        - i128::from(residual.known_tid_runtime_upper_ticks);
    let signed_upper = i128::from(residual.process_runtime_upper_ticks)
        - i128::from(residual.known_tid_runtime_lower_ticks);
    if i64::try_from(signed_lower).ok() != Some(residual.signed_residual_lower_ticks)
        || i64::try_from(signed_upper).ok() != Some(residual.signed_residual_upper_ticks)
    {
        return Err(Error::new(
            "retained signed residual differs from counter brackets",
        ));
    }
    Ok(())
}

fn runtime_residual_clean(residual: &RuntimeResidualEvidence) -> bool {
    if residual.phase == "frozen" {
        residual.signed_residual_lower_ticks <= 0
            && residual.signed_residual_upper_ticks >= 0
            && residual.u_role_lower_ticks == 0
            && residual.u_role_upper_ticks == 0
    } else {
        let known_plus_u_lower = residual
            .known_tid_runtime_lower_ticks
            .checked_add(residual.u_role_lower_ticks);
        let known_plus_u_upper = residual
            .known_tid_runtime_upper_ticks
            .checked_add(residual.u_role_upper_ticks);
        residual.u_role_lower_ticks <= residual.u_role_upper_ticks
            && known_plus_u_lower.is_some_and(|value| value <= residual.process_runtime_upper_ticks)
            && known_plus_u_upper.is_some_and(|value| value >= residual.process_runtime_lower_ticks)
    }
}

fn direct_headroom_drift_clean(
    direct: Option<u64>,
    gateway: Option<u64>,
    calibration: Option<u64>,
) -> bool {
    match (direct, gateway, calibration) {
        (None, None, None) => true,
        (Some(direct), Some(gateway), Some(calibration))
            if direct > 0 && gateway > 0 && calibration > 0 =>
        {
            u128::from(direct) * 4 >= u128::from(gateway) * 5
                && u128::from(direct) * 10 >= u128::from(calibration) * 9
                && u128::from(direct) * 10 <= u128::from(calibration) * 11
        }
        _ => false,
    }
}

fn resource_noise_clean(buckets: &[CpuBucketEvidence]) -> bool {
    if buckets.is_empty() {
        return false;
    }
    let accepted = |external: u64, capacity: u64, basis_points: u16| {
        capacity > 0
            && u128::from(external) * 10_000 <= u128::from(capacity) * u128::from(basis_points)
    };
    let mut intervals = BTreeMap::<(u64, u64), Vec<&CpuBucketEvidence>>::new();
    let mut whole = BTreeMap::<u16, (u64, u64, &str)>::new();
    for bucket in buckets {
        intervals
            .entry((bucket.start_ns, bucket.end_ns))
            .or_default()
            .push(bucket);
        let entry = whole.entry(bucket.cpu).or_insert((0, 0, &bucket.role));
        let Some(capacity) = entry.0.checked_add(bucket.capacity_ticks) else {
            return false;
        };
        let Some(external) = entry.1.checked_add(bucket.external_upper_ticks) else {
            return false;
        };
        if entry.2 != bucket.role {
            return false;
        }
        *entry = (capacity, external, entry.2);
    }
    for rows in intervals.values() {
        if rows
            .iter()
            .any(|row| !accepted(row.external_upper_ticks, row.capacity_ticks, 200))
        {
            return false;
        }
        if !aggregate_resource_scopes(rows, 100, 50, &accepted) {
            return false;
        }
    }
    if whole
        .values()
        .any(|(capacity, external, _)| !accepted(*external, *capacity, 100))
    {
        return false;
    }
    let whole_rows = whole
        .iter()
        .map(|(cpu, (capacity, external, role))| CpuBucketEvidence {
            cpu: *cpu,
            role: (*role).to_owned(),
            start_ns: 0,
            end_ns: 1,
            process_runtime_lower: 0,
            process_runtime_upper: 0,
            tid_runtime_lower: 0,
            tid_runtime_upper: 0,
            capacity_ticks: *capacity,
            scheduled_ticks: *external,
            external_upper_ticks: *external,
            attribution_uncertainty_ticks: 0,
        })
        .collect::<Vec<_>>();
    let refs = whole_rows.iter().collect::<Vec<_>>();
    aggregate_resource_scopes(&refs, 50, 25, &accepted)
}

fn aggregate_resource_scopes(
    rows: &[&CpuBucketEvidence],
    pair_limit: u16,
    role_limit: u16,
    accepted: &impl Fn(u64, u64, u16) -> bool,
) -> bool {
    let by_cpu = rows
        .iter()
        .map(|row| (row.cpu, *row))
        .collect::<BTreeMap<_, _>>();
    for first in 0_u16..16 {
        if let (Some(left), Some(right)) = (by_cpu.get(&first), by_cpu.get(&(first + 16))) {
            let Some(capacity) = left.capacity_ticks.checked_add(right.capacity_ticks) else {
                return false;
            };
            let Some(external) = left
                .external_upper_ticks
                .checked_add(right.external_upper_ticks)
            else {
                return false;
            };
            if !accepted(external, capacity, pair_limit) {
                return false;
            }
        }
    }
    let mut roles = BTreeMap::<&str, (u64, u64)>::new();
    for row in rows {
        let entry = roles.entry(&row.role).or_default();
        let Some(capacity) = entry.0.checked_add(row.capacity_ticks) else {
            return false;
        };
        let Some(external) = entry.1.checked_add(row.external_upper_ticks) else {
            return false;
        };
        *entry = (capacity, external);
    }
    roles
        .values()
        .all(|(capacity, external)| accepted(*external, *capacity, role_limit))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPhaseEvidence {
    pub phase: RawPhase,
    pub started_operations: u64,
    pub attempt_starts: u64,
    pub attempt_successes: u64,
    pub planned_connections: u64,
    pub socket_creations: u64,
    pub connect_attempts: u64,
    pub connect_successes: u64,
    pub failed_attempts: u64,
    pub cumulative_connections: u64,
    pub requests: u64,
    pub responses: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub close_tokens: u64,
    pub keep_alive_tokens: u64,
    pub response_eos: u64,
    pub transport_eof: u64,
    pub active_connections: u64,
    pub max_active_connections: u64,
    pub max_requests_per_connection: u64,
    pub h2_streams: u64,
    pub max_active_h2_streams: u64,
    pub first_h2_stream_id: Option<u32>,
    pub last_h2_stream_id: Option<u32>,
    pub h2_stream_sequence_sha256: String,
    pub retries: u64,
    pub reconnects: u64,
    pub reuse_attempts: u64,
    pub operation_hash_sha256: String,
    pub connection_hash_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointEvidence {
    pub schema: String,
    pub downstream_protocol: RawProtocol,
    pub upstream_protocol: RawProtocol,
    pub downstream_physical_connections: u64,
    pub upstream_physical_connections: u64,
    pub h2_settings_seen: bool,
    pub h2_settings_ack_seen: bool,
    pub enable_connect_seen: bool,
    pub upstream_h2_settings_seen: bool,
    pub upstream_h2_settings_ack_seen: bool,
    pub upstream_enable_connect_seen: bool,
    pub downstream_stream_count: u64,
    pub downstream_first_stream_id: Option<u32>,
    pub downstream_last_stream_id: Option<u32>,
    pub downstream_stream_sequence_sha256: String,
    pub upstream_stream_count: u64,
    pub upstream_first_stream_id: Option<u32>,
    pub upstream_last_stream_id: Option<u32>,
    pub upstream_stream_sequence_sha256: String,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub load_operation_hash_sha256: String,
    pub fixture_operation_hash_sha256: String,
    pub tripwire_connections: u64,
    pub tripwire_bytes: u64,
    pub duplicate_operations: u64,
    pub phases: Vec<EndpointPhaseEvidence>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub downstream_protocol_observations: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub upstream_protocol_observations: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub fixture_identity_observations: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub fixture_identity_correct_observations: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fixture_identity_correct: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub request_header_observations: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub request_headers_sanitized_observations: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub request_headers_sanitized: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub response_header_observations: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub response_headers_sanitized_observations: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub response_headers_sanitized: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub gateway_date_observations: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway_date_values_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_manifest_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub corpus_manifest_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub connection_policy_manifest_sha256: String,
}

impl EndpointEvidence {
    pub fn validate(
        &self,
        metadata: &RawArmMetadata,
        operation: &OperationSummaryEvidence,
    ) -> Result<()> {
        if !matches!(
            self.schema.as_str(),
            "amg-http2-perf/endpoints/v1" | "amg-http2-perf/endpoints/v2"
        ) || self.phases.len() != 4
        {
            return Err(Error::new("invalid endpoint evidence schema/inventory"));
        }
        if self.schema == "amg-http2-perf/endpoints/v2" {
            for (name, hash) in [
                ("gateway Date values", &self.gateway_date_values_sha256),
                ("config manifest", &self.config_manifest_sha256),
                ("corpus manifest", &self.corpus_manifest_sha256),
                (
                    "connection policy manifest",
                    &self.connection_policy_manifest_sha256,
                ),
            ] {
                validate_sha256(name, hash)?;
                if placeholder_hash(hash) {
                    return Err(Error::new(format!("{name} hash is a placeholder")));
                }
            }
            if self.downstream_protocol_observations == 0
                || self.upstream_protocol_observations == 0
                || self.fixture_identity_observations == 0
                || self.fixture_identity_correct_observations > self.fixture_identity_observations
                || self.request_header_observations == 0
                || self.request_headers_sanitized_observations > self.request_header_observations
                || self.response_header_observations == 0
                || self.response_headers_sanitized_observations > self.response_header_observations
                || self.fixture_identity_correct
                    != (self.fixture_identity_correct_observations
                        == self.fixture_identity_observations)
                || self.request_headers_sanitized
                    != (self.request_headers_sanitized_observations
                        == self.request_header_observations)
                || self.response_headers_sanitized
                    != (self.response_headers_sanitized_observations
                        == self.response_header_observations)
                || (metadata.class != EvidenceClass::D && self.gateway_date_observations == 0)
            {
                return Err(Error::new(
                    "observed protocol/identity/header/Date evidence is incomplete or forged",
                ));
            }
        }
        for hash in [
            &self.load_operation_hash_sha256,
            &self.fixture_operation_hash_sha256,
            &self.downstream_stream_sequence_sha256,
            &self.upstream_stream_sequence_sha256,
        ] {
            validate_sha256("endpoint operation hash", hash)?;
            if placeholder_hash(hash) {
                return Err(Error::new("endpoint evidence contains a placeholder hash"));
            }
        }
        if self.load_operation_hash_sha256 != self.fixture_operation_hash_sha256
            || self.load_operation_hash_sha256 != operation.operation_hash_sha256
            || self.tripwire_connections != 0
            || self.tripwire_bytes != 0
            || self.duplicate_operations != 0
            || self.request_bytes != operation.request_bytes
            || self.response_bytes != operation.response_bytes
        {
            return Err(Error::new(
                "endpoint operation/byte/tripwire reconciliation failed",
            ));
        }
        let mut phases = BTreeMap::new();
        for phase in &self.phases {
            validate_sha256("phase operation hash", &phase.operation_hash_sha256)?;
            validate_sha256("phase connection hash", &phase.connection_hash_sha256)?;
            validate_sha256("phase H2 stream hash", &phase.h2_stream_sequence_sha256)?;
            if placeholder_hash(&phase.operation_hash_sha256)
                || placeholder_hash(&phase.connection_hash_sha256)
            {
                return Err(Error::new("endpoint phase contains a placeholder hash"));
            }
            if phases.insert(phase.phase, phase).is_some()
                || phase.deadline_count_is_impossible()
                || phase.active_connections > phase.max_active_connections
                || phase.max_active_connections > u64::from(metadata.cell.concurrency)
                || phase.retries != 0
                || phase.reconnects != 0
                || phase.reuse_attempts != 0
                || phase.failed_attempts != 0
                || phase.attempt_starts != phase.started_operations
                || phase.attempt_successes != phase.started_operations
                || phase.connect_successes.checked_add(phase.failed_attempts)
                    != Some(phase.connect_attempts)
            {
                return Err(Error::new(
                    "endpoint phase counters are malformed or unsafe",
                ));
            }
        }
        let expected_phases = [
            RawPhase::Proof,
            RawPhase::Warmup,
            RawPhase::Measured,
            RawPhase::Drain,
        ];
        if expected_phases
            .iter()
            .any(|phase| !phases.contains_key(phase))
        {
            return Err(Error::new("endpoint phase inventory is not exact"));
        }
        validate_phase_counter_sums(&self.phases)?;
        let measured = phases[&RawPhase::Measured];
        if measured.started_operations != operation.started_operations
            || measured.requests != operation.started_operations
            || measured.responses > operation.drained_operations
            || measured.response_eos > measured.responses
            || measured.transport_eof > measured.response_eos
            || measured.request_bytes != operation.request_bytes
            || measured.response_bytes != operation.response_bytes
        {
            return Err(Error::new(
                "endpoint measured-phase counters do not reconcile",
            ));
        }
        if self.downstream_protocol == RawProtocol::H1
            && metadata.cell.workload == Workload::Upload1Mib
        {
            for phase in &self.phases {
                let exact = phase.started_operations;
                if phase.planned_connections != exact
                    || phase.socket_creations != exact
                    || phase.connect_attempts != exact
                    || phase.connect_successes != exact
                    || phase.cumulative_connections != exact
                    || phase.requests != exact
                    || phase.max_requests_per_connection != u64::from(exact > 0)
                    || phase.active_connections != 0
                    || phase.keep_alive_tokens != 0
                    || phase.h2_streams != 0
                {
                    return Err(Error::new(
                        "fresh-H1 upload connection/start ledger mismatch",
                    ));
                }
            }
        }
        if self.downstream_protocol == RawProtocol::H2 {
            if self.downstream_physical_connections != 1
                || self.downstream_stream_count == 0
                || !stream_sequence_matches(
                    self.downstream_stream_count,
                    self.downstream_first_stream_id,
                    self.downstream_last_stream_id,
                    &self.downstream_stream_sequence_sha256,
                )?
            {
                return Err(Error::new("wire-observed downstream H2 topology mismatch"));
            }
        } else if self.downstream_stream_count != 0
            || self.downstream_first_stream_id.is_some()
            || self.downstream_last_stream_id.is_some()
            || self.downstream_stream_sequence_sha256 != stream_sequence_sha256(0)?
        {
            return Err(Error::new("H1 downstream carries H2 stream evidence"));
        }
        if self.upstream_protocol == RawProtocol::H2 {
            if self.upstream_physical_connections != 1
                || self.upstream_stream_count == 0
                || !stream_sequence_matches(
                    self.upstream_stream_count,
                    self.upstream_first_stream_id,
                    self.upstream_last_stream_id,
                    &self.upstream_stream_sequence_sha256,
                )?
            {
                return Err(Error::new("wire-observed upstream H2 topology mismatch"));
            }
        } else if self.upstream_stream_count != 0
            || self.upstream_first_stream_id.is_some()
            || self.upstream_last_stream_id.is_some()
            || self.upstream_stream_sequence_sha256 != stream_sequence_sha256(0)?
        {
            return Err(Error::new("H1 upstream carries H2 stream evidence"));
        }
        Ok(())
    }

    #[must_use]
    pub fn semantic_violations(
        &self,
        metadata: &RawArmMetadata,
        operation: &OperationSummaryEvidence,
    ) -> Vec<String> {
        let mut violations = Vec::new();
        let expected = expected_protocols(metadata);
        if let Some((downstream, upstream)) = expected {
            if self.downstream_protocol != downstream {
                violations.push("downstream protocol differs from the sealed arm".to_owned());
            }
            if self.upstream_protocol != upstream {
                violations.push("upstream protocol differs from the sealed arm".to_owned());
            }
        }
        let measured = self
            .phases
            .iter()
            .find(|phase| phase.phase == RawPhase::Measured);
        if let Some(measured) = measured {
            if measured.responses != operation.drained_operations {
                violations.push("response count differs from drained operations".to_owned());
            }
            if measured.response_eos != operation.drained_operations {
                violations.push("response EOS count differs from drained operations".to_owned());
            }
            if self.downstream_protocol == RawProtocol::H1
                && metadata.cell.workload == Workload::Upload1Mib
            {
                if measured.close_tokens != operation.started_operations {
                    violations.push("fresh-H1 upload close token is missing".to_owned());
                }
                if measured.transport_eof != operation.started_operations {
                    violations.push("fresh-H1 upload transport EOF is missing".to_owned());
                }
            }
        }
        if self.schema == "amg-http2-perf/endpoints/v2" {
            if !self.fixture_identity_correct {
                violations.push("fixture identity injection was not observed".to_owned());
            }
            if !self.request_headers_sanitized {
                violations.push(
                    "browser credential/request header sanitation was not observed".to_owned(),
                );
            }
            if !self.response_headers_sanitized {
                violations.push("response header sanitation was not observed".to_owned());
            }
            if metadata.class != EvidenceClass::D && self.gateway_date_observations == 0 {
                violations.push("gateway HTTP Date observation is missing".to_owned());
            }
        }
        if self.downstream_protocol == RawProtocol::H2 {
            if !self.h2_settings_seen || !self.h2_settings_ack_seen {
                violations.push("downstream H2 SETTINGS/ACK proof is missing".to_owned());
            }
            if metadata.cell.workload == Workload::WebSocket && !self.enable_connect_seen {
                violations.push("ENABLE_CONNECT_PROTOCOL proof is missing".to_owned());
            }
        }
        if self.upstream_protocol == RawProtocol::H2 {
            if !self.upstream_h2_settings_seen || !self.upstream_h2_settings_ack_seen {
                violations.push("upstream H2 SETTINGS/ACK proof is missing".to_owned());
            }
            if metadata.cell.workload == Workload::WebSocket && !self.upstream_enable_connect_seen {
                violations.push("upstream ENABLE_CONNECT_PROTOCOL proof is missing".to_owned());
            }
        }
        violations
    }
}

pub fn stream_sequence_sha256(count: u64) -> Result<String> {
    crate::wire::request_stream_sequence_sha256(count)
}

fn stream_sequence_matches(
    count: u64,
    first: Option<u32>,
    last: Option<u32>,
    hash: &str,
) -> Result<bool> {
    let expected_last = if count == 0 {
        None
    } else {
        Some(
            count
                .checked_mul(2)
                .and_then(|value| value.checked_sub(1))
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| Error::new("H2 stream last identity exceeds u32"))?,
        )
    };
    Ok(first == (count > 0).then_some(1)
        && last == expected_last
        && hash == stream_sequence_sha256(count)?)
}

impl EndpointPhaseEvidence {
    fn deadline_count_is_impossible(&self) -> bool {
        self.responses > self.requests
            || self.response_eos > self.responses
            || self.transport_eof > self.response_eos
            || self.connect_successes > self.connect_attempts
            || self.connect_attempts > self.socket_creations
            || self.socket_creations > self.planned_connections
            || self.requests > self.started_operations
            || self.close_tokens > self.responses
            || self.attempt_successes > self.attempt_starts
            || self.failed_attempts > self.attempt_starts
            || self.attempt_successes.saturating_add(self.failed_attempts) > self.attempt_starts
            || self.keep_alive_tokens > self.responses
            || self.h2_streams > self.started_operations
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSummaryEvidence {
    pub schema: String,
    pub window_start_ns: u64,
    pub deadline_ns: u64,
    pub drain_end_ns: u64,
    pub started_operations: u64,
    pub deadline_completions: u64,
    pub drained_operations: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub first_operation_id: String,
    pub last_operation_id: String,
    pub operation_hash_sha256: String,
    pub exact_status: bool,
    pub exact_version: bool,
    pub exact_payload: bool,
    pub exact_eos: bool,
    pub sse_content_type: bool,
    pub hidden_retry_count: u64,
    pub lane_quotas: Vec<u64>,
    pub lane_starts: Vec<u64>,
    pub lane_completions: Vec<u64>,
}

impl OperationSummaryEvidence {
    pub fn validate(&self, metadata: &RawArmMetadata) -> Result<()> {
        if self.schema != "amg-http2-perf/operation-summary/v1"
            || self.window_start_ns >= self.deadline_ns
            || self.deadline_ns > self.drain_end_ns
            || self.started_operations != metadata.started_operations
            || self.deadline_completions != metadata.deadline_completions
            || self.drained_operations != metadata.drained_operations
            || self.drained_operations != self.started_operations
            || self.deadline_completions > self.started_operations
            || self.first_operation_id.is_empty()
            || self.last_operation_id.is_empty()
            || is_placeholder(&self.first_operation_id)
            || is_placeholder(&self.last_operation_id)
            || self.hidden_retry_count != 0
            || self.lane_quotas.len() != usize::from(metadata.cell.concurrency)
            || self.lane_starts.len() != self.lane_quotas.len()
            || self.lane_completions.len() != self.lane_quotas.len()
        {
            return Err(Error::new("invalid raw operation boundaries/counts"));
        }
        validate_sha256("operation hash", &self.operation_hash_sha256)?;
        if placeholder_hash(&self.operation_hash_sha256) {
            return Err(Error::new("operation summary contains a placeholder hash"));
        }
        let quota_total = self
            .lane_quotas
            .iter()
            .try_fold(0_u64, |total, value| total.checked_add(*value));
        let start_total = self
            .lane_starts
            .iter()
            .try_fold(0_u64, |total, value| total.checked_add(*value));
        let completion_total = self
            .lane_completions
            .iter()
            .try_fold(0_u64, |total, value| total.checked_add(*value));
        if quota_total != Some(self.started_operations)
            || start_total != Some(self.started_operations)
            || completion_total != Some(self.drained_operations)
            || self
                .lane_starts
                .iter()
                .zip(&self.lane_completions)
                .any(|(started, completed)| completed > started)
        {
            return Err(Error::new(
                "per-lane quota/start/completion ledger is incomplete",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn semantic_violations(&self, workload: Workload) -> Vec<String> {
        let mut violations = Vec::new();
        for (exact, detail) in [
            (self.exact_status, "status"),
            (self.exact_version, "HTTP version"),
            (self.exact_payload, "payload"),
            (self.exact_eos, "response EOS"),
        ] {
            if !exact {
                violations.push(format!("operation {detail} is not exact"));
            }
        }
        if workload == Workload::Sse && !self.sse_content_type {
            violations.push("SSE content type is not exact".to_owned());
        }
        violations
    }
}

#[derive(Debug, Clone)]
pub struct ParsedArm {
    pub leaf: PathBuf,
    pub metadata: RawArmMetadata,
    pub quiet: QuietEvidence,
    pub thread_map: ThreadMapEvidence,
    pub lifecycle: ThreadLifecycleEvidence,
    pub session_clock: SessionClockEvidence,
    pub resources: ResourceEvidence,
    pub endpoints: EndpointEvidence,
    pub operation: OperationSummaryEvidence,
    pub materialization: Option<crate::materialization::MaterializationEvidence>,
    pub latencies_ns: Vec<u64>,
    pub raw_sha256: String,
}

impl ParsedArm {
    pub fn metrics(&self) -> Result<ArmMetrics> {
        if !self.metadata.class.has_latencies() {
            return Err(Error::new(
                "S/D evidence cannot produce authoritative metrics",
            ));
        }
        let elapsed_ns = self
            .operation
            .deadline_ns
            .checked_sub(self.operation.window_start_ns)
            .ok_or_else(|| Error::new("operation elapsed time underflow"))?;
        if elapsed_ns == 0 || self.operation.deadline_completions == 0 {
            return Err(Error::new("zero authoritative throughput denominator"));
        }
        let ticks = self
            .resources
            .gateway_ticks_drain
            .checked_sub(self.resources.gateway_ticks_start)
            .ok_or_else(|| Error::new("gateway tick underflow"))?;
        Ok(ArmMetrics {
            throughput_ops_per_second: self.operation.deadline_completions as f64
                * 1_000_000_000_f64
                / elapsed_ns as f64,
            p99_latency_ns: crate::statistics::nearest_rank_p99(&self.latencies_ns)?,
            cpu_seconds_per_operation: ticks as f64
                / 100_f64
                / self.operation.drained_operations as f64,
            peak_rss_kib: self.resources.vm_hwm_kib,
        })
    }

    #[must_use]
    pub fn semantic_violations(&self) -> Vec<String> {
        let mut violations = self
            .operation
            .semantic_violations(self.metadata.cell.workload);
        violations.extend(
            self.endpoints
                .semantic_violations(&self.metadata, &self.operation),
        );
        violations
    }

    #[must_use]
    pub fn semantic_class(&self) -> SemanticClass {
        if self.semantic_violations().is_empty() {
            return SemanticClass::Ok;
        }
        if self.metadata.class == EvidenceClass::D {
            SemanticClass::IntegrityFailure
        } else if self.metadata.arm == Some(Arm::B11) {
            SemanticClass::BaselineFailure
        } else {
            SemanticClass::CandidateFailure
        }
    }

    #[must_use]
    pub fn quality_clean(&self) -> bool {
        self.quiet.clean()
            && self.resources.clean()
            && self.session_clock.comparable
            && self.semantic_class() == SemanticClass::Ok
            && self.measurement_violations().is_empty()
    }

    #[must_use]
    pub fn measurement_violations(&self) -> Vec<String> {
        operation_quality_violations(
            self.metadata.class,
            self.operation.deadline_completions,
            self.operation.drained_operations,
            self.resources
                .gateway_ticks_drain
                .checked_sub(self.resources.gateway_ticks_start),
        )
    }
}

fn operation_quality_violations(
    class: EvidenceClass,
    deadline_completions: u64,
    drained_operations: u64,
    gateway_ticks: Option<u64>,
) -> Vec<String> {
    let mut violations = Vec::new();
    if deadline_completions == 0 {
        violations.push("arm has zero deadline completions".to_owned());
    }
    if matches!(
        class,
        EvidenceClass::C | EvidenceClass::D | EvidenceClass::A
    ) && (deadline_completions < 5_000 || drained_operations < 5_000)
    {
        violations.push("fixed-duration arm misses the 5,000-operation floor".to_owned());
    }
    if class != EvidenceClass::D {
        match gateway_ticks {
            Some(ticks) if ticks >= 500 => {}
            _ => violations.push("gateway arm misses the 500-tick CPU floor".to_owned()),
        }
    }
    violations
}

fn expected_protocols(metadata: &RawArmMetadata) -> Option<(RawProtocol, RawProtocol)> {
    if metadata.class == EvidenceClass::D {
        return metadata
            .direct_protocol
            .map(|protocol| (protocol, protocol));
    }
    metadata.arm.map(|arm| match arm {
        Arm::B11 | Arm::C11 => (RawProtocol::H1, RawProtocol::H1),
        Arm::C21 => (RawProtocol::H2, RawProtocol::H1),
        Arm::C12 => (RawProtocol::H1, RawProtocol::H2),
        Arm::C22 => (RawProtocol::H2, RawProtocol::H2),
    })
}

pub fn encode_latencies(class: EvidenceClass, latencies_ns: &[u64]) -> Result<Vec<u8>> {
    if !class.has_latencies() {
        return Err(Error::new("S/D evidence forbids a latency payload"));
    }
    if latencies_ns.is_empty() || latencies_ns.contains(&0) {
        return Err(Error::new("C/A latency payload records must be nonzero"));
    }
    let count = u64::try_from(latencies_ns.len())
        .map_err(|_| Error::new("latency count does not fit u64"))?;
    let payload_len = latencies_ns
        .len()
        .checked_mul(8)
        .ok_or_else(|| Error::new("latency payload length overflow"))?;
    let payload_len_u32 =
        u32::try_from(payload_len).map_err(|_| Error::new("latency payload exceeds u32"))?;
    let total_len = LATENCY_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| Error::new("latency file length overflow"))?;
    if u64::try_from(total_len).unwrap_or(u64::MAX) > TASK_CAP_BYTES {
        return Err(Error::new(
            "latency file exceeds the raw preallocation limit",
        ));
    }
    let mut output = Vec::with_capacity(total_len);
    output.extend_from_slice(LATENCY_MAGIC);
    output.extend_from_slice(&LATENCY_SCHEMA.to_le_bytes());
    output.push(class.byte());
    output.push(LATENCY_ENDIAN_LE);
    output.extend_from_slice(&LATENCY_RECORD_WIDTH.to_le_bytes());
    output.extend_from_slice(&count.to_le_bytes());
    output.extend_from_slice(&payload_len_u32.to_le_bytes());
    output.extend_from_slice(&[0_u8; 4]);
    for latency in latencies_ns {
        output.extend_from_slice(&latency.to_le_bytes());
    }
    let crc = crc32(&output[LATENCY_HEADER_BYTES..]);
    output[28..32].copy_from_slice(&crc.to_le_bytes());
    Ok(output)
}

pub fn decode_latencies(
    bytes: &[u8],
    expected_class: EvidenceClass,
    expected_count: u64,
    ceiling: u64,
) -> Result<Vec<u64>> {
    if !expected_class.has_latencies() {
        return Err(Error::new("S/D evidence may not decode a latency member"));
    }
    if bytes.len() < LATENCY_HEADER_BYTES || &bytes[..8] != LATENCY_MAGIC {
        return Err(Error::new(
            "latency header is truncated or has the wrong magic",
        ));
    }
    let schema = u16::from_le_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| Error::new("latency schema field is truncated"))?,
    );
    let class = EvidenceClass::from_byte(bytes[10])?;
    let endian = bytes[11];
    let width = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| Error::new("latency width field is truncated"))?,
    );
    let count = u64::from_le_bytes(
        bytes[16..24]
            .try_into()
            .map_err(|_| Error::new("latency count field is truncated"))?,
    );
    let payload_len = u32::from_le_bytes(
        bytes[24..28]
            .try_into()
            .map_err(|_| Error::new("latency length field is truncated"))?,
    );
    let expected_crc = u32::from_le_bytes(
        bytes[28..32]
            .try_into()
            .map_err(|_| Error::new("latency CRC field is truncated"))?,
    );
    if schema != LATENCY_SCHEMA
        || class != expected_class
        || endian != LATENCY_ENDIAN_LE
        || width != LATENCY_RECORD_WIDTH
    {
        return Err(Error::new("latency schema/class/endian/width mismatch"));
    }
    if count != expected_count || count > ceiling {
        return Err(Error::new(
            "latency record count mismatch or ceiling overflow",
        ));
    }
    let expected_payload = count
        .checked_mul(u64::from(LATENCY_RECORD_WIDTH))
        .ok_or_else(|| Error::new("latency payload calculation overflow"))?;
    if u64::from(payload_len) != expected_payload
        || bytes.len()
            != LATENCY_HEADER_BYTES
                .checked_add(
                    usize::try_from(payload_len)
                        .map_err(|_| Error::new("latency payload length does not fit usize"))?,
                )
                .ok_or_else(|| Error::new("latency total length overflow"))?
    {
        return Err(Error::new("latency payload length/count mismatch"));
    }
    if crc32(&bytes[LATENCY_HEADER_BYTES..]) != expected_crc {
        return Err(Error::new("latency payload CRC mismatch"));
    }
    let mut latencies = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for record in bytes[LATENCY_HEADER_BYTES..].chunks_exact(8) {
        let latency = u64::from_le_bytes(
            record
                .try_into()
                .map_err(|_| Error::new("truncated latency record"))?,
        );
        if latency == 0 {
            return Err(Error::new("zero latency record is invalid"));
        }
        latencies.push(latency);
    }
    Ok(latencies)
}

pub fn write_latencies_new(path: &Path, class: EvidenceClass, latencies_ns: &[u64]) -> Result<()> {
    let bytes = encode_latencies(class, latencies_ns)?;
    json::write_new_bytes(path, &bytes)
}

fn encode_record<T: Serialize>(
    kind: RecordKind,
    class: EvidenceClass,
    value: &T,
) -> Result<Vec<u8>> {
    let payload = json::canonical_bytes(value)?;
    if u64::try_from(payload.len()).unwrap_or(u64::MAX)
        > TASK_CAP_BYTES - RECORD_HEADER_BYTES as u64
    {
        return Err(Error::new(
            "raw record payload exceeds its preallocation limit",
        ));
    }
    encode_record_payload(kind, class, &payload)
}

fn encode_record_payload(
    kind: RecordKind,
    class: EvidenceClass,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let payload_len = u64::try_from(payload.len())
        .map_err(|_| Error::new("raw record payload length overflow"))?;
    let mut output = Vec::with_capacity(
        RECORD_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or_else(|| Error::new("raw record total length overflow"))?,
    );
    output.extend_from_slice(RECORD_MAGIC);
    output.extend_from_slice(&RECORD_SCHEMA.to_le_bytes());
    output.push(kind as u8);
    output.push(class.byte());
    output.extend_from_slice(&payload_len.to_le_bytes());
    output.extend_from_slice(&crc32(payload).to_le_bytes());
    output.extend_from_slice(&[0_u8; 8]);
    output.extend_from_slice(payload);
    Ok(output)
}

fn decode_record<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    expected_kind: RecordKind,
    expected_class: EvidenceClass,
) -> Result<T> {
    if bytes.len() < RECORD_HEADER_BYTES || &bytes[..8] != RECORD_MAGIC {
        return Err(Error::new("raw record has a truncated or wrong header"));
    }
    let schema = u16::from_le_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| Error::new("raw record schema is truncated"))?,
    );
    let kind = RecordKind::from_byte(bytes[10])?;
    let class = EvidenceClass::from_byte(bytes[11])?;
    let payload_len = u64::from_le_bytes(
        bytes[12..20]
            .try_into()
            .map_err(|_| Error::new("raw record length is truncated"))?,
    );
    let expected_crc = u32::from_le_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| Error::new("raw record CRC is truncated"))?,
    );
    if schema != RECORD_SCHEMA
        || kind != expected_kind
        || class != expected_class
        || bytes[24..32] != [0_u8; 8]
    {
        return Err(Error::new("raw record schema/kind/class/reserved mismatch"));
    }
    let expected_len = RECORD_HEADER_BYTES
        .checked_add(
            usize::try_from(payload_len)
                .map_err(|_| Error::new("raw record payload does not fit usize"))?,
        )
        .ok_or_else(|| Error::new("raw record total length overflow"))?;
    if bytes.len() != expected_len || crc32(&bytes[RECORD_HEADER_BYTES..]) != expected_crc {
        return Err(Error::new("raw record length or CRC mismatch"));
    }
    json::require_canonical(&bytes[RECORD_HEADER_BYTES..])
}

pub fn write_record_new<T: Serialize>(
    path: &Path,
    class: EvidenceClass,
    member: &str,
    value: &T,
) -> Result<()> {
    let kind = member_kind(member)?;
    let bytes = if kind == RecordKind::OperationSummary {
        let canonical = json::canonical_bytes(value)?;
        let operation: OperationSummaryEvidence = json::require_canonical(&canonical)?;
        encode_record_payload(kind, class, &encode_operation_summary(&operation)?)?
    } else {
        encode_record(kind, class, value)?
    };
    crate::json::write_new_bytes(path, &bytes)
}

fn member_kind(member: &str) -> Result<RecordKind> {
    match member {
        "thread-lifecycle.bin" => Ok(RecordKind::ThreadLifecycle),
        "session-clock.bin" => Ok(RecordKind::SessionClock),
        "resources.bin" => Ok(RecordKind::Resources),
        "endpoints.bin" => Ok(RecordKind::Endpoints),
        "operation-summary.bin" => Ok(RecordKind::OperationSummary),
        _ => Err(Error::new(format!("unknown raw binary member `{member}`"))),
    }
}

#[derive(Debug, Default)]
pub struct EvidenceTreeInspection {
    pub arms: Vec<ParsedArm>,
    pub blockers: Vec<String>,
}

pub fn validate_evidence_tree(root: &Path) -> Result<Vec<ParsedArm>> {
    let inspection = inspect_evidence_tree(root)?;
    if inspection.blockers.is_empty() && !inspection.arms.is_empty() {
        Ok(inspection.arms)
    } else if inspection.arms.is_empty() && inspection.blockers.is_empty() {
        Err(Error::new("evidence closure contains zero raw arms"))
    } else {
        Err(Error::new(inspection.blockers.join("; ")))
    }
}

/// Validates one raw arm independently while binding a temporary leaf to its
/// eventual class-specific path.
pub fn validate_evidence_leaf(leaf: &Path, expected_relative: &Path) -> Result<ParsedArm> {
    let metadata: RawArmMetadata =
        json::require_canonical(&read_bounded(&leaf.join("metadata.json"), 65_536)?)?;
    metadata.validate()?;
    validate_raw_path(expected_relative, &metadata)?;
    validate_arm_leaf(leaf, metadata)
}

pub fn inspect_evidence_tree(root: &Path) -> Result<EvidenceTreeInspection> {
    let mut files = Vec::new();
    collect_regular_files(root, root, &mut files)?;
    let mut leaves = BTreeSet::new();
    for relative in files {
        let first = relative.components().next();
        if matches!(first, Some(component) if component.as_os_str() == "arms" || component.as_os_str() == "direct" || component.as_os_str() == "scouts")
        {
            let leaf = relative
                .parent()
                .ok_or_else(|| Error::new("raw member path has no leaf"))?;
            leaves.insert(root.join(leaf));
        }
    }

    let mut inspection = EvidenceTreeInspection::default();
    for leaf in leaves {
        let relative = leaf
            .strip_prefix(root)
            .map_err(|_| Error::new("raw leaf escaped evidence root"))?;
        let parsed = validate_evidence_leaf(&leaf, relative);
        match parsed {
            Ok(arm) => inspection.arms.push(arm),
            Err(error) => inspection.blockers.push(format!(
                "raw leaf `{}` is invalid: {error}",
                relative.display()
            )),
        }
    }
    inspection.arms.sort_by_key(|arm| arm.metadata.ordinal);
    let mut observations = BTreeSet::new();
    let mut ordinals = BTreeSet::new();
    let identity = inspection.arms.first().map(|arm| {
        (
            arm.metadata.evidence_id.clone(),
            arm.metadata.run_id.clone(),
        )
    });
    for arm in &inspection.arms {
        if identity.as_ref()
            != Some(&(
                arm.metadata.evidence_id.clone(),
                arm.metadata.run_id.clone(),
            ))
        {
            inspection
                .blockers
                .push("raw arms mix evidence/run identities".to_owned());
        }
        if !observations.insert(arm.metadata.observation_id.clone()) {
            inspection.blockers.push(format!(
                "duplicate raw observation `{}`",
                arm.metadata.observation_id
            ));
        }
        if !ordinals.insert(arm.metadata.ordinal) {
            inspection
                .blockers
                .push(format!("duplicate raw ordinal {}", arm.metadata.ordinal));
        }
    }
    for (expected, arm) in inspection.arms.iter().enumerate() {
        if arm.metadata.ordinal != u64::try_from(expected).unwrap_or(u64::MAX) {
            inspection
                .blockers
                .push("raw ordinals are not contiguous from zero".to_owned());
            break;
        }
    }
    inspection.blockers.sort();
    inspection.blockers.dedup();
    Ok(inspection)
}

fn collect_regular_files(root: &Path, directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir() {
        return Err(Error::new(format!(
            "evidence root is not a directory: {}",
            directory.display()
        )));
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::new(format!(
                "evidence link is forbidden: {}",
                path.display()
            )));
        }
        if metadata.file_type().is_dir() {
            collect_regular_files(root, &path, output)?;
        } else if metadata.file_type().is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(Error::new(format!(
                        "raw hard link is forbidden: {}",
                        path.display()
                    )));
                }
            }
            output.push(
                path.strip_prefix(root)
                    .map_err(|_| Error::new("raw traversal escaped evidence root"))?
                    .to_path_buf(),
            );
        } else {
            return Err(Error::new(format!(
                "non-regular evidence member is forbidden: {}",
                path.display()
            )));
        }
    }
    output.sort();
    Ok(())
}

fn validate_raw_path(path: &Path, metadata: &RawArmMetadata) -> Result<()> {
    let parts = path
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .ok_or_else(|| Error::new("raw path component is not UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    if parts.len() != 4 {
        return Err(Error::new(
            "raw leaf path must contain exactly four components",
        ));
    }
    let arm = metadata.arm.map(Arm::code);
    let protocol = metadata.direct_protocol.map(|value| match value {
        RawProtocol::H1 => "h1",
        RawProtocol::H2 => "h2",
    });
    let expected = match metadata.class {
        EvidenceClass::S => (
            "scouts",
            metadata.cell.id(),
            metadata.scout_target.unwrap_or_default().to_string(),
            arm.unwrap_or_default().to_owned(),
        ),
        EvidenceClass::C => (
            "arms",
            metadata.row.unwrap_or(u8::MAX).to_string(),
            metadata.cell.id(),
            arm.unwrap_or_default().to_owned(),
        ),
        EvidenceClass::D => (
            "direct",
            metadata.epoch.unwrap_or(u32::MAX).to_string(),
            metadata.cell.id(),
            protocol.unwrap_or_default().to_owned(),
        ),
        EvidenceClass::A => (
            "arms",
            metadata.round.unwrap_or(u32::MAX).to_string(),
            metadata.cell.id(),
            arm.unwrap_or_default().to_owned(),
        ),
    };
    if parts != [expected.0, &expected.1, &expected.2, &expected.3] {
        return Err(Error::new(format!(
            "raw path does not bind its class/domain metadata: expected {}/{}/{}/{}",
            expected.0, expected.1, expected.2, expected.3
        )));
    }
    Ok(())
}

fn validate_arm_leaf(leaf: &Path, metadata: RawArmMetadata) -> Result<ParsedArm> {
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(leaf)? {
        let entry = entry?;
        let path = entry.path();
        let file_metadata = fs::symlink_metadata(&path)?;
        if !file_metadata.file_type().is_file() {
            return Err(Error::new(format!(
                "arm leaf contains a non-regular member: {}",
                path.display()
            )));
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| Error::new("arm member name is not UTF-8"))?
            .to_owned();
        if !actual.insert(name) {
            return Err(Error::new("duplicate arm member name"));
        }
    }
    let mut expected: BTreeSet<String> = COMMON_ARM_MEMBERS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    if metadata.class.has_latencies() {
        expected.insert("latencies.u64le".to_owned());
    }
    if metadata.materialization_sha256.is_some() {
        expected.insert("materialization.json".to_owned());
    }
    if actual != expected {
        return Err(Error::new(format!(
            "arm member set differs from class {:?}: expected {expected:?}, got {actual:?}",
            metadata.class
        )));
    }
    let latencies_ns = if metadata.class.has_latencies() {
        let bytes = read_bounded(&leaf.join("latencies.u64le"), TASK_CAP_BYTES)?;
        decode_latencies(
            &bytes,
            metadata.class,
            metadata.drained_operations,
            metadata.latency_record_ceiling,
        )?
    } else {
        Vec::new()
    };
    let quiet: QuietEvidence = read_canonical_member(leaf, "quiet.json", 131_072)?;
    quiet.validate()?;
    let thread_map: ThreadMapEvidence = read_canonical_member(leaf, "thread-map.json", 131_072)?;
    thread_map.validate()?;
    let lifecycle: ThreadLifecycleEvidence = decode_binary_member(
        leaf,
        "thread-lifecycle.bin",
        RecordKind::ThreadLifecycle,
        metadata.class,
        TASK_CAP_BYTES,
    )?;
    lifecycle.validate(metadata.cell.workload)?;
    let session_clock: SessionClockEvidence = decode_binary_member(
        leaf,
        "session-clock.bin",
        RecordKind::SessionClock,
        metadata.class,
        TASK_CAP_BYTES,
    )?;
    session_clock.validate()?;
    if session_clock.direct != (metadata.class == EvidenceClass::D) {
        return Err(Error::new("session clock direct/gateway class mismatch"));
    }
    let resources: ResourceEvidence = decode_binary_member(
        leaf,
        "resources.bin",
        RecordKind::Resources,
        metadata.class,
        TASK_CAP_BYTES,
    )?;
    resources.validate(metadata.class)?;
    let operation_bound = 256_u64
        .checked_add(96_u64 * u64::from(metadata.cell.concurrency))
        .ok_or_else(|| Error::new("operation summary byte cap overflow"))?;
    let operation = decode_operation_summary(
        &read_bounded(&leaf.join("operation-summary.bin"), operation_bound)?,
        metadata.class,
    )?;
    operation.validate(&metadata)?;
    let endpoints: EndpointEvidence = decode_binary_member(
        leaf,
        "endpoints.bin",
        RecordKind::Endpoints,
        metadata.class,
        endpoint_member_bound(metadata.cell.concurrency)?,
    )?;
    endpoints.validate(&metadata, &operation)?;
    let materialization = metadata
        .materialization_sha256
        .as_ref()
        .map(|expected_hash| {
            let bytes = read_bounded(&leaf.join("materialization.json"), 1_048_576)?;
            if crate::seal::sha256_hex(&bytes) != *expected_hash {
                return Err(Error::new(
                    "materialization member hash differs from raw metadata",
                ));
            }
            let evidence: crate::materialization::MaterializationEvidence =
                json::require_canonical(&bytes)?;
            evidence.validate()?;
            if evidence.cell != metadata.cell {
                return Err(Error::new(
                    "materialization cell differs from raw arm metadata",
                ));
            }
            Ok(evidence)
        })
        .transpose()?;

    let mut hasher = Sha256::new();
    for member in &actual {
        let bytes = fs::read(leaf.join(member))?;
        hasher.update((member.len() as u64).to_be_bytes());
        hasher.update(member.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(Sha256::digest(&bytes));
    }
    let parsed = ParsedArm {
        leaf: leaf.to_path_buf(),
        metadata,
        quiet,
        thread_map,
        lifecycle,
        session_clock,
        resources,
        endpoints,
        operation,
        materialization,
        latencies_ns,
        raw_sha256: format!("{:x}", hasher.finalize()),
    };
    validate_derived_arm_invariants(&parsed)?;
    Ok(parsed)
}

fn read_canonical_member<T: DeserializeOwned + Serialize>(
    leaf: &Path,
    name: &str,
    maximum_bytes: u64,
) -> Result<T> {
    let bytes = read_bounded(&leaf.join(name), maximum_bytes)?;
    json::require_canonical(&bytes)
}

fn decode_binary_member<T: DeserializeOwned + Serialize>(
    leaf: &Path,
    name: &str,
    kind: RecordKind,
    class: EvidenceClass,
    maximum_bytes: u64,
) -> Result<T> {
    decode_record(&read_bounded(&leaf.join(name), maximum_bytes)?, kind, class)
}

fn read_bounded(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum_bytes {
        return Err(Error::new(format!(
            "raw member is not a bounded regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(Error::new(format!(
                "raw member is a hard link: {}",
                path.display()
            )));
        }
    }
    let bytes = fs::read(path)?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(Error::new(format!(
            "raw member changed length while reading: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn endpoint_member_bound(concurrency: u16) -> Result<u64> {
    let concurrency = u64::from(concurrency);
    let conn_live = 136_u64
        .checked_add(concurrency)
        .ok_or_else(|| Error::new("endpoint CONN_LIVE bound overflow"))?;
    512_u64
        .checked_add(
            160_u64
                .checked_mul(conn_live)
                .ok_or_else(|| Error::new("endpoint slot bound overflow"))?,
        )
        .and_then(|value| value.checked_add(512_u64.checked_mul(concurrency)?))
        .ok_or_else(|| Error::new("endpoint member bound overflow"))
}

fn validate_derived_arm_invariants(arm: &ParsedArm) -> Result<()> {
    if let Some(materialization) = &arm.materialization {
        let measured_phases = [
            crate::topology::parse_operation_id(&arm.operation.first_operation_id)?,
            crate::topology::parse_operation_id(&arm.operation.last_operation_id)?,
        ]
        .map(|operation| (operation >> 112) as u16);
        if measured_phases != [3, 3]
            || materialization.operation_root_sha256 == arm.operation.operation_hash_sha256
            || materialization
                .waves
                .iter()
                .any(|wave| !wave.result.latencies_ns.is_empty() || wave.phase == 3)
        {
            return Err(Error::new(
                "materialization IDs/latencies are not separated from measured evidence",
            ));
        }
    }
    if arm.metadata.class == EvidenceClass::S {
        let target = arm
            .metadata
            .scout_target
            .ok_or_else(|| Error::new("scout target is missing"))?;
        if arm.operation.started_operations != target
            || arm.operation.deadline_completions != target
            || arm.operation.drained_operations != target
        {
            return Err(Error::new(
                "scout target and exact count-window totals differ",
            ));
        }
    }
    validate_workload_bytes(arm)
}

fn validate_workload_bytes(arm: &ParsedArm) -> Result<()> {
    let operations = arm.operation.drained_operations;
    let expected_request = match arm.metadata.cell.workload {
        Workload::Upload1Mib => Some(
            operations
                .checked_mul(1_048_576)
                .ok_or_else(|| Error::new("upload request-byte total overflow"))?,
        ),
        Workload::WebSocket => Some(
            operations
                .checked_mul(8)
                .ok_or_else(|| Error::new("WebSocket request-byte total overflow"))?,
        ),
        Workload::Get | Workload::Download1Mib | Workload::Sse => Some(0),
    };
    let expected_response = match arm.metadata.cell.workload {
        Workload::Get => Some(
            operations
                .checked_mul(64)
                .ok_or_else(|| Error::new("GET response-byte total overflow"))?,
        ),
        Workload::Download1Mib => Some(
            operations
                .checked_mul(1_048_576)
                .ok_or_else(|| Error::new("download response-byte total overflow"))?,
        ),
        Workload::WebSocket => Some(
            operations
                .checked_mul(8)
                .ok_or_else(|| Error::new("WebSocket response-byte total overflow"))?,
        ),
        Workload::Upload1Mib | Workload::Sse => None,
    };
    if expected_request != Some(arm.operation.request_bytes)
        || expected_response.is_some_and(|expected| expected != arm.operation.response_bytes)
    {
        return Err(Error::new(
            "raw application-byte totals differ from the exact workload",
        ));
    }
    Ok(())
}

fn encode_operation_summary(value: &OperationSummaryEvidence) -> Result<Vec<u8>> {
    let first = value.first_operation_id.as_bytes();
    let last = value.last_operation_id.as_bytes();
    if first.is_empty()
        || last.is_empty()
        || first.len() > 32
        || last.len() > 32
        || value.lane_quotas.is_empty()
        || value.lane_quotas.len() > 64
        || value.lane_starts.len() != value.lane_quotas.len()
        || value.lane_completions.len() != value.lane_quotas.len()
    {
        return Err(Error::new(
            "operation IDs or lane ledgers do not fit the fixed operation-summary record",
        ));
    }
    validate_sha256("operation hash", &value.operation_hash_sha256)?;
    let lane_bytes = value
        .lane_quotas
        .len()
        .checked_mul(OPERATION_LANE_RECORD_BYTES)
        .ok_or_else(|| Error::new("operation-summary lane bytes overflow"))?;
    let mut output = vec![
        0_u8;
        OPERATION_BASE_PAYLOAD_BYTES
            .checked_add(lane_bytes)
            .ok_or_else(|| Error::new("operation-summary payload overflow"))?
    ];
    for (index, number) in [
        value.window_start_ns,
        value.deadline_ns,
        value.drain_end_ns,
        value.started_operations,
        value.deadline_completions,
        value.drained_operations,
        value.request_bytes,
        value.response_bytes,
        value.hidden_retry_count,
    ]
    .into_iter()
    .enumerate()
    {
        let start = index * 8;
        output[start..start + 8].copy_from_slice(&number.to_le_bytes());
    }
    output[72] = u8::from(value.exact_status)
        | (u8::from(value.exact_version) << 1)
        | (u8::from(value.exact_payload) << 2)
        | (u8::from(value.exact_eos) << 3)
        | (u8::from(value.sse_content_type) << 4);
    output[73..75].copy_from_slice(
        &u16::try_from(first.len())
            .map_err(|_| Error::new("first operation ID length exceeds u16"))?
            .to_le_bytes(),
    );
    output[75..77].copy_from_slice(
        &u16::try_from(last.len())
            .map_err(|_| Error::new("last operation ID length exceeds u16"))?
            .to_le_bytes(),
    );
    output[77..109].copy_from_slice(&decode_hash(&value.operation_hash_sha256)?);
    output[109..109 + first.len()].copy_from_slice(first);
    output[141..141 + last.len()].copy_from_slice(last);
    output[173..175].copy_from_slice(
        &u16::try_from(value.lane_quotas.len())
            .map_err(|_| Error::new("operation-summary lane count exceeds u16"))?
            .to_le_bytes(),
    );
    for (index, ((quota, started), completed)) in value
        .lane_quotas
        .iter()
        .zip(&value.lane_starts)
        .zip(&value.lane_completions)
        .enumerate()
    {
        let offset = OPERATION_BASE_PAYLOAD_BYTES + index * OPERATION_LANE_RECORD_BYTES;
        output[offset..offset + 8].copy_from_slice(&quota.to_le_bytes());
        output[offset + 8..offset + 16].copy_from_slice(&started.to_le_bytes());
        output[offset + 16..offset + 24].copy_from_slice(&completed.to_le_bytes());
    }
    Ok(output)
}

fn decode_operation_summary(
    bytes: &[u8],
    expected_class: EvidenceClass,
) -> Result<OperationSummaryEvidence> {
    let payload = decode_record_payload(bytes, RecordKind::OperationSummary, expected_class)?;
    if payload.len() < OPERATION_BASE_PAYLOAD_BYTES
        || payload[72] & !0x1f != 0
        || payload[175..OPERATION_BASE_PAYLOAD_BYTES]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(Error::new("operation-summary fixed payload is malformed"));
    }
    let first_len =
        usize::from(u16::from_le_bytes(payload[73..75].try_into().map_err(
            |_| Error::new("first operation ID length is truncated"),
        )?));
    let last_len = usize::from(u16::from_le_bytes(
        payload[75..77]
            .try_into()
            .map_err(|_| Error::new("last operation ID length is truncated"))?,
    ));
    let lane_count =
        usize::from(u16::from_le_bytes(payload[173..175].try_into().map_err(
            |_| Error::new("operation-summary lane count is truncated"),
        )?));
    let expected_payload_len = OPERATION_BASE_PAYLOAD_BYTES
        .checked_add(
            lane_count
                .checked_mul(OPERATION_LANE_RECORD_BYTES)
                .ok_or_else(|| Error::new("operation-summary lane payload overflow"))?,
        )
        .ok_or_else(|| Error::new("operation-summary payload length overflow"))?;
    if first_len == 0
        || first_len > 32
        || last_len == 0
        || last_len > 32
        || lane_count == 0
        || lane_count > 64
        || payload.len() != expected_payload_len
        || payload[109 + first_len..141].iter().any(|byte| *byte != 0)
        || payload[141 + last_len..173].iter().any(|byte| *byte != 0)
    {
        return Err(Error::new("operation-summary ID fields are malformed"));
    }
    let mut numbers = [0_u64; 9];
    for (index, number) in numbers.iter_mut().enumerate() {
        let start = index * 8;
        *number = u64::from_le_bytes(
            payload[start..start + 8]
                .try_into()
                .map_err(|_| Error::new("operation-summary number is truncated"))?,
        );
    }
    let first_operation_id = std::str::from_utf8(&payload[109..109 + first_len])
        .map_err(|_| Error::new("first operation ID is not UTF-8"))?
        .to_owned();
    let last_operation_id = std::str::from_utf8(&payload[141..141 + last_len])
        .map_err(|_| Error::new("last operation ID is not UTF-8"))?
        .to_owned();
    let mut lane_quotas = Vec::with_capacity(lane_count);
    let mut lane_starts = Vec::with_capacity(lane_count);
    let mut lane_completions = Vec::with_capacity(lane_count);
    for index in 0..lane_count {
        let offset = OPERATION_BASE_PAYLOAD_BYTES + index * OPERATION_LANE_RECORD_BYTES;
        lane_quotas.push(u64::from_le_bytes(
            payload[offset..offset + 8]
                .try_into()
                .map_err(|_| Error::new("operation-summary lane quota is truncated"))?,
        ));
        lane_starts.push(u64::from_le_bytes(
            payload[offset + 8..offset + 16]
                .try_into()
                .map_err(|_| Error::new("operation-summary lane start is truncated"))?,
        ));
        lane_completions.push(u64::from_le_bytes(
            payload[offset + 16..offset + 24]
                .try_into()
                .map_err(|_| Error::new("operation-summary lane completion is truncated"))?,
        ));
    }
    Ok(OperationSummaryEvidence {
        schema: "amg-http2-perf/operation-summary/v1".to_owned(),
        window_start_ns: numbers[0],
        deadline_ns: numbers[1],
        drain_end_ns: numbers[2],
        started_operations: numbers[3],
        deadline_completions: numbers[4],
        drained_operations: numbers[5],
        request_bytes: numbers[6],
        response_bytes: numbers[7],
        first_operation_id,
        last_operation_id,
        operation_hash_sha256: hex_lower(&payload[77..109]),
        exact_status: payload[72] & 1 != 0,
        exact_version: payload[72] & 2 != 0,
        exact_payload: payload[72] & 4 != 0,
        exact_eos: payload[72] & 8 != 0,
        sse_content_type: payload[72] & 16 != 0,
        hidden_retry_count: numbers[8],
        lane_quotas,
        lane_starts,
        lane_completions,
    })
}

fn decode_record_payload(
    bytes: &[u8],
    expected_kind: RecordKind,
    expected_class: EvidenceClass,
) -> Result<&[u8]> {
    if bytes.len() < RECORD_HEADER_BYTES || &bytes[..8] != RECORD_MAGIC {
        return Err(Error::new("raw record has a truncated or wrong header"));
    }
    let schema = u16::from_le_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| Error::new("raw record schema is truncated"))?,
    );
    let kind = RecordKind::from_byte(bytes[10])?;
    let class = EvidenceClass::from_byte(bytes[11])?;
    let payload_len = u64::from_le_bytes(
        bytes[12..20]
            .try_into()
            .map_err(|_| Error::new("raw record length is truncated"))?,
    );
    let expected_crc = u32::from_le_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| Error::new("raw record CRC is truncated"))?,
    );
    if schema != RECORD_SCHEMA
        || kind != expected_kind
        || class != expected_class
        || bytes[24..32] != [0_u8; 8]
    {
        return Err(Error::new("raw record schema/kind/class/reserved mismatch"));
    }
    let expected_len = RECORD_HEADER_BYTES
        .checked_add(
            usize::try_from(payload_len)
                .map_err(|_| Error::new("raw record payload does not fit usize"))?,
        )
        .ok_or_else(|| Error::new("raw record total length overflow"))?;
    if bytes.len() != expected_len || crc32(&bytes[RECORD_HEADER_BYTES..]) != expected_crc {
        return Err(Error::new("raw record length or CRC mismatch"));
    }
    Ok(&bytes[RECORD_HEADER_BYTES..])
}

fn decode_hash(value: &str) -> Result<[u8; 32]> {
    validate_sha256("raw hash", value)?;
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(Error::new("invalid lowercase hexadecimal digit")),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn validate_phase_counter_sums(phases: &[EndpointPhaseEvidence]) -> Result<()> {
    let counters: [fn(&EndpointPhaseEvidence) -> u64; 21] = [
        |phase: &EndpointPhaseEvidence| phase.started_operations,
        |phase: &EndpointPhaseEvidence| phase.attempt_starts,
        |phase: &EndpointPhaseEvidence| phase.attempt_successes,
        |phase: &EndpointPhaseEvidence| phase.planned_connections,
        |phase: &EndpointPhaseEvidence| phase.socket_creations,
        |phase: &EndpointPhaseEvidence| phase.connect_attempts,
        |phase: &EndpointPhaseEvidence| phase.connect_successes,
        |phase: &EndpointPhaseEvidence| phase.failed_attempts,
        |phase: &EndpointPhaseEvidence| phase.cumulative_connections,
        |phase: &EndpointPhaseEvidence| phase.requests,
        |phase: &EndpointPhaseEvidence| phase.responses,
        |phase: &EndpointPhaseEvidence| phase.request_bytes,
        |phase: &EndpointPhaseEvidence| phase.response_bytes,
        |phase: &EndpointPhaseEvidence| phase.close_tokens,
        |phase: &EndpointPhaseEvidence| phase.keep_alive_tokens,
        |phase: &EndpointPhaseEvidence| phase.response_eos,
        |phase: &EndpointPhaseEvidence| phase.transport_eof,
        |phase: &EndpointPhaseEvidence| phase.active_connections,
        |phase: &EndpointPhaseEvidence| phase.max_active_connections,
        |phase: &EndpointPhaseEvidence| phase.h2_streams,
        |phase: &EndpointPhaseEvidence| phase.max_active_h2_streams,
    ];
    for counter in counters {
        phases.iter().try_fold(0_u64, |total, phase| {
            total
                .checked_add(counter(phase))
                .ok_or_else(|| Error::new("endpoint cumulative counter overflow"))
        })?;
    }
    Ok(())
}

fn is_placeholder(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "unknown" | "placeholder" | "opaque" | "todo" | "n/a" | "null"
    )
}

fn placeholder_hash(value: &str) -> bool {
    value.len() == 64
        && (value.bytes().all(|byte| byte == b'0') || value.bytes().all(|byte| byte == b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_encoding_is_golden_little_endian_and_bounded() {
        let encoded = encode_latencies(EvidenceClass::A, &[1, 0x0102_0304_0506_0708])
            .expect("encode latencies");
        assert_eq!(&encoded[..8], LATENCY_MAGIC);
        assert_eq!(encoded[10], b'A');
        assert_eq!(&encoded[32..40], &1_u64.to_le_bytes());
        assert_eq!(&encoded[40..48], &0x0102_0304_0506_0708_u64.to_le_bytes());
        assert_eq!(
            decode_latencies(&encoded, EvidenceClass::A, 2, 2).expect("decode"),
            vec![1, 0x0102_0304_0506_0708]
        );
        assert!(decode_latencies(&encoded, EvidenceClass::A, 2, 1).is_err());
    }

    #[test]
    fn malformed_latency_header_count_endian_crc_and_class_are_rejected() {
        let valid = encode_latencies(EvidenceClass::C, &[10, 20]).expect("valid encoding");
        for index in [0_usize, 8, 10, 11, 12, 16, 24, 28, 32, valid.len() - 1] {
            let mut malformed = valid.clone();
            malformed[index] ^= 1;
            assert!(decode_latencies(&malformed, EvidenceClass::C, 2, 2).is_err());
        }
        assert!(decode_latencies(&valid[..valid.len() - 1], EvidenceClass::C, 2, 2).is_err());
        assert!(decode_latencies(&valid, EvidenceClass::A, 2, 2).is_err());
        assert!(decode_latencies(&valid, EvidenceClass::S, 2, 2).is_err());
    }

    #[test]
    fn scout_and_direct_latency_encoding_is_forbidden() {
        assert!(encode_latencies(EvidenceClass::S, &[1]).is_err());
        assert!(encode_latencies(EvidenceClass::D, &[1]).is_err());
        assert!(encode_latencies(EvidenceClass::C, &[]).is_err());
        assert!(encode_latencies(EvidenceClass::A, &[0]).is_err());
    }

    fn phase(phase: RawPhase, started: u64) -> EndpointPhaseEvidence {
        EndpointPhaseEvidence {
            phase,
            started_operations: started,
            attempt_starts: started,
            attempt_successes: started,
            planned_connections: started,
            socket_creations: started,
            connect_attempts: started,
            connect_successes: started,
            failed_attempts: 0,
            cumulative_connections: started,
            requests: started,
            responses: started,
            request_bytes: 0,
            response_bytes: 0,
            close_tokens: started,
            keep_alive_tokens: 0,
            response_eos: started,
            transport_eof: started,
            active_connections: 0,
            max_active_connections: 1,
            max_requests_per_connection: 1,
            h2_streams: 0,
            max_active_h2_streams: 0,
            first_h2_stream_id: None,
            last_h2_stream_id: None,
            h2_stream_sequence_sha256: stream_sequence_sha256(0).unwrap(),
            retries: 0,
            reconnects: 0,
            reuse_attempts: 0,
            operation_hash_sha256: crate::seal::sha256_hex(b"operation"),
            connection_hash_sha256: crate::seal::sha256_hex(b"connection"),
        }
    }

    #[test]
    fn cumulative_counter_overflow_is_rejected_before_any_derived_rate() {
        let phases = [
            phase(RawPhase::Proof, u64::MAX),
            phase(RawPhase::Warmup, 1),
            phase(RawPhase::Measured, 0),
            phase(RawPhase::Drain, 0),
        ];
        assert!(validate_phase_counter_sums(&phases).is_err());
    }

    #[test]
    fn thermal_frequency_and_direct_headroom_drift_contamination_fail_closed() {
        assert!(direct_headroom_drift_clean(
            Some(1_250),
            Some(1_000),
            Some(1_200)
        ));
        assert!(!direct_headroom_drift_clean(
            Some(1_249),
            Some(1_000),
            Some(1_200)
        ));
        assert!(!direct_headroom_drift_clean(
            Some(1_250),
            Some(1_000),
            Some(1_000)
        ));
        assert!(!direct_headroom_drift_clean(Some(1), None, Some(1)));

        let mut resource = ResourceEvidence {
            schema: "amg-http2-perf/resources/v1".to_owned(),
            gateway_ticks_start: 1,
            gateway_ticks_deadline: 2,
            gateway_ticks_drain: 3,
            vm_hwm_kib: 1,
            major_faults: 0,
            swap_in_delta: 0,
            swap_out_delta: 0,
            steal_ticks_delta: 0,
            memory_psi_full_us: 0,
            io_psi_full_us: 0,
            tctl_start_millidegrees: 75_000,
            tctl_max_millidegrees: 84_999,
            median_frequency_khz: 4_000_000,
            frequency_floor_khz: 4_000_000,
            buckets: vec![CpuBucketEvidence {
                cpu: 0,
                role: "gateway".to_owned(),
                start_ns: 1,
                end_ns: 2,
                process_runtime_lower: 0,
                process_runtime_upper: 0,
                tid_runtime_lower: 0,
                tid_runtime_upper: 0,
                capacity_ticks: 10_000,
                scheduled_ticks: 0,
                external_upper_ticks: 0,
                attribution_uncertainty_ticks: 0,
            }],
            utilization: vec![RoleUtilizationEvidence {
                role: "fixture".to_owned(),
                used_ticks: 0,
                capacity_ticks: 1,
            }],
            direct_ceiling_ops: None,
            gateway_ops: None,
            calibration_direct_ops: None,
            frozen_whole_buckets: Vec::new(),
            frozen_bracket_buckets: Vec::new(),
            dynamic_buckets: Vec::new(),
            residuals: Vec::new(),
            scope_decisions: Vec::new(),
            producer_blockers: Vec::new(),
            calibration_frequency_p05_khz: None,
        };
        assert!(resource.clean());
        resource.tctl_max_millidegrees = 85_000;
        assert!(!resource.clean());
        resource.tctl_max_millidegrees = 84_999;
        resource.median_frequency_khz = resource.frequency_floor_khz - 1;
        assert!(!resource.clean());
    }

    #[test]
    fn fixed_operation_summary_round_trips_inside_the_rfc_bound() {
        let operation = OperationSummaryEvidence {
            schema: "amg-http2-perf/operation-summary/v1".to_owned(),
            window_start_ns: 1,
            deadline_ns: 2,
            drain_end_ns: 3,
            started_operations: 5_000,
            deadline_completions: 5_000,
            drained_operations: 5_000,
            request_bytes: 0,
            response_bytes: 320_000,
            first_operation_id: "first-operation".to_owned(),
            last_operation_id: "last-operation".to_owned(),
            operation_hash_sha256: crate::seal::sha256_hex(b"operation-summary"),
            exact_status: true,
            exact_version: true,
            exact_payload: true,
            exact_eos: true,
            sse_content_type: false,
            hidden_retry_count: 0,
            lane_quotas: vec![5_000],
            lane_starts: vec![5_000],
            lane_completions: vec![5_000],
        };
        let bytes = encode_record_payload(
            RecordKind::OperationSummary,
            EvidenceClass::A,
            &encode_operation_summary(&operation).expect("fixed payload"),
        )
        .expect("record");
        assert_eq!(bytes.len(), 248);
        assert_eq!(
            decode_operation_summary(&bytes, EvidenceClass::A).expect("decode"),
            operation
        );
        let mut corrupted = bytes;
        corrupted[175 + RECORD_HEADER_BYTES] = 1;
        let payload_crc = crc32(&corrupted[RECORD_HEADER_BYTES..]);
        corrupted[20..24].copy_from_slice(&payload_crc.to_le_bytes());
        assert!(decode_operation_summary(&corrupted, EvidenceClass::A).is_err());
    }

    #[test]
    fn zero_counts_and_operation_or_tick_floors_are_never_pass_quality() {
        assert_eq!(
            operation_quality_violations(EvidenceClass::A, 0, 0, Some(0)).len(),
            3
        );
        assert!(
            operation_quality_violations(EvidenceClass::A, 4_999, 5_000, Some(500))
                .iter()
                .any(|value| value.contains("5,000"))
        );
        assert!(
            operation_quality_violations(EvidenceClass::A, 5_000, 5_000, Some(499))
                .iter()
                .any(|value| value.contains("500-tick"))
        );
        assert!(operation_quality_violations(EvidenceClass::D, 5_000, 5_000, None).is_empty());
    }
}
