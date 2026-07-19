//! Executable scout/calibration/direct/campaign process plans and lifecycle gates.

use crate::calibration::{
    phase_counts, project_runtime, CellDurations, FrozenDurations, PhaseCounts, RuntimeProjection,
    SCOUT_TARGETS,
};
use crate::control::{ConnectionPolicy, ControlBody, LoadTarget};
use crate::json;
use crate::rng::{fisher_yates, SplitMix64};
use crate::schedule::{generate_rounds, validate_williams_balance, williams_rows};
use crate::schema::{all_cells, Arm, Cell, EvidenceClass, RoundPlan, Workload};
use crate::seal::sha256_hex;
use crate::topology::{ArmTopology, Protocol};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

pub const PROCESS_PLAN_SCHEMA: &str = "amg-http2-perf/process-plan/v1";
pub const SMOKE_WARMUP_OPERATIONS: u64 = 1;
pub const WEBSOCKET_KEEPALIVE_NS: u64 = 10_000_000_000;
pub const WEBSOCKET_STABILITY_NS: u64 = 2_000_000_000;
pub const WEBSOCKET_SETTLE_CAP_NS: u64 = 15_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleStage {
    QuietObservation,
    SetupReadiness,
    ProtocolProof,
    Materialization,
    WarmupDrain,
    WebsocketRetirement,
    Freeze,
    Steady,
    MeasuredDrain,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleEvent {
    pub stage: LifecycleStage,
    pub monotonic_start_ns: u64,
    pub monotonic_end_ns: u64,
}

pub fn validate_lifecycle(workload: Workload, events: &[LifecycleEvent]) -> Result<()> {
    let expected: Vec<_> = [
        LifecycleStage::QuietObservation,
        LifecycleStage::SetupReadiness,
        LifecycleStage::ProtocolProof,
        LifecycleStage::Materialization,
        LifecycleStage::WarmupDrain,
    ]
    .into_iter()
    .chain((workload == Workload::WebSocket).then_some(LifecycleStage::WebsocketRetirement))
    .chain([
        LifecycleStage::Freeze,
        LifecycleStage::Steady,
        LifecycleStage::MeasuredDrain,
        LifecycleStage::Exit,
    ])
    .collect();
    if events.len() != expected.len() {
        return Err(Error::new("lifecycle event count mismatch"));
    }
    let caps = |stage| match stage {
        LifecycleStage::QuietObservation => Some(10_000_000_000),
        LifecycleStage::SetupReadiness | LifecycleStage::ProtocolProof => Some(2_000_000_000),
        LifecycleStage::WarmupDrain | LifecycleStage::MeasuredDrain => Some(2_000_000_000),
        LifecycleStage::WebsocketRetirement => Some(15_000_000_000),
        LifecycleStage::Freeze | LifecycleStage::Exit => Some(1_000_000_000),
        LifecycleStage::Materialization | LifecycleStage::Steady => None,
    };
    let mut previous_end = None;
    for (event, expected_stage) in events.iter().zip(expected) {
        if event.stage != expected_stage || event.monotonic_end_ns < event.monotonic_start_ns {
            return Err(Error::new("lifecycle stage order or clock mismatch"));
        }
        if previous_end.is_some_and(|end| end > event.monotonic_start_ns) {
            return Err(Error::new("lifecycle events overlap"));
        }
        let elapsed = event.monotonic_end_ns - event.monotonic_start_ns;
        if let Some(cap) = caps(event.stage) {
            if event.stage == LifecycleStage::QuietObservation {
                if elapsed != cap {
                    return Err(Error::new("Q_obs is not exactly ten seconds"));
                }
            } else if elapsed > cap {
                return Err(Error::new(format!("{:?} exceeded its cap", event.stage)));
            }
        }
        if event.stage == LifecycleStage::WebsocketRetirement
            && elapsed < WEBSOCKET_KEEPALIVE_NS + WEBSOCKET_STABILITY_NS
        {
            return Err(Error::new(
                "WebSocket retirement credited before 12 seconds",
            ));
        }
        previous_end = Some(event.monotonic_end_ns);
    }
    let drain = events
        .iter()
        .find(|event| event.stage == LifecycleStage::WarmupDrain)
        .ok_or_else(|| Error::new("missing warmup drain"))?;
    let freeze = events
        .iter()
        .find(|event| event.stage == LifecycleStage::Freeze)
        .ok_or_else(|| Error::new("missing freeze"))?;
    if workload != Workload::WebSocket
        && freeze
            .monotonic_end_ns
            .saturating_sub(drain.monotonic_start_ns)
            > 3_000_000_000
    {
        return Err(Error::new(
            "ordinary warmup drain plus freeze exceeds three seconds",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedArm {
    pub ordinal: u64,
    pub evidence_class: EvidenceClass,
    pub cell: Cell,
    pub arm: Option<Arm>,
    pub direct_protocol: Option<Protocol>,
    pub round: Option<u32>,
    pub row: Option<u8>,
    pub target: Option<u64>,
    pub lane_quotas: Vec<u64>,
    pub fresh_process_set: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationBoundary {
    PersistentRequestResponse,
    FreshH1ConnectThroughCloseEof,
    PreEstablishedPingPong,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionPrimitive {
    pub evidence_class: EvidenceClass,
    pub target: LoadTarget,
    pub load_protocol: Protocol,
    pub fixture_protocol: Protocol,
    pub connection_policy: ConnectionPolicy,
    pub operation_boundary: OperationBoundary,
    pub direct_h1_fixture_close_mode: bool,
    pub retain_latencies: bool,
    pub measurement: ControlBody,
}

pub fn execution_primitive(
    arm: &PlannedArm,
    fixed_duration_seconds: Option<u64>,
) -> Result<ProcessExecutionPrimitive> {
    arm.validate()?;
    let (target, load_protocol, fixture_protocol) = match arm.evidence_class {
        EvidenceClass::S | EvidenceClass::C | EvidenceClass::A => {
            let topology = ArmTopology::for_arm(
                arm.arm
                    .ok_or_else(|| Error::new("gateway primitive has no treatment"))?,
            );
            (LoadTarget::Gateway, topology.downstream, topology.upstream)
        }
        EvidenceClass::D => {
            let protocol = arm
                .direct_protocol
                .ok_or_else(|| Error::new("direct primitive has no protocol"))?;
            (LoadTarget::Direct, protocol, protocol)
        }
    };
    let connection_policy = match (load_protocol, arm.cell.workload) {
        (Protocol::H1, Workload::Upload1Mib) => ConnectionPolicy::FreshH1PerOperation,
        (Protocol::H1, Workload::WebSocket) => ConnectionPolicy::H1UpgradeTunnels,
        (Protocol::H1, _) => ConnectionPolicy::PersistentH1,
        (Protocol::H2, Workload::WebSocket) => ConnectionPolicy::H2ExtendedConnectStreams,
        (Protocol::H2, _) => ConnectionPolicy::PersistentH2,
    };
    let operation_boundary = match (load_protocol, arm.cell.workload) {
        (Protocol::H1, Workload::Upload1Mib) => OperationBoundary::FreshH1ConnectThroughCloseEof,
        (_, Workload::WebSocket) => OperationBoundary::PreEstablishedPingPong,
        _ => OperationBoundary::PersistentRequestResponse,
    };
    let retain_latencies = matches!(arm.evidence_class, EvidenceClass::C | EvidenceClass::A);
    let measurement = match arm.evidence_class {
        EvidenceClass::S => ControlBody::MeasureCount {
            phase: 2,
            operations: arm
                .target
                .ok_or_else(|| Error::new("scout primitive has no target"))?,
            retain_latencies: false,
        },
        EvidenceClass::C | EvidenceClass::D | EvidenceClass::A => {
            let seconds = fixed_duration_seconds
                .ok_or_else(|| Error::new("fixed-duration primitive has no duration"))?;
            if !(5..=30).contains(&seconds) {
                return Err(Error::new(
                    "fixed-duration primitive must use 5..=30 seconds",
                ));
            }
            ControlBody::MeasureDuration {
                phase: 2,
                duration_ns: seconds
                    .checked_mul(1_000_000_000)
                    .ok_or_else(|| Error::new("fixed-duration primitive overflow"))?,
                retain_latencies,
            }
        }
    };
    Ok(ProcessExecutionPrimitive {
        evidence_class: arm.evidence_class,
        target,
        load_protocol,
        fixture_protocol,
        connection_policy,
        operation_boundary,
        direct_h1_fixture_close_mode: target == LoadTarget::Direct
            && load_protocol == Protocol::H1
            && arm.cell.workload == Workload::Upload1Mib,
        retain_latencies,
        measurement,
    })
}

impl PlannedArm {
    pub fn validate(&self) -> Result<()> {
        self.cell.validate()?;
        if !self.fresh_process_set {
            return Err(Error::new("planned arm does not require fresh processes"));
        }
        match self.evidence_class {
            EvidenceClass::S => {
                if self.arm.is_none()
                    || self.direct_protocol.is_some()
                    || self.target.is_none()
                    || self.lane_quotas.len() != usize::from(self.cell.concurrency)
                {
                    return Err(Error::new("invalid S-class process plan"));
                }
                if self.lane_quotas.iter().sum::<u64>() != self.target.unwrap_or_default() {
                    return Err(Error::new("scout lane quotas do not sum to target"));
                }
            }
            EvidenceClass::C | EvidenceClass::A => {
                if self.arm.is_none() || self.direct_protocol.is_some() || self.target.is_some() {
                    return Err(Error::new("invalid gateway fixed-duration process plan"));
                }
            }
            EvidenceClass::D => {
                if self.arm.is_some() || self.direct_protocol.is_none() || self.target.is_some() {
                    return Err(Error::new("invalid direct process plan"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoutPlan {
    pub schema: String,
    pub seed: u64,
    pub attempts: Vec<PlannedArm>,
    pub maximum_arms: u64,
    pub hash_sha256: String,
}

pub fn scout_plan(seed: u64) -> Result<ScoutPlan> {
    let mut rng = SplitMix64::new(seed);
    let mut attempts = Vec::with_capacity(525);
    let mut ordinal = 0_u64;
    for cell in all_cells() {
        for target in SCOUT_TARGETS {
            let mut arms = Arm::ALL.to_vec();
            fisher_yates(&mut arms, &mut rng)?;
            for arm in arms {
                let planned = PlannedArm {
                    ordinal,
                    evidence_class: EvidenceClass::S,
                    cell,
                    arm: Some(arm),
                    direct_protocol: None,
                    round: None,
                    row: None,
                    target: Some(target),
                    lane_quotas: lane_quotas(target, cell.concurrency),
                    fresh_process_set: true,
                };
                planned.validate()?;
                attempts.push(planned);
                ordinal += 1;
            }
        }
    }
    let mut plan = ScoutPlan {
        schema: PROCESS_PLAN_SCHEMA.to_owned(),
        seed,
        attempts,
        maximum_arms: 525,
        hash_sha256: String::new(),
    };
    plan.hash_sha256 = hash_without_field(&plan)?;
    Ok(plan)
}

#[must_use]
pub fn lane_quotas(target: u64, concurrency: u16) -> Vec<u64> {
    let concurrency = u64::from(concurrency);
    (0..concurrency)
        .map(|lane| target / concurrency + u64::from(lane < target % concurrency))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationExecutionPlan {
    pub schema: String,
    pub seed: u64,
    pub arms: Vec<PlannedArm>,
    pub establishment_ordinals: Vec<EstablishmentArm>,
    pub direct_epoch_zero: Vec<PlannedArm>,
    pub hash_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstablishmentArm {
    pub cell: Cell,
    pub arm: Arm,
    pub ordinal: u64,
}

pub fn calibration_plan(seed: u64) -> Result<CalibrationExecutionPlan> {
    let rows = williams_rows();
    validate_williams_balance(&rows)?;
    let mut rng = SplitMix64::new(seed);
    let mut cells = all_cells();
    fisher_yates(&mut cells, &mut rng)?;
    let mut row_order: Vec<u8> = (0..10).collect();
    fisher_yates(&mut row_order, &mut rng)?;
    let mut arms = Vec::with_capacity(750);
    let mut establishment = Vec::with_capacity(75);
    let mut seen = std::collections::BTreeSet::new();
    let mut ordinal = 0_u64;
    for row in row_order {
        for cell in &cells {
            for arm in rows[usize::from(row)] {
                let planned = PlannedArm {
                    ordinal,
                    evidence_class: EvidenceClass::C,
                    cell: *cell,
                    arm: Some(arm),
                    direct_protocol: None,
                    round: Some(u32::from(row)),
                    row: Some(row),
                    target: None,
                    lane_quotas: Vec::new(),
                    fresh_process_set: true,
                };
                planned.validate()?;
                if seen.insert((*cell, arm)) {
                    establishment.push(EstablishmentArm {
                        cell: *cell,
                        arm,
                        ordinal,
                    });
                }
                arms.push(planned);
                ordinal += 1;
            }
        }
    }
    if arms.len() != 750 || establishment.len() != 75 {
        return Err(Error::new("calibration plan inventory mismatch"));
    }
    establishment.sort_by_key(|item| (item.cell, item.arm));
    let mut direct_epoch_zero = Vec::with_capacity(30);
    for cell in &cells {
        for protocol in [Protocol::H1, Protocol::H2] {
            let planned = PlannedArm {
                ordinal,
                evidence_class: EvidenceClass::D,
                cell: *cell,
                arm: None,
                direct_protocol: Some(protocol),
                round: Some(0),
                row: None,
                target: None,
                lane_quotas: Vec::new(),
                fresh_process_set: true,
            };
            planned.validate()?;
            direct_epoch_zero.push(planned);
            ordinal += 1;
        }
    }
    let mut plan = CalibrationExecutionPlan {
        schema: PROCESS_PLAN_SCHEMA.to_owned(),
        seed,
        arms,
        establishment_ordinals: establishment,
        direct_epoch_zero,
        hash_sha256: String::new(),
    };
    plan.hash_sha256 = hash_without_field(&plan)?;
    Ok(plan)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectMapping {
    pub arm: Arm,
    pub protocols: Vec<Protocol>,
}

#[must_use]
pub fn direct_mappings() -> Vec<DirectMapping> {
    Arm::ALL
        .into_iter()
        .map(|arm| DirectMapping {
            arm,
            protocols: ArmTopology::for_arm(arm).direct_protocols(),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignDryRun {
    pub schema: String,
    pub seed: u64,
    pub n: u32,
    pub rounds: Vec<RoundPlan>,
    pub phase_counts: PhaseCounts,
    pub direct_mappings: Vec<DirectMapping>,
    pub runtime_projection: RuntimeProjection,
    pub authoritative_gateway_arms: u64,
    pub authoritative_direct_arms: u64,
    pub hash_sha256: String,
}

pub fn campaign_dry_run(seed: u64, n: u32) -> Result<CampaignDryRun> {
    if !matches!(n, 30 | 50) {
        return Err(Error::new(
            "campaign dry-run accepts only prospectively runtime-admissible N=30/50",
        ));
    }
    let rounds = generate_rounds(seed, n)?;
    let counts = phase_counts(&[1_u8; 15], n, true)?;
    let durations = all_cells()
        .into_iter()
        .map(|cell| CellDurations {
            cell,
            durations: FrozenDurations {
                warmup_seconds: 3,
                measure_seconds: 5,
            },
        })
        .collect::<Vec<_>>();
    let runtime_projection = project_runtime(n, 17_217, 0, &durations)?;
    let mut plan = CampaignDryRun {
        schema: PROCESS_PLAN_SCHEMA.to_owned(),
        seed,
        n,
        rounds,
        authoritative_gateway_arms: 75 * u64::from(n),
        authoritative_direct_arms: 3 * u64::from(n),
        phase_counts: counts,
        direct_mappings: direct_mappings(),
        runtime_projection,
        hash_sha256: String::new(),
    };
    plan.hash_sha256 = hash_without_field(&plan)?;
    Ok(plan)
}

fn hash_without_field<T>(value: &T) -> Result<String>
where
    T: Serialize + CloneHashField,
{
    let bytes = json::canonical_bytes(&value.without_hash())?;
    Ok(sha256_hex(&bytes))
}

trait CloneHashField {
    type Output: Serialize;
    fn without_hash(&self) -> Self::Output;
}

impl CloneHashField for ScoutPlan {
    type Output = (String, u64, Vec<PlannedArm>, u64);
    fn without_hash(&self) -> Self::Output {
        (
            self.schema.clone(),
            self.seed,
            self.attempts.clone(),
            self.maximum_arms,
        )
    }
}

impl CloneHashField for CalibrationExecutionPlan {
    type Output = (
        String,
        u64,
        Vec<PlannedArm>,
        Vec<EstablishmentArm>,
        Vec<PlannedArm>,
    );
    fn without_hash(&self) -> Self::Output {
        (
            self.schema.clone(),
            self.seed,
            self.arms.clone(),
            self.establishment_ordinals.clone(),
            self.direct_epoch_zero.clone(),
        )
    }
}

impl CloneHashField for CampaignDryRun {
    type Output = (
        String,
        u64,
        u32,
        Vec<RoundPlan>,
        PhaseCounts,
        Vec<DirectMapping>,
        RuntimeProjection,
        u64,
        u64,
    );
    fn without_hash(&self) -> Self::Output {
        (
            self.schema.clone(),
            self.seed,
            self.n,
            self.rounds.clone(),
            self.phase_counts.clone(),
            self.direct_mappings.clone(),
            self.runtime_projection.clone(),
            self.authoritative_gateway_arms,
            self.authoritative_direct_arms,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scout_plan_has_all_seven_fresh_five_arm_panels_and_exact_quotas() {
        let plan = scout_plan(7).expect("scout plan");
        assert_eq!(plan.attempts.len(), 525);
        assert_eq!(plan.maximum_arms, 525);
        assert!(plan
            .attempts
            .iter()
            .all(|attempt| attempt.fresh_process_set));
        for attempt in &plan.attempts {
            assert_eq!(
                attempt.lane_quotas.iter().sum::<u64>(),
                attempt.target.unwrap()
            );
        }
    }

    #[test]
    fn calibration_plan_has_exact_750_arms_and_prospective_signatures() {
        let plan = calibration_plan(9).expect("calibration plan");
        assert_eq!(plan.arms.len(), 750);
        assert_eq!(plan.establishment_ordinals.len(), 75);
        assert_eq!(plan.direct_epoch_zero.len(), 30);
        assert!(plan
            .arms
            .iter()
            .all(|arm| arm.evidence_class == EvidenceClass::C));
        assert!(plan
            .direct_epoch_zero
            .iter()
            .all(|arm| arm.evidence_class == EvidenceClass::D));
    }

    #[test]
    fn campaign_dry_run_reproduces_floor_and_exact_arm_counts() {
        let n30 = campaign_dry_run(42, 30).expect("N30");
        assert_eq!(n30.authoritative_gateway_arms, 2_250);
        assert_eq!(n30.authoritative_direct_arms, 90);
        assert_eq!(n30.runtime_projection.projected_total_seconds, 98_757);
        let n50 = campaign_dry_run(42, 50).expect("N50");
        assert_eq!(n50.runtime_projection.projected_total_seconds, 147_117);
        assert!(campaign_dry_run(42, 70).is_err());
    }

    #[test]
    fn websocket_lifecycle_cannot_credit_stability_before_keepalive() {
        let stages = [
            LifecycleStage::QuietObservation,
            LifecycleStage::SetupReadiness,
            LifecycleStage::ProtocolProof,
            LifecycleStage::Materialization,
            LifecycleStage::WarmupDrain,
            LifecycleStage::WebsocketRetirement,
            LifecycleStage::Freeze,
            LifecycleStage::Steady,
            LifecycleStage::MeasuredDrain,
            LifecycleStage::Exit,
        ];
        let mut cursor = 0_u64;
        let mut events = Vec::new();
        for stage in stages {
            let elapsed = match stage {
                LifecycleStage::QuietObservation => 10_000_000_000,
                LifecycleStage::WebsocketRetirement => 12_000_000_000,
                _ => 1,
            };
            events.push(LifecycleEvent {
                stage,
                monotonic_start_ns: cursor,
                monotonic_end_ns: cursor + elapsed,
            });
            cursor += elapsed;
        }
        validate_lifecycle(Workload::WebSocket, &events).expect("valid lifecycle");
        events[5].monotonic_end_ns = events[5].monotonic_start_ns + 11_999_999_999;
        assert!(validate_lifecycle(Workload::WebSocket, &events).is_err());
    }

    #[test]
    fn execution_primitives_bind_class_protocol_latency_and_upload_policy() {
        let scout = scout_plan(7).unwrap();
        let h1_upload = scout
            .attempts
            .iter()
            .find(|arm| arm.cell.workload == Workload::Upload1Mib && arm.arm == Some(Arm::B11))
            .unwrap();
        let primitive = execution_primitive(h1_upload, None).unwrap();
        assert_eq!(primitive.target, LoadTarget::Gateway);
        assert_eq!(
            primitive.connection_policy,
            ConnectionPolicy::FreshH1PerOperation
        );
        assert_eq!(
            primitive.operation_boundary,
            OperationBoundary::FreshH1ConnectThroughCloseEof
        );
        assert!(!primitive.retain_latencies);
        assert!(matches!(
            primitive.measurement,
            ControlBody::MeasureCount {
                retain_latencies: false,
                ..
            }
        ));

        let calibration = calibration_plan(9).unwrap();
        let h2_upload = calibration
            .arms
            .iter()
            .find(|arm| arm.cell.workload == Workload::Upload1Mib && arm.arm == Some(Arm::C22))
            .unwrap();
        let primitive = execution_primitive(h2_upload, Some(5)).unwrap();
        assert_eq!(primitive.connection_policy, ConnectionPolicy::PersistentH2);
        assert!(primitive.retain_latencies);
        assert!(matches!(
            primitive.measurement,
            ControlBody::MeasureDuration {
                duration_ns: 5_000_000_000,
                retain_latencies: true,
                ..
            }
        ));

        let direct_h1_upload = calibration
            .direct_epoch_zero
            .iter()
            .find(|arm| {
                arm.cell.workload == Workload::Upload1Mib
                    && arm.direct_protocol == Some(Protocol::H1)
            })
            .unwrap();
        let primitive = execution_primitive(direct_h1_upload, Some(30)).unwrap();
        assert_eq!(primitive.target, LoadTarget::Direct);
        assert!(primitive.direct_h1_fixture_close_mode);
        assert!(!primitive.retain_latencies);
        assert!(matches!(
            primitive.measurement,
            ControlBody::MeasureDuration {
                duration_ns: 30_000_000_000,
                retain_latencies: false,
                ..
            }
        ));
        assert!(execution_primitive(direct_h1_upload, Some(31)).is_err());
    }
}
