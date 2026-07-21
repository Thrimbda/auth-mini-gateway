use crate::process_plan::{CalibrationExecutionPlan, ScoutPlan};
use crate::schema::{
    all_cells, hard_comparisons, BlockedCode, BlockedReason, CalibrationPhase, CalibrationRecord,
    Cell, EvidenceClass, SignatureBinding, AUTHORITATIVE_PARAMETERS_SCHEMA,
    CALIBRATION_PLAN_SCHEMA,
};
use crate::seal::sha256_hex;
use crate::statistics::{order_stratum_standard_deviations, Metric, PairedMetrics};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SCOUT_TARGETS: [u64; 7] = [5_000, 10_000, 20_000, 40_000, 80_000, 160_000, 320_000];
pub const COUNT_WINDOW_MAX_NS: u64 = 15_000_000_000;
pub const COUNT_QUALITY_MIN_NS: u64 = 2_000_000_000;
pub const COUNT_QUALITY_MIN_TICKS: u64 = 100;
pub const FIXED_Q_OBS_NS: u64 = 10_000_000_000;
pub const Q_EXTRA_CAP_NS: u64 = 7_200_000_000_000;
pub const ANALYSIS_CAP_NS: u64 = 1_800_000_000_000;
pub const PROJECTION_CAP_NS: u64 = 151_200_000_000_000;
pub const ACTUAL_CAP_NS: u64 = 172_800_000_000_000;
pub const PRE_FREEZE_FLOOR_NS: u64 = 17_217_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileHashBinding {
    pub path: String,
    pub sha256: String,
}

impl FileHashBinding {
    pub fn validate(&self) -> Result<()> {
        crate::seal::validate_relative_path(&self.path)?;
        crate::schema::validate_non_placeholder_sha256("file hash binding", &self.sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedScoutPanel {
    pub cell: Cell,
    pub attempted_targets: Vec<u64>,
    pub accepted_target: u64,
    pub arm_ordinals: Vec<u64>,
    pub arm_raw_sha256: Vec<String>,
    pub durations: FrozenDurations,
}

impl AcceptedScoutPanel {
    pub fn validate(&self) -> Result<()> {
        self.cell.validate()?;
        self.durations.validate()?;
        let accepted_index = SCOUT_TARGETS
            .iter()
            .position(|target| *target == self.accepted_target)
            .ok_or_else(|| Error::new("accepted scout target is not canonical"))?;
        if self.attempted_targets != SCOUT_TARGETS[..=accepted_index]
            || self.arm_ordinals.len() != self.attempted_targets.len() * 5
            || self.arm_raw_sha256.len() != self.arm_ordinals.len()
        {
            return Err(Error::new(
                "accepted scout panel is not an exact complete target prefix",
            ));
        }
        for hash in &self.arm_raw_sha256 {
            crate::schema::validate_non_placeholder_sha256("accepted scout raw", hash)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationPlanEvidence {
    pub schema: String,
    pub calibration_id: String,
    pub campaign_seed: u64,
    pub intent: FileHashBinding,
    pub topology_smoke: FileHashBinding,
    pub scout_plan: ScoutPlan,
    pub accepted_scouts: Vec<AcceptedScoutPanel>,
    pub williams_plan: CalibrationExecutionPlan,
    pub first_williams_ordinal: u64,
    pub direct_mappings: Vec<crate::process_plan::DirectMapping>,
    pub phase_constants_sha256: String,
}

impl CalibrationPlanEvidence {
    pub fn validate(&self) -> Result<()> {
        if self.schema != CALIBRATION_PLAN_SCHEMA {
            return Err(Error::new("unsupported calibration-plan schema"));
        }
        crate::schema::validate_identifier("calibration plan ID", &self.calibration_id)?;
        self.intent.validate()?;
        self.topology_smoke.validate()?;
        if self.scout_plan != crate::process_plan::scout_plan(self.campaign_seed)? {
            return Err(Error::new(
                "calibration plan scout schedule does not regenerate from its seed",
            ));
        }
        if self.accepted_scouts.len() != 15 {
            return Err(Error::new("calibration plan lacks 15 accepted scout cells"));
        }
        let mut cells = BTreeSet::new();
        let mut expected_ordinal = 0_u64;
        for scout in &self.accepted_scouts {
            scout.validate()?;
            if !cells.insert(scout.cell)
                || scout.arm_ordinals.first().copied() != Some(expected_ordinal)
            {
                return Err(Error::new(
                    "calibration plan accepted scout cells/ordinals are not canonical",
                ));
            }
            for ordinal in &scout.arm_ordinals {
                if *ordinal != expected_ordinal {
                    return Err(Error::new(
                        "calibration plan scout ordinals are not contiguous",
                    ));
                }
                expected_ordinal += 1;
            }
        }
        if cells != all_cells().into_iter().collect()
            || self.first_williams_ordinal != expected_ordinal
        {
            return Err(Error::new(
                "calibration plan scout cell set or Williams prefix is invalid",
            ));
        }
        let regenerated = crate::process_plan::calibration_plan_with_offset(
            self.campaign_seed,
            self.first_williams_ordinal,
        )?;
        if self.williams_plan != regenerated
            || self.direct_mappings != crate::process_plan::direct_mappings()
        {
            return Err(Error::new(
                "calibration plan Williams/direct schedule does not regenerate",
            ));
        }
        crate::schema::validate_non_placeholder_sha256(
            "calibration phase constants",
            &self.phase_constants_sha256,
        )
    }

    pub fn calibration_durations(&self) -> Vec<CellDurations> {
        self.accepted_scouts
            .iter()
            .map(|entry| CellDurations {
                cell: entry.cell,
                durations: entry.durations,
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParameterDisposition {
    Admitted,
    RuntimeBlocked,
    StorageBlocked,
    PrecisionBlocked,
    QualityBlocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeParameters {
    pub schema: String,
    pub calibration_id: String,
    pub intent: FileHashBinding,
    pub calibration_plan: FileHashBinding,
    pub accepted_treatment_signatures: Vec<SignatureBinding>,
    pub variances: Vec<VarianceEstimate>,
    pub authoritative_durations: Vec<CellDurations>,
    pub selected_n: Option<u32>,
    pub disposition: ParameterDisposition,
    pub direct_plan: Vec<crate::process_plan::PlannedArm>,
    pub lower_bound_runtime_ns: u64,
    pub terminal_reason: Option<BlockedReason>,
}

impl AuthoritativeParameters {
    pub fn validate(&self) -> Result<()> {
        if self.schema != AUTHORITATIVE_PARAMETERS_SCHEMA {
            return Err(Error::new("unsupported authoritative-parameters schema"));
        }
        crate::schema::validate_identifier("authoritative calibration ID", &self.calibration_id)?;
        self.intent.validate()?;
        self.calibration_plan.validate()?;
        if self.accepted_treatment_signatures.len() != 75 {
            return Err(Error::new(
                "authoritative parameters lack 75 treatment signatures",
            ));
        }
        let mut signatures = BTreeSet::new();
        for binding in &self.accepted_treatment_signatures {
            binding.validate()?;
            if binding.arm.is_none()
                || binding.direct_protocol.is_some()
                || !signatures.insert((binding.cell, binding.arm))
            {
                return Err(Error::new(
                    "authoritative treatment signature inventory is invalid",
                ));
            }
        }
        if self.variances.len() != 180 {
            return Err(Error::new(
                "authoritative parameters lack the 45x4 variance matrix",
            ));
        }
        for variance in &self.variances {
            variance.validate()?;
        }
        validate_duration_inventory(&self.authoritative_durations)?;
        if self.lower_bound_runtime_ns < PRE_FREEZE_FLOOR_NS {
            return Err(Error::new(
                "authoritative lower-bound runtime is below the reviewed floor",
            ));
        }
        match self.disposition {
            ParameterDisposition::Admitted => {
                if !matches!(self.selected_n, Some(30 | 50))
                    || self.direct_plan.len() != 30
                    || self.terminal_reason.is_some()
                {
                    return Err(Error::new(
                        "admitted authoritative parameters are incomplete",
                    ));
                }
            }
            ParameterDisposition::RuntimeBlocked => {
                if !matches!(self.selected_n, Some(30 | 50 | 70 | 100))
                    || !self.direct_plan.is_empty()
                    || self.terminal_reason.is_none()
                {
                    return Err(Error::new(
                        "runtime-blocked authoritative parameters are inconsistent",
                    ));
                }
            }
            ParameterDisposition::StorageBlocked => {
                if !matches!(self.selected_n, Some(30 | 50))
                    || !self.direct_plan.is_empty()
                    || self.terminal_reason.is_none()
                {
                    return Err(Error::new(
                        "storage-blocked authoritative parameters are inconsistent",
                    ));
                }
            }
            ParameterDisposition::PrecisionBlocked | ParameterDisposition::QualityBlocked => {
                if self.selected_n.is_some()
                    || !self.direct_plan.is_empty()
                    || self.terminal_reason.is_none()
                {
                    return Err(Error::new(
                        "blocked authoritative parameters are inconsistent",
                    ));
                }
            }
        }
        if let Some(reason) = &self.terminal_reason {
            reason.validate()?;
        }
        Ok(())
    }
}

fn validate_duration_inventory(values: &[CellDurations]) -> Result<()> {
    if values.len() != 15 {
        return Err(Error::new("duration inventory does not contain 15 cells"));
    }
    let mut cells = BTreeSet::new();
    for value in values {
        value.cell.validate()?;
        value.durations.validate()?;
        if !cells.insert(value.cell) {
            return Err(Error::new("duration inventory repeats a cell"));
        }
    }
    if cells != all_cells().into_iter().collect() {
        return Err(Error::new("duration inventory cell set is incomplete"));
    }
    Ok(())
}

#[must_use]
pub fn phase_constants_sha256() -> String {
    sha256_hex(
        b"Tsmoke=300s;Qobs=10s;R=2s;P=2s;Ws=3s;Dw=2s;Ktokio=10s;Sinv=2s;Lws=15s;F=1s;Dm=2s;X=1s;count=15s;qcap=7200s;acap=1800s",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoutTransition {
    Accept { target: u64 },
    Double { current: u64, next: u64 },
    Blocked(BlockedReason),
}

pub fn scout_transition(target: u64, attempts: &[CalibrationRecord]) -> ScoutTransition {
    let result = validate_scout_panel(target, attempts);
    match result {
        Err(error) => ScoutTransition::Blocked(BlockedReason::new(
            BlockedCode::InvalidCalibration,
            error.to_string(),
        )),
        Ok(all_quality) if all_quality => ScoutTransition::Accept { target },
        Ok(_) => {
            let Some(index) = SCOUT_TARGETS
                .iter()
                .position(|candidate| *candidate == target)
            else {
                return ScoutTransition::Blocked(BlockedReason::new(
                    BlockedCode::InvalidCalibration,
                    "scout target is not in the seven-level sequence",
                ));
            };
            if let Some(next) = SCOUT_TARGETS.get(index + 1) {
                ScoutTransition::Double {
                    current: target,
                    next: *next,
                }
            } else {
                ScoutTransition::Blocked(BlockedReason::new(
                    BlockedCode::InvalidCalibration,
                    "320,000-operation scout still lacks count quality",
                ))
            }
        }
    }
}

fn validate_scout_panel(target: u64, attempts: &[CalibrationRecord]) -> Result<bool> {
    if !SCOUT_TARGETS.contains(&target) || attempts.len() != 5 {
        return Err(Error::new("scout panel target/count is invalid"));
    }
    let mut arms = BTreeSet::new();
    let mut processes = BTreeSet::new();
    let mut cell = None;
    let mut all_quality = true;
    for attempt in attempts {
        attempt.validate()?;
        if attempt.phase != CalibrationPhase::Scout
            || attempt.class != EvidenceClass::S
            || attempt.target != Some(target)
        {
            return Err(Error::new(
                "scout panel contains the wrong phase/class/target",
            ));
        }
        if attempt.elapsed_ns > COUNT_WINDOW_MAX_NS {
            return Err(Error::new(
                "scout count window exceeded the inclusive 15-second cap",
            ));
        }
        if !arms.insert(attempt.arm) || !processes.insert(attempt.process_identity.clone()) {
            return Err(Error::new("scout panel reused an arm or process identity"));
        }
        match cell {
            Some(expected) if expected != attempt.cell => {
                return Err(Error::new("scout panel mixes cells"));
            }
            None => cell = Some(attempt.cell),
            Some(_) => {}
        }
        all_quality &= attempt.elapsed_ns >= COUNT_QUALITY_MIN_NS
            && attempt.gateway_ticks >= COUNT_QUALITY_MIN_TICKS;
    }
    Ok(all_quality)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenDurations {
    pub warmup_seconds: u64,
    pub measure_seconds: u64,
}

impl FrozenDurations {
    pub fn validate(self) -> Result<()> {
        if !(3..=10).contains(&self.warmup_seconds) || !(5..=30).contains(&self.measure_seconds) {
            return Err(Error::new("frozen W/T is outside the RFC range"));
        }
        Ok(())
    }
}

pub fn derive_scout_durations(attempts: &[CalibrationRecord]) -> Result<FrozenDurations> {
    if attempts.len() != 5 {
        return Err(Error::new(
            "duration derivation requires five accepted scout arms",
        ));
    }
    let observations = attempts
        .iter()
        .map(|attempt| {
            attempt.validate()?;
            if attempt.phase != CalibrationPhase::Scout {
                return Err(Error::new("non-scout record used for scout duration"));
            }
            Ok((
                attempt.deadline_completions,
                attempt.elapsed_ns,
                attempt.gateway_ticks,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    derive_durations(&observations)
}

/// Derives W/T from exact `(operations, elapsed_ns, gateway_ticks)` observations.
pub fn derive_durations(observations: &[(u64, u64, u64)]) -> Result<FrozenDurations> {
    if observations.is_empty() {
        return Err(Error::new("duration derivation has no observations"));
    }
    let mut warmup = 3_u64;
    let mut measure = 5_u64;
    for (operations, elapsed_ns, ticks) in observations.iter().copied() {
        if operations == 0 || elapsed_ns == 0 || ticks == 0 {
            return Err(Error::new("duration rate denominator is zero"));
        }
        let warmup_candidate = ceil_ratio_seconds(1_250, elapsed_ns, operations)?;
        let operation_candidate = ceil_ratio_seconds(6_250, elapsed_ns, operations)?;
        let tick_candidate = ceil_ratio_seconds(625, elapsed_ns, ticks)?;
        warmup = warmup.max(warmup_candidate);
        measure = measure.max(operation_candidate).max(tick_candidate);
    }
    let durations = FrozenDurations {
        warmup_seconds: warmup,
        measure_seconds: measure,
    };
    durations.validate()?;
    Ok(durations)
}

fn ceil_ratio_seconds(multiplier: u64, elapsed_ns: u64, count: u64) -> Result<u64> {
    let numerator = u128::from(multiplier)
        .checked_mul(u128::from(elapsed_ns))
        .ok_or_else(|| Error::new("duration numerator overflow"))?;
    let denominator = u128::from(count)
        .checked_mul(1_000_000_000)
        .ok_or_else(|| Error::new("duration denominator overflow"))?;
    let value = ceil_div(numerator, denominator)?;
    u64::try_from(value).map_err(|_| Error::new("duration does not fit u64"))
}

fn ceil_div(numerator: u128, denominator: u128) -> Result<u128> {
    if denominator == 0 {
        return Err(Error::new("division by zero"));
    }
    numerator
        .checked_add(denominator - 1)
        .map(|value| value / denominator)
        .ok_or_else(|| Error::new("ceiling division overflow"))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VarianceEstimate {
    pub comparison_id: String,
    pub metric: Metric,
    pub s_ab: f64,
    pub s_ba: f64,
}

impl VarianceEstimate {
    pub fn validate(&self) -> Result<()> {
        if self.comparison_id.is_empty()
            || !self.s_ab.is_finite()
            || !self.s_ba.is_finite()
            || self.s_ab < 0.0
            || self.s_ba < 0.0
        {
            return Err(Error::new("invalid calibration variance estimate"));
        }
        Ok(())
    }
}

pub fn variance_from_calibration(
    comparison_id: impl Into<String>,
    metric: Metric,
    pairs: &[PairedMetrics],
) -> Result<VarianceEstimate> {
    let (s_ab, s_ba) = order_stratum_standard_deviations(pairs, metric)?;
    let estimate = VarianceEstimate {
        comparison_id: comparison_id.into(),
        metric,
        s_ab,
        s_ba,
    };
    estimate.validate()?;
    Ok(estimate)
}

#[derive(Debug, Clone, PartialEq)]
pub enum NSelection {
    Admissible {
        n: u32,
    },
    RuntimeBlocked {
        selected_n: u32,
        reason: BlockedReason,
    },
    PrecisionBlocked {
        reason: BlockedReason,
    },
}

pub fn select_authoritative_n(estimates: &[VarianceEstimate]) -> Result<NSelection> {
    if estimates.len() != 180 {
        return Err(Error::new(
            "N selection requires 45 comparisons × 4 metrics",
        ));
    }
    let mut keys = BTreeSet::new();
    for estimate in estimates {
        estimate.validate()?;
        if !keys.insert((estimate.comparison_id.clone(), estimate.metric.index())) {
            return Err(Error::new("duplicate comparison/metric variance estimate"));
        }
    }
    let expected_keys: BTreeSet<_> = hard_comparisons()
        .into_iter()
        .flat_map(|comparison| {
            Metric::ALL
                .into_iter()
                .map(move |metric| (comparison.id.clone(), metric.index()))
        })
        .collect();
    if keys != expected_keys {
        return Err(Error::new(
            "N selection variance keys are not the canonical 45×4 matrix",
        ));
    }
    for n in [30_u32, 50, 70, 100] {
        if estimates.iter().all(|estimate| {
            projected_half_width(estimate, n)
                .is_ok_and(|width| width <= width_limit(estimate.metric))
        }) {
            return if n >= 70 {
                Ok(NSelection::RuntimeBlocked {
                    selected_n: n,
                    reason: BlockedReason::new(
                        BlockedCode::RuntimeProjection,
                        format!(
                            "statistically selected N={n} is prospectively runtime-inadmissible"
                        ),
                    ),
                })
            } else {
                Ok(NSelection::Admissible { n })
            };
        }
    }
    Ok(NSelection::PrecisionBlocked {
        reason: BlockedReason::new(
            BlockedCode::Precision,
            "projected N=100 still exceeds at least one precision width",
        ),
    })
}

pub fn projected_half_width(estimate: &VarianceEstimate, n: u32) -> Result<f64> {
    estimate.validate()?;
    let t95 = match n {
        30 => 1.701,
        50 => 1.677,
        70 => 1.668,
        100 => 1.661,
        _ => return Err(Error::new("projected width N is not allowed")),
    };
    let floor = match estimate.metric {
        Metric::PeakRss => 1.01_f64.ln(),
        Metric::Throughput | Metric::P99Latency | Metric::CpuPerOperation => 1.005_f64.ln(),
    };
    let s_ab = estimate.s_ab.max(floor);
    let s_ba = estimate.s_ba.max(floor);
    Ok(2.0 * t95 * ((s_ab.mul_add(s_ab, s_ba * s_ba)) / (2.0 * f64::from(n))).sqrt())
}

fn width_limit(metric: Metric) -> f64 {
    match metric {
        Metric::Throughput => 1.02_f64.ln(),
        Metric::P99Latency | Metric::CpuPerOperation => 1.03_f64.ln(),
        Metric::PeakRss => 1.05_f64.ln(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellDurations {
    pub cell: Cell,
    pub durations: FrozenDurations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseCounts {
    pub scout_arms: u64,
    pub calibration_arms: u64,
    pub calibration_direct_arms: u64,
    pub authoritative_gateway_arms: u64,
    pub authoritative_direct_arms: u64,
}

pub fn phase_counts(
    scout_levels: &[u8; 15],
    n: u32,
    continuation_reachable: bool,
) -> Result<PhaseCounts> {
    if scout_levels.iter().any(|level| !(1..=7).contains(level)) {
        return Err(Error::new("scout level outside 1..=7"));
    }
    if !matches!(n, 30 | 50 | 70 | 100) {
        return Err(Error::new("phase-count N is not allowed"));
    }
    let scout_arms = 5 * scout_levels
        .iter()
        .map(|level| u64::from(*level))
        .sum::<u64>();
    Ok(PhaseCounts {
        scout_arms,
        calibration_arms: 750,
        calibration_direct_arms: u64::from(continuation_reachable) * 30,
        authoritative_gateway_arms: if continuation_reachable {
            75 * u64::from(n)
        } else {
            0
        },
        authoritative_direct_arms: if continuation_reachable {
            3 * u64::from(n)
        } else {
            0
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProjection {
    pub n: u32,
    pub e_pre_ns: u64,
    pub q_extra_pre_ns: u64,
    pub future_arm_ns: u64,
    pub remaining_q_extra_ns: u64,
    pub analysis_reserve_ns: u64,
    pub projected_total_ns: u64,
    pub admissible: bool,
}

pub fn project_runtime(
    n: u32,
    e_pre_ns: u64,
    q_extra_pre_ns: u64,
    durations: &[CellDurations],
) -> Result<RuntimeProjection> {
    if !matches!(n, 30 | 50) {
        return Err(Error::new(
            "only runtime-admissible N=30/50 can reach exact admission",
        ));
    }
    if q_extra_pre_ns > Q_EXTRA_CAP_NS {
        return Err(Error::new("completed Q_extra already exceeds Q_cap"));
    }
    if durations.len() != 15 {
        return Err(Error::new(
            "runtime projection requires all 15 cell durations",
        ));
    }
    let mut duration_map = BTreeMap::new();
    for entry in durations {
        entry.cell.validate()?;
        entry.durations.validate()?;
        if duration_map.insert(entry.cell, entry.durations).is_some() {
            return Err(Error::new("duplicate runtime-projection cell"));
        }
    }
    if duration_map.len() != all_cells().len() {
        return Err(Error::new("runtime projection cell set is incomplete"));
    }
    let future_per_cell = 5_u64
        .checked_mul(u64::from(n))
        .and_then(|value| value.checked_add(2 * u64::from(n / 10)))
        .ok_or_else(|| Error::new("future per-cell arm count overflow"))?;
    let mut future_arm_ns = 0_u64;
    for cell in all_cells() {
        let cell_duration = arm_cap_ns(
            cell,
            *duration_map
                .get(&cell)
                .ok_or_else(|| Error::new("missing cell duration"))?,
        )?;
        future_arm_ns = future_arm_ns
            .checked_add(
                future_per_cell
                    .checked_mul(cell_duration)
                    .ok_or_else(|| Error::new("future arm subtotal overflow"))?,
            )
            .ok_or_else(|| Error::new("future arm total overflow"))?;
    }
    let remaining_q_extra_ns = Q_EXTRA_CAP_NS - q_extra_pre_ns;
    let projected_total_ns = e_pre_ns
        .checked_add(future_arm_ns)
        .and_then(|value| value.checked_add(remaining_q_extra_ns))
        .and_then(|value| value.checked_add(ANALYSIS_CAP_NS))
        .ok_or_else(|| Error::new("runtime projection overflow"))?;
    Ok(RuntimeProjection {
        n,
        e_pre_ns,
        q_extra_pre_ns,
        future_arm_ns,
        remaining_q_extra_ns,
        analysis_reserve_ns: ANALYSIS_CAP_NS,
        projected_total_ns,
        admissible: projected_total_ns <= PROJECTION_CAP_NS,
    })
}

pub fn arm_cap_ns(cell: Cell, durations: FrozenDurations) -> Result<u64> {
    cell.validate()?;
    durations.validate()?;
    let ordinary_seconds = 20_u64
        .checked_add(durations.warmup_seconds)
        .and_then(|value| value.checked_add(durations.measure_seconds))
        .ok_or_else(|| Error::new("arm cap overflow"))?;
    let total_seconds = ordinary_seconds
        .checked_add(u64::from(cell.workload == crate::schema::Workload::WebSocket) * 15)
        .ok_or_else(|| Error::new("WebSocket arm cap overflow"))?;
    total_seconds
        .checked_mul(1_000_000_000)
        .ok_or_else(|| Error::new("arm cap nanosecond conversion overflow"))
}

#[must_use]
pub const fn actual_runtime_allowed(elapsed_ns: u64) -> bool {
    elapsed_ns <= ACTUAL_CAP_NS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Arm, Workload, EXECUTION_SCHEMA};

    fn scout(
        arm: Arm,
        target: u64,
        elapsed_ns: u64,
        ticks: u64,
        process: usize,
    ) -> CalibrationRecord {
        CalibrationRecord {
            schema: EXECUTION_SCHEMA.to_owned(),
            calibration_id: "cal-fixture".to_owned(),
            phase: CalibrationPhase::Scout,
            class: EvidenceClass::S,
            cell: Cell {
                workload: Workload::Get,
                concurrency: 1,
            },
            arm: Some(arm),
            target: Some(target),
            elapsed_ns,
            gateway_ticks: ticks,
            started_operations: target,
            deadline_completions: target,
            drained_operations: target,
            lane_quotas: vec![target],
            lane_completions: vec![target],
            endpoint_hashes_match: true,
            process_identity: format!("pid-{process}"),
        }
    }

    fn panel(target: u64, elapsed_ns: u64, ticks: u64) -> Vec<CalibrationRecord> {
        Arm::ALL
            .into_iter()
            .enumerate()
            .map(|(index, arm)| scout(arm, target, elapsed_ns, ticks, index))
            .collect()
    }

    fn variance_panel(standard_deviation: f64) -> Vec<VarianceEstimate> {
        hard_comparisons()
            .into_iter()
            .flat_map(|comparison| {
                Metric::ALL.into_iter().map(move |metric| VarianceEstimate {
                    comparison_id: comparison.id.clone(),
                    metric,
                    s_ab: standard_deviation,
                    s_ba: standard_deviation,
                })
            })
            .collect()
    }

    #[test]
    fn all_seven_scout_transitions_are_exact_and_fresh() {
        for (index, target) in SCOUT_TARGETS.into_iter().enumerate() {
            let transition = scout_transition(target, &panel(target, 1_999_999_999, 100));
            if index < 6 {
                assert_eq!(
                    transition,
                    ScoutTransition::Double {
                        current: target,
                        next: SCOUT_TARGETS[index + 1]
                    }
                );
            } else {
                assert!(matches!(transition, ScoutTransition::Blocked(_)));
            }
        }
        assert_eq!(
            scout_transition(5_000, &panel(5_000, 2_000_000_000, 100)),
            ScoutTransition::Accept { target: 5_000 }
        );
        let mut reused = panel(5_000, 2_000_000_000, 100);
        reused[4].process_identity = reused[0].process_identity.clone();
        assert!(matches!(
            scout_transition(5_000, &reused),
            ScoutTransition::Blocked(_)
        ));
    }

    #[test]
    fn scout_timeout_is_inclusive_and_non_quality_failures_never_double() {
        assert!(matches!(
            scout_transition(5_000, &panel(5_000, COUNT_WINDOW_MAX_NS, 100)),
            ScoutTransition::Accept { .. }
        ));
        assert!(matches!(
            scout_transition(5_000, &panel(5_000, COUNT_WINDOW_MAX_NS + 1, 100)),
            ScoutTransition::Blocked(_)
        ));
        let mut malformed = panel(5_000, 2_000_000_000, 100);
        malformed[0].endpoint_hashes_match = false;
        assert!(matches!(
            scout_transition(5_000, &malformed),
            ScoutTransition::Blocked(_)
        ));
    }

    #[test]
    fn exact_w_and_t_formulas_round_up_and_enforce_ranges() {
        assert_eq!(
            derive_durations(&[(5_000, 2_000_000_000, 100)]).expect("durations"),
            FrozenDurations {
                warmup_seconds: 3,
                measure_seconds: 13
            }
        );
        assert_eq!(
            derive_durations(&[(10_000, 2_000_000_001, 200)]).expect("durations"),
            FrozenDurations {
                warmup_seconds: 3,
                measure_seconds: 7
            }
        );
        assert!(derive_durations(&[(1, 15_000_000_000, 1)]).is_err());
    }

    #[test]
    fn n_selection_covers_every_bucket_and_high_n_never_substitutes() {
        assert_eq!(
            select_authoritative_n(&variance_panel(0.02)).expect("N=30"),
            NSelection::Admissible { n: 30 }
        );
        assert_eq!(
            select_authoritative_n(&variance_panel(0.035)).expect("N=50"),
            NSelection::Admissible { n: 50 }
        );
        assert!(matches!(
            select_authoritative_n(&variance_panel(0.045)).expect("N=70"),
            NSelection::RuntimeBlocked { selected_n: 70, .. }
        ));
        assert!(matches!(
            select_authoritative_n(&variance_panel(0.055)).expect("N=100"),
            NSelection::RuntimeBlocked {
                selected_n: 100,
                ..
            }
        ));
        assert!(matches!(
            select_authoritative_n(&variance_panel(0.08)).expect("blocked"),
            NSelection::PrecisionBlocked { .. }
        ));
    }

    #[test]
    fn exact_phase_counts_cover_reachable_and_terminal_branches() {
        assert_eq!(
            phase_counts(&[1; 15], 30, true).expect("counts"),
            PhaseCounts {
                scout_arms: 75,
                calibration_arms: 750,
                calibration_direct_arms: 30,
                authoritative_gateway_arms: 2_250,
                authoritative_direct_arms: 90,
            }
        );
        assert_eq!(
            phase_counts(&[7; 15], 100, false).expect("terminal counts"),
            PhaseCounts {
                scout_arms: 525,
                calibration_arms: 750,
                calibration_direct_arms: 0,
                authoritative_gateway_arms: 0,
                authoritative_direct_arms: 0,
            }
        );
    }

    #[test]
    fn arm_caps_and_runtime_lower_bounds_are_exact() {
        let minimum = FrozenDurations {
            warmup_seconds: 3,
            measure_seconds: 5,
        };
        let maximum = FrozenDurations {
            warmup_seconds: 10,
            measure_seconds: 30,
        };
        let ordinary = Cell {
            workload: Workload::Get,
            concurrency: 1,
        };
        let websocket = Cell {
            workload: Workload::WebSocket,
            concurrency: 1,
        };
        assert_eq!(arm_cap_ns(ordinary, minimum).expect("cap"), 28_000_000_000);
        assert_eq!(arm_cap_ns(ordinary, maximum).expect("cap"), 60_000_000_000);
        assert_eq!(arm_cap_ns(websocket, minimum).expect("cap"), 43_000_000_000);
        assert_eq!(arm_cap_ns(websocket, maximum).expect("cap"), 75_000_000_000);
        assert_eq!(PRE_FREEZE_FLOOR_NS, 17_217_000_000_000);
    }

    #[test]
    fn runtime_projection_and_actual_caps_are_inclusive() {
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
        let n30 = project_runtime(30, PRE_FREEZE_FLOOR_NS, 0, &durations).expect("N=30 projection");
        assert_eq!(n30.future_arm_ns, 72_540_000_000_000);
        assert_eq!(n30.projected_total_ns, 98_757_000_000_000);
        assert!(n30.admissible);
        let n50 = project_runtime(50, PRE_FREEZE_FLOOR_NS, 0, &durations).expect("N=50 projection");
        assert_eq!(n50.future_arm_ns, 120_900_000_000_000);
        assert_eq!(n50.projected_total_ns, 147_117_000_000_000);
        assert!(n50.admissible);
        assert!(project_runtime(70, PRE_FREEZE_FLOOR_NS, 0, &durations).is_err());
        assert!(actual_runtime_allowed(ACTUAL_CAP_NS));
        assert!(!actual_runtime_allowed(ACTUAL_CAP_NS + 1));
    }
}
