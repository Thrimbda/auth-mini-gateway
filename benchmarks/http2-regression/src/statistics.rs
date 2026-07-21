use crate::rng::{bounded, SplitMix64};
use crate::schedule::PairIdentity;
use crate::schema::{
    hard_comparisons, ArmMetrics, AuthoritativeManifest, AuthoritativeRecord, BlockedCode,
    BlockedReason, ComparisonSpec, QualityEvidence, Verdict, ANALYSIS_SCHEMA,
};
use crate::seal::sha256_hex;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const BOOTSTRAP_REPLICATES: usize = 100_000;
pub const LOWER_PERCENTILE_INDEX: usize = 4_999;
pub const UPPER_PERCENTILE_INDEX: usize = 94_999;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Metric {
    Throughput,
    P99Latency,
    CpuPerOperation,
    PeakRss,
}

impl Metric {
    pub const ALL: [Self; 4] = [
        Self::Throughput,
        Self::P99Latency,
        Self::CpuPerOperation,
        Self::PeakRss,
    ];

    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Throughput => 0,
            Self::P99Latency => 1,
            Self::CpuPerOperation => 2,
            Self::PeakRss => 3,
        }
    }

    #[must_use]
    pub const fn favors_larger(self) -> bool {
        matches!(self, Self::Throughput)
    }

    #[must_use]
    pub fn order_limit(self) -> f64 {
        match self {
            Self::PeakRss => 1.05_f64.ln(),
            Self::Throughput | Self::P99Latency | Self::CpuPerOperation => 1.03_f64.ln(),
        }
    }

    #[must_use]
    pub fn precision_limit(self) -> f64 {
        match self {
            Self::Throughput => 1.02_f64.ln(),
            Self::P99Latency | Self::CpuPerOperation => 1.03_f64.ln(),
            Self::PeakRss => 1.05_f64.ln(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PairedMetrics {
    pub treatment: ArmMetrics,
    pub reference: ArmMetrics,
    pub treatment_before_reference: bool,
}

impl PairedMetrics {
    pub fn validate(self) -> Result<()> {
        self.treatment.validate()?;
        self.reference.validate()
    }

    fn log_ratios(self) -> [f64; 4] {
        [
            (self.treatment.throughput_ops_per_second / self.reference.throughput_ops_per_second)
                .ln(),
            ((self.treatment.p99_latency_ns as f64) / (self.reference.p99_latency_ns as f64)).ln(),
            (self.treatment.cpu_seconds_per_operation / self.reference.cpu_seconds_per_operation)
                .ln(),
            ((self.treatment.peak_rss_kib as f64) / (self.reference.peak_rss_kib as f64)).ln(),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricResult {
    pub metric: Metric,
    pub point_estimate: f64,
    pub point_estimate_bits: String,
    pub lower_bound: f64,
    pub lower_bound_bits: String,
    pub upper_bound: f64,
    pub upper_bound_bits: String,
    pub order_effect_log: f64,
    pub precision_width_log: f64,
    pub bound_gate_passed: bool,
    pub point_gate_passed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonResult {
    pub comparison_id: String,
    pub metrics: Vec<MetricResult>,
    pub blocked_reasons: Vec<BlockedReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerdictStage {
    EvidenceIntegrity,
    CandidateSafety,
    MeasurementQuality,
    Performance,
    GlobalPass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictDecision {
    pub verdict: Verdict,
    pub stage: VerdictStage,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisResult {
    pub schema: String,
    pub run_id: String,
    pub math_target_sha256: String,
    pub comparison_count: u32,
    pub scalar_gate_count: u32,
    pub comparisons: Vec<ComparisonResult>,
    pub decision: VerdictDecision,
}

/// Names every target property that can affect the RFC's pinned floating-point result bits.
/// This identity is deliberately part of sealed analysis input rather than an output label.
#[must_use]
pub fn math_target_identity() -> String {
    format!(
        "rustc-1.96.0/{}/{}/endian-{}/pointer-{}/fma-{}/f64-ieee754-v1",
        std::env::consts::ARCH,
        std::env::consts::OS,
        if cfg!(target_endian = "little") {
            "little"
        } else {
            "big"
        },
        usize::BITS,
        cfg!(target_feature = "fma")
    )
}

#[must_use]
pub fn math_target_sha256() -> String {
    sha256_hex(math_target_identity().as_bytes())
}

#[derive(Debug, Clone, PartialEq)]
pub struct BootstrapResult {
    pub point_log: [f64; 4],
    pub lower_log: [f64; 4],
    pub upper_log: [f64; 4],
    pub order_effect_log: [f64; 4],
}

pub fn nearest_rank_p99(latencies_ns: &[u64]) -> Result<u64> {
    if latencies_ns.is_empty() {
        return Err(Error::new("p99 requires at least one latency"));
    }
    if latencies_ns.contains(&0) {
        return Err(Error::new("latencies must be nonzero"));
    }
    let mut sorted = latencies_ns.to_vec();
    sorted.sort_unstable();
    let numerator = sorted
        .len()
        .checked_mul(99)
        .and_then(|value| value.checked_add(99))
        .ok_or_else(|| Error::new("p99 rank overflow"))?;
    let rank_one_based = numerator / 100;
    sorted
        .get(rank_one_based - 1)
        .copied()
        .ok_or_else(|| Error::new("p99 rank outside latency array"))
}

pub fn comparison_seed(analysis_config_sha256: &str, comparison_id: &str) -> Result<u64> {
    crate::schema::validate_sha256("analysis_config_sha256", analysis_config_sha256)?;
    let digest_bytes = decode_sha256(analysis_config_sha256)?;
    let mut hasher = Sha256::new();
    hasher.update(digest_bytes);
    hasher.update(comparison_id.as_bytes());
    let digest = hasher.finalize();
    Ok(u64::from_be_bytes(digest[..8].try_into().map_err(
        |_| Error::new("SHA-256 seed extraction failed"),
    )?))
}

pub fn order_stratified_bootstrap(pairs: &[PairedMetrics], seed: u64) -> Result<BootstrapResult> {
    if pairs.is_empty() || !pairs.len().is_multiple_of(2) {
        return Err(Error::new("bootstrap requires a nonempty even pair count"));
    }
    let mut before = Vec::with_capacity(pairs.len() / 2);
    let mut after = Vec::with_capacity(pairs.len() / 2);
    for pair in pairs {
        pair.validate()?;
        if pair.treatment_before_reference {
            before.push(pair.log_ratios());
        } else {
            after.push(pair.log_ratios());
        }
    }
    if before.len() != pairs.len() / 2 || after.len() != pairs.len() / 2 {
        return Err(Error::new(
            "bootstrap order strata are not exactly balanced",
        ));
    }
    let before_means = means(&before);
    let after_means = means(&after);
    let mut point_log = [0.0; 4];
    let mut order_effect_log = [0.0; 4];
    for metric in 0..4 {
        point_log[metric] = (before_means[metric] + after_means[metric]) / 2.0;
        order_effect_log[metric] = (before_means[metric] - after_means[metric]).abs();
    }

    let mut replicates: [Vec<f64>; 4] =
        std::array::from_fn(|_| Vec::with_capacity(BOOTSTRAP_REPLICATES));
    let mut rng = SplitMix64::new(seed);
    let stratum_len_u64 =
        u64::try_from(before.len()).map_err(|_| Error::new("stratum length overflow"))?;
    let denominator = before.len() as f64;
    for _ in 0..BOOTSTRAP_REPLICATES {
        let mut before_sum = [0.0; 4];
        let mut after_sum = [0.0; 4];
        for _ in 0..before.len() {
            let before_index = usize::try_from(bounded(&mut rng, stratum_len_u64)?)
                .map_err(|_| Error::new("bootstrap index overflow"))?;
            let after_index = usize::try_from(bounded(&mut rng, stratum_len_u64)?)
                .map_err(|_| Error::new("bootstrap index overflow"))?;
            for metric in 0..4 {
                before_sum[metric] += before[before_index][metric];
                after_sum[metric] += after[after_index][metric];
            }
        }
        for metric in 0..4 {
            replicates[metric].push(
                ((before_sum[metric] / denominator) + (after_sum[metric] / denominator)) / 2.0,
            );
        }
    }
    let mut lower_log = [0.0; 4];
    let mut upper_log = [0.0; 4];
    for metric in 0..4 {
        replicates[metric].sort_unstable_by(f64::total_cmp);
        lower_log[metric] = replicates[metric][LOWER_PERCENTILE_INDEX];
        upper_log[metric] = replicates[metric][UPPER_PERCENTILE_INDEX];
    }
    Ok(BootstrapResult {
        point_log,
        lower_log,
        upper_log,
        order_effect_log,
    })
}

pub fn order_stratum_standard_deviations(
    pairs: &[PairedMetrics],
    metric: Metric,
) -> Result<(f64, f64)> {
    if pairs.len() != 10 {
        return Err(Error::new(
            "Williams calibration variance requires exactly ten paired blocks",
        ));
    }
    let mut before = Vec::with_capacity(5);
    let mut after = Vec::with_capacity(5);
    for pair in pairs {
        pair.validate()?;
        let value = pair.log_ratios()[metric.index()];
        if pair.treatment_before_reference {
            before.push(value);
        } else {
            after.push(value);
        }
    }
    if before.len() != 5 || after.len() != 5 {
        return Err(Error::new(
            "Williams calibration variance strata must contain five AB and five BA pairs",
        ));
    }
    Ok((
        sample_standard_deviation(&before),
        sample_standard_deviation(&after),
    ))
}

fn sample_standard_deviation(values: &[f64]) -> f64 {
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let squared_residuals = values
        .iter()
        .map(|value| {
            let residual = *value - mean;
            residual * residual
        })
        .sum::<f64>();
    (squared_residuals / (values.len() - 1) as f64).sqrt()
}

fn means(values: &[[f64; 4]]) -> [f64; 4] {
    let mut result = [0.0; 4];
    for value in values {
        for metric in 0..4 {
            result[metric] += value[metric];
        }
    }
    let denominator = values.len() as f64;
    for value in &mut result {
        *value /= denominator;
    }
    result
}

pub fn gate_lower(observed: f64, threshold: f64) -> bool {
    observed.is_finite() && threshold.is_finite() && observed >= threshold
}

pub fn gate_upper(observed: f64, threshold: f64) -> bool {
    observed.is_finite() && threshold.is_finite() && observed <= threshold
}

#[must_use]
pub fn gate_lower_log(observed_log: f64, threshold: f64) -> bool {
    observed_log.is_finite()
        && threshold.is_finite()
        && threshold > 0.0
        && observed_log >= threshold.ln()
}

#[must_use]
pub fn gate_upper_log(observed_log: f64, threshold: f64) -> bool {
    observed_log.is_finite()
        && threshold.is_finite()
        && threshold > 0.0
        && observed_log <= threshold.ln()
}

#[must_use]
pub fn order_gate(metric: Metric, order_effect_log: f64) -> bool {
    order_effect_log.is_finite()
        && order_effect_log >= 0.0
        && order_effect_log <= metric.order_limit()
}

#[must_use]
pub fn precision_gate(metric: Metric, precision_width_log: f64) -> bool {
    precision_width_log.is_finite()
        && precision_width_log >= 0.0
        && precision_width_log <= metric.precision_limit()
}

pub fn analyze_comparison(
    spec: &ComparisonSpec,
    pairs: &[PairedMetrics],
    analysis_config_sha256: &str,
) -> Result<ComparisonResult> {
    spec.validate()?;
    let seed = comparison_seed(analysis_config_sha256, &spec.id)?;
    let bootstrap = order_stratified_bootstrap(pairs, seed)?;
    let mut metrics = Vec::with_capacity(4);
    let mut blocked_reasons = Vec::new();
    for metric in Metric::ALL {
        let index = metric.index();
        let point = bootstrap.point_log[index].exp();
        let lower = bootstrap.lower_log[index].exp();
        let upper = bootstrap.upper_log[index].exp();
        let precision = if metric.favors_larger() {
            bootstrap.point_log[index] - bootstrap.lower_log[index]
        } else {
            bootstrap.upper_log[index] - bootstrap.point_log[index]
        };
        if !order_gate(metric, bootstrap.order_effect_log[index]) {
            blocked_reasons.push(BlockedReason::new(
                BlockedCode::OrderEffect,
                format!(
                    "{} {:?} order effect exceeds its inclusive limit",
                    spec.id, metric
                ),
            ));
        }
        if !precision_gate(metric, precision) {
            blocked_reasons.push(BlockedReason::new(
                BlockedCode::Precision,
                format!(
                    "{} {:?} precision exceeds its inclusive limit",
                    spec.id, metric
                ),
            ));
        }
        let (bound_gate_passed, point_gate_passed) = match metric {
            Metric::Throughput => (
                gate_lower_log(bootstrap.lower_log[index], spec.thresholds.throughput_lower),
                spec.thresholds
                    .throughput_point_lower
                    .map(|threshold| gate_lower_log(bootstrap.point_log[index], threshold)),
            ),
            Metric::P99Latency => (
                gate_upper_log(bootstrap.upper_log[index], spec.thresholds.p99_upper),
                None,
            ),
            Metric::CpuPerOperation => (
                gate_upper_log(bootstrap.upper_log[index], spec.thresholds.cpu_upper),
                None,
            ),
            Metric::PeakRss => (
                gate_upper_log(bootstrap.upper_log[index], spec.thresholds.rss_upper),
                None,
            ),
        };
        metrics.push(MetricResult {
            metric,
            point_estimate: point,
            point_estimate_bits: bits(point),
            lower_bound: lower,
            lower_bound_bits: bits(lower),
            upper_bound: upper,
            upper_bound_bits: bits(upper),
            order_effect_log: bootstrap.order_effect_log[index],
            precision_width_log: precision,
            bound_gate_passed,
            point_gate_passed,
        });
    }
    Ok(ComparisonResult {
        comparison_id: spec.id.clone(),
        metrics,
        blocked_reasons,
    })
}

pub(crate) fn analyze_derived_manifest(
    manifest: &AuthoritativeManifest,
    pair_identities: &[PairIdentity],
) -> Result<AnalysisResult> {
    manifest.validate()?;
    if manifest.math_target_sha256 != math_target_sha256() {
        return Err(Error::new(
            "sealed deterministic math target identity mismatch",
        ));
    }
    let by_key = manifest.by_key();
    let expected_pair_count = hard_comparisons()
        .len()
        .checked_mul(usize::try_from(manifest.n).map_err(|_| Error::new("N does not fit usize"))?)
        .ok_or_else(|| Error::new("authoritative pair count overflow"))?;
    if pair_identities.len() != expected_pair_count {
        return Err(Error::new(
            "authoritative pair identity inventory is incomplete",
        ));
    }
    let mut pairs_by_key = BTreeMap::new();
    for identity in pair_identities {
        crate::schema::validate_identifier("pair comparison_id", &identity.comparison_id)?;
        crate::schema::validate_sha256(
            "pair treatment raw sha256",
            &identity.treatment_raw_sha256,
        )?;
        crate::schema::validate_sha256(
            "pair reference raw sha256",
            &identity.reference_raw_sha256,
        )?;
        if pairs_by_key
            .insert((identity.comparison_id.clone(), identity.round), identity)
            .is_some()
        {
            return Err(Error::new("duplicate authoritative pair identity"));
        }
    }
    let mut comparison_results = Vec::with_capacity(45);
    for spec in hard_comparisons() {
        let mut pairs = Vec::with_capacity(usize::try_from(manifest.n).unwrap_or(0));
        for round in 0..manifest.n {
            let treatment = by_key
                .get(&(round, spec.cell, spec.treatment))
                .ok_or_else(|| Error::new("missing treatment record"))?;
            let reference = by_key
                .get(&(round, spec.cell, spec.reference))
                .ok_or_else(|| Error::new("missing reference record"))?;
            let identity = pairs_by_key
                .get(&(spec.id.clone(), round))
                .ok_or_else(|| Error::new("missing sealed pair identity"))?;
            validate_pair_binding(&spec, treatment, reference, identity)?;
            pairs.push(PairedMetrics {
                treatment: treatment.metrics,
                reference: reference.metrics,
                treatment_before_reference: identity.treatment_before_reference,
            });
        }
        comparison_results.push(analyze_comparison(
            &spec,
            &pairs,
            &manifest.analysis_config_sha256,
        )?);
    }
    let scalar_gate_count: usize = comparison_results
        .iter()
        .flat_map(|comparison| comparison.metrics.iter())
        .map(|metric| 1 + usize::from(metric.point_gate_passed.is_some()))
        .sum();
    if scalar_gate_count != 190 {
        return Err(Error::new(
            "analysis did not produce exactly 190 hard scalar gates",
        ));
    }
    let decision = classify_verdict(&manifest.quality, &comparison_results);
    Ok(AnalysisResult {
        schema: ANALYSIS_SCHEMA.to_owned(),
        run_id: manifest.run_id.clone(),
        math_target_sha256: math_target_sha256(),
        comparison_count: 45,
        scalar_gate_count: 190,
        comparisons: comparison_results,
        decision,
    })
}

fn validate_pair_binding(
    spec: &ComparisonSpec,
    treatment: &AuthoritativeRecord,
    reference: &AuthoritativeRecord,
    identity: &PairIdentity,
) -> Result<()> {
    if identity.comparison_id != spec.id
        || identity.round != treatment.round
        || identity.round != reference.round
        || identity.cell != spec.cell
        || identity.treatment != spec.treatment
        || identity.reference != spec.reference
        || identity.treatment_observation_id != treatment.observation_id
        || identity.reference_observation_id != reference.observation_id
        || identity.treatment_raw_sha256 != treatment.raw_sha256
        || identity.reference_raw_sha256 != reference.raw_sha256
        || identity.treatment_position != treatment.position
        || identity.reference_position != reference.position
        || identity.treatment_before_reference != (treatment.position < reference.position)
    {
        return Err(Error::new(
            "sealed pair identity/position/raw hash differs from derived observations",
        ));
    }
    identity.validate()
}

pub(crate) fn classify_verdict(
    quality: &QualityEvidence,
    comparisons: &[ComparisonResult],
) -> VerdictDecision {
    let mut integrity = quality
        .integrity_blockers
        .iter()
        .map(|reason| reason.detail.clone())
        .collect::<Vec<_>>();
    integrity.extend(quality.baseline_semantic_failures.iter().cloned());
    if !integrity.is_empty() {
        return VerdictDecision {
            verdict: Verdict::Blocked,
            stage: VerdictStage::EvidenceIntegrity,
            reasons: integrity,
        };
    }
    if !quality.candidate_semantic_failures.is_empty() {
        return VerdictDecision {
            verdict: Verdict::Fail,
            stage: VerdictStage::CandidateSafety,
            reasons: quality.candidate_semantic_failures.clone(),
        };
    }
    let mut measurement = quality
        .measurement_blockers
        .iter()
        .map(|reason| reason.detail.clone())
        .collect::<Vec<_>>();
    measurement.extend(
        comparisons
            .iter()
            .flat_map(|comparison| comparison.blocked_reasons.iter())
            .map(|reason| reason.detail.clone()),
    );
    if !measurement.is_empty() {
        return VerdictDecision {
            verdict: Verdict::Blocked,
            stage: VerdictStage::MeasurementQuality,
            reasons: measurement,
        };
    }
    let failed = comparisons
        .iter()
        .flat_map(|comparison| {
            comparison
                .metrics
                .iter()
                .filter(|metric| {
                    !metric.bound_gate_passed
                        || metric.point_gate_passed.is_some_and(|passed| !passed)
                })
                .map(|metric| {
                    format!(
                        "{} {:?} hard gate failed",
                        comparison.comparison_id, metric.metric
                    )
                })
        })
        .collect::<Vec<_>>();
    if !failed.is_empty() {
        return VerdictDecision {
            verdict: Verdict::Fail,
            stage: VerdictStage::Performance,
            reasons: failed,
        };
    }
    VerdictDecision {
        verdict: Verdict::Pass,
        stage: VerdictStage::GlobalPass,
        reasons: Vec::new(),
    }
}

fn bits(value: f64) -> String {
    format!("0x{:016x}", value.to_bits())
}

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output[index] = (high << 4) | low;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{all_cells, Arm, BlockedCode, ComparisonKind, QualityEvidence};

    fn metric(value: f64) -> ArmMetrics {
        ArmMetrics {
            throughput_ops_per_second: value,
            p99_latency_ns: (value * 10_000.0) as u64,
            cpu_seconds_per_operation: value / 1000.0,
            peak_rss_kib: (value * 1000.0) as u64,
        }
    }

    fn clean_quality() -> QualityEvidence {
        QualityEvidence {
            integrity_blockers: Vec::new(),
            candidate_semantic_failures: Vec::new(),
            baseline_semantic_failures: Vec::new(),
            measurement_blockers: Vec::new(),
        }
    }

    fn passing_comparison() -> ComparisonResult {
        ComparisonResult {
            comparison_id: "fixture".to_owned(),
            metrics: Metric::ALL
                .into_iter()
                .map(|metric| MetricResult {
                    metric,
                    point_estimate: 1.0,
                    point_estimate_bits: bits(1.0),
                    lower_bound: 1.0,
                    lower_bound_bits: bits(1.0),
                    upper_bound: 1.0,
                    upper_bound_bits: bits(1.0),
                    order_effect_log: 0.0,
                    precision_width_log: 0.0,
                    bound_gate_passed: true,
                    point_gate_passed: None,
                })
                .collect(),
            blocked_reasons: Vec::new(),
        }
    }

    #[test]
    fn nearest_rank_p99_has_no_interpolation() {
        let values: Vec<_> = (1..=100).rev().collect();
        assert_eq!(nearest_rank_p99(&values).expect("p99"), 99);
        assert_eq!(nearest_rank_p99(&[7]).expect("singleton p99"), 7);
        assert!(nearest_rank_p99(&[]).is_err());
        assert!(nearest_rank_p99(&[0]).is_err());
    }

    #[test]
    fn percentile_indices_and_seed_are_golden() {
        assert_eq!(LOWER_PERCENTILE_INDEX, 4_999);
        assert_eq!(UPPER_PERCENTILE_INDEX, 94_999);
        assert_eq!(
            comparison_seed(
                "0000000000000000000000000000000000000000000000000000000000000000",
                "get-c16-c22-vs-c11"
            )
            .expect("seed"),
            10_343_602_386_143_478_008
        );
    }

    #[test]
    fn bootstrap_f64_bits_are_golden() {
        let pairs: Vec<_> = (0..10)
            .map(|index| PairedMetrics {
                treatment: metric(100.0 + f64::from(index)),
                reference: metric(100.0),
                treatment_before_reference: index % 2 == 0,
            })
            .collect();
        let result = order_stratified_bootstrap(&pairs, 0x1234_5678_9abc_def0).expect("bootstrap");
        assert_eq!(
            result.point_log.map(f64::to_bits),
            [
                4_586_449_848_332_246_543,
                4_586_449_848_332_246_543,
                4_586_449_848_332_246_518,
                4_586_449_848_332_246_543,
            ]
        );
        assert_eq!(
            result.lower_log.map(f64::to_bits),
            [
                4_584_337_247_501_534_268,
                4_584_337_247_501_534_268,
                4_584_337_247_501_534_232,
                4_584_337_247_501_534_268,
            ]
        );
        assert_eq!(
            result.upper_log.map(f64::to_bits),
            [
                4_588_395_915_015_173_600,
                4_588_395_915_015_173_600,
                4_588_395_915_015_173_570,
                4_588_395_915_015_173_600,
            ]
        );
    }

    #[test]
    fn calibration_variance_uses_five_observation_sample_sd_per_order_stratum() {
        let pairs: Vec<_> = (0..10)
            .map(|index| PairedMetrics {
                treatment: metric(105.0),
                reference: metric(100.0),
                treatment_before_reference: index % 2 == 0,
            })
            .collect();
        for metric in Metric::ALL {
            assert_eq!(
                order_stratum_standard_deviations(&pairs, metric)
                    .expect("balanced calibration strata"),
                (0.0, 0.0)
            );
        }
        let mut unbalanced = pairs;
        unbalanced[1].treatment_before_reference = true;
        assert!(order_stratum_standard_deviations(&unbalanced, Metric::Throughput).is_err());
    }

    #[test]
    fn inclusive_thresholds_pass_and_one_bit_beyond_fails() {
        for threshold in [0.95_f64, 0.97, 1.0] {
            assert!(gate_lower(threshold, threshold));
            assert!(!gate_lower(
                f64::from_bits(threshold.to_bits() - 1),
                threshold
            ));
            let threshold_log = threshold.ln();
            assert!(gate_lower_log(threshold_log, threshold));
            let one_bit_lower = if threshold_log > 0.0 {
                f64::from_bits(threshold_log.to_bits() - 1)
            } else if threshold_log < 0.0 {
                f64::from_bits(threshold_log.to_bits() + 1)
            } else {
                -f64::from_bits(1)
            };
            assert!(!gate_lower_log(one_bit_lower, threshold));
        }
        for threshold in [1.05_f64, 1.10, 1.15] {
            assert!(gate_upper(threshold, threshold));
            assert!(!gate_upper(
                f64::from_bits(threshold.to_bits() + 1),
                threshold
            ));
            let threshold_log = threshold.ln();
            assert!(gate_upper_log(threshold_log, threshold));
            let one_bit_upper = if threshold_log >= 0.0 {
                f64::from_bits(threshold_log.to_bits() + 1)
            } else {
                f64::from_bits(threshold_log.to_bits() - 1)
            };
            assert!(!gate_upper_log(one_bit_upper, threshold));
        }
    }

    #[test]
    fn h2_point_estimate_gate_is_independent_of_lower_bound() {
        let spec = hard_comparisons()
            .into_iter()
            .find(|spec| spec.kind == ComparisonKind::H2ToH2 && spec.cell == all_cells()[4])
            .expect("H2 comparison");
        assert_eq!(spec.thresholds.throughput_point_lower, Some(1.0));
        assert!(gate_lower(0.97, spec.thresholds.throughput_lower));
        assert!(!gate_lower(
            f64::from_bits(1.0_f64.to_bits() - 1),
            spec.thresholds.throughput_point_lower.unwrap_or_default()
        ));
    }

    #[test]
    fn verdict_precedence_is_integrity_safety_quality_performance_pass() {
        let mut quality = clean_quality();
        let mut comparison = passing_comparison();
        comparison.metrics[0].bound_gate_passed = false;
        quality
            .measurement_blockers
            .push(BlockedReason::new(BlockedCode::Noise, "noise"));
        quality
            .candidate_semantic_failures
            .push("candidate crash".to_owned());
        quality.integrity_blockers.push(BlockedReason::new(
            BlockedCode::EvidenceIntegrity,
            "hash mismatch",
        ));
        assert_eq!(
            classify_verdict(&quality, &[comparison.clone()]).stage,
            VerdictStage::EvidenceIntegrity
        );
        quality.integrity_blockers.clear();
        assert_eq!(
            classify_verdict(&quality, &[comparison.clone()]).stage,
            VerdictStage::CandidateSafety
        );
        quality.candidate_semantic_failures.clear();
        assert_eq!(
            classify_verdict(&quality, &[comparison.clone()]).stage,
            VerdictStage::MeasurementQuality
        );
        quality.measurement_blockers.clear();
        assert_eq!(
            classify_verdict(&quality, &[comparison.clone()]).stage,
            VerdictStage::Performance
        );
        comparison.metrics[0].bound_gate_passed = true;
        assert_eq!(
            classify_verdict(&quality, &[comparison]).stage,
            VerdictStage::GlobalPass
        );
    }

    #[test]
    fn order_and_precision_equalities_are_inclusive() {
        for metric in Metric::ALL {
            assert!(order_gate(metric, metric.order_limit()));
            assert!(!order_gate(
                metric,
                f64::from_bits(metric.order_limit().to_bits() + 1)
            ));
            assert!(precision_gate(metric, metric.precision_limit()));
            assert!(!precision_gate(
                metric,
                f64::from_bits(metric.precision_limit().to_bits() + 1)
            ));
            assert!(!order_gate(metric, f64::NAN));
            assert!(!precision_gate(metric, -0.0_f64 - f64::EPSILON));
        }
    }

    #[test]
    fn global_intersection_requires_every_one_of_190_scalars() {
        let mut comparisons = hard_comparisons()
            .into_iter()
            .map(|spec| {
                let mut result = passing_comparison();
                result.comparison_id = spec.id;
                if spec.thresholds.throughput_point_lower.is_some() {
                    result.metrics[0].point_gate_passed = Some(true);
                }
                result
            })
            .collect::<Vec<_>>();
        let scalar_count: usize = comparisons
            .iter()
            .flat_map(|comparison| &comparison.metrics)
            .map(|metric| 1 + usize::from(metric.point_gate_passed.is_some()))
            .sum();
        assert_eq!(scalar_count, 190);
        assert_eq!(
            classify_verdict(&clean_quality(), &comparisons).stage,
            VerdictStage::GlobalPass
        );
        comparisons[44].metrics[3].bound_gate_passed = false;
        assert_eq!(
            classify_verdict(&clean_quality(), &comparisons).stage,
            VerdictStage::Performance
        );
    }

    #[test]
    fn deterministic_math_target_identity_is_hash_bound() {
        let identity = math_target_identity();
        assert!(identity.contains(std::env::consts::ARCH));
        assert!(identity.contains("rustc-1.96.0"));
        assert_eq!(math_target_sha256(), sha256_hex(identity.as_bytes()));
        assert_ne!(
            math_target_sha256(),
            sha256_hex(format!("{identity}-different-default").as_bytes())
        );
    }

    #[test]
    fn pair_binding_rejects_position_and_shared_raw_hash_drift() {
        let spec = hard_comparisons()
            .into_iter()
            .find(|value| value.kind == ComparisonKind::CandidateH1)
            .expect("candidate H1 comparison");
        let record = |arm, position, observation: &str, hash: &str| AuthoritativeRecord {
            schema: crate::schema::EXECUTION_SCHEMA.to_owned(),
            run_id: "run".to_owned(),
            round: 0,
            cell: spec.cell,
            arm,
            position,
            observation_id: observation.to_owned(),
            raw_sha256: hash.to_owned(),
            metrics: metric(100.0),
        };
        let treatment = record(Arm::C11, 1, "candidate", &"11".repeat(32));
        let reference = record(Arm::B11, 0, "baseline", &"22".repeat(32));
        let identity = PairIdentity {
            comparison_id: spec.id.clone(),
            round: 0,
            cell: spec.cell,
            treatment: Arm::C11,
            reference: Arm::B11,
            treatment_observation_id: treatment.observation_id.clone(),
            reference_observation_id: reference.observation_id.clone(),
            treatment_raw_sha256: treatment.raw_sha256.clone(),
            reference_raw_sha256: reference.raw_sha256.clone(),
            treatment_position: 1,
            reference_position: 0,
            treatment_before_reference: false,
        };
        validate_pair_binding(&spec, &treatment, &reference, &identity)
            .expect("exact pair binding");
        let mut drifted = identity.clone();
        drifted.reference_raw_sha256 = "33".repeat(32);
        assert!(validate_pair_binding(&spec, &treatment, &reference, &drifted).is_err());
        drifted = identity;
        drifted.treatment_position = 2;
        assert!(validate_pair_binding(&spec, &treatment, &reference, &drifted).is_err());
    }
}
