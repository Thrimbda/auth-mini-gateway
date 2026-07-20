use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const EXECUTION_SCHEMA: &str = "amg-http2-perf/v1";
pub const BUNDLE_SCHEMA: &str = "amg-http2-perf-bundle/v1";
pub const DELIVERY_SCHEMA: &str = "amg-http2-perf-delivery/v1";
pub const ARCHIVE_SCHEMA: &str = "amg-http2-perf-canonical-ustar/v1";
pub const ARM_SCHEMA: &str = "amg-http2-perf/arm/v1";
pub const ANALYSIS_SCHEMA: &str = "amg-http2-perf/analysis/v1";
pub const INTENT_SCHEMA: &str = "amg-http2-perf/intent/v1";
pub const DESIGN_LOCK_SCHEMA: &str = "amg-http2-perf/design-lock/v1";
pub const CALIBRATION_MANIFEST_SCHEMA: &str = "amg-http2-perf/calibration-manifest/v1";
pub const ZSTD_PROGRAM_SCHEMA: &str = "amg-http2-perf/zstd-program/v1";
pub const RAW_LIMIT_SCHEMA: &str = "amg-http2-perf/raw-limits/v1";
pub const MACHINE_SCHEMA: &str = "amg-http2-perf/machine/v1";
pub const EXECUTION_STATE_SCHEMA: &str = "amg-http2-perf/execution-state/v1";

pub const BASELINE_COMMIT: &str = "28a4a273ea9b2725191dce35233f55972beaac6f";
pub const INITIAL_CANDIDATE_COMMIT: &str = "1f9821ab36f546ca0ffd9f6b83cb9a1f0af512ad";
pub const CHUNK_BYTES: u64 = 50_331_648;
pub const JSON_MAX_BYTES: u64 = 1_048_576;
pub const TASK_CAP_BYTES: u64 = 536_870_912;
pub const MAX_ARCHIVE_MEMBERS: u64 = TASK_CAP_BYTES / 512;
pub const ZSTD_SAFE_CHECKSUM: &str =
    "8f49c4d5f0abb602a93fb8736af2a4f4dd9512e36f7f570d66e65ff867ed3b9d";
pub const ZSTD_SYS_CHECKSUM: &str =
    "91e19ebc2adc8f83e43039e79776e3fda8ca919132d68a1fed6a5faca2683748";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Workload {
    Get,
    Upload1Mib,
    Download1Mib,
    Sse,
    WebSocket,
}

impl Workload {
    pub const ALL: [Self; 5] = [
        Self::Get,
        Self::Upload1Mib,
        Self::Download1Mib,
        Self::Sse,
        Self::WebSocket,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Upload1Mib => "upload-1mib",
            Self::Download1Mib => "download-1mib",
            Self::Sse => "sse",
            Self::WebSocket => "websocket",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    pub workload: Workload,
    pub concurrency: u16,
}

impl Cell {
    pub fn validate(self) -> Result<()> {
        if !matches!(self.concurrency, 1 | 16 | 64) {
            return Err(Error::new(format!(
                "unsupported concurrency {}",
                self.concurrency
            )));
        }
        Ok(())
    }

    #[must_use]
    pub fn id(self) -> String {
        format!("{}-c{}", self.workload.code(), self.concurrency)
    }
}

#[must_use]
pub fn all_cells() -> Vec<Cell> {
    Workload::ALL
        .into_iter()
        .flat_map(|workload| {
            [1_u16, 16, 64].into_iter().map(move |concurrency| Cell {
                workload,
                concurrency,
            })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Arm {
    B11,
    C11,
    C21,
    C12,
    C22,
}

impl Arm {
    pub const ALL: [Self; 5] = [Self::B11, Self::C11, Self::C21, Self::C12, Self::C22];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::B11 => "B11",
            Self::C11 => "C11",
            Self::C21 => "C21",
            Self::C12 => "C12",
            Self::C22 => "C22",
        }
    }

    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::B11 => 0,
            Self::C11 => 1,
            Self::C21 => 2,
            Self::C12 => 3,
            Self::C22 => 4,
        }
    }

    pub fn from_index(index: usize) -> Result<Self> {
        Self::ALL
            .get(index)
            .copied()
            .ok_or_else(|| Error::new(format!("invalid arm index {index}")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceClass {
    S,
    C,
    D,
    A,
}

impl EvidenceClass {
    #[must_use]
    pub const fn has_latencies(self) -> bool {
        matches!(self, Self::C | Self::A)
    }

    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::S => b'S',
            Self::C => b'C',
            Self::D => b'D',
            Self::A => b'A',
        }
    }

    pub fn from_byte(value: u8) -> Result<Self> {
        match value {
            b'S' => Ok(Self::S),
            b'C' => Ok(Self::C),
            b'D' => Ok(Self::D),
            b'A' => Ok(Self::A),
            _ => Err(Error::new(format!("invalid evidence class byte {value}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Calibration,
    Campaign,
    Diagnostic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RawProtocol {
    H1,
    H2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminalState {
    Pass,
    Fail,
    Blocked,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComparisonKind {
    CandidateH1,
    H2ToH1,
    H1ToH2,
    H2ToH2,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub throughput_lower: f64,
    pub throughput_point_lower: Option<f64>,
    pub p99_upper: f64,
    pub cpu_upper: f64,
    pub rss_upper: f64,
}

impl Thresholds {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("throughput_lower", self.throughput_lower),
            ("p99_upper", self.p99_upper),
            ("cpu_upper", self.cpu_upper),
            ("rss_upper", self.rss_upper),
        ] {
            validate_positive_finite(name, value)?;
        }
        if let Some(value) = self.throughput_point_lower {
            validate_positive_finite("throughput_point_lower", value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonSpec {
    pub id: String,
    pub cell: Cell,
    pub kind: ComparisonKind,
    pub treatment: Arm,
    pub reference: Arm,
    pub hard: bool,
    pub thresholds: Thresholds,
}

impl ComparisonSpec {
    pub fn validate(&self) -> Result<()> {
        self.cell.validate()?;
        if self.id != comparison_id(self.cell, self.kind) {
            return Err(Error::new(format!(
                "comparison ID does not match its domain: {}",
                self.id
            )));
        }
        let expected = comparison_arms(self.kind);
        if (self.treatment, self.reference) != expected {
            return Err(Error::new(format!(
                "comparison {} has the wrong treatment/reference",
                self.id
            )));
        }
        if self.kind != ComparisonKind::CandidateH1 && self.cell.concurrency == 1 && self.hard {
            return Err(Error::new("candidate H2/bridge C1 must be descriptive"));
        }
        self.thresholds.validate()
    }
}

fn comparison_arms(kind: ComparisonKind) -> (Arm, Arm) {
    match kind {
        ComparisonKind::CandidateH1 => (Arm::C11, Arm::B11),
        ComparisonKind::H2ToH1 => (Arm::C21, Arm::C11),
        ComparisonKind::H1ToH2 => (Arm::C12, Arm::C11),
        ComparisonKind::H2ToH2 => (Arm::C22, Arm::C11),
    }
}

#[must_use]
pub fn comparison_id(cell: Cell, kind: ComparisonKind) -> String {
    let suffix = match kind {
        ComparisonKind::CandidateH1 => "c11-vs-b11",
        ComparisonKind::H2ToH1 => "c21-vs-c11",
        ComparisonKind::H1ToH2 => "c12-vs-c11",
        ComparisonKind::H2ToH2 => "c22-vs-c11",
    };
    format!("{}-{suffix}", cell.id())
}

#[must_use]
pub fn hard_comparisons() -> Vec<ComparisonSpec> {
    let mut comparisons = Vec::with_capacity(45);
    for cell in all_cells() {
        comparisons.push(ComparisonSpec {
            id: comparison_id(cell, ComparisonKind::CandidateH1),
            cell,
            kind: ComparisonKind::CandidateH1,
            treatment: Arm::C11,
            reference: Arm::B11,
            hard: true,
            thresholds: Thresholds {
                throughput_lower: 0.97,
                throughput_point_lower: None,
                p99_upper: 1.05,
                cpu_upper: 1.05,
                rss_upper: 1.10,
            },
        });
        if cell.concurrency != 1 {
            for kind in [
                ComparisonKind::H2ToH1,
                ComparisonKind::H1ToH2,
                ComparisonKind::H2ToH2,
            ] {
                let (treatment, reference) = comparison_arms(kind);
                let is_h2 = kind == ComparisonKind::H2ToH2;
                comparisons.push(ComparisonSpec {
                    id: comparison_id(cell, kind),
                    cell,
                    kind,
                    treatment,
                    reference,
                    hard: true,
                    thresholds: Thresholds {
                        throughput_lower: if is_h2 { 0.97 } else { 0.95 },
                        throughput_point_lower: is_h2.then_some(1.0),
                        p99_upper: if is_h2 { 1.05 } else { 1.10 },
                        cpu_upper: 1.10,
                        rss_upper: 1.15,
                    },
                });
            }
        }
    }
    comparisons
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodecIdentity {
    pub binding_name: String,
    pub binding_version: String,
    pub native_name: String,
    pub native_version: String,
    pub native_version_number: u32,
    pub native_source_package: String,
    pub binding_package_checksum_sha256: String,
    pub native_package_checksum_sha256: String,
    pub nested_lock_sha256: String,
    pub codec_module_sha256: String,
    pub resolver_sha256: String,
    pub target_identity: String,
    pub parameter_program: String,
}

impl CodecIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.binding_name != "zstd-safe"
            || self.binding_version != "7.2.4"
            || self.native_name != "libzstd"
            || self.native_version != "1.5.7"
            || self.native_version_number != 10_507
            || self.native_source_package != "zstd-sys-2.0.16+zstd.1.5.7"
            || self.binding_package_checksum_sha256 != ZSTD_SAFE_CHECKSUM
            || self.native_package_checksum_sha256 != ZSTD_SYS_CHECKSUM
            || self.parameter_program != ZSTD_PROGRAM_SCHEMA
            || self.target_identity != crate::statistics::math_target_identity()
        {
            return Err(Error::new("unsupported Zstandard encoder identity"));
        }
        for (name, value) in [
            (
                "binding_package_checksum_sha256",
                &self.binding_package_checksum_sha256,
            ),
            (
                "native_package_checksum_sha256",
                &self.native_package_checksum_sha256,
            ),
            ("nested_lock_sha256", &self.nested_lock_sha256),
            ("codec_module_sha256", &self.codec_module_sha256),
            ("resolver_sha256", &self.resolver_sha256),
        ] {
            validate_non_placeholder_sha256(name, value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZstdParameterProgram {
    pub schema: String,
    pub format: String,
    pub compression_level: i32,
    pub nb_workers: u32,
    pub checksum_flag: bool,
    pub content_size_flag: bool,
    pub dict_id_flag: bool,
    pub long_distance_matching: bool,
    pub dictionary: Option<String>,
    pub resolver: String,
    pub explicit_parameter_ids: Vec<String>,
    pub feature_unavailable_parameter_ids: Vec<String>,
}

impl ZstdParameterProgram {
    #[must_use]
    pub fn fixed() -> Self {
        Self {
            schema: ZSTD_PROGRAM_SCHEMA.to_owned(),
            format: "zstd1".to_owned(),
            compression_level: 9,
            nb_workers: 0,
            checksum_flag: true,
            content_size_flag: true,
            dict_id_flag: false,
            long_distance_matching: false,
            dictionary: None,
            resolver: "amg-http2-perf/zstd-level9-resolver/v1".to_owned(),
            explicit_parameter_ids: [
                "compressionLevel",
                "windowLog",
                "hashLog",
                "chainLog",
                "searchLog",
                "minMatch",
                "targetLength",
                "strategy",
                "nbWorkers",
                "checksumFlag",
                "contentSizeFlag",
                "dictIDFlag",
                "enableLongDistanceMatching",
                "ldmHashLog",
                "ldmMinMatch",
                "ldmBucketSizeLog",
                "ldmHashRateLog",
                "jobSize",
                "overlapSizeLog",
                "targetCBlockSize",
                "pledgedSrcSize",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            feature_unavailable_parameter_ids: ["forceMaxWindow", "format", "srcSizeHint"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self != &Self::fixed() {
            return Err(Error::new(
                "Zstandard parameter program is not the RFC-fixed vector",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedZstdParameters {
    pub program: ZstdParameterProgram,
    pub pledged_source_size: u64,
    pub window_log: u32,
    pub hash_log: u32,
    pub chain_log: u32,
    pub search_log: u32,
    pub min_match: u32,
    pub target_length: u32,
    pub strategy: i32,
    pub ldm_hash_log: u32,
    pub ldm_min_match: u32,
    pub ldm_bucket_size_log: u32,
    pub ldm_hash_rate_log: u32,
    pub job_size: u32,
    pub overlap_size_log: u32,
    pub target_cblock_size: u32,
    pub parameter_map_sha256: String,
}

impl ResolvedZstdParameters {
    pub fn validate(&self) -> Result<()> {
        self.program.validate()?;
        if self.pledged_source_size > TASK_CAP_BYTES
            || self.window_log == 0
            || self.hash_log == 0
            || self.chain_log == 0
            || self.search_log == 0
            || self.min_match == 0
            || self.strategy != 6
        {
            return Err(Error::new(
                "resolved Zstandard parameter map is out of bounds",
            ));
        }
        validate_non_placeholder_sha256("parameter_map_sha256", &self.parameter_map_sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLimits {
    pub schema: String,
    pub json_max_bytes: u64,
    pub chunk_bytes: u64,
    pub task_cap_bytes: u64,
    pub canonical_buffer_bytes: u64,
}

impl RawLimits {
    #[must_use]
    pub fn fixed() -> Self {
        Self {
            schema: RAW_LIMIT_SCHEMA.to_owned(),
            json_max_bytes: JSON_MAX_BYTES,
            chunk_bytes: CHUNK_BYTES,
            task_cap_bytes: TASK_CAP_BYTES,
            canonical_buffer_bytes: 1_048_576,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self != &Self::fixed() {
            return Err(Error::new("raw limits differ from the fixed RFC limits"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub schema: String,
    pub evidence_id: String,
    pub evidence_kind: EvidenceKind,
    pub baseline_commit: String,
    pub candidate_commit: String,
    pub campaign_seed: u64,
    pub encoder: CodecIdentity,
    pub producer_executable_sha256: String,
    pub zstd: ZstdParameterProgram,
    pub raw_limits: RawLimits,
}

impl Intent {
    pub fn validate(&self) -> Result<()> {
        if self.schema != INTENT_SCHEMA {
            return Err(Error::new("unsupported intent schema"));
        }
        validate_identifier("evidence_id", &self.evidence_id)?;
        validate_commit("baseline_commit", &self.baseline_commit)?;
        validate_commit("candidate_commit", &self.candidate_commit)?;
        if self.baseline_commit != BASELINE_COMMIT {
            return Err(Error::new(
                "intent baseline is not the immutable baseline commit",
            ));
        }
        self.encoder.validate()?;
        validate_non_placeholder_sha256(
            "producer_executable_sha256",
            &self.producer_executable_sha256,
        )?;
        self.zstd.validate()?;
        self.raw_limits.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundPlan {
    pub round: u32,
    pub row: u8,
    pub arm_order: Vec<Arm>,
    pub cells: Vec<Cell>,
}

impl RoundPlan {
    pub fn validate(&self) -> Result<()> {
        if self.row >= 10 {
            return Err(Error::new(format!("invalid Williams row {}", self.row)));
        }
        let canonical = crate::schedule::williams_rows()[usize::from(self.row)].to_vec();
        if self.arm_order != canonical {
            return Err(Error::new(
                "round arm positions do not match the named Williams row",
            ));
        }
        let unique_arms: BTreeSet<_> = self.arm_order.iter().copied().collect();
        if self.arm_order.len() != 5 || unique_arms.len() != 5 {
            return Err(Error::new(
                "round does not contain five unique arm positions",
            ));
        }
        if self.cells.len() != 15 {
            return Err(Error::new("round does not contain all 15 cells"));
        }
        let expected: BTreeSet<_> = all_cells().into_iter().collect();
        let actual: BTreeSet<_> = self.cells.iter().copied().collect();
        if actual != expected || actual.len() != self.cells.len() {
            return Err(Error::new("round cell order is incomplete or duplicated"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignLock {
    pub schema: String,
    pub intent_sha256: String,
    pub calibration_plan_sha256: String,
    pub selected_n: u32,
    pub schedule_seed: u64,
    pub rounds: Vec<RoundPlan>,
    pub comparisons: Vec<ComparisonSpec>,
}

impl DesignLock {
    pub fn validate(&self) -> Result<()> {
        if self.schema != DESIGN_LOCK_SCHEMA {
            return Err(Error::new("unsupported design-lock schema"));
        }
        validate_non_placeholder_sha256("intent_sha256", &self.intent_sha256)?;
        validate_non_placeholder_sha256("calibration_plan_sha256", &self.calibration_plan_sha256)?;
        if !matches!(self.selected_n, 30 | 50) {
            return Err(Error::new(
                "design-lock N must be runtime-admissible 30 or 50; N=70/100 stop before a design lock",
            ));
        }
        if self.rounds.len() != usize::try_from(self.selected_n).unwrap_or(usize::MAX) {
            return Err(Error::new(
                "design-lock round count does not equal selected N",
            ));
        }
        for (index, round) in self.rounds.iter().enumerate() {
            if round.round != u32::try_from(index).unwrap_or(u32::MAX) {
                return Err(Error::new("design-lock rounds are not contiguous"));
            }
            round.validate()?;
        }
        let regenerated = crate::schedule::generate_rounds(self.schedule_seed, self.selected_n)?;
        if self.rounds != regenerated {
            return Err(Error::new(
                "design-lock schedule does not regenerate from its seed and N",
            ));
        }
        let expected = hard_comparisons();
        if self.comparisons != expected {
            return Err(Error::new(
                "design-lock hard comparison matrix is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CalibrationPhase {
    Scout,
    Williams,
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationRecord {
    pub schema: String,
    pub calibration_id: String,
    pub phase: CalibrationPhase,
    pub class: EvidenceClass,
    pub cell: Cell,
    pub arm: Option<Arm>,
    pub target: Option<u64>,
    pub elapsed_ns: u64,
    pub gateway_ticks: u64,
    pub started_operations: u64,
    pub deadline_completions: u64,
    pub drained_operations: u64,
    pub lane_quotas: Vec<u64>,
    pub lane_completions: Vec<u64>,
    pub endpoint_hashes_match: bool,
    pub process_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationManifest {
    pub schema: String,
    pub calibration_id: String,
    pub records: Vec<CalibrationRecord>,
}

impl CalibrationManifest {
    pub fn validate(&self) -> Result<()> {
        if self.schema != CALIBRATION_MANIFEST_SCHEMA || self.records.is_empty() {
            return Err(Error::new("unsupported or empty calibration manifest"));
        }
        validate_identifier("calibration_id", &self.calibration_id)?;
        let mut identities = BTreeSet::new();
        for record in &self.records {
            record.validate()?;
            if record.calibration_id != self.calibration_id {
                return Err(Error::new(
                    "calibration record ID differs from its manifest",
                ));
            }
            let key = (
                record.phase,
                record.cell,
                record.arm,
                record.target,
                record.process_identity.clone(),
            );
            if !identities.insert(key) {
                return Err(Error::new("duplicate calibration manifest record"));
            }
        }
        Ok(())
    }
}

impl CalibrationRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema != EXECUTION_SCHEMA {
            return Err(Error::new("unsupported calibration record schema"));
        }
        validate_identifier("calibration_id", &self.calibration_id)?;
        self.cell.validate()?;
        if self.elapsed_ns == 0 || !self.endpoint_hashes_match || self.process_identity.is_empty() {
            return Err(Error::new(
                "invalid calibration timing, endpoint, or process evidence",
            ));
        }
        if self.lane_quotas.len() != usize::from(self.cell.concurrency)
            || self.lane_completions.len() != self.lane_quotas.len()
        {
            return Err(Error::new(
                "calibration lane evidence does not match concurrency",
            ));
        }
        match self.phase {
            CalibrationPhase::Scout => {
                if self.class != EvidenceClass::S || self.arm.is_none() || self.target.is_none() {
                    return Err(Error::new("scout record has invalid class/arm/target"));
                }
                let target = self.target.unwrap_or_default();
                let quota_total = self
                    .lane_quotas
                    .iter()
                    .try_fold(0_u64, |total, value| total.checked_add(*value));
                let completion_total = self
                    .lane_completions
                    .iter()
                    .try_fold(0_u64, |total, value| total.checked_add(*value));
                if quota_total != Some(target)
                    || completion_total != Some(target)
                    || self.lane_completions != self.lane_quotas
                    || self.started_operations != target
                    || self.deadline_completions != target
                    || self.drained_operations != target
                {
                    return Err(Error::new("scout quota/count evidence is inconsistent"));
                }
            }
            CalibrationPhase::Williams => {
                if self.class != EvidenceClass::C || self.arm.is_none() || self.target.is_some() {
                    return Err(Error::new("Williams record has invalid class/arm/target"));
                }
            }
            CalibrationPhase::Direct => {
                if self.class != EvidenceClass::D || self.arm.is_some() || self.target.is_some() {
                    return Err(Error::new("direct record has invalid class/arm/target"));
                }
            }
        }
        if self.deadline_completions > self.started_operations
            || self.started_operations > self.drained_operations
        {
            return Err(Error::new("calibration operation counts are not ordered"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmMetrics {
    pub throughput_ops_per_second: f64,
    pub p99_latency_ns: u64,
    pub cpu_seconds_per_operation: f64,
    pub peak_rss_kib: u64,
}

impl ArmMetrics {
    pub fn validate(self) -> Result<()> {
        validate_positive_finite("throughput", self.throughput_ops_per_second)?;
        validate_positive_finite("cpu_seconds_per_operation", self.cpu_seconds_per_operation)?;
        if self.p99_latency_ns == 0 || self.peak_rss_kib == 0 {
            return Err(Error::new("p99 and RSS metrics must be nonzero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeRecord {
    pub schema: String,
    pub run_id: String,
    pub round: u32,
    pub cell: Cell,
    pub arm: Arm,
    pub position: u8,
    pub observation_id: String,
    pub raw_sha256: String,
    pub metrics: ArmMetrics,
}

impl AuthoritativeRecord {
    pub fn validate(&self, n: u32) -> Result<()> {
        if self.schema != EXECUTION_SCHEMA || self.round >= n || self.position >= 5 {
            return Err(Error::new(
                "authoritative record has invalid schema/round/position",
            ));
        }
        validate_identifier("run_id", &self.run_id)?;
        validate_identifier("observation_id", &self.observation_id)?;
        validate_non_placeholder_sha256("raw_sha256", &self.raw_sha256)?;
        self.cell.validate()?;
        self.metrics.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockedCode {
    EvidenceIntegrity,
    BaselineSemantic,
    Noise,
    Headroom,
    OrderEffect,
    Precision,
    RuntimeProjection,
    RuntimeActual,
    StorageProjection,
    StorageActual,
    IncompleteMatrix,
    InvalidCalibration,
    EncoderMismatch,
    UnsafePath,
    SecretEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedReason {
    pub code: BlockedCode,
    pub detail: String,
}

impl BlockedReason {
    #[must_use]
    pub fn new(code: BlockedCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.detail.is_empty() || self.detail.len() > 4096 {
            return Err(Error::new("blocked reason detail is empty or too long"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityEvidence {
    pub integrity_blockers: Vec<BlockedReason>,
    pub candidate_semantic_failures: Vec<String>,
    pub baseline_semantic_failures: Vec<String>,
    pub measurement_blockers: Vec<BlockedReason>,
}

impl QualityEvidence {
    pub fn validate(&self) -> Result<()> {
        for reason in self
            .integrity_blockers
            .iter()
            .chain(self.measurement_blockers.iter())
        {
            reason.validate()?;
        }
        if self
            .candidate_semantic_failures
            .iter()
            .chain(self.baseline_semantic_failures.iter())
            .any(String::is_empty)
        {
            return Err(Error::new("empty semantic failure"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeManifest {
    pub schema: String,
    pub run_id: String,
    pub design_lock_sha256: String,
    pub analysis_config_sha256: String,
    pub math_target_sha256: String,
    pub n: u32,
    pub observations: Vec<AuthoritativeRecord>,
    pub quality: QualityEvidence,
}

impl AuthoritativeManifest {
    pub fn validate(&self) -> Result<()> {
        if self.schema != EXECUTION_SCHEMA || !matches!(self.n, 30 | 50) {
            return Err(Error::new("authoritative manifest schema/N is invalid"));
        }
        validate_identifier("run_id", &self.run_id)?;
        validate_non_placeholder_sha256("design_lock_sha256", &self.design_lock_sha256)?;
        validate_non_placeholder_sha256("analysis_config_sha256", &self.analysis_config_sha256)?;
        validate_non_placeholder_sha256("math_target_sha256", &self.math_target_sha256)?;
        if self.math_target_sha256 != crate::statistics::math_target_sha256() {
            return Err(Error::new(
                "authoritative manifest math target differs from this verifier",
            ));
        }
        self.quality.validate()?;
        let expected_count = 75_u32
            .checked_mul(self.n)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| Error::new("authoritative matrix count overflow"))?;
        if self.observations.len() != expected_count {
            return Err(Error::new(format!(
                "authoritative matrix has {} records, expected {expected_count}",
                self.observations.len()
            )));
        }
        let mut identities = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for record in &self.observations {
            record.validate(self.n)?;
            if record.run_id != self.run_id {
                return Err(Error::new("record run ID differs from manifest"));
            }
            if !identities.insert(record.observation_id.clone()) {
                return Err(Error::new("duplicate authoritative observation ID"));
            }
            if !keys.insert((record.round, record.cell, record.arm)) {
                return Err(Error::new("duplicate authoritative round/cell/arm"));
            }
        }
        for round in 0..self.n {
            for cell in all_cells() {
                for arm in Arm::ALL {
                    if !keys.contains(&(round, cell, arm)) {
                        return Err(Error::new("authoritative matrix is incomplete"));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn by_key(&self) -> BTreeMap<(u32, Cell, Arm), &AuthoritativeRecord> {
        self.observations
            .iter()
            .map(|record| ((record.round, record.cell, record.arm), record))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawArmMetadata {
    pub schema: String,
    pub evidence_id: String,
    pub run_id: String,
    pub class: EvidenceClass,
    pub cell: Cell,
    pub arm: Option<Arm>,
    pub direct_protocol: Option<RawProtocol>,
    pub ordinal: u64,
    pub round: Option<u32>,
    pub row: Option<u8>,
    pub position: Option<u8>,
    pub epoch: Option<u32>,
    pub scout_target: Option<u64>,
    pub observation_id: String,
    pub started_operations: u64,
    pub deadline_completions: u64,
    pub drained_operations: u64,
    pub latency_record_ceiling: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub materialization_sha256: Option<String>,
}

impl RawArmMetadata {
    pub fn validate(&self) -> Result<()> {
        if self.schema != ARM_SCHEMA {
            return Err(Error::new("unsupported raw arm metadata schema"));
        }
        self.cell.validate()?;
        validate_identifier("evidence_id", &self.evidence_id)?;
        validate_identifier("run_id", &self.run_id)?;
        validate_identifier("observation_id", &self.observation_id)?;
        match self.class {
            EvidenceClass::S => {
                if self.arm.is_none()
                    || self.direct_protocol.is_some()
                    || self.scout_target.is_none()
                    || self.round.is_some()
                    || self.row.is_some()
                    || self.position.is_some()
                    || self.epoch.is_some()
                {
                    return Err(Error::new("invalid scout metadata domain"));
                }
            }
            EvidenceClass::C => {
                if self.arm.is_none()
                    || self.direct_protocol.is_some()
                    || self.row.is_none_or(|row| row >= 10)
                    || self.position.is_none_or(|position| position >= 5)
                    || self.round.is_some()
                    || self.epoch.is_some()
                    || self.scout_target.is_some()
                {
                    return Err(Error::new("invalid Williams metadata domain"));
                }
            }
            EvidenceClass::D => {
                if self.arm.is_some()
                    || self.direct_protocol.is_none()
                    || self.epoch.is_none()
                    || self.round.is_some()
                    || self.row.is_some()
                    || self.position.is_some()
                    || self.scout_target.is_some()
                {
                    return Err(Error::new("invalid direct metadata domain"));
                }
            }
            EvidenceClass::A => {
                if self.arm.is_none()
                    || self.direct_protocol.is_some()
                    || self.round.is_none()
                    || self.row.is_none_or(|row| row >= 10)
                    || self.position.is_none_or(|position| position >= 5)
                    || self.epoch.is_some()
                    || self.scout_target.is_some()
                {
                    return Err(Error::new("invalid authoritative metadata domain"));
                }
            }
        }
        if self.deadline_completions > self.started_operations
            || self.started_operations > self.drained_operations
        {
            return Err(Error::new("raw operation counts are not ordered"));
        }
        if self.drained_operations != self.started_operations {
            return Err(Error::new(
                "raw drained operations must equal started operations",
            ));
        }
        if self.started_operations > u64::MAX / 1_048_576 {
            return Err(Error::new(
                "raw operation count exceeds checked workload-byte arithmetic",
            ));
        }
        if self.class.has_latencies() {
            if self.drained_operations > self.latency_record_ceiling
                || self.latency_record_ceiling > (TASK_CAP_BYTES - 32) / 8
            {
                return Err(Error::new(
                    "latency count or sealed ceiling exceeds its bound",
                ));
            }
        } else if self.latency_record_ceiling != 0 {
            return Err(Error::new("S/D evidence must have a zero latency ceiling"));
        }
        if let Some(hash) = &self.materialization_sha256 {
            validate_non_placeholder_sha256("materialization evidence", hash)?;
            if self.class == EvidenceClass::D || self.cell.workload == Workload::WebSocket {
                return Err(Error::new(
                    "direct/WebSocket raw evidence cannot bind ordinary authenticated materialization",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Pass,
    Fail,
    Blocked,
}

pub fn validate_sha256(name: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::new(format!(
            "{name} is not a lowercase SHA-256 hex digest"
        )));
    }
    Ok(())
}

pub fn validate_non_placeholder_sha256(name: &str, value: &str) -> Result<()> {
    validate_sha256(name, value)?;
    if value.bytes().all(|byte| byte == b'0') || value.bytes().all(|byte| byte == b'f') {
        return Err(Error::new(format!(
            "{name} is a placeholder SHA-256 digest"
        )));
    }
    Ok(())
}

pub fn validate_commit(name: &str, value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::new(format!(
            "{name} is not a full lowercase Git object ID"
        )));
    }
    Ok(())
}

pub fn validate_identifier(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 200
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(Error::new(format!(
            "{name} is not a safe bounded identifier"
        )));
    }
    Ok(())
}

fn validate_positive_finite(name: &str, value: f64) -> Result<()> {
    if !value.is_finite() || value <= 0.0 {
        return Err(Error::new(format!("{name} must be positive and finite")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;
    use crate::schedule;

    #[test]
    fn hard_matrix_has_45_comparisons_and_190_scalars() {
        let comparisons = hard_comparisons();
        assert_eq!(comparisons.len(), 45);
        assert!(comparisons
            .iter()
            .all(|comparison| comparison.validate().is_ok()));
        let scalars: usize = comparisons
            .iter()
            .map(|comparison| {
                4 + usize::from(comparison.thresholds.throughput_point_lower.is_some())
            })
            .sum();
        assert_eq!(scalars, 190);
    }

    #[test]
    fn intent_strictly_rejects_unknown_fields_and_bad_versions() {
        let fixture = Intent {
            schema: "wrong".to_owned(),
            evidence_id: "x".to_owned(),
            evidence_kind: EvidenceKind::Calibration,
            baseline_commit: BASELINE_COMMIT.to_owned(),
            candidate_commit: INITIAL_CANDIDATE_COMMIT.to_owned(),
            campaign_seed: 1,
            encoder: crate::codec::current_identity(),
            producer_executable_sha256: crate::codec::current_executable_sha256()
                .expect("test executable hash"),
            zstd: ZstdParameterProgram::fixed(),
            raw_limits: RawLimits::fixed(),
        };
        let bytes = json::canonical_bytes(&fixture).expect("canonical fixture");
        let intent: Intent = json::from_slice_strict(&bytes).expect("strict shape");
        assert!(intent.validate().is_err());

        let mut value = serde_json::to_value(fixture).expect("intent value");
        value
            .as_object_mut()
            .expect("intent object")
            .insert("unknown".to_owned(), serde_json::Value::from(1));
        assert!(json::from_slice_strict::<Intent>(
            &serde_json::to_vec(&value).expect("unknown fixture")
        )
        .is_err());
    }

    #[test]
    fn raw_class_latency_contract_is_strict() {
        let mut metadata = RawArmMetadata {
            schema: ARM_SCHEMA.to_owned(),
            evidence_id: "fixture-evidence".to_owned(),
            run_id: "fixture-evidence".to_owned(),
            class: EvidenceClass::S,
            cell: Cell {
                workload: Workload::Get,
                concurrency: 1,
            },
            arm: Some(Arm::B11),
            direct_protocol: None,
            ordinal: 0,
            round: None,
            row: None,
            position: None,
            epoch: None,
            scout_target: Some(10),
            observation_id: "fixture-observation".to_owned(),
            started_operations: 10,
            deadline_completions: 10,
            drained_operations: 10,
            latency_record_ceiling: 0,
            materialization_sha256: None,
        };
        assert!(metadata.validate().is_ok());
        metadata.latency_record_ceiling = 10;
        assert!(metadata.validate().is_err());
        metadata.class = EvidenceClass::A;
        metadata.scout_target = None;
        metadata.round = Some(0);
        metadata.row = Some(0);
        metadata.position = Some(0);
        assert!(metadata.validate().is_ok());
        metadata.drained_operations = 11;
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn design_lock_and_authoritative_records_reject_drifted_domain_data() {
        let mut design = DesignLock {
            schema: DESIGN_LOCK_SCHEMA.to_owned(),
            intent_sha256: "01".repeat(32),
            calibration_plan_sha256: "11".repeat(32),
            selected_n: 30,
            schedule_seed: 9,
            rounds: schedule::generate_rounds(9, 30).expect("rounds"),
            comparisons: hard_comparisons(),
        };
        assert!(design.validate().is_ok());
        design.rounds[0].cells[0] = design.rounds[0].cells[1];
        assert!(design.validate().is_err());

        let record = AuthoritativeRecord {
            schema: EXECUTION_SCHEMA.to_owned(),
            run_id: "run-fixture".to_owned(),
            round: 0,
            cell: all_cells()[0],
            arm: Arm::B11,
            position: 0,
            observation_id: "obs-fixture".to_owned(),
            raw_sha256: "01".repeat(32),
            metrics: ArmMetrics {
                throughput_ops_per_second: 1.0,
                p99_latency_ns: 1,
                cpu_seconds_per_operation: 1.0,
                peak_rss_kib: 1,
            },
        };
        assert!(record.validate(30).is_ok());
        let mut wrong_round = record;
        wrong_round.round = 30;
        assert!(wrong_round.validate(30).is_err());
    }

    #[test]
    fn scout_count_overflow_and_raw_workload_count_overflow_fail_closed() {
        let record = CalibrationRecord {
            schema: EXECUTION_SCHEMA.to_owned(),
            calibration_id: "calibration-fixture".to_owned(),
            phase: CalibrationPhase::Scout,
            class: EvidenceClass::S,
            cell: Cell {
                workload: Workload::Get,
                concurrency: 16,
            },
            arm: Some(Arm::B11),
            target: Some(u64::MAX),
            elapsed_ns: 1,
            gateway_ticks: 100,
            started_operations: u64::MAX,
            deadline_completions: u64::MAX,
            drained_operations: u64::MAX,
            lane_quotas: {
                let mut values = vec![0; 16];
                values[0] = u64::MAX;
                values[1] = 1;
                values
            },
            lane_completions: {
                let mut values = vec![0; 16];
                values[0] = u64::MAX;
                values[1] = 1;
                values
            },
            endpoint_hashes_match: true,
            process_identity: "process".to_owned(),
        };
        assert!(record.validate().is_err());

        let mut metadata = RawArmMetadata {
            schema: ARM_SCHEMA.to_owned(),
            evidence_id: "fixture".to_owned(),
            run_id: "fixture".to_owned(),
            class: EvidenceClass::S,
            cell: Cell {
                workload: Workload::Upload1Mib,
                concurrency: 1,
            },
            arm: Some(Arm::B11),
            direct_protocol: None,
            ordinal: 0,
            round: None,
            row: None,
            position: None,
            epoch: None,
            scout_target: Some(u64::MAX),
            observation_id: "observation".to_owned(),
            started_operations: u64::MAX,
            deadline_completions: u64::MAX,
            drained_operations: u64::MAX,
            latency_record_ceiling: 0,
            materialization_sha256: None,
        };
        assert!(metadata.validate().is_err());
        metadata.started_operations = 1;
        metadata.deadline_completions = 1;
        metadata.drained_operations = 1;
        metadata.scout_target = Some(1);
        assert!(metadata.validate().is_ok());
    }
}
