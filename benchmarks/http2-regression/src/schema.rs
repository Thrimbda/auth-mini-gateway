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
pub const COORDINATED_INTENT_SCHEMA: &str = "amg-http2-perf/intent/v2";
pub const DESIGN_LOCK_SCHEMA: &str = "amg-http2-perf/design-lock/v1";
pub const CALIBRATION_PLAN_SCHEMA: &str = "amg-http2-perf/calibration-plan/v1";
pub const CALIBRATION_MANIFEST_SCHEMA: &str = "amg-http2-perf/calibration-manifest/v1";
pub const CAMPAIGN_BINDING_SCHEMA: &str = "amg-http2-perf/campaign-binding/v1";
pub const CAMPAIGN_MANIFEST_SCHEMA: &str = "amg-http2-perf/campaign-manifest/v1";
pub const CAMPAIGN_PLAN_SCHEMA: &str = "amg-http2-perf/campaign-plan/v1";
pub const ACCEPTED_SIGNATURE_SCHEMA: &str = "amg-http2-perf/accepted-signature/v1";
pub const AUTHORITATIVE_PARAMETERS_SCHEMA: &str = "amg-http2-perf/authoritative-parameters/v1";
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalInputManifest {
    pub schema: String,
    pub build_set_sha256: String,
    pub baseline_commit: String,
    pub candidate_commit: String,
    pub read_only_surfaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockBoundaryManifest {
    pub schema: String,
    pub realtime_provenance: Vec<String>,
    pub monotonic_destinations: Vec<String>,
    pub boottime_destinations: Vec<String>,
    pub prohibited_realtime_destinations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkConfigManifest {
    pub schema: String,
    pub fixed_values: BTreeMap<String, String>,
    pub arm_local_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusManifest {
    pub schema: String,
    pub seed_sha256: String,
    pub corpus_sha256: String,
    pub corpus_bytes: u64,
    pub chunk_bytes: u64,
    pub chunk_count: u64,
    pub sse_events: u64,
    pub sse_data_bytes: u64,
    pub payload_domain: String,
    pub websocket_mask_domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionPolicyEntry {
    pub protocol: RawProtocol,
    pub workload: Workload,
    pub policy: String,
    pub operation_boundary: String,
    pub reconciliation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionPolicyManifest {
    pub schema: String,
    pub entries: Vec<ConnectionPolicyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustBoundaryManifest {
    pub schema: String,
    pub external_inputs: ExternalInputManifest,
    pub clocks: ClockBoundaryManifest,
    pub config: BenchmarkConfigManifest,
    pub corpus: CorpusManifest,
    pub connection_policies: ConnectionPolicyManifest,
}

impl TrustBoundaryManifest {
    pub fn coordinated(
        build_set_sha256: String,
        baseline_commit: String,
        candidate_commit: String,
    ) -> Result<Self> {
        let mut fixed_values = BTreeMap::new();
        for (name, value) in [
            ("HOST", "127.0.0.1"),
            ("GATEWAY_PUBLIC_BASE_URL", "http://public.example"),
            ("COOKIE_SECURE", "false"),
            ("COOKIE_SAME_SITE", "lax"),
            ("SESSION_TTL_SECONDS", "604800"),
            ("SESSION_ABSOLUTE_TTL_SECONDS", "2592000"),
            ("SESSION_TOUCH_INTERVAL_SECONDS", "604800"),
            ("REFRESH_SKEW_SECONDS", "60"),
            ("ALLOW_USER_IDS", "bench-user"),
            ("TRUSTED_PROXY_CIDRS", ""),
            ("GATEWAY_MAX_DOWNSTREAM_CONNECTIONS", "256"),
            ("GATEWAY_MAX_ACTIVE_UPSTREAMS", "128"),
            ("GATEWAY_MAX_BLOCKING_RESOLVERS", "8"),
            ("NO_COLOR", "1"),
        ] {
            fixed_values.insert(name.to_owned(), value.to_owned());
        }
        let corpus = crate::topology::Corpus::fixed();
        let mut entries = Vec::new();
        for protocol in [RawProtocol::H1, RawProtocol::H2] {
            for workload in Workload::ALL {
                let (policy, operation_boundary, reconciliation) =
                    match (protocol, workload) {
                        (RawProtocol::H1, Workload::Upload1Mib) => (
                            "fresh-h1-per-operation",
                            "connect-through-close-eof",
                            "connections=starts=requests=responses=close=eos=eof; reuse=retry=reconnect=0",
                        ),
                        (RawProtocol::H1, Workload::WebSocket) => (
                            "h1-upgrade-tunnels",
                            "pre-established-ping-pong",
                            "connections=concurrency; one tunnel per connection",
                        ),
                        (RawProtocol::H1, _) => (
                            "persistent-h1",
                            "request-through-response-eos",
                            "connections=concurrency; one outstanding operation per lane",
                        ),
                        (RawProtocol::H2, Workload::WebSocket) => (
                            "h2-extended-connect-streams",
                            "pre-established-ping-pong",
                            "connections=1; tunnels=concurrency; odd unique stream ids",
                        ),
                        (RawProtocol::H2, _) => (
                            "persistent-h2",
                            "request-through-response-eos",
                            "connections=1; streams=starts; odd unique stream ids",
                        ),
                    };
                entries.push(ConnectionPolicyEntry {
                    protocol,
                    workload,
                    policy: policy.to_owned(),
                    operation_boundary: operation_boundary.to_owned(),
                    reconciliation: reconciliation.to_owned(),
                });
            }
        }
        let manifest = Self {
            schema: "amg-http2-perf/trust-boundary/v1".to_owned(),
            external_inputs: ExternalInputManifest {
                schema: "amg-http2-perf/external-inputs/v1".to_owned(),
                build_set_sha256,
                baseline_commit,
                candidate_commit,
                read_only_surfaces: vec![
                    "git-object-database".to_owned(),
                    "git-executable".to_owned(),
                    "rust-cargo-toolchain".to_owned(),
                    "dynamic-loader-runtime-libraries".to_owned(),
                    "dependency-cache-artifacts".to_owned(),
                    "/dev/null".to_owned(),
                    "/proc-read-only".to_owned(),
                    "/sys-read-only".to_owned(),
                    "literal-loopback-sockets".to_owned(),
                    "getrandom".to_owned(),
                ],
            },
            clocks: ClockBoundaryManifest {
                schema: "amg-http2-perf/clock-boundary/v1".to_owned(),
                realtime_provenance: vec![
                    "untouched-archived-gateway-production-semantics".to_owned(),
                    "orchestrator-sampler-utc-metadata".to_owned(),
                ],
                monotonic_destinations: vec![
                    "operation-latency".to_owned(),
                    "performance-count-throughput-windows".to_owned(),
                    "cpu-window-boundaries".to_owned(),
                    "warmup-settle-freeze-drain".to_owned(),
                    "operation-phase-deadlines".to_owned(),
                ],
                boottime_destinations: vec![
                    "campaign-elapsed".to_owned(),
                    "resource-budget-gates".to_owned(),
                    "realtime-sample-brackets".to_owned(),
                ],
                prohibited_realtime_destinations: vec![
                    "latency-duration-throughput-cpu-window".to_owned(),
                    "deadline-ordering-schedule-seed-statistics".to_owned(),
                    "campaign-resource-accounting".to_owned(),
                    "fixture-load-control-dependencies".to_owned(),
                ],
            },
            config: BenchmarkConfigManifest {
                schema: "amg-http2-perf/config/v1".to_owned(),
                fixed_values,
                arm_local_values: vec![
                    "PORT=reserved-literal-loopback".to_owned(),
                    "AUTH_MINI_ISSUER=arm-tripwire-literal-loopback".to_owned(),
                    "AUTH_MINI_PUBLIC_BASE_URL=arm-tripwire-literal-loopback".to_owned(),
                    "GATEWAY_DB=restricted-arm-runtime-path".to_owned(),
                    "UPSTREAM_URL=arm-fixture-literal-loopback".to_owned(),
                    "UPSTREAM_PROTOCOL=sealed-treatment-protocol".to_owned(),
                    "TMPDIR=restricted-arm-runtime-path".to_owned(),
                ],
            },
            corpus: CorpusManifest {
                schema: crate::topology::CORPUS_SCHEMA.to_owned(),
                seed_sha256: crate::seal::sha256_hex(&crate::topology::FIXED_CORPUS_SEED),
                corpus_sha256: corpus.sha256(),
                corpus_bytes: crate::topology::CORPUS_BYTES as u64,
                chunk_bytes: crate::topology::CHUNK_BYTES as u64,
                chunk_count: crate::topology::CHUNK_COUNT as u64,
                sse_events: crate::topology::SSE_EVENTS as u64,
                sse_data_bytes: crate::topology::SSE_DATA_BYTES as u64,
                payload_domain: "amg-http2-perf/v1/payload".to_owned(),
                websocket_mask_domain: "amg-http2-perf/v1/ws-mask".to_owned(),
            },
            connection_policies: ConnectionPolicyManifest {
                schema: "amg-http2-perf/connection-policies/v1".to_owned(),
                entries,
            },
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != "amg-http2-perf/trust-boundary/v1"
            || self.external_inputs.schema != "amg-http2-perf/external-inputs/v1"
            || self.clocks.schema != "amg-http2-perf/clock-boundary/v1"
            || self.config.schema != "amg-http2-perf/config/v1"
            || self.corpus.schema != crate::topology::CORPUS_SCHEMA
            || self.connection_policies.schema != "amg-http2-perf/connection-policies/v1"
            || self.connection_policies.entries.len() != 10
        {
            return Err(Error::new(
                "unsupported or incomplete trust-boundary manifest",
            ));
        }
        validate_non_placeholder_sha256(
            "trust-boundary build set",
            &self.external_inputs.build_set_sha256,
        )?;
        validate_commit(
            "trust-boundary baseline",
            &self.external_inputs.baseline_commit,
        )?;
        validate_commit(
            "trust-boundary candidate",
            &self.external_inputs.candidate_commit,
        )?;
        validate_non_placeholder_sha256("corpus seed", &self.corpus.seed_sha256)?;
        validate_non_placeholder_sha256("corpus bytes", &self.corpus.corpus_sha256)?;
        let regenerated = Self::coordinated_unchecked(
            self.external_inputs.build_set_sha256.clone(),
            self.external_inputs.baseline_commit.clone(),
            self.external_inputs.candidate_commit.clone(),
        );
        if self != &regenerated {
            return Err(Error::new(
                "trust-boundary manifest differs from the approved policy",
            ));
        }
        Ok(())
    }

    fn coordinated_unchecked(
        build_set_sha256: String,
        baseline_commit: String,
        candidate_commit: String,
    ) -> Self {
        // Construction is infallible for the fixed constants; avoid recursive validation.
        let mut fixed_values = BTreeMap::new();
        for (name, value) in [
            ("HOST", "127.0.0.1"),
            ("GATEWAY_PUBLIC_BASE_URL", "http://public.example"),
            ("COOKIE_SECURE", "false"),
            ("COOKIE_SAME_SITE", "lax"),
            ("SESSION_TTL_SECONDS", "604800"),
            ("SESSION_ABSOLUTE_TTL_SECONDS", "2592000"),
            ("SESSION_TOUCH_INTERVAL_SECONDS", "604800"),
            ("REFRESH_SKEW_SECONDS", "60"),
            ("ALLOW_USER_IDS", "bench-user"),
            ("TRUSTED_PROXY_CIDRS", ""),
            ("GATEWAY_MAX_DOWNSTREAM_CONNECTIONS", "256"),
            ("GATEWAY_MAX_ACTIVE_UPSTREAMS", "128"),
            ("GATEWAY_MAX_BLOCKING_RESOLVERS", "8"),
            ("NO_COLOR", "1"),
        ] {
            fixed_values.insert(name.to_owned(), value.to_owned());
        }
        let corpus = crate::topology::Corpus::fixed();
        let mut entries = Vec::new();
        for protocol in [RawProtocol::H1, RawProtocol::H2] {
            for workload in Workload::ALL {
                let (policy, operation_boundary, reconciliation) =
                    match (protocol, workload) {
                        (RawProtocol::H1, Workload::Upload1Mib) => (
                            "fresh-h1-per-operation",
                            "connect-through-close-eof",
                            "connections=starts=requests=responses=close=eos=eof; reuse=retry=reconnect=0",
                        ),
                        (RawProtocol::H1, Workload::WebSocket) => (
                            "h1-upgrade-tunnels",
                            "pre-established-ping-pong",
                            "connections=concurrency; one tunnel per connection",
                        ),
                        (RawProtocol::H1, _) => (
                            "persistent-h1",
                            "request-through-response-eos",
                            "connections=concurrency; one outstanding operation per lane",
                        ),
                        (RawProtocol::H2, Workload::WebSocket) => (
                            "h2-extended-connect-streams",
                            "pre-established-ping-pong",
                            "connections=1; tunnels=concurrency; odd unique stream ids",
                        ),
                        (RawProtocol::H2, _) => (
                            "persistent-h2",
                            "request-through-response-eos",
                            "connections=1; streams=starts; odd unique stream ids",
                        ),
                    };
                entries.push(ConnectionPolicyEntry {
                    protocol,
                    workload,
                    policy: policy.to_owned(),
                    operation_boundary: operation_boundary.to_owned(),
                    reconciliation: reconciliation.to_owned(),
                });
            }
        }
        Self {
            schema: "amg-http2-perf/trust-boundary/v1".to_owned(),
            external_inputs: ExternalInputManifest {
                schema: "amg-http2-perf/external-inputs/v1".to_owned(),
                build_set_sha256,
                baseline_commit,
                candidate_commit,
                read_only_surfaces: vec![
                    "git-object-database".to_owned(),
                    "git-executable".to_owned(),
                    "rust-cargo-toolchain".to_owned(),
                    "dynamic-loader-runtime-libraries".to_owned(),
                    "dependency-cache-artifacts".to_owned(),
                    "/dev/null".to_owned(),
                    "/proc-read-only".to_owned(),
                    "/sys-read-only".to_owned(),
                    "literal-loopback-sockets".to_owned(),
                    "getrandom".to_owned(),
                ],
            },
            clocks: ClockBoundaryManifest {
                schema: "amg-http2-perf/clock-boundary/v1".to_owned(),
                realtime_provenance: vec![
                    "untouched-archived-gateway-production-semantics".to_owned(),
                    "orchestrator-sampler-utc-metadata".to_owned(),
                ],
                monotonic_destinations: vec![
                    "operation-latency".to_owned(),
                    "performance-count-throughput-windows".to_owned(),
                    "cpu-window-boundaries".to_owned(),
                    "warmup-settle-freeze-drain".to_owned(),
                    "operation-phase-deadlines".to_owned(),
                ],
                boottime_destinations: vec![
                    "campaign-elapsed".to_owned(),
                    "resource-budget-gates".to_owned(),
                    "realtime-sample-brackets".to_owned(),
                ],
                prohibited_realtime_destinations: vec![
                    "latency-duration-throughput-cpu-window".to_owned(),
                    "deadline-ordering-schedule-seed-statistics".to_owned(),
                    "campaign-resource-accounting".to_owned(),
                    "fixture-load-control-dependencies".to_owned(),
                ],
            },
            config: BenchmarkConfigManifest {
                schema: "amg-http2-perf/config/v1".to_owned(),
                fixed_values,
                arm_local_values: vec![
                    "PORT=reserved-literal-loopback".to_owned(),
                    "AUTH_MINI_ISSUER=arm-tripwire-literal-loopback".to_owned(),
                    "AUTH_MINI_PUBLIC_BASE_URL=arm-tripwire-literal-loopback".to_owned(),
                    "GATEWAY_DB=restricted-arm-runtime-path".to_owned(),
                    "UPSTREAM_URL=arm-fixture-literal-loopback".to_owned(),
                    "UPSTREAM_PROTOCOL=sealed-treatment-protocol".to_owned(),
                    "TMPDIR=restricted-arm-runtime-path".to_owned(),
                ],
            },
            corpus: CorpusManifest {
                schema: crate::topology::CORPUS_SCHEMA.to_owned(),
                seed_sha256: crate::seal::sha256_hex(&crate::topology::FIXED_CORPUS_SEED),
                corpus_sha256: corpus.sha256(),
                corpus_bytes: crate::topology::CORPUS_BYTES as u64,
                chunk_bytes: crate::topology::CHUNK_BYTES as u64,
                chunk_count: crate::topology::CHUNK_COUNT as u64,
                sse_events: crate::topology::SSE_EVENTS as u64,
                sse_data_bytes: crate::topology::SSE_DATA_BYTES as u64,
                payload_domain: "amg-http2-perf/v1/payload".to_owned(),
                websocket_mask_domain: "amg-http2-perf/v1/ws-mask".to_owned(),
            },
            connection_policies: ConnectionPolicyManifest {
                schema: "amg-http2-perf/connection-policies/v1".to_owned(),
                entries,
            },
        }
    }

    pub fn sha256(&self) -> Result<String> {
        Ok(crate::seal::sha256_hex(&crate::json::canonical_bytes(
            self,
        )?))
    }

    pub fn clock_sha256(&self) -> Result<String> {
        Ok(crate::seal::sha256_hex(&crate::json::canonical_bytes(
            &self.clocks,
        )?))
    }

    pub fn config_sha256(&self) -> Result<String> {
        Ok(crate::seal::sha256_hex(&crate::json::canonical_bytes(
            &self.config,
        )?))
    }

    pub fn corpus_sha256(&self) -> Result<String> {
        Ok(crate::seal::sha256_hex(&crate::json::canonical_bytes(
            &self.corpus,
        )?))
    }

    pub fn connection_policy_sha256(&self) -> Result<String> {
        Ok(crate::seal::sha256_hex(&crate::json::canonical_bytes(
            &self.connection_policies,
        )?))
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_boundary: Option<TrustBoundaryManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_provenance: Option<HarnessProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessProvenance {
    pub commit: String,
    pub tree_object: String,
    pub source_archive_sha256: String,
    pub cargo_lock_sha256: String,
}

impl HarnessProvenance {
    pub fn validate(&self) -> Result<()> {
        validate_commit("harness provenance commit", &self.commit)?;
        if self.tree_object.len() != 40
            || !self
                .tree_object
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::new("harness provenance tree object is invalid"));
        }
        validate_non_placeholder_sha256("harness source archive", &self.source_archive_sha256)?;
        validate_non_placeholder_sha256("harness Cargo.lock", &self.cargo_lock_sha256)
    }
}

impl Intent {
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            self.schema.as_str(),
            INTENT_SCHEMA | COORDINATED_INTENT_SCHEMA
        ) {
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
        self.raw_limits.validate()?;
        if let Some(provenance) = &self.harness_provenance {
            provenance.validate()?;
        }
        match (&*self.schema, &self.trust_boundary) {
            (INTENT_SCHEMA, None) => Ok(()),
            (COORDINATED_INTENT_SCHEMA, Some(manifest)) => {
                if self.harness_provenance.is_none() {
                    return Err(Error::new(
                        "coordinated intent lacks exact harness provenance",
                    ));
                }
                manifest.validate()?;
                if manifest.external_inputs.baseline_commit != self.baseline_commit
                    || manifest.external_inputs.candidate_commit != self.candidate_commit
                {
                    return Err(Error::new(
                        "intent trust-boundary commits differ from the intent",
                    ));
                }
                Ok(())
            }
            _ => Err(Error::new(
                "intent schema and trust-boundary manifest do not match",
            )),
        }
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
    pub calibration_id: String,
    pub candidate_commit: String,
    pub intent_sha256: String,
    pub machine_sha256: String,
    pub build_set_sha256: String,
    pub topology_smoke_sha256: String,
    pub calibration_plan_sha256: String,
    pub authoritative_parameters_sha256: String,
    pub calibration_manifest_sha256: String,
    pub projection_sha256: String,
    pub calibration_seal_root_sha256: String,
    pub calibration_bundle_index_sha256: String,
    pub selected_n: u32,
    pub schedule_seed: u64,
    pub rounds: Vec<RoundPlan>,
    pub comparisons: Vec<ComparisonSpec>,
    pub authoritative_durations: Vec<crate::calibration::CellDurations>,
    pub treatment_signatures: Vec<SignatureBinding>,
    pub direct_signatures: Vec<SignatureBinding>,
    pub direct_mappings: Vec<crate::process_plan::DirectMapping>,
    pub runtime_projection: crate::calibration::RuntimeProjection,
    pub tracked_projection: crate::storage::TrackedProjection,
    pub calibration_frequency_p05_khz: u64,
}

impl DesignLock {
    pub fn validate(&self) -> Result<()> {
        if self.schema != DESIGN_LOCK_SCHEMA {
            return Err(Error::new("unsupported design-lock schema"));
        }
        validate_identifier("design-lock calibration_id", &self.calibration_id)?;
        validate_commit("design-lock candidate_commit", &self.candidate_commit)?;
        for (name, hash) in [
            ("intent_sha256", &self.intent_sha256),
            ("machine_sha256", &self.machine_sha256),
            ("build_set_sha256", &self.build_set_sha256),
            ("topology_smoke_sha256", &self.topology_smoke_sha256),
            ("calibration_plan_sha256", &self.calibration_plan_sha256),
            (
                "authoritative_parameters_sha256",
                &self.authoritative_parameters_sha256,
            ),
            (
                "calibration_manifest_sha256",
                &self.calibration_manifest_sha256,
            ),
            ("projection_sha256", &self.projection_sha256),
            (
                "calibration_seal_root_sha256",
                &self.calibration_seal_root_sha256,
            ),
            (
                "calibration_bundle_index_sha256",
                &self.calibration_bundle_index_sha256,
            ),
        ] {
            validate_non_placeholder_sha256(name, hash)?;
        }
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
        validate_cell_durations(&self.authoritative_durations)?;
        validate_signature_bindings(&self.treatment_signatures, 75, false)?;
        validate_signature_bindings(&self.direct_signatures, 30, true)?;
        if self.direct_mappings != crate::process_plan::direct_mappings() {
            return Err(Error::new("design-lock direct mappings are not canonical"));
        }
        if self.runtime_projection.n != self.selected_n || !self.runtime_projection.admissible {
            return Err(Error::new(
                "design-lock runtime projection does not admit the selected N",
            ));
        }
        if !self.tracked_projection.admissible {
            return Err(Error::new(
                "design-lock tracked projection does not admit the continuation",
            ));
        }
        if self.calibration_frequency_p05_khz < 4_000_000 {
            return Err(Error::new(
                "design-lock calibration frequency p05 is below the approved floor",
            ));
        }
        Ok(())
    }
}

fn validate_cell_durations(values: &[crate::calibration::CellDurations]) -> Result<()> {
    if values.len() != 15 {
        return Err(Error::new("design-lock duration inventory is not 15 cells"));
    }
    let mut cells = BTreeSet::new();
    for value in values {
        value.cell.validate()?;
        value.durations.validate()?;
        if !cells.insert(value.cell) {
            return Err(Error::new("design-lock duration cell is duplicated"));
        }
    }
    if cells != all_cells().into_iter().collect() {
        return Err(Error::new("design-lock duration cell set is incomplete"));
    }
    Ok(())
}

fn validate_signature_bindings(
    values: &[SignatureBinding],
    expected: usize,
    direct: bool,
) -> Result<()> {
    if values.len() != expected {
        return Err(Error::new(
            "design-lock accepted-signature inventory differs",
        ));
    }
    let mut keys = BTreeSet::new();
    for value in values {
        value.validate()?;
        if value.direct_protocol.is_some() != direct || !keys.insert(value.key()) {
            return Err(Error::new(
                "design-lock accepted-signature key is duplicated or misclassified",
            ));
        }
    }
    Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureBinding {
    pub cell: Cell,
    pub arm: Option<Arm>,
    pub direct_protocol: Option<RawProtocol>,
    pub record_path: String,
    pub record_sha256: String,
    pub signature_sha256: String,
}

impl SignatureBinding {
    pub fn validate(&self) -> Result<()> {
        self.cell.validate()?;
        if self.arm.is_some() == self.direct_protocol.is_some() {
            return Err(Error::new("accepted-signature binding key is ambiguous"));
        }
        crate::seal::validate_relative_path(&self.record_path)?;
        validate_non_placeholder_sha256("accepted-signature record", &self.record_sha256)?;
        validate_non_placeholder_sha256("accepted thread signature", &self.signature_sha256)
    }

    fn key(&self) -> (Cell, Option<Arm>, Option<RawProtocol>) {
        (self.cell, self.arm, self.direct_protocol)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedSignatureRecord {
    pub schema: String,
    pub calibration_id: String,
    pub calibration_plan_sha256: String,
    pub cell: Cell,
    pub arm: Option<Arm>,
    pub direct_protocol: Option<RawProtocol>,
    pub establishment_class: EvidenceClass,
    pub establishment_ordinal: u64,
    pub source_observation_id: String,
    pub signature_sha256: String,
}

impl AcceptedSignatureRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema != ACCEPTED_SIGNATURE_SCHEMA {
            return Err(Error::new("unsupported accepted-signature schema"));
        }
        validate_identifier("signature calibration_id", &self.calibration_id)?;
        validate_non_placeholder_sha256(
            "signature calibration plan",
            &self.calibration_plan_sha256,
        )?;
        self.cell.validate()?;
        validate_identifier("signature source observation", &self.source_observation_id)?;
        validate_non_placeholder_sha256("accepted thread signature", &self.signature_sha256)?;
        match self.establishment_class {
            EvidenceClass::C if self.arm.is_some() && self.direct_protocol.is_none() => Ok(()),
            EvidenceClass::D if self.arm.is_none() && self.direct_protocol.is_some() => Ok(()),
            _ => Err(Error::new(
                "accepted signature was not established by a C or D key",
            )),
        }
    }

    pub fn binding(&self, path: String, record_sha256: String) -> Result<SignatureBinding> {
        self.validate()?;
        let binding = SignatureBinding {
            cell: self.cell,
            arm: self.arm,
            direct_protocol: self.direct_protocol,
            record_path: path,
            record_sha256,
            signature_sha256: self.signature_sha256.clone(),
        };
        binding.validate()?;
        Ok(binding)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationManifest {
    pub schema: String,
    pub calibration_id: String,
    pub intent_sha256: String,
    pub machine_sha256: String,
    pub build_set_sha256: String,
    pub topology_smoke_sha256: String,
    pub calibration_plan_sha256: Option<String>,
    pub authoritative_parameters_sha256: Option<String>,
    pub execution_state_sha256: String,
    pub projection_sha256: String,
    pub arm_bindings: Vec<CalibrationArmBinding>,
    pub signature_bindings: Vec<SignatureBinding>,
    pub selected_n: Option<u32>,
    pub terminal_state: TerminalState,
    pub terminal_reasons: Vec<String>,
    pub records: Vec<CalibrationRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationArmBinding {
    pub ordinal: u64,
    pub class: EvidenceClass,
    pub path: String,
    pub raw_sha256: String,
}

impl CalibrationArmBinding {
    pub fn validate(&self) -> Result<()> {
        crate::seal::validate_relative_path(&self.path)?;
        validate_non_placeholder_sha256("calibration arm raw", &self.raw_sha256)
    }
}

impl CalibrationManifest {
    pub fn validate(&self) -> Result<()> {
        if self.schema != CALIBRATION_MANIFEST_SCHEMA {
            return Err(Error::new("unsupported calibration manifest"));
        }
        validate_identifier("calibration_id", &self.calibration_id)?;
        for hash in [
            &self.intent_sha256,
            &self.machine_sha256,
            &self.build_set_sha256,
            &self.topology_smoke_sha256,
            &self.execution_state_sha256,
            &self.projection_sha256,
        ] {
            validate_non_placeholder_sha256("calibration manifest hash", hash)?;
        }
        for hash in [
            self.calibration_plan_sha256.as_ref(),
            self.authoritative_parameters_sha256.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_non_placeholder_sha256("optional calibration manifest hash", hash)?;
        }
        if self
            .selected_n
            .is_some_and(|n| !matches!(n, 30 | 50 | 70 | 100))
            || self.terminal_reasons.iter().any(String::is_empty)
            || (self.terminal_state == TerminalState::Pass && !self.terminal_reasons.is_empty())
            || (self.records.is_empty() && self.terminal_state != TerminalState::Blocked)
        {
            return Err(Error::new("calibration manifest terminal data is invalid"));
        }
        for (expected_ordinal, binding) in (0_u64..).zip(&self.arm_bindings) {
            binding.validate()?;
            if binding.ordinal != expected_ordinal {
                return Err(Error::new(
                    "calibration manifest arm bindings are not a contiguous prefix",
                ));
            }
        }
        if self.records.len() != self.arm_bindings.len() {
            return Err(Error::new(
                "calibration manifest records and raw bindings differ in length",
            ));
        }
        let mut signature_keys = BTreeSet::new();
        for signature in &self.signature_bindings {
            signature.validate()?;
            if !signature_keys.insert(signature.key()) {
                return Err(Error::new(
                    "calibration manifest signature binding is duplicated",
                ));
            }
        }
        let mut identities = BTreeSet::new();
        for (record, binding) in self.records.iter().zip(&self.arm_bindings) {
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
            if record.class != binding.class {
                return Err(Error::new(
                    "calibration record class differs from its raw binding",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignDirectBaseline {
    pub cell: Cell,
    pub protocol: RawProtocol,
    pub raw_sha256: String,
    pub deadline_completions: u64,
    pub elapsed_ns: u64,
    pub signature_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationFrequencyObservation {
    pub ordinal: u64,
    pub raw_sha256: String,
    pub median_frequency_khz: u64,
}

impl CalibrationFrequencyObservation {
    pub fn validate(&self) -> Result<()> {
        validate_non_placeholder_sha256("calibration frequency raw", &self.raw_sha256)?;
        if self.median_frequency_khz < 4_000_000 {
            return Err(Error::new(
                "calibration frequency observation is below the absolute floor",
            ));
        }
        Ok(())
    }
}

impl CampaignDirectBaseline {
    pub fn validate(&self) -> Result<()> {
        self.cell.validate()?;
        validate_non_placeholder_sha256("campaign D0 raw", &self.raw_sha256)?;
        validate_non_placeholder_sha256("campaign D0 signature", &self.signature_sha256)?;
        if self.deadline_completions == 0 || self.elapsed_ns == 0 {
            return Err(Error::new("campaign D0 baseline has a zero rate input"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignCalibrationBinding {
    pub schema: String,
    pub calibration_id: String,
    pub calibration_intent: crate::calibration::FileHashBinding,
    pub calibration_machine: crate::calibration::FileHashBinding,
    pub calibration_build_set: crate::calibration::FileHashBinding,
    pub calibration_plan: crate::calibration::FileHashBinding,
    pub authoritative_parameters: crate::calibration::FileHashBinding,
    pub calibration_manifest: crate::calibration::FileHashBinding,
    pub calibration_projection: crate::calibration::FileHashBinding,
    pub calibration_seal_root_sha256: String,
    pub calibration_bundle_index: crate::calibration::FileHashBinding,
    pub calibration_verification: crate::calibration::FileHashBinding,
    pub compression_profile: crate::calibration::FileHashBinding,
    pub continuation_projection: crate::calibration::FileHashBinding,
    pub campaign_boottime_origin_ns: u64,
    pub calibration_frequency_observations: Vec<CalibrationFrequencyObservation>,
    pub direct_baselines: Vec<CampaignDirectBaseline>,
}

impl CampaignCalibrationBinding {
    pub fn validate(&self, design: &DesignLock) -> Result<()> {
        if self.schema != CAMPAIGN_BINDING_SCHEMA || self.calibration_id != design.calibration_id {
            return Err(Error::new(
                "campaign calibration binding identity is invalid",
            ));
        }
        validate_identifier("campaign calibration ID", &self.calibration_id)?;
        for binding in [
            &self.calibration_intent,
            &self.calibration_machine,
            &self.calibration_build_set,
            &self.calibration_plan,
            &self.authoritative_parameters,
            &self.calibration_manifest,
            &self.calibration_projection,
            &self.calibration_bundle_index,
            &self.calibration_verification,
            &self.compression_profile,
            &self.continuation_projection,
        ] {
            binding.validate()?;
        }
        validate_non_placeholder_sha256(
            "campaign calibration seal",
            &self.calibration_seal_root_sha256,
        )?;
        if self.calibration_intent.sha256 != design.intent_sha256
            || self.calibration_machine.sha256 != design.machine_sha256
            || self.calibration_build_set.sha256 != design.build_set_sha256
            || self.calibration_plan.sha256 != design.calibration_plan_sha256
            || self.authoritative_parameters.sha256 != design.authoritative_parameters_sha256
            || self.calibration_manifest.sha256 != design.calibration_manifest_sha256
            || self.continuation_projection.sha256 != design.projection_sha256
            || self.calibration_seal_root_sha256 != design.calibration_seal_root_sha256
            || self.calibration_bundle_index.sha256 != design.calibration_bundle_index_sha256
            || self.campaign_boottime_origin_ns == 0
        {
            return Err(Error::new(
                "campaign calibration binding differs from the design lock",
            ));
        }
        if self.calibration_frequency_observations.len() != 750 {
            return Err(Error::new(
                "campaign binding lacks exactly 750 class-C frequency observations",
            ));
        }
        let mut frequency_ordinals = BTreeSet::new();
        let mut frequencies = Vec::with_capacity(750);
        for observation in &self.calibration_frequency_observations {
            observation.validate()?;
            if !frequency_ordinals.insert(observation.ordinal) {
                return Err(Error::new(
                    "campaign binding duplicates a class-C frequency ordinal",
                ));
            }
            frequencies.push(observation.median_frequency_khz);
        }
        frequencies.sort_unstable();
        let rank = frequencies
            .len()
            .checked_mul(5)
            .and_then(|value| value.checked_add(99))
            .ok_or_else(|| Error::new("campaign frequency percentile rank overflow"))?
            / 100;
        if frequencies.get(rank.saturating_sub(1)).copied()
            != Some(design.calibration_frequency_p05_khz)
        {
            return Err(Error::new(
                "campaign binding class-C frequency p05 differs from design lock",
            ));
        }
        let mut keys = BTreeSet::new();
        for baseline in &self.direct_baselines {
            baseline.validate()?;
            if !keys.insert((baseline.cell, baseline.protocol)) {
                return Err(Error::new("campaign D0 baseline key is duplicated"));
            }
        }
        let expected = all_cells()
            .into_iter()
            .flat_map(|cell| {
                [RawProtocol::H1, RawProtocol::H2]
                    .into_iter()
                    .map(move |protocol| (cell, protocol))
            })
            .collect::<BTreeSet<_>>();
        if keys != expected {
            return Err(Error::new(
                "campaign D0 baseline inventory is not exactly 30",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignManifest {
    pub schema: String,
    pub run_id: String,
    pub intent_sha256: String,
    pub design_lock_sha256: String,
    pub calibration_binding_sha256: String,
    pub campaign_plan_sha256: String,
    pub schedule_sha256: String,
    pub machine_sha256: String,
    pub build_set_sha256: String,
    pub execution_state_sha256: String,
    pub projection_sha256: String,
    pub planned_arms: u64,
    pub completed_arms: u64,
    pub arm_bindings: Vec<CalibrationArmBinding>,
    pub pair_bindings: Vec<crate::schedule::PairIdentity>,
    pub terminal_state: TerminalState,
    pub terminal_reasons: Vec<String>,
}

impl CampaignManifest {
    pub fn validate(&self, n: u32) -> Result<()> {
        if self.schema != CAMPAIGN_MANIFEST_SCHEMA || !matches!(n, 30 | 50) {
            return Err(Error::new("campaign manifest schema/N is invalid"));
        }
        validate_identifier("campaign manifest run ID", &self.run_id)?;
        for hash in [
            &self.intent_sha256,
            &self.design_lock_sha256,
            &self.calibration_binding_sha256,
            &self.campaign_plan_sha256,
            &self.schedule_sha256,
            &self.machine_sha256,
            &self.build_set_sha256,
            &self.execution_state_sha256,
            &self.projection_sha256,
        ] {
            validate_non_placeholder_sha256("campaign manifest hash", hash)?;
        }
        let expected = 78_u64
            .checked_mul(u64::from(n))
            .ok_or_else(|| Error::new("campaign manifest arm count overflow"))?;
        if self.planned_arms != expected
            || self.completed_arms > self.planned_arms
            || self.arm_bindings.len() as u64 != self.completed_arms
            || self.terminal_reasons.iter().any(String::is_empty)
            || (self.terminal_state == TerminalState::Pass
                && (!self.terminal_reasons.is_empty() || self.completed_arms != expected))
        {
            return Err(Error::new(
                "campaign manifest terminal inventory is invalid",
            ));
        }
        for (ordinal, binding) in (0_u64..).zip(&self.arm_bindings) {
            binding.validate()?;
            if binding.ordinal != ordinal
                || !matches!(binding.class, EvidenceClass::A | EvidenceClass::D)
            {
                return Err(Error::new(
                    "campaign manifest arm bindings are not an exact A/D prefix",
                ));
            }
        }
        let mut pair_keys = BTreeSet::new();
        for pair in &self.pair_bindings {
            pair.validate()?;
            if !pair_keys.insert((pair.comparison_id.clone(), pair.round)) {
                return Err(Error::new("campaign manifest pair identity is duplicated"));
            }
        }
        let expected_pairs = 45_usize
            .checked_mul(usize::try_from(n).map_err(|_| Error::new("campaign N overflow"))?)
            .ok_or_else(|| Error::new("campaign pair count overflow"))?;
        if self.terminal_state == TerminalState::Pass && self.pair_bindings.len() != expected_pairs
        {
            return Err(Error::new(
                "passing campaign manifest lacks the complete pair inventory",
            ));
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
            trust_boundary: None,
            harness_provenance: None,
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
        let durations = all_cells()
            .into_iter()
            .map(|cell| crate::calibration::CellDurations {
                cell,
                durations: crate::calibration::FrozenDurations {
                    warmup_seconds: 3,
                    measure_seconds: 5,
                },
            })
            .collect::<Vec<_>>();
        let treatment_signatures = all_cells()
            .into_iter()
            .flat_map(|cell| {
                Arm::ALL.into_iter().map(move |arm| SignatureBinding {
                    cell,
                    arm: Some(arm),
                    direct_protocol: None,
                    record_path: format!("signatures/{}/{}.json", cell.id(), arm.code()),
                    record_sha256: "21".repeat(32),
                    signature_sha256: "22".repeat(32),
                })
            })
            .collect::<Vec<_>>();
        let direct_signatures = all_cells()
            .into_iter()
            .flat_map(|cell| {
                [RawProtocol::H1, RawProtocol::H2]
                    .into_iter()
                    .map(move |protocol| SignatureBinding {
                        cell,
                        arm: None,
                        direct_protocol: Some(protocol),
                        record_path: format!(
                            "signatures/{}/{}.json",
                            cell.id(),
                            match protocol {
                                RawProtocol::H1 => "h1",
                                RawProtocol::H2 => "h2",
                            }
                        ),
                        record_sha256: "23".repeat(32),
                        signature_sha256: "24".repeat(32),
                    })
            })
            .collect::<Vec<_>>();
        let mut design = DesignLock {
            schema: DESIGN_LOCK_SCHEMA.to_owned(),
            calibration_id: "calibration-fixture".to_owned(),
            candidate_commit: INITIAL_CANDIDATE_COMMIT.to_owned(),
            intent_sha256: "01".repeat(32),
            machine_sha256: "02".repeat(32),
            build_set_sha256: "03".repeat(32),
            topology_smoke_sha256: "04".repeat(32),
            calibration_plan_sha256: "11".repeat(32),
            authoritative_parameters_sha256: "12".repeat(32),
            calibration_manifest_sha256: "13".repeat(32),
            projection_sha256: "14".repeat(32),
            calibration_seal_root_sha256: "15".repeat(32),
            calibration_bundle_index_sha256: "16".repeat(32),
            selected_n: 30,
            schedule_seed: 9,
            rounds: schedule::generate_rounds(9, 30).expect("rounds"),
            comparisons: hard_comparisons(),
            authoritative_durations: durations.clone(),
            treatment_signatures,
            direct_signatures,
            direct_mappings: crate::process_plan::direct_mappings(),
            runtime_projection: crate::calibration::project_runtime(
                30,
                crate::calibration::PRE_FREEZE_FLOOR_NS,
                0,
                &durations,
            )
            .expect("runtime projection"),
            tracked_projection: crate::storage::tracked_projection(
                0,
                0,
                &[],
                &[],
                5 * crate::storage::MIB,
            )
            .expect("tracked projection"),
            calibration_frequency_p05_khz: 4_000_000,
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
