use crate::schema::{EvidenceClass, CHUNK_BYTES, TASK_CAP_BYTES};
use crate::seal::sha256_hex;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const KIB: u64 = 1_024;
pub const MIB: u64 = 1_048_576;
pub const GIB: u64 = 1_073_741_824;
pub const COMPRESSION_PROFILE_SCHEMA: &str = "amg-http2-perf/compression-profile/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmStorageInput {
    pub class: EvidenceClass,
    pub gateway: bool,
    pub duration_ns: u64,
    pub tid_slots: u64,
    pub lifecycle_events: u64,
    pub connection_records: u64,
    pub latency_records: u64,
    pub concurrency: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentBounds {
    pub metadata_json: u64,
    pub quiet_json: u64,
    pub thread_map_json: u64,
    pub thread_lifecycle_bin: u64,
    pub session_clock_bin: u64,
    pub resources_bin: u64,
    pub endpoints_bin: u64,
    pub operation_summary_bin: u64,
    pub materialization_json: u64,
    pub latencies_u64le: u64,
    pub total: u64,
}

impl ComponentBounds {
    pub fn member_lengths(&self) -> Vec<u64> {
        [
            self.metadata_json,
            self.quiet_json,
            self.thread_map_json,
            self.thread_lifecycle_bin,
            self.session_clock_bin,
            self.resources_bin,
            self.endpoints_bin,
            self.operation_summary_bin,
            self.materialization_json,
            self.latencies_u64le,
        ]
        .into_iter()
        .filter(|length| *length != 0)
        .collect()
    }
}

pub fn component_bounds(input: &ArmStorageInput) -> Result<ComponentBounds> {
    if input.duration_ns == 0 || !matches!(input.concurrency, 1 | 16 | 64) {
        return Err(Error::new(
            "invalid arm duration or concurrency for storage bound",
        ));
    }
    if input.class.has_latencies() != (input.latency_records > 0) {
        return Err(Error::new("latency bound does not match evidence class"));
    }
    let h10 = 2_u64
        .checked_add(ceil_div(input.duration_ns, 10_000_000)?)
        .ok_or_else(|| Error::new("H10 overflow"))?;
    let h100 = 2_u64
        .checked_add(ceil_div(input.duration_ns, 100_000_000)?)
        .ok_or_else(|| Error::new("H100 overflow"))?;
    let thread_lifecycle_bin = checked_sum(&[
        128,
        checked_mul(64, h10)?,
        checked_mul(96, input.lifecycle_events)?,
    ])?;
    let session_clock_bin = if input.gateway {
        checked_sum(&[128, checked_mul(128, h10)?])?
    } else {
        128
    };
    let resource_width = checked_sum(&[32, input.tid_slots, 4])?;
    let resources_bin = checked_sum(&[128, checked_mul(checked_mul(160, h100)?, resource_width)?])?;
    let endpoints_bin = checked_sum(&[
        512,
        checked_mul(160, input.connection_records)?,
        checked_mul(512, input.concurrency)?,
    ])?;
    let operation_summary_bin = checked_sum(&[256, checked_mul(96, input.concurrency)?])?;
    let materialization_json = if input.gateway { MIB } else { 0 };
    let latencies_u64le = if input.class.has_latencies() {
        checked_sum(&[32, checked_mul(8, input.latency_records)?])?
    } else {
        0
    };
    let mut result = ComponentBounds {
        metadata_json: 65_536,
        quiet_json: 131_072,
        thread_map_json: 131_072,
        thread_lifecycle_bin,
        session_clock_bin,
        resources_bin,
        endpoints_bin,
        operation_summary_bin,
        materialization_json,
        latencies_u64le,
        total: 0,
    };
    result.total = checked_sum(&[
        result.metadata_json,
        result.quiet_json,
        result.thread_map_json,
        result.thread_lifecycle_bin,
        result.session_clock_bin,
        result.resources_bin,
        result.endpoints_bin,
        result.operation_summary_bin,
        result.materialization_json,
        result.latencies_u64le,
    ])?;
    Ok(result)
}

pub fn ustar_bound(member_lengths: &[u64]) -> Result<u64> {
    let mut total = 1_024_u64;
    for length in member_lengths {
        let blocks = ceil_div(*length, 512)?;
        total = total
            .checked_add(512)
            .and_then(|value| value.checked_add(blocks.checked_mul(512)?))
            .ok_or_else(|| Error::new("ustar size overflow"))?;
    }
    Ok(total)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReachableBranch {
    BeforeSmoke,
    BeforeFirstScout,
    BeforeWilliams,
    BeforeCalibrationDirect,
    AuthoritativeContinuation,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachableInventory {
    pub scout: u64,
    pub williams: u64,
    pub direct: u64,
    pub authoritative: u64,
}

pub fn reachable_inventory(branch: ReachableBranch, n: Option<u32>) -> Result<ReachableInventory> {
    match branch {
        ReachableBranch::BeforeSmoke => Ok(ReachableInventory {
            scout: 0,
            williams: 0,
            direct: 0,
            authoritative: 0,
        }),
        ReachableBranch::BeforeFirstScout => Ok(ReachableInventory {
            scout: 525,
            williams: 0,
            direct: 0,
            authoritative: 0,
        }),
        ReachableBranch::BeforeWilliams => Ok(ReachableInventory {
            scout: 0,
            williams: 750,
            direct: 0,
            authoritative: 0,
        }),
        ReachableBranch::BeforeCalibrationDirect => {
            let selected = n.ok_or_else(|| Error::new("pre-direct branch lacks selected N"))?;
            if !matches!(selected, 30 | 50) {
                return Err(Error::new("N=70/100 cannot reach calibration-direct work"));
            }
            Ok(ReachableInventory {
                scout: 0,
                williams: 0,
                direct: 30,
                authoritative: 0,
            })
        }
        ReachableBranch::AuthoritativeContinuation => {
            let selected = n.ok_or_else(|| Error::new("continuation branch lacks selected N"))?;
            if !matches!(selected, 30 | 50) {
                return Err(Error::new("N=70/100 has no authoritative continuation"));
            }
            Ok(ReachableInventory {
                scout: 0,
                williams: 0,
                direct: 3 * u64::from(selected),
                authoritative: 75 * u64::from(selected),
            })
        }
        ReachableBranch::Terminal => Ok(ReachableInventory {
            scout: 0,
            williams: 0,
            direct: 0,
            authoritative: 0,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawExecutionProjection {
    pub future_raw_bytes: u64,
    pub compressed_bound_bytes: u64,
    pub extracted_source_bytes: u64,
    pub encoder_workspace_bytes: u64,
    pub canonical_buffer_bytes: u64,
    pub chunk_compare_buffers_bytes: u64,
    pub coexistence_bytes: u64,
    pub doubled_coexistence_bytes: u64,
    pub fixed_free_reserve_bytes: u64,
    pub required_free_bytes_exclusive: u64,
    pub observed_free_bytes: u64,
    pub admissible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachedBranchProjection {
    pub gate_id: String,
    pub next_ordinal: u64,
    pub inventory: ReachableInventory,
    pub completed_member_count: u64,
    pub archive_member_lengths: Vec<u64>,
    pub completed_payload_bytes: u64,
    pub future_arm_payload_bytes: u64,
    pub future_unit_payload_bytes: u64,
    pub future_raw_bytes: u64,
    pub canonical_archive_bound_bytes: u64,
    pub compressed_bound_bytes: u64,
    pub extracted_source_bound_bytes: u64,
    pub raw: RawExecutionProjection,
    pub tracked_actual_bytes: u64,
    pub tracked_remaining_maximum_bytes: u64,
    pub tracked_total_bound_bytes: u64,
    pub task_cap_bytes: u64,
    pub tracked_admissible: bool,
    pub admissible: bool,
}

impl ReachedBranchProjection {
    pub fn validate(&self) -> Result<()> {
        if self.gate_id.is_empty()
            || self.gate_id.len() > 128
            || !self
                .gate_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(Error::new("reached-branch storage gate ID is invalid"));
        }
        let future_raw_bytes = self
            .future_arm_payload_bytes
            .checked_add(self.future_unit_payload_bytes)
            .ok_or_else(|| Error::new("reached-branch future raw total overflow"))?;
        let extracted_source_bound_bytes = self
            .completed_payload_bytes
            .checked_add(future_raw_bytes)
            .ok_or_else(|| Error::new("reached-branch extracted source total overflow"))?;
        let tracked_total_bound_bytes = self
            .tracked_actual_bytes
            .checked_add(self.tracked_remaining_maximum_bytes)
            .ok_or_else(|| Error::new("reached-branch tracked total overflow"))?;
        let completed_member_count = usize::try_from(self.completed_member_count)
            .map_err(|_| Error::new("completed storage member count exceeds usize"))?;
        if completed_member_count > self.archive_member_lengths.len() {
            return Err(Error::new(
                "completed storage member count exceeds archive members",
            ));
        }
        let (completed_members, future_members) =
            self.archive_member_lengths.split_at(completed_member_count);
        let canonical_archive_bound_bytes = ustar_bound(&self.archive_member_lengths)?;
        let canonical_usize = usize::try_from(canonical_archive_bound_bytes)
            .map_err(|_| Error::new("canonical archive bound exceeds usize"))?;
        let compressed_bound_bytes = u64::try_from(zstd_safe::compress_bound(canonical_usize))
            .map_err(|_| Error::new("Zstandard compression bound exceeds u64"))?;
        let raw = raw_execution_projection(
            future_raw_bytes,
            compressed_bound_bytes,
            extracted_source_bound_bytes,
            self.raw.encoder_workspace_bytes,
            self.raw.observed_free_bytes,
        )?;
        if self.future_raw_bytes != future_raw_bytes
            || checked_sum(completed_members)? != self.completed_payload_bytes
            || checked_sum(future_members)? != future_raw_bytes
            || self.canonical_archive_bound_bytes != canonical_archive_bound_bytes
            || self.compressed_bound_bytes != compressed_bound_bytes
            || self.extracted_source_bound_bytes != extracted_source_bound_bytes
            || self.raw != raw
            || self.tracked_total_bound_bytes != tracked_total_bound_bytes
            || self.task_cap_bytes != TASK_CAP_BYTES
            || self.tracked_admissible != (tracked_total_bound_bytes <= TASK_CAP_BYTES)
            || self.admissible != (self.raw.admissible && self.tracked_admissible)
        {
            return Err(Error::new(
                "reached-branch storage projection arithmetic is inconsistent",
            ));
        }
        Ok(())
    }
}

pub struct ReachedBranchInput<'a> {
    pub gate_id: &'a str,
    pub next_ordinal: u64,
    pub inventory: ReachableInventory,
    pub completed_member_lengths: &'a [u64],
    pub future_arms: &'a [ArmStorageInput],
    pub future_unit_member_lengths: &'a [u64],
    pub encoder_workspace_bytes: u64,
    pub observed_free_bytes: u64,
    pub tracked_actual_bytes: u64,
    pub tracked_remaining_maximum_bytes: u64,
}

pub fn reached_branch_projection(input: ReachedBranchInput<'_>) -> Result<ReachedBranchProjection> {
    let ReachedBranchInput {
        gate_id,
        next_ordinal,
        inventory,
        completed_member_lengths,
        future_arms,
        future_unit_member_lengths,
        encoder_workspace_bytes,
        observed_free_bytes,
        tracked_actual_bytes,
        tracked_remaining_maximum_bytes,
    } = input;
    let observed_inventory = ReachableInventory {
        scout: u64::try_from(
            future_arms
                .iter()
                .filter(|input| input.class == EvidenceClass::S)
                .count(),
        )
        .map_err(|_| Error::new("scout storage inventory exceeds u64"))?,
        williams: u64::try_from(
            future_arms
                .iter()
                .filter(|input| input.class == EvidenceClass::C)
                .count(),
        )
        .map_err(|_| Error::new("Williams storage inventory exceeds u64"))?,
        direct: u64::try_from(
            future_arms
                .iter()
                .filter(|input| input.class == EvidenceClass::D)
                .count(),
        )
        .map_err(|_| Error::new("direct storage inventory exceeds u64"))?,
        authoritative: u64::try_from(
            future_arms
                .iter()
                .filter(|input| input.class == EvidenceClass::A)
                .count(),
        )
        .map_err(|_| Error::new("authoritative storage inventory exceeds u64"))?,
    };
    if observed_inventory != inventory {
        return Err(Error::new(
            "reached-branch arm inputs differ from the declared inventory",
        ));
    }
    let mut future_member_lengths = future_unit_member_lengths.to_vec();
    let mut future_arm_payload_bytes = 0_u64;
    for input in future_arms {
        let bounds = component_bounds(input)?;
        future_arm_payload_bytes = future_arm_payload_bytes
            .checked_add(bounds.total)
            .ok_or_else(|| Error::new("reached-branch arm payload overflow"))?;
        future_member_lengths.extend(bounds.member_lengths());
    }
    let completed_payload_bytes = checked_sum(completed_member_lengths)?;
    let future_unit_payload_bytes = checked_sum(future_unit_member_lengths)?;
    let future_raw_bytes = future_arm_payload_bytes
        .checked_add(future_unit_payload_bytes)
        .ok_or_else(|| Error::new("reached-branch future payload overflow"))?;
    let extracted_source_bound_bytes = completed_payload_bytes
        .checked_add(future_raw_bytes)
        .ok_or_else(|| Error::new("reached-branch source payload overflow"))?;
    let mut archive_members = completed_member_lengths.to_vec();
    archive_members.extend(future_member_lengths);
    let canonical_archive_bound_bytes = ustar_bound(&archive_members)?;
    let canonical_usize = usize::try_from(canonical_archive_bound_bytes)
        .map_err(|_| Error::new("canonical archive bound exceeds usize"))?;
    let compressed_bound_bytes = u64::try_from(zstd_safe::compress_bound(canonical_usize))
        .map_err(|_| Error::new("Zstandard compression bound exceeds u64"))?;
    let raw = raw_execution_projection(
        future_raw_bytes,
        compressed_bound_bytes,
        extracted_source_bound_bytes,
        encoder_workspace_bytes,
        observed_free_bytes,
    )?;
    let tracked_total_bound_bytes = tracked_actual_bytes
        .checked_add(tracked_remaining_maximum_bytes)
        .ok_or_else(|| Error::new("reached-branch tracked total overflow"))?;
    let tracked_admissible = tracked_total_bound_bytes <= TASK_CAP_BYTES;
    let projection = ReachedBranchProjection {
        gate_id: gate_id.to_owned(),
        next_ordinal,
        inventory,
        completed_member_count: u64::try_from(completed_member_lengths.len())
            .map_err(|_| Error::new("completed storage member count exceeds u64"))?,
        archive_member_lengths: archive_members,
        completed_payload_bytes,
        future_arm_payload_bytes,
        future_unit_payload_bytes,
        future_raw_bytes,
        canonical_archive_bound_bytes,
        compressed_bound_bytes,
        extracted_source_bound_bytes,
        admissible: raw.admissible && tracked_admissible,
        raw,
        tracked_actual_bytes,
        tracked_remaining_maximum_bytes,
        tracked_total_bound_bytes,
        task_cap_bytes: TASK_CAP_BYTES,
        tracked_admissible,
    };
    projection.validate()?;
    Ok(projection)
}

pub fn raw_execution_projection(
    future_raw_bytes: u64,
    compressed_bound_bytes: u64,
    extracted_source_bytes: u64,
    encoder_workspace_bytes: u64,
    observed_free_bytes: u64,
) -> Result<RawExecutionProjection> {
    let canonical_buffer_bytes = MIB;
    let chunk_compare_buffers_bytes = checked_mul(2, CHUNK_BYTES)?;
    let verification_bytes = checked_sum(&[
        extracted_source_bytes,
        encoder_workspace_bytes,
        canonical_buffer_bytes,
        chunk_compare_buffers_bytes,
    ])?;
    let coexistence_bytes =
        checked_sum(&[future_raw_bytes, compressed_bound_bytes, verification_bytes])?;
    let doubled_coexistence_bytes = checked_mul(2, coexistence_bytes)?;
    let fixed_free_reserve_bytes = checked_mul(20, GIB)?;
    let required_free_bytes_exclusive =
        checked_sum(&[doubled_coexistence_bytes, fixed_free_reserve_bytes])?;
    Ok(RawExecutionProjection {
        future_raw_bytes,
        compressed_bound_bytes,
        extracted_source_bytes,
        encoder_workspace_bytes,
        canonical_buffer_bytes,
        chunk_compare_buffers_bytes,
        coexistence_bytes,
        doubled_coexistence_bytes,
        fixed_free_reserve_bytes,
        required_free_bytes_exclusive,
        observed_free_bytes,
        admissible: observed_free_bytes > required_free_bytes_exclusive,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionWitness {
    pub match_key: String,
    pub component: String,
    pub compressed_bytes_per_arm: u64,
    pub compressed_record_count: u64,
    pub witness_sha256: String,
    pub compressed_bytes_per_record: u64,
    pub record_witness_sha256: String,
}

impl CompressionWitness {
    pub fn validate(&self) -> Result<()> {
        if self.match_key.is_empty()
            || self.match_key.len() > 1_024
            || self.component.is_empty()
            || !matches!(
                self.component.as_str(),
                "metadata.json"
                    | "quiet.json"
                    | "thread-map.json"
                    | "thread-lifecycle.bin"
                    | "session-clock.bin"
                    | "resources.bin"
                    | "endpoints.bin"
                    | "operation-summary.bin"
                    | "latencies.u64le"
            )
            || self.compressed_bytes_per_arm == 0
            || self.compressed_record_count == 0
            || self.compressed_bytes_per_record == 0
        {
            return Err(Error::new("invalid compression-profile witness"));
        }
        crate::schema::validate_non_placeholder_sha256("witness_sha256", &self.witness_sha256)?;
        crate::schema::validate_non_placeholder_sha256(
            "record_witness_sha256",
            &self.record_witness_sha256,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionProfile {
    pub schema: String,
    pub evidence_id: String,
    pub intent_sha256: String,
    pub witnesses: Vec<CompressionWitness>,
    pub root_sha256: String,
}

impl CompressionProfile {
    pub fn validate(&self) -> Result<()> {
        if self.schema != COMPRESSION_PROFILE_SCHEMA || self.evidence_id.is_empty() {
            return Err(Error::new(
                "unsupported or unidentified compression profile",
            ));
        }
        crate::schema::validate_identifier("compression profile evidence_id", &self.evidence_id)?;
        crate::schema::validate_non_placeholder_sha256(
            "compression profile intent",
            &self.intent_sha256,
        )?;
        crate::schema::validate_non_placeholder_sha256(
            "compression profile root",
            &self.root_sha256,
        )?;
        let mut previous: Option<(&[u8], &[u8])> = None;
        for witness in &self.witnesses {
            witness.validate()?;
            let key = (witness.match_key.as_bytes(), witness.component.as_bytes());
            if previous.is_some_and(|old| old >= key) {
                return Err(Error::new(
                    "compression witnesses are not strictly sorted and unique",
                ));
            }
            previous = Some(key);
        }
        if compression_profile_root(&self.witnesses)? != self.root_sha256 {
            return Err(Error::new(
                "compression profile root differs from its witnesses",
            ));
        }
        Ok(())
    }
}

pub fn compression_profile_root(witnesses: &[CompressionWitness]) -> Result<String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"amg-http2-perf/compression-profile-root/v1\0");
    for witness in witnesses {
        witness.validate()?;
        for value in [witness.match_key.as_bytes(), witness.component.as_bytes()] {
            let length = u32::try_from(value.len())
                .map_err(|_| Error::new("compression profile string exceeds u32"))?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(value);
        }
        bytes.extend_from_slice(&witness.compressed_bytes_per_arm.to_be_bytes());
        bytes.extend_from_slice(&witness.compressed_record_count.to_be_bytes());
        bytes.extend_from_slice(witness.witness_sha256.as_bytes());
        bytes.extend_from_slice(&witness.compressed_bytes_per_record.to_be_bytes());
        bytes.extend_from_slice(witness.record_witness_sha256.as_bytes());
    }
    Ok(sha256_hex(&bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionRequirement {
    pub match_key: String,
    pub component: String,
    pub future_records: u64,
    pub future_arms: u64,
}

pub fn verified_compression_projection(
    profile: &CompressionProfile,
    requirements: &[CompressionRequirement],
) -> Result<u64> {
    profile.validate()?;
    let lookup = profile
        .witnesses
        .iter()
        .map(|witness| {
            (
                (witness.match_key.as_str(), witness.component.as_str()),
                witness,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    requirements.iter().try_fold(0_u64, |total, requirement| {
        if requirement.match_key.is_empty()
            || requirement.component.is_empty()
            || requirement.future_arms == 0
        {
            return Err(Error::new("invalid compression projection requirement"));
        }
        let witness = lookup
            .get(&(
                requirement.match_key.as_str(),
                requirement.component.as_str(),
            ))
            .ok_or_else(|| Error::new("compression profile lacks an exact matching component"))?;
        let per_arm = projected_component_bytes(witness, requirement.future_records)?;
        let term = per_arm
            .checked_mul(requirement.future_arms)
            .ok_or_else(|| Error::new("compression projection arm product overflow"))?;
        total
            .checked_add(term)
            .ok_or_else(|| Error::new("compression projection total overflow"))
    })
}

pub fn projected_component_bytes(witness: &CompressionWitness, future_records: u64) -> Result<u64> {
    witness.validate()?;
    let rounded_per_record = ceil_div(
        witness.compressed_bytes_per_arm,
        witness.compressed_record_count,
    )?;
    if witness.compressed_bytes_per_record < rounded_per_record {
        return Err(Error::new(
            "compression profile per-record maximum underpredicts its arm witness",
        ));
    }
    let record_projection = witness
        .compressed_bytes_per_record
        .checked_mul(future_records.max(1))
        .ok_or_else(|| Error::new("component record projection overflow"))?;
    witness
        .compressed_bytes_per_arm
        .max(record_projection)
        .checked_mul(2)
        .ok_or_else(|| Error::new("2x component projection overflow"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackedProjection {
    pub prior_bytes: u64,
    pub calibration_bytes: u64,
    pub authoritative_projection_bytes: u64,
    pub direct_projection_bytes: u64,
    pub fixed_overhead_bytes: u64,
    pub projected_total_bytes: u64,
    pub task_cap_bytes: u64,
    pub admissible: bool,
}

pub fn tracked_projection(
    prior_bytes: u64,
    calibration_bytes: u64,
    authoritative_terms: &[u64],
    direct_terms: &[u64],
    fixed_overhead_bytes: u64,
) -> Result<TrackedProjection> {
    let minimum_fixed_overhead = checked_mul(5, MIB)?;
    if fixed_overhead_bytes < minimum_fixed_overhead {
        return Err(Error::new(
            "tracked projection omits the five mandatory 1 MiB fixed-output reserves",
        ));
    }
    let authoritative_projection_bytes = checked_sum(authoritative_terms)?;
    let direct_projection_bytes = checked_sum(direct_terms)?;
    let projected_total_bytes = checked_sum(&[
        prior_bytes,
        calibration_bytes,
        authoritative_projection_bytes,
        direct_projection_bytes,
        fixed_overhead_bytes,
    ])?;
    Ok(TrackedProjection {
        prior_bytes,
        calibration_bytes,
        authoritative_projection_bytes,
        direct_projection_bytes,
        fixed_overhead_bytes,
        projected_total_bytes,
        task_cap_bytes: TASK_CAP_BYTES,
        admissible: projected_total_bytes <= TASK_CAP_BYTES,
    })
}

#[must_use]
pub const fn actual_cap_allows(bytes: u64) -> bool {
    bytes <= TASK_CAP_BYTES
}

pub fn actual_checkpoint_allows(actual_bytes: u64, remaining_formal_maximum: u64) -> Result<bool> {
    let committed_total = actual_bytes
        .checked_add(remaining_formal_maximum)
        .ok_or_else(|| Error::new("actual checkpoint byte total overflow"))?;
    Ok(committed_total <= TASK_CAP_BYTES)
}

pub fn actual_regular_bytes(root: &Path) -> Result<u64> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        Error::new(format!(
            "cannot stat artifact root {}: {error}",
            root.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(Error::new("artifact root is not a directory"));
    }
    walk_regular_bytes(root)
}

pub fn actual_regular_bytes_if_exists(root: &Path) -> Result<u64> {
    match fs::symlink_metadata(root) {
        Ok(_) => actual_regular_bytes(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(Error::new(format!(
            "cannot inspect artifact root {}: {error}",
            root.display()
        ))),
    }
}

fn walk_regular_bytes(directory: &Path) -> Result<u64> {
    let mut total = 0_u64;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let kind = metadata.file_type();
        if kind.is_symlink() {
            return Err(Error::new(format!(
                "artifact link is forbidden: {}",
                path.display()
            )));
        }
        if kind.is_dir() {
            total = total
                .checked_add(walk_regular_bytes(&path)?)
                .ok_or_else(|| Error::new("artifact byte total overflow"))?;
        } else if kind.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(Error::new(format!(
                        "artifact hard link is forbidden: {}",
                        path.display()
                    )));
                }
            }
            let maximum = if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".tar.zst.part"))
            {
                CHUNK_BYTES
            } else {
                MIB
            };
            if metadata.len() > maximum {
                return Err(Error::new(format!(
                    "artifact file exceeds its class limit: {}",
                    path.display()
                )));
            }
            total = total
                .checked_add(metadata.len())
                .ok_or_else(|| Error::new("artifact byte total overflow"))?;
        } else {
            return Err(Error::new(format!(
                "non-regular artifact is forbidden: {}",
                path.display()
            )));
        }
    }
    Ok(total)
}

fn ceil_div(numerator: u64, denominator: u64) -> Result<u64> {
    if denominator == 0 {
        return Err(Error::new("division by zero"));
    }
    numerator
        .checked_add(denominator - 1)
        .map(|value| value / denominator)
        .ok_or_else(|| Error::new("ceiling division overflow"))
}

fn checked_mul(left: u64, right: u64) -> Result<u64> {
    left.checked_mul(right)
        .ok_or_else(|| Error::new("storage multiplication overflow"))
}

fn checked_sum(values: &[u64]) -> Result<u64> {
    values.iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(*value)
            .ok_or_else(|| Error::new("storage sum overflow"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_component_rows_and_ustar_padding_are_bounded() {
        let scout = component_bounds(&ArmStorageInput {
            class: EvidenceClass::S,
            gateway: true,
            duration_ns: 15_000_000_000,
            tid_slots: 8,
            lifecycle_events: 10,
            connection_records: 200,
            latency_records: 0,
            concurrency: 64,
        })
        .expect("scout bound");
        assert_eq!(scout.thread_lifecycle_bin, 97_216);
        assert_eq!(scout.session_clock_bin, 192_384);
        assert_eq!(scout.resources_bin, 1_070_208);
        assert_eq!(scout.endpoints_bin, 65_280);
        assert_eq!(scout.operation_summary_bin, 6_400);
        assert_eq!(scout.latencies_u64le, 0);
        assert_eq!(ustar_bound(&[]).expect("empty archive bound"), 1_024);
        assert_eq!(ustar_bound(&[0, 1, 512, 513]).expect("ustar bound"), 5_120);
    }

    #[test]
    fn evidence_classes_enforce_latency_storage() {
        let mut input = ArmStorageInput {
            class: EvidenceClass::A,
            gateway: true,
            duration_ns: 5_000_000_000,
            tid_slots: 4,
            lifecycle_events: 2,
            connection_records: 1,
            latency_records: 5_000,
            concurrency: 1,
        };
        assert_eq!(
            component_bounds(&input).expect("A bound").latencies_u64le,
            40_032
        );
        input.class = EvidenceClass::D;
        assert!(component_bounds(&input).is_err());
        input.latency_records = 0;
        assert_eq!(
            component_bounds(&input).expect("D bound").latencies_u64le,
            0
        );
    }

    #[test]
    fn reachable_branches_never_cartesian_reserve() {
        assert_eq!(
            reachable_inventory(ReachableBranch::BeforeSmoke, None).expect("smoke"),
            ReachableInventory {
                scout: 0,
                williams: 0,
                direct: 0,
                authoritative: 0,
            }
        );
        assert_eq!(
            reachable_inventory(ReachableBranch::BeforeFirstScout, None).expect("scout"),
            ReachableInventory {
                scout: 525,
                williams: 0,
                direct: 0,
                authoritative: 0,
            }
        );
        assert_eq!(
            reachable_inventory(ReachableBranch::BeforeWilliams, None).expect("Williams"),
            ReachableInventory {
                scout: 0,
                williams: 750,
                direct: 0,
                authoritative: 0,
            }
        );
        assert_eq!(
            reachable_inventory(ReachableBranch::AuthoritativeContinuation, Some(30))
                .expect("N=30"),
            ReachableInventory {
                scout: 0,
                williams: 0,
                direct: 90,
                authoritative: 2_250,
            }
        );
        assert!(reachable_inventory(ReachableBranch::AuthoritativeContinuation, Some(70)).is_err());
        assert_eq!(
            reachable_inventory(ReachableBranch::Terminal, Some(100)).expect("terminal"),
            ReachableInventory {
                scout: 0,
                williams: 0,
                direct: 0,
                authoritative: 0,
            }
        );
    }

    #[test]
    fn raw_execution_projection_includes_streaming_scratch_double_and_20_gib_reserve() {
        let projection =
            raw_execution_projection(1, 2, 3, 4, u64::MAX).expect("raw execution projection");
        assert_eq!(projection.canonical_buffer_bytes, MIB);
        assert_eq!(projection.chunk_compare_buffers_bytes, 2 * CHUNK_BYTES);
        assert_eq!(projection.fixed_free_reserve_bytes, 20 * GIB);
        assert_eq!(
            projection.coexistence_bytes,
            1 + 2 + 3 + 4 + MIB + 2 * CHUNK_BYTES
        );
        assert!(projection.admissible);
        let exact = raw_execution_projection(1, 2, 3, 4, projection.required_free_bytes_exclusive)
            .expect("strict free-space equality");
        assert!(!exact.admissible, "RFC free-space gate is strict >");
    }

    #[test]
    fn two_x_component_projection_rounds_up_and_keeps_fixed_overhead() {
        let witness = CompressionWitness {
            match_key: "C11/get/c16".to_owned(),
            component: "resources.bin".to_owned(),
            compressed_bytes_per_arm: 101,
            compressed_record_count: 10,
            witness_sha256: "22".repeat(32),
            compressed_bytes_per_record: 11,
            record_witness_sha256: "11".repeat(32),
        };
        assert_eq!(projected_component_bytes(&witness, 5).expect("small"), 202);
        assert_eq!(projected_component_bytes(&witness, 20).expect("large"), 440);
    }

    #[test]
    fn tracked_and_actual_cap_accept_equality_and_reject_one_byte_over() {
        let fixed = 5 * MIB;
        let projection = tracked_projection(TASK_CAP_BYTES - fixed - 3, 1, &[1], &[1], fixed)
            .expect("equal projection");
        assert_eq!(projection.projected_total_bytes, TASK_CAP_BYTES);
        assert!(projection.admissible);
        let over = tracked_projection(TASK_CAP_BYTES - fixed - 2, 1, &[1], &[1], fixed)
            .expect("over projection");
        assert!(!over.admissible);
        assert!(actual_cap_allows(TASK_CAP_BYTES));
        assert!(!actual_cap_allows(TASK_CAP_BYTES + 1));
        assert!(actual_checkpoint_allows(TASK_CAP_BYTES - 1, 1).expect("checkpoint equality"));
        assert!(!actual_checkpoint_allows(TASK_CAP_BYTES - 1, 2).expect("checkpoint over"));
    }

    #[test]
    fn verified_component_profile_requires_exact_matches_and_blocks_underprediction() {
        let witness = CompressionWitness {
            match_key: "gateway:C11:get:c16:down-h1-persistent:up-h1-persistent".to_owned(),
            component: "resources.bin".to_owned(),
            compressed_bytes_per_arm: 101,
            compressed_record_count: 10,
            witness_sha256: "12".repeat(32),
            compressed_bytes_per_record: 11,
            record_witness_sha256: "34".repeat(32),
        };
        let witnesses = vec![witness.clone()];
        let profile = CompressionProfile {
            schema: COMPRESSION_PROFILE_SCHEMA.to_owned(),
            evidence_id: "calibration-fixture".to_owned(),
            intent_sha256: "56".repeat(32),
            root_sha256: compression_profile_root(&witnesses).expect("profile root"),
            witnesses,
        };
        let requirement = CompressionRequirement {
            match_key: witness.match_key.clone(),
            component: witness.component.clone(),
            future_records: 20,
            future_arms: 2,
        };
        assert_eq!(
            verified_compression_projection(&profile, std::slice::from_ref(&requirement))
                .expect("verified projection"),
            880
        );
        let mut missing = requirement;
        missing.match_key.push_str(":different-policy");
        assert!(verified_compression_projection(&profile, &[missing]).is_err());

        let mut underpredicted = profile;
        underpredicted.witnesses[0].compressed_bytes_per_record = 10;
        underpredicted.root_sha256 =
            compression_profile_root(&underpredicted.witnesses).expect("mutated root");
        assert!(projected_component_bytes(&underpredicted.witnesses[0], 20).is_err());
    }

    #[test]
    fn every_reached_branch_projects_raw_archive_recompression_reserve_and_cap() {
        for (ordinal, (branch, n)) in [
            (ReachableBranch::BeforeSmoke, None),
            (ReachableBranch::BeforeFirstScout, None),
            (ReachableBranch::BeforeWilliams, None),
            (ReachableBranch::BeforeCalibrationDirect, Some(30)),
            (ReachableBranch::AuthoritativeContinuation, Some(50)),
            (ReachableBranch::Terminal, None),
        ]
        .into_iter()
        .enumerate()
        {
            let inventory = reachable_inventory(branch, n).expect("inventory");
            let mut arms = Vec::new();
            for (class, count) in [
                (EvidenceClass::S, inventory.scout),
                (EvidenceClass::C, inventory.williams),
                (EvidenceClass::D, inventory.direct),
                (EvidenceClass::A, inventory.authoritative),
            ] {
                for _ in 0..count {
                    arms.push(ArmStorageInput {
                        class,
                        gateway: class != EvidenceClass::D,
                        duration_ns: 5_000_000_000,
                        tid_slots: 4,
                        lifecycle_events: 4,
                        connection_records: 137,
                        latency_records: if class.has_latencies() { 5_000 } else { 0 },
                        concurrency: 1,
                    });
                }
            }
            let gate_id = format!("gate-{ordinal}");
            let projection = reached_branch_projection(ReachedBranchInput {
                gate_id: &gate_id,
                next_ordinal: 0,
                inventory,
                completed_member_lengths: &[17, 31],
                future_arms: &arms,
                future_unit_member_lengths: &[MIB, MIB],
                encoder_workspace_bytes: 8 * MIB,
                observed_free_bytes: u64::MAX,
                tracked_actual_bytes: 1,
                tracked_remaining_maximum_bytes: 5 * MIB,
            })
            .expect("reached branch projection");
            assert!(projection.admissible);
            assert_eq!(
                projection.raw.canonical_buffer_bytes, MIB,
                "canonical reconstruction buffer"
            );
            assert_eq!(projection.raw.chunk_compare_buffers_bytes, 2 * CHUNK_BYTES);
            assert_eq!(projection.raw.fixed_free_reserve_bytes, 20 * GIB);
            assert!(projection.canonical_archive_bound_bytes >= projection.future_raw_bytes);
            assert!(projection.compressed_bound_bytes > 0);
            assert!(
                u64::try_from(
                    crate::json::canonical_bytes(&projection)
                        .expect("projection JSON")
                        .len()
                )
                .expect("projection JSON length")
                    <= crate::schema::JSON_MAX_BYTES
            );
        }

        let terminal = reachable_inventory(ReachableBranch::Terminal, None).expect("terminal");
        let projected = reached_branch_projection(ReachedBranchInput {
            gate_id: "terminal-cap",
            next_ordinal: 0,
            inventory: terminal,
            completed_member_lengths: &[1],
            future_arms: &[],
            future_unit_member_lengths: &[1],
            encoder_workspace_bytes: 1,
            observed_free_bytes: u64::MAX,
            tracked_actual_bytes: TASK_CAP_BYTES,
            tracked_remaining_maximum_bytes: 1,
        })
        .expect("tracked over-cap projection");
        assert!(!projected.tracked_admissible);
        assert!(!projected.admissible);
        let exact_free = reached_branch_projection(ReachedBranchInput {
            gate_id: "terminal-free",
            next_ordinal: 0,
            inventory: terminal,
            completed_member_lengths: &[1],
            future_arms: &[],
            future_unit_member_lengths: &[1],
            encoder_workspace_bytes: 1,
            observed_free_bytes: u64::MAX,
            tracked_actual_bytes: 0,
            tracked_remaining_maximum_bytes: 0,
        })
        .expect("free projection");
        let blocked = reached_branch_projection(ReachedBranchInput {
            gate_id: "terminal-free",
            next_ordinal: 0,
            inventory: terminal,
            completed_member_lengths: &[1],
            future_arms: &[],
            future_unit_member_lengths: &[1],
            encoder_workspace_bytes: 1,
            observed_free_bytes: exact_free.raw.required_free_bytes_exclusive,
            tracked_actual_bytes: 0,
            tracked_remaining_maximum_bytes: 0,
        })
        .expect("strict free gate");
        assert!(!blocked.raw.admissible);
    }
}
