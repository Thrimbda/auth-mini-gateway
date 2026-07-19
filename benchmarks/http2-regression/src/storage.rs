use crate::schema::{EvidenceClass, CHUNK_BYTES, TASK_CAP_BYTES};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const KIB: u64 = 1_024;
pub const MIB: u64 = 1_048_576;
pub const GIB: u64 = 1_073_741_824;

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
    pub latencies_u64le: u64,
    pub total: u64,
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
        256,
        checked_mul(160, input.connection_records)?,
        checked_mul(128, input.concurrency)?,
    ])?;
    let operation_summary_bin = checked_sum(&[256, checked_mul(96, input.concurrency)?])?;
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
}

impl CompressionWitness {
    pub fn validate(&self) -> Result<()> {
        if self.match_key.is_empty()
            || self.component.is_empty()
            || self.compressed_bytes_per_arm == 0
            || self.compressed_record_count == 0
        {
            return Err(Error::new("invalid compression-profile witness"));
        }
        crate::schema::validate_sha256("witness_sha256", &self.witness_sha256)
    }
}

pub fn projected_component_bytes(witness: &CompressionWitness, future_records: u64) -> Result<u64> {
    witness.validate()?;
    let rounded_per_record = ceil_div(
        witness.compressed_bytes_per_arm,
        witness.compressed_record_count,
    )?;
    let record_projection = rounded_per_record
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
            connection_records: 136,
            latency_records: 0,
            concurrency: 64,
        })
        .expect("scout bound");
        assert_eq!(scout.thread_lifecycle_bin, 97_216);
        assert_eq!(scout.session_clock_bin, 192_384);
        assert_eq!(scout.resources_bin, 1_070_208);
        assert_eq!(scout.endpoints_bin, 30_208);
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
            witness_sha256: "00".repeat(32),
        };
        assert_eq!(projected_component_bytes(&witness, 5).expect("small"), 202);
        assert_eq!(projected_component_bytes(&witness, 20).expect("large"), 440);
    }

    #[test]
    fn tracked_and_actual_cap_accept_equality_and_reject_one_byte_over() {
        let projection =
            tracked_projection(TASK_CAP_BYTES - 4, 1, &[1], &[1], 1).expect("equal projection");
        assert_eq!(projection.projected_total_bytes, TASK_CAP_BYTES);
        assert!(projection.admissible);
        let over =
            tracked_projection(TASK_CAP_BYTES - 3, 1, &[1], &[1], 1).expect("over projection");
        assert!(!over.admissible);
        assert!(actual_cap_allows(TASK_CAP_BYTES));
        assert!(!actual_cap_allows(TASK_CAP_BYTES + 1));
        assert!(actual_checkpoint_allows(TASK_CAP_BYTES - 1, 1).expect("checkpoint equality"));
        assert!(!actual_checkpoint_allows(TASK_CAP_BYTES - 1, 2).expect("checkpoint over"));
    }
}
