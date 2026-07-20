//! Bounded full-concurrency materialization and inventory-stability evidence.

use crate::control::{
    ConnectionLedger, ConnectionPolicy, InventoryCheckpoint, InventoryStabilityObservation,
    LoadResult, ThreadInventory,
};
use crate::schema::{validate_non_placeholder_sha256, Cell, Workload};
use crate::topology::{parse_operation_id, Protocol};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MATERIALIZATION_SCHEMA: &str = "amg-http2-perf/materialization/v1";
pub const MATERIALIZATION_PHASE_BASE: u16 = 16_384;
pub const MIN_UNCHANGED_FULL_WAVES: u16 = 2;
pub const MAX_FULL_WAVES: u16 = 16;
pub const INVENTORY_STABILITY_NS: u64 = 100_000_000;
pub const INVENTORY_STABILITY_SLACK_NS: u64 = 100_000_000;
pub const PROCESS_STABILITY_CAP_NS: u64 = 2_000_000_000;
pub const SMOKE_STABILITY_CAP_NS: u64 = 5_000_000_000;
pub const CAP_FINALIZATION_SLACK_NS: u64 = 100_000_000;
pub const FREEZE_HANDOFF_CAP_NS: u64 = 1_000_000_000;
pub const MEASURE_HANDOFF_CAP_NS: u64 = 250_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializationOutcome {
    Stable,
    CapExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationWaveEvidence {
    pub ordinal: u16,
    pub phase: u16,
    pub before: InventoryCheckpoint,
    pub result: LoadResult,
    pub after: InventoryCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationEvidence {
    pub schema: String,
    pub cell: Cell,
    pub protocol: Protocol,
    pub authenticated: bool,
    pub minimum_unchanged_full_waves: u16,
    pub maximum_full_waves: u16,
    pub cap_ns: u64,
    pub start_ns: u64,
    pub end_ns: u64,
    pub outcome: MaterializationOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prelude: Option<LoadResult>,
    pub waves: Vec<MaterializationWaveEvidence>,
    pub stability_observations: Vec<InventoryStabilityObservation>,
    pub operations_started: u64,
    pub operations_completed: u64,
    pub lane_starts: Vec<u64>,
    pub lane_completions: Vec<u64>,
    pub operation_root_sha256: String,
    pub connection_root_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_inventory_signature_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_tid_signature_sha256: Option<String>,
}

impl MaterializationEvidence {
    pub fn validate(&self) -> Result<()> {
        self.cell.validate()?;
        if self.schema != MATERIALIZATION_SCHEMA
            || self.cell.workload == Workload::WebSocket
            || !self.authenticated
            || self.minimum_unchanged_full_waves != MIN_UNCHANGED_FULL_WAVES
            || self.maximum_full_waves != MAX_FULL_WAVES
            || !matches!(
                self.cap_ns,
                PROCESS_STABILITY_CAP_NS | SMOKE_STABILITY_CAP_NS
            )
            || self.start_ns >= self.end_ns
            || self.end_ns.saturating_sub(self.start_ns)
                > self.cap_ns.saturating_add(CAP_FINALIZATION_SLACK_NS)
            || self.waves.is_empty()
            || self.waves.len() > usize::from(MAX_FULL_WAVES)
        {
            return Err(Error::new(
                "materialization identity/cap evidence is invalid",
            ));
        }
        validate_non_placeholder_sha256(
            "materialization operation root",
            &self.operation_root_sha256,
        )?;
        validate_non_placeholder_sha256(
            "materialization connection root",
            &self.connection_root_sha256,
        )?;

        let concurrency = usize::from(self.cell.concurrency);
        if self.lane_starts.len() != concurrency || self.lane_completions.len() != concurrency {
            return Err(Error::new(
                "materialization aggregate lane inventory differs from concurrency",
            ));
        }

        let mut operation_hashes = Vec::new();
        let mut connection_hashes = Vec::new();
        let mut operations_started = 0_u64;
        let mut operations_completed = 0_u64;
        let mut lane_starts = vec![0_u64; concurrency];
        let mut lane_completions = vec![0_u64; concurrency];
        if let Some(prelude) = &self.prelude {
            validate_prelude(prelude, self.cell, self.protocol)?;
            accumulate_result(
                prelude,
                &mut operations_started,
                &mut operations_completed,
                &mut lane_starts,
                &mut lane_completions,
            )?;
            operation_hashes.push((2_u16, prelude.operation_hash_sha256.as_str()));
            connection_hashes.push((
                2_u16,
                prelude
                    .connection_ledger
                    .operation_connection_hash_sha256
                    .as_str(),
            ));
        }

        let mut previous_after = None;
        let mut unchanged_waves = 0_u16;
        for (index, wave) in self.waves.iter().enumerate() {
            let expected_ordinal = u16::try_from(index)
                .map_err(|_| Error::new("materialization wave ordinal overflow"))?;
            let expected_phase = MATERIALIZATION_PHASE_BASE
                .checked_add(expected_ordinal)
                .ok_or_else(|| Error::new("materialization phase overflow"))?;
            if wave.ordinal != expected_ordinal || wave.phase != expected_phase {
                return Err(Error::new(
                    "materialization wave ordinal/phase is not contiguous",
                ));
            }
            wave.before.validate()?;
            wave.after.validate()?;
            if previous_after
                .as_ref()
                .is_some_and(|checkpoint| checkpoint != &wave.before)
                || wave.before.monotonic_ns > wave.result.window_start_ns
                || wave.result.window_end_ns > wave.after.monotonic_ns
            {
                return Err(Error::new(
                    "materialization wave/checkpoint ordering is not exact",
                ));
            }
            validate_full_wave(&wave.result, self.cell, self.protocol, wave.phase)?;
            if checkpoints_match(&wave.before, &wave.after) {
                unchanged_waves = unchanged_waves
                    .checked_add(1)
                    .ok_or_else(|| Error::new("unchanged-wave counter overflow"))?;
            } else {
                unchanged_waves = 0;
            }
            previous_after = Some(wave.after.clone());
            accumulate_result(
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
        if operations_started != self.operations_started
            || operations_completed != self.operations_completed
            || lane_starts != self.lane_starts
            || lane_completions != self.lane_completions
            || self.operations_started != self.operations_completed
            || phase_hash_root(b"operation", &operation_hashes) != self.operation_root_sha256
            || phase_hash_root(b"connection", &connection_hashes) != self.connection_root_sha256
        {
            return Err(Error::new(
                "materialization operation/lane/hash aggregate does not reconcile",
            ));
        }

        match self.outcome {
            MaterializationOutcome::Stable => {
                let observation = self.stability_observations.last().ok_or_else(|| {
                    Error::new("stable materialization lacks stability observation")
                })?;
                for attempt in &self.stability_observations {
                    attempt.validate()?;
                }
                let final_checkpoint = previous_after
                    .as_ref()
                    .ok_or_else(|| Error::new("stable materialization has no final checkpoint"))?;
                if unchanged_waves < MIN_UNCHANGED_FULL_WAVES
                    || self
                        .lane_completions
                        .iter()
                        .any(|completed| *completed < u64::from(MIN_UNCHANGED_FULL_WAVES))
                    || !observation.stable
                    || !checkpoints_match(&observation.initial, final_checkpoint)
                    || !checkpoints_match(&observation.initial, &observation.final_checkpoint)
                    || self.stable_inventory_signature_sha256.as_deref()
                        != Some(
                            observation
                                .final_checkpoint
                                .inventory_signature_sha256
                                .as_str(),
                        )
                    || self.stable_tid_signature_sha256.as_deref()
                        != Some(observation.final_checkpoint.tid_signature_sha256.as_str())
                    || self.end_ns != observation.end_ns
                {
                    return Err(Error::new(
                        "materialization did not prove two unchanged waves plus stability",
                    ));
                }
            }
            MaterializationOutcome::CapExhausted => {
                for attempt in &self.stability_observations {
                    attempt.validate()?;
                }
                if self
                    .stability_observations
                    .iter()
                    .any(|attempt| attempt.stable)
                    || self.stable_inventory_signature_sha256.is_some()
                    || self.stable_tid_signature_sha256.is_some()
                    || (self.waves.len() != usize::from(MAX_FULL_WAVES)
                        && self.end_ns.saturating_sub(self.start_ns) < self.cap_ns)
                {
                    return Err(Error::new(
                        "unstable materialization does not retain its exhausted bound",
                    ));
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn stable(&self) -> bool {
        self.outcome == MaterializationOutcome::Stable
    }

    #[must_use]
    pub fn full_wave_operations(&self) -> u64 {
        u64::try_from(self.waves.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::from(self.cell.concurrency))
    }
}

impl InventoryCheckpoint {
    pub fn validate(&self) -> Result<()> {
        if self.monotonic_ns == 0 || self.inventories.is_empty() {
            return Err(Error::new("inventory checkpoint is empty"));
        }
        validate_non_placeholder_sha256(
            "inventory checkpoint signature",
            &self.inventory_signature_sha256,
        )?;
        validate_non_placeholder_sha256(
            "inventory checkpoint TID signature",
            &self.tid_signature_sha256,
        )?;
        let (inventory, tids) = inventory_signatures(&self.inventories)?;
        if inventory != self.inventory_signature_sha256 || tids != self.tid_signature_sha256 {
            return Err(Error::new(
                "inventory checkpoint hashes differ from retained inventories",
            ));
        }
        Ok(())
    }
}

impl InventoryStabilityObservation {
    pub fn validate(&self) -> Result<()> {
        self.initial.validate()?;
        self.final_checkpoint.validate()?;
        let elapsed = self
            .end_ns
            .checked_sub(self.start_ns)
            .ok_or_else(|| Error::new("inventory stability clock moved backwards"))?;
        if self.requested_duration_ns != INVENTORY_STABILITY_NS
            || elapsed < self.requested_duration_ns
            || elapsed
                > self
                    .requested_duration_ns
                    .saturating_add(INVENTORY_STABILITY_SLACK_NS)
            || self.polls < 2
            || self.initial.monotonic_ns < self.start_ns
            || self.final_checkpoint.monotonic_ns > self.end_ns
            || (self.stable && !checkpoints_match(&self.initial, &self.final_checkpoint))
        {
            return Err(Error::new(
                "inventory stability observation is malformed or unbounded",
            ));
        }
        Ok(())
    }
}

pub fn checkpoint(
    monotonic_ns: u64,
    lifecycle_events: u64,
    inventories: Vec<ThreadInventory>,
) -> Result<InventoryCheckpoint> {
    let (inventory_signature_sha256, tid_signature_sha256) = inventory_signatures(&inventories)?;
    let checkpoint = InventoryCheckpoint {
        monotonic_ns,
        lifecycle_events,
        inventory_signature_sha256,
        tid_signature_sha256,
        inventories,
    };
    checkpoint.validate()?;
    Ok(checkpoint)
}

pub fn inventory_signatures(inventories: &[ThreadInventory]) -> Result<(String, String)> {
    if inventories.is_empty() {
        return Err(Error::new("cannot sign an empty inventory"));
    }
    let mut sorted = inventories.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|inventory| inventory.role);
    let mut roles = BTreeSet::new();
    let mut inventory_hasher = Sha256::new();
    inventory_hasher.update(b"amg-http2-perf/inventory-signature/v1\0");
    let mut tid_hasher = Sha256::new();
    tid_hasher.update(b"amg-http2-perf/tid-signature/v1\0");
    for inventory in sorted {
        if !roles.insert(inventory.role) || inventory.threads.is_empty() {
            return Err(Error::new("inventory role is duplicate or empty"));
        }
        validate_non_placeholder_sha256(
            "role semantic signature",
            &inventory.semantic_signature_sha256,
        )?;
        validate_non_placeholder_sha256("role executable signature", &inventory.executable_sha256)?;
        inventory_hasher.update(inventory.role.label().as_bytes());
        inventory_hasher.update(inventory.executable_sha256.as_bytes());
        inventory_hasher.update(inventory.semantic_signature_sha256.as_bytes());
        inventory_hasher.update((inventory.threads.len() as u64).to_be_bytes());
        tid_hasher.update(inventory.role.label().as_bytes());
        tid_hasher.update(inventory.executable_sha256.as_bytes());
        let mut threads = inventory.threads.iter().collect::<Vec<_>>();
        threads.sort_by_key(|thread| (thread.pid, thread.tid, thread.start_time_ticks));
        let mut keys = BTreeSet::new();
        for thread in threads {
            if !keys.insert((thread.pid, thread.tid, thread.start_time_ticks))
                || thread.comm.is_empty()
            {
                return Err(Error::new("inventory contains a duplicate or empty TID"));
            }
            tid_hasher.update(thread.pid.to_be_bytes());
            tid_hasher.update(thread.tid.to_be_bytes());
            tid_hasher.update(thread.start_time_ticks.to_be_bytes());
            tid_hasher.update(thread.comm.as_bytes());
        }
    }
    Ok((
        format!("{:x}", inventory_hasher.finalize()),
        format!("{:x}", tid_hasher.finalize()),
    ))
}

#[must_use]
pub fn checkpoints_match(left: &InventoryCheckpoint, right: &InventoryCheckpoint) -> bool {
    left.lifecycle_events == right.lifecycle_events
        && left.inventory_signature_sha256 == right.inventory_signature_sha256
        && left.tid_signature_sha256 == right.tid_signature_sha256
}

pub fn phase_hash_root(domain: &[u8], hashes: &[(u16, &str)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"amg-http2-perf/materialization-phase-root/v1\0");
    hasher.update(domain);
    for (phase, hash) in hashes {
        hasher.update(phase.to_be_bytes());
        hasher.update(hash.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn validate_prelude(result: &LoadResult, cell: Cell, protocol: Protocol) -> Result<()> {
    validate_common_result(result, cell, protocol)?;
    let deadline = result
        .window_deadline_ns
        .ok_or_else(|| Error::new("materialization prelude lacks a fixed deadline"))?;
    let duration = deadline
        .checked_sub(result.window_start_ns)
        .ok_or_else(|| Error::new("materialization prelude deadline underflow"))?;
    if !(3_000_000_000..=10_000_000_000).contains(&duration)
        || result.lane_completions.contains(&0)
        || operation_phase(&result.first_operation_id)? != 2
        || operation_phase(&result.last_operation_id)? != 2
    {
        return Err(Error::new(
            "materialization prelude is not a full-concurrency 3..=10s window",
        ));
    }
    Ok(())
}

fn validate_full_wave(
    result: &LoadResult,
    cell: Cell,
    protocol: Protocol,
    phase: u16,
) -> Result<()> {
    validate_common_result(result, cell, protocol)?;
    let concurrency = u64::from(cell.concurrency);
    if result.window_deadline_ns.is_some()
        || result.operations_started != concurrency
        || result.lane_quotas != vec![1; usize::from(cell.concurrency)]
        || result.lane_completions != result.lane_quotas
        || operation_phase(&result.first_operation_id)? != phase
        || operation_phase(&result.last_operation_id)? != phase
    {
        return Err(Error::new(
            "materialization wave is not one barrier-released operation per lane",
        ));
    }
    Ok(())
}

fn validate_common_result(result: &LoadResult, cell: Cell, protocol: Protocol) -> Result<()> {
    let operations = result.operations_started;
    if result.protocol != protocol
        || operations == 0
        || result.operations_completed != operations
        || result.operations_completed_by_deadline != operations
        || result.window_start_ns >= result.window_end_ns
        || !result.status_ok
        || !result.eos_ok
        || !result.payload_ok
        || !result.sse_content_type_ok
        || !result.response_headers_sanitized
        || result.retries != 0
        || !result.latencies_ns.is_empty()
        || result.attempts.starts != operations
        || result.attempts.successes != operations
        || result.attempts.failures != 0
        || result.attempts.reconnects != 0
        || result.attempts.retries != 0
        || result.lane_quotas.len() != usize::from(cell.concurrency)
        || result.lane_completions != result.lane_quotas
        || result.lane_quotas.iter().sum::<u64>() != operations
    {
        return Err(Error::new(
            "materialization operation/correctness/lane evidence is invalid",
        ));
    }
    validate_non_placeholder_sha256(
        "materialization operation hash",
        &result.operation_hash_sha256,
    )?;
    validate_connection_ledger(&result.connection_ledger, cell, protocol, operations)
}

fn validate_connection_ledger(
    ledger: &ConnectionLedger,
    cell: Cell,
    protocol: Protocol,
    operations: u64,
) -> Result<()> {
    let expected = match (protocol, cell.workload) {
        (Protocol::H1, Workload::Upload1Mib) => ConnectionPolicy::FreshH1PerOperation,
        (Protocol::H1, _) => ConnectionPolicy::PersistentH1,
        (Protocol::H2, _) => ConnectionPolicy::PersistentH2,
    };
    validate_non_placeholder_sha256(
        "materialization connection hash",
        &ledger.operation_connection_hash_sha256,
    )?;
    if ledger.policy != expected
        || ledger.requests != operations
        || ledger.responses != operations
        || ledger.response_eos != operations
        || ledger.failed_connect_attempts != 0
        || ledger.reuse_attempts != 0
        || ledger.reconnect_attempts != 0
        || ledger.retry_attempts != 0
    {
        return Err(Error::new(
            "materialization connection ledger is incomplete or unsafe",
        ));
    }
    match expected {
        ConnectionPolicy::FreshH1PerOperation => {
            if [
                ledger.planned_connections,
                ledger.socket_creations,
                ledger.connect_attempts,
                ledger.connect_successes,
                ledger.cumulative_connections,
                ledger.close_tokens,
                ledger.transport_eof,
            ]
            .into_iter()
            .any(|value| value != operations)
                || ledger.active_connections != 0
                || ledger.max_active_connections == 0
                || ledger.max_active_connections > u64::from(cell.concurrency)
                || ledger.max_requests_per_connection != 1
            {
                return Err(Error::new(
                    "fresh-H1 materialization connect/close/EOF ledger differs",
                ));
            }
        }
        ConnectionPolicy::PersistentH1 => {
            if ledger.cumulative_connections != u64::from(cell.concurrency)
                || ledger.close_tokens != 0
                || ledger.transport_eof != 0
                || ledger.h2_streams != 0
            {
                return Err(Error::new(
                    "persistent-H1 materialization connection ledger differs",
                ));
            }
        }
        ConnectionPolicy::PersistentH2 => {
            if ledger.cumulative_connections != 1
                || ledger.h2_streams != operations
                || ledger.close_tokens != 0
                || ledger.transport_eof != 0
                || ledger.max_active_h2_streams == 0
                || ledger.max_active_h2_streams > u64::from(cell.concurrency)
            {
                return Err(Error::new(
                    "persistent-H2 materialization stream ledger differs",
                ));
            }
        }
        ConnectionPolicy::H1UpgradeTunnels | ConnectionPolicy::H2ExtendedConnectStreams => {
            return Err(Error::new(
                "ordinary materialization unexpectedly uses a tunnel policy",
            ));
        }
    }
    Ok(())
}

fn accumulate_result(
    result: &LoadResult,
    operations_started: &mut u64,
    operations_completed: &mut u64,
    lane_starts: &mut [u64],
    lane_completions: &mut [u64],
) -> Result<()> {
    *operations_started = operations_started
        .checked_add(result.operations_started)
        .ok_or_else(|| Error::new("materialization start count overflow"))?;
    *operations_completed = operations_completed
        .checked_add(result.operations_completed)
        .ok_or_else(|| Error::new("materialization completion count overflow"))?;
    for ((started, completed), (result_started, result_completed)) in lane_starts
        .iter_mut()
        .zip(lane_completions.iter_mut())
        .zip(result.lane_quotas.iter().zip(&result.lane_completions))
    {
        *started = started
            .checked_add(*result_started)
            .ok_or_else(|| Error::new("materialization lane start overflow"))?;
        *completed = completed
            .checked_add(*result_completed)
            .ok_or_else(|| Error::new("materialization lane completion overflow"))?;
    }
    Ok(())
}

fn operation_phase(value: &str) -> Result<u16> {
    let operation = parse_operation_id(value)?;
    u16::try_from(operation >> 112).map_err(|_| Error::new("operation phase exceeds u16"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{AttemptEvidence, Role, ThreadIdentity};
    use crate::seal::sha256_hex;

    fn inventory(tid: u32) -> Vec<ThreadInventory> {
        let executable = sha256_hex(b"executable");
        let mut semantic = Sha256::new();
        semantic.update(b"gateway");
        semantic.update(executable.as_bytes());
        semantic.update(b"worker");
        semantic.update(0_u64.to_be_bytes());
        semantic.update(0_u16.to_be_bytes());
        vec![ThreadInventory {
            role: Role::Gateway,
            executable_sha256: executable,
            threads: vec![ThreadIdentity {
                pid: 10,
                tid,
                start_time_ticks: 20,
                comm: "worker".to_owned(),
                assigned_cpu: 0,
            }],
            semantic_signature_sha256: format!("{:x}", semantic.finalize()),
        }]
    }

    #[test]
    fn checkpoint_signatures_include_exact_tid_identity() {
        let one = checkpoint(1, 1, inventory(11)).expect("checkpoint one");
        let two = checkpoint(2, 1, inventory(12)).expect("checkpoint two");
        assert_eq!(
            one.inventory_signature_sha256,
            two.inventory_signature_sha256
        );
        assert_ne!(one.tid_signature_sha256, two.tid_signature_sha256);
        assert!(!checkpoints_match(&one, &two));
    }

    #[test]
    fn two_operations_cannot_claim_c64_full_concurrency() {
        let cell = Cell {
            workload: Workload::Get,
            concurrency: 64,
        };
        let result = LoadResult {
            protocol: Protocol::H1,
            operations_started: 2,
            operations_completed: 2,
            operations_completed_by_deadline: 2,
            window_start_ns: 2,
            window_deadline_ns: None,
            window_end_ns: 3,
            request_bytes: 0,
            response_bytes: 128,
            first_operation_id: crate::topology::operation_id_text(
                u128::from(MATERIALIZATION_PHASE_BASE) << 112,
            ),
            last_operation_id: crate::topology::operation_id_text(
                (u128::from(MATERIALIZATION_PHASE_BASE) << 112) | 1,
            ),
            operation_hash_sha256: sha256_hex(b"operations"),
            status_ok: true,
            eos_ok: true,
            payload_ok: true,
            sse_content_type_ok: true,
            response_headers_sanitized: true,
            retries: 0,
            latencies_ns: Vec::new(),
            connection_ledger: ConnectionLedger {
                policy: ConnectionPolicy::PersistentH1,
                planned_connections: 64,
                socket_creations: 64,
                connect_attempts: 64,
                connect_successes: 64,
                failed_connect_attempts: 0,
                cumulative_connections: 64,
                requests: 2,
                responses: 2,
                close_tokens: 0,
                keep_alive_tokens: 0,
                response_eos: 2,
                transport_eof: 0,
                active_connections: 64,
                max_active_connections: 64,
                max_requests_per_connection: 1,
                h2_streams: 0,
                active_h2_streams: 0,
                max_active_h2_streams: 0,
                first_h2_stream_id: None,
                last_h2_stream_id: None,
                h2_stream_sequence_sha256: sha256_hex(b"empty-streams"),
                reuse_attempts: 0,
                reconnect_attempts: 0,
                retry_attempts: 0,
                operation_connection_hash_sha256: sha256_hex(b"connections"),
            },
            h2_wire: Vec::new(),
            attempts: AttemptEvidence {
                starts: 2,
                successes: 2,
                failures: 0,
                reconnects: 0,
                retries: 0,
            },
            lane_quotas: {
                let mut lanes = vec![0; 64];
                lanes[0] = 1;
                lanes[1] = 1;
                lanes
            },
            lane_completions: {
                let mut lanes = vec![0; 64];
                lanes[0] = 1;
                lanes[1] = 1;
                lanes
            },
        };
        assert!(
            validate_full_wave(&result, cell, Protocol::H1, MATERIALIZATION_PHASE_BASE)
                .unwrap_err()
                .to_string()
                .contains("one barrier-released operation per lane")
        );
    }
}
