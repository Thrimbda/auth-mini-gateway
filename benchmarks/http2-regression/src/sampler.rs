//! Separate Linux sampler role with dynamic pinning and strict post-freeze inventory.

use crate::control::{
    ControlBody, ControlContext, CpuAttribution, FramedControl, InventoryCheckpoint,
    InventoryStabilityObservation, NoiseScopeEvidence, ObservedProcess, ResourcePoint, Role,
    RoleErrorClass, RoleErrorCode, RoleErrorStage, RuntimeResidual, SamplerReport, ThreadIdentity,
    ThreadInventory,
};
use crate::linux::{
    clock_ns, parse_cpu_list, pressure_totals, process_identity, read_per_cpu_ticks,
    read_proc_stat, read_proc_status, realtime_triplet, scaling_cur_frequencies_khz, set_affinity,
    swap_counters, task_ids, tctl_millidegrees, validate_identity, ClockKind, CpuTicks,
    PressureTotals, ProcessIdentity, RealtimeTriplet, CONTROL_CPUS, FIXTURE_CPUS, GATEWAY_CPUS,
    LOAD_CPUS,
};
use crate::seal::sha256_hex;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TrackedThread {
    pub(crate) identity: ThreadIdentity,
    pub(crate) role: Role,
    pub(crate) alive: bool,
    pub(crate) last_ticks: u64,
    pub(crate) last_cpu: i32,
    pub(crate) first_seen_ns: u64,
    pub(crate) last_seen_ns: u64,
    pub(crate) provisional_pin_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BoundarySnapshot {
    pub(crate) monotonic_ns: u64,
    pub(crate) boottime_ns: u64,
    #[serde(with = "tid_tick_map")]
    pub(crate) tid_before: BTreeMap<(u32, u32), u64>,
    pub(crate) cpus: BTreeMap<u16, CpuTicks>,
    #[serde(with = "tid_tick_map")]
    pub(crate) tid_after: BTreeMap<(u32, u32), u64>,
    pub(crate) process_before: BTreeMap<Role, u64>,
    pub(crate) process_after: BTreeMap<Role, u64>,
    #[serde(with = "tid_cpu_map")]
    pub(crate) tid_cpu: BTreeMap<(u32, u32), u16>,
    pub(crate) process_resources: BTreeMap<Role, ResourcePoint>,
}

mod tid_tick_map {
    use super::*;
    use serde::{Deserializer, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entry {
        pid: u32,
        tid: u32,
        ticks: u64,
    }

    pub fn serialize<S>(
        value: &BTreeMap<(u32, u32), u64>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .iter()
            .map(|(&(pid, tid), &ticks)| Entry { pid, tid, ticks })
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<(u32, u32), u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<Entry>::deserialize(deserializer)?;
        let mut output = BTreeMap::new();
        for entry in entries {
            if output.insert((entry.pid, entry.tid), entry.ticks).is_some() {
                return Err(serde::de::Error::custom(
                    "duplicate persistent TID tick key",
                ));
            }
        }
        Ok(output)
    }
}

mod tid_cpu_map {
    use super::*;
    use serde::{Deserializer, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entry {
        pid: u32,
        tid: u32,
        cpu: u16,
    }

    pub fn serialize<S>(
        value: &BTreeMap<(u32, u32), u16>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .iter()
            .map(|(&(pid, tid), &cpu)| Entry { pid, tid, cpu })
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<(u32, u32), u16>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<Entry>::deserialize(deserializer)?;
        let mut output = BTreeMap::new();
        for entry in entries {
            if output.insert((entry.pid, entry.tid), entry.cpu).is_some() {
                return Err(serde::de::Error::custom("duplicate persistent TID CPU key"));
            }
        }
        Ok(output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SamplerPersistentEvidence {
    pub(crate) schema: String,
    pub(crate) report: SamplerReport,
    pub(crate) boundaries: Vec<BoundarySnapshot>,
    pub(crate) threads: Vec<TrackedThread>,
    pub(crate) lifecycle_poll_max_ns: u64,
    pub(crate) realtime_triplets: Vec<RealtimeTriplet>,
}

#[derive(Default)]
struct SamplerState {
    processes: Vec<ObservedProcess>,
    threads: BTreeMap<(u32, u32), TrackedThread>,
    lifecycle_events: u64,
    births_before_freeze: u64,
    deaths_before_freeze: u64,
    births_after_freeze: u64,
    deaths_after_freeze: u64,
    migrations_after_freeze: u64,
    frozen: bool,
    frozen_keys: BTreeSet<(u32, u32)>,
    post_freeze_change: Option<String>,
    freeze_boundary: Option<BoundarySnapshot>,
    gateway_stopped: bool,
    poll_error: Option<String>,
    last_poll_ns: Option<u64>,
    lifecycle_poll_max_ns: u64,
    frozen_lifecycle_poll_max_ns: Option<u64>,
    boundaries: Vec<BoundarySnapshot>,
    last_boundary_ns: Option<u64>,
    pressure_start: Option<PressureTotals>,
    swap_start: Option<(u64, u64)>,
    major_faults_start: Option<u64>,
    tctl_start: Option<u64>,
    tctl_max: Option<u64>,
    last_environment_ns: Option<u64>,
    frequency_samples: Vec<u64>,
    realtime_samples: u64,
    realtime_discontinuities: u64,
    last_realtime: Option<RealtimeTriplet>,
    realtime_triplets: Vec<RealtimeTriplet>,
    evidence_root: Option<PathBuf>,
}

pub async fn run_sampler_role(_context: ControlContext, control: &mut FramedControl) -> Result<()> {
    control
        .authenticate_inherited_role(Role::Sampler, process_identity(std::process::id())?)
        .await?;
    control.mark_failure_stage(RoleErrorStage::Startup);
    control
        .send(ControlBody::Ready {
            role: Role::Sampler,
            data_address: None,
            tripwire_address: None,
        })
        .await?;
    let state = Arc::new(Mutex::new(SamplerState::default()));
    let polling_state = Arc::clone(&state);
    let (poll_error_sender, mut poll_error_receiver) = tokio::sync::mpsc::unbounded_channel();
    let poller = tokio::spawn(async move {
        loop {
            let result = polling_state
                .lock()
                .map_err(|_| Error::new("background sampler state poisoned"))
                .and_then(|mut state| state.poll_tick());
            if let Err(error) = result {
                if let Ok(mut state) = polling_state.lock() {
                    state.poll_error = Some(error.to_string());
                }
                let _ = poll_error_sender.send(error.to_string());
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    loop {
        let message = tokio::select! {
            error = poll_error_receiver.recv() => {
                let detail = error.unwrap_or_else(|| {
                    "background sampler stopped without a result".to_owned()
                });
                let _ = control
                    .send_terminal_error(
                        RoleErrorClass::Command,
                        control.failure_stage(),
                        RoleErrorCode::SamplerFailed,
                        &detail,
                        None,
                    )
                    .await;
                return Err(Error::new(format!("background sampler failure: {detail}")));
            }
            message = control.receive() => message?,
        };
        match message {
            ControlBody::RegisterProcesses {
                processes,
                evidence_root,
            } => {
                control.mark_failure_stage(RoleErrorStage::Prepare);
                {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    state.register(processes, evidence_root)?;
                    state.poll_lifecycle()?;
                }
                control.send(ControlBody::ProcessesRegistered).await?;
            }
            ControlBody::Inventory => {
                control.mark_failure_stage(RoleErrorStage::Prepare);
                let inventories = {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    state.poll_lifecycle()?;
                    state.inventories()?
                };
                control
                    .send(ControlBody::InventoryObserved { inventories })
                    .await?;
            }
            ControlBody::MaterializationInventory => {
                control.mark_failure_stage(RoleErrorStage::Materialize);
                let checkpoint = {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    state.materialization_checkpoint()?
                };
                control
                    .send(ControlBody::MaterializationInventoryObserved { checkpoint })
                    .await?;
            }
            ControlBody::ObserveInventoryStability {
                expected_inventory_signature_sha256,
                expected_tid_signature_sha256,
                duration_ns,
            } => {
                control.mark_failure_stage(RoleErrorStage::Materialize);
                let observation = observe_inventory_stability(
                    &state,
                    &expected_inventory_signature_sha256,
                    &expected_tid_signature_sha256,
                    duration_ns,
                )
                .await?;
                control
                    .send(ControlBody::InventoryStabilityObserved { observation })
                    .await?;
            }
            ControlBody::WaitWebsocketRetirement {
                gateway_pre_auth_tids,
                keepalive_ns,
                stability_ns,
                cap_ns,
            } => {
                control.mark_failure_stage(RoleErrorStage::Materialize);
                let (elapsed_ns, inventories) = wait_websocket_retirement(
                    &state,
                    &gateway_pre_auth_tids,
                    keepalive_ns,
                    stability_ns,
                    cap_ns,
                )
                .await?;
                control
                    .send(ControlBody::WebsocketRetired {
                        elapsed_ns,
                        inventories,
                    })
                    .await?;
            }
            ControlBody::Freeze => {
                control.mark_failure_stage(RoleErrorStage::Prepare);
                let freeze = {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    match state.freeze() {
                        Ok(report) => match state.persist("sampler-freeze.bin", &report) {
                            Ok(()) => Ok(report),
                            Err(error) => Err(("sampler-freeze-persist", error)),
                        },
                        Err(error) => Err(("sampler-freeze-state", error)),
                    }
                };
                let mut report = match freeze {
                    Ok(report) => report,
                    Err((safe_detail, error)) => {
                        let _ = control
                            .send_terminal_error(
                                RoleErrorClass::Command,
                                RoleErrorStage::Prepare,
                                RoleErrorCode::SamplerFailed,
                                safe_detail,
                                None,
                            )
                            .await;
                        return Err(error);
                    }
                };
                compact_control_report(&mut report);
                control.send(ControlBody::Frozen { report }).await?;
            }
            ControlBody::Release => {
                control.mark_failure_stage(RoleErrorStage::Measure);
                let monotonic_ns = {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    state.release_gateway()?
                };
                control.send(ControlBody::Released { monotonic_ns }).await?;
            }
            ControlBody::FinalSample => {
                control.mark_failure_stage(RoleErrorStage::Drain);
                let mut report = {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    state.poll_lifecycle()?;
                    let report = state.report()?;
                    state.persist("sampler-final.bin", &report)?;
                    report
                };
                compact_control_report(&mut report);
                control.send(ControlBody::Sampled { report }).await?;
            }
            ControlBody::Stop => {
                control.mark_failure_stage(RoleErrorStage::Exit);
                poller.abort();
                {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    state.ensure_poll_clean()?;
                    if state.gateway_stopped {
                        state.release_gateway()?;
                    }
                }
                control
                    .send(ControlBody::Stopped {
                        role: Role::Sampler,
                    })
                    .await?;
                return Ok(());
            }
            other => {
                return Err(Error::new(format!(
                    "sampler received unexpected control message: {other:?}"
                ))
                .with_role_diagnostic(control.failure_stage(), RoleErrorCode::ControlProtocol))
            }
        }
    }
}

impl SamplerState {
    fn register(
        &mut self,
        mut processes: Vec<ObservedProcess>,
        evidence_root: Option<String>,
    ) -> Result<()> {
        if !self.processes.is_empty() || processes.is_empty() {
            return Err(Error::new(
                "sampler process registration is duplicate or empty",
            ));
        }
        processes.sort_by_key(|process| (process.role, process.identity.pid));
        let orchestrator = processes
            .iter()
            .find(|process| process.role == Role::Orchestrator)
            .ok_or_else(|| Error::new("sampler registration lacks orchestrator"))?
            .identity
            .clone();
        if processes
            .iter()
            .filter(|process| process.role == Role::Gateway)
            .count()
            > 1
        {
            return Err(Error::new("more than one gateway registered"));
        }
        let mut executable_hashes: BTreeMap<PathBuf, String> = BTreeMap::new();
        for process in &processes {
            validate_identity(&process.identity)?;
            if process.role != Role::Orchestrator && process.identity.parent_pid != orchestrator.pid
            {
                return Err(Error::new(format!(
                    "{} PID {} is not an orchestrator descendant",
                    process.role.label(),
                    process.identity.pid
                )));
            }
            if process.broad_cpus.is_empty() {
                return Err(Error::new("registered process has empty broad affinity"));
            }
            let executable = fs::read_link(format!("/proc/{}/exe", process.identity.pid))?;
            let actual_hash = if let Some(hash) = executable_hashes.get(&executable) {
                hash.clone()
            } else {
                let hash = sha256_hex(&fs::read(&executable)?);
                executable_hashes.insert(executable, hash.clone());
                hash
            };
            if actual_hash != process.executable_sha256 {
                return Err(Error::new(format!(
                    "{} executable hash mismatch",
                    process.role.label()
                )));
            }
        }
        self.processes = processes;
        self.evidence_root = match evidence_root {
            Some(path) => {
                let root = fs::canonicalize(path)?;
                let repository = fs::canonicalize(std::env::current_dir()?)?;
                if !root.starts_with(&repository) || !root.is_dir() {
                    return Err(Error::new(
                        "sampler evidence root escaped the repository or is not a directory",
                    ));
                }
                Some(root)
            }
            None => None,
        };
        self.pressure_start = Some(pressure_totals()?);
        self.swap_start = Some(swap_counters()?);
        self.major_faults_start = Some(self.major_faults_total()?);
        let tctl = tctl_millidegrees()?;
        self.tctl_start = Some(tctl);
        self.tctl_max = Some(tctl);
        let now = clock_ns(ClockKind::Monotonic)?;
        self.last_poll_ns = Some(now);
        self.lifecycle_poll_max_ns = 0;
        self.sample_environment(now)?;
        Ok(())
    }

    fn ensure_poll_clean(&self) -> Result<()> {
        if let Some(error) = &self.poll_error {
            Err(Error::new(format!(
                "background sampler failure was retained: {error}"
            )))
        } else {
            Ok(())
        }
    }

    fn materialization_checkpoint(&mut self) -> Result<InventoryCheckpoint> {
        if self.frozen {
            return Err(Error::new(
                "materialization inventory requested after authoritative freeze",
            ));
        }
        self.poll_lifecycle()?;
        crate::materialization::checkpoint(
            clock_ns(ClockKind::Monotonic)?,
            self.lifecycle_events,
            self.inventories()?,
        )
    }

    fn poll_tick(&mut self) -> Result<()> {
        self.ensure_poll_clean()?;
        let now = clock_ns(ClockKind::Monotonic)?;
        if let Some(previous) = self.last_poll_ns {
            let spacing = now
                .checked_sub(previous)
                .ok_or_else(|| Error::new("lifecycle poll clock moved backwards"))?;
            self.lifecycle_poll_max_ns = self.lifecycle_poll_max_ns.max(spacing);
        }
        self.last_poll_ns = Some(now);
        self.poll_lifecycle()?;
        self.sample_realtime()?;
        if self
            .last_environment_ns
            .is_none_or(|previous| now.saturating_sub(previous) >= 250_000_000)
        {
            self.sample_environment(now)?;
        }
        if !self.processes.is_empty()
            && self
                .last_boundary_ns
                .is_none_or(|previous| now.saturating_sub(previous) >= 100_000_000)
        {
            if self.boundaries.len() >= 4_000 {
                return Err(Error::new(
                    "100ms sampler boundary count exceeds fixed arm capacity",
                ));
            }
            let boundary = self.boundary_snapshot()?;
            self.last_boundary_ns = Some(boundary.monotonic_ns);
            self.boundaries.push(boundary);
        }
        Ok(())
    }

    fn sample_environment(&mut self, now: u64) -> Result<()> {
        let tctl = tctl_millidegrees()?;
        self.tctl_max = Some(self.tctl_max.unwrap_or(tctl).max(tctl));
        let frequencies = scaling_cur_frequencies_khz(GATEWAY_CPUS)?;
        self.frequency_samples.extend(frequencies.into_values());
        if self.frequency_samples.len() > 16 * 400 {
            return Err(Error::new(
                "frequency sample count exceeds fixed arm capacity",
            ));
        }
        self.last_environment_ns = Some(now);
        Ok(())
    }

    fn sample_realtime(&mut self) -> Result<()> {
        let sample = realtime_triplet()?;
        if let Some(previous) = &self.last_realtime {
            if realtime_discontinuous(previous, &sample)? {
                self.realtime_discontinuities = self
                    .realtime_discontinuities
                    .checked_add(1)
                    .ok_or_else(|| Error::new("REALTIME discontinuity count overflow"))?;
            }
        }
        self.realtime_samples = self
            .realtime_samples
            .checked_add(1)
            .ok_or_else(|| Error::new("REALTIME continuity sample count overflow"))?;
        if self.realtime_triplets.len() >= 20_000 {
            return Err(Error::new(
                "REALTIME continuity sample count exceeds fixed arm capacity",
            ));
        }
        self.realtime_triplets.push(sample.clone());
        self.last_realtime = Some(sample);
        Ok(())
    }

    fn major_faults_total(&self) -> Result<u64> {
        self.processes.iter().try_fold(0_u64, |total, process| {
            let stat = validate_identity(&process.identity)?;
            total
                .checked_add(stat.major_faults)
                .ok_or_else(|| Error::new("major-fault counter overflow"))
        })
    }

    fn persist(&self, name: &str, report: &SamplerReport) -> Result<()> {
        let Some(root) = &self.evidence_root else {
            return Ok(());
        };
        if !matches!(name, "sampler-freeze.bin" | "sampler-final.bin") {
            return Err(Error::new("unknown persistent sampler member"));
        }
        let mut threads = self.threads.values().cloned().collect::<Vec<_>>();
        threads.sort_by_key(|thread| {
            (
                thread.role,
                thread.identity.pid,
                thread.identity.tid,
                thread.identity.start_time_ticks,
            )
        });
        let evidence = SamplerPersistentEvidence {
            schema: "amg-http2-perf/sampler-persistent/v1".to_owned(),
            report: report.clone(),
            boundaries: self.boundaries.clone(),
            threads,
            lifecycle_poll_max_ns: report.lifecycle_poll_max_ns,
            realtime_triplets: self.realtime_triplets.clone(),
        };
        let bytes = crate::json::canonical_bytes(&evidence)?;
        crate::json::write_new_bytes(&root.join(name), &bytes)
    }

    fn poll_lifecycle(&mut self) -> Result<()> {
        if self.processes.is_empty() {
            return Ok(());
        }
        let mut observed = BTreeSet::new();
        let processes = self.processes.clone();
        for process in &processes {
            if let Err(error) = validate_identity(&process.identity) {
                if self.frozen {
                    self.note_post_freeze(format!(
                        "{} process identity unreadable after freeze: {error}",
                        process.role.label()
                    ));
                }
                continue;
            }
            let tids = match task_ids(process.identity.pid) {
                Ok(value) => value,
                Err(error) => {
                    if self.frozen {
                        self.note_post_freeze(format!(
                            "{} task inventory unreadable after freeze: {error}",
                            process.role.label()
                        ));
                    }
                    continue;
                }
            };
            for tid in tids {
                let key = (process.identity.pid, tid);
                observed.insert(key);
                let stat = match read_proc_stat(process.identity.pid, Some(tid)) {
                    Ok(value) => value,
                    Err(error) => {
                        if self.frozen {
                            self.note_post_freeze(format!("frozen TID {tid} unreadable: {error}"));
                        }
                        continue;
                    }
                };
                let ticks = stat
                    .user_ticks
                    .checked_add(stat.system_ticks)
                    .ok_or_else(|| Error::new("TID CPU tick overflow during lifecycle poll"))?;
                if let Some(thread) = self.threads.get_mut(&key) {
                    let mut post_freeze_issues = Vec::new();
                    let mut migration_observed = false;
                    let start_time_changed =
                        thread.identity.start_time_ticks != stat.start_time_ticks;
                    thread.alive = true;
                    thread.last_seen_ns = self.last_poll_ns.unwrap_or_default();
                    if start_time_changed {
                        post_freeze_issues.push(format!("TID {tid} start time changed"));
                    } else if self.frozen {
                        let status = read_proc_status(process.identity.pid, Some(tid))?;
                        let allowed = parse_cpu_list(&status.cpus_allowed_list)?;
                        if allowed != BTreeSet::from([thread.identity.assigned_cpu]) {
                            post_freeze_issues.push(format!(
                                "frozen TID {tid} affinity is no longer singleton-assigned"
                            ));
                        }
                        if runtime_migrated(
                            thread.identity.assigned_cpu,
                            stat.processor,
                            thread.last_ticks,
                            ticks,
                        ) {
                            migration_observed = true;
                            post_freeze_issues.push(format!(
                                "frozen TID {tid} accrued runtime on CPU {} instead of {}",
                                stat.processor, thread.identity.assigned_cpu
                            ));
                        }
                    }
                    thread.last_ticks = ticks;
                    thread.last_cpu = stat.processor;
                    if migration_observed {
                        self.migrations_after_freeze = self
                            .migrations_after_freeze
                            .checked_add(1)
                            .ok_or_else(|| Error::new("post-freeze migration count overflow"))?;
                    }
                    for issue in post_freeze_issues {
                        self.note_post_freeze(issue);
                    }
                } else {
                    if self.frozen {
                        self.note_post_freeze(format!("new TID {tid} after freeze"));
                    }
                    let ordinal = self
                        .threads
                        .values()
                        .filter(|thread| thread.role == process.role && thread.alive)
                        .count();
                    let cpu = process.broad_cpus[ordinal % process.broad_cpus.len()];
                    set_affinity(tid, &[cpu])?;
                    self.threads.insert(
                        key,
                        TrackedThread {
                            identity: ThreadIdentity {
                                pid: process.identity.pid,
                                tid,
                                start_time_ticks: stat.start_time_ticks,
                                comm: stat.comm,
                                assigned_cpu: cpu,
                            },
                            role: process.role,
                            alive: true,
                            last_ticks: ticks,
                            last_cpu: stat.processor,
                            first_seen_ns: self.last_poll_ns.unwrap_or_default(),
                            last_seen_ns: self.last_poll_ns.unwrap_or_default(),
                            provisional_pin_ns: self.last_poll_ns.unwrap_or_default(),
                        },
                    );
                    self.lifecycle_events = self
                        .lifecycle_events
                        .checked_add(1)
                        .ok_or_else(|| Error::new("thread lifecycle event count overflow"))?;
                    if self.frozen {
                        self.births_after_freeze = self
                            .births_after_freeze
                            .checked_add(1)
                            .ok_or_else(|| Error::new("post-freeze birth count overflow"))?;
                    } else {
                        self.births_before_freeze = self
                            .births_before_freeze
                            .checked_add(1)
                            .ok_or_else(|| Error::new("pre-freeze birth count overflow"))?;
                    }
                }
            }
        }
        let keys: Vec<_> = self.threads.keys().copied().collect();
        for key in keys {
            if !observed.contains(&key) && self.threads.get(&key).is_some_and(|thread| thread.alive)
            {
                if self.frozen && self.frozen_keys.contains(&key) {
                    self.note_post_freeze(format!("frozen TID {} disappeared", key.1));
                }
                if let Some(thread) = self.threads.get_mut(&key) {
                    thread.alive = false;
                    thread.last_seen_ns = self.last_poll_ns.unwrap_or(thread.last_seen_ns);
                }
                self.lifecycle_events = self
                    .lifecycle_events
                    .checked_add(1)
                    .ok_or_else(|| Error::new("thread lifecycle event count overflow"))?;
                if self.frozen {
                    self.deaths_after_freeze = self
                        .deaths_after_freeze
                        .checked_add(1)
                        .ok_or_else(|| Error::new("post-freeze death count overflow"))?;
                } else {
                    self.deaths_before_freeze = self
                        .deaths_before_freeze
                        .checked_add(1)
                        .ok_or_else(|| Error::new("pre-freeze death count overflow"))?;
                }
            }
        }
        Ok(())
    }

    fn note_post_freeze(&mut self, message: String) {
        if self.post_freeze_change.is_none() {
            self.post_freeze_change = Some(message);
        }
    }

    fn final_map(&mut self) -> Result<()> {
        self.poll_lifecycle()?;
        for process in &self.processes {
            let mut keys: Vec<_> = self
                .threads
                .iter()
                .filter(|(_, thread)| thread.alive && thread.identity.pid == process.identity.pid)
                .map(|(key, _)| *key)
                .collect();
            keys.sort_by(|left, right| {
                let left_thread = &self.threads[left];
                let right_thread = &self.threads[right];
                left_thread
                    .identity
                    .comm
                    .as_bytes()
                    .cmp(right_thread.identity.comm.as_bytes())
                    .then(
                        left_thread
                            .identity
                            .start_time_ticks
                            .cmp(&right_thread.identity.start_time_ticks),
                    )
                    .then(left.1.cmp(&right.1))
            });
            for (ordinal, key) in keys.into_iter().enumerate() {
                let cpu = process.broad_cpus[ordinal % process.broad_cpus.len()];
                set_affinity(key.1, &[cpu])?;
                self.threads
                    .get_mut(&key)
                    .ok_or_else(|| Error::new("thread vanished from final map"))?
                    .identity
                    .assigned_cpu = cpu;
                let stat = read_proc_stat(key.0, Some(key.1))?;
                if let Some(thread) = self.threads.get_mut(&key) {
                    thread.last_ticks = stat
                        .user_ticks
                        .checked_add(stat.system_ticks)
                        .ok_or_else(|| Error::new("TID tick overflow at final map"))?;
                    thread.last_cpu = stat.processor;
                }
            }
        }
        Ok(())
    }

    fn freeze(&mut self) -> Result<SamplerReport> {
        if self.frozen {
            return Err(Error::new("sampler freeze invoked twice"));
        }
        self.poll_tick()?;
        self.frozen_lifecycle_poll_max_ns = Some(self.lifecycle_poll_max_ns);
        if let Some(gateway) = self.gateway_identity() {
            let gateway = gateway.clone();
            validated_signal(&gateway, libc::SIGSTOP)?;
            self.gateway_stopped = true;
        }
        let dynamic_end = self.boundary_snapshot()?;
        self.last_boundary_ns = Some(dynamic_end.monotonic_ns);
        self.boundaries.push(dynamic_end);
        self.final_map()?;
        self.frozen_keys = self
            .threads
            .iter()
            .filter(|(_, thread)| thread.alive)
            .map(|(key, _)| *key)
            .collect();
        let boundary = self.boundary_snapshot()?;
        self.last_boundary_ns = Some(boundary.monotonic_ns);
        self.boundaries.push(boundary.clone());
        self.freeze_boundary = Some(boundary);
        self.frozen = true;
        self.report()
    }

    fn release_gateway(&mut self) -> Result<u64> {
        if !self.frozen {
            return Err(Error::new("sampler release invoked before freeze"));
        }
        let timestamp = clock_ns(ClockKind::Monotonic)?;
        if self.gateway_stopped {
            let gateway = self
                .gateway_identity()
                .ok_or_else(|| Error::new("stopped gateway identity disappeared"))?
                .clone();
            validated_signal(&gateway, libc::SIGCONT)?;
            self.gateway_stopped = false;
        } else if self.gateway_identity().is_some() {
            return Err(Error::new("gateway is not stopped at release"));
        }
        Ok(timestamp)
    }

    fn gateway_identity(&self) -> Option<&ProcessIdentity> {
        self.processes
            .iter()
            .find(|process| process.role == Role::Gateway)
            .map(|process| &process.identity)
    }

    fn inventories(&self) -> Result<Vec<ThreadInventory>> {
        let mut output = Vec::new();
        for process in &self.processes {
            let mut threads: Vec<_> = self
                .threads
                .values()
                .filter(|thread| thread.alive && thread.identity.pid == process.identity.pid)
                .map(|thread| thread.identity.clone())
                .collect();
            threads.sort_by(|left, right| {
                left.comm
                    .as_bytes()
                    .cmp(right.comm.as_bytes())
                    .then(left.start_time_ticks.cmp(&right.start_time_ticks))
                    .then(left.tid.cmp(&right.tid))
            });
            let mut hasher = Sha256::new();
            hasher.update(process.role.label().as_bytes());
            hasher.update(process.executable_sha256.as_bytes());
            for (ordinal, thread) in threads.iter().enumerate() {
                hasher.update(thread.comm.as_bytes());
                hasher.update((ordinal as u64).to_be_bytes());
                hasher.update(thread.assigned_cpu.to_be_bytes());
            }
            output.push(ThreadInventory {
                role: process.role,
                executable_sha256: process.executable_sha256.clone(),
                threads,
                semantic_signature_sha256: format!("{:x}", hasher.finalize()),
            });
        }
        output.sort_by_key(|inventory| inventory.role);
        Ok(output)
    }

    fn resources(&self) -> Result<Vec<ResourcePoint>> {
        let mut resources = Vec::new();
        for process in &self.processes {
            let stat = validate_identity(&process.identity)?;
            let status = read_proc_status(process.identity.pid, None)?;
            resources.push(ResourcePoint {
                role: process.role,
                pid: process.identity.pid,
                start_time_ticks: process.identity.start_time_ticks,
                user_ticks: stat.user_ticks,
                system_ticks: stat.system_ticks,
                major_faults: stat.major_faults,
                vm_hwm_kib: status.vm_hwm_kib,
                vm_rss_kib: status.vm_rss_kib,
            });
        }
        resources.sort_by_key(|resource| resource.role);
        Ok(resources)
    }

    fn boundary_snapshot(&self) -> Result<BoundarySnapshot> {
        self.ensure_poll_clean()?;
        let process_before = self.read_process_ticks()?;
        let tid_before = self.read_live_tid_ticks()?;
        let cpus = read_per_cpu_ticks()?;
        let tid_after = self.read_live_tid_ticks()?;
        let process_after = self.read_process_ticks()?;
        if tid_before.keys().collect::<Vec<_>>() != tid_after.keys().collect::<Vec<_>>() {
            return Err(Error::new(
                "TID inventory changed inside bracketed boundary snapshot",
            ));
        }
        Ok(BoundarySnapshot {
            monotonic_ns: clock_ns(ClockKind::Monotonic)?,
            boottime_ns: clock_ns(ClockKind::Boottime)?,
            tid_before,
            cpus,
            tid_after,
            process_before,
            process_after,
            tid_cpu: self
                .threads
                .iter()
                .filter(|(_, thread)| thread.alive)
                .map(|(key, thread)| (*key, thread.identity.assigned_cpu))
                .collect(),
            process_resources: self
                .resources()?
                .into_iter()
                .map(|resource| (resource.role, resource))
                .collect(),
        })
    }

    fn read_process_ticks(&self) -> Result<BTreeMap<Role, u64>> {
        let mut values = BTreeMap::new();
        for process in &self.processes {
            let stat = validate_identity(&process.identity)?;
            let ticks = stat
                .user_ticks
                .checked_add(stat.system_ticks)
                .ok_or_else(|| Error::new("process CPU tick overflow"))?;
            if values.insert(process.role, ticks).is_some() {
                // Orchestrator and sampler intentionally share a role CPU set,
                // but remain distinct process roles in the control schema.
                return Err(Error::new("duplicate sampled process role"));
            }
        }
        Ok(values)
    }

    fn read_live_tid_ticks(&self) -> Result<BTreeMap<(u32, u32), u64>> {
        let mut values = BTreeMap::new();
        for (key, thread) in &self.threads {
            if !thread.alive {
                continue;
            }
            let stat = read_proc_stat(key.0, Some(key.1))?;
            if stat.start_time_ticks != thread.identity.start_time_ticks {
                return Err(Error::new("TID start time changed at boundary"));
            }
            values.insert(
                *key,
                stat.user_ticks
                    .checked_add(stat.system_ticks)
                    .ok_or_else(|| Error::new("TID CPU tick overflow"))?,
            );
        }
        Ok(values)
    }

    fn report(&mut self) -> Result<SamplerReport> {
        self.ensure_poll_clean()?;
        let current = self.boundary_snapshot()?;
        if self
            .boundaries
            .last()
            .is_none_or(|previous| previous.monotonic_ns != current.monotonic_ns)
        {
            self.boundaries.push(current.clone());
            self.last_boundary_ns = Some(current.monotonic_ns);
        }
        let attribution = match &self.freeze_boundary {
            Some(start) => compute_attribution(start, &current, &self.threads)?,
            None => Vec::new(),
        };
        let residuals = match &self.freeze_boundary {
            Some(start) => compute_runtime_residuals(start, &current, &self.threads, true)?,
            None => Vec::new(),
        };
        let (dynamic_attribution, dynamic_residuals) = compute_dynamic_evidence(
            &self.boundaries,
            self.freeze_boundary.as_ref(),
            &self.threads,
        )?;
        let bracket_attribution = compute_bracket_attribution(
            &self.boundaries,
            self.freeze_boundary.as_ref(),
            &self.threads,
        )?;
        let mut noise_scopes = evaluate_noise_scopes(&attribution, true, "frozen", "whole")?;
        for bucket in one_second_buckets(&bracket_attribution)? {
            noise_scopes.extend(evaluate_noise_scopes(
                &bucket,
                false,
                "frozen",
                "one-second",
            )?);
        }
        let dynamic_whole = aggregate_attribution(&dynamic_attribution)?;
        if !dynamic_whole.is_empty() {
            noise_scopes.extend(evaluate_noise_scopes(
                &dynamic_whole,
                true,
                "dynamic",
                "whole",
            )?);
        }
        for bucket in one_second_buckets(&dynamic_attribution)? {
            noise_scopes.extend(evaluate_noise_scopes(
                &bucket,
                false,
                "dynamic",
                "one-second",
            )?);
        }
        let pressure = pressure_totals()?;
        let (swap_in, swap_out) = swap_counters()?;
        let pressure_start = self
            .pressure_start
            .as_ref()
            .ok_or_else(|| Error::new("sampler pressure baseline missing"))?;
        let swap_start = self
            .swap_start
            .ok_or_else(|| Error::new("sampler swap baseline missing"))?;
        let major_faults = self.major_faults_total()?;
        let major_faults_start = self
            .major_faults_start
            .ok_or_else(|| Error::new("sampler major-fault baseline missing"))?;
        let mut frequency_samples = self.frequency_samples.clone();
        frequency_samples.sort_unstable();
        let median_frequency_khz = frequency_samples
            .get(frequency_samples.len().saturating_sub(1) / 2)
            .copied();
        let bracket_samples_100ms = self
            .boundaries
            .windows(2)
            .filter(|pair| {
                self.freeze_boundary
                    .as_ref()
                    .is_some_and(|freeze| pair[0].monotonic_ns >= freeze.monotonic_ns)
            })
            .count() as u64;
        let boundary_interval_max_ns = self
            .boundaries
            .windows(2)
            .map(|pair| pair[1].monotonic_ns.saturating_sub(pair[0].monotonic_ns))
            .max()
            .unwrap_or(0);
        let steal_ticks_delta =
            self.boundaries
                .first()
                .ok_or_else(|| Error::new("sampler has no initial CPU boundary"))?
                .cpus
                .iter()
                .try_fold(0_u64, |total, (cpu, before)| {
                    let after = current.cpus.get(cpu).ok_or_else(|| {
                        Error::new("sampled CPU disappeared before final boundary")
                    })?;
                    total
                        .checked_add(
                            after
                                .steal
                                .checked_sub(before.steal)
                                .ok_or_else(|| Error::new("sampled steal counter decreased"))?,
                        )
                        .ok_or_else(|| Error::new("sampled steal delta overflow"))
                })?;
        Ok(SamplerReport {
            monotonic_ns: current.monotonic_ns,
            boottime_ns: current.boottime_ns,
            frozen: self.frozen,
            inventories: self.inventories()?,
            resources: self.resources()?,
            attribution,
            bracket_attribution,
            dynamic_attribution,
            bracket_samples_100ms,
            boundary_interval_max_ns,
            residuals,
            dynamic_residuals,
            noise_scopes,
            lifecycle_events: self.lifecycle_events,
            births_before_freeze: self.births_before_freeze,
            deaths_before_freeze: self.deaths_before_freeze,
            births_after_freeze: self.births_after_freeze,
            deaths_after_freeze: self.deaths_after_freeze,
            migrations_after_freeze: self.migrations_after_freeze,
            lifecycle_poll_max_ns: self
                .frozen_lifecycle_poll_max_ns
                .unwrap_or(self.lifecycle_poll_max_ns),
            post_freeze_change: self.post_freeze_change.clone(),
            tctl_millidegrees: self.tctl_max,
            tctl_start_millidegrees: self.tctl_start,
            tctl_max_millidegrees: self.tctl_max,
            median_frequency_khz,
            major_faults_delta: major_faults
                .checked_sub(major_faults_start)
                .ok_or_else(|| Error::new("major-fault counter decreased"))?,
            swap_in: swap_in
                .checked_sub(swap_start.0)
                .ok_or_else(|| Error::new("swap-in counter decreased"))?,
            swap_out: swap_out
                .checked_sub(swap_start.1)
                .ok_or_else(|| Error::new("swap-out counter decreased"))?,
            cpu_psi_some_us: pressure
                .cpu_some_us
                .checked_sub(pressure_start.cpu_some_us)
                .ok_or_else(|| Error::new("CPU PSI counter decreased"))?,
            memory_psi_full_us: pressure
                .memory_full_us
                .checked_sub(pressure_start.memory_full_us)
                .ok_or_else(|| Error::new("memory PSI counter decreased"))?,
            io_psi_full_us: pressure
                .io_full_us
                .checked_sub(pressure_start.io_full_us)
                .ok_or_else(|| Error::new("I/O PSI counter decreased"))?,
            realtime_samples: self.realtime_samples,
            realtime_discontinuities: self.realtime_discontinuities,
            realtime_comparable: self.realtime_samples > 0 && self.realtime_discontinuities == 0,
            steal_ticks_delta,
        })
    }
}

async fn wait_websocket_retirement(
    state: &Arc<Mutex<SamplerState>>,
    expected: &[ThreadIdentity],
    keepalive_ns: u64,
    stability_ns: u64,
    cap_ns: u64,
) -> Result<(u64, Vec<ThreadInventory>)> {
    if keepalive_ns != 10_000_000_000 || stability_ns != 2_000_000_000 || cap_ns != 15_000_000_000 {
        return Err(Error::new("WebSocket retirement constants changed"));
    }
    let start = clock_ns(ClockKind::Monotonic)?;
    let eligible = start
        .checked_add(keepalive_ns)
        .ok_or_else(|| Error::new("retirement keepalive overflow"))?;
    let deadline = start
        .checked_add(cap_ns)
        .ok_or_else(|| Error::new("retirement cap overflow"))?;
    let expected_keys: BTreeSet<_> = expected
        .iter()
        .map(|thread| (thread.tid, thread.start_time_ticks))
        .collect();
    let mut stable_since = None;
    let mut direct_signature: Option<Vec<(Role, String)>> = None;
    loop {
        let now = clock_ns(ClockKind::Monotonic)?;
        if now > deadline {
            return Err(Error::new(
                "WebSocket worker retirement exceeded 15-second cap",
            ));
        }
        let (matches, inventories) = {
            let mut state = state
                .lock()
                .map_err(|_| Error::new("sampler state poisoned"))?;
            state.poll_lifecycle()?;
            let inventories = state.inventories()?;
            if expected_keys.is_empty() {
                let signature = inventories
                    .iter()
                    .map(|inventory| (inventory.role, inventory.semantic_signature_sha256.clone()))
                    .collect::<Vec<_>>();
                let unchanged = direct_signature
                    .as_ref()
                    .is_some_and(|previous| previous == &signature);
                direct_signature = Some(signature);
                (unchanged, inventories)
            } else {
                let gateway = inventories
                    .iter()
                    .find(|inventory| inventory.role == Role::Gateway)
                    .ok_or_else(|| Error::new("gateway inventory missing during retirement"))?;
                let actual: BTreeSet<_> = gateway
                    .threads
                    .iter()
                    .map(|thread| (thread.tid, thread.start_time_ticks))
                    .collect();
                (actual == expected_keys, inventories)
            }
        };
        if now >= eligible && matches {
            let since = stable_since.get_or_insert(now);
            if now.saturating_sub(*since) >= stability_ns {
                return Ok((now.saturating_sub(start), inventories));
            }
        } else {
            stable_since = None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn observe_inventory_stability(
    state: &Arc<Mutex<SamplerState>>,
    expected_inventory_signature_sha256: &str,
    expected_tid_signature_sha256: &str,
    duration_ns: u64,
) -> Result<InventoryStabilityObservation> {
    if duration_ns != crate::materialization::INVENTORY_STABILITY_NS {
        return Err(Error::new(
            "ordinary inventory stability duration differs from the sealed bound",
        ));
    }
    crate::schema::validate_non_placeholder_sha256(
        "expected inventory signature",
        expected_inventory_signature_sha256,
    )?;
    crate::schema::validate_non_placeholder_sha256(
        "expected TID signature",
        expected_tid_signature_sha256,
    )?;
    let start_ns = clock_ns(ClockKind::Monotonic)?;
    let deadline_ns = start_ns
        .checked_add(duration_ns)
        .ok_or_else(|| Error::new("inventory stability deadline overflow"))?;
    let initial = {
        let mut state = state
            .lock()
            .map_err(|_| Error::new("sampler state poisoned"))?;
        state.materialization_checkpoint()?
    };
    let mut polls = 1_u64;
    let mut stable = checkpoint_matches_expected(
        &initial,
        expected_inventory_signature_sha256,
        expected_tid_signature_sha256,
        initial.lifecycle_events,
    );
    loop {
        let now = clock_ns(ClockKind::Monotonic)?;
        if now >= deadline_ns {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        let checkpoint = {
            let mut state = state
                .lock()
                .map_err(|_| Error::new("sampler state poisoned"))?;
            state.materialization_checkpoint()?
        };
        polls = polls
            .checked_add(1)
            .ok_or_else(|| Error::new("inventory stability poll counter overflow"))?;
        stable &= checkpoint_matches_expected(
            &checkpoint,
            expected_inventory_signature_sha256,
            expected_tid_signature_sha256,
            initial.lifecycle_events,
        );
    }
    let final_checkpoint = {
        let mut state = state
            .lock()
            .map_err(|_| Error::new("sampler state poisoned"))?;
        state.materialization_checkpoint()?
    };
    polls = polls
        .checked_add(1)
        .ok_or_else(|| Error::new("inventory stability poll counter overflow"))?;
    stable &= checkpoint_matches_expected(
        &final_checkpoint,
        expected_inventory_signature_sha256,
        expected_tid_signature_sha256,
        initial.lifecycle_events,
    );
    let end_ns = clock_ns(ClockKind::Monotonic)?;
    let observation = InventoryStabilityObservation {
        start_ns,
        end_ns,
        requested_duration_ns: duration_ns,
        polls,
        stable,
        initial,
        final_checkpoint,
    };
    observation.validate()?;
    Ok(observation)
}

fn checkpoint_matches_expected(
    checkpoint: &InventoryCheckpoint,
    expected_inventory_signature_sha256: &str,
    expected_tid_signature_sha256: &str,
    expected_lifecycle_events: u64,
) -> bool {
    checkpoint.inventory_signature_sha256 == expected_inventory_signature_sha256
        && checkpoint.tid_signature_sha256 == expected_tid_signature_sha256
        && checkpoint.lifecycle_events == expected_lifecycle_events
}

fn compute_attribution(
    start: &BoundarySnapshot,
    end: &BoundarySnapshot,
    threads: &BTreeMap<(u32, u32), TrackedThread>,
) -> Result<Vec<CpuAttribution>> {
    let mut output = Vec::new();
    for (cpu, start_cpu) in &start.cpus {
        let Some(end_cpu) = end.cpus.get(cpu) else {
            return Err(Error::new("per-CPU row disappeared"));
        };
        let scheduled = end_cpu
            .scheduled()?
            .checked_sub(start_cpu.scheduled()?)
            .ok_or_else(|| Error::new("scheduled CPU ticks decreased"))?;
        let capacity = end_cpu
            .capacity()?
            .checked_sub(start_cpu.capacity()?)
            .ok_or_else(|| Error::new("CPU capacity ticks decreased"))?;
        let mut lower = 0_u64;
        let mut upper = 0_u64;
        for (key, thread) in threads {
            if !thread.alive
                || start.tid_cpu.get(key) != Some(cpu)
                || end.tid_cpu.get(key) != Some(cpu)
            {
                continue;
            }
            let start_minus = *start
                .tid_before
                .get(key)
                .ok_or_else(|| Error::new("frozen TID absent at start-minus"))?;
            let start_plus = *start
                .tid_after
                .get(key)
                .ok_or_else(|| Error::new("frozen TID absent at start-plus"))?;
            let end_minus = *end
                .tid_before
                .get(key)
                .ok_or_else(|| Error::new("frozen TID absent at end-minus"))?;
            let end_plus = *end
                .tid_after
                .get(key)
                .ok_or_else(|| Error::new("frozen TID absent at end-plus"))?;
            lower = lower.saturating_add(end_minus.saturating_sub(start_plus));
            upper = upper.saturating_add(end_plus.saturating_sub(start_minus));
        }
        let uncertainty = upper
            .checked_sub(lower)
            .ok_or_else(|| Error::new("attribution bounds inverted"))?;
        output.push(CpuAttribution {
            cpu: *cpu,
            start_ns: start.monotonic_ns,
            end_ns: end.monotonic_ns,
            capacity_ticks: capacity,
            scheduled_ticks: scheduled,
            role_runtime_lower_ticks: lower,
            role_runtime_upper_ticks: upper,
            attribution_uncertainty_ticks: uncertainty,
            external_upper_ticks: scheduled.saturating_sub(lower),
        });
    }
    Ok(output)
}

fn compute_runtime_residuals(
    start: &BoundarySnapshot,
    end: &BoundarySnapshot,
    threads: &BTreeMap<(u32, u32), TrackedThread>,
    frozen: bool,
) -> Result<Vec<RuntimeResidual>> {
    let mut output = Vec::new();
    let roles = start
        .process_before
        .keys()
        .chain(end.process_before.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    for role in roles {
        let process_start_minus = *start
            .process_before
            .get(&role)
            .ok_or_else(|| Error::new("process role absent at start-minus"))?;
        let process_start_plus = *start
            .process_after
            .get(&role)
            .ok_or_else(|| Error::new("process role absent at start-plus"))?;
        let process_end_minus = *end
            .process_before
            .get(&role)
            .ok_or_else(|| Error::new("process role absent at end-minus"))?;
        let process_end_plus = *end
            .process_after
            .get(&role)
            .ok_or_else(|| Error::new("process role absent at end-plus"))?;
        let process_lower = process_end_minus
            .checked_sub(process_start_plus)
            .ok_or_else(|| Error::new("process lower runtime counter decreased"))?;
        let process_upper = process_end_plus
            .checked_sub(process_start_minus)
            .ok_or_else(|| Error::new("process upper runtime counter decreased"))?;
        let mut tid_lower = 0_u64;
        let mut tid_upper = 0_u64;
        for (key, thread) in threads {
            if thread.role != role
                || (frozen && !thread.alive)
                || !start.tid_before.contains_key(key)
                || !start.tid_after.contains_key(key)
                || !end.tid_before.contains_key(key)
                || !end.tid_after.contains_key(key)
            {
                continue;
            }
            let start_minus = *start
                .tid_before
                .get(key)
                .ok_or_else(|| Error::new("role TID absent at residual start-minus"))?;
            let start_plus = *start
                .tid_after
                .get(key)
                .ok_or_else(|| Error::new("role TID absent at residual start-plus"))?;
            let end_minus = *end
                .tid_before
                .get(key)
                .ok_or_else(|| Error::new("role TID absent at residual end-minus"))?;
            let end_plus = *end
                .tid_after
                .get(key)
                .ok_or_else(|| Error::new("role TID absent at residual end-plus"))?;
            tid_lower = tid_lower
                .checked_add(end_minus.saturating_sub(start_plus))
                .ok_or_else(|| Error::new("role TID lower runtime overflow"))?;
            tid_upper = tid_upper
                .checked_add(end_plus.saturating_sub(start_minus))
                .ok_or_else(|| Error::new("role TID upper runtime overflow"))?;
        }
        if process_lower > process_upper || tid_lower > tid_upper {
            return Err(Error::new(
                "process or per-TID runtime interval is inverted",
            ));
        }
        let u_lower = if frozen {
            0
        } else {
            process_lower.saturating_sub(tid_upper)
        };
        let u_upper = if frozen {
            0
        } else {
            process_upper.saturating_sub(tid_lower)
        };
        if u_lower > u_upper {
            return Err(Error::new("dynamic u_role interval is inverted"));
        }
        let signed_lower = i128::from(process_lower) - i128::from(tid_upper);
        let signed_upper = i128::from(process_upper) - i128::from(tid_lower);
        output.push(RuntimeResidual {
            role,
            start_ns: start.monotonic_ns,
            end_ns: end.monotonic_ns,
            process_runtime_lower_ticks: process_lower,
            process_runtime_upper_ticks: process_upper,
            known_tid_runtime_lower_ticks: tid_lower,
            known_tid_runtime_upper_ticks: tid_upper,
            u_role_lower_ticks: u_lower,
            u_role_upper_ticks: u_upper,
            signed_residual_lower_ticks: i64::try_from(signed_lower)
                .map_err(|_| Error::new("signed residual lower exceeds i64"))?,
            signed_residual_upper_ticks: i64::try_from(signed_upper)
                .map_err(|_| Error::new("signed residual upper exceeds i64"))?,
        });
    }
    output.sort_by_key(|residual| residual.role);
    Ok(output)
}

fn compute_bracket_attribution(
    boundaries: &[BoundarySnapshot],
    freeze: Option<&BoundarySnapshot>,
    threads: &BTreeMap<(u32, u32), TrackedThread>,
) -> Result<Vec<CpuAttribution>> {
    let Some(freeze) = freeze else {
        return Ok(Vec::new());
    };
    let mut output = Vec::new();
    for pair in boundaries.windows(2) {
        if pair[0].monotonic_ns < freeze.monotonic_ns
            || pair[1].monotonic_ns <= pair[0].monotonic_ns
        {
            continue;
        }
        output.extend(compute_attribution(&pair[0], &pair[1], threads)?);
    }
    output.sort_by_key(|sample| (sample.start_ns, sample.cpu));
    Ok(output)
}

fn compute_dynamic_evidence(
    boundaries: &[BoundarySnapshot],
    freeze: Option<&BoundarySnapshot>,
    threads: &BTreeMap<(u32, u32), TrackedThread>,
) -> Result<(Vec<CpuAttribution>, Vec<RuntimeResidual>)> {
    let Some(freeze) = freeze else {
        return Ok((Vec::new(), Vec::new()));
    };
    let mut attribution = Vec::new();
    let mut residuals = Vec::new();
    for pair in boundaries.windows(2) {
        if pair[1].monotonic_ns > freeze.monotonic_ns
            || pair[1].monotonic_ns <= pair[0].monotonic_ns
        {
            continue;
        }
        let mut bracketed = threads.clone();
        for (key, thread) in &mut bracketed {
            thread.alive = pair[0].tid_before.contains_key(key)
                && pair[0].tid_after.contains_key(key)
                && pair[1].tid_before.contains_key(key)
                && pair[1].tid_after.contains_key(key)
                && pair[0].tid_cpu.get(key) == pair[1].tid_cpu.get(key);
        }
        attribution.extend(compute_attribution(&pair[0], &pair[1], &bracketed)?);
        residuals.extend(compute_runtime_residuals(
            &pair[0], &pair[1], &bracketed, false,
        )?);
    }
    attribution.sort_by_key(|sample| (sample.start_ns, sample.cpu));
    residuals.sort_by_key(|sample| (sample.start_ns, sample.role));
    Ok((attribution, residuals))
}

fn aggregate_attribution(samples: &[CpuAttribution]) -> Result<Vec<CpuAttribution>> {
    let mut by_cpu = BTreeMap::<u16, CpuAttribution>::new();
    for sample in samples {
        let entry = by_cpu.entry(sample.cpu).or_insert(CpuAttribution {
            cpu: sample.cpu,
            start_ns: sample.start_ns,
            end_ns: sample.end_ns,
            capacity_ticks: 0,
            scheduled_ticks: 0,
            role_runtime_lower_ticks: 0,
            role_runtime_upper_ticks: 0,
            attribution_uncertainty_ticks: 0,
            external_upper_ticks: 0,
        });
        entry.start_ns = entry.start_ns.min(sample.start_ns);
        entry.end_ns = entry.end_ns.max(sample.end_ns);
        entry.capacity_ticks = entry
            .capacity_ticks
            .checked_add(sample.capacity_ticks)
            .ok_or_else(|| Error::new("whole attribution capacity overflow"))?;
        entry.scheduled_ticks = entry
            .scheduled_ticks
            .checked_add(sample.scheduled_ticks)
            .ok_or_else(|| Error::new("whole attribution scheduled overflow"))?;
        entry.role_runtime_lower_ticks = entry
            .role_runtime_lower_ticks
            .checked_add(sample.role_runtime_lower_ticks)
            .ok_or_else(|| Error::new("whole attribution lower runtime overflow"))?;
        entry.role_runtime_upper_ticks = entry
            .role_runtime_upper_ticks
            .checked_add(sample.role_runtime_upper_ticks)
            .ok_or_else(|| Error::new("whole attribution upper runtime overflow"))?;
        entry.attribution_uncertainty_ticks = entry
            .attribution_uncertainty_ticks
            .checked_add(sample.attribution_uncertainty_ticks)
            .ok_or_else(|| Error::new("whole attribution uncertainty overflow"))?;
        entry.external_upper_ticks = entry
            .external_upper_ticks
            .checked_add(sample.external_upper_ticks)
            .ok_or_else(|| Error::new("whole attribution external-time overflow"))?;
    }
    Ok(by_cpu.into_values().collect())
}

fn one_second_buckets(samples: &[CpuAttribution]) -> Result<Vec<Vec<CpuAttribution>>> {
    let mut intervals = BTreeMap::<(u64, u64), Vec<&CpuAttribution>>::new();
    for sample in samples {
        intervals
            .entry((sample.start_ns, sample.end_ns))
            .or_default()
            .push(sample);
    }
    let intervals = intervals.into_values().collect::<Vec<_>>();
    let mut ranges = Vec::<(usize, usize)>::new();
    let mut start = 0_usize;
    while start < intervals.len() {
        let first_ns = intervals[start]
            .first()
            .ok_or_else(|| Error::new("empty 100ms attribution interval"))?
            .start_ns;
        let mut end = start;
        while end < intervals.len() {
            end += 1;
            let end_ns = intervals[end - 1]
                .first()
                .ok_or_else(|| Error::new("empty 100ms attribution interval"))?
                .end_ns;
            if end_ns.saturating_sub(first_ns) >= 1_000_000_000 {
                break;
            }
        }
        let elapsed = intervals[end - 1]
            .first()
            .ok_or_else(|| Error::new("empty 100ms attribution interval"))?
            .end_ns
            .saturating_sub(first_ns);
        if elapsed < 1_000_000_000 {
            if let Some(last) = ranges.last_mut() {
                last.1 = intervals.len();
            }
            break;
        }
        ranges.push((start, end));
        start = end;
    }
    let mut output = Vec::new();
    for (start, end) in ranges {
        let first_ns = intervals[start]
            .first()
            .ok_or_else(|| Error::new("empty 100ms attribution interval"))?
            .start_ns;
        let end_ns = intervals[end - 1]
            .first()
            .ok_or_else(|| Error::new("empty 100ms attribution interval"))?
            .end_ns;
        if end_ns.saturating_sub(first_ns) < 1_000_000_000 {
            return Err(Error::new(
                "tested resource-noise bucket is shorter than one second",
            ));
        }
        let mut by_cpu = BTreeMap::<u16, CpuAttribution>::new();
        for interval in &intervals[start..end] {
            for sample in interval {
                let entry = by_cpu.entry(sample.cpu).or_insert(CpuAttribution {
                    cpu: sample.cpu,
                    start_ns: first_ns,
                    end_ns,
                    capacity_ticks: 0,
                    scheduled_ticks: 0,
                    role_runtime_lower_ticks: 0,
                    role_runtime_upper_ticks: 0,
                    attribution_uncertainty_ticks: 0,
                    external_upper_ticks: 0,
                });
                entry.capacity_ticks = entry
                    .capacity_ticks
                    .checked_add(sample.capacity_ticks)
                    .ok_or_else(|| Error::new("bucket CPU capacity overflow"))?;
                entry.scheduled_ticks =
                    entry
                        .scheduled_ticks
                        .checked_add(sample.scheduled_ticks)
                        .ok_or_else(|| Error::new("bucket scheduled ticks overflow"))?;
                entry.role_runtime_lower_ticks = entry
                    .role_runtime_lower_ticks
                    .checked_add(sample.role_runtime_lower_ticks)
                    .ok_or_else(|| Error::new("bucket role lower ticks overflow"))?;
                entry.role_runtime_upper_ticks = entry
                    .role_runtime_upper_ticks
                    .checked_add(sample.role_runtime_upper_ticks)
                    .ok_or_else(|| Error::new("bucket role upper ticks overflow"))?;
                entry.attribution_uncertainty_ticks = entry
                    .attribution_uncertainty_ticks
                    .checked_add(sample.attribution_uncertainty_ticks)
                    .ok_or_else(|| Error::new("bucket attribution uncertainty overflow"))?;
                entry.external_upper_ticks = entry
                    .external_upper_ticks
                    .checked_add(sample.external_upper_ticks)
                    .ok_or_else(|| Error::new("bucket external ticks overflow"))?;
            }
        }
        output.push(by_cpu.into_values().collect());
    }
    Ok(output)
}

fn evaluate_noise_scopes(
    attribution: &[CpuAttribution],
    whole_interval: bool,
    attribution_phase: &str,
    interval_kind: &str,
) -> Result<Vec<NoiseScopeEvidence>> {
    if attribution.is_empty() {
        return Ok(Vec::new());
    }
    let start_ns = attribution
        .iter()
        .map(|sample| sample.start_ns)
        .min()
        .ok_or_else(|| Error::new("noise attribution start missing"))?;
    let end_ns = attribution
        .iter()
        .map(|sample| sample.end_ns)
        .max()
        .ok_or_else(|| Error::new("noise attribution end missing"))?;
    let by_cpu = attribution
        .iter()
        .map(|sample| (sample.cpu, sample))
        .collect::<BTreeMap<_, _>>();
    if by_cpu.len() != attribution.len() {
        return Err(Error::new("noise attribution contains duplicate CPU rows"));
    }
    let mut output = Vec::new();
    let mut add_scope =
        |scope: &str, role: &str, cpus: &[u16], limit_basis_points: u16| -> Result<()> {
            let mut capacity = 0_u64;
            let mut external = 0_u64;
            for cpu in cpus {
                let sample = by_cpu
                    .get(cpu)
                    .ok_or_else(|| Error::new(format!("noise scope lacks CPU {cpu}")))?;
                capacity = capacity
                    .checked_add(sample.capacity_ticks)
                    .ok_or_else(|| Error::new("noise scope capacity overflow"))?;
                external = external
                    .checked_add(sample.external_upper_ticks)
                    .ok_or_else(|| Error::new("noise scope external-time overflow"))?;
            }
            let accepted = capacity > 0
                && u128::from(external) * 10_000
                    <= u128::from(capacity) * u128::from(limit_basis_points);
            output.push(NoiseScopeEvidence {
                attribution_phase: attribution_phase.to_owned(),
                interval_kind: interval_kind.to_owned(),
                scope: scope.to_owned(),
                role: role.to_owned(),
                cpus: cpus.to_vec(),
                start_ns,
                end_ns,
                capacity_ticks: capacity,
                external_upper_ticks: external,
                limit_basis_points,
                accepted,
            });
            Ok(())
        };
    let logical_limit = if whole_interval { 100 } else { 200 };
    let pair_limit = if whole_interval { 50 } else { 100 };
    let role_limit = if whole_interval { 25 } else { 50 };
    for cpu in by_cpu.keys().copied() {
        add_scope("logical", cpu_role(cpu)?, &[cpu], logical_limit)?;
    }
    for first in 0_u16..16 {
        add_scope(
            "sibling-pair",
            cpu_role(first)?,
            &[first, first + 16],
            pair_limit,
        )?;
    }
    for (role, cpus) in [
        ("gateway", GATEWAY_CPUS),
        ("fixture", FIXTURE_CPUS),
        ("load", LOAD_CPUS),
        ("control", CONTROL_CPUS),
    ] {
        add_scope("role", role, cpus, role_limit)?;
    }
    Ok(output)
}

pub(crate) fn recompute_noise_scopes_from_raw(
    frozen_whole: &[crate::raw::CpuBucketEvidence],
    frozen_bracket: &[crate::raw::CpuBucketEvidence],
    dynamic: &[crate::raw::CpuBucketEvidence],
) -> Result<Vec<crate::raw::NoiseScopeDecisionEvidence>> {
    let convert = |values: &[crate::raw::CpuBucketEvidence]| {
        values
            .iter()
            .map(|value| CpuAttribution {
                cpu: value.cpu,
                start_ns: value.start_ns,
                end_ns: value.end_ns,
                capacity_ticks: value.capacity_ticks,
                scheduled_ticks: value.scheduled_ticks,
                role_runtime_lower_ticks: value.process_runtime_lower,
                role_runtime_upper_ticks: value.process_runtime_upper,
                attribution_uncertainty_ticks: value.attribution_uncertainty_ticks,
                external_upper_ticks: value.external_upper_ticks,
            })
            .collect::<Vec<_>>()
    };
    let frozen_whole = convert(frozen_whole);
    let frozen_bracket = convert(frozen_bracket);
    let dynamic = convert(dynamic);
    let mut scopes = evaluate_noise_scopes(&frozen_whole, true, "frozen", "whole")?;
    for bucket in one_second_buckets(&frozen_bracket)? {
        scopes.extend(evaluate_noise_scopes(
            &bucket,
            false,
            "frozen",
            "one-second",
        )?);
    }
    let dynamic_whole = aggregate_attribution(&dynamic)?;
    if !dynamic_whole.is_empty() {
        scopes.extend(evaluate_noise_scopes(
            &dynamic_whole,
            true,
            "dynamic",
            "whole",
        )?);
    }
    for bucket in one_second_buckets(&dynamic)? {
        scopes.extend(evaluate_noise_scopes(
            &bucket,
            false,
            "dynamic",
            "one-second",
        )?);
    }
    Ok(scopes
        .into_iter()
        .map(|scope| crate::raw::NoiseScopeDecisionEvidence {
            attribution_phase: scope.attribution_phase,
            interval_kind: scope.interval_kind,
            scope: scope.scope,
            role: scope.role,
            cpus: scope.cpus,
            start_ns: scope.start_ns,
            end_ns: scope.end_ns,
            capacity_ticks: scope.capacity_ticks,
            external_upper_ticks: scope.external_upper_ticks,
            limit_basis_points: scope.limit_basis_points,
            accepted: scope.accepted,
        })
        .collect())
}

fn cpu_role(cpu: u16) -> Result<&'static str> {
    if GATEWAY_CPUS.contains(&cpu) {
        Ok("gateway")
    } else if FIXTURE_CPUS.contains(&cpu) {
        Ok("fixture")
    } else if LOAD_CPUS.contains(&cpu) {
        Ok("load")
    } else if CONTROL_CPUS.contains(&cpu) {
        Ok("control")
    } else {
        Err(Error::new(format!(
            "CPU {cpu} is outside every sealed role set"
        )))
    }
}

fn realtime_discontinuous(previous: &RealtimeTriplet, current: &RealtimeTriplet) -> Result<bool> {
    let previous_boot = previous
        .boottime_before_ns
        .checked_add(previous.boottime_after_ns)
        .ok_or_else(|| Error::new("previous BOOTTIME midpoint overflow"))?
        / 2;
    let current_boot = current
        .boottime_before_ns
        .checked_add(current.boottime_after_ns)
        .ok_or_else(|| Error::new("current BOOTTIME midpoint overflow"))?
        / 2;
    let boot_delta = current_boot
        .checked_sub(previous_boot)
        .ok_or_else(|| Error::new("BOOTTIME continuity moved backwards"))?;
    let realtime_delta = current.realtime_ns.checked_sub(previous.realtime_ns);
    Ok(match realtime_delta {
        None => true,
        Some(delta) => delta.abs_diff(boot_delta) > 100_000_000,
    })
}

fn compact_control_report(report: &mut SamplerReport) {
    report.bracket_attribution.clear();
    report.dynamic_attribution.clear();
    report.dynamic_residuals.clear();
}

pub fn verify_persistent(path: &std::path::Path) -> Result<SamplerReport> {
    Ok(read_persistent(path)?.report)
}

pub(crate) fn read_persistent(path: &std::path::Path) -> Result<SamplerPersistentEvidence> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > crate::schema::TASK_CAP_BYTES {
        return Err(Error::new(
            "persistent sampler member type/length is invalid",
        ));
    }
    let bytes = fs::read(path)?;
    let evidence: SamplerPersistentEvidence = crate::json::require_canonical(&bytes)?;
    if evidence.schema != "amg-http2-perf/sampler-persistent/v1"
        || evidence.boundaries.is_empty()
        || evidence.threads.is_empty()
        || evidence.lifecycle_poll_max_ns != evidence.report.lifecycle_poll_max_ns
        || evidence
            .boundaries
            .windows(2)
            .any(|pair| pair[0].monotonic_ns > pair[1].monotonic_ns)
        || evidence.report.realtime_samples == 0
        || evidence.realtime_triplets.len() as u64 != evidence.report.realtime_samples
        || evidence.boundaries.iter().any(|boundary| {
            boundary.process_resources.len() != evidence.report.resources.len()
                || evidence
                    .report
                    .resources
                    .iter()
                    .any(|resource| !boundary.process_resources.contains_key(&resource.role))
        })
        || evidence.report.lifecycle_events
            != evidence
                .report
                .births_before_freeze
                .checked_add(evidence.report.deaths_before_freeze)
                .and_then(|value| value.checked_add(evidence.report.births_after_freeze))
                .and_then(|value| value.checked_add(evidence.report.deaths_after_freeze))
                .unwrap_or(u64::MAX)
        || evidence.threads.iter().any(|thread| {
            thread.provisional_pin_ns != thread.first_seen_ns
                || thread.provisional_pin_ns > thread.last_seen_ns
        })
    {
        return Err(Error::new("persistent sampler evidence is incomplete"));
    }
    Ok(evidence)
}

fn runtime_migrated(assigned_cpu: u16, observed_cpu: i32, before: u64, after: u64) -> bool {
    after > before && observed_cpu != i32::from(assigned_cpu)
}

#[allow(unsafe_code)]
fn validated_signal(identity: &ProcessIdentity, signal: i32) -> Result<()> {
    validate_identity(identity)?;
    let pid = i32::try_from(identity.pid).map_err(|_| Error::new("PID exceeds pid_t"))?;
    // SAFETY: identity was immediately revalidated and signals are sent only to
    // the registered descendant gateway.
    if unsafe { libc::kill(pid, signal) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticks(cpu: u16, scheduled: u64, idle: u64) -> CpuTicks {
        CpuTicks {
            cpu,
            user: scheduled,
            nice: 0,
            system: 0,
            idle,
            iowait: 0,
            irq: 0,
            softirq: 0,
            steal: 0,
        }
    }

    #[test]
    fn bracketed_attribution_uses_conservative_lower_bound() {
        let key = (10, 11);
        let start = BoundarySnapshot {
            monotonic_ns: 1,
            boottime_ns: 1,
            tid_before: BTreeMap::from([(key, 100)]),
            cpus: BTreeMap::from([(0, ticks(0, 1_000, 1_000))]),
            tid_after: BTreeMap::from([(key, 101)]),
            process_before: BTreeMap::from([(Role::Load, 100)]),
            process_after: BTreeMap::from([(Role::Load, 101)]),
            tid_cpu: BTreeMap::from([(key, 0)]),
            process_resources: BTreeMap::new(),
        };
        let end = BoundarySnapshot {
            monotonic_ns: 2,
            boottime_ns: 2,
            tid_before: BTreeMap::from([(key, 110)]),
            cpus: BTreeMap::from([(0, ticks(0, 1_020, 1_080))]),
            tid_after: BTreeMap::from([(key, 111)]),
            process_before: BTreeMap::from([(Role::Load, 110)]),
            process_after: BTreeMap::from([(Role::Load, 111)]),
            tid_cpu: BTreeMap::from([(key, 0)]),
            process_resources: BTreeMap::new(),
        };
        let threads = BTreeMap::from([(
            key,
            TrackedThread {
                identity: ThreadIdentity {
                    pid: 10,
                    tid: 11,
                    start_time_ticks: 9,
                    comm: "worker".to_owned(),
                    assigned_cpu: 0,
                },
                role: Role::Load,
                alive: true,
                last_ticks: 111,
                last_cpu: 0,
                first_seen_ns: 0,
                last_seen_ns: 2,
                provisional_pin_ns: 0,
            },
        )]);
        let result = compute_attribution(&start, &end, &threads).expect("attribution");
        assert_eq!(result[0].role_runtime_lower_ticks, 9);
        assert_eq!(result[0].role_runtime_upper_ticks, 11);
        assert_eq!(result[0].attribution_uncertainty_ticks, 2);
        assert_eq!(result[0].external_upper_ticks, 11);
    }

    #[test]
    fn persistent_boundary_encodes_tuple_tid_keys_as_sorted_records() {
        let key = (10, 11);
        let boundary = BoundarySnapshot {
            monotonic_ns: 1,
            boottime_ns: 2,
            tid_before: BTreeMap::from([(key, 3)]),
            cpus: BTreeMap::from([(0, ticks(0, 4, 5))]),
            tid_after: BTreeMap::from([(key, 6)]),
            process_before: BTreeMap::from([(Role::Load, 7)]),
            process_after: BTreeMap::from([(Role::Load, 8)]),
            tid_cpu: BTreeMap::from([(key, 9)]),
            process_resources: BTreeMap::new(),
        };
        let bytes = crate::json::canonical_bytes(&boundary).expect("serializable TID records");
        let text = std::str::from_utf8(&bytes).expect("canonical UTF-8");
        assert!(text.contains("\"tid_before\":[{\"pid\":10,\"ticks\":3,\"tid\":11}]"));
        assert!(text.contains("\"tid_cpu\":[{\"cpu\":9,\"pid\":10,\"tid\":11}]"));
        let parsed: BoundarySnapshot =
            crate::json::from_slice_strict(&bytes).expect("persistent boundary round trip");
        assert_eq!(parsed.tid_before, boundary.tid_before);
        assert_eq!(parsed.tid_after, boundary.tid_after);
        assert_eq!(parsed.tid_cpu, boundary.tid_cpu);
    }

    #[test]
    fn signature_excludes_ephemeral_tid_values() {
        let mut one = Sha256::new();
        one.update(b"worker");
        one.update(0_u64.to_be_bytes());
        one.update(11_u16.to_be_bytes());
        let mut two = Sha256::new();
        two.update(b"worker");
        two.update(0_u64.to_be_bytes());
        two.update(11_u16.to_be_bytes());
        assert_eq!(one.finalize(), two.finalize());
    }

    fn full_attribution(external_by_cpu: &BTreeMap<u16, u64>) -> Vec<CpuAttribution> {
        (0_u16..32)
            .map(|cpu| CpuAttribution {
                cpu,
                start_ns: 0,
                end_ns: 1_000_000_000,
                capacity_ticks: 10_000,
                scheduled_ticks: *external_by_cpu.get(&cpu).unwrap_or(&0),
                role_runtime_lower_ticks: 0,
                role_runtime_upper_ticks: 0,
                attribution_uncertainty_ticks: 0,
                external_upper_ticks: *external_by_cpu.get(&cpu).unwrap_or(&0),
            })
            .collect()
    }

    #[test]
    fn one_core_and_distributed_contamination_fail_logical_pair_and_role_scopes() {
        let one_core = full_attribution(&BTreeMap::from([(0, 10_000)]));
        let scopes = evaluate_noise_scopes(&one_core, false, "frozen", "one-second")
            .expect("one-core scopes");
        assert!(scopes
            .iter()
            .any(|scope| scope.scope == "logical" && scope.cpus == [0] && !scope.accepted));
        assert!(scopes.iter().any(|scope| {
            scope.scope == "sibling-pair" && scope.cpus == [0, 16] && !scope.accepted
        }));
        assert!(scopes
            .iter()
            .any(|scope| { scope.scope == "role" && scope.role == "gateway" && !scope.accepted }));

        let pair = full_attribution(&BTreeMap::from([(0, 150), (16, 150)]));
        let pair_scopes =
            evaluate_noise_scopes(&pair, false, "frozen", "one-second").expect("pair scopes");
        assert!(pair_scopes.iter().any(|scope| {
            scope.scope == "sibling-pair" && scope.cpus == [0, 16] && !scope.accepted
        }));

        let role = full_attribution(&GATEWAY_CPUS.iter().copied().map(|cpu| (cpu, 30)).collect());
        let role_scopes =
            evaluate_noise_scopes(&role, true, "frozen", "whole").expect("role scopes");
        assert!(role_scopes
            .iter()
            .any(|scope| { scope.scope == "role" && scope.role == "gateway" && !scope.accepted }));
    }

    #[test]
    fn transient_tid_is_retained_as_dynamic_u_role_and_runtime_migration_is_terminal() {
        let key = (10, 11);
        let start = BoundarySnapshot {
            monotonic_ns: 0,
            boottime_ns: 0,
            tid_before: BTreeMap::from([(key, 1)]),
            cpus: BTreeMap::from([(11, ticks(11, 100, 100))]),
            tid_after: BTreeMap::from([(key, 1)]),
            process_before: BTreeMap::from([(Role::Load, 1)]),
            process_after: BTreeMap::from([(Role::Load, 1)]),
            tid_cpu: BTreeMap::from([(key, 11)]),
            process_resources: BTreeMap::new(),
        };
        let end = BoundarySnapshot {
            monotonic_ns: 100_000_000,
            boottime_ns: 100_000_000,
            tid_before: BTreeMap::new(),
            cpus: BTreeMap::from([(11, ticks(11, 110, 190))]),
            tid_after: BTreeMap::new(),
            process_before: BTreeMap::from([(Role::Load, 11)]),
            process_after: BTreeMap::from([(Role::Load, 11)]),
            tid_cpu: BTreeMap::new(),
            process_resources: BTreeMap::new(),
        };
        let threads = BTreeMap::from([(
            key,
            TrackedThread {
                identity: ThreadIdentity {
                    pid: 10,
                    tid: 11,
                    start_time_ticks: 1,
                    comm: "transient".to_owned(),
                    assigned_cpu: 11,
                },
                role: Role::Load,
                alive: false,
                last_ticks: 1,
                last_cpu: 11,
                first_seen_ns: 0,
                last_seen_ns: 100_000_000,
                provisional_pin_ns: 0,
            },
        )]);
        let residual =
            compute_runtime_residuals(&start, &end, &threads, false).expect("dynamic residual");
        assert_eq!(residual[0].u_role_lower_ticks, 10);
        assert_eq!(residual[0].u_role_upper_ticks, 10);
        assert!(runtime_migrated(11, 12, 100, 101));
        assert!(!runtime_migrated(11, 12, 100, 100));
    }

    #[test]
    fn realtime_forward_backward_and_clean_progress_are_classified() {
        let previous = RealtimeTriplet {
            boottime_before_ns: 1_000_000_000,
            realtime_ns: 10_000_000_000,
            boottime_after_ns: 1_000_000_010,
        };
        let clean = RealtimeTriplet {
            boottime_before_ns: 1_100_000_000,
            realtime_ns: 10_100_000_000,
            boottime_after_ns: 1_100_000_010,
        };
        assert!(!realtime_discontinuous(&previous, &clean).unwrap());
        let forward = RealtimeTriplet {
            realtime_ns: 11_000_000_000,
            ..clean.clone()
        };
        assert!(realtime_discontinuous(&previous, &forward).unwrap());
        let backward = RealtimeTriplet {
            realtime_ns: 9_000_000_000,
            ..clean
        };
        assert!(realtime_discontinuous(&previous, &backward).unwrap());
    }
}
