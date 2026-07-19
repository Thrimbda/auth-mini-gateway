//! Separate Linux sampler role with dynamic pinning and strict post-freeze inventory.

use crate::control::{
    connect_loopback, ControlBody, ControlContext, CpuAttribution, ObservedProcess, ResourcePoint,
    Role, SamplerReport, ThreadIdentity, ThreadInventory,
};
use crate::linux::{
    clock_ns, pressure_totals, process_identity, read_per_cpu_ticks, read_proc_stat,
    read_proc_status, set_affinity, swap_counters, task_ids, tctl_millidegrees, validate_identity,
    ClockKind, CpuTicks, ProcessIdentity,
};
use crate::seal::sha256_hex;
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
struct TrackedThread {
    identity: ThreadIdentity,
    role: Role,
    alive: bool,
}

#[derive(Debug, Clone)]
struct BoundarySnapshot {
    monotonic_ns: u64,
    boottime_ns: u64,
    tid_before: BTreeMap<(u32, u32), u64>,
    cpus: BTreeMap<u16, CpuTicks>,
    tid_after: BTreeMap<(u32, u32), u64>,
}

#[derive(Default)]
struct SamplerState {
    processes: Vec<ObservedProcess>,
    threads: BTreeMap<(u32, u32), TrackedThread>,
    lifecycle_events: u64,
    frozen: bool,
    frozen_keys: BTreeSet<(u32, u32)>,
    post_freeze_change: Option<String>,
    freeze_boundary: Option<BoundarySnapshot>,
    gateway_stopped: bool,
}

pub async fn run_sampler_role(context: ControlContext, control_address: SocketAddr) -> Result<()> {
    let mut control = connect_loopback(control_address, context).await?;
    control
        .send(ControlBody::Hello {
            role: Role::Sampler,
            identity: process_identity(std::process::id())?,
        })
        .await?;
    control
        .send(ControlBody::Ready {
            role: Role::Sampler,
            data_address: None,
            tripwire_address: None,
        })
        .await?;
    let state = Arc::new(Mutex::new(SamplerState::default()));
    let polling_state = Arc::clone(&state);
    let poller = tokio::spawn(async move {
        loop {
            if let Ok(mut state) = polling_state.lock() {
                let _ = state.poll_lifecycle();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    loop {
        match control.receive().await? {
            ControlBody::RegisterProcesses { processes } => {
                {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    state.register(processes)?;
                    state.poll_lifecycle()?;
                }
                control.send(ControlBody::ProcessesRegistered).await?;
            }
            ControlBody::Inventory => {
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
            ControlBody::WaitWebsocketRetirement {
                gateway_pre_auth_tids,
                keepalive_ns,
                stability_ns,
                cap_ns,
            } => {
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
                let report = {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    state.freeze()?
                };
                control.send(ControlBody::Frozen { report }).await?;
            }
            ControlBody::Release => {
                let monotonic_ns = {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    state.release_gateway()?
                };
                control.send(ControlBody::Released { monotonic_ns }).await?;
            }
            ControlBody::FinalSample => {
                let report = {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    state.poll_lifecycle()?;
                    state.report()?
                };
                control.send(ControlBody::Sampled { report }).await?;
            }
            ControlBody::Stop => {
                poller.abort();
                {
                    let mut state = state
                        .lock()
                        .map_err(|_| Error::new("sampler state poisoned"))?;
                    if state.gateway_stopped {
                        let _ = state.release_gateway();
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
                )))
            }
        }
    }
}

impl SamplerState {
    fn register(&mut self, mut processes: Vec<ObservedProcess>) -> Result<()> {
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
            let actual_hash = sha256_hex(&fs::read(executable)?);
            if actual_hash != process.executable_sha256 {
                return Err(Error::new(format!(
                    "{} executable hash mismatch",
                    process.role.label()
                )));
            }
        }
        self.processes = processes;
        Ok(())
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
                if let Some(thread) = self.threads.get_mut(&key) {
                    let start_time_changed =
                        thread.identity.start_time_ticks != stat.start_time_ticks;
                    thread.alive = true;
                    if start_time_changed {
                        self.note_post_freeze(format!("TID {tid} start time changed"));
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
                        },
                    );
                    self.lifecycle_events = self.lifecycle_events.saturating_add(1);
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
                }
                self.lifecycle_events = self.lifecycle_events.saturating_add(1);
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
            }
        }
        Ok(())
    }

    fn freeze(&mut self) -> Result<SamplerReport> {
        if self.frozen {
            return Err(Error::new("sampler freeze invoked twice"));
        }
        if let Some(gateway) = self.gateway_identity() {
            let gateway = gateway.clone();
            validated_signal(&gateway, libc::SIGSTOP)?;
            self.gateway_stopped = true;
        }
        self.final_map()?;
        self.frozen_keys = self
            .threads
            .iter()
            .filter(|(_, thread)| thread.alive)
            .map(|(key, _)| *key)
            .collect();
        self.freeze_boundary = Some(self.boundary_snapshot()?);
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
                vm_hwm_kib: status.vm_hwm_kib,
                vm_rss_kib: status.vm_rss_kib,
            });
        }
        resources.sort_by_key(|resource| resource.role);
        Ok(resources)
    }

    fn boundary_snapshot(&self) -> Result<BoundarySnapshot> {
        let tid_before = self.read_live_tid_ticks()?;
        let cpus = read_per_cpu_ticks()?;
        let tid_after = self.read_live_tid_ticks()?;
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
        })
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

    fn report(&self) -> Result<SamplerReport> {
        let current = self.boundary_snapshot()?;
        let attribution = match &self.freeze_boundary {
            Some(start) => compute_attribution(start, &current, &self.threads)?,
            None => Vec::new(),
        };
        let pressure = pressure_totals()?;
        let (swap_in, swap_out) = swap_counters()?;
        Ok(SamplerReport {
            monotonic_ns: current.monotonic_ns,
            boottime_ns: current.boottime_ns,
            frozen: self.frozen,
            inventories: self.inventories()?,
            resources: self.resources()?,
            attribution,
            lifecycle_events: self.lifecycle_events,
            post_freeze_change: self.post_freeze_change.clone(),
            tctl_millidegrees: tctl_millidegrees().ok(),
            swap_in,
            swap_out,
            cpu_psi_some_us: pressure.cpu_some_us,
            memory_psi_full_us: pressure.memory_full_us,
            io_psi_full_us: pressure.io_full_us,
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
            if !thread.alive || thread.identity.assigned_cpu != *cpu {
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
        };
        let end = BoundarySnapshot {
            monotonic_ns: 2,
            boottime_ns: 2,
            tid_before: BTreeMap::from([(key, 110)]),
            cpus: BTreeMap::from([(0, ticks(0, 1_020, 1_080))]),
            tid_after: BTreeMap::from([(key, 111)]),
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
            },
        )]);
        let result = compute_attribution(&start, &end, &threads).expect("attribution");
        assert_eq!(result[0].role_runtime_lower_ticks, 9);
        assert_eq!(result[0].role_runtime_upper_ticks, 11);
        assert_eq!(result[0].attribution_uncertainty_ticks, 2);
        assert_eq!(result[0].external_upper_ticks, 11);
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
}
