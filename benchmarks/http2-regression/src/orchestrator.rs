//! Fresh-process arm orchestration and bounded all-topology correctness smoke.

#![allow(unsafe_code)]

use crate::build::{build_pair, BuildSet};
use crate::control::{
    bind_loopback, ConnectionPolicy, ControlBody, ControlContext, FixtureResult, FramedControl,
    LoadProof, LoadResult, LoadTarget, ObservedProcess, Role, SamplerReport, ThreadIdentity,
};
use crate::json;
use crate::linux::{
    clock_ns, preflight, process_identity, realtime_triplet, set_affinity, utc_rfc3339, ClockKind,
    HostPreflight, ProcessIdentity, CONTROL_CPUS, FIXTURE_CPUS, GATEWAY_CPUS, LOAD_CPUS,
};
use crate::process_plan::{
    WEBSOCKET_KEEPALIVE_NS, WEBSOCKET_SETTLE_CAP_NS, WEBSOCKET_STABILITY_NS,
};
use crate::schema::{Arm, Cell, Workload, BASELINE_COMMIT};
use crate::seal::{create_seal, sha256_hex};
use crate::session::{
    create_ready_session, ReadySessionEvidence, COOKIE_SECRET, SESSION_TTL_SECONDS,
    TOUCH_INTERVAL_SECONDS, USER_ID,
};
use crate::topology::{ArmTopology, GatewayObject, Protocol};
use crate::{Error, Result, ResultContext};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::net::SocketAddr;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const SMOKE_SCHEMA: &str = "amg-http2-perf/smoke/v1";
pub const SMOKE_CAP_NS: u64 = 300_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeSummary {
    pub schema: String,
    pub authoritative: bool,
    pub run_id: String,
    pub baseline_commit: String,
    pub candidate_commit: String,
    pub baseline_binary_sha256: String,
    pub candidate_binary_sha256: String,
    pub harness_binary_sha256: String,
    pub started_utc: String,
    pub boottime_start_ns: u64,
    pub boottime_end_ns: u64,
    pub arms: Vec<SmokeArmOutcome>,
    pub protocol_correct_arms: u64,
    pub direct_upload_controls: Vec<DirectSmokeOutcome>,
    pub direct_protocol_correct_cases: u64,
    pub host_quality_blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSmokeOutcome {
    pub ordinal: u64,
    pub cell: Cell,
    pub protocol: Protocol,
    pub proof: LoadProof,
    pub measured: LoadResult,
    pub fixture_physical_connections: u64,
    pub fixture_active_connections: u64,
    pub fixture_max_active_connections: u64,
    pub fixture_max_requests_per_connection: u64,
    pub fixture_connection_ids: Vec<u64>,
    pub fixture_stream_ids: Vec<u64>,
    pub frozen_thread_counts: BTreeMap<String, u64>,
    pub sampler_lifecycle_events: u64,
    pub sampler_attribution_cpus: u64,
    pub quality_blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeArmOutcome {
    pub ordinal: u64,
    pub cell: Cell,
    pub arm: Arm,
    pub downstream: Protocol,
    pub upstream: Protocol,
    pub gateway_binary_sha256: String,
    pub ready_session: ReadySessionEvidence,
    pub proof: LoadProof,
    pub websocket_warmup: Option<LoadResult>,
    pub measured: LoadResult,
    pub fixture_physical_connections: u64,
    pub fixture_max_active_connections: u64,
    pub fixture_max_requests_per_connection: u64,
    pub fixture_connection_ids: Vec<u64>,
    pub fixture_stream_ids: Vec<u64>,
    pub fixture_observations: u64,
    pub fixture_operation_hash_sha256: String,
    pub frozen_thread_counts: BTreeMap<String, u64>,
    pub sampler_lifecycle_events: u64,
    pub sampler_attribution_cpus: u64,
    pub ordinary_handoff_ns: Option<u64>,
    pub websocket_retirement_ns: Option<u64>,
    pub quality_blockers: Vec<String>,
}

struct ManagedChild {
    role: Role,
    child: Child,
    identity: ProcessIdentity,
    reaped: bool,
}

impl ManagedChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn validate(&self) -> Result<()> {
        let current = process_identity(self.pid())?;
        if current != self.identity || current.parent_pid != std::process::id() {
            return Err(Error::new(format!(
                "{} child PID/start-time/parent validation failed",
                self.role.label()
            )));
        }
        Ok(())
    }

    fn wait_clean(mut self, cap: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                if status.success() {
                    return Ok(());
                }
                return Err(Error::new(format!(
                    "{} child exited with {status}",
                    self.role.label()
                )));
            }
            if start.elapsed() >= cap {
                self.validate()?;
                validated_signal(&self.identity, libc::SIGKILL)?;
                let _ = self.child.wait();
                self.reaped = true;
                return Err(Error::new(format!(
                    "{} child exceeded clean-exit cap",
                    self.role.label()
                )));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn terminate(mut self, cap: Duration) -> Result<()> {
        self.validate()?;
        validated_signal(&self.identity, libc::SIGTERM)?;
        let start = std::time::Instant::now();
        loop {
            if self.child.try_wait()?.is_some() {
                self.reaped = true;
                return Ok(());
            }
            if start.elapsed() >= cap {
                self.validate()?;
                validated_signal(&self.identity, libc::SIGKILL)?;
                let _ = self.child.wait();
                self.reaped = true;
                return Err(Error::new(format!(
                    "{} child required emergency KILL",
                    self.role.label()
                )));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.reaped || self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        if self.validate().is_ok() {
            let _ = validated_signal(&self.identity, libc::SIGKILL);
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}

pub fn execution_root(repository: &Path) -> PathBuf {
    repository.join(".perf/prove-http2-performance-regression")
}

pub fn run_preflight(repository: &Path) -> Result<HostPreflight> {
    preflight(repository, Duration::from_secs(1))
}

pub fn build_exact_pair(repository: &Path, candidate: &str) -> Result<BuildSet> {
    let root = execution_root(repository);
    fs::create_dir_all(&root)?;
    build_pair(repository, &root, candidate)
}

pub async fn direct_upload_probe(repository: &Path) -> Result<Vec<DirectSmokeOutcome>> {
    let run_id = format!("direct-upload-probe-{}", realtime_triplet()?.realtime_ns);
    let mut outcomes = Vec::with_capacity(2);
    for (ordinal, protocol) in [Protocol::H1, Protocol::H2].into_iter().enumerate() {
        outcomes.push(
            run_direct_upload_smoke(repository, &run_id, ordinal as u64, protocol)
                .await
                .context(format!("direct upload probe {}", protocol.label()))?,
        );
    }
    Ok(outcomes)
}

pub async fn smoke_all(
    repository: &Path,
    candidate: &str,
    host: HostPreflight,
) -> Result<(SmokeSummary, PathBuf)> {
    if !host.smoke_ready {
        return Err(Error::new(format!(
            "host cannot run bounded smoke: {}",
            host.blockers.join("; ")
        )));
    }
    let builds = build_exact_pair(repository, candidate)?;
    let triplet = realtime_triplet()?;
    let unix_seconds = triplet.realtime_ns / 1_000_000_000;
    let started_utc = utc_rfc3339(unix_seconds)?;
    let run_id = format!("smoke-{}-{}", triplet.realtime_ns, &candidate[..12]);
    let root = execution_root(repository).join("smoke").join(&run_id);
    fs::create_dir_all(
        root.parent()
            .ok_or_else(|| Error::new("smoke root has no parent"))?,
    )?;
    fs::create_dir(&root).context("exclusive-create smoke root")?;
    set_mode(&root, 0o700)?;
    let boottime_start_ns = clock_ns(ClockKind::Boottime)?;
    let harness_binary_sha256 = sha256_hex(&fs::read(std::env::current_exe()?)?);
    let mut arms = Vec::with_capacity(25);
    let mut ordinal = 0_u64;
    for workload in Workload::ALL {
        for arm in Arm::ALL {
            let arm_root = root.join(format!(
                "arm-{ordinal:02}-{}-{}",
                workload.code(),
                arm.code()
            ));
            fs::create_dir(&arm_root)?;
            set_mode(&arm_root, 0o700)?;
            let outcome = run_smoke_arm(
                repository, &builds, &run_id, ordinal, workload, arm, &arm_root,
            )
            .await;
            match outcome {
                Ok(value) => {
                    fs::remove_dir_all(&arm_root)?;
                    arms.push(value);
                }
                Err(error) => {
                    let _ = fs::remove_dir_all(&arm_root);
                    let _ = fs::remove_dir_all(&root);
                    return Err(error.context(format!("smoke {} {}", workload.code(), arm.code())));
                }
            }
            let elapsed = clock_ns(ClockKind::Boottime)?
                .checked_sub(boottime_start_ns)
                .ok_or_else(|| Error::new("smoke BOOTTIME moved backwards"))?;
            if elapsed > SMOKE_CAP_NS {
                let _ = fs::remove_dir_all(&root);
                return Err(Error::new("all-topology smoke exceeded 300-second cap"));
            }
            ordinal += 1;
        }
    }
    let mut direct_upload_controls = Vec::with_capacity(2);
    for (direct_ordinal, protocol) in [Protocol::H1, Protocol::H2].into_iter().enumerate() {
        let arm_root = root.join(format!("direct-upload-{}", protocol.label()));
        fs::create_dir(&arm_root)?;
        set_mode(&arm_root, 0o700)?;
        let outcome =
            run_direct_upload_smoke(repository, &run_id, direct_ordinal as u64, protocol).await;
        match outcome {
            Ok(value) => {
                fs::remove_dir_all(&arm_root)?;
                direct_upload_controls.push(value);
            }
            Err(error) => {
                let _ = fs::remove_dir_all(&arm_root);
                let _ = fs::remove_dir_all(&root);
                return Err(error.context(format!("smoke direct upload {}", protocol.label())));
            }
        }
        let elapsed = clock_ns(ClockKind::Boottime)?
            .checked_sub(boottime_start_ns)
            .ok_or_else(|| Error::new("smoke BOOTTIME moved backwards"))?;
        if elapsed > SMOKE_CAP_NS {
            let _ = fs::remove_dir_all(&root);
            return Err(Error::new("all-topology smoke exceeded 300-second cap"));
        }
    }
    let boottime_end_ns = clock_ns(ClockKind::Boottime)?;
    let host_quality_blockers = host.blockers;
    let summary = SmokeSummary {
        schema: SMOKE_SCHEMA.to_owned(),
        authoritative: false,
        run_id,
        baseline_commit: BASELINE_COMMIT.to_owned(),
        candidate_commit: candidate.to_owned(),
        baseline_binary_sha256: builds.baseline.binary_sha256.clone(),
        candidate_binary_sha256: builds.candidate.binary_sha256.clone(),
        harness_binary_sha256,
        started_utc,
        boottime_start_ns,
        boottime_end_ns,
        protocol_correct_arms: arms.len() as u64,
        direct_protocol_correct_cases: direct_upload_controls.len() as u64,
        direct_upload_controls,
        host_quality_blockers,
        arms,
    };
    let summary_path = root.join("topology-smoke.json");
    json::write_new_canonical(&summary_path, &summary)?;
    create_seal(&root)?;
    Ok((summary, root))
}

async fn run_smoke_arm(
    repository: &Path,
    builds: &BuildSet,
    run_id: &str,
    ordinal: u64,
    workload: Workload,
    arm: Arm,
    arm_root: &Path,
) -> Result<SmokeArmOutcome> {
    let topology = ArmTopology::for_arm(arm);
    let build = match topology.gateway {
        GatewayObject::Baseline => &builds.baseline,
        GatewayObject::Candidate => &builds.candidate,
    };
    let binary = build.validate(repository)?;
    let cell = Cell {
        workload,
        concurrency: 1,
    };
    let context = ControlContext {
        run_id: format!("{run_id}-{ordinal}"),
        cell,
        arm,
        block: ordinal,
    };
    let (listener, control_address) = bind_loopback().await?;
    let executable = std::env::current_exe()?;
    let executable_sha256 = sha256_hex(&fs::read(&executable)?);
    let fixture_child = spawn_role(
        &executable,
        repository,
        Role::Fixture,
        FIXTURE_CPUS,
        control_address,
        &context,
    )?;
    let load_child = spawn_role(
        &executable,
        repository,
        Role::Load,
        LOAD_CPUS,
        control_address,
        &context,
    )?;
    let sampler_child = spawn_role(
        &executable,
        repository,
        Role::Sampler,
        CONTROL_CPUS,
        control_address,
        &context,
    )?;
    let mut controls = accept_roles(
        &listener,
        &context,
        [&fixture_child, &load_child, &sampler_child],
    )
    .await
    .context("accept gateway smoke role controls")?;
    let mut fixture = controls
        .remove(&Role::Fixture)
        .ok_or_else(|| Error::new("fixture control missing"))?;
    let mut load = controls
        .remove(&Role::Load)
        .ok_or_else(|| Error::new("load control missing"))?;
    let mut sampler = controls
        .remove(&Role::Sampler)
        .ok_or_else(|| Error::new("sampler control missing"))?;
    let (fixture_address, tripwire_address) = role_ready_fixture(&mut fixture).await?;
    role_ready(&mut load, Role::Load).await?;
    role_ready(&mut sampler, Role::Sampler).await?;
    fixture
        .send(ControlBody::ConfigureFixture {
            target: LoadTarget::Gateway,
            workload,
            expected_protocol: topology.upstream,
            corpus_sha256: crate::topology::Corpus::fixed().sha256(),
        })
        .await?;
    expect(&mut fixture, |body| {
        matches!(body, ControlBody::FixtureConfigured)
    })
    .await?;

    let session_root = arm_root.join("runtime");
    fs::create_dir(&session_root)?;
    set_mode(&session_root, 0o700)?;
    let session = create_ready_session(&session_root.join("gateway.sqlite"))?;
    let gateway_address = reserve_loopback_address().await?;
    let gateway_child = spawn_gateway(
        &binary,
        repository,
        GATEWAY_CPUS,
        gateway_address,
        fixture_address,
        tripwire_address,
        topology.upstream,
        &session.database_path,
        &session_root,
    )?;
    wait_gateway(gateway_address).await?;
    sampler
        .send(ControlBody::RegisterProcesses {
            processes: vec![
                observed(
                    Role::Orchestrator,
                    process_identity(std::process::id())?,
                    &executable_sha256,
                    CONTROL_CPUS,
                ),
                observed(
                    Role::Fixture,
                    fixture_child.identity.clone(),
                    &executable_sha256,
                    FIXTURE_CPUS,
                ),
                observed(
                    Role::Load,
                    load_child.identity.clone(),
                    &executable_sha256,
                    LOAD_CPUS,
                ),
                observed(
                    Role::Sampler,
                    sampler_child.identity.clone(),
                    &executable_sha256,
                    CONTROL_CPUS,
                ),
                observed(
                    Role::Gateway,
                    gateway_child.identity.clone(),
                    &build.binary_sha256,
                    GATEWAY_CPUS,
                ),
            ],
        })
        .await?;
    expect(&mut sampler, |body| {
        matches!(body, ControlBody::ProcessesRegistered)
    })
    .await?;
    let pre_auth_tids = if workload == Workload::WebSocket {
        sampler.send(ControlBody::Inventory).await?;
        gateway_threads(expect_inventory(&mut sampler).await?)?
    } else {
        Vec::new()
    };
    load.send(ControlBody::PrepareLoad {
        target: LoadTarget::Gateway,
        workload,
        protocol: topology.downstream,
        gateway_address: Some(gateway_address.to_string()),
        fixture_address: fixture_address.to_string(),
        cookie_header: Some(session.cookie_header.clone()),
        warmup_operations: 1,
        websocket_settle: workload == Workload::WebSocket,
    })
    .await?;
    let proof = expect_prepared(&mut load).await?;
    validate_proof(&proof, topology.downstream, workload, 1)?;
    let (websocket_retirement_ns, websocket_warmup) = if workload == Workload::WebSocket {
        sampler
            .send(ControlBody::WaitWebsocketRetirement {
                gateway_pre_auth_tids: pre_auth_tids,
                keepalive_ns: WEBSOCKET_KEEPALIVE_NS,
                stability_ns: WEBSOCKET_STABILITY_NS,
                cap_ns: WEBSOCKET_SETTLE_CAP_NS,
            })
            .await?;
        let elapsed = match sampler.receive().await? {
            ControlBody::WebsocketRetired { elapsed_ns, .. } => elapsed_ns,
            other => {
                return Err(Error::new(format!(
                    "expected WebsocketRetired, got {other:?}"
                )))
            }
        };
        load.send(ControlBody::Measure {
            phase: 1,
            operations: 1,
        })
        .await?;
        let warm = expect_measured(&mut load).await?;
        validate_load_result(&warm, 1, workload, topology.downstream, 1)?;
        (Some(elapsed), Some(warm))
    } else {
        (None, None)
    };
    let freeze_start = clock_ns(ClockKind::Monotonic)?;
    sampler.send(ControlBody::Freeze).await?;
    let frozen = expect_frozen(&mut sampler).await?;
    if let Some(blocker) = &frozen.post_freeze_change {
        return Err(Error::new(format!(
            "post-freeze change at freeze: {blocker}"
        )));
    }
    sampler.send(ControlBody::Release).await?;
    let release_ns = match sampler.receive().await? {
        ControlBody::Released { monotonic_ns } => monotonic_ns,
        other => return Err(Error::new(format!("expected Released, got {other:?}"))),
    };
    load.send(ControlBody::Measure {
        phase: 2,
        operations: 1,
    })
    .await?;
    let measured = expect_measured(&mut load).await?;
    validate_load_result(&measured, 1, workload, topology.downstream, 1)?;
    sampler.send(ControlBody::FinalSample).await?;
    let sampled = expect_sampled(&mut sampler).await?;
    if let Some(blocker) = &sampled.post_freeze_change {
        return Err(Error::new(format!(
            "post-freeze TID integrity failure: {blocker}"
        )));
    }
    fixture.send(ControlBody::FixtureSnapshot).await?;
    let fixture_result = expect_fixture(&mut fixture).await?;
    validate_fixture(
        &fixture_result,
        LoadTarget::Gateway,
        topology.upstream,
        &measured,
    )?;
    let quality_blockers = sampler_quality_blockers(&sampled);
    let ordinary_handoff_ns = (workload != Workload::WebSocket).then(|| release_ns - freeze_start);

    sampler.send(ControlBody::Stop).await?;
    expect_stopped(&mut sampler, Role::Sampler).await?;
    sampler_child.wait_clean(Duration::from_secs(1))?;
    load.send(ControlBody::Stop).await?;
    expect_stopped(&mut load, Role::Load).await?;
    load_child.wait_clean(Duration::from_secs(1))?;
    gateway_child.terminate(Duration::from_secs(1))?;
    fixture.send(ControlBody::Stop).await?;
    expect_stopped(&mut fixture, Role::Fixture).await?;
    fixture_child.wait_clean(Duration::from_secs(1))?;

    let frozen_thread_counts = frozen
        .inventories
        .iter()
        .map(|inventory| {
            (
                inventory.role.label().to_owned(),
                inventory.threads.len() as u64,
            )
        })
        .collect();
    let mut fixture_connection_ids = fixture_result
        .observations
        .iter()
        .map(|observation| observation.connection_id)
        .collect::<Vec<_>>();
    fixture_connection_ids.sort_unstable();
    fixture_connection_ids.dedup();
    let mut fixture_stream_ids = fixture_result
        .observations
        .iter()
        .filter_map(|observation| observation.stream_id)
        .collect::<Vec<_>>();
    fixture_stream_ids.sort_unstable();
    fixture_stream_ids.dedup();
    Ok(SmokeArmOutcome {
        ordinal,
        cell,
        arm,
        downstream: topology.downstream,
        upstream: topology.upstream,
        gateway_binary_sha256: build.binary_sha256.clone(),
        ready_session: session.evidence,
        proof,
        websocket_warmup,
        measured,
        fixture_physical_connections: fixture_result.physical_connections,
        fixture_max_active_connections: fixture_result.max_active_connections,
        fixture_max_requests_per_connection: fixture_result.max_requests_per_connection,
        fixture_connection_ids,
        fixture_stream_ids,
        fixture_observations: fixture_result.observations.len() as u64,
        fixture_operation_hash_sha256: fixture_result.operation_hash_sha256,
        frozen_thread_counts,
        sampler_lifecycle_events: sampled.lifecycle_events,
        sampler_attribution_cpus: sampled.attribution.len() as u64,
        ordinary_handoff_ns,
        websocket_retirement_ns,
        quality_blockers,
    })
}

async fn run_direct_upload_smoke(
    repository: &Path,
    run_id: &str,
    ordinal: u64,
    protocol: Protocol,
) -> Result<DirectSmokeOutcome> {
    let cell = Cell {
        workload: Workload::Upload1Mib,
        concurrency: 1,
    };
    let context = ControlContext {
        run_id: format!("{run_id}-direct-upload-{}", protocol.label()),
        cell,
        arm: if protocol == Protocol::H1 {
            Arm::B11
        } else {
            Arm::C22
        },
        block: 25 + ordinal,
    };
    let (listener, control_address) = bind_loopback().await?;
    let executable = std::env::current_exe()?;
    let executable_sha256 = sha256_hex(&fs::read(&executable)?);
    let fixture_child = spawn_role(
        &executable,
        repository,
        Role::Fixture,
        FIXTURE_CPUS,
        control_address,
        &context,
    )?;
    let load_child = spawn_role(
        &executable,
        repository,
        Role::Load,
        LOAD_CPUS,
        control_address,
        &context,
    )?;
    let sampler_child = spawn_role(
        &executable,
        repository,
        Role::Sampler,
        CONTROL_CPUS,
        control_address,
        &context,
    )?;
    let mut controls = accept_roles(
        &listener,
        &context,
        [&fixture_child, &load_child, &sampler_child],
    )
    .await
    .context("accept direct role controls")?;
    let mut fixture = controls
        .remove(&Role::Fixture)
        .ok_or_else(|| Error::new("direct fixture control missing"))?;
    let mut load = controls
        .remove(&Role::Load)
        .ok_or_else(|| Error::new("direct load control missing"))?;
    let mut sampler = controls
        .remove(&Role::Sampler)
        .ok_or_else(|| Error::new("direct sampler control missing"))?;
    let (fixture_address, _) = role_ready_fixture(&mut fixture)
        .await
        .context("direct fixture readiness")?;
    role_ready(&mut load, Role::Load)
        .await
        .context("direct load readiness")?;
    role_ready(&mut sampler, Role::Sampler)
        .await
        .context("direct sampler readiness")?;
    fixture
        .send(ControlBody::ConfigureFixture {
            target: LoadTarget::Direct,
            workload: Workload::Upload1Mib,
            expected_protocol: protocol,
            corpus_sha256: crate::topology::Corpus::fixed().sha256(),
        })
        .await?;
    expect(&mut fixture, |body| {
        matches!(body, ControlBody::FixtureConfigured)
    })
    .await
    .context("direct fixture configuration")?;
    sampler
        .send(ControlBody::RegisterProcesses {
            processes: vec![
                observed(
                    Role::Orchestrator,
                    process_identity(std::process::id())?,
                    &executable_sha256,
                    CONTROL_CPUS,
                ),
                observed(
                    Role::Fixture,
                    fixture_child.identity.clone(),
                    &executable_sha256,
                    FIXTURE_CPUS,
                ),
                observed(
                    Role::Load,
                    load_child.identity.clone(),
                    &executable_sha256,
                    LOAD_CPUS,
                ),
                observed(
                    Role::Sampler,
                    sampler_child.identity.clone(),
                    &executable_sha256,
                    CONTROL_CPUS,
                ),
            ],
        })
        .await?;
    expect(&mut sampler, |body| {
        matches!(body, ControlBody::ProcessesRegistered)
    })
    .await
    .context("direct process registration")?;
    load.send(ControlBody::PrepareLoad {
        target: LoadTarget::Direct,
        workload: Workload::Upload1Mib,
        protocol,
        gateway_address: None,
        fixture_address: fixture_address.to_string(),
        cookie_header: None,
        warmup_operations: 1,
        websocket_settle: false,
    })
    .await?;
    let proof = expect_prepared(&mut load)
        .await
        .context("direct load preparation")?;
    validate_proof(&proof, protocol, Workload::Upload1Mib, 1)?;
    sampler.send(ControlBody::Freeze).await?;
    let frozen = expect_frozen(&mut sampler)
        .await
        .context("direct sampler freeze")?;
    if let Some(blocker) = &frozen.post_freeze_change {
        return Err(Error::new(format!(
            "direct post-freeze change at freeze: {blocker}"
        )));
    }
    sampler.send(ControlBody::Release).await?;
    match sampler.receive().await? {
        ControlBody::Released { .. } => {}
        other => return Err(Error::new(format!("expected Released, got {other:?}"))),
    }
    load.send(ControlBody::Measure {
        phase: 2,
        operations: 1,
    })
    .await?;
    let measured = expect_measured(&mut load)
        .await
        .context("direct load measurement")?;
    validate_load_result(&measured, 1, Workload::Upload1Mib, protocol, 1)?;
    sampler.send(ControlBody::FinalSample).await?;
    let sampled = expect_sampled(&mut sampler)
        .await
        .context("direct final sample")?;
    if let Some(blocker) = &sampled.post_freeze_change {
        return Err(Error::new(format!(
            "direct post-freeze TID integrity failure: {blocker}"
        )));
    }
    if protocol == Protocol::H1 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    fixture.send(ControlBody::FixtureSnapshot).await?;
    let fixture_result = expect_fixture(&mut fixture)
        .await
        .context("direct fixture snapshot")?;
    validate_direct_upload_fixture(&fixture_result, protocol, &measured)?;

    sampler.send(ControlBody::Stop).await?;
    expect_stopped(&mut sampler, Role::Sampler).await?;
    sampler_child.wait_clean(Duration::from_secs(1))?;
    load.send(ControlBody::Stop).await?;
    expect_stopped(&mut load, Role::Load).await?;
    load_child.wait_clean(Duration::from_secs(1))?;
    fixture.send(ControlBody::Stop).await?;
    expect_stopped(&mut fixture, Role::Fixture).await?;
    fixture_child.wait_clean(Duration::from_secs(1))?;

    let mut fixture_connection_ids = fixture_result
        .observations
        .iter()
        .map(|observation| observation.connection_id)
        .collect::<Vec<_>>();
    fixture_connection_ids.sort_unstable();
    fixture_connection_ids.dedup();
    let mut fixture_stream_ids = fixture_result
        .observations
        .iter()
        .filter_map(|observation| observation.stream_id)
        .collect::<Vec<_>>();
    fixture_stream_ids.sort_unstable();
    fixture_stream_ids.dedup();
    let frozen_thread_counts = frozen
        .inventories
        .iter()
        .map(|inventory| {
            (
                inventory.role.label().to_owned(),
                inventory.threads.len() as u64,
            )
        })
        .collect();
    Ok(DirectSmokeOutcome {
        ordinal,
        cell,
        protocol,
        proof,
        measured,
        fixture_physical_connections: fixture_result.physical_connections,
        fixture_active_connections: fixture_result.active_connections,
        fixture_max_active_connections: fixture_result.max_active_connections,
        fixture_max_requests_per_connection: fixture_result.max_requests_per_connection,
        fixture_connection_ids,
        fixture_stream_ids,
        frozen_thread_counts,
        sampler_lifecycle_events: sampled.lifecycle_events,
        sampler_attribution_cpus: sampled.attribution.len() as u64,
        quality_blockers: sampler_quality_blockers(&sampled),
    })
}

async fn accept_roles<const N: usize>(
    listener: &tokio::net::TcpListener,
    context: &ControlContext,
    children: [&ManagedChild; N],
) -> Result<BTreeMap<Role, FramedControl>> {
    let mut expected = BTreeMap::new();
    for child in children {
        expected.insert(child.role, child.identity.clone());
    }
    let mut controls = BTreeMap::new();
    for _ in 0..N {
        let (stream, peer) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .map_err(|_| Error::new("role control connection timed out"))??;
        if !peer.ip().is_loopback() {
            return Err(Error::new("role control peer is not loopback"));
        }
        let mut control = FramedControl::new(stream, context.clone())?;
        let (role, identity) = match control.receive().await? {
            ControlBody::Hello { role, identity } => (role, identity),
            other => return Err(Error::new(format!("expected role Hello, got {other:?}"))),
        };
        let expected_identity = expected
            .get(&role)
            .ok_or_else(|| Error::new("unexpected role connected"))?;
        if &identity != expected_identity || controls.insert(role, control).is_some() {
            return Err(Error::new("role PID/start identity mismatch or duplicate"));
        }
    }
    Ok(controls)
}

fn spawn_role(
    executable: &Path,
    repository: &Path,
    role: Role,
    cpus: &[u16],
    control_address: SocketAddr,
    context: &ControlContext,
) -> Result<ManagedChild> {
    let mut command = Command::new(executable);
    command
        .current_dir(repository)
        .env_clear()
        .args([
            "role",
            "--kind",
            role.label(),
            "--control",
            &control_address.to_string(),
            "--run",
            &context.run_id,
            "--workload",
            context.cell.workload.code(),
            "--concurrency",
            &context.cell.concurrency.to_string(),
            "--arm",
            context.arm.code(),
            "--block",
            &context.block.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let affinity = cpus.to_vec();
    // SAFETY: pre_exec performs only the benchmark process's own affinity call.
    unsafe {
        command.pre_exec(move || {
            set_affinity(0, &affinity).map_err(|error| std::io::Error::other(error.to_string()))
        });
    }
    let child = command
        .spawn()
        .context(format!("spawn {} role", role.label()))?;
    let identity = process_identity(child.id())?;
    if identity.parent_pid != std::process::id() {
        return Err(Error::new("spawned role is not a direct descendant"));
    }
    Ok(ManagedChild {
        role,
        child,
        identity,
        reaped: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_gateway(
    binary: &Path,
    repository: &Path,
    cpus: &[u16],
    address: SocketAddr,
    fixture: SocketAddr,
    tripwire: SocketAddr,
    upstream_protocol: Protocol,
    database: &Path,
    runtime_root: &Path,
) -> Result<ManagedChild> {
    let devnull = File::options().read(true).write(true).open("/dev/null")?;
    let stdout = devnull.try_clone()?;
    let stderr = devnull;
    let mut command = Command::new(binary);
    command
        .current_dir(repository)
        .env_clear()
        .env("HOST", "127.0.0.1")
        .env("PORT", address.port().to_string())
        .env("GATEWAY_PUBLIC_BASE_URL", "http://public.example")
        .env("AUTH_MINI_ISSUER", format!("http://{tripwire}"))
        .env("AUTH_MINI_PUBLIC_BASE_URL", format!("http://{tripwire}"))
        .env("GATEWAY_DB", database)
        .env("GATEWAY_COOKIE_SECRET", COOKIE_SECRET)
        .env("COOKIE_SECURE", "false")
        .env("COOKIE_SAME_SITE", "lax")
        .env("SESSION_TTL_SECONDS", SESSION_TTL_SECONDS.to_string())
        .env("SESSION_ABSOLUTE_TTL_SECONDS", "2592000")
        .env(
            "SESSION_TOUCH_INTERVAL_SECONDS",
            TOUCH_INTERVAL_SECONDS.to_string(),
        )
        .env("REFRESH_SKEW_SECONDS", "60")
        .env("ALLOW_USER_IDS", USER_ID)
        .env("TRUSTED_PROXY_CIDRS", "")
        .env("GATEWAY_MAX_DOWNSTREAM_CONNECTIONS", "256")
        .env("GATEWAY_MAX_ACTIVE_UPSTREAMS", "128")
        .env("GATEWAY_MAX_BLOCKING_RESOLVERS", "8")
        .env("UPSTREAM_URL", format!("http://{fixture}"))
        .env(
            "UPSTREAM_PROTOCOL",
            upstream_protocol.label().replace('h', "http"),
        )
        .env("NO_COLOR", "1")
        .env("TMPDIR", runtime_root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let affinity = cpus.to_vec();
    // SAFETY: pre_exec performs only the soon-to-exec gateway's own affinity call.
    unsafe {
        command.pre_exec(move || {
            set_affinity(0, &affinity).map_err(|error| std::io::Error::other(error.to_string()))
        });
    }
    let child = command.spawn().context("spawn exact archived gateway")?;
    let identity = process_identity(child.id())?;
    if identity.parent_pid != std::process::id() {
        return Err(Error::new("spawned gateway is not a direct descendant"));
    }
    Ok(ManagedChild {
        role: Role::Gateway,
        child,
        identity,
        reaped: false,
    })
}

async fn reserve_loopback_address() -> Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

async fn wait_gateway(address: SocketAddr) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(mut stream) = TcpStream::connect(address).await {
            stream
                .write_all(
                    b"GET /healthz HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n",
                )
                .await?;
            let mut bytes = Vec::new();
            if stream.read_to_end(&mut bytes).await.is_ok() && bytes.starts_with(b"HTTP/1.1 204") {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::new("gateway readiness exceeded two-second cap"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn role_ready_fixture(control: &mut FramedControl) -> Result<(SocketAddr, SocketAddr)> {
    match control.receive().await? {
        ControlBody::Ready {
            role: Role::Fixture,
            data_address: Some(data),
            tripwire_address: Some(tripwire),
        } => Ok((
            crate::control::parse_loopback_address(&data)?,
            crate::control::parse_loopback_address(&tripwire)?,
        )),
        other => Err(Error::new(format!("expected fixture Ready, got {other:?}"))),
    }
}

async fn role_ready(control: &mut FramedControl, role: Role) -> Result<()> {
    match control.receive().await? {
        ControlBody::Ready {
            role: actual,
            data_address: None,
            tripwire_address: None,
        } if actual == role => Ok(()),
        other => Err(Error::new(format!(
            "expected {role:?} Ready, got {other:?}"
        ))),
    }
}

async fn expect(
    control: &mut FramedControl,
    predicate: impl FnOnce(&ControlBody) -> bool,
) -> Result<()> {
    let body = control.receive().await?;
    if predicate(&body) {
        Ok(())
    } else {
        Err(Error::new(format!("unexpected control response: {body:?}")))
    }
}

async fn expect_prepared(control: &mut FramedControl) -> Result<LoadProof> {
    match control.receive().await? {
        ControlBody::Prepared { proof } => Ok(proof),
        ControlBody::RoleError { class, message } => Err(Error::new(format!("{class}: {message}"))),
        other => Err(Error::new(format!("expected Prepared, got {other:?}"))),
    }
}

async fn expect_measured(control: &mut FramedControl) -> Result<LoadResult> {
    match control.receive().await? {
        ControlBody::Measured { result } => Ok(result),
        ControlBody::RoleError { class, message } => Err(Error::new(format!("{class}: {message}"))),
        other => Err(Error::new(format!("expected Measured, got {other:?}"))),
    }
}

async fn expect_inventory(
    control: &mut FramedControl,
) -> Result<Vec<crate::control::ThreadInventory>> {
    match control.receive().await? {
        ControlBody::InventoryObserved { inventories } => Ok(inventories),
        other => Err(Error::new(format!(
            "expected InventoryObserved, got {other:?}"
        ))),
    }
}

async fn expect_frozen(control: &mut FramedControl) -> Result<SamplerReport> {
    match control.receive().await? {
        ControlBody::Frozen { report } => Ok(report),
        other => Err(Error::new(format!("expected Frozen, got {other:?}"))),
    }
}

async fn expect_sampled(control: &mut FramedControl) -> Result<SamplerReport> {
    match control.receive().await? {
        ControlBody::Sampled { report } => Ok(report),
        other => Err(Error::new(format!("expected Sampled, got {other:?}"))),
    }
}

async fn expect_fixture(control: &mut FramedControl) -> Result<FixtureResult> {
    match control.receive().await? {
        ControlBody::FixtureObserved { result } => Ok(result),
        other => Err(Error::new(format!(
            "expected FixtureObserved, got {other:?}"
        ))),
    }
}

async fn expect_stopped(control: &mut FramedControl, role: Role) -> Result<()> {
    match control.receive().await? {
        ControlBody::Stopped { role: actual } if actual == role => Ok(()),
        other => Err(Error::new(format!(
            "expected {role:?} Stopped, got {other:?}"
        ))),
    }
}

fn gateway_threads(
    inventories: Vec<crate::control::ThreadInventory>,
) -> Result<Vec<ThreadIdentity>> {
    inventories
        .into_iter()
        .find(|inventory| inventory.role == Role::Gateway)
        .map(|inventory| inventory.threads)
        .ok_or_else(|| Error::new("gateway pre-auth inventory missing"))
}

fn validate_proof(
    proof: &LoadProof,
    protocol: Protocol,
    workload: Workload,
    concurrency: u64,
) -> Result<()> {
    let expected_connections = if protocol == Protocol::H1 && workload == Workload::Upload1Mib {
        proof.warmup_operations
    } else if protocol == Protocol::H1 {
        concurrency
    } else {
        1
    };
    if proof.downstream_protocol != protocol
        || proof.physical_connections != expected_connections
        || proof.tunnels != concurrency * u64::from(workload == Workload::WebSocket)
        || (protocol == Protocol::H2 && !proof.h2_settings_proved)
        || (protocol == Protocol::H2
            && workload == Workload::WebSocket
            && !proof.extended_connect_proved)
    {
        return Err(Error::new("load proof protocol/connection/tunnel mismatch"));
    }
    validate_connection_ledger(
        &proof.connection_ledger,
        if workload == Workload::WebSocket {
            concurrency
        } else {
            proof.warmup_operations
        },
        workload,
        protocol,
        concurrency,
    )?;
    Ok(())
}

fn validate_load_result(
    result: &LoadResult,
    expected_operations: u64,
    workload: Workload,
    protocol: Protocol,
    concurrency: u64,
) -> Result<()> {
    if result.operations_started != expected_operations
        || result.operations_completed != expected_operations
        || result.operations_completed_by_deadline != expected_operations
        || result.window_deadline_ns.is_some()
        || result.window_end_ns < result.window_start_ns
        || !result.status_ok
        || !result.eos_ok
        || !result.payload_ok
        || !result.response_headers_sanitized
        || result.retries != 0
        || result.latencies_ns.len() as u64 != expected_operations
    {
        return Err(Error::new(
            "load correctness/count/no-retry validation failed",
        ));
    }
    validate_connection_ledger(
        &result.connection_ledger,
        expected_operations,
        workload,
        protocol,
        concurrency,
    )?;
    Ok(())
}

fn validate_connection_ledger(
    ledger: &crate::control::ConnectionLedger,
    operations: u64,
    workload: Workload,
    protocol: Protocol,
    concurrency: u64,
) -> Result<()> {
    let expected_policy = match (protocol, workload) {
        (Protocol::H1, Workload::Upload1Mib) => ConnectionPolicy::FreshH1PerOperation,
        (Protocol::H1, Workload::WebSocket) => ConnectionPolicy::H1UpgradeTunnels,
        (Protocol::H1, _) => ConnectionPolicy::PersistentH1,
        (Protocol::H2, Workload::WebSocket) => ConnectionPolicy::H2ExtendedConnectStreams,
        (Protocol::H2, _) => ConnectionPolicy::PersistentH2,
    };
    if ledger.policy != expected_policy
        || ledger.reuse_attempts != 0
        || ledger.reconnect_attempts != 0
        || ledger.retry_attempts != 0
        || ledger.operation_connection_hash_sha256.len() != 64
    {
        return Err(Error::new(
            "load connection policy/violation ledger mismatch",
        ));
    }
    match expected_policy {
        ConnectionPolicy::FreshH1PerOperation => {
            if [
                ledger.planned_connections,
                ledger.socket_creations,
                ledger.connect_attempts,
                ledger.connect_successes,
                ledger.cumulative_connections,
                ledger.requests,
                ledger.responses,
                ledger.close_tokens,
                ledger.response_eos,
                ledger.transport_eof,
            ]
            .iter()
            .any(|count| *count != operations)
                || ledger.keep_alive_tokens != 0
                || ledger.active_connections != 0
                || ledger.max_active_connections == 0
                || ledger.max_active_connections > concurrency
                || ledger.max_requests_per_connection != 1
            {
                return Err(Error::new(
                    "fresh-H1 connect/request/close/EOF ledger mismatch",
                ));
            }
        }
        ConnectionPolicy::PersistentH2 if workload == Workload::Upload1Mib => {
            if ledger.cumulative_connections != 1
                || ledger.h2_streams != operations
                || ledger.active_connections != 1
                || ledger.close_tokens != 0
                || ledger.transport_eof != 0
            {
                return Err(Error::new("persistent-H2 upload stream ledger mismatch"));
            }
        }
        ConnectionPolicy::PersistentH1 | ConnectionPolicy::H1UpgradeTunnels => {
            if ledger.cumulative_connections != concurrency || ledger.close_tokens != 0 {
                return Err(Error::new(
                    "persistent-H1/tunnel connection ledger mismatch",
                ));
            }
        }
        ConnectionPolicy::PersistentH2 | ConnectionPolicy::H2ExtendedConnectStreams => {
            if ledger.cumulative_connections != 1 || ledger.close_tokens != 0 {
                return Err(Error::new("persistent-H2 connection ledger mismatch"));
            }
        }
    }
    Ok(())
}

fn validate_fixture(
    fixture: &FixtureResult,
    target: LoadTarget,
    protocol: Protocol,
    measured: &LoadResult,
) -> Result<()> {
    if fixture.target != target
        || fixture.expected_protocol != protocol
        || fixture.physical_connections != 1
        || fixture.max_active_connections != 1
        || fixture.max_requests_per_connection == 0
        || fixture.tripwire_connections != 0
        || fixture.tripwire_bytes != 0
        || fixture.duplicate_operations != 0
        || fixture.unknown_requests != 0
        || !fixture.observations.iter().all(|observation| {
            observation.protocol == protocol
                && observation.payload_ok
                && observation.identity_ok
                && observation.request_headers_sanitized
                && observation.request_eos
                && (observation.method == "PING"
                    || observation.status == 200
                    || observation.status == 101)
                && if protocol == Protocol::H2 {
                    observation.stream_id.is_some_and(|stream| stream % 2 == 1)
                } else {
                    observation.stream_id.is_none()
                }
        })
        || !fixture
            .observations
            .iter()
            .any(|observation| observation.operation_id == measured.first_operation_id)
    {
        return Err(Error::new(
            "fixture endpoint/topology/tripwire reconciliation failed",
        ));
    }
    Ok(())
}

fn validate_direct_upload_fixture(
    fixture: &FixtureResult,
    protocol: Protocol,
    measured: &LoadResult,
) -> Result<()> {
    let expected_connections = if protocol == Protocol::H1 { 2 } else { 1 };
    let expected_active = if protocol == Protocol::H1 { 0 } else { 1 };
    let expected_max_requests = if protocol == Protocol::H1 { 1 } else { 2 };
    let mut connection_ids = fixture
        .observations
        .iter()
        .map(|observation| observation.connection_id)
        .collect::<Vec<_>>();
    connection_ids.sort_unstable();
    connection_ids.dedup();
    if fixture.target != LoadTarget::Direct
        || fixture.expected_protocol != protocol
        || fixture.physical_connections != expected_connections
        || fixture.active_connections != expected_active
        || fixture.max_active_connections != 1
        || fixture.max_requests_per_connection != expected_max_requests
        || connection_ids.len() as u64 != expected_connections
        || fixture.tripwire_connections != 0
        || fixture.tripwire_bytes != 0
        || fixture.duplicate_operations != 0
        || fixture.unknown_requests != 0
        || fixture.observations.len() != 2
        || !fixture.observations.iter().all(|observation| {
            observation.protocol == protocol
                && observation.payload_ok
                && observation.identity_ok
                && observation.request_headers_sanitized
                && observation.request_eos
                && observation.response_eos
                && observation.status == 200
                && if protocol == Protocol::H2 {
                    observation.stream_id.is_some_and(|stream| stream % 2 == 1)
                } else {
                    observation.stream_id.is_none()
                }
        })
        || !fixture
            .observations
            .iter()
            .any(|observation| observation.operation_id == measured.first_operation_id)
    {
        return Err(Error::new(
            "direct upload fixture connection/stream reconciliation failed",
        ));
    }
    Ok(())
}

fn sampler_quality_blockers(report: &SamplerReport) -> Vec<String> {
    let mut blockers = Vec::new();
    for bucket in &report.attribution {
        if bucket.attribution_uncertainty_ticks > 1 {
            blockers.push(format!(
                "CPU {} attribution uncertainty {} ticks exceeds one",
                bucket.cpu, bucket.attribution_uncertainty_ticks
            ));
        }
        if bucket.capacity_ticks > 0
            && u128::from(bucket.external_upper_ticks) * 100 > u128::from(bucket.capacity_ticks)
        {
            blockers.push(format!(
                "CPU {} whole-window external upper bound exceeds 1%",
                bucket.cpu
            ));
        }
    }
    if report
        .tctl_millidegrees
        .is_some_and(|value| value >= 85_000)
    {
        blockers.push("Tctl reached the 85C immediate-stop threshold".to_owned());
    }
    blockers
}

fn observed(
    role: Role,
    identity: ProcessIdentity,
    executable_sha256: &str,
    cpus: &[u16],
) -> ObservedProcess {
    ObservedProcess {
        role,
        identity,
        executable_sha256: executable_sha256.to_owned(),
        broad_cpus: cpus.to_vec(),
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[allow(unsafe_code)]
fn validated_signal(identity: &ProcessIdentity, signal: i32) -> Result<()> {
    let current = process_identity(identity.pid)?;
    if &current != identity || current.parent_pid != std::process::id() {
        return Err(Error::new(
            "refusing to signal non-matching descendant identity",
        ));
    }
    let pid = i32::try_from(identity.pid).map_err(|_| Error::new("PID exceeds pid_t"))?;
    // SAFETY: the direct-child PID/start-time tuple was immediately revalidated.
    if unsafe { libc::kill(pid, signal) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampler_quality_is_diagnostic_for_non_authoritative_smoke() {
        let report = SamplerReport {
            monotonic_ns: 1,
            boottime_ns: 1,
            frozen: true,
            inventories: Vec::new(),
            resources: Vec::new(),
            attribution: vec![crate::control::CpuAttribution {
                cpu: 0,
                capacity_ticks: 100,
                scheduled_ticks: 100,
                role_runtime_lower_ticks: 98,
                role_runtime_upper_ticks: 100,
                attribution_uncertainty_ticks: 2,
                external_upper_ticks: 2,
            }],
            lifecycle_events: 0,
            post_freeze_change: None,
            tctl_millidegrees: Some(70_000),
            swap_in: 0,
            swap_out: 0,
            cpu_psi_some_us: 0,
            memory_psi_full_us: 0,
            io_psi_full_us: 0,
        };
        assert_eq!(sampler_quality_blockers(&report).len(), 2);
    }
}
