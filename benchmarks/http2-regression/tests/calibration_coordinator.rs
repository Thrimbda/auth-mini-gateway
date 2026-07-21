use auth_mini_http2_regression::bundle::{create_bundle_derived, verify_bundle};
use auth_mini_http2_regression::calibration::ParameterDisposition;
use auth_mini_http2_regression::calibration_coordinator::test_support::{
    run_fake_calibration, FakeArmExecutor, FakeArmObservation, FakeResumeState,
};
use auth_mini_http2_regression::evidence::{
    execution_journal_root, ExecutionJournalKind, ExecutionJournalRecord, ExecutionPhase,
    ExecutionStateEvidence, MachineEvidence, ProjectionEvidence, SmokeCaseEvidence, SmokeCaseKey,
    SmokeKind, TopologySmokeEvidence, EXECUTION_STATE_SCHEMA, PROJECTION_SCHEMA, SMOKE_SCHEMA,
};
use auth_mini_http2_regression::process_plan::PlannedArm;
use auth_mini_http2_regression::raw::SemanticClass;
use auth_mini_http2_regression::schema::{
    Arm, CalibrationManifest, EvidenceClass, EvidenceKind, Intent, RawLimits, TerminalState,
    Workload, BASELINE_COMMIT, CALIBRATION_MANIFEST_SCHEMA, INITIAL_CANDIDATE_COMMIT,
    INTENT_SCHEMA, MACHINE_SCHEMA, TASK_CAP_BYTES,
};
use auth_mini_http2_regression::seal::{create_seal, sha256_hex};
use auth_mini_http2_regression::{json, Error, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-scratch");
        fs::create_dir_all(&parent).expect("test scratch parent");
        let root = parent.join(format!(
            "{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("exclusive test scratch");
        Self(root)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FakeExecutor {
    doubled_scout: bool,
    deviation: f64,
    mismatch: bool,
    direct_operations: u64,
    calls: u64,
    c_seen: std::collections::BTreeMap<(auth_mini_http2_regression::schema::Cell, Arm), u64>,
}

impl FakeExecutor {
    fn new(deviation: f64) -> Self {
        Self {
            doubled_scout: false,
            deviation,
            mismatch: false,
            direct_operations: 6_250,
            calls: 0,
            c_seen: std::collections::BTreeMap::new(),
        }
    }
}

impl FakeArmExecutor for FakeExecutor {
    fn execute(&mut self, arm: &PlannedArm) -> Result<FakeArmObservation> {
        self.calls += 1;
        let elapsed_ns = if self.doubled_scout
            && arm.evidence_class == EvidenceClass::S
            && arm.target == Some(5_000)
        {
            1_999_999_999
        } else {
            2_000_000_000
        };
        let mut signature = sha256_hex(
            format!("{}-{:?}-{:?}", arm.cell.id(), arm.arm, arm.direct_protocol).as_bytes(),
        );
        if arm.evidence_class == EvidenceClass::C {
            let key = (
                arm.cell,
                arm.arm
                    .ok_or_else(|| Error::new("fake C arm missing arm"))?,
            );
            let seen = self.c_seen.entry(key).or_default();
            *seen += 1;
            if self.mismatch && *seen == 2 {
                signature = sha256_hex(b"mismatched-fake-signature");
            }
        }
        Ok(FakeArmObservation {
            elapsed_ns,
            gateway_ticks: 100,
            operations: if arm.evidence_class == EvidenceClass::D {
                self.direct_operations
            } else {
                5_000
            },
            signature_sha256: signature,
        })
    }

    fn variance_standard_deviation(&self) -> f64 {
        self.deviation
    }
}

#[test]
fn accepted_first_scout_and_doubled_scout_are_exact() {
    let first = run_fake_calibration(7, &mut FakeExecutor::new(0.02), FakeResumeState::default())
        .expect("first-level calibration");
    assert_eq!(first.scout_levels, [1; 15]);
    assert_eq!(first.selected_n, Some(30));
    assert_eq!(first.direct_arms, 30);

    let mut doubled = FakeExecutor::new(0.02);
    doubled.doubled_scout = true;
    let doubled = run_fake_calibration(7, &mut doubled, FakeResumeState::default())
        .expect("doubled calibration");
    assert_eq!(doubled.scout_levels, [2; 15]);
}

#[test]
fn n30_n50_admit_and_n70_n100_block_without_substitution() {
    for (deviation, expected, disposition) in [
        (0.02, Some(30), ParameterDisposition::Admitted),
        (0.035, Some(50), ParameterDisposition::Admitted),
        (0.045, Some(70), ParameterDisposition::RuntimeBlocked),
        (0.055, Some(100), ParameterDisposition::RuntimeBlocked),
    ] {
        let result = run_fake_calibration(
            11,
            &mut FakeExecutor::new(deviation),
            FakeResumeState::default(),
        )
        .expect("N transition");
        assert_eq!(result.selected_n, expected);
        assert_eq!(result.disposition, disposition);
        assert_eq!(
            result.direct_arms,
            if disposition == ParameterDisposition::Admitted {
                30
            } else {
                0
            }
        );
    }
}

#[test]
fn signature_mismatch_and_direct_headroom_stop() {
    let mut mismatch = FakeExecutor::new(0.02);
    mismatch.mismatch = true;
    assert!(
        run_fake_calibration(13, &mut mismatch, FakeResumeState::default())
            .expect_err("signature mismatch")
            .to_string()
            .contains("signature mismatch")
    );

    let mut headroom = FakeExecutor::new(0.02);
    headroom.direct_operations = 6_249;
    assert!(
        run_fake_calibration(13, &mut headroom, FakeResumeState::default())
            .expect_err("headroom block")
            .to_string()
            .contains("1.25x headroom")
    );
}

#[test]
fn interrupted_prefix_never_resumes_and_completed_prefix_does() {
    let mut interrupted = FakeExecutor::new(0.02);
    let blocked = run_fake_calibration(
        17,
        &mut interrupted,
        FakeResumeState {
            completed_prefix: 9,
            partially_started_ordinal: Some(9),
        },
    )
    .expect("partial arm terminal");
    assert_eq!(blocked.disposition, ParameterDisposition::QualityBlocked);
    assert_eq!(interrupted.calls, 0);

    let mut resumed = FakeExecutor::new(0.02);
    let completed = run_fake_calibration(
        17,
        &mut resumed,
        FakeResumeState {
            completed_prefix: 3,
            partially_started_ordinal: None,
        },
    )
    .expect("resume before unstarted arm");
    assert_eq!(completed.resumed_prefix, 3);
    assert_eq!(completed.selected_n, Some(30));
}

#[test]
fn sealed_terminal_bundle_recomputes_without_source_trust() {
    let scratch = Scratch::new("calibration-terminal-bundle");
    let source = scratch.path("source");
    let bundle = scratch.path("bundle");
    let verify = scratch.path("verify");
    write_terminal_source(&source).expect("terminal source");
    let index = create_bundle_derived(&source, &bundle).expect("bundle");
    assert_eq!(index.terminal_state, TerminalState::Blocked);
    let receipt = verify_bundle(&bundle.join("bundle-index.json"), &verify)
        .expect("independent bundle verification");
    assert!(receipt.success && receipt.byte_equal);
    assert_eq!(receipt.raw_arm_count, 0);
}

fn write_terminal_source(root: &Path) -> Result<()> {
    fs::create_dir(root)?;
    let intent = Intent {
        schema: INTENT_SCHEMA.to_owned(),
        evidence_id: "fake-terminal-calibration".to_owned(),
        evidence_kind: EvidenceKind::Calibration,
        baseline_commit: BASELINE_COMMIT.to_owned(),
        candidate_commit: INITIAL_CANDIDATE_COMMIT.to_owned(),
        campaign_seed: 19,
        encoder: auth_mini_http2_regression::codec::current_identity(),
        producer_executable_sha256: auth_mini_http2_regression::codec::current_executable_sha256()?,
        zstd: auth_mini_http2_regression::schema::ZstdParameterProgram::fixed(),
        raw_limits: RawLimits::fixed(),
        trust_boundary: None,
        harness_provenance: None,
    };
    let intent_bytes = json::write_new_canonical(&root.join("intent.json"), &intent)?;
    let machine = MachineEvidence {
        schema: MACHINE_SCHEMA.to_owned(),
        fingerprint_sha256: sha256_hex(b"fake-machine"),
        boot_id_sha256: sha256_hex(b"fake-boot"),
        online_cpus: "0-31".to_owned(),
        clocksource: "tsc".to_owned(),
        clock_ticks_per_second: 100,
        math_abi_sha256: auth_mini_http2_regression::statistics::math_target_sha256(),
    };
    let machine_bytes = json::write_new_canonical(&root.join("machine.json"), &machine)?;
    let build_set_bytes = json::write_new_canonical(
        &root.join("build-set.json"),
        &serde_json::json!({"test_only": true}),
    )?;
    let tracked = auth_mini_http2_regression::storage::actual_regular_bytes_if_exists(
        &auth_mini_http2_regression::bundle::repository_root(root)?
            .join(".legion/tasks/prove-http2-performance-regression/artifacts"),
    )?;
    fs::create_dir(root.join("state"))?;
    fs::create_dir(root.join("projections"))?;
    let plan_sha256 = sha256_hex(&intent_bytes);
    let campaign_start = ExecutionJournalRecord {
        schema: EXECUTION_STATE_SCHEMA.to_owned(),
        calibration_id: intent.evidence_id.clone(),
        sequence: 0,
        kind: ExecutionJournalKind::CampaignStart,
        phase: ExecutionPhase::Smoke,
        ordinal: None,
        boottime_ns: 1,
        boot_id_sha256: machine.boot_id_sha256.clone(),
        machine_sha256: sha256_hex(&machine_bytes),
        build_set_sha256: sha256_hex(&build_set_bytes),
        plan_sha256: plan_sha256.clone(),
        predecessor_sha256: None,
        raw_path: None,
        raw_sha256: None,
    };
    let campaign_bytes = json::write_new_canonical(
        &root.join("state/000000-campaign-start.json"),
        &campaign_start,
    )?;
    let smoke_start = ExecutionJournalRecord {
        schema: EXECUTION_STATE_SCHEMA.to_owned(),
        calibration_id: intent.evidence_id.clone(),
        sequence: 1,
        kind: ExecutionJournalKind::SmokeStart,
        phase: ExecutionPhase::Smoke,
        ordinal: None,
        boottime_ns: 2,
        boot_id_sha256: machine.boot_id_sha256.clone(),
        machine_sha256: sha256_hex(&machine_bytes),
        build_set_sha256: sha256_hex(&build_set_bytes),
        plan_sha256,
        predecessor_sha256: Some(sha256_hex(&campaign_bytes)),
        raw_path: None,
        raw_sha256: None,
    };
    json::write_new_canonical(&root.join("state/000001-smoke-start.json"), &smoke_start)?;
    let journal_root = execution_journal_root(&[campaign_start, smoke_start])?;

    let arm_root = sha256_hex(b"amg-http2-perf/raw-arm-prefix/v1\0");
    let projection0 = ProjectionEvidence {
        schema: PROJECTION_SCHEMA.to_owned(),
        revision: 0,
        predecessor: None,
        source_arm_root_sha256: Some(arm_root.clone()),
        completed_arms: 0,
        runtime_projected_ns: 1,
        runtime_actual_ns: 1,
        q_extra_ns: 0,
        raw_projected_bytes: TASK_CAP_BYTES,
        raw_actual_bytes: 0,
        tracked_projected_bytes: TASK_CAP_BYTES,
        tracked_actual_bytes: tracked,
        endpoint_bound_bytes: 512 + 160 * 137 + 512,
        conn_live: 137,
        concurrency: 1,
        storage_admission: None,
    };
    let projection0_bytes =
        json::write_new_canonical(&root.join("projections/000.json"), &projection0)?;
    let projection1 = ProjectionEvidence {
        revision: 1,
        predecessor: Some(auth_mini_http2_regression::calibration::FileHashBinding {
            path: "projections/000.json".to_owned(),
            sha256: sha256_hex(&projection0_bytes),
        }),
        ..projection0.clone()
    };
    let projection1_bytes = json::write_new_canonical(&root.join("projection.json"), &projection1)?;
    let delivery_projection = ProjectionEvidence {
        revision: 2,
        predecessor: Some(auth_mini_http2_regression::calibration::FileHashBinding {
            path: "projection.json".to_owned(),
            sha256: sha256_hex(&projection1_bytes),
        }),
        ..projection0
    };
    let delivery_projection_bytes =
        json::write_new_canonical(&root.join("delivery-projection.json"), &delivery_projection)?;
    let state = ExecutionStateEvidence {
        schema: EXECUTION_STATE_SCHEMA.to_owned(),
        evidence_id: intent.evidence_id.clone(),
        phase: ExecutionPhase::Complete,
        next_ordinal: 0,
        planned_arms: 0,
        completed_arms: 0,
        complete: true,
        crash_detail: Some("bounded fake terminal".to_owned()),
        campaign_boottime_start_ns: Some(1),
        campaign_boottime_end_ns: Some(2),
        machine_sha256: Some(sha256_hex(&machine_bytes)),
        build_set_sha256: Some(sha256_hex(&build_set_bytes)),
        journal_root_sha256: Some(journal_root),
        partially_started_ordinal: None,
    };
    let state_bytes = json::write_new_canonical(&root.join("execution-state.json"), &state)?;
    let operation_hash = sha256_hex(b"fake-smoke-operation");
    let smoke_bytes = json::write_new_canonical(
        &root.join("topology-smoke.json"),
        &TopologySmokeEvidence {
            schema: SMOKE_SCHEMA.to_owned(),
            calibration_id: intent.evidence_id,
            attempt_ordinal: 0,
            monotonic_start_ns: 1,
            monotonic_deadline_ns: 300_000_000_001,
            monotonic_end_ns: 2,
            baseline_binary_sha256: sha256_hex(b"baseline"),
            candidate_binary_sha256: sha256_hex(b"candidate"),
            harness_binary_sha256: intent.producer_executable_sha256,
            build_set_sha256: sha256_hex(b"build-set"),
            build_set_required: false,
            raw_cases_required: false,
            terminal_integrity_failure: None,
            cases: vec![SmokeCaseEvidence {
                key: SmokeCaseKey {
                    kind: SmokeKind::Gateway,
                    concurrency: 1,
                    workload: Workload::Upload1Mib,
                    arm: Some(Arm::B11),
                    direct_protocol: None,
                },
                started_operations: 2,
                completed_operations: 1,
                physical_connections: 2,
                stream_ids: Vec::new(),
                close_tokens: 1,
                transport_eof: 1,
                retries: 0,
                reconnects: 0,
                reuse_attempts: 0,
                evidence_integrity_failure: false,
                operation_hash_sha256: operation_hash.clone(),
                connection_hash_sha256: operation_hash,
                semantic_class: SemanticClass::BaselineFailure,
                semantic_detail: "bounded fake baseline failure".to_owned(),
                phase_separation: None,
            }],
        },
    )?;
    let manifest = CalibrationManifest {
        schema: CALIBRATION_MANIFEST_SCHEMA.to_owned(),
        calibration_id: "fake-terminal-calibration".to_owned(),
        intent_sha256: sha256_hex(&intent_bytes),
        machine_sha256: sha256_hex(&machine_bytes),
        build_set_sha256: sha256_hex(&build_set_bytes),
        topology_smoke_sha256: sha256_hex(&smoke_bytes),
        calibration_plan_sha256: None,
        authoritative_parameters_sha256: None,
        execution_state_sha256: sha256_hex(&state_bytes),
        projection_sha256: sha256_hex(&delivery_projection_bytes),
        arm_bindings: Vec::new(),
        signature_bindings: Vec::new(),
        selected_n: None,
        terminal_state: TerminalState::Blocked,
        terminal_reasons: vec!["bounded fake smoke interruption".to_owned()],
        records: Vec::new(),
    };
    json::write_new_canonical(&root.join("calibration-manifest.json"), &manifest)?;
    create_seal(root)?;
    Ok(())
}
