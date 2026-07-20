use auth_mini_http2_regression::archive;
use auth_mini_http2_regression::bundle::{chunk_ranges, create_bundle, verify_bundle, BundleIndex};
use auth_mini_http2_regression::codec;
use auth_mini_http2_regression::control::{RoleErrorCode, RoleErrorStage};
use auth_mini_http2_regression::evidence::{
    ExecutionPhase, ExecutionStateEvidence, MachineEvidence, ProjectionEvidence,
    RetainedSmokeFailure, SmokeCaseEvidence, SmokeCaseKey, SmokeKind, TopologySmokeEvidence,
    EXECUTION_STATE_SCHEMA, PROJECTION_SCHEMA, SMOKE_FAILURE_SCHEMA, SMOKE_SCHEMA,
};
use auth_mini_http2_regression::json;
use auth_mini_http2_regression::raw::{
    self, ClockSample, CpuBucketEvidence, EndpointEvidence, EndpointPhaseEvidence, FrozenThread,
    LifecycleStageEvidence, OperationSummaryEvidence, QuietEvidence, RawPhase, ResourceEvidence,
    RoleUtilizationEvidence, SemanticClass, SessionClockEvidence, ThreadLifecycleEvidence,
    ThreadMapEvidence,
};
use auth_mini_http2_regression::schema::{
    Arm, Cell, EvidenceClass, EvidenceKind, Intent, RawArmMetadata, RawLimits, RawProtocol,
    TerminalState, Workload, ARM_SCHEMA, BASELINE_COMMIT, INITIAL_CANDIDATE_COMMIT, INTENT_SCHEMA,
    MACHINE_SCHEMA,
};
use auth_mini_http2_regression::seal::{self, sha256_hex};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use zstd_safe::{CCtx, CParameter};

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

struct Scratch {
    root: PathBuf,
    parent: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let package = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    package.join(path)
                }
            })
            .unwrap_or_else(|| package.join("target"));
        let parent = target.join("test-scratch");
        fs::create_dir_all(&parent).expect("create repository-local test scratch parent");
        let unique = format!(
            "{}-{}-{}",
            name,
            std::process::id(),
            NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed)
        );
        let root = parent.join(unique);
        fs::create_dir(&root).expect("exclusive test scratch");
        Self { root, parent }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir(&self.parent);
    }
}

fn intent(id: &str, kind: EvidenceKind) -> Intent {
    Intent {
        schema: INTENT_SCHEMA.to_owned(),
        evidence_id: id.to_owned(),
        evidence_kind: kind,
        baseline_commit: BASELINE_COMMIT.to_owned(),
        candidate_commit: INITIAL_CANDIDATE_COMMIT.to_owned(),
        campaign_seed: 7,
        encoder: codec::current_identity(),
        producer_executable_sha256: codec::current_executable_sha256().expect("executable hash"),
        zstd: auth_mini_http2_regression::schema::ZstdParameterProgram::fixed(),
        raw_limits: RawLimits::fixed(),
    }
}

fn create_source(root: &Path, class: EvidenceClass) {
    fs::create_dir(root).expect("source root");
    json::write_new_canonical(
        &root.join("intent.json"),
        &intent("fixture-evidence", EvidenceKind::Calibration),
    )
    .expect("intent");
    let actual_tracked = auth_mini_http2_regression::bundle::repository_root(root)
        .ok()
        .map(|repository| {
            auth_mini_http2_regression::storage::actual_regular_bytes_if_exists(
                &repository.join(".legion/tasks/prove-http2-performance-regression/artifacts"),
            )
            .expect("actual tracked bytes")
        })
        .unwrap_or(0);
    let projection = ProjectionEvidence {
        schema: PROJECTION_SCHEMA.to_owned(),
        runtime_projected_ns: 1,
        runtime_actual_ns: 1,
        raw_projected_bytes: 1_000_000,
        raw_actual_bytes: 0,
        tracked_projected_bytes: actual_tracked,
        tracked_actual_bytes: actual_tracked,
        endpoint_bound_bytes: 512 + 160 * 137 + 512,
        conn_live: 137,
        concurrency: 1,
    };
    json::write_new_canonical(&root.join("projection.json"), &projection).expect("projection");
    json::write_new_canonical(&root.join("delivery-projection.json"), &projection)
        .expect("delivery projection");
    json::write_new_canonical(
        &root.join("machine.json"),
        &MachineEvidence {
            schema: MACHINE_SCHEMA.to_owned(),
            fingerprint_sha256: sha256_hex(b"fixture-machine"),
            boot_id_sha256: sha256_hex(b"fixture-boot"),
            online_cpus: "0-31".to_owned(),
            clocksource: "tsc".to_owned(),
            clock_ticks_per_second: 100,
            math_abi_sha256: auth_mini_http2_regression::statistics::math_target_sha256(),
        },
    )
    .expect("machine");
    json::write_new_canonical(
        &root.join("execution-state.json"),
        &ExecutionStateEvidence {
            schema: EXECUTION_STATE_SCHEMA.to_owned(),
            evidence_id: "fixture-evidence".to_owned(),
            phase: ExecutionPhase::Williams,
            next_ordinal: 1,
            planned_arms: 1,
            completed_arms: 1,
            complete: false,
            crash_detail: None,
        },
    )
    .expect("execution state");
    let smoke_hash = sha256_hex(b"smoke-fixture");
    json::write_new_canonical(
        &root.join("topology-smoke.json"),
        &TopologySmokeEvidence {
            schema: SMOKE_SCHEMA.to_owned(),
            calibration_id: "fixture-evidence".to_owned(),
            attempt_ordinal: 0,
            monotonic_start_ns: 1,
            monotonic_deadline_ns: 300_000_000_001,
            monotonic_end_ns: 2,
            baseline_binary_sha256: sha256_hex(b"baseline-bin"),
            candidate_binary_sha256: sha256_hex(b"candidate-bin"),
            harness_binary_sha256: sha256_hex(b"harness-bin"),
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
                operation_hash_sha256: smoke_hash.clone(),
                connection_hash_sha256: smoke_hash,
                semantic_class: SemanticClass::BaselineFailure,
                semantic_detail: "baseline smoke fixture failure".to_owned(),
                phase_separation: None,
            }],
        },
    )
    .expect("smoke");

    let class = if class.has_latencies() {
        EvidenceClass::C
    } else {
        EvidenceClass::S
    };
    let leaf = match class {
        EvidenceClass::S => root.join("scouts/get-c1/5000/B11"),
        EvidenceClass::C => root.join("arms/0/get-c1/B11"),
        _ => unreachable!("fixture class is normalized above"),
    };
    fs::create_dir_all(&leaf).expect("arm leaf");
    let drained = 5_000;
    let metadata = RawArmMetadata {
        schema: ARM_SCHEMA.to_owned(),
        evidence_id: "fixture-evidence".to_owned(),
        run_id: "fixture-evidence".to_owned(),
        class,
        cell: Cell {
            workload: Workload::Get,
            concurrency: 1,
        },
        arm: Some(Arm::B11),
        direct_protocol: None,
        ordinal: 0,
        round: None,
        row: (class == EvidenceClass::C).then_some(0),
        position: (class == EvidenceClass::C).then_some(0),
        epoch: None,
        scout_target: (class == EvidenceClass::S).then_some(drained),
        observation_id: "fixture-observation".to_owned(),
        started_operations: drained,
        deadline_completions: drained,
        drained_operations: drained,
        latency_record_ceiling: if class.has_latencies() { drained } else { 0 },
        materialization_sha256: None,
    };
    json::write_new_canonical(&leaf.join("metadata.json"), &metadata).expect("metadata");
    json::write_new_canonical(
        &leaf.join("quiet.json"),
        &QuietEvidence {
            schema: "amg-http2-perf/quiet/v1".to_owned(),
            clock: "CLOCK_MONOTONIC".to_owned(),
            start_ns: 1,
            end_ns: 10_000_000_001,
            q_extra_ns: 0,
            cpu_psi_some_us: 0,
            memory_psi_full_us: 0,
            io_psi_full_us: 0,
            swap_in_delta: 0,
            swap_out_delta: 0,
            steal_ticks_delta: 0,
            external_time_clean: true,
        },
    )
    .expect("quiet");
    json::write_new_canonical(
        &leaf.join("thread-map.json"),
        &ThreadMapEvidence {
            schema: "amg-http2-perf/thread-map/v1".to_owned(),
            signature_sha256: sha256_hex(b"thread-signature"),
            threads: vec![FrozenThread {
                role: "gateway".to_owned(),
                pid: 1,
                tid: 1,
                start_time_ticks: 1,
                comm: "gateway".to_owned(),
                assigned_cpu: 0,
                allowed_cpu: 0,
                observed_last_cpu: 0,
            }],
        },
    )
    .expect("thread map");
    raw::write_record_new(
        &leaf.join("thread-lifecycle.bin"),
        class,
        "thread-lifecycle.bin",
        &ThreadLifecycleEvidence {
            schema: "amg-http2-perf/thread-lifecycle/v1".to_owned(),
            stages: vec![LifecycleStageEvidence {
                name: "fixture".to_owned(),
                start_ns: 1,
                end_ns: 2,
            }],
            lifecycle_poll_max_ns: 10_000_000,
            births_before_freeze: 0,
            deaths_before_freeze: 0,
            births_after_freeze: 0,
            deaths_after_freeze: 0,
            migrations_after_freeze: 0,
            freeze_ns: 2,
            ordinary_handoff_ns: Some(1),
            websocket_auth_done_ns: None,
            websocket_eligible_ns: None,
            websocket_stable_ns: None,
        },
    )
    .expect("lifecycle");
    raw::write_record_new(
        &leaf.join("session-clock.bin"),
        class,
        "session-clock.bin",
        &SessionClockEvidence {
            schema: "amg-http2-perf/session-clock/v1".to_owned(),
            direct: false,
            comparable: true,
            discontinuities: 0,
            samples: vec![ClockSample {
                boottime_before_ns: 1,
                realtime_ns: 2,
                boottime_after_ns: 3,
                ready: true,
                active: true,
                refresh_due: false,
                touch_due: false,
            }],
        },
    )
    .expect("session clock");
    raw::write_record_new(
        &leaf.join("resources.bin"),
        class,
        "resources.bin",
        &ResourceEvidence {
            schema: "amg-http2-perf/resources/v1".to_owned(),
            gateway_ticks_start: 0,
            gateway_ticks_deadline: 500,
            gateway_ticks_drain: 500,
            vm_hwm_kib: 1,
            major_faults: 0,
            swap_in_delta: 0,
            swap_out_delta: 0,
            steal_ticks_delta: 0,
            memory_psi_full_us: 0,
            io_psi_full_us: 0,
            tctl_start_millidegrees: 50_000,
            tctl_max_millidegrees: 60_000,
            median_frequency_khz: 4_000_000,
            frequency_floor_khz: 4_000_000,
            buckets: vec![CpuBucketEvidence {
                cpu: 0,
                role: "gateway".to_owned(),
                start_ns: 1,
                end_ns: 1_000_000_001,
                process_runtime_lower: 500,
                process_runtime_upper: 500,
                tid_runtime_lower: 500,
                tid_runtime_upper: 500,
                capacity_ticks: 1_000,
                scheduled_ticks: 500,
                external_upper_ticks: 0,
                attribution_uncertainty_ticks: 0,
            }],
            utilization: vec![RoleUtilizationEvidence {
                role: "load".to_owned(),
                used_ticks: 1,
                capacity_ticks: 100,
            }],
            direct_ceiling_ops: None,
            gateway_ops: Some(drained),
            calibration_direct_ops: None,
        },
    )
    .expect("resources");
    let operation_hash = sha256_hex(b"fixture-operations");
    let phases = [
        RawPhase::Proof,
        RawPhase::Warmup,
        RawPhase::Measured,
        RawPhase::Drain,
    ]
    .into_iter()
    .map(|phase| EndpointPhaseEvidence {
        phase,
        started_operations: if phase == RawPhase::Measured {
            drained
        } else {
            0
        },
        attempt_starts: if phase == RawPhase::Measured {
            drained
        } else {
            0
        },
        attempt_successes: if phase == RawPhase::Measured {
            drained
        } else {
            0
        },
        planned_connections: 0,
        socket_creations: 0,
        connect_attempts: 0,
        connect_successes: 0,
        failed_attempts: 0,
        cumulative_connections: 0,
        requests: if phase == RawPhase::Measured {
            drained
        } else {
            0
        },
        responses: if phase == RawPhase::Measured {
            drained
        } else {
            0
        },
        request_bytes: 0,
        response_bytes: if phase == RawPhase::Measured {
            drained * 64
        } else {
            0
        },
        close_tokens: 0,
        keep_alive_tokens: 0,
        response_eos: if phase == RawPhase::Measured {
            drained
        } else {
            0
        },
        transport_eof: 0,
        active_connections: 0,
        max_active_connections: 0,
        max_requests_per_connection: 0,
        h2_streams: 0,
        max_active_h2_streams: 0,
        first_h2_stream_id: None,
        last_h2_stream_id: None,
        h2_stream_sequence_sha256: raw::stream_sequence_sha256(0).expect("empty phase stream hash"),
        retries: 0,
        reconnects: 0,
        reuse_attempts: 0,
        operation_hash_sha256: operation_hash.clone(),
        connection_hash_sha256: sha256_hex(format!("connection-{phase:?}").as_bytes()),
    })
    .collect::<Vec<_>>();
    raw::write_record_new(
        &leaf.join("endpoints.bin"),
        class,
        "endpoints.bin",
        &EndpointEvidence {
            schema: "amg-http2-perf/endpoints/v1".to_owned(),
            downstream_protocol: RawProtocol::H1,
            upstream_protocol: RawProtocol::H1,
            downstream_physical_connections: 1,
            upstream_physical_connections: 1,
            h2_settings_seen: false,
            h2_settings_ack_seen: false,
            enable_connect_seen: false,
            upstream_h2_settings_seen: false,
            upstream_h2_settings_ack_seen: false,
            upstream_enable_connect_seen: false,
            downstream_stream_count: 0,
            downstream_first_stream_id: None,
            downstream_last_stream_id: None,
            downstream_stream_sequence_sha256: raw::stream_sequence_sha256(0)
                .expect("empty downstream stream hash"),
            upstream_stream_count: 0,
            upstream_first_stream_id: None,
            upstream_last_stream_id: None,
            upstream_stream_sequence_sha256: raw::stream_sequence_sha256(0)
                .expect("empty upstream stream hash"),
            request_bytes: 0,
            response_bytes: drained * 64,
            load_operation_hash_sha256: operation_hash.clone(),
            fixture_operation_hash_sha256: operation_hash.clone(),
            tripwire_connections: 0,
            tripwire_bytes: 0,
            duplicate_operations: 0,
            phases,
        },
    )
    .expect("endpoints");
    raw::write_record_new(
        &leaf.join("operation-summary.bin"),
        class,
        "operation-summary.bin",
        &OperationSummaryEvidence {
            schema: "amg-http2-perf/operation-summary/v1".to_owned(),
            window_start_ns: 1,
            deadline_ns: 5_000_000_001,
            drain_end_ns: 5_000_000_002,
            started_operations: drained,
            deadline_completions: drained,
            drained_operations: drained,
            request_bytes: 0,
            response_bytes: drained * 64,
            first_operation_id: "operation-00000001".to_owned(),
            last_operation_id: "operation-00005000".to_owned(),
            operation_hash_sha256: operation_hash,
            exact_status: true,
            exact_version: true,
            exact_payload: true,
            exact_eos: true,
            sse_content_type: false,
            hidden_retry_count: 0,
            lane_quotas: vec![drained],
            lane_starts: vec![drained],
            lane_completions: vec![drained],
        },
    )
    .expect("operation summary");
    if class.has_latencies() {
        raw::write_latencies_new(&leaf.join("latencies.u64le"), class, &vec![10; 5_000])
            .expect("latencies");
    }
    seal::create_seal(root).expect("seal source");
}

#[test]
fn bundle_round_trip_recompresses_and_ignores_poisoned_analysis_json() {
    let scratch = Scratch::new("bundle-round-trip");
    let source = scratch.path("source");
    let bundle = scratch.path("bundle");
    create_source(&source, EvidenceClass::A);
    let index = create_bundle(&source, &bundle, TerminalState::Blocked).expect("bundle");
    assert_eq!(index.archive_member_count, index.seal_entry_count + 1);
    assert!(create_bundle(&source, &bundle, TerminalState::Pass).is_err());

    fs::write(
        bundle.join("analysis.json"),
        b"{\"verdict\":\"PASS\",\"poisoned\":true}\n",
    )
    .expect("poisoned derived analysis");
    let verification_scratch = scratch.path("verify");
    let receipt = verify_bundle(&bundle.join("bundle-index.json"), &verification_scratch)
        .expect("source-independent verification");
    assert!(receipt.byte_equal);
    assert!(receipt.analysis_input_ignored);
    assert_eq!(receipt.raw_arm_count, 1);
    assert!(
        !verification_scratch.exists(),
        "successful verifier cleans scratch"
    );
}

#[test]
fn bundle_creates_absent_repository_local_staging_and_verify_parents_strictly() {
    let scratch = Scratch::new("bundle-absent-parents");
    let source = scratch.path("source");
    let bundle = scratch.path("new/delivery-staging/evidence");
    create_source(&source, EvidenceClass::S);
    let index = create_bundle(&source, &bundle, TerminalState::Blocked).expect("nested bundle");
    assert_eq!(index.terminal_state, TerminalState::Blocked);
    let verify = scratch.path("new/bundle-verify/index-hash");
    let receipt = verify_bundle(&bundle.join("bundle-index.json"), &verify)
        .expect("nested verification scratch");
    assert!(receipt.success && receipt.byte_equal);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(bundle.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&bundle).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[test]
fn retained_failed_smoke_is_a_complete_verified_bundle() {
    let scratch = Scratch::new("retained-failure-bundle");
    let source = scratch.path("source");
    let bundle = scratch.path("delivery-staging/failed-smoke");
    create_source(&source, EvidenceClass::S);
    let intent_path = source.join("intent.json");
    let mut sealed_intent: Intent =
        json::read_strict(&intent_path, 1_048_576).expect("fixture intent");
    sealed_intent.producer_executable_sha256 = sha256_hex(b"retained-older-producer");
    fs::write(
        &intent_path,
        json::canonical_bytes(&sealed_intent).expect("older producer intent"),
    )
    .expect("replace fixture intent");
    let detail = "classified retained smoke failure";
    json::write_new_canonical(
        &source.join("smoke-failure.json"),
        &RetainedSmokeFailure {
            schema: SMOKE_FAILURE_SCHEMA.to_owned(),
            key: SmokeCaseKey {
                kind: SmokeKind::Gateway,
                concurrency: 1,
                workload: Workload::Get,
                arm: Some(Arm::B11),
                direct_protocol: None,
            },
            detail: detail.to_owned(),
            detail_sha256: sha256_hex(detail.as_bytes()),
            role_failure: None,
        },
    )
    .expect("retained failure");
    fs::remove_file(source.join("seal.json")).expect("replace fixture seal");
    let seal = seal::create_seal(&source).expect("seal retained failure");
    assert!(seal
        .entries
        .iter()
        .any(|entry| entry.path == "smoke-failure.json"));
    let index =
        create_bundle(&source, &bundle, TerminalState::Blocked).expect("retained failure bundle");
    assert_eq!(index.uncompressed_seal_root_sha256, seal.root_sha256);
    assert_eq!(
        index.producer_executable_sha256,
        sealed_intent.producer_executable_sha256
    );
    let receipt = verify_bundle(
        &bundle.join("bundle-index.json"),
        &scratch.path("bundle-verify/failed-smoke"),
    )
    .expect("verify retained failure bundle");
    assert_eq!(receipt.seal_root_sha256, seal.root_sha256);
}

#[test]
fn bundle_output_never_overwrites_an_existing_directory() {
    let scratch = Scratch::new("bundle-no-overwrite");
    let source = scratch.path("source");
    let bundle = scratch.path("delivery-staging/evidence");
    create_source(&source, EvidenceClass::S);
    create_bundle(&source, &bundle, TerminalState::Blocked).expect("first bundle");
    let index_path = bundle.join("bundle-index.json");
    let before = fs::read(&index_path).expect("first index");
    assert!(create_bundle(&source, &bundle, TerminalState::Blocked).is_err());
    assert_eq!(fs::read(index_path).expect("unchanged index"), before);
}

#[test]
fn chunk_hash_length_name_and_index_order_tampering_are_rejected() {
    let scratch = Scratch::new("chunk-tamper");
    let source = scratch.path("source");
    let bundle = scratch.path("bundle");
    create_source(&source, EvidenceClass::S);
    create_bundle(&source, &bundle, TerminalState::Blocked).expect("bundle");
    let index_path = bundle.join("bundle-index.json");
    let index: BundleIndex = json::read_strict(&index_path, 1_048_576).expect("index");
    let chunk_path = bundle.join(&index.chunks[0].path);
    let mut chunk = fs::read(&chunk_path).expect("chunk");
    chunk[0] ^= 1;
    fs::write(&chunk_path, &chunk).expect("tamper chunk");
    assert!(verify_bundle(&index_path, &scratch.path("verify-hash")).is_err());

    chunk[0] ^= 1;
    fs::write(&chunk_path, &chunk).expect("restore chunk");
    fs::write(bundle.join("chunks/999999.tar.zst.part"), b"extra").expect("extra chunk");
    assert!(verify_bundle(&index_path, &scratch.path("verify-extra")).is_err());
    fs::remove_file(bundle.join("chunks/999999.tar.zst.part")).expect("remove extra fixture");

    let mut malformed = index;
    malformed.chunks[0].ordinal = 1;
    malformed.chunks[0].path = "chunks/000001.tar.zst.part".to_owned();
    assert!(malformed.validate().is_err());
}

#[test]
fn valid_frame_from_different_zstd_level_fails_exact_bundle_recompression() {
    let scratch = Scratch::new("alternate-level");
    let source = scratch.path("source");
    let bundle = scratch.path("bundle");
    create_source(&source, EvidenceClass::S);
    create_bundle(&source, &bundle, TerminalState::Blocked).expect("bundle");

    let index_path = bundle.join("bundle-index.json");
    let mut index: BundleIndex = json::read_strict(&index_path, 1_048_576).expect("index");
    let sealed = seal::verify_seal(&source).expect("source seal");
    let canonical = archive::canonical_archive(&source, &sealed).expect("canonical source");
    let alternate = encode_level_one(&canonical);
    assert_eq!(
        codec::decode(&alternate, canonical.len() as u64).expect("alternate is valid"),
        canonical
    );
    let authoritative = codec::encode(
        &canonical,
        &codec::resolve_parameters(canonical.len() as u64).expect("parameters"),
    )
    .expect("authoritative encoding");
    assert_ne!(alternate, authoritative);
    let ranges = chunk_ranges(alternate.len() as u64).expect("alternate ranges");
    assert_eq!(ranges.len(), 1, "fixture intentionally remains one chunk");
    fs::write(bundle.join(&index.chunks[0].path), &alternate).expect("alternate chunk");
    index.chunks[0].bytes = alternate.len() as u64;
    index.chunks[0].sha256 = sha256_hex(&alternate);
    index.compressed_stream_bytes = alternate.len() as u64;
    index.compressed_stream_sha256 = sha256_hex(&alternate);
    index.chunk_total_bytes = alternate.len() as u64;
    let index_bytes = json::canonical_bytes(&index).expect("canonical altered index");
    fs::write(&index_path, index_bytes).expect("alter index fixture");
    let error = verify_bundle(&index_path, &scratch.path("verify"))
        .expect_err("different level must fail exact recompression");
    assert!(error.to_string().contains("recompression"));
}

fn encode_level_one(input: &[u8]) -> Vec<u8> {
    let mut context = CCtx::create();
    context
        .set_parameter(CParameter::CompressionLevel(1))
        .expect("level");
    context
        .set_parameter(CParameter::NbWorkers(0))
        .expect("workers");
    context
        .set_parameter(CParameter::ChecksumFlag(true))
        .expect("checksum");
    context
        .set_parameter(CParameter::ContentSizeFlag(true))
        .expect("content size");
    context
        .set_parameter(CParameter::DictIdFlag(false))
        .expect("dict ID");
    context
        .set_parameter(CParameter::EnableLongDistanceMatching(false))
        .expect("LDM");
    context
        .set_pledged_src_size(Some(input.len() as u64))
        .expect("pledged size");
    let mut output = vec![0; zstd_safe::compress_bound(input.len())];
    let written = context
        .compress2(&mut output, input)
        .expect("alternate compression");
    output.truncate(written);
    output
}

#[test]
fn malformed_raw_class_schema_seal_secret_and_unsafe_paths_fail_closed() {
    let scratch = Scratch::new("malformed-source");

    let missing_latency = scratch.path("missing-latency");
    create_source(&missing_latency, EvidenceClass::A);
    fs::remove_file(missing_latency.join("arms/0/get-c1/B11/latencies.u64le"))
        .expect("remove required latency");
    assert!(seal::verify_seal(&missing_latency).is_err());

    let forbidden_latency = scratch.path("forbidden-latency");
    create_source(&forbidden_latency, EvidenceClass::S);
    fs::write(
        forbidden_latency.join("scouts/get-c1/5000/B11/latencies.u64le"),
        b"forbidden",
    )
    .expect("forbidden member");
    fs::remove_file(forbidden_latency.join("seal.json")).expect("fixture reseal");
    seal::create_seal(&forbidden_latency).expect("reseal invalid class fixture");
    assert!(raw::validate_evidence_tree(&forbidden_latency).is_err());

    let placeholder = scratch.path("placeholder");
    create_source(&placeholder, EvidenceClass::S);
    let operation = placeholder.join("scouts/get-c1/5000/B11/operation-summary.bin");
    fs::write(&operation, b"opaque-placeholder").expect("placeholder raw member");
    fs::remove_file(placeholder.join("seal.json")).expect("placeholder reseal");
    seal::create_seal(&placeholder).expect("seal placeholder fixture");
    assert!(auth_mini_http2_regression::bundle::verify_source(&placeholder).is_err());

    let unknown = scratch.path("unknown-member");
    create_source(&unknown, EvidenceClass::S);
    fs::write(unknown.join("unknown-evidence.bin"), b"not schema-owned").expect("unknown member");
    fs::remove_file(unknown.join("seal.json")).expect("unknown reseal");
    seal::create_seal(&unknown).expect("seal unknown fixture");
    assert!(auth_mini_http2_regression::bundle::verify_source(&unknown).is_err());

    let missing = scratch.path("missing-member");
    create_source(&missing, EvidenceClass::S);
    fs::remove_file(missing.join("scouts/get-c1/5000/B11/resources.bin"))
        .expect("remove mandatory member");
    fs::remove_file(missing.join("seal.json")).expect("missing reseal");
    seal::create_seal(&missing).expect("seal missing fixture");
    assert!(auth_mini_http2_regression::bundle::verify_source(&missing).is_err());

    let secret = scratch.path("secret");
    fs::create_dir(&secret).expect("secret root");
    fs::write(secret.join("raw.json"), b"{\"token\":\"not-allowed\"}\n").expect("secret fixture");
    assert!(seal::create_seal(&secret).is_err());

    let unsafe_name = scratch.path("unsafe-name");
    fs::create_dir(&unsafe_name).expect("unsafe root");
    fs::write(unsafe_name.join("bad\\path"), b"x").expect("backslash fixture");
    assert!(seal::create_seal(&unsafe_name).is_err());

    let bad_schema = scratch.path("bad-schema");
    create_source(&bad_schema, EvidenceClass::S);
    let intent_path = bad_schema.join("intent.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&intent_path).expect("intent bytes"))
            .expect("intent value");
    value["schema"] = serde_json::Value::String("wrong/v1".to_owned());
    fs::write(
        &intent_path,
        json::canonical_bytes(&value).expect("bad intent bytes"),
    )
    .expect("bad intent");
    fs::remove_file(bad_schema.join("seal.json")).expect("fixture reseal");
    seal::create_seal(&bad_schema).expect("seal malformed schema fixture");
    assert!(create_bundle(
        &bad_schema,
        &scratch.path("bad-bundle"),
        TerminalState::Blocked
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn source_links_are_rejected_before_sealing() {
    use std::os::unix::fs::symlink;

    let scratch = Scratch::new("links");
    let source = scratch.path("source");
    fs::create_dir(&source).expect("source");
    fs::write(source.join("member.bin"), b"x").expect("member");
    fs::hard_link(source.join("member.bin"), source.join("alias.bin")).expect("hard link");
    assert!(seal::create_seal(&source).is_err());

    fs::remove_file(source.join("alias.bin")).expect("remove hard-link fixture");
    symlink("member.bin", source.join("link.bin")).expect("symlink");
    assert!(seal::create_seal(&source).is_err());
}

#[test]
fn cli_self_test_is_bounded_and_unknown_or_outside_paths_fail() {
    let binary = env!("CARGO_BIN_EXE_auth-mini-http2-regression");
    let output = Command::new(binary)
        .arg("self-test")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run self-test");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "self-test: PASS\n");

    let outside = Command::new(binary)
        .args(["verify", "--source", "/outside-repository"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run outside-path check");
    assert!(!outside.status.success());

    let unknown = Command::new(binary)
        .arg("not-a-command")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run unknown command");
    assert!(!unknown.status.success());
}

#[test]
fn cli_analyze_rejects_forged_equal_aggregate_input() {
    let scratch = Scratch::new("forged-aggregate");
    let aggregate = scratch.path("authoritative.json");
    let output_path = scratch.path("analysis.json");
    fs::write(
        &aggregate,
        b"{\"all_metrics_equal\":true,\"terminal\":\"PASS\"}\n",
    )
    .expect("forged aggregate");
    let binary = env!("CARGO_BIN_EXE_auth-mini-http2-regression");
    let output = Command::new(binary)
        .args([
            "analyze",
            "--source",
            aggregate.to_str().expect("aggregate path"),
            "--output",
            output_path.to_str().expect("output path"),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run forged aggregate check");
    assert!(!output.status.success());
    assert!(!output_path.exists());
}

#[test]
fn partial_smoke_candidate_failure_outranks_incompleteness_but_not_integrity() {
    let scratch = Scratch::new("partial-terminal-precedence");
    let source = scratch.path("source");
    create_source(&source, EvidenceClass::S);
    fs::remove_dir_all(source.join("scouts")).expect("remove not-yet-started scouts");

    let smoke_path = source.join("topology-smoke.json");
    let mut smoke: TopologySmokeEvidence =
        json::read_strict(&smoke_path, 1_048_576).expect("smoke fixture");
    smoke.cases[0].key.arm = Some(Arm::C11);
    smoke.cases[0].semantic_class = SemanticClass::CandidateFailure;
    smoke.cases[0].semantic_detail = "candidate smoke failure".to_owned();
    fs::write(
        &smoke_path,
        json::canonical_bytes(&smoke).expect("candidate smoke bytes"),
    )
    .expect("candidate smoke");
    let state_path = source.join("execution-state.json");
    let mut state: ExecutionStateEvidence =
        json::read_strict(&state_path, 1_048_576).expect("state fixture");
    state.phase = ExecutionPhase::Smoke;
    state.next_ordinal = 0;
    state.planned_arms = 0;
    state.completed_arms = 0;
    fs::write(
        &state_path,
        json::canonical_bytes(&state).expect("state bytes"),
    )
    .expect("state");
    fs::remove_file(source.join("seal.json")).expect("candidate reseal");
    seal::create_seal(&source).expect("candidate seal");
    let candidate = auth_mini_http2_regression::bundle::verify_source(&source)
        .expect("candidate semantic evidence remains structurally valid");
    assert_eq!(candidate.terminal_state, TerminalState::Fail);

    smoke.cases[0].retries = 1;
    smoke.cases[0].semantic_class = SemanticClass::IntegrityFailure;
    smoke.cases[0].semantic_detail = "retry integrity failure".to_owned();
    fs::write(
        &smoke_path,
        json::canonical_bytes(&smoke).expect("integrity smoke bytes"),
    )
    .expect("integrity smoke");
    fs::remove_file(source.join("seal.json")).expect("integrity reseal");
    seal::create_seal(&source).expect("integrity seal");
    let integrity = auth_mini_http2_regression::bundle::verify_source(&source)
        .expect("integrity terminal is derivable");
    assert_eq!(integrity.terminal_state, TerminalState::Blocked);
}

#[test]
fn real_spawned_roles_complete_one_b11_c1_get_control_cycle() {
    let scratch = Scratch::new("spawned-b11-get-control-cycle");
    let evidence = scratch.path("evidence");
    fs::create_dir(&evidence).expect("role-cycle evidence root");
    let repository =
        auth_mini_http2_regression::bundle::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("repository");
    let executable = Path::new(env!("CARGO_BIN_EXE_auth-mini-http2-regression"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("role-cycle runtime");
    let outcome = runtime
        .block_on(
            auth_mini_http2_regression::orchestrator::spawned_b11_get_role_cycle(
                &repository,
                executable,
                &evidence,
            ),
        )
        .expect("real spawned role cycle");
    assert_eq!(outcome.proof_operations, 1);
    assert_eq!(outcome.measured_operations, 1);
    assert_eq!(outcome.fixture_operations, 2);
    assert!(evidence.join("sampler-freeze.bin").is_file());
    assert!(evidence.join("sampler-final.bin").is_file());
}

#[test]
fn role_startup_command_crash_and_eof_are_retained_without_raw_text() {
    let scratch = Scratch::new("spawned-role-failures");
    let evidence = scratch.path("evidence");
    fs::create_dir(&evidence).expect("role-failure evidence root");
    let repository =
        auth_mini_http2_regression::bundle::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("repository");
    let executable = Path::new(env!("CARGO_BIN_EXE_auth-mini-http2-regression"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("role-failure runtime");
    let failures = runtime
        .block_on(
            auth_mini_http2_regression::orchestrator::spawned_role_failure_probes(
                &repository,
                executable,
                &evidence,
            ),
        )
        .expect("real retained role failures");
    assert_eq!(failures.len(), 3);
    assert_eq!(failures[0].class, "authenticated-terminal-error");
    assert_eq!(failures[0].terminal_class.as_deref(), Some("command"));
    assert_eq!(failures[0].stage, Some(RoleErrorStage::Prepare));
    assert_eq!(failures[0].code, Some(RoleErrorCode::ControlProtocol));
    assert!(failures[0]
        .summary()
        .contains("stage=prepare code=control-protocol"));
    assert_eq!(failures[0].exit_code, Some(2));
    assert_eq!(failures[1].class, "startup-control-eof");
    assert_eq!(failures[1].terminal_class, None);
    assert_eq!(failures[1].stage, Some(RoleErrorStage::Startup));
    assert_eq!(failures[1].code, Some(RoleErrorCode::ControlIo));
    assert_eq!(failures[1].exit_code, Some(2));
    assert_eq!(failures[2].class, "authenticated-control-eof");
    assert_eq!(failures[2].terminal_class, None);
    assert_eq!(failures[2].stage, Some(RoleErrorStage::Exit));
    assert_eq!(failures[2].code, Some(RoleErrorCode::ControlIo));
    assert_eq!(failures[2].signal, Some(libc::SIGKILL));
    for (directory, failure) in ["command", "startup", "crash"].into_iter().zip(&failures) {
        failure.validate().expect("classified role failure");
        let path = evidence.join(directory).join("role-failure-fixture.json");
        let bytes = fs::read(path).expect("retained role evidence");
        let text = String::from_utf8(bytes).expect("role evidence UTF-8");
        assert!(!text.contains("unexpected control message"));
        assert!(!text.contains("panic payload"));
        assert!(!text.contains("cookie"));
    }
}
