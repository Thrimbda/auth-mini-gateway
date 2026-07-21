//! One-shot calibration coordination and design-freeze delivery.

use crate::build::BuildSet;
use crate::bundle::{self, DeliveryEntry, DeliveryLedger};
use crate::calibration::{
    self, AcceptedScoutPanel, AuthoritativeParameters, CalibrationPlanEvidence, CellDurations,
    FileHashBinding, FrozenDurations, NSelection, ParameterDisposition, ScoutTransition,
    VarianceEstimate,
};
use crate::delivery::{DeliveryBinding, DeliveryPhase, DeliveryTransaction};
use crate::evidence::{
    execution_journal_root, ExecutionJournalKind, ExecutionJournalRecord, ExecutionPhase,
    ExecutionStateEvidence, MachineEvidence, ProjectionEvidence, EXECUTION_STATE_SCHEMA,
    PROJECTION_SCHEMA,
};
use crate::json;
use crate::linux::{clock_ns, filesystem_free_bytes, ClockKind};
use crate::orchestrator::{
    execute_process_arm, smoke_into_open_calibration, PreMeasureSignaturePolicy, ProcessArmOutcome,
    ProcessArmRequest,
};
use crate::process_plan::{self, PlannedArm};
use crate::raw::{self, ParsedArm, SemanticClass};
use crate::schema::{
    all_cells, hard_comparisons, AcceptedSignatureRecord, Arm, BlockedCode, BlockedReason,
    CalibrationArmBinding, CalibrationManifest, CalibrationPhase, CalibrationRecord, DesignLock,
    EvidenceClass, EvidenceKind, Intent, RawLimits, RawProtocol, SignatureBinding, TerminalState,
    TrustBoundaryManifest, ZstdParameterProgram, AUTHORITATIVE_PARAMETERS_SCHEMA, BASELINE_COMMIT,
    CALIBRATION_MANIFEST_SCHEMA, CALIBRATION_PLAN_SCHEMA, COORDINATED_INTENT_SCHEMA,
    DESIGN_LOCK_SCHEMA, MACHINE_SCHEMA, TASK_CAP_BYTES,
};
use crate::seal::{create_seal, sha256_hex};
use crate::statistics::{Metric, PairedMetrics};
use crate::storage::{
    self, ArmStorageInput, CompressionProfile, CompressionRequirement, ReachableInventory,
    ReachedBranchInput, ReachedBranchProjection, TrackedProjection, MIB,
};
use crate::topology::{ArmTopology, Protocol};
use crate::{Error, Result, ResultContext};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

pub const CONTINUATION_PROJECTION_SCHEMA: &str = "amg-http2-perf/continuation-projection/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationOutcome {
    pub calibration_id: String,
    pub candidate_commit: String,
    pub evidence_root: String,
    pub terminal_state: TerminalState,
    pub reasons: Vec<String>,
    pub selected_n: Option<u32>,
    pub seal_root_sha256: String,
    pub bundle_index_path: String,
    pub bundle_index_sha256: String,
    pub verification_path: String,
    pub verification_sha256: String,
    pub design_lock_path: Option<String>,
    pub design_lock_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationProjection {
    pub schema: String,
    pub calibration_id: String,
    pub intent_sha256: String,
    pub calibration_plan_sha256: String,
    pub authoritative_parameters_sha256: String,
    pub calibration_manifest_sha256: String,
    pub calibration_bundle_index_sha256: String,
    pub compression_profile_sha256: String,
    pub runtime: calibration::RuntimeProjection,
    pub tracked: TrackedProjection,
    pub authoritative_requirements: Vec<CompressionRequirement>,
    pub direct_requirements: Vec<CompressionRequirement>,
}

impl ContinuationProjection {
    pub fn validate(&self) -> Result<()> {
        if self.schema != CONTINUATION_PROJECTION_SCHEMA {
            return Err(Error::new("unsupported continuation projection schema"));
        }
        crate::schema::validate_identifier(
            "continuation projection calibration ID",
            &self.calibration_id,
        )?;
        for hash in [
            &self.intent_sha256,
            &self.calibration_plan_sha256,
            &self.authoritative_parameters_sha256,
            &self.calibration_manifest_sha256,
            &self.calibration_bundle_index_sha256,
            &self.compression_profile_sha256,
        ] {
            crate::schema::validate_non_placeholder_sha256("continuation projection hash", hash)?;
        }
        if !self.runtime.admissible || !self.tracked.admissible {
            return Err(Error::new(
                "continuation projection does not admit campaign execution",
            ));
        }
        for requirement in self
            .authoritative_requirements
            .iter()
            .chain(&self.direct_requirements)
        {
            if requirement.match_key.is_empty()
                || requirement.component.is_empty()
                || requirement.future_arms == 0
            {
                return Err(Error::new(
                    "continuation compression requirement is invalid",
                ));
            }
        }
        Ok(())
    }
}

struct CalibrationContext {
    repository: PathBuf,
    root: PathBuf,
    calibration_id: String,
    candidate: String,
    seed: u64,
    builds: BuildSet,
    build_set_sha256: String,
    machine_sha256: String,
    boot_id_sha256: String,
    intent_sha256: String,
    campaign_start_ns: u64,
    journal: Vec<ExecutionJournalRecord>,
    projections: Vec<FileHashBinding>,
}

pub async fn run_calibration(
    repository: &Path,
    candidate: &str,
    seed: u64,
) -> Result<CalibrationOutcome> {
    crate::schema::validate_commit("calibration candidate", candidate)?;
    let calibration_id = calibration_identity(candidate, seed)?;
    let sealed_root = crate::orchestrator::execution_root(repository)
        .join("calibrations")
        .join(&calibration_id);
    if sealed_root.join("seal.json").is_file() {
        return sealed_outcome(repository, &sealed_root);
    }
    let host = crate::orchestrator::run_preflight(repository)?;
    if !host.smoke_ready {
        return Err(Error::new(format!(
            "host cannot run calibration: {}",
            host.blockers.join("; ")
        )));
    }
    let builds = crate::orchestrator::build_exact_pair(repository, candidate)?;
    let mut context = initialize(repository, candidate, seed, &host, builds)?;
    if let Some(outcome) = resume_terminal_if_partial(&mut context)? {
        return Ok(outcome);
    }
    match run_open_calibration(&mut context, host).await {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            let reason = BlockedReason::new(BlockedCode::EvidenceIntegrity, error.to_string());
            finish_calibration(
                &mut context,
                TerminalState::Blocked,
                vec![reason],
                None,
                None,
            )
            .map_err(|finish| {
                Error::new(format!(
                    "calibration failed: {error}; terminal sealing also failed: {finish}"
                ))
            })
        }
    }
}

fn initialize(
    repository: &Path,
    candidate: &str,
    seed: u64,
    host: &crate::linux::HostPreflight,
    builds: BuildSet,
) -> Result<CalibrationContext> {
    let harness_sha256 = sha256_hex(&fs::read(std::env::current_exe()?)?);
    let calibration_id = calibration_identity(candidate, seed)?;
    let root = crate::orchestrator::execution_root(repository)
        .join("calibrations")
        .join(&calibration_id);
    let build_set_bytes = json::canonical_bytes(&builds)?;
    let build_set_sha256 = sha256_hex(&build_set_bytes);
    let host_bytes = json::canonical_bytes(host)?;
    let boot_id = fs::read("/proc/sys/kernel/random/boot_id")?;
    let boot_id_sha256 = sha256_hex(&boot_id);
    let machine = MachineEvidence {
        schema: MACHINE_SCHEMA.to_owned(),
        fingerprint_sha256: sha256_hex(&host_bytes),
        boot_id_sha256: boot_id_sha256.clone(),
        online_cpus: required_host_observation(host, "online_cpus")?.to_owned(),
        clocksource: required_host_observation(host, "clocksource")?.to_owned(),
        clock_ticks_per_second: required_host_observation(host, "clk_tck")?
            .parse::<u64>()
            .context("parse calibration CLK_TCK")?,
        math_abi_sha256: crate::statistics::math_target_sha256(),
    };
    machine.validate()?;
    let machine_bytes = json::canonical_bytes(&machine)?;
    let machine_sha256 = sha256_hex(&machine_bytes);
    let harness_provenance = crate::harness::require_exact_committed_harness(repository)?;
    let intent = Intent {
        schema: COORDINATED_INTENT_SCHEMA.to_owned(),
        evidence_id: calibration_id.clone(),
        evidence_kind: EvidenceKind::Calibration,
        baseline_commit: BASELINE_COMMIT.to_owned(),
        candidate_commit: candidate.to_owned(),
        campaign_seed: seed,
        encoder: crate::codec::current_identity(),
        producer_executable_sha256: harness_sha256,
        zstd: ZstdParameterProgram::fixed(),
        raw_limits: RawLimits::fixed(),
        trust_boundary: Some(TrustBoundaryManifest::coordinated(
            build_set_sha256.clone(),
            BASELINE_COMMIT.to_owned(),
            candidate.to_owned(),
        )?),
        harness_provenance: Some(harness_provenance),
    };
    intent.validate()?;
    let intent_bytes = json::canonical_bytes(&intent)?;
    let intent_sha256 = sha256_hex(&intent_bytes);

    if !root.exists() {
        fs::create_dir_all(
            root.parent()
                .ok_or_else(|| Error::new("calibration root has no parent"))?,
        )?;
        fs::create_dir(&root).context("exclusive-create calibration root")?;
        set_mode(&root, 0o700)?;
        json::write_new_bytes(&root.join("intent.json"), &intent_bytes)?;
        json::write_new_bytes(&root.join("build-set.json"), &build_set_bytes)?;
        json::write_new_bytes(&root.join("machine.json"), &machine_bytes)?;
        fs::create_dir(root.join("state"))?;
        set_mode(&root.join("state"), 0o700)?;
        fs::create_dir(root.join("projections"))?;
        set_mode(&root.join("projections"), 0o700)?;
    } else {
        if root.join("seal.json").exists() {
            return Err(Error::new(
                "calibration identity is already sealed; overwrite/resume is forbidden",
            ));
        }
        require_file_bytes(&root.join("intent.json"), &intent_bytes)?;
        require_file_bytes(&root.join("build-set.json"), &build_set_bytes)?;
        require_file_bytes(&root.join("machine.json"), &machine_bytes)?;
    }

    let mut journal = read_journal(&root)?;
    let campaign_start_ns = if let Some(first) = journal.first() {
        first.boottime_ns
    } else {
        let start = clock_ns(ClockKind::Boottime)?;
        append_journal_record(
            &root,
            &mut journal,
            JournalInput {
                calibration_id: &calibration_id,
                kind: ExecutionJournalKind::CampaignStart,
                phase: ExecutionPhase::Smoke,
                ordinal: None,
                boottime_ns: start,
                boot_id_sha256: &boot_id_sha256,
                machine_sha256: &machine_sha256,
                build_set_sha256: &build_set_sha256,
                plan_sha256: &intent_sha256,
                raw: None,
            },
        )?;
        start
    };
    let projections = read_projection_bindings(&root)?;
    let context = CalibrationContext {
        repository: repository.to_path_buf(),
        root,
        calibration_id,
        candidate: candidate.to_owned(),
        seed,
        builds,
        build_set_sha256,
        machine_sha256,
        boot_id_sha256,
        intent_sha256,
        campaign_start_ns,
        journal,
        projections,
    };
    validate_resume_prefix(&context)?;
    Ok(context)
}

fn calibration_identity(candidate: &str, seed: u64) -> Result<String> {
    crate::schema::validate_commit("calibration candidate", candidate)?;
    let harness_sha256 = sha256_hex(&fs::read(std::env::current_exe()?)?);
    Ok(format!(
        "cal-{}-{}-{seed:016x}",
        &candidate[..12],
        &harness_sha256[..12]
    ))
}

fn required_host_observation<'a>(
    host: &'a crate::linux::HostPreflight,
    name: &str,
) -> Result<&'a str> {
    host.observations
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| Error::new(format!("preflight lacks {name}")))
}

async fn run_open_calibration(
    context: &mut CalibrationContext,
    host: crate::linux::HostPreflight,
) -> Result<CalibrationOutcome> {
    ensure_actual_runtime(context)?;
    let smoke_storage = admit_reached_storage(
        context,
        "before-smoke",
        calibration::PROJECTION_CAP_NS,
        ReachableInventory {
            scout: 0,
            williams: 0,
            direct: 0,
            authoritative: 0,
        },
        &[],
        226,
        Some(0),
    )?;
    require_storage_admission(&smoke_storage)?;
    let smoke_hash = if context.root.join("topology-smoke.json").exists() {
        sha256_file(&context.root.join("topology-smoke.json"))?
    } else {
        append_simple_journal(
            context,
            ExecutionJournalKind::SmokeStart,
            ExecutionPhase::Smoke,
            None,
            &context.intent_sha256.clone(),
            None,
        )?;
        let summary = smoke_into_open_calibration(
            &context.repository,
            &context.candidate,
            host,
            &context.builds,
            &context.root,
            &context.calibration_id,
            context.campaign_start_ns,
        )
        .await?;
        if summary
            .boottime_end_ns
            .saturating_sub(context.campaign_start_ns)
            > crate::orchestrator::SMOKE_CAP_NS
        {
            return Err(Error::new(
                "calibration smoke BOOTTIME exceeded 300 seconds",
            ));
        }
        let smoke_hash = sha256_file(&context.root.join("topology-smoke.json"))?;
        append_simple_journal(
            context,
            ExecutionJournalKind::SmokeComplete,
            ExecutionPhase::Smoke,
            None,
            &context.intent_sha256.clone(),
            Some(("topology-smoke.json".to_owned(), smoke_hash.clone())),
        )?;
        smoke_hash
    };
    let scout_plan = process_plan::scout_plan(context.seed)?;
    let mut next_ordinal = 0_u64;
    let mut accepted_scouts = Vec::with_capacity(15);
    for (cell_index, cell) in all_cells().into_iter().enumerate() {
        let mut attempted_targets = Vec::new();
        let mut arm_ordinals = Vec::new();
        let mut arm_hashes = Vec::new();
        let mut accepted = None;
        for (target_index, target) in calibration::SCOUT_TARGETS.into_iter().enumerate() {
            let (inventory, future, prefixes) = remaining_scout_storage(cell_index, target_index)?;
            let scout_storage = admit_reached_storage(
                context,
                &format!("scout-{}-{target}", cell.id()),
                calibration::PROJECTION_CAP_NS,
                inventory,
                &future,
                8_u64
                    .checked_add(prefixes)
                    .ok_or_else(|| Error::new("scout future unit count overflow"))?,
                Some(0),
            )?;
            require_storage_admission(&scout_storage)?;
            attempted_targets.push(target);
            let panel_template = scout_plan
                .attempts
                .iter()
                .filter(|arm| arm.cell == cell && arm.target == Some(target))
                .cloned()
                .collect::<Vec<_>>();
            if panel_template.len() != 5 {
                return Err(Error::new("scout plan panel is not exactly five arms"));
            }
            let mut panel_records = Vec::with_capacity(5);
            for mut planned in panel_template {
                planned.ordinal = next_ordinal;
                let outcome = run_or_recover_arm(
                    context,
                    &planned,
                    3,
                    None,
                    None,
                    PreMeasureSignaturePolicy::Observe,
                    &scout_plan.hash_sha256,
                )
                .await?;
                let record = outcome
                    .calibration_record
                    .ok_or_else(|| Error::new("scout arm lacks calibration record"))?;
                let parsed = raw_arm_by_ordinal(&context.root, next_ordinal)?;
                require_scout_quality(&parsed)?;
                panel_records.push(record);
                arm_ordinals.push(next_ordinal);
                arm_hashes.push(parsed.raw_sha256);
                next_ordinal += 1;
                ensure_actual_runtime(context)?;
            }
            match calibration::scout_transition(target, &panel_records) {
                ScoutTransition::Accept {
                    target: accepted_target,
                } => {
                    let durations = calibration::derive_scout_durations(&panel_records)?;
                    accepted = Some((accepted_target, durations));
                    break;
                }
                ScoutTransition::Double { .. } => {}
                ScoutTransition::Blocked(reason) => {
                    return finish_calibration(
                        context,
                        TerminalState::Blocked,
                        vec![reason],
                        None,
                        None,
                    );
                }
            }
        }
        let (accepted_target, durations) =
            accepted.ok_or_else(|| Error::new("scout target sequence ended without a decision"))?;
        accepted_scouts.push(AcceptedScoutPanel {
            cell,
            attempted_targets,
            accepted_target,
            arm_ordinals,
            arm_raw_sha256: arm_hashes,
            durations,
        });
    }
    let plan_path = context.root.join("calibration-plan.json");
    let williams_plan = process_plan::calibration_plan_with_offset(context.seed, next_ordinal)?;
    let plan = CalibrationPlanEvidence {
        schema: CALIBRATION_PLAN_SCHEMA.to_owned(),
        calibration_id: context.calibration_id.clone(),
        campaign_seed: context.seed,
        intent: FileHashBinding {
            path: "intent.json".to_owned(),
            sha256: context.intent_sha256.clone(),
        },
        topology_smoke: FileHashBinding {
            path: "topology-smoke.json".to_owned(),
            sha256: smoke_hash,
        },
        scout_plan,
        accepted_scouts,
        williams_plan: williams_plan.clone(),
        first_williams_ordinal: next_ordinal,
        direct_mappings: process_plan::direct_mappings(),
        phase_constants_sha256: calibration::phase_constants_sha256(),
    };
    plan.validate()?;
    write_or_require_canonical(&plan_path, &plan)?;
    let plan_sha256 = sha256_file(&plan_path)?;
    let williams_storage = williams_storage_inputs(&plan, &parse_raw_arms(&context.root)?)?;
    let williams_admission = admit_reached_storage(
        context,
        "before-williams",
        calibration::PROJECTION_CAP_NS,
        ReachableInventory {
            scout: 0,
            williams: 750,
            direct: 0,
            authoritative: 0,
        },
        &williams_storage,
        9,
        Some(0),
    )?;
    require_storage_admission(&williams_admission)?;

    let calibration_durations = plan
        .calibration_durations()
        .into_iter()
        .map(|entry| (entry.cell, entry.durations))
        .collect::<BTreeMap<_, _>>();
    let establishment = williams_plan
        .establishment_ordinals
        .iter()
        .map(|entry| ((entry.cell, entry.arm), entry.ordinal))
        .collect::<BTreeMap<_, _>>();
    for planned in &williams_plan.arms {
        let accepted_path = treatment_signature_path(&context.root, planned.cell, planned.arm)?;
        let signature_policy = if establishment
            .get(&(planned.cell, planned.arm.unwrap_or(Arm::B11)))
            == Some(&planned.ordinal)
        {
            PreMeasureSignaturePolicy::Establish {
                accepted_record: &accepted_path,
            }
        } else {
            PreMeasureSignaturePolicy::Require {
                accepted_record: &accepted_path,
            }
        };
        let durations = calibration_durations
            .get(&planned.cell)
            .copied()
            .ok_or_else(|| Error::new("Williams arm lacks frozen cell durations"))?;
        run_or_recover_arm(
            context,
            planned,
            durations.warmup_seconds,
            Some(durations.measure_seconds),
            Some(&plan_sha256),
            signature_policy,
            &plan_sha256,
        )
        .await?;
        require_fixed_quality(&raw_arm_by_ordinal(&context.root, planned.ordinal)?)?;
        next_ordinal = planned.ordinal + 1;
        ensure_actual_runtime(context)?;
    }
    let arms = parse_raw_arms(&context.root)?;
    quarantine_incomplete_signatures(context, &arms)?;
    let variances = derive_variances(&arms)?;
    let authoritative_durations = derive_authoritative_durations(&arms)?;
    let treatment_signatures = read_signature_bindings(&context.root, false)?;
    let selection = calibration::select_authoritative_n(&variances)?;
    let elapsed = campaign_elapsed(context)?;
    let lower_bound_runtime_ns = elapsed.max(calibration::PRE_FREEZE_FLOOR_NS);
    let (selected_n, mut disposition, mut direct_plan, mut parameter_reason) = match selection {
        NSelection::Admissible { n } => (
            Some(n),
            ParameterDisposition::Admitted,
            williams_plan.direct_epoch_zero.clone(),
            None,
        ),
        NSelection::RuntimeBlocked { selected_n, reason } => (
            Some(selected_n),
            ParameterDisposition::RuntimeBlocked,
            Vec::new(),
            Some(reason),
        ),
        NSelection::PrecisionBlocked { reason } => (
            None,
            ParameterDisposition::PrecisionBlocked,
            Vec::new(),
            Some(reason),
        ),
    };

    let mut runtime_projection = None;
    if let Some(n @ (30 | 50)) = selected_n {
        let direct_cap = direct_plan.iter().try_fold(0_u64, |total, arm| {
            let duration = authoritative_durations
                .iter()
                .find(|entry| entry.cell == arm.cell)
                .ok_or_else(|| Error::new("direct runtime screen lacks cell durations"))?;
            total
                .checked_add(calibration::arm_cap_ns(arm.cell, duration.durations)?)
                .ok_or_else(|| Error::new("calibration-direct cap subtotal overflow"))
        })?;
        let projected_e_pre = elapsed
            .checked_add(direct_cap)
            .ok_or_else(|| Error::new("pre-direct runtime screen overflow"))?;
        let projected = calibration::project_runtime(
            n,
            projected_e_pre,
            q_extra_ns(&arms)?,
            &authoritative_durations,
        )?;
        if !projected.admissible {
            disposition = ParameterDisposition::RuntimeBlocked;
            direct_plan.clear();
            parameter_reason = Some(BlockedReason::new(
                BlockedCode::RuntimeProjection,
                format!(
                    "selected N={n} exact pre-direct screen projects {}ns",
                    projected.projected_total_ns
                ),
            ));
        }
        runtime_projection = Some(projected);

        if disposition == ParameterDisposition::Admitted {
            let direct_storage = direct_storage_inputs(&direct_plan, &authoritative_durations)?;
            let admission = admit_reached_storage(
                context,
                "before-d0",
                calibration::PROJECTION_CAP_NS,
                ReachableInventory {
                    scout: 0,
                    williams: 0,
                    direct: 30,
                    authoritative: 0,
                },
                &direct_storage,
                8,
                Some(0),
            )?;
            if !admission.admissible {
                disposition = ParameterDisposition::StorageBlocked;
                direct_plan.clear();
                parameter_reason = Some(BlockedReason::new(
                    BlockedCode::StorageProjection,
                    format!(
                        "pre-direct raw coexistence requires >{} bytes with {} observed",
                        admission.raw.required_free_bytes_exclusive,
                        admission.raw.observed_free_bytes
                    ),
                ));
            }
        }
    }

    let parameters = AuthoritativeParameters {
        schema: AUTHORITATIVE_PARAMETERS_SCHEMA.to_owned(),
        calibration_id: context.calibration_id.clone(),
        intent: FileHashBinding {
            path: "intent.json".to_owned(),
            sha256: context.intent_sha256.clone(),
        },
        calibration_plan: FileHashBinding {
            path: "calibration-plan.json".to_owned(),
            sha256: plan_sha256.clone(),
        },
        accepted_treatment_signatures: treatment_signatures,
        variances,
        authoritative_durations: authoritative_durations.clone(),
        selected_n,
        disposition,
        direct_plan: direct_plan.clone(),
        lower_bound_runtime_ns,
        terminal_reason: parameter_reason.clone(),
    };
    parameters.validate()?;
    write_or_require_canonical(
        &context.root.join("authoritative-parameters.json"),
        &parameters,
    )?;

    if disposition != ParameterDisposition::Admitted {
        let reason =
            parameter_reason.ok_or_else(|| Error::new("blocked parameters lack reason"))?;
        return finish_calibration(
            context,
            TerminalState::Blocked,
            vec![reason],
            selected_n,
            runtime_projection,
        );
    }
    let n = selected_n.ok_or_else(|| Error::new("admitted parameters lack N"))?;
    let auth_by_cell = authoritative_durations
        .iter()
        .map(|entry| (entry.cell, entry.durations))
        .collect::<BTreeMap<_, _>>();
    for planned in &direct_plan {
        let accepted_path = direct_signature_path(
            &context.root,
            planned.cell,
            planned
                .direct_protocol
                .ok_or_else(|| Error::new("direct plan lacks protocol"))?,
        );
        let durations = auth_by_cell
            .get(&planned.cell)
            .copied()
            .ok_or_else(|| Error::new("direct arm lacks authoritative durations"))?;
        run_or_recover_arm(
            context,
            planned,
            durations.warmup_seconds,
            Some(durations.measure_seconds),
            Some(&plan_sha256),
            PreMeasureSignaturePolicy::Establish {
                accepted_record: &accepted_path,
            },
            &plan_sha256,
        )
        .await?;
        require_fixed_quality(&raw_arm_by_ordinal(&context.root, planned.ordinal)?)?;
        next_ordinal = planned.ordinal + 1;
        ensure_actual_runtime(context)?;
    }
    let arms = parse_raw_arms(&context.root)?;
    enforce_direct_headroom(&arms)?;
    let exact_runtime = calibration::project_runtime(
        n,
        campaign_elapsed(context)?,
        q_extra_ns(&arms)?,
        &authoritative_durations,
    )?;
    if !exact_runtime.admissible {
        return finish_calibration(
            context,
            TerminalState::Blocked,
            vec![BlockedReason::new(
                BlockedCode::RuntimeProjection,
                format!(
                    "post-direct selected N={n} projection is {}ns",
                    exact_runtime.projected_total_ns
                ),
            )],
            Some(n),
            Some(exact_runtime),
        );
    }
    let preseal_tracked = preseal_continuation_storage(context, n)?;
    if !preseal_tracked.admissible {
        return finish_calibration(
            context,
            TerminalState::Blocked,
            vec![BlockedReason::new(
                BlockedCode::StorageProjection,
                format!(
                    "preseal 2x exact-component continuation projects {} bytes",
                    preseal_tracked.projected_total_bytes
                ),
            )],
            Some(n),
            Some(exact_runtime),
        );
    }
    let _ = next_ordinal;
    finish_calibration(
        context,
        TerminalState::Pass,
        Vec::new(),
        Some(n),
        Some(exact_runtime),
    )
}

async fn run_or_recover_arm(
    context: &mut CalibrationContext,
    planned: &PlannedArm,
    warmup_seconds: u64,
    measure_seconds: Option<u64>,
    calibration_plan_sha256: Option<&str>,
    signature_policy: PreMeasureSignaturePolicy<'_>,
    journal_plan_sha256: &str,
) -> Result<ProcessArmOutcome> {
    let existing = parse_raw_arms(&context.root)?;
    if planned.ordinal < existing.len() as u64 {
        let parsed = existing
            .get(usize::try_from(planned.ordinal).map_err(|_| Error::new("ordinal overflow"))?)
            .ok_or_else(|| Error::new("resume raw prefix lookup failed"))?;
        ensure_planned_matches_raw(planned, parsed)?;
        if partially_started_ordinal(&context.journal) == Some(planned.ordinal) {
            let start = context
                .journal
                .last()
                .ok_or_else(|| Error::new("published raw recovery lacks arm-start journal"))?;
            if start.phase != phase_for_class(planned.evidence_class)
                || start.plan_sha256 != journal_plan_sha256
            {
                return Err(Error::new(
                    "published raw recovery differs from its arm-start journal",
                ));
            }
            let raw_path = parsed
                .leaf
                .strip_prefix(&context.root)
                .map_err(|_| Error::new("recovered raw leaf escaped calibration root"))?
                .to_string_lossy()
                .into_owned();
            append_simple_journal(
                context,
                ExecutionJournalKind::ArmComplete,
                phase_for_class(planned.evidence_class),
                Some(planned.ordinal),
                journal_plan_sha256,
                Some((raw_path, parsed.raw_sha256.clone())),
            )?;
        }
        return outcome_from_parsed(parsed);
    }
    if planned.ordinal != existing.len() as u64 {
        return Err(Error::new(
            "next process arm is not the exact raw prefix ordinal",
        ));
    }
    if partially_started_ordinal(&context.journal) == Some(planned.ordinal) {
        crate::orchestrator::retain_interrupted_process_arm(
            &context.repository,
            &context.root,
            &context.calibration_id,
            &context.calibration_id,
            planned,
        )?;
        return Err(Error::new(format!(
            "arm ordinal {} was partially started and cannot resume",
            planned.ordinal
        )));
    }
    append_simple_journal(
        context,
        ExecutionJournalKind::ArmStart,
        phase_for_class(planned.evidence_class),
        Some(planned.ordinal),
        journal_plan_sha256,
        None,
    )?;
    let outcome = execute_process_arm(
        &context.repository,
        &context.builds,
        &context.root,
        ProcessArmRequest {
            evidence_id: &context.calibration_id,
            run_id: &context.calibration_id,
            planned,
            raw_ordinal: planned.ordinal,
            warmup_seconds,
            measure_seconds,
            calibration_plan_sha256,
            signature_policy,
            trust_boundary: coordinated_trust_boundary(&context.root)?,
            frequency_gate: crate::orchestrator::FrequencyGate::CalibrationAbsolute,
        },
    )
    .await?;
    let parsed = raw_arm_by_ordinal(&context.root, planned.ordinal)?;
    ensure_planned_matches_raw(planned, &parsed)?;
    let raw_path = parsed
        .leaf
        .strip_prefix(&context.root)
        .map_err(|_| Error::new("completed raw leaf escaped calibration root"))?
        .to_string_lossy()
        .into_owned();
    append_simple_journal(
        context,
        ExecutionJournalKind::ArmComplete,
        phase_for_class(planned.evidence_class),
        Some(planned.ordinal),
        journal_plan_sha256,
        Some((raw_path, parsed.raw_sha256)),
    )?;
    Ok(outcome)
}

fn coordinated_trust_boundary(root: &Path) -> Result<TrustBoundaryManifest> {
    let intent: Intent =
        json::read_strict(&root.join("intent.json"), crate::schema::JSON_MAX_BYTES)?;
    intent.validate()?;
    intent
        .trust_boundary
        .ok_or_else(|| Error::new("coordinated calibration intent lacks trust-boundary manifest"))
}

pub(crate) fn derive_frequency_p05_khz(arms: &[ParsedArm]) -> Result<u64> {
    let mut frequencies = arms
        .iter()
        .filter(|arm| arm.metadata.class == EvidenceClass::C)
        .map(|arm| arm.resources.median_frequency_khz)
        .collect::<Vec<_>>();
    if frequencies.is_empty() || frequencies.iter().any(|frequency| *frequency < 4_000_000) {
        return Err(Error::new(
            "calibration frequency envelope is empty or below the absolute preflight floor",
        ));
    }
    frequencies.sort_unstable();
    let rank = frequencies
        .len()
        .checked_mul(5)
        .and_then(|value| value.checked_add(99))
        .ok_or_else(|| Error::new("calibration frequency percentile rank overflow"))?
        / 100;
    frequencies
        .get(rank.saturating_sub(1))
        .copied()
        .ok_or_else(|| Error::new("calibration frequency percentile is missing"))
}

fn phase_for_class(class: EvidenceClass) -> ExecutionPhase {
    match class {
        EvidenceClass::S => ExecutionPhase::Scout,
        EvidenceClass::C => ExecutionPhase::Williams,
        EvidenceClass::D => ExecutionPhase::CalibrationDirect,
        EvidenceClass::A => ExecutionPhase::Authoritative,
    }
}

pub(crate) fn ensure_planned_matches_raw(planned: &PlannedArm, raw: &ParsedArm) -> Result<()> {
    let metadata = &raw.metadata;
    let expected_round = (planned.evidence_class == EvidenceClass::A)
        .then_some(planned.round)
        .flatten();
    let expected_row = matches!(planned.evidence_class, EvidenceClass::C | EvidenceClass::A)
        .then_some(planned.row)
        .flatten();
    let expected_position = expected_row.and_then(|row| {
        crate::schedule::williams_rows()[usize::from(row)]
            .iter()
            .position(|arm| Some(*arm) == planned.arm)
            .and_then(|position| u8::try_from(position).ok())
    });
    let expected_epoch = (planned.evidence_class == EvidenceClass::D)
        .then_some(planned.round)
        .flatten();
    if metadata.ordinal != planned.ordinal
        || metadata.class != planned.evidence_class
        || metadata.cell != planned.cell
        || metadata.arm != planned.arm
        || metadata.direct_protocol != planned.direct_protocol.map(raw_protocol)
        || metadata.scout_target != planned.target
        || metadata.round != expected_round
        || metadata.row != expected_row
        || metadata.position != expected_position
        || metadata.epoch != expected_epoch
        || raw.operation.lane_quotas != planned.lane_quotas
    {
        return Err(Error::new(
            "raw prefix arm differs from its deterministic plan",
        ));
    }
    Ok(())
}

fn outcome_from_parsed(parsed: &ParsedArm) -> Result<ProcessArmOutcome> {
    Ok(ProcessArmOutcome {
        metadata: parsed.metadata.clone(),
        calibration_record: Some(calibration_record_from_raw(parsed)?),
        raw_leaf: parsed.leaf.to_string_lossy().into_owned(),
        thread_signature_sha256: parsed.thread_map.signature_sha256.clone(),
        lifecycle: Vec::new(),
        quality_blockers: Vec::new(),
    })
}

pub(crate) fn calibration_record_from_raw(arm: &ParsedArm) -> Result<CalibrationRecord> {
    let phase = match arm.metadata.class {
        EvidenceClass::S => CalibrationPhase::Scout,
        EvidenceClass::C => CalibrationPhase::Williams,
        EvidenceClass::D => CalibrationPhase::Direct,
        EvidenceClass::A => return Err(Error::new("class A is not calibration evidence")),
    };
    let record = CalibrationRecord {
        schema: crate::schema::EXECUTION_SCHEMA.to_owned(),
        calibration_id: arm.metadata.evidence_id.clone(),
        phase,
        class: arm.metadata.class,
        cell: arm.metadata.cell,
        arm: arm.metadata.arm,
        target: arm.metadata.scout_target,
        elapsed_ns: arm
            .operation
            .deadline_ns
            .checked_sub(arm.operation.window_start_ns)
            .ok_or_else(|| Error::new("calibration raw elapsed underflow"))?,
        gateway_ticks: arm
            .resources
            .gateway_ticks_drain
            .checked_sub(arm.resources.gateway_ticks_start)
            .ok_or_else(|| Error::new("calibration raw gateway ticks underflow"))?,
        started_operations: arm.operation.started_operations,
        deadline_completions: arm.operation.deadline_completions,
        drained_operations: arm.operation.drained_operations,
        lane_quotas: arm.operation.lane_quotas.clone(),
        lane_completions: arm.operation.lane_completions.clone(),
        endpoint_hashes_match: arm.endpoints.load_operation_hash_sha256
            == arm.endpoints.fixture_operation_hash_sha256,
        process_identity: arm.metadata.observation_id.clone(),
    };
    record.validate()?;
    Ok(record)
}

fn require_scout_quality(arm: &ParsedArm) -> Result<()> {
    if arm.semantic_class() != SemanticClass::Ok
        || !arm.quiet.clean()
        || !arm.resources.clean()
        || !arm.session_clock.comparable
    {
        return Err(Error::new(format!(
            "scout {} failed non-retryable semantic/noise quality",
            arm.metadata.observation_id
        )));
    }
    Ok(())
}

fn require_fixed_quality(arm: &ParsedArm) -> Result<()> {
    if !arm.quality_clean() {
        return Err(Error::new(format!(
            "fixed-duration arm {} failed integrity/noise/count quality: {}",
            arm.metadata.observation_id,
            arm.measurement_violations().join(", ")
        )));
    }
    Ok(())
}

pub(crate) fn derive_authoritative_durations(arms: &[ParsedArm]) -> Result<Vec<CellDurations>> {
    all_cells()
        .into_iter()
        .map(|cell| {
            let observations = arms
                .iter()
                .filter(|arm| arm.metadata.class == EvidenceClass::C && arm.metadata.cell == cell)
                .map(|arm| {
                    Ok((
                        arm.operation.deadline_completions,
                        arm.operation
                            .deadline_ns
                            .checked_sub(arm.operation.window_start_ns)
                            .ok_or_else(|| Error::new("Williams elapsed underflow"))?,
                        arm.resources
                            .gateway_ticks_drain
                            .checked_sub(arm.resources.gateway_ticks_start)
                            .ok_or_else(|| Error::new("Williams tick underflow"))?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            if observations.len() != 50 {
                return Err(Error::new("cell lacks exactly 50 Williams arms"));
            }
            Ok(CellDurations {
                cell,
                durations: calibration::derive_durations(&observations)?,
            })
        })
        .collect()
}

pub(crate) fn derive_variances(arms: &[ParsedArm]) -> Result<Vec<VarianceEstimate>> {
    let mut lookup = BTreeMap::new();
    for arm in arms
        .iter()
        .filter(|arm| arm.metadata.class == EvidenceClass::C)
    {
        let row = arm
            .metadata
            .row
            .ok_or_else(|| Error::new("Williams raw arm lacks row"))?;
        let treatment = arm
            .metadata
            .arm
            .ok_or_else(|| Error::new("Williams raw arm lacks treatment"))?;
        if lookup
            .insert((row, arm.metadata.cell, treatment), arm)
            .is_some()
        {
            return Err(Error::new("duplicate Williams row/cell/treatment"));
        }
    }
    let mut estimates = Vec::with_capacity(180);
    for comparison in hard_comparisons() {
        let mut pairs = Vec::with_capacity(10);
        for row in 0_u8..10 {
            let treatment = lookup
                .get(&(row, comparison.cell, comparison.treatment))
                .ok_or_else(|| Error::new("Williams treatment observation missing"))?;
            let reference = lookup
                .get(&(row, comparison.cell, comparison.reference))
                .ok_or_else(|| Error::new("Williams reference observation missing"))?;
            pairs.push(PairedMetrics {
                treatment: treatment.metrics()?,
                reference: reference.metrics()?,
                treatment_before_reference: treatment.metadata.position
                    < reference.metadata.position,
            });
        }
        for metric in Metric::ALL {
            estimates.push(calibration::variance_from_calibration(
                comparison.id.clone(),
                metric,
                &pairs,
            )?);
        }
    }
    Ok(estimates)
}

pub(crate) fn enforce_direct_headroom(arms: &[ParsedArm]) -> Result<()> {
    let direct = arms
        .iter()
        .filter(|arm| arm.metadata.class == EvidenceClass::D)
        .map(|arm| {
            (
                (
                    arm.metadata.cell,
                    arm.metadata.direct_protocol.unwrap_or(RawProtocol::H1),
                ),
                arm,
            )
        })
        .collect::<BTreeMap<_, _>>();
    if direct.len() != 30 {
        return Err(Error::new(
            "calibration direct panel is not exactly 30 arms",
        ));
    }
    for gateway in arms
        .iter()
        .filter(|arm| matches!(arm.metadata.class, EvidenceClass::S | EvidenceClass::C))
    {
        let treatment = gateway
            .metadata
            .arm
            .ok_or_else(|| Error::new("gateway calibration arm lacks treatment"))?;
        for protocol in ArmTopology::for_arm(treatment).direct_protocols() {
            let protocol = raw_protocol(protocol);
            let ceiling = direct
                .get(&(gateway.metadata.cell, protocol))
                .ok_or_else(|| Error::new("mapped calibration direct ceiling is missing"))?;
            if !rate_has_headroom(ceiling, gateway)? {
                return Err(Error::new(format!(
                    "direct {:?} {} lacks 1.25x headroom for {}",
                    protocol,
                    gateway.metadata.cell.id(),
                    gateway.metadata.observation_id
                )));
            }
        }
    }
    Ok(())
}

fn rate_has_headroom(direct: &ParsedArm, gateway: &ParsedArm) -> Result<bool> {
    let direct_elapsed = direct
        .operation
        .deadline_ns
        .checked_sub(direct.operation.window_start_ns)
        .ok_or_else(|| Error::new("direct elapsed underflow"))?;
    let gateway_elapsed = gateway
        .operation
        .deadline_ns
        .checked_sub(gateway.operation.window_start_ns)
        .ok_or_else(|| Error::new("gateway elapsed underflow"))?;
    rate_values_have_headroom(
        direct.operation.deadline_completions,
        direct_elapsed,
        gateway.operation.deadline_completions,
        gateway_elapsed,
    )
}

fn rate_values_have_headroom(
    direct_operations: u64,
    direct_elapsed_ns: u64,
    gateway_operations: u64,
    gateway_elapsed_ns: u64,
) -> Result<bool> {
    if direct_elapsed_ns == 0 || gateway_elapsed_ns == 0 {
        return Err(Error::new("direct headroom elapsed time is zero"));
    }
    let left = u128::from(direct_operations)
        .checked_mul(u128::from(gateway_elapsed_ns))
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| Error::new("direct headroom numerator overflow"))?;
    let right = u128::from(gateway_operations)
        .checked_mul(u128::from(direct_elapsed_ns))
        .and_then(|value| value.checked_mul(5))
        .ok_or_else(|| Error::new("direct headroom threshold overflow"))?;
    Ok(left >= right)
}

#[cfg(test)]
mod tests {
    use super::rate_values_have_headroom;

    #[test]
    fn direct_headroom_compares_rates_not_raw_counts() {
        assert!(rate_values_have_headroom(125, 2, 100, 2).expect("equal windows"));
        assert!(!rate_values_have_headroom(125, 4, 100, 2).expect("slower direct window"));
        assert!(rate_values_have_headroom(250, 4, 100, 2).expect("equal rates"));
        assert!(rate_values_have_headroom(1, 0, 1, 1).is_err());
    }
}

const STORAGE_ENCODER_WORKSPACE_BYTES: u64 = 8 * MIB;
const STORAGE_UNIT_MEMBER_MAX_BYTES: u64 = MIB;

fn admit_reached_storage(
    context: &mut CalibrationContext,
    gate_id: &str,
    runtime_projected_ns: u64,
    inventory: ReachableInventory,
    future_arms: &[ArmStorageInput],
    future_unit_members: u64,
    tracked_remaining_maximum_bytes: Option<u64>,
) -> Result<ReachedBranchProjection> {
    for binding in &context.projections {
        let projection: ProjectionEvidence = json::read_strict(
            &context.root.join(&binding.path),
            crate::schema::JSON_MAX_BYTES,
        )?;
        if let Some(admission) = projection.storage_admission {
            if admission.gate_id == gate_id {
                admission.validate()?;
                return Ok(admission);
            }
        }
    }
    let completed_member_lengths = regular_member_lengths(&context.root)?;
    let future_unit_count = usize::try_from(future_unit_members)
        .map_err(|_| Error::new("future unit member count exceeds usize"))?;
    let future_unit_lengths = vec![STORAGE_UNIT_MEMBER_MAX_BYTES; future_unit_count];
    let tracked_actual =
        storage::actual_regular_bytes_if_exists(&artifact_root(&context.repository))?;
    let next_ordinal = u64::try_from(parse_raw_arms(&context.root)?.len())
        .map_err(|_| Error::new("storage admission raw prefix exceeds u64"))?;
    let mut admission = storage::reached_branch_projection(ReachedBranchInput {
        gate_id,
        next_ordinal,
        inventory,
        completed_member_lengths: &completed_member_lengths,
        future_arms,
        future_unit_member_lengths: &future_unit_lengths,
        encoder_workspace_bytes: STORAGE_ENCODER_WORKSPACE_BYTES,
        observed_free_bytes: filesystem_free_bytes(&context.repository)?,
        tracked_actual_bytes: tracked_actual,
        tracked_remaining_maximum_bytes: tracked_remaining_maximum_bytes.unwrap_or(0),
    })?;
    if tracked_remaining_maximum_bytes.is_none() {
        let delivery_maximum = admission
            .compressed_bound_bytes
            .checked_add(5 * MIB)
            .ok_or_else(|| Error::new("final delivery tracked bound overflow"))?;
        admission = storage::reached_branch_projection(ReachedBranchInput {
            gate_id,
            next_ordinal,
            inventory,
            completed_member_lengths: &completed_member_lengths,
            future_arms,
            future_unit_member_lengths: &future_unit_lengths,
            encoder_workspace_bytes: STORAGE_ENCODER_WORKSPACE_BYTES,
            observed_free_bytes: filesystem_free_bytes(&context.repository)?,
            tracked_actual_bytes: tracked_actual,
            tracked_remaining_maximum_bytes: delivery_maximum,
        })?;
    }
    write_projection_revision(context, runtime_projected_ns, Some(admission.clone()))?;
    Ok(admission)
}

fn require_storage_admission(admission: &ReachedBranchProjection) -> Result<()> {
    if admission.admissible {
        Ok(())
    } else {
        Err(Error::new(format!(
            "storage gate {} requires >{} free bytes (observed {}) or exceeds 512 MiB",
            admission.gate_id,
            admission.raw.required_free_bytes_exclusive,
            admission.raw.observed_free_bytes
        )))
    }
}

fn regular_member_lengths(root: &Path) -> Result<Vec<u64>> {
    fn collect(directory: &Path, output: &mut Vec<u64>) -> Result<()> {
        let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_dir() {
                collect(&path, output)?;
            } else if metadata.file_type().is_file() {
                output.push(metadata.len());
            } else {
                return Err(Error::new(
                    "storage admission source contains a link or special file",
                ));
            }
        }
        Ok(())
    }
    let mut lengths = Vec::new();
    collect(root, &mut lengths)?;
    Ok(lengths)
}

fn storage_arm(
    class: EvidenceClass,
    cell: crate::schema::Cell,
    duration_ns: u64,
    latency_records: u64,
) -> ArmStorageInput {
    ArmStorageInput {
        class,
        gateway: class != EvidenceClass::D,
        duration_ns,
        tid_slots: 32,
        lifecycle_events: 4_096,
        connection_records: 136 + u64::from(cell.concurrency),
        latency_records,
        concurrency: u64::from(cell.concurrency),
    }
}

fn remaining_scout_storage(
    cell_index: usize,
    target_index: usize,
) -> Result<(ReachableInventory, Vec<ArmStorageInput>, u64)> {
    let cells = all_cells();
    let mut arms = Vec::new();
    let mut prefixes = 0_u64;
    for (index, cell) in cells.into_iter().enumerate().skip(cell_index) {
        let first_target = if index == cell_index { target_index } else { 0 };
        for _ in calibration::SCOUT_TARGETS.iter().skip(first_target) {
            prefixes = prefixes
                .checked_add(1)
                .ok_or_else(|| Error::new("scout storage prefix count overflow"))?;
            for _ in Arm::ALL {
                arms.push(storage_arm(
                    EvidenceClass::S,
                    cell,
                    calibration::arm_cap_ns(
                        cell,
                        FrozenDurations {
                            warmup_seconds: 3,
                            measure_seconds: 15,
                        },
                    )?,
                    0,
                ));
            }
        }
    }
    let scout = u64::try_from(arms.len()).map_err(|_| Error::new("scout inventory exceeds u64"))?;
    Ok((
        ReachableInventory {
            scout,
            williams: 0,
            direct: 0,
            authoritative: 0,
        },
        arms,
        prefixes,
    ))
}

fn williams_storage_inputs(
    plan: &CalibrationPlanEvidence,
    source_arms: &[ParsedArm],
) -> Result<Vec<ArmStorageInput>> {
    let duration_by_cell = plan
        .calibration_durations()
        .into_iter()
        .map(|entry| (entry.cell, entry.durations))
        .collect::<BTreeMap<_, _>>();
    let accepted_ordinals = plan
        .accepted_scouts
        .iter()
        .flat_map(|panel| panel.arm_ordinals.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut inputs = Vec::with_capacity(plan.williams_plan.arms.len());
    for planned in &plan.williams_plan.arms {
        let treatment = planned
            .arm
            .ok_or_else(|| Error::new("Williams storage arm lacks treatment"))?;
        let scout = source_arms
            .iter()
            .find(|arm| {
                accepted_ordinals.contains(&arm.metadata.ordinal)
                    && arm.metadata.cell == planned.cell
                    && arm.metadata.arm == Some(treatment)
            })
            .ok_or_else(|| Error::new("Williams storage lacks its accepted scout witness"))?;
        let elapsed_ns = scout
            .operation
            .deadline_ns
            .checked_sub(scout.operation.window_start_ns)
            .ok_or_else(|| Error::new("accepted scout elapsed time underflow"))?;
        let durations = *duration_by_cell
            .get(&planned.cell)
            .ok_or_else(|| Error::new("Williams storage lacks cell durations"))?;
        let latency_window_ns = durations
            .measure_seconds
            .checked_add(2)
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or_else(|| Error::new("LAT_C window overflow"))?;
        let numerator = u128::from(scout.operation.started_operations)
            .checked_mul(4)
            .and_then(|value| value.checked_mul(u128::from(latency_window_ns)))
            .ok_or_else(|| Error::new("LAT_C projection overflow"))?;
        let projected = ceil_div_u128(numerator, u128::from(elapsed_ns))?;
        let latency_records = u64::from(planned.cell.concurrency)
            .checked_add(u64::try_from(projected).map_err(|_| Error::new("LAT_C exceeds u64"))?)
            .ok_or_else(|| Error::new("LAT_C ceiling overflow"))?;
        inputs.push(storage_arm(
            EvidenceClass::C,
            planned.cell,
            calibration::arm_cap_ns(planned.cell, durations)?,
            latency_records,
        ));
    }
    Ok(inputs)
}

fn direct_storage_inputs(
    direct: &[PlannedArm],
    durations: &[CellDurations],
) -> Result<Vec<ArmStorageInput>> {
    let by_cell = durations
        .iter()
        .map(|entry| (entry.cell, entry.durations))
        .collect::<BTreeMap<_, _>>();
    direct
        .iter()
        .map(|arm| {
            let duration = calibration::arm_cap_ns(
                arm.cell,
                *by_cell
                    .get(&arm.cell)
                    .ok_or_else(|| Error::new("D0 storage lacks cell durations"))?,
            )?;
            Ok(storage_arm(EvidenceClass::D, arm.cell, duration, 0))
        })
        .collect()
}

fn latest_storage_admission(context: &CalibrationContext) -> Result<ReachedBranchProjection> {
    for binding in context.projections.iter().rev() {
        let projection: ProjectionEvidence = json::read_strict(
            &context.root.join(&binding.path),
            crate::schema::JSON_MAX_BYTES,
        )?;
        if let Some(admission) = projection.storage_admission {
            return Ok(admission);
        }
    }
    Err(Error::new(
        "calibration lacks a reached-branch storage admission",
    ))
}

fn finish_calibration(
    context: &mut CalibrationContext,
    requested_terminal: TerminalState,
    reasons: Vec<BlockedReason>,
    selected_n: Option<u32>,
    runtime_projection: Option<calibration::RuntimeProjection>,
) -> Result<CalibrationOutcome> {
    if context.root.join("seal.json").exists() {
        return sealed_outcome(&context.repository, &context.root);
    }
    let arms = parse_raw_arms(&context.root)?;
    quarantine_incomplete_signatures(context, &arms)?;
    let completed_arms =
        u64::try_from(arms.len()).map_err(|_| Error::new("calibration arm count exceeds u64"))?;
    let partial = partially_started_ordinal(&context.journal);
    let terminal_state = if requested_terminal == TerminalState::Pass && partial.is_none() {
        TerminalState::Pass
    } else {
        TerminalState::Blocked
    };
    let mut reason_text = reasons
        .iter()
        .map(|reason| format!("{:?}: {}", reason.code, reason.detail))
        .collect::<Vec<_>>();
    if let Some(ordinal) = partial {
        reason_text.push(format!(
            "arm ordinal {ordinal} started without a durable completion; resume forbidden"
        ));
    }
    reason_text.sort();
    reason_text.dedup();
    let final_admission = admit_reached_storage(
        context,
        "final-delivery",
        runtime_projection
            .as_ref()
            .map_or(calibration::PROJECTION_CAP_NS, |value| {
                value.projected_total_ns
            }),
        ReachableInventory {
            scout: 0,
            williams: 0,
            direct: 0,
            authoritative: 0,
        },
        &[],
        7,
        None,
    )?;
    require_storage_admission(&final_admission)?;
    let campaign_end_ns = clock_ns(ClockKind::Boottime)?;
    let journal_root = execution_journal_root(&context.journal)?;
    let state = ExecutionStateEvidence {
        schema: EXECUTION_STATE_SCHEMA.to_owned(),
        evidence_id: context.calibration_id.clone(),
        phase: ExecutionPhase::Complete,
        next_ordinal: completed_arms,
        planned_arms: completed_arms,
        completed_arms,
        complete: true,
        crash_detail: (terminal_state != TerminalState::Pass).then(|| reason_text.join("; ")),
        campaign_boottime_start_ns: Some(context.campaign_start_ns),
        campaign_boottime_end_ns: Some(campaign_end_ns),
        machine_sha256: Some(context.machine_sha256.clone()),
        build_set_sha256: Some(context.build_set_sha256.clone()),
        journal_root_sha256: Some(journal_root),
        partially_started_ordinal: partial,
    };
    state.validate()?;
    json::write_new_canonical(&context.root.join("execution-state.json"), &state)?;
    let state_sha256 = sha256_file(&context.root.join("execution-state.json"))?;

    let runtime_projected_ns = runtime_projection.as_ref().map_or(
        campaign_end_ns.saturating_sub(context.campaign_start_ns),
        |value| value.projected_total_ns,
    );
    let final_storage = latest_storage_admission(context)?;
    write_projection_revision(context, runtime_projected_ns, Some(final_storage.clone()))?;
    let projection = build_projection(
        context,
        u32::try_from(context.projections.len()).unwrap_or(u32::MAX),
        context.projections.last().cloned(),
        runtime_projected_ns,
        Some(final_storage.clone()),
    )?;
    json::write_new_canonical(&context.root.join("projection.json"), &projection)?;
    let projection_binding = FileHashBinding {
        path: "projection.json".to_owned(),
        sha256: sha256_file(&context.root.join("projection.json"))?,
    };
    let delivery_projection = build_projection(
        context,
        projection.revision + 1,
        Some(projection_binding),
        runtime_projected_ns,
        Some(final_storage),
    )?;
    json::write_new_canonical(
        &context.root.join("delivery-projection.json"),
        &delivery_projection,
    )?;
    let delivery_projection_sha256 = sha256_file(&context.root.join("delivery-projection.json"))?;

    let plan_sha256 = optional_sha256(&context.root.join("calibration-plan.json"))?;
    let parameters_sha256 = optional_sha256(&context.root.join("authoritative-parameters.json"))?;
    let signature_bindings = read_signature_bindings(&context.root, true)?;
    let records = arms
        .iter()
        .map(calibration_record_from_raw)
        .collect::<Result<Vec<_>>>()?;
    let arm_bindings = arms
        .iter()
        .map(|arm| {
            Ok(CalibrationArmBinding {
                ordinal: arm.metadata.ordinal,
                class: arm.metadata.class,
                path: arm
                    .leaf
                    .strip_prefix(&context.root)
                    .map_err(|_| Error::new("manifest arm path escaped root"))?
                    .to_string_lossy()
                    .into_owned(),
                raw_sha256: arm.raw_sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let manifest = CalibrationManifest {
        schema: CALIBRATION_MANIFEST_SCHEMA.to_owned(),
        calibration_id: context.calibration_id.clone(),
        intent_sha256: context.intent_sha256.clone(),
        machine_sha256: context.machine_sha256.clone(),
        build_set_sha256: context.build_set_sha256.clone(),
        topology_smoke_sha256: sha256_file(&context.root.join("topology-smoke.json"))?,
        calibration_plan_sha256: plan_sha256,
        authoritative_parameters_sha256: parameters_sha256,
        execution_state_sha256: state_sha256,
        projection_sha256: delivery_projection_sha256,
        arm_bindings,
        signature_bindings,
        selected_n,
        terminal_state,
        terminal_reasons: reason_text,
        records,
    };
    manifest.validate()?;
    json::write_new_canonical(&context.root.join("calibration-manifest.json"), &manifest)?;

    let seal = create_seal(&context.root)?;
    let verified = bundle::verify_source(&context.root)?;
    if verified.terminal_state != terminal_state {
        return Err(Error::new(format!(
            "sealed calibration derived {:?}, expected {:?}",
            verified.terminal_state, terminal_state
        )));
    }
    deliver_sealed_calibration(&context.repository, &context.root, &seal.root_sha256)
}

fn deliver_sealed_calibration(
    repository: &Path,
    root: &Path,
    expected_seal_root: &str,
) -> Result<CalibrationOutcome> {
    let verified = bundle::verify_source(root)?;
    if verified.intent.evidence_kind != EvidenceKind::Calibration
        || verified.seal.root_sha256 != expected_seal_root
    {
        return Err(Error::new("sealed calibration delivery identity changed"));
    }
    let calibration_id = verified.intent.evidence_id.clone();
    let manifest: CalibrationManifest = json::read_strict(
        &root.join("calibration-manifest.json"),
        crate::schema::JSON_MAX_BYTES,
    )?;
    manifest.validate()?;
    if manifest.calibration_id != calibration_id
        || manifest.terminal_state != verified.terminal_state
    {
        return Err(Error::new(
            "sealed calibration manifest differs from independently derived source",
        ));
    }
    let mut transaction = DeliveryTransaction::open(
        repository,
        EvidenceKind::Calibration,
        &calibration_id,
        expected_seal_root,
    )?;
    transaction.record(
        DeliveryPhase::SourceVerified,
        vec![DeliveryBinding::from_file_at(
            "source/seal.json",
            &root.join("seal.json"),
        )?],
    )?;

    let destination = artifact_root(repository)
        .join("bundles/calibration")
        .join(&calibration_id);
    let staging = crate::orchestrator::execution_root(repository)
        .join("delivery-staging")
        .join(&calibration_id);
    if !staging.exists() && !destination.exists() {
        let attempt = transaction.next_attempt("bundle")?;
        bundle::create_bundle_derived(root, &attempt)?;
        fs::create_dir_all(
            staging
                .parent()
                .ok_or_else(|| Error::new("calibration staging has no parent"))?,
        )?;
        fs::rename(&attempt, &staging)?;
        File::open(
            staging
                .parent()
                .ok_or_else(|| Error::new("calibration staging parent disappeared"))?,
        )?
        .sync_all()?;
    }
    if staging.exists() && destination.exists() {
        return Err(Error::new(
            "calibration delivery has both staging and installed bundle directories",
        ));
    }
    let bundle_root = if destination.exists() {
        &destination
    } else {
        &staging
    };
    let index_path = bundle_root.join("bundle-index.json");
    let index: bundle::BundleIndex = json::read_strict(&index_path, crate::schema::JSON_MAX_BYTES)?;
    index.validate()?;
    if index.evidence_kind != EvidenceKind::Calibration
        || index.evidence_id != calibration_id
        || index.uncompressed_seal_root_sha256 != expected_seal_root
        || index.terminal_state != verified.terminal_state
    {
        return Err(Error::new(
            "calibration bundle index differs from sealed source",
        ));
    }
    transaction.record(
        DeliveryPhase::BundleCreated,
        vec![DeliveryBinding::from_file_at(
            "bundle/bundle-index.json",
            &index_path,
        )?],
    )?;

    let scratch = transaction.next_attempt("verify")?;
    let receipt = bundle::verify_bundle(&index_path, &scratch)?;
    receipt.validate()?;
    let receipt_path = bundle_root.join("verification.json");
    write_or_require_canonical(&receipt_path, &receipt)?;
    let mut verification_bindings = vec![
        DeliveryBinding::from_file_at("bundle/bundle-index.json", &index_path)?,
        DeliveryBinding::from_file_at("bundle/verification.json", &receipt_path)?,
    ];
    if bundle_root.join("compression-profile.json").is_file() {
        verification_bindings.push(DeliveryBinding::from_file_at(
            "bundle/compression-profile.json",
            &bundle_root.join("compression-profile.json"),
        )?);
    }
    transaction.record(DeliveryPhase::BundleVerified, verification_bindings)?;

    let (design_sha256, continuation_sha256) = ensure_calibration_derived_products(
        repository,
        root,
        bundle_root,
        &index,
        &manifest,
        expected_seal_root,
    )?;
    let mut derived_bindings = Vec::new();
    if design_sha256.is_some() {
        derived_bindings.push(DeliveryBinding::from_file_at(
            "bundle/design-lock.json",
            &bundle_root.join("design-lock.json"),
        )?);
        derived_bindings.push(DeliveryBinding::from_file_at(
            "bundle/continuation-projection.json",
            &bundle_root.join("continuation-projection.json"),
        )?);
    }
    transaction.record(DeliveryPhase::DerivedProducts, derived_bindings)?;

    let entry = calibration_delivery_entry(
        repository,
        bundle_root,
        &index,
        &receipt,
        expected_seal_root,
        design_sha256.as_deref(),
        continuation_sha256.as_deref(),
    )?;
    let ledger_path = artifact_root(repository).join("delivery-index.json");
    let previous = if ledger_path.exists() {
        json::read_strict(&ledger_path, crate::schema::JSON_MAX_BYTES)?
    } else {
        DeliveryLedger::empty()
    };
    let next = if let Some(existing) = previous.entries.iter().find(|existing| {
        existing.evidence_kind == EvidenceKind::Calibration
            && existing.evidence_id == calibration_id
    }) {
        if existing != &entry {
            return Err(Error::new(
                "calibration delivery ledger identity was published with different content",
            ));
        }
        previous.clone()
    } else {
        bundle::append_delivery_entry(&previous, entry.clone())?
    };
    ensure_prepublish_cap(repository, bundle_root, &destination, &previous, &next)?;
    let prepared_entry = transaction.root().join("prepared-entry.json");
    let prepared_ledger = transaction.root().join("prepared-ledger.json");
    write_or_require_canonical(&prepared_entry, &entry)?;
    write_or_require_canonical(&prepared_ledger, &next)?;
    transaction.record(
        DeliveryPhase::PrepublishCap,
        vec![
            DeliveryBinding::from_file_at("prepared/entry.json", &prepared_entry)?,
            DeliveryBinding::from_file_at("prepared/ledger.json", &prepared_ledger)?,
        ],
    )?;

    if !destination.exists() {
        fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| Error::new("calibration bundle destination has no parent"))?,
        )?;
        fs::rename(&staging, &destination)?;
        File::open(
            destination
                .parent()
                .ok_or_else(|| Error::new("calibration bundle parent disappeared"))?,
        )?
        .sync_all()?;
    }
    transaction.record(
        DeliveryPhase::BundleInstalled,
        vec![DeliveryBinding::from_file_at(
            "installed/bundle-index.json",
            &destination.join("bundle-index.json"),
        )?],
    )?;
    transaction.record(
        DeliveryPhase::ConclusionInstalled,
        vec![DeliveryBinding::from_file_at(
            "installed/verification.json",
            &destination.join("verification.json"),
        )?],
    )?;

    ensure_prepublish_cap(repository, &destination, &destination, &previous, &next)?;
    transaction.record(
        DeliveryPhase::FinalCap,
        vec![DeliveryBinding::from_file_at(
            "prepared/ledger.json",
            &prepared_ledger,
        )?],
    )?;
    write_ledger(&ledger_path, &next)?;
    transaction.record(
        DeliveryPhase::LedgerPublished,
        vec![DeliveryBinding::from_file_at(
            "installed/delivery-index.json",
            &ledger_path,
        )?],
    )?;
    transaction.record(
        DeliveryPhase::OutcomePublished,
        vec![DeliveryBinding::from_file_at(
            "installed/delivery-index.json",
            &ledger_path,
        )?],
    )?;
    let delivered = crate::delivery::validate_local_delivery(
        repository,
        EvidenceKind::Calibration,
        &calibration_id,
        expected_seal_root,
    )?;
    Ok(CalibrationOutcome {
        calibration_id,
        candidate_commit: verified.intent.candidate_commit,
        evidence_root: root.display().to_string(),
        terminal_state: delivered.outcome,
        reasons: verified.reasons,
        selected_n: manifest.selected_n,
        seal_root_sha256: expected_seal_root.to_owned(),
        bundle_index_path: delivered.bundle_index_path,
        bundle_index_sha256: delivered.bundle_index_sha256,
        verification_path: delivered.verification_path,
        verification_sha256: delivered.verification_sha256,
        design_lock_path: delivered.design_lock_path,
        design_lock_sha256: delivered.design_lock_sha256,
    })
}

fn ensure_calibration_derived_products(
    repository: &Path,
    root: &Path,
    bundle_root: &Path,
    index: &bundle::BundleIndex,
    manifest: &CalibrationManifest,
    seal_root: &str,
) -> Result<(Option<String>, Option<String>)> {
    if manifest.terminal_state != TerminalState::Pass {
        if bundle_root.join("design-lock.json").exists()
            || bundle_root.join("continuation-projection.json").exists()
        {
            return Err(Error::new(
                "blocked calibration unexpectedly has continuation products",
            ));
        }
        return Ok((None, None));
    }
    let design_path = bundle_root.join("design-lock.json");
    let continuation_path = bundle_root.join("continuation-projection.json");
    match (design_path.is_file(), continuation_path.is_file()) {
        (true, true) => {
            let design: DesignLock =
                json::read_strict(&design_path, crate::schema::JSON_MAX_BYTES)?;
            let continuation: ContinuationProjection =
                json::read_strict(&continuation_path, crate::schema::JSON_MAX_BYTES)?;
            design.validate()?;
            continuation.validate()?;
            if design.calibration_id != manifest.calibration_id
                || design.calibration_seal_root_sha256 != seal_root
                || design.calibration_bundle_index_sha256
                    != sha256_file(&bundle_root.join("bundle-index.json"))?
                || design.projection_sha256 != sha256_file(&continuation_path)?
                || continuation.calibration_manifest_sha256
                    != sha256_file(&root.join("calibration-manifest.json"))?
            {
                return Err(Error::new(
                    "existing calibration derived products are stale or changed",
                ));
            }
            return Ok((
                Some(sha256_file(&design_path)?),
                Some(sha256_file(&continuation_path)?),
            ));
        }
        (false, false) => {}
        _ => {
            return Err(Error::new(
                "calibration derived products are only partially present",
            ))
        }
    }
    let n = manifest
        .selected_n
        .filter(|value| matches!(value, 30 | 50))
        .ok_or_else(|| Error::new("passing calibration lacks runtime-admissible N"))?;
    let parameters: AuthoritativeParameters = json::read_strict(
        &root.join("authoritative-parameters.json"),
        crate::schema::JSON_MAX_BYTES,
    )?;
    parameters.validate()?;
    let state: ExecutionStateEvidence = json::read_strict(
        &root.join("execution-state.json"),
        crate::schema::JSON_MAX_BYTES,
    )?;
    let e_pre_ns = state
        .campaign_boottime_end_ns
        .zip(state.campaign_boottime_start_ns)
        .and_then(|(end, start)| end.checked_sub(start))
        .ok_or_else(|| Error::new("passing calibration lacks BOOTTIME bounds"))?;
    let source_arms = parse_raw_arms(root)?;
    let runtime = calibration::project_runtime(
        n,
        e_pre_ns,
        q_extra_ns(&source_arms)?,
        &parameters.authoritative_durations,
    )?;
    if !runtime.admissible {
        return Err(Error::new(
            "sealed calibration runtime projection no longer admits its campaign",
        ));
    }
    let profile: CompressionProfile = json::read_strict(
        &bundle_root.join("compression-profile.json"),
        crate::schema::JSON_MAX_BYTES,
    )?;
    let (authoritative_requirements, direct_requirements) = continuation_requirements(
        &profile,
        n,
        &source_arms,
        &parameters.authoritative_durations,
    )?;
    let authoritative_bytes =
        storage::verified_compression_projection(&profile, &authoritative_requirements)?;
    let direct_bytes = storage::verified_compression_projection(&profile, &direct_requirements)?;
    let prior_bytes = storage::actual_regular_bytes_if_exists(&artifact_root(repository))?;
    let calibration_bytes = storage::actual_regular_bytes(bundle_root)?
        .checked_add(2 * MIB)
        .ok_or_else(|| Error::new("calibration derived-product reserve overflow"))?;
    let tracked = storage::tracked_projection(
        prior_bytes,
        calibration_bytes,
        &[authoritative_bytes],
        &[direct_bytes],
        5 * MIB,
    )?;
    if !tracked.admissible {
        return Err(Error::new(
            "verified post-calibration continuation projection exceeds 512 MiB",
        ));
    }
    let intent: Intent =
        json::read_strict(&root.join("intent.json"), crate::schema::JSON_MAX_BYTES)?;
    let manifest_sha256 = sha256_file(&root.join("calibration-manifest.json"))?;
    let continuation = ContinuationProjection {
        schema: CONTINUATION_PROJECTION_SCHEMA.to_owned(),
        calibration_id: manifest.calibration_id.clone(),
        intent_sha256: manifest.intent_sha256.clone(),
        calibration_plan_sha256: require_optional_hash(
            &manifest.calibration_plan_sha256,
            "passing calibration plan",
        )?,
        authoritative_parameters_sha256: require_optional_hash(
            &manifest.authoritative_parameters_sha256,
            "passing authoritative parameters",
        )?,
        calibration_manifest_sha256: manifest_sha256.clone(),
        calibration_bundle_index_sha256: sha256_file(&bundle_root.join("bundle-index.json"))?,
        compression_profile_sha256: sha256_file(&bundle_root.join("compression-profile.json"))?,
        runtime: runtime.clone(),
        tracked: tracked.clone(),
        authoritative_requirements,
        direct_requirements,
    };
    continuation.validate()?;
    write_or_require_canonical(&continuation_path, &continuation)?;
    let continuation_sha256 = sha256_file(&continuation_path)?;
    let design = DesignLock {
        schema: DESIGN_LOCK_SCHEMA.to_owned(),
        calibration_id: manifest.calibration_id.clone(),
        candidate_commit: intent.candidate_commit,
        intent_sha256: manifest.intent_sha256.clone(),
        machine_sha256: manifest.machine_sha256.clone(),
        build_set_sha256: manifest.build_set_sha256.clone(),
        topology_smoke_sha256: manifest.topology_smoke_sha256.clone(),
        calibration_plan_sha256: continuation.calibration_plan_sha256.clone(),
        authoritative_parameters_sha256: continuation.authoritative_parameters_sha256.clone(),
        calibration_manifest_sha256: manifest_sha256,
        projection_sha256: continuation_sha256.clone(),
        calibration_seal_root_sha256: seal_root.to_owned(),
        calibration_bundle_index_sha256: sha256_file(&bundle_root.join("bundle-index.json"))?,
        selected_n: n,
        schedule_seed: intent.campaign_seed ^ 0x4155_5448_5343_4844,
        rounds: crate::schedule::generate_rounds(intent.campaign_seed ^ 0x4155_5448_5343_4844, n)?,
        comparisons: hard_comparisons(),
        authoritative_durations: parameters.authoritative_durations,
        treatment_signatures: parameters.accepted_treatment_signatures,
        direct_signatures: manifest
            .signature_bindings
            .iter()
            .filter(|binding| binding.direct_protocol.is_some())
            .cloned()
            .collect(),
        direct_mappings: process_plan::direct_mappings(),
        runtime_projection: runtime,
        tracked_projection: tracked,
        calibration_frequency_p05_khz: derive_frequency_p05_khz(&source_arms)?,
    };
    design.validate()?;
    write_or_require_canonical(&design_path, &design)?;
    if index.evidence_id != design.calibration_id {
        return Err(Error::new("derived design differs from bundle identity"));
    }
    Ok((Some(sha256_file(&design_path)?), Some(continuation_sha256)))
}

fn calibration_delivery_entry(
    _repository: &Path,
    bundle_root: &Path,
    index: &bundle::BundleIndex,
    receipt: &bundle::VerificationReceipt,
    seal_root: &str,
    design_sha256: Option<&str>,
    continuation_sha256: Option<&str>,
) -> Result<DeliveryEntry> {
    let prefix = format!("bundles/calibration/{}", index.evidence_id);
    let entry = DeliveryEntry {
        evidence_kind: EvidenceKind::Calibration,
        evidence_id: index.evidence_id.clone(),
        bundle_index_path: format!("{prefix}/bundle-index.json"),
        bundle_index_sha256: receipt.bundle_index_sha256.clone(),
        verification_path: format!("{prefix}/verification.json"),
        verification_sha256: sha256_file(&bundle_root.join("verification.json"))?,
        result_path: None,
        result_sha256: None,
        report_path: None,
        report_sha256: None,
        design_lock_path: design_sha256.map(|_| format!("{prefix}/design-lock.json")),
        design_lock_sha256: design_sha256.map(str::to_owned),
        continuation_projection_path: continuation_sha256
            .map(|_| format!("{prefix}/continuation-projection.json")),
        continuation_projection_sha256: continuation_sha256.map(str::to_owned),
        seal_root_sha256: seal_root.to_owned(),
        outcome: index.terminal_state,
        tracked_bytes: storage::actual_regular_bytes(bundle_root)?,
    };
    entry.validate()?;
    Ok(entry)
}

fn ensure_prepublish_cap(
    repository: &Path,
    bundle_root: &Path,
    destination: &Path,
    previous: &DeliveryLedger,
    next: &DeliveryLedger,
) -> Result<()> {
    let artifacts = artifact_root(repository);
    let mut projected = storage::actual_regular_bytes_if_exists(&artifacts)?;
    if !destination.exists() {
        projected = projected
            .checked_add(storage::actual_regular_bytes(bundle_root)?)
            .ok_or_else(|| Error::new("prepublish bundle byte total overflow"))?;
    }
    let ledger_path = artifacts.join("delivery-index.json");
    let next_bytes = json::canonical_bytes(next)?;
    let pending_ledger = ledger_path.with_extension("json.next");
    if pending_ledger.exists() {
        let pending_bytes = fs::read(&pending_ledger)?;
        if pending_bytes != next_bytes {
            return Err(Error::new(
                "pending calibration ledger contains different content",
            ));
        }
        projected = projected
            .checked_sub(u64::try_from(pending_bytes.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| Error::new("pending calibration ledger byte underflow"))?;
    }
    if ledger_path.exists() {
        let previous_bytes = fs::read(&ledger_path)?;
        if previous != next {
            projected = projected
                .checked_sub(u64::try_from(previous_bytes.len()).unwrap_or(u64::MAX))
                .and_then(|value| {
                    value.checked_add(u64::try_from(next_bytes.len()).unwrap_or(u64::MAX))
                })
                .ok_or_else(|| Error::new("prepublish ledger replacement overflow"))?;
            if !previous.entries.is_empty() {
                let history = artifacts
                    .join("ledger-history")
                    .join(format!("{}.json", sha256_hex(&previous_bytes)));
                if !history.exists() {
                    projected = projected
                        .checked_add(u64::try_from(previous_bytes.len()).unwrap_or(u64::MAX))
                        .ok_or_else(|| Error::new("prepublish ledger history overflow"))?;
                }
            }
        }
    } else {
        projected = projected
            .checked_add(u64::try_from(next_bytes.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| Error::new("prepublish genesis ledger overflow"))?;
    }
    if projected > TASK_CAP_BYTES {
        return Err(Error::new(
            "prepublish calibration delivery exceeds the exact 512 MiB gate",
        ));
    }
    Ok(())
}

fn continuation_requirements(
    profile: &CompressionProfile,
    n: u32,
    arms: &[ParsedArm],
    durations: &[CellDurations],
) -> Result<(Vec<CompressionRequirement>, Vec<CompressionRequirement>)> {
    profile.validate()?;
    let duration_by_cell = durations
        .iter()
        .map(|entry| (entry.cell, entry.durations))
        .collect::<BTreeMap<_, _>>();
    let mut authoritative = Vec::new();
    let mut direct = Vec::new();
    for witness in &profile.witnesses {
        let matching = arms
            .iter()
            .filter(|arm| bundle::compression_match_key(arm) == witness.match_key)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Err(Error::new(
                "compression witness lacks matching raw calibration arms",
            ));
        }
        let cell = matching[0].metadata.cell;
        let duration = *duration_by_cell
            .get(&cell)
            .ok_or_else(|| Error::new("continuation requirement lacks cell durations"))?;
        let future_records = matching.iter().try_fold(0_u64, |maximum, arm| {
            Ok::<u64, Error>(maximum.max(future_component_records(
                &witness.component,
                arm,
                duration,
                &matching,
            )?))
        })?;
        if witness.match_key.starts_with("gateway:") {
            authoritative.push(CompressionRequirement {
                match_key: witness.match_key.clone(),
                component: witness.component.clone(),
                future_records,
                future_arms: u64::from(n),
            });
        } else if witness.match_key.starts_with("direct:") {
            direct.push(CompressionRequirement {
                match_key: witness.match_key.clone(),
                component: witness.component.clone(),
                future_records,
                future_arms: u64::from(n / 10),
            });
        }
    }
    if authoritative.is_empty() || direct.is_empty() {
        return Err(Error::new(
            "calibration compression profile lacks gateway or direct matches",
        ));
    }
    Ok((authoritative, direct))
}

fn future_component_records(
    component: &str,
    arm: &ParsedArm,
    durations: FrozenDurations,
    matching: &[&ParsedArm],
) -> Result<u64> {
    let full_ns = calibration::arm_cap_ns(arm.metadata.cell, durations)?;
    let sampled_ns = full_ns
        .checked_sub(calibration::FIXED_Q_OBS_NS)
        .ok_or_else(|| Error::new("future sampled duration underflow"))?;
    let h10 = 2_u64
        .checked_add(ceil_div_u64(sampled_ns, 10_000_000)?)
        .ok_or_else(|| Error::new("future H10 overflow"))?;
    let h100 = 2_u64
        .checked_add(ceil_div_u64(sampled_ns, 100_000_000)?)
        .ok_or_else(|| Error::new("future H100 overflow"))?;
    let tids = u64::try_from(arm.thread_map.threads.len())
        .map_err(|_| Error::new("future TID count overflow"))?;
    let events = arm
        .lifecycle
        .births_before_freeze
        .checked_add(arm.lifecycle.deaths_before_freeze)
        .ok_or_else(|| Error::new("future lifecycle event count overflow"))?;
    let concurrency = u64::from(arm.metadata.cell.concurrency);
    match component {
        "metadata.json" | "quiet.json" => Ok(1),
        "thread-map.json" => Ok(tids.max(1)),
        "thread-lifecycle.bin" => h10
            .checked_add(events)
            .ok_or_else(|| Error::new("future lifecycle record count overflow")),
        "session-clock.bin" => Ok(if arm.metadata.class == EvidenceClass::D {
            1
        } else {
            h10
        }),
        "resources.bin" => h100
            .checked_mul(
                32_u64
                    .checked_add(tids)
                    .and_then(|value| value.checked_add(4))
                    .ok_or_else(|| Error::new("future resource width overflow"))?,
            )
            .ok_or_else(|| Error::new("future resource record count overflow")),
        "endpoints.bin" => 1_u64
            .checked_add(136 + concurrency)
            .and_then(|value| value.checked_add(concurrency))
            .ok_or_else(|| Error::new("future endpoint record count overflow")),
        "operation-summary.bin" => 1_u64
            .checked_add(concurrency)
            .ok_or_else(|| Error::new("future operation record count overflow")),
        "latencies.u64le" => {
            if arm.metadata.class != EvidenceClass::C {
                return Err(Error::new(
                    "direct compression match unexpectedly has latency component",
                ));
            }
            let max_started = matching
                .iter()
                .map(|value| value.operation.started_operations)
                .max()
                .ok_or_else(|| Error::new("latency continuation match is empty"))?;
            let calibration_ns = arm
                .operation
                .deadline_ns
                .checked_sub(arm.operation.window_start_ns)
                .ok_or_else(|| Error::new("calibration latency duration underflow"))?;
            let future_ns = durations
                .measure_seconds
                .checked_add(2)
                .and_then(|seconds| seconds.checked_mul(1_000_000_000))
                .ok_or_else(|| Error::new("authoritative latency duration overflow"))?;
            let numerator = u128::from(max_started)
                .checked_mul(2)
                .and_then(|value| value.checked_mul(u128::from(future_ns)))
                .ok_or_else(|| Error::new("LAT_A numerator overflow"))?;
            let projected = ceil_div_u128(numerator, u128::from(calibration_ns))?;
            u64::from(arm.metadata.cell.concurrency)
                .checked_add(
                    u64::try_from(projected).map_err(|_| Error::new("LAT_A does not fit u64"))?,
                )
                .ok_or_else(|| Error::new("LAT_A ceiling overflow"))
        }
        _ => Err(Error::new("unknown continuation schema component")),
    }
}

fn ceil_div_u64(numerator: u64, denominator: u64) -> Result<u64> {
    let value = ceil_div_u128(u128::from(numerator), u128::from(denominator))?;
    u64::try_from(value).map_err(|_| Error::new("ceiling division does not fit u64"))
}

fn ceil_div_u128(numerator: u128, denominator: u128) -> Result<u128> {
    if denominator == 0 {
        return Err(Error::new("ceiling division denominator is zero"));
    }
    numerator
        .checked_add(denominator - 1)
        .map(|value| value / denominator)
        .ok_or_else(|| Error::new("ceiling division overflow"))
}

fn preseal_continuation_storage(context: &CalibrationContext, n: u32) -> Result<TrackedProjection> {
    let intent_bytes = fs::read(context.root.join("intent.json"))?;
    let intent: Intent = json::require_canonical(&intent_bytes)?;
    let profile = bundle::build_compression_profile(&context.root, &intent, &intent_bytes)?
        .ok_or_else(|| Error::new("complete calibration lacks a compression profile"))?;
    let parameters: AuthoritativeParameters = json::read_strict(
        &context.root.join("authoritative-parameters.json"),
        crate::schema::JSON_MAX_BYTES,
    )?;
    let arms = parse_raw_arms(&context.root)?;
    let (authoritative_requirements, direct_requirements) =
        continuation_requirements(&profile, n, &arms, &parameters.authoritative_durations)?;
    let authoritative =
        storage::verified_compression_projection(&profile, &authoritative_requirements)?;
    let direct = storage::verified_compression_projection(&profile, &direct_requirements)?;
    let prior = storage::actual_regular_bytes_if_exists(&artifact_root(&context.repository))?;
    // The uncompressed open source plus 5 MiB exceeds the later compressed
    // calibration/index/receipt footprint, so a pass cannot rely on optimistic
    // compression of the current unit.
    let calibration_upper = directory_regular_bytes(&context.root)?
        .checked_add(5 * MIB)
        .ok_or_else(|| Error::new("preseal calibration delivery upper bound overflow"))?;
    storage::tracked_projection(
        prior,
        calibration_upper,
        &[authoritative],
        &[direct],
        5 * MIB,
    )
}

fn directory_regular_bytes(directory: &Path) -> Result<u64> {
    fs::read_dir(directory)?.try_fold(0_u64, |total, entry| {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let bytes = if metadata.file_type().is_dir() {
            directory_regular_bytes(&path)?
        } else if metadata.file_type().is_file() {
            metadata.len()
        } else {
            return Err(Error::new(
                "calibration source contains a non-regular member",
            ));
        };
        total
            .checked_add(bytes)
            .ok_or_else(|| Error::new("calibration source byte total overflow"))
    })
}

fn write_ledger(path: &Path, ledger: &DeliveryLedger) -> Result<()> {
    ledger.validate()?;
    let bytes = json::canonical_bytes(ledger)?;
    if path.exists() {
        let previous_bytes = fs::read(path)?;
        if previous_bytes == bytes {
            return Ok(());
        }
        let previous_sha256 = sha256_hex(&previous_bytes);
        let history = path
            .parent()
            .ok_or_else(|| Error::new("delivery ledger has no parent"))?
            .join("ledger-history")
            .join(format!("{previous_sha256}.json"));
        fs::create_dir_all(
            history
                .parent()
                .ok_or_else(|| Error::new("ledger history has no parent"))?,
        )?;
        if history.exists() {
            require_file_bytes(&history, &previous_bytes)?;
        } else {
            json::write_new_bytes(&history, &previous_bytes)?;
        }
        if ledger
            .predecessor
            .as_ref()
            .is_none_or(|value| value.sha256 != previous_sha256)
        {
            return Err(Error::new(
                "delivery successor does not bind the installed predecessor",
            ));
        }
        let temporary = path.with_extension("json.next");
        if temporary.exists() {
            require_file_bytes(&temporary, &bytes)?;
        } else {
            json::write_new_bytes(&temporary, &bytes)?;
        }
        fs::rename(&temporary, path)?;
    } else {
        json::write_new_bytes(path, &bytes)?;
    }
    File::open(
        path.parent()
            .ok_or_else(|| Error::new("delivery ledger has no parent"))?,
    )?
    .sync_all()?;
    Ok(())
}

fn artifact_root(repository: &Path) -> PathBuf {
    repository.join(".legion/tasks/prove-http2-performance-regression/artifacts")
}

fn write_projection_revision(
    context: &mut CalibrationContext,
    runtime_projected_ns: u64,
    storage_admission: Option<ReachedBranchProjection>,
) -> Result<()> {
    let revision = u32::try_from(context.projections.len())
        .map_err(|_| Error::new("projection revision exceeds u32"))?;
    let projection = build_projection(
        context,
        revision,
        context.projections.last().cloned(),
        runtime_projected_ns,
        storage_admission,
    )?;
    let relative = format!("projections/{revision:03}.json");
    let path = context.root.join(&relative);
    write_or_require_canonical(&path, &projection)?;
    let binding = FileHashBinding {
        path: relative,
        sha256: sha256_file(&path)?,
    };
    if context.projections.get(revision as usize) != Some(&binding) {
        context.projections.push(binding);
    }
    Ok(())
}

fn build_projection(
    context: &CalibrationContext,
    revision: u32,
    predecessor: Option<FileHashBinding>,
    runtime_projected_ns: u64,
    storage_admission: Option<ReachedBranchProjection>,
) -> Result<ProjectionEvidence> {
    let arms = parse_raw_arms(&context.root)?;
    let completed_arms = arms.len() as u64;
    let source_arm_root_sha256 = Some(raw_arm_root(&arms)?);
    let raw_actual_bytes = raw_arm_bytes(&arms)?;
    let tracked_actual =
        storage::actual_regular_bytes_if_exists(&artifact_root(&context.repository))?;
    let raw_projected_bytes = storage_admission
        .as_ref()
        .map_or(raw_actual_bytes, |value| value.extracted_source_bound_bytes);
    let tracked_projected_bytes = storage_admission
        .as_ref()
        .map_or(tracked_actual, |value| value.tracked_total_bound_bytes);
    let projection = ProjectionEvidence {
        schema: PROJECTION_SCHEMA.to_owned(),
        revision,
        predecessor,
        source_arm_root_sha256,
        completed_arms,
        runtime_projected_ns,
        runtime_actual_ns: campaign_elapsed(context)?,
        q_extra_ns: q_extra_ns(&arms)?,
        raw_projected_bytes,
        raw_actual_bytes,
        tracked_projected_bytes,
        tracked_actual_bytes: tracked_actual,
        endpoint_bound_bytes: 512 + 160 * 200 + 512 * 64,
        conn_live: 200,
        concurrency: 64,
        storage_admission,
    };
    projection.validate()?;
    Ok(projection)
}

pub(crate) fn raw_arm_root(arms: &[ParsedArm]) -> Result<String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"amg-http2-perf/raw-arm-prefix/v1\0");
    for arm in arms {
        bytes.extend_from_slice(&arm.metadata.ordinal.to_be_bytes());
        bytes.extend_from_slice(arm.raw_sha256.as_bytes());
    }
    Ok(sha256_hex(&bytes))
}

pub(crate) fn raw_arm_bytes(arms: &[ParsedArm]) -> Result<u64> {
    arms.iter().try_fold(0_u64, |total, arm| {
        let bytes = fs::read_dir(&arm.leaf)?.try_fold(0_u64, |subtotal, entry| {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_file() {
                return Err(Error::new("raw arm leaf contains a non-file"));
            }
            subtotal
                .checked_add(metadata.len())
                .ok_or_else(|| Error::new("raw arm byte subtotal overflow"))
        })?;
        total
            .checked_add(bytes)
            .ok_or_else(|| Error::new("raw arm byte total overflow"))
    })
}

fn q_extra_ns(arms: &[ParsedArm]) -> Result<u64> {
    arms.iter().try_fold(0_u64, |total, arm| {
        total
            .checked_add(arm.quiet.q_extra_ns)
            .ok_or_else(|| Error::new("Q_extra total overflow"))
    })
}

fn campaign_elapsed(context: &CalibrationContext) -> Result<u64> {
    clock_ns(ClockKind::Boottime)?
        .checked_sub(context.campaign_start_ns)
        .ok_or_else(|| Error::new("campaign BOOTTIME moved backwards"))
}

fn ensure_actual_runtime(context: &CalibrationContext) -> Result<()> {
    let elapsed = campaign_elapsed(context)?;
    if calibration::actual_runtime_allowed(elapsed) {
        Ok(())
    } else {
        Err(Error::new(
            "actual post-build calibration runtime exceeds 48 hours",
        ))
    }
}

fn parse_raw_arms(root: &Path) -> Result<Vec<ParsedArm>> {
    let inspection = raw::inspect_evidence_tree(root)?;
    if !inspection.blockers.is_empty() {
        return Err(Error::new(format!(
            "calibration raw prefix failed revalidation: {}",
            inspection.blockers.join("; ")
        )));
    }
    Ok(inspection.arms)
}

fn raw_arm_by_ordinal(root: &Path, ordinal: u64) -> Result<ParsedArm> {
    parse_raw_arms(root)?
        .into_iter()
        .find(|arm| arm.metadata.ordinal == ordinal)
        .ok_or_else(|| Error::new(format!("raw arm ordinal {ordinal} is missing")))
}

fn treatment_signature_path(
    root: &Path,
    cell: crate::schema::Cell,
    arm: Option<Arm>,
) -> Result<PathBuf> {
    Ok(root.join("signatures").join(cell.id()).join(format!(
        "{}.json",
        arm.ok_or_else(|| Error::new("treatment signature lacks arm"))?
            .code()
    )))
}

fn direct_signature_path(root: &Path, cell: crate::schema::Cell, protocol: Protocol) -> PathBuf {
    root.join("signatures")
        .join(cell.id())
        .join(format!("{}.json", protocol.label()))
}

fn read_signature_bindings(root: &Path, include_direct: bool) -> Result<Vec<SignatureBinding>> {
    let signatures = root.join("signatures");
    if !signatures.exists() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    collect_json_files(&signatures, &mut paths)?;
    let mut bindings = Vec::new();
    for path in paths {
        let bytes = fs::read(&path)?;
        let record: AcceptedSignatureRecord = json::require_canonical(&bytes)?;
        record.validate()?;
        if include_direct || record.direct_protocol.is_none() {
            bindings.push(
                record.binding(
                    path.strip_prefix(root)
                        .map_err(|_| Error::new("signature path escaped root"))?
                        .to_string_lossy()
                        .into_owned(),
                    sha256_hex(&bytes),
                )?,
            );
        }
    }
    bindings.sort();
    Ok(bindings)
}

fn quarantine_incomplete_signatures(
    context: &CalibrationContext,
    arms: &[ParsedArm],
) -> Result<()> {
    let directory = context.root.join("signatures");
    if !directory.exists() {
        return Ok(());
    }
    let completed = arms
        .iter()
        .map(|arm| arm.metadata.ordinal)
        .collect::<BTreeSet<_>>();
    let mut paths = Vec::new();
    collect_json_files(&directory, &mut paths)?;
    for path in paths {
        let record: AcceptedSignatureRecord =
            json::read_strict(&path, crate::schema::JSON_MAX_BYTES)?;
        if completed.contains(&record.establishment_ordinal) {
            continue;
        }
        let class = match record.establishment_class {
            EvidenceClass::C => "c",
            EvidenceClass::D => "d",
            _ => "invalid",
        };
        let target_directory = context.root.join("arm-failures").join(class);
        fs::create_dir_all(&target_directory)?;
        let target = target_directory.join(format!(
            "{:06}-incomplete-signature.json",
            record.establishment_ordinal
        ));
        if target.exists() {
            require_file_bytes(&target, &fs::read(&path)?)?;
            fs::remove_file(&path)?;
        } else {
            fs::rename(&path, &target)?;
        }
        File::open(&target_directory)?.sync_all()?;
    }
    Ok(())
}

fn collect_json_files(directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            collect_json_files(&path, output)?;
        } else if metadata.file_type().is_file()
            && path.extension().and_then(|value| value.to_str()) == Some("json")
        {
            output.push(path);
        } else {
            return Err(Error::new(
                "signature tree contains a non-JSON regular file",
            ));
        }
    }
    output.sort();
    Ok(())
}

struct JournalInput<'a> {
    calibration_id: &'a str,
    kind: ExecutionJournalKind,
    phase: ExecutionPhase,
    ordinal: Option<u64>,
    boottime_ns: u64,
    boot_id_sha256: &'a str,
    machine_sha256: &'a str,
    build_set_sha256: &'a str,
    plan_sha256: &'a str,
    raw: Option<(String, String)>,
}

fn append_simple_journal(
    context: &mut CalibrationContext,
    kind: ExecutionJournalKind,
    phase: ExecutionPhase,
    ordinal: Option<u64>,
    plan_sha256: &str,
    raw: Option<(String, String)>,
) -> Result<()> {
    append_journal_record(
        &context.root,
        &mut context.journal,
        JournalInput {
            calibration_id: &context.calibration_id,
            kind,
            phase,
            ordinal,
            boottime_ns: clock_ns(ClockKind::Boottime)?,
            boot_id_sha256: &context.boot_id_sha256,
            machine_sha256: &context.machine_sha256,
            build_set_sha256: &context.build_set_sha256,
            plan_sha256,
            raw,
        },
    )
}

fn append_journal_record(
    root: &Path,
    journal: &mut Vec<ExecutionJournalRecord>,
    input: JournalInput<'_>,
) -> Result<()> {
    let sequence = journal.len() as u64;
    let predecessor_sha256 = journal
        .last()
        .map(json::canonical_bytes)
        .transpose()?
        .map(|bytes| sha256_hex(&bytes));
    let (raw_path, raw_sha256) = input
        .raw
        .map_or((None, None), |(path, hash)| (Some(path), Some(hash)));
    let record = ExecutionJournalRecord {
        schema: EXECUTION_STATE_SCHEMA.to_owned(),
        calibration_id: input.calibration_id.to_owned(),
        sequence,
        kind: input.kind,
        phase: input.phase,
        ordinal: input.ordinal,
        boottime_ns: input.boottime_ns,
        boot_id_sha256: input.boot_id_sha256.to_owned(),
        machine_sha256: input.machine_sha256.to_owned(),
        build_set_sha256: input.build_set_sha256.to_owned(),
        plan_sha256: input.plan_sha256.to_owned(),
        predecessor_sha256,
        raw_path,
        raw_sha256,
    };
    record.validate()?;
    let path = root.join("state").join(format!(
        "{sequence:06}-{}.json",
        journal_kind_label(record.kind)
    ));
    json::write_new_canonical(&path, &record)?;
    journal.push(record);
    execution_journal_root(journal)?;
    Ok(())
}

fn journal_kind_label(kind: ExecutionJournalKind) -> &'static str {
    match kind {
        ExecutionJournalKind::CampaignStart => "campaign-start",
        ExecutionJournalKind::SmokeStart => "smoke-start",
        ExecutionJournalKind::SmokeComplete => "smoke-complete",
        ExecutionJournalKind::ArmStart => "arm-start",
        ExecutionJournalKind::ArmComplete => "arm-complete",
    }
}

fn read_journal(root: &Path) -> Result<Vec<ExecutionJournalRecord>> {
    let directory = root.join("state");
    let mut files = fs::read_dir(&directory)?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.sort();
    let records = files
        .iter()
        .map(|path| json::read_strict(path, crate::schema::JSON_MAX_BYTES))
        .collect::<Result<Vec<ExecutionJournalRecord>>>()?;
    if !records.is_empty() {
        execution_journal_root(&records)?;
    }
    Ok(records)
}

fn read_projection_bindings(root: &Path) -> Result<Vec<FileHashBinding>> {
    let mut files = fs::read_dir(root.join("projections"))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.sort();
    let mut bindings = Vec::new();
    for (index, path) in files.into_iter().enumerate() {
        let projection: ProjectionEvidence =
            json::read_strict(&path, crate::schema::JSON_MAX_BYTES)?;
        projection.validate()?;
        if projection.revision != index as u32 || projection.predecessor != bindings.last().cloned()
        {
            return Err(Error::new("projection revision chain is invalid"));
        }
        bindings.push(FileHashBinding {
            path: path
                .strip_prefix(root)
                .map_err(|_| Error::new("projection path escaped root"))?
                .to_string_lossy()
                .into_owned(),
            sha256: sha256_file(&path)?,
        });
    }
    Ok(bindings)
}

fn validate_resume_prefix(context: &CalibrationContext) -> Result<()> {
    if context.journal.is_empty()
        || context.journal[0].kind != ExecutionJournalKind::CampaignStart
        || context.journal[0].calibration_id != context.calibration_id
    {
        return Err(Error::new(
            "calibration resume lacks its campaign-start journal",
        ));
    }
    for record in &context.journal {
        if record.boot_id_sha256 != context.boot_id_sha256
            || record.machine_sha256 != context.machine_sha256
            || record.build_set_sha256 != context.build_set_sha256
        {
            return Err(Error::new(
                "calibration resume boot/machine/build identity changed",
            ));
        }
    }
    let arms = parse_raw_arms(&context.root)?;
    let completions = context
        .journal
        .iter()
        .filter(|record| record.kind == ExecutionJournalKind::ArmComplete)
        .collect::<Vec<_>>();
    let durable_unjournaled_tail = arms.len() == completions.len() + 1
        && partially_started_ordinal(&context.journal) == Some(completions.len() as u64)
        && arms
            .last()
            .is_some_and(|arm| arm.metadata.ordinal == completions.len() as u64);
    if completions.len() != arms.len() && !durable_unjournaled_tail {
        return Err(Error::new(
            "calibration resume journal/raw completion counts differ",
        ));
    }
    for (expected, (record, arm)) in completions.iter().zip(&arms).enumerate() {
        if record.ordinal != Some(expected as u64)
            || record.raw_sha256.as_deref() != Some(arm.raw_sha256.as_str())
        {
            return Err(Error::new(
                "calibration resume journal does not bind the exact raw prefix",
            ));
        }
    }
    Ok(())
}

fn partially_started_ordinal(journal: &[ExecutionJournalRecord]) -> Option<u64> {
    match journal.last() {
        Some(record) if record.kind == ExecutionJournalKind::ArmStart => record.ordinal,
        _ => None,
    }
}

fn resume_terminal_if_partial(
    context: &mut CalibrationContext,
) -> Result<Option<CalibrationOutcome>> {
    if context
        .journal
        .last()
        .is_some_and(|record| record.kind == ExecutionJournalKind::SmokeStart)
    {
        if context.root.join("topology-smoke.json").exists() {
            let intent: Intent = json::read_strict(
                &context.root.join("intent.json"),
                crate::schema::JSON_MAX_BYTES,
            )?;
            if crate::evidence::verify_smoke_continuation(&context.root, &intent)? {
                let smoke_hash = sha256_file(&context.root.join("topology-smoke.json"))?;
                append_simple_journal(
                    context,
                    ExecutionJournalKind::SmokeComplete,
                    ExecutionPhase::Smoke,
                    None,
                    &context.intent_sha256.clone(),
                    Some(("topology-smoke.json".to_owned(), smoke_hash)),
                )?;
                return Ok(None);
            }
        }
        return finish_calibration(
            context,
            TerminalState::Blocked,
            vec![BlockedReason::new(
                BlockedCode::EvidenceIntegrity,
                "topology smoke was partially started and cannot resume",
            )],
            None,
            None,
        )
        .map(Some);
    }
    Ok(None)
}

fn optional_sha256(path: &Path) -> Result<Option<String>> {
    if path.exists() {
        sha256_file(path).map(Some)
    } else {
        Ok(None)
    }
}

fn require_optional_hash(value: &Option<String>, label: &str) -> Result<String> {
    value
        .clone()
        .ok_or_else(|| Error::new(format!("{label} hash is missing")))
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256_hex(&fs::read(path)?))
}

fn write_or_require_canonical<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let expected = json::canonical_bytes(value)?;
    if path.exists() {
        require_file_bytes(path, &expected)
    } else {
        json::write_new_bytes(path, &expected)
    }
}

fn require_file_bytes(path: &Path, expected: &[u8]) -> Result<()> {
    if fs::read(path)? == expected {
        Ok(())
    } else {
        Err(Error::new(format!(
            "resume file differs from exact initialized bytes: {}",
            path.display()
        )))
    }
}

fn sealed_outcome(repository: &Path, root: &Path) -> Result<CalibrationOutcome> {
    let verified = bundle::verify_source(root)?;
    deliver_sealed_calibration(repository, root, &verified.seal.root_sha256)
}

const fn raw_protocol(protocol: Protocol) -> RawProtocol {
    match protocol {
        Protocol::H1 => RawProtocol::H1,
        Protocol::H2 => RawProtocol::H2,
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub mod test_support {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FakeArmObservation {
        pub elapsed_ns: u64,
        pub gateway_ticks: u64,
        pub operations: u64,
        pub signature_sha256: String,
    }

    pub trait FakeArmExecutor {
        fn execute(&mut self, arm: &PlannedArm) -> Result<FakeArmObservation>;
        fn variance_standard_deviation(&self) -> f64;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct FakeResumeState {
        pub completed_prefix: u64,
        pub partially_started_ordinal: Option<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FakeCalibrationResult {
        pub scout_levels: [u8; 15],
        pub selected_n: Option<u32>,
        pub disposition: ParameterDisposition,
        pub completed_arms: u64,
        pub direct_arms: u64,
        pub resumed_prefix: u64,
    }

    pub fn run_fake_calibration<E: FakeArmExecutor>(
        seed: u64,
        executor: &mut E,
        resume: FakeResumeState,
    ) -> Result<FakeCalibrationResult> {
        if let Some(partial) = resume.partially_started_ordinal {
            if partial != resume.completed_prefix {
                return Err(Error::new(
                    "fake resume partial ordinal is not the next prefix arm",
                ));
            }
            return Ok(FakeCalibrationResult {
                scout_levels: [0; 15],
                selected_n: None,
                disposition: ParameterDisposition::QualityBlocked,
                completed_arms: resume.completed_prefix,
                direct_arms: 0,
                resumed_prefix: resume.completed_prefix,
            });
        }
        let scout = process_plan::scout_plan(seed)?;
        let mut ordinal = 0_u64;
        let mut levels = [0_u8; 15];
        for (cell_index, cell) in all_cells().into_iter().enumerate() {
            for (level, target) in calibration::SCOUT_TARGETS.into_iter().enumerate() {
                let templates = scout
                    .attempts
                    .iter()
                    .filter(|arm| arm.cell == cell && arm.target == Some(target))
                    .cloned()
                    .collect::<Vec<_>>();
                let mut records = Vec::with_capacity(5);
                for mut arm in templates {
                    arm.ordinal = ordinal;
                    let observation = fake_execute(executor, &arm, resume.completed_prefix)?;
                    records.push(fake_record(&arm, &observation)?);
                    ordinal += 1;
                }
                match calibration::scout_transition(target, &records) {
                    ScoutTransition::Accept { .. } => {
                        levels[cell_index] = (level + 1) as u8;
                        break;
                    }
                    ScoutTransition::Double { .. } => {}
                    ScoutTransition::Blocked(reason) => {
                        return Err(Error::new(reason.detail));
                    }
                }
            }
            if levels[cell_index] == 0 {
                return Err(Error::new("fake scout did not reach an accepted level"));
            }
        }

        let calibration_plan = process_plan::calibration_plan_with_offset(seed, ordinal)?;
        let first = calibration_plan
            .establishment_ordinals
            .iter()
            .map(|entry| ((entry.cell, entry.arm), entry.ordinal))
            .collect::<BTreeMap<_, _>>();
        let mut signatures = BTreeMap::new();
        let mut max_gateway_rate = BTreeMap::<(crate::schema::Cell, RawProtocol), u64>::new();
        for arm in &calibration_plan.arms {
            let observation = fake_execute(executor, arm, resume.completed_prefix)?;
            let treatment = arm
                .arm
                .ok_or_else(|| Error::new("fake C arm lacks treatment"))?;
            let key = (arm.cell, treatment);
            if first.get(&key) == Some(&arm.ordinal) {
                signatures.insert(key, observation.signature_sha256.clone());
            } else if signatures.get(&key) != Some(&observation.signature_sha256) {
                return Err(Error::new("fake accepted treatment signature mismatch"));
            }
            for protocol in ArmTopology::for_arm(treatment).direct_protocols() {
                max_gateway_rate
                    .entry((arm.cell, raw_protocol(protocol)))
                    .and_modify(|value| *value = (*value).max(observation.operations))
                    .or_insert(observation.operations);
            }
            ordinal += 1;
        }

        let deviation = executor.variance_standard_deviation();
        let variances = hard_comparisons()
            .into_iter()
            .flat_map(|comparison| {
                Metric::ALL.into_iter().map(move |metric| VarianceEstimate {
                    comparison_id: comparison.id.clone(),
                    metric,
                    s_ab: deviation,
                    s_ba: deviation,
                })
            })
            .collect::<Vec<_>>();
        let selection = calibration::select_authoritative_n(&variances)?;
        let (selected_n, disposition) = match selection {
            NSelection::Admissible { n } => (Some(n), ParameterDisposition::Admitted),
            NSelection::RuntimeBlocked { selected_n, .. } => {
                (Some(selected_n), ParameterDisposition::RuntimeBlocked)
            }
            NSelection::PrecisionBlocked { .. } => (None, ParameterDisposition::PrecisionBlocked),
        };
        let mut direct_arms = 0_u64;
        if disposition == ParameterDisposition::Admitted {
            let mut direct_signatures = BTreeMap::new();
            for arm in &calibration_plan.direct_epoch_zero {
                let observation = fake_execute(executor, arm, resume.completed_prefix)?;
                let protocol = raw_protocol(
                    arm.direct_protocol
                        .ok_or_else(|| Error::new("fake D arm lacks protocol"))?,
                );
                let key = (arm.cell, protocol);
                if direct_signatures
                    .insert(key, observation.signature_sha256)
                    .is_some()
                {
                    return Err(Error::new("fake direct signature key duplicated"));
                }
                let gateway = max_gateway_rate
                    .get(&key)
                    .ok_or_else(|| Error::new("fake direct mapping lacks gateway rate"))?;
                if u128::from(observation.operations) * 4 < u128::from(*gateway) * 5 {
                    return Err(Error::new("fake direct ceiling lacks 1.25x headroom"));
                }
                ordinal += 1;
                direct_arms += 1;
            }
        }
        Ok(FakeCalibrationResult {
            scout_levels: levels,
            selected_n,
            disposition,
            completed_arms: ordinal,
            direct_arms,
            resumed_prefix: resume.completed_prefix,
        })
    }

    fn fake_execute<E: FakeArmExecutor>(
        executor: &mut E,
        arm: &PlannedArm,
        completed_prefix: u64,
    ) -> Result<FakeArmObservation> {
        if arm.ordinal < completed_prefix {
            return Ok(FakeArmObservation {
                elapsed_ns: 2_000_000_000,
                gateway_ticks: 100,
                operations: arm.target.unwrap_or(5_000),
                signature_sha256: sha256_hex(format!("{}-{:?}", arm.cell.id(), arm.arm).as_bytes()),
            });
        }
        if arm.ordinal != completed_prefix
            && completed_prefix != 0
            && arm.ordinal < completed_prefix
        {
            return Err(Error::new("fake resume arm prefix is not contiguous"));
        }
        executor.execute(arm)
    }

    fn fake_record(
        arm: &PlannedArm,
        observation: &FakeArmObservation,
    ) -> Result<CalibrationRecord> {
        let target = arm
            .target
            .ok_or_else(|| Error::new("fake scout record lacks target"))?;
        let record = CalibrationRecord {
            schema: crate::schema::EXECUTION_SCHEMA.to_owned(),
            calibration_id: "fake-calibration".to_owned(),
            phase: CalibrationPhase::Scout,
            class: EvidenceClass::S,
            cell: arm.cell,
            arm: arm.arm,
            target: Some(target),
            elapsed_ns: observation.elapsed_ns,
            gateway_ticks: observation.gateway_ticks,
            started_operations: target,
            deadline_completions: target,
            drained_operations: target,
            lane_quotas: arm.lane_quotas.clone(),
            lane_completions: arm.lane_quotas.clone(),
            endpoint_hashes_match: true,
            process_identity: format!("fake-process-{:06}", arm.ordinal),
        };
        record.validate()?;
        Ok(record)
    }
}
