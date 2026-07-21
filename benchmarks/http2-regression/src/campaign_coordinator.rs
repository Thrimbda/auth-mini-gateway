//! Authoritative campaign coordination from a verified calibration design lock.

use crate::build::BuildSet;
use crate::bundle::{self, DeliveryEntry, DeliveryLedger, VerificationReceipt};
use crate::calibration::{AuthoritativeParameters, FileHashBinding, FrozenDurations};
use crate::calibration_coordinator::{ensure_planned_matches_raw, raw_arm_bytes, raw_arm_root};
use crate::delivery::{DeliveryBinding, DeliveryPhase, DeliveryTransaction};
use crate::error::RoleErrorCode;
use crate::evidence::{
    execution_journal_root, ExecutionJournalKind, ExecutionJournalRecord, ExecutionPhase,
    ExecutionStateEvidence, MachineEvidence, ProjectionEvidence, ScheduleEvidence,
    EXECUTION_STATE_SCHEMA, PROJECTION_SCHEMA, SCHEDULE_SCHEMA,
};
use crate::json;
use crate::linux::{clock_ns, filesystem_free_bytes, ClockKind};
use crate::orchestrator::{
    execute_process_arm, retain_interrupted_process_arm, PreMeasureSignaturePolicy,
    ProcessArmRequest,
};
use crate::process_plan::{campaign_plan, CampaignDirectKey, CampaignPlan, PlannedArm};
use crate::raw::{self, ParsedArm, SemanticClass};
use crate::schema::{
    AcceptedSignatureRecord, Arm, BlockedCode, BlockedReason, CalibrationArmBinding,
    CalibrationFrequencyObservation, CalibrationManifest, CampaignCalibrationBinding,
    CampaignDirectBaseline, CampaignManifest, DesignLock, EvidenceClass, EvidenceKind, Intent,
    RawLimits, RawProtocol, TerminalState, TrustBoundaryManifest, ZstdParameterProgram,
    BASELINE_COMMIT, CAMPAIGN_BINDING_SCHEMA, CAMPAIGN_MANIFEST_SCHEMA, COORDINATED_INTENT_SCHEMA,
    MACHINE_SCHEMA, TASK_CAP_BYTES,
};
use crate::seal::{create_seal, sha256_hex};
use crate::statistics::AnalysisResult;
use crate::storage::{
    self, ArmStorageInput, ReachableInventory, ReachedBranchInput, ReachedBranchProjection, MIB,
};
use crate::topology::{ArmTopology, Protocol};
use crate::{Error, Result, ResultContext};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

type AcceptedSignatureBytes =
    BTreeMap<(crate::schema::Cell, Option<Arm>, Option<RawProtocol>), Vec<u8>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignOutcome {
    pub run_id: String,
    pub calibration_id: String,
    pub candidate_commit: String,
    pub evidence_root: String,
    pub terminal_state: TerminalState,
    pub reasons: Vec<String>,
    pub completed_arms: u64,
    pub bundle_index_path: String,
    pub bundle_index_sha256: String,
    pub verification_path: String,
    pub verification_sha256: String,
    pub result_path: String,
    pub result_sha256: String,
    pub report_path: String,
    pub report_sha256: String,
}

struct LoadedCalibration {
    design: DesignLock,
    design_bytes: Vec<u8>,
    design_sha256: String,
    binding: CampaignCalibrationBinding,
    direct_order: Vec<CampaignDirectKey>,
    signature_bytes: BTreeMap<(crate::schema::Cell, Option<Arm>, Option<RawProtocol>), Vec<u8>>,
    latency_ceilings: BTreeMap<(crate::schema::Cell, Arm), u64>,
    machine: MachineEvidence,
}

struct CampaignContext {
    repository: PathBuf,
    root: PathBuf,
    run_id: String,
    design: DesignLock,
    design_bytes: Vec<u8>,
    design_sha256: String,
    binding: CampaignCalibrationBinding,
    binding_sha256: String,
    plan: CampaignPlan,
    plan_sha256: String,
    builds: BuildSet,
    build_set_sha256: String,
    machine: MachineEvidence,
    machine_sha256: String,
    boot_id_sha256: String,
    intent_sha256: String,
    journal: Vec<ExecutionJournalRecord>,
    projections: Vec<FileHashBinding>,
    raw_storage_inputs: Vec<ArmStorageInput>,
}

pub async fn run_campaign(
    repository: &Path,
    candidate: &str,
    calibration: &str,
) -> Result<CampaignOutcome> {
    let host = crate::orchestrator::run_preflight(repository)?;
    if !host.smoke_ready {
        return Err(Error::new(format!(
            "host cannot run authoritative campaign: {}",
            host.blockers.join("; ")
        )));
    }
    let builds = crate::orchestrator::build_exact_pair(repository, candidate)?;
    let current_machine = machine_from_preflight(&host)?;
    let loaded = load_calibration(
        repository,
        candidate,
        calibration,
        &builds,
        &current_machine,
    )?;
    let mut context = initialize(repository, candidate, builds, loaded)?;
    if context.root.join("seal.json").exists() {
        return sealed_outcome(&context.repository, &context.root);
    }
    match run_open_campaign(&mut context).await {
        Ok(outcome) => Ok(outcome),
        Err(error) => finish_campaign(
            &mut context,
            TerminalState::Blocked,
            vec![BlockedReason::new(
                BlockedCode::EvidenceIntegrity,
                error.to_string(),
            )],
        )
        .map_err(|finish| {
            Error::new(format!(
                "campaign failed: {error}; terminal sealing also failed: {finish}"
            ))
        }),
    }
}

fn machine_from_preflight(host: &crate::linux::HostPreflight) -> Result<MachineEvidence> {
    let host_bytes = json::canonical_bytes(host)?;
    let boot_id = fs::read("/proc/sys/kernel/random/boot_id")?;
    let machine = MachineEvidence {
        schema: MACHINE_SCHEMA.to_owned(),
        fingerprint_sha256: sha256_hex(&host_bytes),
        boot_id_sha256: sha256_hex(&boot_id),
        online_cpus: required_host_observation(host, "online_cpus")?.to_owned(),
        clocksource: required_host_observation(host, "clocksource")?.to_owned(),
        clock_ticks_per_second: required_host_observation(host, "clk_tck")?
            .parse::<u64>()
            .context("parse campaign CLK_TCK")?,
        math_abi_sha256: crate::statistics::math_target_sha256(),
    };
    machine.validate()?;
    Ok(machine)
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

fn load_calibration(
    repository: &Path,
    candidate: &str,
    calibration: &str,
    current_builds: &BuildSet,
    current_machine: &MachineEvidence,
) -> Result<LoadedCalibration> {
    let directory = resolve_calibration_directory(repository, calibration)?;
    let index_path = directory.join("bundle-index.json");
    let index_sha256 = sha256_file(&index_path)?;
    let scratch = crate::orchestrator::execution_root(repository)
        .join("campaign-calibration-verify")
        .join(&index_sha256);
    let result = load_calibration_inner(
        repository,
        candidate,
        current_builds,
        current_machine,
        &directory,
        &index_path,
        &index_sha256,
        &scratch,
    );
    if scratch.exists() {
        fs::remove_dir_all(&scratch)?;
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn load_calibration_inner(
    repository: &Path,
    candidate: &str,
    current_builds: &BuildSet,
    current_machine: &MachineEvidence,
    directory: &Path,
    index_path: &Path,
    index_sha256: &str,
    scratch: &Path,
) -> Result<LoadedCalibration> {
    let (receipt, extracted) = bundle::verify_bundle_retained(index_path, scratch)?;
    receipt.validate()?;
    if receipt.terminal_state != TerminalState::Pass {
        return Err(Error::new("calibration bundle is not an admitted PASS"));
    }
    let stored_receipt: VerificationReceipt = json::read_strict(
        &directory.join("verification.json"),
        crate::schema::JSON_MAX_BYTES,
    )?;
    if stored_receipt != receipt {
        return Err(Error::new(
            "stored calibration receipt differs from independent verification",
        ));
    }
    let verified = crate::evidence::verify_raw_closure_structural(&extracted)?;
    if verified.terminal_state != TerminalState::Pass
        || verified.intent.evidence_kind != EvidenceKind::Calibration
        || verified.intent.candidate_commit != candidate
        || verified.intent.producer_executable_sha256 != crate::codec::current_executable_sha256()?
    {
        return Err(Error::new(
            "calibration source identity is blocked, stale, or from another harness",
        ));
    }
    let machine_bytes = fs::read(extracted.join("machine.json"))?;
    let machine: MachineEvidence = json::require_canonical(&machine_bytes)?;
    if &machine != current_machine {
        return Err(Error::new(
            "calibration machine/boot identity differs from the current host",
        ));
    }
    let build_set_bytes = fs::read(extracted.join("build-set.json"))?;
    let builds: BuildSet = json::require_canonical(&build_set_bytes)?;
    if &builds != current_builds {
        return Err(Error::new(
            "calibration build set differs from the exact current candidate pair",
        ));
    }
    let calibration_manifest_bytes = fs::read(extracted.join("calibration-manifest.json"))?;
    let calibration_manifest: CalibrationManifest =
        json::require_canonical(&calibration_manifest_bytes)?;
    calibration_manifest.validate()?;
    if calibration_manifest.terminal_state != TerminalState::Pass
        || !matches!(calibration_manifest.selected_n, Some(30 | 50))
    {
        return Err(Error::new("calibration manifest is blocked or incomplete"));
    }
    let parameters_bytes = fs::read(extracted.join("authoritative-parameters.json"))?;
    let parameters: AuthoritativeParameters = json::require_canonical(&parameters_bytes)?;
    parameters.validate()?;
    if parameters.disposition != crate::calibration::ParameterDisposition::Admitted
        || parameters.selected_n != calibration_manifest.selected_n
    {
        return Err(Error::new(
            "calibration authoritative parameters are not admitted",
        ));
    }
    let state: ExecutionStateEvidence = json::read_strict(
        &extracted.join("execution-state.json"),
        crate::schema::JSON_MAX_BYTES,
    )?;
    let origin = state
        .campaign_boottime_start_ns
        .ok_or_else(|| Error::new("calibration state lacks campaign BOOTTIME origin"))?;

    let design_bytes = fs::read(directory.join("design-lock.json"))?;
    let design: DesignLock = json::require_canonical(&design_bytes)?;
    design.validate()?;
    let recomputed_frequency_p05 =
        crate::calibration_coordinator::derive_frequency_p05_khz(&verified.arms)?;
    let calibration_projection: ProjectionEvidence = json::read_strict(
        &extracted.join("delivery-projection.json"),
        crate::schema::JSON_MAX_BYTES,
    )?;
    let design_sha256 = sha256_hex(&design_bytes);
    if design.calibration_id != verified.intent.evidence_id
        || design.candidate_commit != candidate
        || design.selected_n != calibration_manifest.selected_n.unwrap_or_default()
        || design.calibration_bundle_index_sha256 != index_sha256
        || design.intent_sha256 != sha256_hex(&verified.intent_bytes)
        || design.machine_sha256 != sha256_hex(&machine_bytes)
        || design.build_set_sha256 != sha256_hex(&build_set_bytes)
        || design.calibration_manifest_sha256 != sha256_hex(&calibration_manifest_bytes)
        || design.authoritative_parameters_sha256 != sha256_hex(&parameters_bytes)
        || design.calibration_frequency_p05_khz != recomputed_frequency_p05
        || design.runtime_projection.q_extra_pre_ns != calibration_projection.q_extra_ns
    {
        return Err(Error::new(
            "delivered design lock differs from verified calibration inputs",
        ));
    }
    let continuation_bytes = fs::read(directory.join("continuation-projection.json"))?;
    let continuation: crate::calibration_coordinator::ContinuationProjection =
        json::require_canonical(&continuation_bytes)?;
    continuation.validate()?;
    let profile_bytes = fs::read(directory.join("compression-profile.json"))?;
    let profile: storage::CompressionProfile = json::require_canonical(&profile_bytes)?;
    profile.validate()?;
    if sha256_hex(&continuation_bytes) != design.projection_sha256
        || continuation.calibration_bundle_index_sha256 != index_sha256
        || continuation.compression_profile_sha256 != sha256_hex(&profile_bytes)
        || continuation.runtime != design.runtime_projection
        || continuation.tracked != design.tracked_projection
    {
        return Err(Error::new(
            "calibration continuation/profile hashes differ from design lock",
        ));
    }
    verify_calibration_delivery_ledger(repository, &design, directory, index_sha256)?;

    let direct_order = parameters
        .direct_plan
        .iter()
        .map(|arm| {
            Ok(CampaignDirectKey {
                cell: arm.cell,
                protocol: arm
                    .direct_protocol
                    .ok_or_else(|| Error::new("calibration direct order lacks protocol"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let direct_arms = verified
        .arms
        .iter()
        .filter(|arm| arm.metadata.class == EvidenceClass::D)
        .collect::<Vec<_>>();
    if direct_arms.len() != 30 {
        return Err(Error::new("verified calibration lacks exactly 30 D0 arms"));
    }
    let mut direct_baselines = Vec::with_capacity(30);
    for arm in direct_arms {
        let elapsed_ns = arm
            .operation
            .deadline_ns
            .checked_sub(arm.operation.window_start_ns)
            .ok_or_else(|| Error::new("D0 elapsed underflow"))?;
        direct_baselines.push(CampaignDirectBaseline {
            cell: arm.metadata.cell,
            protocol: arm
                .metadata
                .direct_protocol
                .ok_or_else(|| Error::new("D0 protocol is missing"))?,
            raw_sha256: arm.raw_sha256.clone(),
            deadline_completions: arm.operation.deadline_completions,
            elapsed_ns,
            signature_sha256: arm.thread_map.signature_sha256.clone(),
        });
    }
    direct_baselines.sort_by_key(|baseline| (baseline.cell, baseline.protocol));
    let binding = CampaignCalibrationBinding {
        schema: CAMPAIGN_BINDING_SCHEMA.to_owned(),
        calibration_id: design.calibration_id.clone(),
        calibration_intent: FileHashBinding {
            path: "intent.json".to_owned(),
            sha256: sha256_hex(&verified.intent_bytes),
        },
        calibration_machine: FileHashBinding {
            path: "machine.json".to_owned(),
            sha256: sha256_hex(&machine_bytes),
        },
        calibration_build_set: FileHashBinding {
            path: "build-set.json".to_owned(),
            sha256: sha256_hex(&build_set_bytes),
        },
        calibration_plan: FileHashBinding {
            path: "calibration-plan.json".to_owned(),
            sha256: sha256_file(&extracted.join("calibration-plan.json"))?,
        },
        authoritative_parameters: FileHashBinding {
            path: "authoritative-parameters.json".to_owned(),
            sha256: sha256_hex(&parameters_bytes),
        },
        calibration_manifest: FileHashBinding {
            path: "calibration-manifest.json".to_owned(),
            sha256: sha256_hex(&calibration_manifest_bytes),
        },
        calibration_projection: FileHashBinding {
            path: "delivery-projection.json".to_owned(),
            sha256: sha256_file(&extracted.join("delivery-projection.json"))?,
        },
        calibration_seal_root_sha256: verified.seal.root_sha256.clone(),
        calibration_bundle_index: FileHashBinding {
            path: repository_relative(repository, index_path)?,
            sha256: index_sha256.to_owned(),
        },
        calibration_verification: FileHashBinding {
            path: repository_relative(repository, &directory.join("verification.json"))?,
            sha256: sha256_file(&directory.join("verification.json"))?,
        },
        compression_profile: FileHashBinding {
            path: repository_relative(repository, &directory.join("compression-profile.json"))?,
            sha256: sha256_hex(&profile_bytes),
        },
        continuation_projection: FileHashBinding {
            path: repository_relative(repository, &directory.join("continuation-projection.json"))?,
            sha256: sha256_hex(&continuation_bytes),
        },
        campaign_boottime_origin_ns: origin,
        calibration_frequency_observations: verified
            .arms
            .iter()
            .filter(|arm| arm.metadata.class == EvidenceClass::C)
            .map(|arm| CalibrationFrequencyObservation {
                ordinal: arm.metadata.ordinal,
                raw_sha256: arm.raw_sha256.clone(),
                median_frequency_khz: arm.resources.median_frequency_khz,
            })
            .collect(),
        direct_baselines,
    };
    binding.validate(&design)?;

    let mut signature_bytes = BTreeMap::new();
    for signature in design
        .treatment_signatures
        .iter()
        .chain(&design.direct_signatures)
    {
        let bytes = fs::read(extracted.join(&signature.record_path))?;
        if sha256_hex(&bytes) != signature.record_sha256 {
            return Err(Error::new("accepted calibration signature hash drifted"));
        }
        let record: AcceptedSignatureRecord = json::require_canonical(&bytes)?;
        record.validate()?;
        if record.calibration_id != design.calibration_id
            || record.calibration_plan_sha256 != design.calibration_plan_sha256
            || record.signature_sha256 != signature.signature_sha256
        {
            return Err(Error::new(
                "accepted signature record differs from design lock",
            ));
        }
        signature_bytes.insert((record.cell, record.arm, record.direct_protocol), bytes);
    }
    if signature_bytes.len() != 105 {
        return Err(Error::new(
            "campaign did not load exactly 75 treatment and 30 direct signatures",
        ));
    }
    let latency_ceilings = calibration_latency_ceilings(&verified.arms, &parameters)?;
    Ok(LoadedCalibration {
        design,
        design_bytes,
        design_sha256,
        binding,
        direct_order,
        signature_bytes,
        latency_ceilings,
        machine,
    })
}

fn resolve_calibration_directory(repository: &Path, value: &str) -> Result<PathBuf> {
    let supplied = Path::new(value);
    let path = if supplied.components().count() > 1 || supplied.is_absolute() || supplied.exists() {
        bundle::ensure_repository_local(supplied, repository)?
    } else {
        artifact_root(repository)
            .join("bundles/calibration")
            .join(value)
    };
    let directory = if path.is_file() {
        path.parent()
            .ok_or_else(|| Error::new("calibration path has no parent"))?
            .to_path_buf()
    } else {
        path
    };
    if !directory.join("bundle-index.json").is_file()
        || !directory.join("verification.json").is_file()
        || !directory.join("design-lock.json").is_file()
        || !directory.join("continuation-projection.json").is_file()
    {
        return Err(Error::new(
            "calibration reference is not a complete delivered design",
        ));
    }
    Ok(directory)
}

fn verify_calibration_delivery_ledger(
    repository: &Path,
    design: &DesignLock,
    directory: &Path,
    index_sha256: &str,
) -> Result<()> {
    let ledger: DeliveryLedger = json::read_strict(
        &artifact_root(repository).join("delivery-index.json"),
        crate::schema::JSON_MAX_BYTES,
    )?;
    ledger.validate()?;
    let entry = ledger
        .entries
        .iter()
        .find(|entry| {
            entry.evidence_kind == EvidenceKind::Calibration
                && entry.evidence_id == design.calibration_id
        })
        .ok_or_else(|| Error::new("calibration is absent from additive delivery ledger"))?;
    let design_sha256 = sha256_file(&directory.join("design-lock.json"))?;
    let continuation_sha256 = sha256_file(&directory.join("continuation-projection.json"))?;
    if entry.bundle_index_sha256 != index_sha256
        || entry.verification_sha256 != sha256_file(&directory.join("verification.json"))?
        || entry.design_lock_sha256.as_deref() != Some(design_sha256.as_str())
        || entry.continuation_projection_sha256.as_deref() != Some(continuation_sha256.as_str())
        || entry.seal_root_sha256 != design.calibration_seal_root_sha256
        || entry.outcome != TerminalState::Pass
    {
        return Err(Error::new(
            "calibration delivery ledger entry differs from delivered files",
        ));
    }
    Ok(())
}

pub(crate) fn calibration_latency_ceilings(
    arms: &[ParsedArm],
    parameters: &AuthoritativeParameters,
) -> Result<BTreeMap<(crate::schema::Cell, Arm), u64>> {
    let durations = parameters
        .authoritative_durations
        .iter()
        .map(|entry| (entry.cell, entry.durations))
        .collect::<BTreeMap<_, _>>();
    let mut ceilings = BTreeMap::new();
    for cell in crate::schema::all_cells() {
        for treatment in Arm::ALL {
            let matching = arms
                .iter()
                .filter(|arm| {
                    arm.metadata.class == EvidenceClass::C
                        && arm.metadata.cell == cell
                        && arm.metadata.arm == Some(treatment)
                })
                .collect::<Vec<_>>();
            if matching.len() != 10 {
                return Err(Error::new(
                    "calibration latency projection lacks ten treatment observations",
                ));
            }
            let max_started = matching
                .iter()
                .map(|arm| arm.operation.started_operations)
                .max()
                .ok_or_else(|| Error::new("calibration latency match is empty"))?;
            let calibration_ns = matching[0]
                .operation
                .deadline_ns
                .checked_sub(matching[0].operation.window_start_ns)
                .ok_or_else(|| Error::new("calibration latency duration underflow"))?;
            let future_ns = durations
                .get(&cell)
                .ok_or_else(|| Error::new("authoritative duration is missing"))?
                .measure_seconds
                .checked_add(2)
                .and_then(|seconds| seconds.checked_mul(1_000_000_000))
                .ok_or_else(|| Error::new("authoritative latency duration overflow"))?;
            let numerator = u128::from(max_started)
                .checked_mul(2)
                .and_then(|value| value.checked_mul(u128::from(future_ns)))
                .ok_or_else(|| Error::new("authoritative latency projection overflow"))?;
            let projected = ceil_div_u128(numerator, u128::from(calibration_ns))?;
            let value = u64::from(cell.concurrency)
                .checked_add(
                    u64::try_from(projected)
                        .map_err(|_| Error::new("authoritative latency ceiling overflow"))?,
                )
                .ok_or_else(|| Error::new("authoritative latency ceiling overflow"))?;
            ceilings.insert((cell, treatment), value);
        }
    }
    Ok(ceilings)
}

fn initialize(
    repository: &Path,
    candidate: &str,
    builds: BuildSet,
    loaded: LoadedCalibration,
) -> Result<CampaignContext> {
    let run_id = format!(
        "run-{}-{}-{:016x}",
        &candidate[..12],
        &loaded.design_sha256[..12],
        loaded.design.schedule_seed
    );
    let root = crate::orchestrator::execution_root(repository)
        .join("runs")
        .join(&run_id);
    let build_set_bytes = json::canonical_bytes(&builds)?;
    let build_set_sha256 = sha256_hex(&build_set_bytes);
    let harness_provenance = crate::harness::require_exact_committed_harness(repository)?;
    let intent = Intent {
        schema: COORDINATED_INTENT_SCHEMA.to_owned(),
        evidence_id: run_id.clone(),
        evidence_kind: EvidenceKind::Campaign,
        baseline_commit: BASELINE_COMMIT.to_owned(),
        candidate_commit: candidate.to_owned(),
        campaign_seed: loaded.design.schedule_seed,
        encoder: crate::codec::current_identity(),
        producer_executable_sha256: crate::codec::current_executable_sha256()?,
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
    let machine_bytes = json::canonical_bytes(&loaded.machine)?;
    let machine_sha256 = sha256_hex(&machine_bytes);
    let binding_bytes = json::canonical_bytes(&loaded.binding)?;
    let binding_sha256 = sha256_hex(&binding_bytes);
    let plan = campaign_plan(
        &run_id,
        &loaded.design,
        &loaded.design_sha256,
        &loaded.direct_order,
    )?;
    let plan_bytes = json::canonical_bytes(&plan)?;
    let plan_sha256 = sha256_hex(&plan_bytes);
    let schedule = ScheduleEvidence {
        schema: SCHEDULE_SCHEMA.to_owned(),
        seed: loaded.design.schedule_seed,
        n: loaded.design.selected_n,
        rounds: loaded.design.rounds.clone(),
    };
    schedule.validate(&loaded.design)?;
    let schedule_bytes = json::canonical_bytes(&schedule)?;

    if !root.exists() {
        fs::create_dir_all(
            root.parent()
                .ok_or_else(|| Error::new("campaign root has no parent"))?,
        )?;
        fs::create_dir(&root).context("exclusive-create campaign root")?;
        set_mode(&root, 0o700)?;
        json::write_new_bytes(&root.join("intent.json"), &intent_bytes)?;
        json::write_new_bytes(&root.join("build-set.json"), &build_set_bytes)?;
        json::write_new_bytes(&root.join("machine.json"), &machine_bytes)?;
        json::write_new_bytes(&root.join("design-lock.json"), &loaded.design_bytes)?;
        json::write_new_bytes(&root.join("calibration-binding.json"), &binding_bytes)?;
        json::write_new_bytes(&root.join("campaign-plan.json"), &plan_bytes)?;
        json::write_new_bytes(&root.join("schedule.json"), &schedule_bytes)?;
        fs::create_dir(root.join("state"))?;
        fs::create_dir(root.join("projections"))?;
        write_accepted_signatures(&root, &loaded.signature_bytes)?;
    } else {
        if root.join("seal.json").exists() {
            return Ok(CampaignContext {
                repository: repository.to_path_buf(),
                root,
                run_id,
                design: loaded.design,
                design_bytes: loaded.design_bytes,
                design_sha256: loaded.design_sha256,
                binding: loaded.binding,
                binding_sha256,
                plan,
                plan_sha256,
                builds,
                build_set_sha256,
                machine: loaded.machine.clone(),
                machine_sha256,
                boot_id_sha256: loaded.machine.boot_id_sha256,
                intent_sha256,
                journal: Vec::new(),
                projections: Vec::new(),
                raw_storage_inputs: Vec::new(),
            });
        }
        for (path, bytes) in [
            ("intent.json", intent_bytes.as_slice()),
            ("build-set.json", build_set_bytes.as_slice()),
            ("machine.json", machine_bytes.as_slice()),
            ("design-lock.json", loaded.design_bytes.as_slice()),
            ("calibration-binding.json", binding_bytes.as_slice()),
            ("campaign-plan.json", plan_bytes.as_slice()),
            ("schedule.json", schedule_bytes.as_slice()),
        ] {
            require_file_bytes(&root.join(path), bytes)?;
        }
        write_accepted_signatures(&root, &loaded.signature_bytes)?;
    }

    let mut journal = read_journal(&root)?;
    if journal.is_empty() {
        append_journal_record(
            &root,
            &mut journal,
            JournalInput {
                run_id: &run_id,
                kind: ExecutionJournalKind::CampaignStart,
                phase: ExecutionPhase::AuthoritativeDirect,
                ordinal: None,
                boottime_ns: clock_ns(ClockKind::Boottime)?,
                boot_id_sha256: &loaded.machine.boot_id_sha256,
                machine_sha256: &machine_sha256,
                build_set_sha256: &build_set_sha256,
                plan_sha256: &plan_sha256,
                raw: None,
            },
        )?;
    }
    let projections = read_projection_bindings(&root)?;
    let raw_storage_inputs = raw_storage_inputs(&plan, &loaded.design, &loaded.latency_ceilings)?;
    let mut context = CampaignContext {
        repository: repository.to_path_buf(),
        root,
        run_id,
        design: loaded.design,
        design_bytes: loaded.design_bytes,
        design_sha256: loaded.design_sha256,
        binding: loaded.binding,
        binding_sha256,
        plan,
        plan_sha256,
        builds,
        build_set_sha256,
        machine: loaded.machine.clone(),
        machine_sha256,
        boot_id_sha256: loaded.machine.boot_id_sha256,
        intent_sha256,
        journal,
        projections,
        raw_storage_inputs,
    };
    validate_resume_prefix(&context)?;
    if context.projections.is_empty() {
        write_projection_revision(&mut context, "authoritative-continuation", false)?;
    }
    Ok(context)
}

fn write_accepted_signatures(root: &Path, signatures: &AcceptedSignatureBytes) -> Result<()> {
    for ((cell, arm, protocol), bytes) in signatures {
        let name = arm
            .map(Arm::code)
            .or_else(|| protocol.map(raw_protocol_label))
            .ok_or_else(|| Error::new("accepted campaign signature key is empty"))?;
        let path = root
            .join("accepted-signatures")
            .join(cell.id())
            .join(format!("{name}.json"));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if path.exists() {
            require_file_bytes(&path, bytes)?;
        } else {
            json::write_new_bytes(&path, bytes)?;
        }
    }
    Ok(())
}

pub(crate) fn raw_storage_inputs(
    plan: &CampaignPlan,
    design: &DesignLock,
    latency_ceilings: &BTreeMap<(crate::schema::Cell, Arm), u64>,
) -> Result<Vec<ArmStorageInput>> {
    let durations = design
        .authoritative_durations
        .iter()
        .map(|entry| (entry.cell, entry.durations))
        .collect::<BTreeMap<_, _>>();
    let mut inputs = Vec::with_capacity(plan.arms.len());
    for arm in &plan.arms {
        let duration = crate::calibration::arm_cap_ns(
            arm.cell,
            *durations
                .get(&arm.cell)
                .ok_or_else(|| Error::new("campaign storage lacks cell durations"))?,
        )?;
        let latency_records = if arm.evidence_class == EvidenceClass::A {
            *latency_ceilings
                .get(&(
                    arm.cell,
                    arm.arm
                        .ok_or_else(|| Error::new("authoritative storage arm lacks treatment"))?,
                ))
                .ok_or_else(|| Error::new("authoritative storage lacks latency ceiling"))?
        } else {
            0
        };
        let input = ArmStorageInput {
            class: arm.evidence_class,
            gateway: arm.evidence_class == EvidenceClass::A,
            duration_ns: duration,
            tid_slots: 32,
            lifecycle_events: 4_096,
            connection_records: 136 + u64::from(arm.cell.concurrency),
            latency_records,
            concurrency: u64::from(arm.cell.concurrency),
        };
        storage::component_bounds(&input)?;
        inputs.push(input);
    }
    Ok(inputs)
}

async fn run_open_campaign(context: &mut CampaignContext) -> Result<CampaignOutcome> {
    let arms = context.plan.arms.clone();
    let durations = context
        .design
        .authoritative_durations
        .iter()
        .map(|entry| (entry.cell, entry.durations))
        .collect::<BTreeMap<_, _>>();
    for planned in &arms {
        ensure_runtime_storage(context, planned.ordinal)?;
        let signature_path = accepted_signature_path(&context.root, planned)?;
        let frozen = *durations
            .get(&planned.cell)
            .ok_or_else(|| Error::new("campaign arm lacks frozen duration"))?;
        if let Err(error) = run_or_recover_arm(context, planned, frozen, &signature_path).await {
            let terminal = terminal_for_arm_error(planned, &error);
            return finish_campaign(
                context,
                terminal,
                vec![BlockedReason::new(
                    BlockedCode::EvidenceIntegrity,
                    error.to_string(),
                )],
            );
        }
        let raw = raw_arm_by_ordinal(&context.root, planned.ordinal)?;
        match raw.semantic_class() {
            SemanticClass::CandidateFailure => {
                return finish_campaign(
                    context,
                    TerminalState::Fail,
                    vec![BlockedReason::new(
                        BlockedCode::EvidenceIntegrity,
                        format!(
                            "candidate semantic failure in {}",
                            raw.metadata.observation_id
                        ),
                    )],
                );
            }
            SemanticClass::IntegrityFailure | SemanticClass::BaselineFailure => {
                return finish_campaign(
                    context,
                    TerminalState::Blocked,
                    vec![BlockedReason::new(
                        BlockedCode::EvidenceIntegrity,
                        format!("invalid authoritative arm {}", raw.metadata.observation_id),
                    )],
                );
            }
            SemanticClass::Ok => {}
        }
        if !raw.quality_clean() {
            return finish_campaign(
                context,
                TerminalState::Blocked,
                vec![BlockedReason::new(
                    BlockedCode::Noise,
                    format!(
                        "authoritative arm {} failed quality",
                        raw.metadata.observation_id
                    ),
                )],
            );
        }
        if planned.evidence_class == EvidenceClass::D {
            enforce_direct_drift(&context.binding, &raw)?;
        } else {
            enforce_gateway_headroom(&context.root, &raw)?;
        }
        ensure_runtime_storage(context, planned.ordinal + 1)?;
        if (planned.ordinal + 1).is_multiple_of(780) {
            write_projection_revision(
                context,
                &format!("authoritative-prefix-{}", planned.ordinal + 1),
                false,
            )?;
        }
    }
    let completed = parse_raw_arms(&context.root)?;
    if let Err(error) = verify_campaign_raw_gates(&context.binding, &context.design, &completed) {
        return finish_campaign(
            context,
            TerminalState::Blocked,
            vec![BlockedReason::new(
                BlockedCode::EvidenceIntegrity,
                error.to_string(),
            )],
        );
    }
    finish_campaign(context, TerminalState::Pass, Vec::new())
}

async fn run_or_recover_arm(
    context: &mut CampaignContext,
    planned: &PlannedArm,
    durations: FrozenDurations,
    signature_path: &Path,
) -> Result<()> {
    let existing = parse_raw_arms(&context.root)?;
    if planned.ordinal < existing.len() as u64 {
        let parsed = &existing[usize::try_from(planned.ordinal)
            .map_err(|_| Error::new("campaign ordinal overflow"))?];
        ensure_planned_matches_raw(planned, parsed)?;
        if partially_started_ordinal(&context.journal) == Some(planned.ordinal) {
            append_arm_complete(context, planned, parsed)?;
        }
        return Ok(());
    }
    if planned.ordinal != existing.len() as u64 {
        return Err(Error::new("campaign raw leaves are not an exact prefix"));
    }
    if partially_started_ordinal(&context.journal) == Some(planned.ordinal) {
        retain_interrupted_process_arm(
            &context.repository,
            &context.root,
            &context.run_id,
            &context.run_id,
            planned,
        )?;
        return Err(Error::new(format!(
            "campaign arm {} was partially started and cannot resume",
            planned.ordinal
        )));
    }
    append_simple_journal(
        context,
        ExecutionJournalKind::ArmStart,
        phase_for_class(planned.evidence_class),
        Some(planned.ordinal),
        None,
    )?;
    execute_process_arm(
        &context.repository,
        &context.builds,
        &context.root,
        ProcessArmRequest {
            evidence_id: &context.run_id,
            run_id: &context.run_id,
            planned,
            raw_ordinal: planned.ordinal,
            warmup_seconds: durations.warmup_seconds,
            measure_seconds: Some(durations.measure_seconds),
            calibration_plan_sha256: Some(&context.design.calibration_plan_sha256),
            signature_policy: PreMeasureSignaturePolicy::Require {
                accepted_record: signature_path,
            },
            trust_boundary: coordinated_trust_boundary(&context.root)?,
            frequency_gate: crate::orchestrator::FrequencyGate::AuthoritativeRelative {
                calibration_p05_khz: context.design.calibration_frequency_p05_khz,
            },
        },
    )
    .await?;
    let parsed = raw_arm_by_ordinal(&context.root, planned.ordinal)?;
    ensure_planned_matches_raw(planned, &parsed)?;
    append_arm_complete(context, planned, &parsed)
}

fn coordinated_trust_boundary(root: &Path) -> Result<TrustBoundaryManifest> {
    let intent: Intent =
        json::read_strict(&root.join("intent.json"), crate::schema::JSON_MAX_BYTES)?;
    intent.validate()?;
    intent
        .trust_boundary
        .ok_or_else(|| Error::new("coordinated campaign intent lacks trust-boundary manifest"))
}

fn append_arm_complete(
    context: &mut CampaignContext,
    planned: &PlannedArm,
    parsed: &ParsedArm,
) -> Result<()> {
    let relative = repository_relative(&context.root, &parsed.leaf)?;
    append_simple_journal(
        context,
        ExecutionJournalKind::ArmComplete,
        phase_for_class(planned.evidence_class),
        Some(planned.ordinal),
        Some((relative, parsed.raw_sha256.clone())),
    )
}

fn accepted_signature_path(root: &Path, planned: &PlannedArm) -> Result<PathBuf> {
    let name = planned
        .arm
        .map(Arm::code)
        .or_else(|| planned.direct_protocol.map(Protocol::label))
        .ok_or_else(|| Error::new("campaign signature key is empty"))?;
    Ok(root
        .join("accepted-signatures")
        .join(planned.cell.id())
        .join(format!("{name}.json")))
}

fn enforce_direct_drift(binding: &CampaignCalibrationBinding, direct: &ParsedArm) -> Result<()> {
    let protocol = direct
        .metadata
        .direct_protocol
        .ok_or_else(|| Error::new("authoritative direct protocol is missing"))?;
    let baseline = binding
        .direct_baselines
        .iter()
        .find(|entry| entry.cell == direct.metadata.cell && entry.protocol == protocol)
        .ok_or_else(|| Error::new("authoritative direct lacks exact D0 baseline"))?;
    if !rates_within_ten_percent(
        direct.operation.deadline_completions,
        arm_elapsed(direct)?,
        baseline.deadline_completions,
        baseline.elapsed_ns,
    )? {
        return Err(Error::new(format!(
            "authoritative direct {:?} {} drifted outside +/-10% of D0",
            protocol,
            direct.metadata.cell.id()
        )));
    }
    Ok(())
}

fn enforce_gateway_headroom(root: &Path, gateway: &ParsedArm) -> Result<()> {
    let epoch = gateway
        .metadata
        .round
        .ok_or_else(|| Error::new("authoritative gateway round is missing"))?
        / 10
        + 1;
    let treatment = gateway
        .metadata
        .arm
        .ok_or_else(|| Error::new("authoritative gateway treatment is missing"))?;
    let arms = parse_raw_arms(root)?;
    for protocol in ArmTopology::for_arm(treatment).direct_protocols() {
        let direct = arms
            .iter()
            .find(|arm| {
                arm.metadata.class == EvidenceClass::D
                    && arm.metadata.epoch == Some(epoch)
                    && arm.metadata.cell == gateway.metadata.cell
                    && arm.metadata.direct_protocol == Some(raw_protocol(protocol))
            })
            .ok_or_else(|| Error::new("mapped authoritative direct ceiling is missing"))?;
        if !rate_has_headroom(direct, gateway)? {
            return Err(Error::new(format!(
                "mapped direct {} {} lacks 1.25x authoritative headroom",
                protocol.label(),
                gateway.metadata.cell.id()
            )));
        }
    }
    Ok(())
}

pub(crate) fn verify_campaign_raw_gates(
    binding: &CampaignCalibrationBinding,
    design: &DesignLock,
    arms: &[ParsedArm],
) -> Result<()> {
    let durations = design
        .authoritative_durations
        .iter()
        .map(|entry| (entry.cell, entry.durations))
        .collect::<BTreeMap<_, _>>();
    for arm in arms {
        let expected_signature = match arm.metadata.class {
            EvidenceClass::D => design.direct_signatures.iter().find(|binding| {
                binding.cell == arm.metadata.cell
                    && binding.direct_protocol == arm.metadata.direct_protocol
                    && binding.arm.is_none()
            }),
            EvidenceClass::A => design.treatment_signatures.iter().find(|binding| {
                binding.cell == arm.metadata.cell
                    && binding.arm == arm.metadata.arm
                    && binding.direct_protocol.is_none()
            }),
            _ => None,
        }
        .ok_or_else(|| Error::new("campaign arm lacks its accepted signature binding"))?;
        if arm.thread_map.signature_sha256 != expected_signature.signature_sha256 {
            return Err(Error::new(
                "campaign arm thread signature differs from the design lock",
            ));
        }
        if arm.resources.calibration_frequency_p05_khz != Some(design.calibration_frequency_p05_khz)
        {
            return Err(Error::new(
                "campaign arm frequency reference differs from the design lock",
            ));
        }
        let expected_ns = durations
            .get(&arm.metadata.cell)
            .ok_or_else(|| Error::new("campaign arm lacks frozen cell duration"))?
            .measure_seconds
            .checked_mul(1_000_000_000)
            .ok_or_else(|| Error::new("campaign frozen duration overflow"))?;
        if arm_elapsed(arm)? != expected_ns {
            return Err(Error::new(
                "campaign arm measurement window differs from design lock",
            ));
        }
        if arm.metadata.class == EvidenceClass::D {
            enforce_direct_drift(binding, arm)?;
        } else if arm.metadata.class == EvidenceClass::A {
            verify_gateway_headroom_from_arms(arms, arm)?;
        }
    }
    Ok(())
}

fn verify_gateway_headroom_from_arms(arms: &[ParsedArm], gateway: &ParsedArm) -> Result<()> {
    let epoch = gateway
        .metadata
        .round
        .ok_or_else(|| Error::new("authoritative gateway round is missing"))?
        / 10
        + 1;
    let treatment = gateway
        .metadata
        .arm
        .ok_or_else(|| Error::new("authoritative gateway treatment is missing"))?;
    for protocol in ArmTopology::for_arm(treatment).direct_protocols() {
        let direct = arms
            .iter()
            .find(|arm| {
                arm.metadata.class == EvidenceClass::D
                    && arm.metadata.epoch == Some(epoch)
                    && arm.metadata.cell == gateway.metadata.cell
                    && arm.metadata.direct_protocol == Some(raw_protocol(protocol))
            })
            .ok_or_else(|| Error::new("mapped authoritative direct ceiling is missing"))?;
        if !rate_has_headroom(direct, gateway)? {
            return Err(Error::new(
                "mapped authoritative direct ceiling lacks 1.25x headroom",
            ));
        }
    }
    Ok(())
}

fn rate_has_headroom(direct: &ParsedArm, gateway: &ParsedArm) -> Result<bool> {
    let left = u128::from(direct.operation.deadline_completions)
        .checked_mul(u128::from(arm_elapsed(gateway)?))
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| Error::new("campaign headroom numerator overflow"))?;
    let right = u128::from(gateway.operation.deadline_completions)
        .checked_mul(u128::from(arm_elapsed(direct)?))
        .and_then(|value| value.checked_mul(5))
        .ok_or_else(|| Error::new("campaign headroom threshold overflow"))?;
    Ok(left >= right)
}

fn rates_within_ten_percent(
    current: u64,
    current_elapsed: u64,
    baseline: u64,
    baseline_elapsed: u64,
) -> Result<bool> {
    if current_elapsed == 0 || baseline_elapsed == 0 {
        return Err(Error::new("campaign direct drift has a zero elapsed input"));
    }
    let scaled_current = u128::from(current)
        .checked_mul(u128::from(baseline_elapsed))
        .ok_or_else(|| Error::new("campaign direct drift overflow"))?;
    let scaled_baseline = u128::from(baseline)
        .checked_mul(u128::from(current_elapsed))
        .ok_or_else(|| Error::new("campaign direct drift overflow"))?;
    Ok(scaled_current * 10 >= scaled_baseline * 9 && scaled_current * 10 <= scaled_baseline * 11)
}

fn arm_elapsed(arm: &ParsedArm) -> Result<u64> {
    arm.operation
        .deadline_ns
        .checked_sub(arm.operation.window_start_ns)
        .ok_or_else(|| Error::new("campaign arm elapsed underflow"))
}

fn terminal_for_arm_error(planned: &PlannedArm, error: &Error) -> TerminalState {
    let candidate = planned.evidence_class == EvidenceClass::A && planned.arm != Some(Arm::B11);
    if candidate
        && error.role_code().is_some_and(|code| {
            matches!(
                code,
                RoleErrorCode::ResponseHeadInvalid
                    | RoleErrorCode::ResponseBodyInvalid
                    | RoleErrorCode::ConnectionCloseMissing
                    | RoleErrorCode::PeerEofMissing
                    | RoleErrorCode::PayloadMismatch
                    | RoleErrorCode::LedgerMismatch
            )
        })
    {
        TerminalState::Fail
    } else {
        TerminalState::Blocked
    }
}

fn ensure_runtime_storage(context: &CampaignContext, next_ordinal: u64) -> Result<()> {
    let elapsed = clock_ns(ClockKind::Boottime)?
        .checked_sub(context.binding.campaign_boottime_origin_ns)
        .ok_or_else(|| Error::new("campaign BOOTTIME moved backwards"))?;
    if elapsed > crate::calibration::ACTUAL_CAP_NS {
        return Err(Error::new(
            "actual calibration/campaign runtime exceeds 48 hours",
        ));
    }
    let arms = parse_raw_arms(&context.root)?;
    if campaign_wide_q_extra(context, &arms)? > crate::calibration::Q_EXTRA_CAP_NS {
        return Err(Error::new(
            "campaign-wide Q_extra exceeds the fixed two-hour cap",
        ));
    }
    let projection = campaign_storage_admission(
        context,
        &format!("authoritative-{next_ordinal}"),
        next_ordinal,
        false,
    )?;
    if !projection.admissible {
        return Err(Error::new(format!(
            "campaign raw storage requires more than {} free bytes",
            projection.raw.required_free_bytes_exclusive
        )));
    }
    let tracked = storage::actual_regular_bytes_if_exists(&artifact_root(&context.repository))?;
    if tracked > TASK_CAP_BYTES || tracked > context.design.tracked_projection.projected_total_bytes
    {
        return Err(Error::new(
            "campaign tracked storage exceeds its admitted calibration projection",
        ));
    }
    Ok(())
}

fn campaign_storage_admission(
    context: &CampaignContext,
    gate_id: &str,
    next_ordinal: u64,
    final_delivery: bool,
) -> Result<ReachedBranchProjection> {
    let index = usize::try_from(next_ordinal)
        .map_err(|_| Error::new("campaign storage ordinal overflow"))?;
    let future_inputs = context
        .raw_storage_inputs
        .get(index..)
        .ok_or_else(|| Error::new("campaign storage ordinal exceeds plan"))?;
    let direct = u64::try_from(
        future_inputs
            .iter()
            .filter(|input| input.class == EvidenceClass::D)
            .count(),
    )
    .map_err(|_| Error::new("campaign direct inventory exceeds u64"))?;
    let authoritative = u64::try_from(
        future_inputs
            .iter()
            .filter(|input| input.class == EvidenceClass::A)
            .count(),
    )
    .map_err(|_| Error::new("campaign authoritative inventory exceeds u64"))?;
    let completed = campaign_regular_member_lengths(&context.root)?;
    let units = vec![MIB; if final_delivery { 6 } else { 8 }];
    let tracked_actual =
        storage::actual_regular_bytes_if_exists(&artifact_root(&context.repository))?;
    let admitted_remaining = context
        .design
        .tracked_projection
        .projected_total_bytes
        .saturating_sub(tracked_actual);
    let inventory = ReachableInventory {
        scout: 0,
        williams: 0,
        direct,
        authoritative,
    };
    let mut projection = storage::reached_branch_projection(ReachedBranchInput {
        gate_id,
        next_ordinal,
        inventory,
        completed_member_lengths: &completed,
        future_arms: future_inputs,
        future_unit_member_lengths: &units,
        encoder_workspace_bytes: 8 * MIB,
        observed_free_bytes: filesystem_free_bytes(&context.repository)?,
        tracked_actual_bytes: tracked_actual,
        tracked_remaining_maximum_bytes: admitted_remaining,
    })?;
    if final_delivery {
        let remaining = projection
            .compressed_bound_bytes
            .checked_add(5 * MIB)
            .ok_or_else(|| Error::new("campaign final delivery bound overflow"))?;
        projection = storage::reached_branch_projection(ReachedBranchInput {
            gate_id,
            next_ordinal,
            inventory,
            completed_member_lengths: &completed,
            future_arms: future_inputs,
            future_unit_member_lengths: &units,
            encoder_workspace_bytes: 8 * MIB,
            observed_free_bytes: filesystem_free_bytes(&context.repository)?,
            tracked_actual_bytes: tracked_actual,
            tracked_remaining_maximum_bytes: remaining,
        })?;
    }
    Ok(projection)
}

fn campaign_regular_member_lengths(root: &Path) -> Result<Vec<u64>> {
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
                    "campaign storage source contains a link or special file",
                ));
            }
        }
        Ok(())
    }
    let mut lengths = Vec::new();
    collect(root, &mut lengths)?;
    Ok(lengths)
}

fn finish_campaign(
    context: &mut CampaignContext,
    requested_terminal: TerminalState,
    reasons: Vec<BlockedReason>,
) -> Result<CampaignOutcome> {
    if context.root.join("seal.json").exists() {
        return sealed_outcome(&context.repository, &context.root);
    }
    let arms = parse_raw_arms(&context.root)?;
    let completed_arms = arms.len() as u64;
    let partial = partially_started_ordinal(&context.journal);
    let terminal_state = if requested_terminal == TerminalState::Pass
        && completed_arms == context.plan.arms.len() as u64
        && partial.is_none()
    {
        TerminalState::Pass
    } else if requested_terminal == TerminalState::Fail {
        TerminalState::Fail
    } else {
        TerminalState::Blocked
    };
    let mut reason_text = reasons
        .iter()
        .map(|reason| format!("{:?}: {}", reason.code, reason.detail))
        .collect::<Vec<_>>();
    if let Some(ordinal) = partial {
        reason_text.push(format!(
            "campaign arm ordinal {ordinal} started without durable completion; resume forbidden"
        ));
    }
    reason_text.sort();
    reason_text.dedup();
    let end = clock_ns(ClockKind::Boottime)?;
    let state = ExecutionStateEvidence {
        schema: EXECUTION_STATE_SCHEMA.to_owned(),
        evidence_id: context.run_id.clone(),
        phase: ExecutionPhase::Complete,
        next_ordinal: completed_arms,
        planned_arms: if terminal_state == TerminalState::Pass {
            context.plan.arms.len() as u64
        } else {
            completed_arms
        },
        completed_arms,
        complete: true,
        crash_detail: (terminal_state != TerminalState::Pass).then(|| reason_text.join("; ")),
        campaign_boottime_start_ns: Some(context.binding.campaign_boottime_origin_ns),
        campaign_boottime_end_ns: Some(end),
        machine_sha256: Some(context.machine_sha256.clone()),
        build_set_sha256: Some(context.build_set_sha256.clone()),
        journal_root_sha256: Some(execution_journal_root(&context.journal)?),
        partially_started_ordinal: partial,
    };
    state.validate()?;
    json::write_new_canonical(&context.root.join("execution-state.json"), &state)?;
    let state_sha256 = sha256_file(&context.root.join("execution-state.json"))?;
    write_projection_revision(context, "final-delivery", true)?;
    let final_storage = latest_campaign_storage_admission(context)?;
    let projection = build_projection(
        context,
        u32::try_from(context.projections.len()).unwrap_or(u32::MAX),
        context.projections.last().cloned(),
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
        Some(final_storage),
    )?;
    json::write_new_canonical(
        &context.root.join("delivery-projection.json"),
        &delivery_projection,
    )?;
    let delivery_projection_sha256 = sha256_file(&context.root.join("delivery-projection.json"))?;

    let pair_bindings = if terminal_state == TerminalState::Pass {
        let intent: Intent = json::read_strict(
            &context.root.join("intent.json"),
            crate::schema::JSON_MAX_BYTES,
        )?;
        crate::evidence::derive_authoritative(
            &intent,
            &context.design,
            &context.design_bytes,
            &context.machine,
            &arms,
        )?
        .1
    } else {
        Vec::new()
    };
    let arm_bindings = arms
        .iter()
        .map(|arm| {
            Ok(CalibrationArmBinding {
                ordinal: arm.metadata.ordinal,
                class: arm.metadata.class,
                path: repository_relative(&context.root, &arm.leaf)?,
                raw_sha256: arm.raw_sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let manifest = CampaignManifest {
        schema: CAMPAIGN_MANIFEST_SCHEMA.to_owned(),
        run_id: context.run_id.clone(),
        intent_sha256: context.intent_sha256.clone(),
        design_lock_sha256: context.design_sha256.clone(),
        calibration_binding_sha256: context.binding_sha256.clone(),
        campaign_plan_sha256: context.plan_sha256.clone(),
        schedule_sha256: sha256_file(&context.root.join("schedule.json"))?,
        machine_sha256: context.machine_sha256.clone(),
        build_set_sha256: context.build_set_sha256.clone(),
        execution_state_sha256: state_sha256,
        projection_sha256: delivery_projection_sha256,
        planned_arms: context.plan.arms.len() as u64,
        completed_arms,
        arm_bindings,
        pair_bindings,
        terminal_state,
        terminal_reasons: reason_text,
    };
    manifest.validate(context.design.selected_n)?;
    json::write_new_canonical(&context.root.join("campaign-manifest.json"), &manifest)?;

    let seal = create_seal(&context.root)?;
    let source = bundle::verify_source_structural(&context.root)?;
    if source.terminal_state != terminal_state {
        return Err(Error::new(format!(
            "sealed campaign derived {:?}, expected {:?}",
            source.terminal_state, terminal_state
        )));
    }
    deliver_sealed_campaign(&context.repository, &context.root, &seal.root_sha256)
}

fn deliver_sealed_campaign(
    repository: &Path,
    root: &Path,
    expected_seal_root: &str,
) -> Result<CampaignOutcome> {
    let verified = bundle::verify_source_structural(root)?;
    if verified.intent.evidence_kind != EvidenceKind::Campaign
        || verified.seal.root_sha256 != expected_seal_root
    {
        return Err(Error::new("sealed campaign delivery identity changed"));
    }
    let run_id = verified.intent.evidence_id.clone();
    let design: DesignLock = json::read_strict(
        &root.join("design-lock.json"),
        crate::schema::JSON_MAX_BYTES,
    )?;
    design.validate()?;
    let manifest: CampaignManifest = json::read_strict(
        &root.join("campaign-manifest.json"),
        crate::schema::JSON_MAX_BYTES,
    )?;
    manifest.validate(design.selected_n)?;
    if manifest.run_id != run_id || manifest.terminal_state != verified.terminal_state {
        return Err(Error::new(
            "sealed campaign manifest differs from independently derived source",
        ));
    }
    let mut transaction = DeliveryTransaction::open(
        repository,
        EvidenceKind::Campaign,
        &run_id,
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
        .join("bundles/campaign")
        .join(&run_id);
    let staging = crate::orchestrator::execution_root(repository)
        .join("delivery-staging")
        .join(&run_id);
    if !staging.exists() && !destination.exists() {
        let attempt = transaction.next_attempt("bundle")?;
        bundle::create_bundle_derived(root, &attempt)?;
        fs::create_dir_all(
            staging
                .parent()
                .ok_or_else(|| Error::new("campaign staging has no parent"))?,
        )?;
        fs::rename(&attempt, &staging)?;
        File::open(
            staging
                .parent()
                .ok_or_else(|| Error::new("campaign staging parent disappeared"))?,
        )?
        .sync_all()?;
    }
    if staging.exists() && destination.exists() {
        return Err(Error::new(
            "campaign delivery has both staging and installed bundle directories",
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
    if index.evidence_kind != EvidenceKind::Campaign
        || index.evidence_id != run_id
        || index.uncompressed_seal_root_sha256 != expected_seal_root
        || index.terminal_state != verified.terminal_state
    {
        return Err(Error::new(
            "campaign bundle index differs from sealed source",
        ));
    }
    transaction.record(
        DeliveryPhase::BundleCreated,
        vec![DeliveryBinding::from_file_at(
            "bundle/bundle-index.json",
            &index_path,
        )?],
    )?;

    let structural_scratch = transaction.next_attempt("verify")?;
    let receipt = bundle::verify_bundle(&index_path, &structural_scratch)?;
    receipt.validate()?;
    let verification_path = bundle_root.join("verification.json");
    write_or_require_canonical(&verification_path, &receipt)?;
    transaction.record(
        DeliveryPhase::BundleVerified,
        vec![
            DeliveryBinding::from_file_at("bundle/bundle-index.json", &index_path)?,
            DeliveryBinding::from_file_at("bundle/verification.json", &verification_path)?,
        ],
    )?;

    preanalysis_campaign_cap(repository, bundle_root, &destination)?;
    let analysis_scratch = transaction.next_attempt("analysis")?;
    let (_, extracted) = bundle::verify_bundle_retained(&index_path, &analysis_scratch)?;
    let extracted_verification = if verified.terminal_state == TerminalState::Pass {
        crate::evidence::verify_raw_closure(&extracted)?
    } else {
        crate::evidence::verify_raw_closure_structural(&extracted)?
    };
    let analysis = extracted_verification.derived_analysis()?;
    let final_terminal = terminal_from_analysis(&analysis);
    let conclusion_id = format!("conclusion-{run_id}");
    let result_relative = format!("results/{conclusion_id}.json");
    let report_relative = format!("reports/{conclusion_id}.md");
    let derived_root = transaction.root().join("derived");
    fs::create_dir_all(&derived_root)?;
    let result_path = derived_root.join("result.json");
    let report_path = derived_root.join("report.md");
    let result_bytes = json::canonical_bytes(&analysis)?;
    let result_sha256 = sha256_hex(&result_bytes);
    let report = format!(
        "# HTTP/2 performance campaign\n\n- Run: `{run_id}`\n- Calibration: `{}`\n- Candidate: `{}`\n- Verdict: `{:?}`\n- Bundle index SHA-256: `{}`\n- Verification SHA-256: `{}`\n- Raw seal root SHA-256: `{expected_seal_root}`\n- Result SHA-256: `{result_sha256}`\n- Comparisons: `{}`\n- Scalar gates: `{}`\n\n{}\n",
        design.calibration_id,
        verified.intent.candidate_commit,
        analysis.decision.verdict,
        sha256_file(&index_path)?,
        sha256_file(&verification_path)?,
        analysis.comparison_count,
        analysis.scalar_gate_count,
        if analysis.decision.reasons.is_empty() {
            "All decision gates completed without a blocker.".to_owned()
        } else {
            format!("Decision reasons: {}", analysis.decision.reasons.join("; "))
        }
    );
    write_or_require_bytes(&result_path, &result_bytes)?;
    write_or_require_bytes(&report_path, report.as_bytes())?;
    transaction.record(
        DeliveryPhase::DerivedProducts,
        vec![
            DeliveryBinding::from_file_at("derived/result.json", &result_path)?,
            DeliveryBinding::from_file_at("derived/report.md", &report_path)?,
        ],
    )?;

    let prefix = format!("bundles/campaign/{run_id}");
    let tracked_bytes = storage::actual_regular_bytes(bundle_root)?
        .checked_add(fs::metadata(&result_path)?.len())
        .and_then(|value| value.checked_add(fs::metadata(&report_path).ok()?.len()))
        .ok_or_else(|| Error::new("campaign tracked-byte total overflow"))?;
    let entry = DeliveryEntry {
        evidence_kind: EvidenceKind::Campaign,
        evidence_id: run_id.clone(),
        bundle_index_path: format!("{prefix}/bundle-index.json"),
        bundle_index_sha256: receipt.bundle_index_sha256.clone(),
        verification_path: format!("{prefix}/verification.json"),
        verification_sha256: sha256_file(&verification_path)?,
        result_path: Some(result_relative.clone()),
        result_sha256: Some(result_sha256.clone()),
        report_path: Some(report_relative.clone()),
        report_sha256: Some(sha256_file(&report_path)?),
        design_lock_path: None,
        design_lock_sha256: None,
        continuation_projection_path: None,
        continuation_projection_sha256: None,
        seal_root_sha256: expected_seal_root.to_owned(),
        outcome: final_terminal,
        tracked_bytes,
    };
    entry.validate()?;
    let artifacts = artifact_root(repository);
    let ledger_path = artifacts.join("delivery-index.json");
    let previous = if ledger_path.exists() {
        json::read_strict(&ledger_path, crate::schema::JSON_MAX_BYTES)?
    } else {
        DeliveryLedger::empty()
    };
    let next = if let Some(existing) = previous.entries.iter().find(|existing| {
        existing.evidence_kind == EvidenceKind::Campaign && existing.evidence_id == run_id
    }) {
        if existing != &entry {
            return Err(Error::new(
                "campaign ledger identity was published with different content",
            ));
        }
        previous.clone()
    } else {
        bundle::append_delivery_entry(&previous, entry.clone())?
    };
    ensure_campaign_prepublish_cap(
        repository,
        bundle_root,
        &destination,
        &result_path,
        &report_path,
        &result_relative,
        &report_relative,
        &previous,
        &next,
    )?;
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
                .ok_or_else(|| Error::new("campaign bundle destination has no parent"))?,
        )?;
        fs::rename(&staging, &destination)?;
        File::open(
            destination
                .parent()
                .ok_or_else(|| Error::new("campaign bundle parent disappeared"))?,
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
    fs::create_dir_all(artifacts.join("results"))?;
    fs::create_dir_all(artifacts.join("reports"))?;
    write_or_require_bytes(&artifacts.join(&result_relative), &result_bytes)?;
    write_or_require_bytes(&artifacts.join(&report_relative), report.as_bytes())?;
    transaction.record(
        DeliveryPhase::ConclusionInstalled,
        vec![
            DeliveryBinding::from_file_at(
                "installed/result.json",
                &artifacts.join(&result_relative),
            )?,
            DeliveryBinding::from_file_at(
                "installed/report.md",
                &artifacts.join(&report_relative),
            )?,
        ],
    )?;
    ensure_campaign_prepublish_cap(
        repository,
        &destination,
        &destination,
        &artifacts.join(&result_relative),
        &artifacts.join(&report_relative),
        &result_relative,
        &report_relative,
        &previous,
        &next,
    )?;
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
        EvidenceKind::Campaign,
        &run_id,
        expected_seal_root,
    )?;
    Ok(CampaignOutcome {
        run_id,
        calibration_id: design.calibration_id,
        candidate_commit: verified.intent.candidate_commit,
        evidence_root: root.display().to_string(),
        terminal_state: delivered.outcome,
        reasons: analysis.decision.reasons,
        completed_arms: verified.raw_arm_count,
        bundle_index_path: delivered.bundle_index_path,
        bundle_index_sha256: delivered.bundle_index_sha256,
        verification_path: delivered.verification_path,
        verification_sha256: delivered.verification_sha256,
        result_path: result_relative,
        result_sha256,
        report_path: report_relative,
        report_sha256: delivered.report_sha256.unwrap_or_default(),
    })
}

fn preanalysis_campaign_cap(
    repository: &Path,
    bundle_root: &Path,
    destination: &Path,
) -> Result<()> {
    let mut projected = storage::actual_regular_bytes_if_exists(&artifact_root(repository))?;
    if !destination.exists() {
        projected = projected
            .checked_add(storage::actual_regular_bytes(bundle_root)?)
            .ok_or_else(|| Error::new("pre-analysis campaign bundle total overflow"))?;
    }
    projected = projected
        .checked_add(3 * MIB)
        .ok_or_else(|| Error::new("pre-analysis result/report reserve overflow"))?;
    if projected > TASK_CAP_BYTES {
        return Err(Error::new(
            "campaign bundle plus result/report reserve exceeds the pre-analysis 512 MiB gate",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn ensure_campaign_prepublish_cap(
    repository: &Path,
    bundle_root: &Path,
    destination: &Path,
    result_source: &Path,
    report_source: &Path,
    result_relative: &str,
    report_relative: &str,
    previous: &DeliveryLedger,
    next: &DeliveryLedger,
) -> Result<()> {
    let artifacts = artifact_root(repository);
    let mut projected = storage::actual_regular_bytes_if_exists(&artifacts)?;
    if !destination.exists() {
        projected = projected
            .checked_add(storage::actual_regular_bytes(bundle_root)?)
            .ok_or_else(|| Error::new("campaign prepublish bundle total overflow"))?;
    }
    for (source, relative) in [
        (result_source, result_relative),
        (report_source, report_relative),
    ] {
        if !artifacts.join(relative).exists() {
            projected = projected
                .checked_add(fs::metadata(source)?.len())
                .ok_or_else(|| Error::new("campaign prepublish conclusion total overflow"))?;
        }
    }
    let ledger_path = artifacts.join("delivery-index.json");
    let next_bytes = json::canonical_bytes(next)?;
    let pending_ledger = ledger_path.with_extension("json.next");
    if pending_ledger.exists() {
        let pending_bytes = fs::read(&pending_ledger)?;
        if pending_bytes != next_bytes {
            return Err(Error::new(
                "pending campaign ledger contains different content",
            ));
        }
        projected = projected
            .checked_sub(u64::try_from(pending_bytes.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| Error::new("pending campaign ledger byte underflow"))?;
    }
    if ledger_path.exists() {
        let previous_bytes = fs::read(&ledger_path)?;
        if previous != next {
            projected = projected
                .checked_sub(u64::try_from(previous_bytes.len()).unwrap_or(u64::MAX))
                .and_then(|value| {
                    value.checked_add(u64::try_from(next_bytes.len()).unwrap_or(u64::MAX))
                })
                .ok_or_else(|| Error::new("campaign prepublish ledger total overflow"))?;
            if !previous.entries.is_empty() {
                let history = artifacts
                    .join("ledger-history")
                    .join(format!("{}.json", sha256_hex(&previous_bytes)));
                if !history.exists() {
                    projected = projected
                        .checked_add(u64::try_from(previous_bytes.len()).unwrap_or(u64::MAX))
                        .ok_or_else(|| Error::new("campaign prepublish history overflow"))?;
                }
            }
        }
    } else {
        projected = projected
            .checked_add(u64::try_from(next_bytes.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| Error::new("campaign prepublish genesis ledger overflow"))?;
    }
    if projected > TASK_CAP_BYTES {
        return Err(Error::new(
            "prepublish campaign delivery exceeds the exact 512 MiB gate",
        ));
    }
    Ok(())
}

fn write_or_require_bytes(path: &Path, expected: &[u8]) -> Result<()> {
    if path.exists() {
        require_file_bytes(path, expected)
    } else {
        json::write_new_bytes(path, expected)
    }
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
                "delivery successor does not bind installed predecessor",
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

fn terminal_from_analysis(analysis: &AnalysisResult) -> TerminalState {
    match analysis.decision.verdict {
        crate::schema::Verdict::Pass => TerminalState::Pass,
        crate::schema::Verdict::Fail => TerminalState::Fail,
        crate::schema::Verdict::Blocked => TerminalState::Blocked,
    }
}

fn build_projection(
    context: &CampaignContext,
    revision: u32,
    predecessor: Option<FileHashBinding>,
    storage_admission: Option<ReachedBranchProjection>,
) -> Result<ProjectionEvidence> {
    let arms = parse_raw_arms(&context.root)?;
    let raw_actual = raw_arm_bytes(&arms)?;
    let tracked_actual =
        storage::actual_regular_bytes_if_exists(&artifact_root(&context.repository))?;
    let raw_projected = storage_admission
        .as_ref()
        .map_or(raw_actual, |value| value.extracted_source_bound_bytes);
    let tracked_projected = storage_admission.as_ref().map_or(
        context.design.tracked_projection.projected_total_bytes,
        |value| value.tracked_total_bound_bytes,
    );
    let projection = ProjectionEvidence {
        schema: PROJECTION_SCHEMA.to_owned(),
        revision,
        predecessor,
        source_arm_root_sha256: Some(raw_arm_root(&arms)?),
        completed_arms: arms.len() as u64,
        runtime_projected_ns: context.design.runtime_projection.projected_total_ns,
        runtime_actual_ns: clock_ns(ClockKind::Boottime)?
            .checked_sub(context.binding.campaign_boottime_origin_ns)
            .ok_or_else(|| Error::new("campaign projection BOOTTIME underflow"))?,
        q_extra_ns: campaign_wide_q_extra(context, &arms)?,
        raw_projected_bytes: raw_projected,
        raw_actual_bytes: raw_actual,
        tracked_projected_bytes: tracked_projected,
        tracked_actual_bytes: tracked_actual,
        endpoint_bound_bytes: 512 + 160 * 200 + 512 * 64,
        conn_live: 200,
        concurrency: 64,
        storage_admission,
    };
    projection.validate()?;
    Ok(projection)
}

fn campaign_wide_q_extra(context: &CampaignContext, arms: &[ParsedArm]) -> Result<u64> {
    arms.iter().try_fold(
        context.design.runtime_projection.q_extra_pre_ns,
        |total, arm| {
            total
                .checked_add(arm.quiet.q_extra_ns)
                .ok_or_else(|| Error::new("campaign-wide Q_extra total overflow"))
        },
    )
}

fn write_projection_revision(
    context: &mut CampaignContext,
    gate_id: &str,
    final_delivery: bool,
) -> Result<()> {
    let revision = u32::try_from(context.projections.len())
        .map_err(|_| Error::new("campaign projection revision overflow"))?;
    let next_ordinal = u64::try_from(parse_raw_arms(&context.root)?.len())
        .map_err(|_| Error::new("campaign projection prefix exceeds u64"))?;
    let admission = campaign_storage_admission(context, gate_id, next_ordinal, final_delivery)?;
    if !admission.admissible {
        return Err(Error::new(format!(
            "campaign storage admission {gate_id} failed"
        )));
    }
    let projection = build_projection(
        context,
        revision,
        context.projections.last().cloned(),
        Some(admission),
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

fn latest_campaign_storage_admission(context: &CampaignContext) -> Result<ReachedBranchProjection> {
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
        "campaign lacks a reached-branch storage admission",
    ))
}

fn validate_resume_prefix(context: &CampaignContext) -> Result<()> {
    if context.journal.first().is_none_or(|record| {
        record.kind != ExecutionJournalKind::CampaignStart
            || record.calibration_id != context.run_id
            || record.plan_sha256 != context.plan_sha256
    }) {
        return Err(Error::new(
            "campaign resume lacks exact campaign-start journal",
        ));
    }
    for record in &context.journal {
        if record.calibration_id != context.run_id
            || record.boot_id_sha256 != context.boot_id_sha256
            || record.machine_sha256 != context.machine_sha256
            || record.build_set_sha256 != context.build_set_sha256
            || record.plan_sha256 != context.plan_sha256
        {
            return Err(Error::new(
                "campaign resume boot/machine/build/plan identity changed",
            ));
        }
    }
    let arms = parse_raw_arms(&context.root)?;
    let completions = context
        .journal
        .iter()
        .filter(|record| record.kind == ExecutionJournalKind::ArmComplete)
        .collect::<Vec<_>>();
    let unjournaled = arms.len() == completions.len() + 1
        && partially_started_ordinal(&context.journal) == Some(completions.len() as u64);
    if arms.len() != completions.len() && !unjournaled {
        return Err(Error::new("campaign journal/raw prefix counts differ"));
    }
    for (ordinal, (record, arm)) in completions.iter().zip(&arms).enumerate() {
        if record.ordinal != Some(ordinal as u64)
            || record.raw_sha256.as_deref() != Some(arm.raw_sha256.as_str())
        {
            return Err(Error::new(
                "campaign journal does not bind exact raw prefix",
            ));
        }
    }
    Ok(())
}

struct JournalInput<'a> {
    run_id: &'a str,
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
    context: &mut CampaignContext,
    kind: ExecutionJournalKind,
    phase: ExecutionPhase,
    ordinal: Option<u64>,
    raw: Option<(String, String)>,
) -> Result<()> {
    append_journal_record(
        &context.root,
        &mut context.journal,
        JournalInput {
            run_id: &context.run_id,
            kind,
            phase,
            ordinal,
            boottime_ns: clock_ns(ClockKind::Boottime)?,
            boot_id_sha256: &context.boot_id_sha256,
            machine_sha256: &context.machine_sha256,
            build_set_sha256: &context.build_set_sha256,
            plan_sha256: &context.plan_sha256,
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
        calibration_id: input.run_id.to_owned(),
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
    let label = match record.kind {
        ExecutionJournalKind::CampaignStart => "campaign-start",
        ExecutionJournalKind::ArmStart => "arm-start",
        ExecutionJournalKind::ArmComplete => "arm-complete",
        _ => return Err(Error::new("campaign journal used a calibration-only event")),
    };
    let path = root
        .join("state")
        .join(format!("{sequence:06}-{label}.json"));
    json::write_new_canonical(&path, &record)?;
    journal.push(record);
    execution_journal_root(journal)?;
    Ok(())
}

fn read_journal(root: &Path) -> Result<Vec<ExecutionJournalRecord>> {
    let mut paths = fs::read_dir(root.join("state"))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    let records = paths
        .iter()
        .map(|path| json::read_strict(path, crate::schema::JSON_MAX_BYTES))
        .collect::<Result<Vec<_>>>()?;
    if !records.is_empty() {
        execution_journal_root(&records)?;
    }
    Ok(records)
}

fn read_projection_bindings(root: &Path) -> Result<Vec<FileHashBinding>> {
    let mut paths = fs::read_dir(root.join("projections"))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    let mut bindings = Vec::new();
    for (revision, path) in paths.into_iter().enumerate() {
        let projection: ProjectionEvidence =
            json::read_strict(&path, crate::schema::JSON_MAX_BYTES)?;
        if projection.revision != revision as u32
            || projection.predecessor != bindings.last().cloned()
        {
            return Err(Error::new("campaign projection chain is invalid"));
        }
        bindings.push(FileHashBinding {
            path: repository_relative(root, &path)?,
            sha256: sha256_file(&path)?,
        });
    }
    Ok(bindings)
}

fn parse_raw_arms(root: &Path) -> Result<Vec<ParsedArm>> {
    let inspection = raw::inspect_evidence_tree(root)?;
    if !inspection.blockers.is_empty() {
        return Err(Error::new(format!(
            "campaign raw prefix failed validation: {}",
            inspection.blockers.join("; ")
        )));
    }
    Ok(inspection.arms)
}

fn raw_arm_by_ordinal(root: &Path, ordinal: u64) -> Result<ParsedArm> {
    parse_raw_arms(root)?
        .into_iter()
        .find(|arm| arm.metadata.ordinal == ordinal)
        .ok_or_else(|| Error::new(format!("campaign raw arm {ordinal} is missing")))
}

fn partially_started_ordinal(journal: &[ExecutionJournalRecord]) -> Option<u64> {
    journal
        .last()
        .filter(|record| record.kind == ExecutionJournalKind::ArmStart)
        .and_then(|record| record.ordinal)
}

fn phase_for_class(class: EvidenceClass) -> ExecutionPhase {
    match class {
        EvidenceClass::D => ExecutionPhase::AuthoritativeDirect,
        EvidenceClass::A => ExecutionPhase::Authoritative,
        EvidenceClass::S => ExecutionPhase::Scout,
        EvidenceClass::C => ExecutionPhase::Williams,
    }
}

fn raw_protocol(protocol: Protocol) -> RawProtocol {
    match protocol {
        Protocol::H1 => RawProtocol::H1,
        Protocol::H2 => RawProtocol::H2,
    }
}

fn raw_protocol_label(protocol: RawProtocol) -> &'static str {
    match protocol {
        RawProtocol::H1 => "h1",
        RawProtocol::H2 => "h2",
    }
}

fn artifact_root(repository: &Path) -> PathBuf {
    repository.join(".legion/tasks/prove-http2-performance-regression/artifacts")
}

fn repository_relative(root: &Path, path: &Path) -> Result<String> {
    path.strip_prefix(root)
        .map_err(|_| Error::new("campaign path escaped its expected root"))
        .map(|value| value.to_string_lossy().into_owned())
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256_hex(&fs::read(path)?))
}

fn write_or_require_canonical<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = json::canonical_bytes(value)?;
    if path.exists() {
        require_file_bytes(path, &bytes)
    } else {
        json::write_new_bytes(path, &bytes)
    }
}

fn require_file_bytes(path: &Path, expected: &[u8]) -> Result<()> {
    if fs::read(path)? == expected {
        Ok(())
    } else {
        Err(Error::new(format!(
            "campaign resume file differs: {}",
            path.display()
        )))
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn ceil_div_u128(numerator: u128, denominator: u128) -> Result<u128> {
    if denominator == 0 {
        return Err(Error::new("campaign ceiling division by zero"));
    }
    numerator
        .checked_add(denominator - 1)
        .map(|value| value / denominator)
        .ok_or_else(|| Error::new("campaign ceiling division overflow"))
}

fn sealed_outcome(repository: &Path, root: &Path) -> Result<CampaignOutcome> {
    let verified = bundle::verify_source_structural(root)?;
    deliver_sealed_campaign(repository, root, &verified.seal.root_sha256)
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub mod test_support {
    use super::*;
    use crate::schema::{all_cells, SignatureBinding};

    pub fn fake_design(n: u32) -> Result<(DesignLock, Vec<CampaignDirectKey>)> {
        if !matches!(n, 30 | 50) {
            return Err(Error::new("fake campaign N must be 30 or 50"));
        }
        let hash = sha256_hex(b"fake-campaign-binding");
        let durations = all_cells()
            .into_iter()
            .map(|cell| crate::calibration::CellDurations {
                cell,
                durations: FrozenDurations {
                    warmup_seconds: 3,
                    measure_seconds: 5,
                },
            })
            .collect::<Vec<_>>();
        let mut treatment_signatures = Vec::new();
        let mut direct_signatures = Vec::new();
        for cell in all_cells() {
            for arm in Arm::ALL {
                treatment_signatures.push(SignatureBinding {
                    cell,
                    arm: Some(arm),
                    direct_protocol: None,
                    record_path: format!("signatures/{}/{}.json", cell.id(), arm.code()),
                    record_sha256: hash.clone(),
                    signature_sha256: hash.clone(),
                });
            }
            for protocol in [RawProtocol::H1, RawProtocol::H2] {
                direct_signatures.push(SignatureBinding {
                    cell,
                    arm: None,
                    direct_protocol: Some(protocol),
                    record_path: format!(
                        "signatures/{}/{}.json",
                        cell.id(),
                        raw_protocol_label(protocol)
                    ),
                    record_sha256: hash.clone(),
                    signature_sha256: hash.clone(),
                });
            }
        }
        let runtime_projection = crate::calibration::project_runtime(n, 0, 0, &durations)?;
        let tracked_projection = storage::tracked_projection(0, 0, &[], &[], 5 * MIB)?;
        let schedule_seed = 0x4641_4b45_4341_4d50;
        let design = DesignLock {
            schema: crate::schema::DESIGN_LOCK_SCHEMA.to_owned(),
            calibration_id: "fake-calibration".to_owned(),
            candidate_commit: crate::schema::INITIAL_CANDIDATE_COMMIT.to_owned(),
            intent_sha256: hash.clone(),
            machine_sha256: hash.clone(),
            build_set_sha256: hash.clone(),
            topology_smoke_sha256: hash.clone(),
            calibration_plan_sha256: hash.clone(),
            authoritative_parameters_sha256: hash.clone(),
            calibration_manifest_sha256: hash.clone(),
            projection_sha256: hash.clone(),
            calibration_seal_root_sha256: hash.clone(),
            calibration_bundle_index_sha256: hash,
            selected_n: n,
            schedule_seed,
            rounds: crate::schedule::generate_rounds(schedule_seed, n)?,
            comparisons: crate::schema::hard_comparisons(),
            authoritative_durations: durations,
            treatment_signatures,
            direct_signatures,
            direct_mappings: crate::process_plan::direct_mappings(),
            runtime_projection,
            tracked_projection,
            calibration_frequency_p05_khz: 4_000_000,
        };
        design.validate()?;
        let direct_order = all_cells()
            .into_iter()
            .flat_map(|cell| {
                [Protocol::H1, Protocol::H2]
                    .into_iter()
                    .map(move |protocol| CampaignDirectKey { cell, protocol })
            })
            .collect::<Vec<_>>();
        Ok((design, direct_order))
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FakeVerdict {
        Pass,
        Fail,
        Blocked,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct FakeResumeState {
        pub completed_prefix: u64,
        pub partially_started_ordinal: Option<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FakeCampaignResult {
        pub n: u32,
        pub total_arms: u64,
        pub direct_arms: u64,
        pub authoritative_arms: u64,
        pub completed_arms: u64,
        pub epochs: u32,
        pub pair_identities: u64,
        pub verdict: FakeVerdict,
    }

    pub trait FakeCampaignExecutor {
        fn signature_matches(&self, arm: &PlannedArm) -> bool;
        fn direct_rate(&self, epoch: u32, key: CampaignDirectKey) -> u64;
        fn baseline_direct_rate(&self, key: CampaignDirectKey) -> u64;
        fn gateway_rate(&self, arm: &PlannedArm) -> u64;
        fn runtime_allowed(&self, next_ordinal: u64) -> bool;
        fn storage_allowed(&self, next_ordinal: u64) -> bool;
        fn performance_passes(&self) -> bool;
    }

    pub fn run_fake_campaign<E: FakeCampaignExecutor>(
        design: &DesignLock,
        direct_order: &[CampaignDirectKey],
        executor: &E,
        resume: FakeResumeState,
    ) -> Result<FakeCampaignResult> {
        let plan = campaign_plan("fake-campaign", design, &"ab".repeat(32), direct_order)?;
        if resume
            .partially_started_ordinal
            .is_some_and(|value| value != resume.completed_prefix)
        {
            return Err(Error::new(
                "fake partial arm is not the next prefix ordinal",
            ));
        }
        if resume.partially_started_ordinal.is_some() {
            return Ok(FakeCampaignResult {
                n: design.selected_n,
                total_arms: plan.arms.len() as u64,
                direct_arms: plan.direct_arms,
                authoritative_arms: plan.authoritative_arms,
                completed_arms: resume.completed_prefix,
                epochs: design.selected_n / 10,
                pair_identities: 0,
                verdict: FakeVerdict::Blocked,
            });
        }
        let mut completed = 0_u64;
        let mut direct = BTreeMap::new();
        for arm in &plan.arms {
            if !executor.runtime_allowed(arm.ordinal) || !executor.storage_allowed(arm.ordinal) {
                return Ok(FakeCampaignResult {
                    n: design.selected_n,
                    total_arms: plan.arms.len() as u64,
                    direct_arms: plan.direct_arms,
                    authoritative_arms: plan.authoritative_arms,
                    completed_arms: completed,
                    epochs: design.selected_n / 10,
                    pair_identities: 0,
                    verdict: FakeVerdict::Blocked,
                });
            }
            if arm.ordinal >= resume.completed_prefix && !executor.signature_matches(arm) {
                return Err(Error::new("fake campaign accepted-signature mismatch"));
            }
            if arm.evidence_class == EvidenceClass::D {
                let epoch = arm.round.unwrap_or_default();
                let key = CampaignDirectKey {
                    cell: arm.cell,
                    protocol: arm.direct_protocol.unwrap_or(Protocol::H1),
                };
                let current = executor.direct_rate(epoch, key);
                let baseline = executor.baseline_direct_rate(key);
                if current * 10 < baseline * 9 || current * 10 > baseline * 11 {
                    return Err(Error::new("fake campaign direct drift block"));
                }
                direct.insert((epoch, key), current);
            } else {
                let epoch = arm.round.unwrap_or_default() / 10 + 1;
                let gateway = executor.gateway_rate(arm);
                for protocol in ArmTopology::for_arm(arm.arm.unwrap_or(Arm::B11)).direct_protocols()
                {
                    let key = CampaignDirectKey {
                        cell: arm.cell,
                        protocol,
                    };
                    let ceiling = direct
                        .get(&(epoch, key))
                        .ok_or_else(|| Error::new("fake campaign mapped direct is missing"))?;
                    if *ceiling * 4 < gateway * 5 {
                        return Err(Error::new("fake campaign mapped direct headroom block"));
                    }
                }
            }
            completed += 1;
        }
        Ok(FakeCampaignResult {
            n: design.selected_n,
            total_arms: plan.arms.len() as u64,
            direct_arms: plan.direct_arms,
            authoritative_arms: plan.authoritative_arms,
            completed_arms: completed,
            epochs: design.selected_n / 10,
            pair_identities: 45 * u64::from(design.selected_n),
            verdict: if executor.performance_passes() {
                FakeVerdict::Pass
            } else {
                FakeVerdict::Fail
            },
        })
    }
}
