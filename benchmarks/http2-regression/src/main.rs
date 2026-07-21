use auth_mini_http2_regression::bundle::{
    create_bundle_derived, ensure_cli_scratch, ensure_repository_local, repository_root,
    verify_bundle, verify_source,
};
use auth_mini_http2_regression::schema::{Cell, TerminalState, INITIAL_CANDIDATE_COMMIT};
use auth_mini_http2_regression::{evidence, json};
use auth_mini_http2_regression::{Error, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("http2-regression: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().ok_or_else(|| Error::new(usage()))?;
    let options = parse_options(arguments.collect())?;
    let current = std::env::current_dir()?;
    let repository = repository_root(&current)?;
    match command.as_str() {
        "self-test" => {
            require_no_options(&options)?;
            auth_mini_http2_regression::self_test()?;
            println!("self-test: PASS");
        }
        "preflight" => {
            require_no_options(&options)?;
            let report = auth_mini_http2_regression::orchestrator::run_preflight(&repository)?;
            print_json(&report)?;
        }
        "build" => {
            require_only(&options, &["candidate"])?;
            let candidate = options
                .get("candidate")
                .map(String::as_str)
                .unwrap_or(INITIAL_CANDIDATE_COMMIT);
            let builds =
                auth_mini_http2_regression::orchestrator::build_exact_pair(&repository, candidate)?;
            print_json(&builds)?;
        }
        "smoke" => {
            require_only(&options, &["candidate"])?;
            auth_mini_http2_regression::harness::require_exact_committed_harness(&repository)?;
            let candidate = options
                .get("candidate")
                .map(String::as_str)
                .unwrap_or(INITIAL_CANDIDATE_COMMIT);
            let host = auth_mini_http2_regression::orchestrator::run_preflight(&repository)?;
            if !host.smoke_ready {
                return Err(Error::new(format!(
                    "host cannot run bounded smoke: {}",
                    host.blockers.join("; ")
                )));
            }
            auth_mini_http2_regression::linux::set_affinity(
                std::process::id(),
                auth_mini_http2_regression::linux::CONTROL_CPUS,
            )?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|error| Error::new(format!("create smoke runtime: {error}")))?;
            let (summary, artifacts) = runtime.block_on(
                auth_mini_http2_regression::orchestrator::smoke_all(&repository, candidate, host),
            )?;
            print_json(&SmokeOutput {
                summary,
                artifact_root: artifacts.display().to_string(),
            })?;
        }
        "direct-upload-probe" => {
            require_no_options(&options)?;
            auth_mini_http2_regression::linux::set_affinity(
                std::process::id(),
                auth_mini_http2_regression::linux::CONTROL_CPUS,
            )?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|error| Error::new(format!("create direct-probe runtime: {error}")))?;
            print_json(&runtime.block_on(
                auth_mini_http2_regression::orchestrator::direct_upload_probe(&repository),
            )?)?;
        }
        "diagnose-b11-c1-upload" => {
            require_only(&options, &["candidate"])?;
            let candidate = options
                .get("candidate")
                .map(String::as_str)
                .unwrap_or(INITIAL_CANDIDATE_COMMIT);
            let host = auth_mini_http2_regression::orchestrator::run_preflight(&repository)?;
            auth_mini_http2_regression::linux::set_affinity(
                std::process::id(),
                auth_mini_http2_regression::linux::CONTROL_CPUS,
            )?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|error| Error::new(format!("create diagnostic runtime: {error}")))?;
            let summary = runtime.block_on(
                auth_mini_http2_regression::orchestrator::diagnose_b11_c1_upload(
                    &repository,
                    candidate,
                    host,
                ),
            )?;
            let succeeded = summary.case_succeeded;
            let stage = summary.stage;
            let code = summary.code;
            let detail_sha256 = summary.detail_sha256.clone();
            let evidence_root = summary.evidence_root.clone();
            print_json(&summary)?;
            if !succeeded {
                return Err(Error::new(format!(
                    "B11 C1 upload diagnostic retained failure stage={} code={} detail-sha256={} evidence={evidence_root}",
                    stage.map_or("unknown", |value| value.label()),
                    code.map_or("unknown", |value| value.label()),
                    detail_sha256.as_deref().unwrap_or("unknown"),
                )));
            }
        }
        "scout" => {
            require_only(&options, &["dry-run", "seed"])?;
            require_true(&options, "dry-run")?;
            let seed = parse_u64_option(&options, "seed", 0x5c0u64)?;
            print_json(&auth_mini_http2_regression::process_plan::scout_plan(seed)?)?;
        }
        "calibrate" => {
            require_only(&options, &["candidate", "dry-run", "seed"])?;
            let seed = parse_u64_option(&options, "seed", 0xca1b_u64)?;
            if options.contains_key("dry-run") {
                require_true(&options, "dry-run")?;
                print_json(&auth_mini_http2_regression::process_plan::calibration_plan(
                    seed,
                )?)?;
            } else {
                let candidate = required(&options, "candidate")?;
                auth_mini_http2_regression::linux::set_affinity(
                    std::process::id(),
                    auth_mini_http2_regression::linux::CONTROL_CPUS,
                )?;
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .map_err(|error| Error::new(format!("create calibration runtime: {error}")))?;
                let outcome =
                    runtime.block_on(auth_mini_http2_regression::orchestrator::run_calibration(
                        &repository,
                        candidate,
                        seed,
                    ))?;
                let terminal = outcome.terminal_state;
                print_json(&outcome)?;
                require_pass_terminal(terminal)?;
            }
        }
        "campaign" => {
            if options.contains_key("dry-run") {
                require_only(&options, &["dry-run", "seed", "n"])?;
                require_true(&options, "dry-run")?;
                let seed = parse_u64_option(&options, "seed", 0xc0a1_u64)?;
                let n = u32::try_from(parse_u64_option(&options, "n", 30)?)
                    .map_err(|_| Error::new("--n exceeds u32"))?;
                print_json(&auth_mini_http2_regression::process_plan::campaign_dry_run(
                    seed, n,
                )?)?;
            } else {
                require_only(&options, &["candidate", "calibration"])?;
                let candidate = required(&options, "candidate")?;
                let calibration = required(&options, "calibration")?;
                auth_mini_http2_regression::linux::set_affinity(
                    std::process::id(),
                    auth_mini_http2_regression::linux::CONTROL_CPUS,
                )?;
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .map_err(|error| Error::new(format!("create campaign runtime: {error}")))?;
                let outcome =
                    runtime.block_on(auth_mini_http2_regression::orchestrator::run_campaign(
                        &repository,
                        candidate,
                        calibration,
                    ))?;
                let terminal = outcome.terminal_state;
                print_json(&outcome)?;
                require_pass_terminal(terminal)?;
            }
        }
        "run" => {
            require_only(&options, &["candidate", "seed"])?;
            let candidate = required(&options, "candidate")?;
            let seed = parse_u64_option(&options, "seed", 0xca1b_u64)?;
            auth_mini_http2_regression::linux::set_affinity(
                std::process::id(),
                auth_mini_http2_regression::linux::CONTROL_CPUS,
            )?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|error| Error::new(format!("create end-to-end runtime: {error}")))?;
            let calibration =
                runtime.block_on(auth_mini_http2_regression::orchestrator::run_calibration(
                    &repository,
                    candidate,
                    seed,
                ))?;
            if calibration.terminal_state != TerminalState::Pass {
                print_json(&RunOutput {
                    calibration: calibration.clone(),
                    campaign: None,
                })?;
                require_pass_terminal(calibration.terminal_state)?;
            }
            let campaign =
                runtime.block_on(auth_mini_http2_regression::orchestrator::run_campaign(
                    &repository,
                    candidate,
                    &calibration.calibration_id,
                ))?;
            let terminal = campaign.terminal_state;
            print_json(&RunOutput {
                calibration,
                campaign: Some(campaign),
            })?;
            require_pass_terminal(terminal)?;
        }
        "delivery-ready" => {
            require_only(&options, &["commit"])?;
            let receipt = auth_mini_http2_regression::delivery::delivery_ready(
                &repository,
                required(&options, "commit")?,
            )?;
            print_json(&receipt)?;
        }
        "delivery-retained" => {
            require_only(&options, &["base", "merge"])?;
            let receipt = auth_mini_http2_regression::delivery::delivery_retained(
                &repository,
                required(&options, "base")?,
                required(&options, "merge")?,
            )?;
            print_json(&receipt)?;
        }
        "role" => {
            require_only(
                &options,
                &["kind", "run", "workload", "concurrency", "arm", "block"],
            )?;
            run_role(&options)?;
        }
        "analyze" => {
            let source = local_required(&options, "source", &repository)?;
            let output = local_required(&options, "output", &repository)?;
            require_only(&options, &["source", "output"])?;
            let verified = evidence::verify_raw_closure(&source)?;
            let terminal = verified.terminal_state;
            let result = verified.derived_analysis()?;
            json::write_new_canonical(&output, &result)?;
            println!("{}", output.display());
            require_pass_terminal(terminal)?;
        }
        "verify" => {
            let source = local_required(&options, "source", &repository)?;
            require_only(&options, &["source"])?;
            let verification = verify_source(&source)?;
            print_json(&VerifySummary {
                seal_root_sha256: verification.seal.root_sha256,
                seal_entries: verification.seal.entries.len() as u64,
                raw_arms: verification.raw_arm_count,
                terminal_state: verification.terminal_state,
                reasons: verification.reasons,
            })?;
            require_pass_terminal(verification.terminal_state)?;
        }
        "bundle" => {
            let source = local_required(&options, "source", &repository)?;
            let output = local_required(&options, "output", &repository)?;
            require_only(&options, &["source", "output"])?;
            let index = create_bundle_derived(&source, &output)?;
            let terminal = index.terminal_state;
            print_json(&index)?;
            require_pass_terminal(terminal)?;
        }
        "verify-bundle" => {
            let index = local_required(&options, "index", &repository)?;
            let scratch_value = PathBuf::from(required(&options, "scratch")?);
            let scratch = ensure_cli_scratch(&scratch_value, &repository)?;
            require_only(&options, &["index", "scratch", "receipt"])?;
            let receipt = verify_bundle(&index, &scratch)?;
            if let Some(path) = options.get("receipt") {
                let output = ensure_repository_local(Path::new(path), &repository)?;
                json::write_new_canonical(&output, &receipt)?;
                println!("{}", output.display());
            } else {
                print_json(&receipt)?;
            }
            require_pass_terminal(receipt.terminal_state)?;
        }
        _ => return Err(Error::new(usage())),
    }
    Ok(())
}

fn parse_options(arguments: Vec<String>) -> Result<BTreeMap<String, String>> {
    let mut options = BTreeMap::new();
    let mut iterator = arguments.into_iter();
    while let Some(flag) = iterator.next() {
        let name = flag
            .strip_prefix("--")
            .ok_or_else(|| Error::new(format!("expected --option, got `{flag}`")))?;
        if name.is_empty() {
            return Err(Error::new("empty option name"));
        }
        let value = iterator
            .next()
            .ok_or_else(|| Error::new(format!("missing value for --{name}")))?;
        if value.starts_with("--") {
            return Err(Error::new(format!("missing value for --{name}")));
        }
        if options.insert(name.to_owned(), value).is_some() {
            return Err(Error::new(format!("duplicate option --{name}")));
        }
    }
    Ok(options)
}

fn required<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| Error::new(format!("missing required --{name}")))
}

fn local_required(
    options: &BTreeMap<String, String>,
    name: &str,
    repository: &Path,
) -> Result<PathBuf> {
    ensure_repository_local(Path::new(required(options, name)?), repository)
}

fn require_only(options: &BTreeMap<String, String>, allowed: &[&str]) -> Result<()> {
    if let Some(unexpected) = options
        .keys()
        .find(|name| !allowed.contains(&name.as_str()))
    {
        return Err(Error::new(format!("unexpected option --{unexpected}")));
    }
    Ok(())
}

fn require_no_options(options: &BTreeMap<String, String>) -> Result<()> {
    if options.is_empty() {
        Ok(())
    } else {
        Err(Error::new("self-test accepts no options"))
    }
}

fn require_true(options: &BTreeMap<String, String>, name: &str) -> Result<()> {
    match required(options, name)? {
        "true" => Ok(()),
        _ => Err(Error::new(format!("--{name} must be true"))),
    }
}

fn parse_u64_option(options: &BTreeMap<String, String>, name: &str, default: u64) -> Result<u64> {
    options.get(name).map_or(Ok(default), |value| {
        value
            .parse::<u64>()
            .map_err(|_| Error::new(format!("--{name} must be an unsigned integer")))
    })
}

fn run_role(options: &BTreeMap<String, String>) -> Result<()> {
    let workload =
        auth_mini_http2_regression::topology::parse_workload(required(options, "workload")?)?;
    let concurrency = required(options, "concurrency")?
        .parse::<u16>()
        .map_err(|_| Error::new("--concurrency must be a u16"))?;
    let self_identity = auth_mini_http2_regression::linux::process_identity(std::process::id())?;
    let orchestrator =
        auth_mini_http2_regression::linux::process_identity(self_identity.parent_pid)?;
    let context = auth_mini_http2_regression::control::ControlContext {
        run_id: required(options, "run")?.to_owned(),
        cell: Cell {
            workload,
            concurrency,
        },
        arm: auth_mini_http2_regression::topology::parse_arm(required(options, "arm")?)?,
        block: required(options, "block")?
            .parse::<u64>()
            .map_err(|_| Error::new("--block must be a u64"))?,
        orchestrator,
    };
    let kind = required(options, "kind")?;
    let role = match kind {
        "fixture" => auth_mini_http2_regression::control::Role::Fixture,
        "load" => auth_mini_http2_regression::control::Role::Load,
        "sampler" => auth_mini_http2_regression::control::Role::Sampler,
        _ => return Err(Error::new("role kind must be fixture, load, or sampler")),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(match kind {
            "fixture" => 4,
            "load" => 4,
            "sampler" => 2,
            _ => unreachable!("role kind checked above"),
        })
        .enable_all()
        .build()
        .map_err(|error| Error::new(format!("create role runtime: {error}")))?;
    let mut control = runtime.block_on(async {
        auth_mini_http2_regression::control::inherited_stdin(context.clone())
    })?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async {
            match kind {
                "fixture" => {
                    auth_mini_http2_regression::fixture::run_fixture_role(
                        context.clone(),
                        &mut control,
                    )
                    .await
                }
                "load" => {
                    auth_mini_http2_regression::load::run_load_role(context.clone(), &mut control)
                        .await
                }
                "sampler" => {
                    auth_mini_http2_regression::sampler::run_sampler_role(
                        context.clone(),
                        &mut control,
                    )
                    .await
                }
                _ => unreachable!("role kind checked above"),
            }
        })
    }));
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            let class = control.failure_class();
            let diagnostic = error.role_diagnostic();
            let stage = diagnostic.map_or(control.failure_stage(), |value| value.stage);
            let code = diagnostic.map_or_else(
                || {
                    error
                        .role_code()
                        .unwrap_or(auth_mini_http2_regression::control::RoleErrorCode::Internal)
                },
                |value| value.code,
            );
            let detail = error.to_string();
            let detail_sha256 =
                auth_mini_http2_regression::control::role_error_detail_sha256(role, class, &detail);
            if control.can_send_terminal_error() {
                let _ = runtime
                    .block_on(control.send_terminal_error(class, stage, code, &detail, None));
            }
            Err(Error::new(format!(
                "{kind} role terminated class={} stage={} code={} detail-sha256={detail_sha256}",
                class.label(),
                stage.label(),
                code.label(),
            )))
        }
        Err(_) => {
            let class = auth_mini_http2_regression::control::RoleErrorClass::Panic;
            let stage = control.failure_stage();
            let code = auth_mini_http2_regression::control::RoleErrorCode::Panic;
            let detail = "bounded-role-panic";
            let detail_sha256 =
                auth_mini_http2_regression::control::role_error_detail_sha256(role, class, detail);
            if control.can_send_terminal_error() {
                let _ =
                    runtime.block_on(control.send_terminal_error(class, stage, code, detail, None));
            }
            Err(Error::new(format!(
                "{kind} role terminated class={} stage={} code={} detail-sha256={detail_sha256}",
                class.label(),
                stage.label(),
                code.label(),
            )))
        }
    }
}

fn require_pass_terminal(terminal: TerminalState) -> Result<()> {
    if terminal == TerminalState::Pass {
        Ok(())
    } else {
        Err(Error::new(format!(
            "derived terminal state is {terminal:?}; non-PASS commands exit nonzero"
        )))
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let bytes = json::canonical_bytes(value)?;
    let text = String::from_utf8(bytes).map_err(|_| Error::new("canonical JSON is not UTF-8"))?;
    print!("{text}");
    Ok(())
}

#[derive(Serialize)]
struct VerifySummary {
    seal_root_sha256: String,
    seal_entries: u64,
    raw_arms: u64,
    terminal_state: TerminalState,
    reasons: Vec<String>,
}

#[derive(Serialize)]
struct SmokeOutput {
    summary: auth_mini_http2_regression::orchestrator::SmokeSummary,
    artifact_root: String,
}

#[derive(Serialize)]
struct RunOutput {
    calibration: auth_mini_http2_regression::calibration_coordinator::CalibrationOutcome,
    campaign: Option<auth_mini_http2_regression::campaign_coordinator::CampaignOutcome>,
}

fn usage() -> &'static str {
    "usage: auth-mini-http2-regression <self-test|preflight|build|smoke|diagnose-b11-c1-upload|direct-upload-probe|scout|calibrate|campaign|run|analyze|verify|bundle|verify-bundle|delivery-ready|delivery-retained> [--name value ...]"
}
