use auth_mini_http2_regression::bundle::{
    create_bundle, ensure_cli_scratch, ensure_repository_local, repository_root, verify_bundle,
    verify_source,
};
use auth_mini_http2_regression::json;
use auth_mini_http2_regression::schema::{
    AuthoritativeManifest, Cell, TerminalState, INITIAL_CANDIDATE_COMMIT, JSON_MAX_BYTES,
};
use auth_mini_http2_regression::statistics;
use auth_mini_http2_regression::{Error, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
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
        "scout" => {
            require_only(&options, &["dry-run", "seed"])?;
            require_true(&options, "dry-run")?;
            let seed = parse_u64_option(&options, "seed", 0x5c0u64)?;
            print_json(&auth_mini_http2_regression::process_plan::scout_plan(seed)?)?;
        }
        "calibrate" => {
            require_only(&options, &["dry-run", "seed"])?;
            require_true(&options, "dry-run")?;
            let seed = parse_u64_option(&options, "seed", 0xca1b_u64)?;
            print_json(&auth_mini_http2_regression::process_plan::calibration_plan(
                seed,
            )?)?;
        }
        "campaign" => {
            require_only(&options, &["dry-run", "seed", "n"])?;
            require_true(&options, "dry-run")?;
            let seed = parse_u64_option(&options, "seed", 0xc0a1_u64)?;
            let n = u32::try_from(parse_u64_option(&options, "n", 30)?)
                .map_err(|_| Error::new("--n exceeds u32"))?;
            print_json(&auth_mini_http2_regression::process_plan::campaign_dry_run(
                seed, n,
            )?)?;
        }
        "role" => {
            require_only(
                &options,
                &[
                    "kind",
                    "control",
                    "run",
                    "workload",
                    "concurrency",
                    "arm",
                    "block",
                ],
            )?;
            run_role(&options)?;
        }
        "analyze" => {
            let input = local_required(&options, "input", &repository)?;
            let output = local_required(&options, "output", &repository)?;
            require_only(&options, &["input", "output"])?;
            let manifest: AuthoritativeManifest = json::read_strict(&input, JSON_MAX_BYTES)?;
            let result = statistics::analyze_manifest(&manifest)?;
            json::write_new_canonical(&output, &result)?;
            println!("{}", output.display());
        }
        "verify" => {
            let source = local_required(&options, "source", &repository)?;
            require_only(&options, &["source"])?;
            let verification = verify_source(&source)?;
            print_json(&VerifySummary {
                seal_root_sha256: verification.seal.root_sha256,
                seal_entries: verification.seal.entries.len() as u64,
                raw_arms: verification.raw_arm_count,
            })?;
        }
        "bundle" => {
            let source = local_required(&options, "source", &repository)?;
            let output = local_required(&options, "output", &repository)?;
            let terminal = parse_terminal(required(&options, "terminal")?)?;
            require_only(&options, &["source", "output", "terminal"])?;
            let index = create_bundle(&source, &output, terminal)?;
            print_json(&index)?;
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
    };
    let address = required(options, "control")?
        .parse::<SocketAddr>()
        .map_err(|_| Error::new("--control must be a socket address"))?;
    if !address.ip().is_loopback() {
        return Err(Error::new("role control address is not loopback"));
    }
    let kind = required(options, "kind")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(match kind {
            "fixture" => 4,
            "load" => 4,
            "sampler" => 2,
            _ => return Err(Error::new("role kind must be fixture, load, or sampler")),
        })
        .enable_all()
        .build()
        .map_err(|error| Error::new(format!("create role runtime: {error}")))?;
    let result = match kind {
        "fixture" => runtime.block_on(auth_mini_http2_regression::fixture::run_fixture_role(
            context, address,
        )),
        "load" => runtime.block_on(auth_mini_http2_regression::load::run_load_role(
            context, address,
        )),
        "sampler" => runtime.block_on(auth_mini_http2_regression::sampler::run_sampler_role(
            context, address,
        )),
        _ => unreachable!("role kind checked above"),
    };
    result.map_err(|error| error.context(format!("{kind} role")))
}

fn parse_terminal(value: &str) -> Result<TerminalState> {
    match value {
        "PASS" => Ok(TerminalState::Pass),
        "FAIL" => Ok(TerminalState::Fail),
        "BLOCKED" => Ok(TerminalState::Blocked),
        "SUPERSEDED" => Ok(TerminalState::Superseded),
        _ => Err(Error::new(
            "--terminal must be PASS, FAIL, BLOCKED, or SUPERSEDED",
        )),
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
}

#[derive(Serialize)]
struct SmokeOutput {
    summary: auth_mini_http2_regression::orchestrator::SmokeSummary,
    artifact_root: String,
}

fn usage() -> &'static str {
    "usage: auth-mini-http2-regression <self-test|preflight|build|smoke|direct-upload-probe|scout|calibrate|campaign|analyze|verify|bundle|verify-bundle> [--name value ...]"
}
