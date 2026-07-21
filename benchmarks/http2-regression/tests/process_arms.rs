use auth_mini_http2_regression::json;
use auth_mini_http2_regression::orchestrator::{
    execute_process_arm_for_test, AcceptedSignatureRecord, ArmFailureRecord, FrequencyGate,
    PreMeasureSignaturePolicy, ProcessArmOutcome, ProcessArmRequest,
};
use auth_mini_http2_regression::process_plan::PlannedArm;
use auth_mini_http2_regression::raw;
use auth_mini_http2_regression::schema::{
    Arm, Cell, EvidenceClass, TrustBoundaryManifest, Workload, BASELINE_COMMIT,
    INITIAL_CANDIDATE_COMMIT,
};
use auth_mini_http2_regression::seal::sha256_hex;
use auth_mini_http2_regression::topology::Protocol;
use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_TYPE, HOST};
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type UpstreamSender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self, BoxError> {
        let package = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let parent = package.join("target/test-scratch");
        fs::create_dir_all(&parent)?;
        let root = parent.join(format!("process-arms-{}", std::process::id()));
        fs::create_dir(&root)?;
        Ok(Self(root))
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

struct FakeGatewayState {
    upstream: SocketAddr,
    sender: Mutex<Option<UpstreamSender>>,
}

fn main() {
    let result = if std::env::var_os("PORT").is_some() && std::env::var_os("UPSTREAM_URL").is_some()
    {
        run_fake_gateway()
    } else {
        run_process_arm_integration()
    };
    if let Err(error) = result {
        eprintln!("process-arms integration failure: {error}");
        std::process::exit(1);
    }
}

fn run_fake_gateway() -> Result<(), BoxError> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(fake_gateway())
}

async fn fake_gateway() -> Result<(), BoxError> {
    let port = std::env::var("PORT")?.parse::<u16>()?;
    let upstream = std::env::var("UPSTREAM_URL")?
        .strip_prefix("http://")
        .ok_or("test upstream URL is not cleartext HTTP")?
        .parse::<SocketAddr>()?;
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let state = Arc::new(FakeGatewayState {
        upstream,
        sender: Mutex::new(None),
    });
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let state = Arc::clone(&state);
                async move { fake_gateway_response(request, state).await }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn fake_gateway_response(
    request: Request<Incoming>,
    state: Arc<FakeGatewayState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.uri().path() == "/healthz" {
        let mut response = Response::new(Full::new(Bytes::new()));
        *response.status_mut() = StatusCode::NO_CONTENT;
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
        return Ok(response);
    }
    Ok(match proxy_request(request, state).await {
        Ok(response) => response,
        Err(_) => {
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            response
        }
    })
}

async fn proxy_request(
    request: Request<Incoming>,
    state: Arc<FakeGatewayState>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let operation_id = request
        .headers()
        .get("x-amg-bench-op")
        .cloned()
        .ok_or("test gateway request lacks operation ID")?;
    let body = request.into_body().collect().await?.to_bytes();
    let mut upstream_request = Request::builder()
        .method(method)
        .uri(uri.path_and_query().map_or("/", |value| value.as_str()))
        .body(Full::new(body))?;
    upstream_request
        .headers_mut()
        .insert("x-amg-bench-op", operation_id);
    upstream_request.headers_mut().insert(
        "x-auth-mini-user-id",
        HeaderValue::from_static(auth_mini_http2_regression::session::USER_ID),
    );
    upstream_request.headers_mut().insert(
        "x-auth-mini-email",
        HeaderValue::from_static(auth_mini_http2_regression::session::USER_EMAIL),
    );
    upstream_request.headers_mut().insert(
        "x-forwarded-host",
        HeaderValue::from_static("public.example"),
    );
    upstream_request
        .headers_mut()
        .insert("x-forwarded-proto", HeaderValue::from_static("http"));
    upstream_request
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(&state.upstream.to_string())?);

    let mut sender = state.sender.lock().await;
    if sender.is_none() {
        let stream = TcpStream::connect(state.upstream).await?;
        let (new_sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        *sender = Some(new_sender);
    }
    let upstream_response = sender
        .as_mut()
        .ok_or("test upstream sender disappeared")?
        .send_request(upstream_request)
        .await?;
    let status = upstream_response.status();
    let content_type = upstream_response.headers().get(CONTENT_TYPE).cloned();
    let marker = upstream_response.headers().get("x-fixture-marker").cloned();
    let response_body = upstream_response.into_body().collect().await?.to_bytes();
    let mut response = Response::new(Full::new(response_body));
    *response.status_mut() = status;
    if let Some(value) = content_type {
        response.headers_mut().insert(CONTENT_TYPE, value);
    }
    if let Some(value) = marker {
        response.headers_mut().insert("x-fixture-marker", value);
    }
    Ok(response)
}

fn run_process_arm_integration() -> Result<(), BoxError> {
    let started = Instant::now();
    let repository =
        auth_mini_http2_regression::bundle::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
    auth_mini_http2_regression::linux::set_affinity(
        std::process::id(),
        auth_mini_http2_regression::linux::CONTROL_CPUS,
    )?;
    let role_executable = PathBuf::from(env!("CARGO_BIN_EXE_auth-mini-http2-regression"));
    let gateway_executable = std::env::current_exe()?;
    let scratch = Scratch::new()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    let scout_root = scratch.path("scout");
    fs::create_dir(&scout_root)?;
    let scout = planned(EvidenceClass::S, 0, Some(Arm::B11), None);
    let scout_outcome = runtime
        .block_on(execute_process_arm_for_test(
            &repository,
            &scout_root,
            request(
                "stage1-s",
                "stage1-s-run",
                &scout,
                PreMeasureSignaturePolicy::Observe,
            ),
            &role_executable,
            &gateway_executable,
        ))
        .map_err(|error| format!("scout arm: {error}"))?;
    validate_leaf(&repository, &scout_root, &scout_outcome, EvidenceClass::S)?;

    let calibration_root = scratch.path("calibration");
    fs::create_dir(&calibration_root)?;
    let accepted_path = calibration_root.join("signatures/get-c1/B11.json");
    let calibration = planned(EvidenceClass::C, 0, Some(Arm::B11), None);
    let calibration_outcome = runtime
        .block_on(execute_process_arm_for_test(
            &repository,
            &calibration_root,
            request(
                "stage1-c",
                "stage1-c-run",
                &calibration,
                PreMeasureSignaturePolicy::Establish {
                    accepted_record: &accepted_path,
                },
            ),
            &role_executable,
            &gateway_executable,
        ))
        .map_err(|error| format!("calibration arm: {error}"))?;
    validate_leaf(
        &repository,
        &calibration_root,
        &calibration_outcome,
        EvidenceClass::C,
    )?;
    let accepted: AcceptedSignatureRecord = json::read_strict(&accepted_path, 65_536)?;
    accepted.validate()?;
    if accepted.signature_sha256 != calibration_outcome.thread_signature_sha256 {
        return Err("established signature does not name its source arm".into());
    }

    let direct_root = scratch.path("direct");
    fs::create_dir(&direct_root)?;
    let direct_signature = direct_root.join("signatures/get-c1/h1.json");
    let direct = planned(EvidenceClass::D, 0, None, Some(Protocol::H1));
    let direct_outcome = runtime
        .block_on(execute_process_arm_for_test(
            &repository,
            &direct_root,
            request(
                "stage1-d",
                "stage1-d-run",
                &direct,
                PreMeasureSignaturePolicy::Establish {
                    accepted_record: &direct_signature,
                },
            ),
            &role_executable,
            &gateway_executable,
        ))
        .map_err(|error| format!("direct arm: {error}"))?;
    validate_leaf(&repository, &direct_root, &direct_outcome, EvidenceClass::D)?;

    let authoritative_root = scratch.path("authoritative");
    fs::create_dir(&authoritative_root)?;
    let authoritative = planned(EvidenceClass::A, 0, Some(Arm::B11), None);
    let authoritative_outcome = runtime
        .block_on(execute_process_arm_for_test(
            &repository,
            &authoritative_root,
            request(
                "stage1-a",
                "stage1-a-run",
                &authoritative,
                PreMeasureSignaturePolicy::Require {
                    accepted_record: &accepted_path,
                },
            ),
            &role_executable,
            &gateway_executable,
        ))
        .map_err(|error| format!("authoritative arm: {error}"))?;
    validate_leaf(
        &repository,
        &authoritative_root,
        &authoritative_outcome,
        EvidenceClass::A,
    )?;

    signature_mismatch_stops_before_measurement(
        &runtime,
        &repository,
        &role_executable,
        &gateway_executable,
        &scratch,
        &accepted,
    )?;
    interrupted_staging_is_not_a_raw_leaf(&repository, &scratch, &authoritative_outcome)?;
    if started.elapsed().as_secs() > 120 {
        return Err("process-arm integration exceeded its bounded 120-second wall".into());
    }
    println!("process-arms: PASS");
    Ok(())
}

fn planned(
    class: EvidenceClass,
    ordinal: u64,
    arm: Option<Arm>,
    direct_protocol: Option<Protocol>,
) -> PlannedArm {
    PlannedArm {
        ordinal,
        evidence_class: class,
        cell: Cell {
            workload: Workload::Get,
            concurrency: 1,
        },
        arm,
        direct_protocol,
        round: matches!(
            class,
            EvidenceClass::C | EvidenceClass::D | EvidenceClass::A
        )
        .then_some(0),
        row: matches!(class, EvidenceClass::C | EvidenceClass::A).then_some(0),
        target: (class == EvidenceClass::S).then_some(5_000),
        lane_quotas: if class == EvidenceClass::S {
            vec![5_000]
        } else {
            Vec::new()
        },
        fresh_process_set: true,
    }
}

fn request<'a>(
    evidence_id: &'a str,
    run_id: &'a str,
    planned: &'a PlannedArm,
    signature_policy: PreMeasureSignaturePolicy<'a>,
) -> ProcessArmRequest<'a> {
    ProcessArmRequest {
        evidence_id,
        run_id,
        planned,
        raw_ordinal: planned.ordinal,
        warmup_seconds: 3,
        measure_seconds: (planned.evidence_class != EvidenceClass::S).then_some(5),
        calibration_plan_sha256: (planned.evidence_class != EvidenceClass::S)
            .then_some("12dada094549b1a30934cba5b82a2e92b5cd4cae004f7052aa4103509eb1c0de"),
        signature_policy,
        trust_boundary: TrustBoundaryManifest::coordinated(
            "11".repeat(32),
            BASELINE_COMMIT.to_owned(),
            INITIAL_CANDIDATE_COMMIT.to_owned(),
        )
        .expect("test trust boundary"),
        frequency_gate: FrequencyGate::CalibrationAbsolute,
    }
}

fn validate_leaf(
    repository: &Path,
    evidence_root: &Path,
    outcome: &ProcessArmOutcome,
    class: EvidenceClass,
) -> Result<(), BoxError> {
    let leaf = repository.join(&outcome.raw_leaf);
    let relative = leaf.strip_prefix(evidence_root)?;
    let parsed = raw::validate_evidence_leaf(&leaf, relative)?;
    if parsed.metadata.class != class {
        return Err("raw leaf class differs from executed arm".into());
    }
    if parsed.resources.direct_ceiling_ops.is_some()
        || parsed.resources.gateway_ops.is_some()
        || parsed.resources.calibration_direct_ops.is_some()
    {
        return Err("per-arm raw resource evidence contains a cross-arm triple".into());
    }
    if class.has_latencies() == parsed.latencies_ns.is_empty() {
        return Err("raw latency membership differs from evidence class".into());
    }
    if parsed.materialization.is_some() {
        return Err("ordinary process arm retained smoke-specific materialization waves".into());
    }
    let arms = raw::validate_evidence_tree(evidence_root)?;
    if arms.len() != 1 {
        return Err("independent evidence root did not contain exactly one valid arm".into());
    }
    Ok(())
}

fn signature_mismatch_stops_before_measurement(
    runtime: &tokio::runtime::Runtime,
    repository: &Path,
    role_executable: &Path,
    gateway_executable: &Path,
    scratch: &Scratch,
    accepted: &AcceptedSignatureRecord,
) -> Result<(), BoxError> {
    let root = scratch.path("signature-mismatch");
    fs::create_dir(&root)?;
    let bad_path = root.join("signatures/get-c1/B11.json");
    fs::create_dir_all(bad_path.parent().ok_or("bad signature has no parent")?)?;
    let mut bad = accepted.clone();
    bad.signature_sha256 = sha256_hex(b"intentionally different exact signature");
    json::write_new_canonical(&bad_path, &bad)?;
    let arm = planned(EvidenceClass::A, 0, Some(Arm::B11), None);
    let result = runtime.block_on(execute_process_arm_for_test(
        repository,
        &root,
        request(
            "stage1-a-mismatch",
            "stage1-a-mismatch-run",
            &arm,
            PreMeasureSignaturePolicy::Require {
                accepted_record: &bad_path,
            },
        ),
        role_executable,
        gateway_executable,
    ));
    if result.is_ok() || root.join("arms/0/get-c1/B11").exists() {
        return Err("signature mismatch published a final authoritative leaf".into());
    }
    if root.join(".arm-runtime-000000-get-c1").exists()
        || root.join(".arm-staging/a-000000-get-c1-B11").exists()
    {
        return Err("signature mismatch retained runtime secrets or staging bytes".into());
    }
    let failures = fs::read_dir(root.join("arm-failures/a"))?.collect::<Result<Vec<_>, _>>()?;
    if failures.len() != 1 {
        return Err("signature mismatch did not retain exactly one arm failure".into());
    }
    let failure_bytes = fs::read(failures[0].path())?;
    let failure_text = String::from_utf8(failure_bytes.clone())?;
    if failure_bytes.len() > 65_536
        || ["cookie", "token", "secret", "environment"]
            .iter()
            .any(|forbidden| failure_text.contains(forbidden))
    {
        return Err("arm failure is unbounded or contains a secret-bearing field".into());
    }
    let failure: ArmFailureRecord = json::require_canonical(&failure_bytes)?;
    failure.validate()?;
    if failure.stage != auth_mini_http2_regression::control::RoleErrorStage::Freeze
        || failure.code != auth_mini_http2_regression::control::RoleErrorCode::SignatureMismatch
        || failure.measured_work_started
        || !failure.runtime_cleaned
        || !failure.staging_cleaned
    {
        return Err(
            "signature mismatch failure classification is not pre-measure and clean".into(),
        );
    }
    Ok(())
}

fn interrupted_staging_is_not_a_raw_leaf(
    repository: &Path,
    scratch: &Scratch,
    source: &ProcessArmOutcome,
) -> Result<(), BoxError> {
    let root = scratch.path("interrupted");
    let staging = root.join(".arm-staging/interrupted");
    fs::create_dir_all(&staging)?;
    fs::copy(
        repository.join(&source.raw_leaf).join("metadata.json"),
        staging.join("metadata.json"),
    )?;
    let final_relative = Path::new("arms/0/get-c1/B11");
    if raw::validate_evidence_leaf(&staging, final_relative).is_ok() {
        return Err("truncated staging leaf passed independent validation".into());
    }
    let inspection = raw::inspect_evidence_tree(&root)?;
    if !inspection.arms.is_empty()
        || !inspection.blockers.is_empty()
        || root.join(final_relative).exists()
    {
        return Err("interrupted staging bytes masqueraded as a final raw leaf".into());
    }
    Ok(())
}
