use auth_mini_http2_regression::archive;
use auth_mini_http2_regression::bundle::{chunk_ranges, create_bundle, verify_bundle, BundleIndex};
use auth_mini_http2_regression::codec;
use auth_mini_http2_regression::json;
use auth_mini_http2_regression::raw::{self, COMMON_ARM_MEMBERS};
use auth_mini_http2_regression::schema::{
    Arm, Cell, EvidenceClass, EvidenceKind, Intent, RawArmMetadata, RawLimits, TerminalState,
    Workload, ARM_SCHEMA, BASELINE_COMMIT, INITIAL_CANDIDATE_COMMIT, INTENT_SCHEMA,
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
    let leaf = root.join("arms/000/get-c1/B11");
    fs::create_dir_all(&leaf).expect("arm leaf");
    let drained = if class.has_latencies() { 3 } else { 10 };
    let metadata = RawArmMetadata {
        schema: ARM_SCHEMA.to_owned(),
        class,
        cell: Cell {
            workload: Workload::Get,
            concurrency: 1,
        },
        arm: Some(Arm::B11),
        started_operations: drained,
        deadline_completions: drained,
        drained_operations: drained,
        latency_record_ceiling: if class.has_latencies() { drained } else { 0 },
    };
    json::write_new_canonical(&leaf.join("metadata.json"), &metadata).expect("metadata");
    for member in COMMON_ARM_MEMBERS {
        if member == "metadata.json" {
            continue;
        }
        let bytes: &[u8] = if member.ends_with(".json") {
            b"{}\n"
        } else {
            b"bounded-raw-record"
        };
        fs::write(leaf.join(member), bytes).expect("raw member");
    }
    if class.has_latencies() {
        raw::write_latencies_new(&leaf.join("latencies.u64le"), class, &[10, 20, 30])
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
    let mut patterned = Vec::new();
    for index in 0_u32..50_000 {
        patterned.extend_from_slice(b"component/schema/member/repeated-prefix/");
        patterned.extend_from_slice(&(index % 997).to_le_bytes());
        patterned.extend_from_slice(b"/record-boundary\n");
    }
    fs::write(source.join("component-records.bin"), patterned).expect("patterned evidence");
    fs::remove_file(source.join("seal.json")).expect("replace fixture seal before observation");
    seal::create_seal(&source).expect("reseal fixture");
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
    fs::remove_file(missing_latency.join("arms/000/get-c1/B11/latencies.u64le"))
        .expect("remove required latency");
    assert!(seal::verify_seal(&missing_latency).is_err());

    let forbidden_latency = scratch.path("forbidden-latency");
    create_source(&forbidden_latency, EvidenceClass::S);
    fs::write(
        forbidden_latency.join("arms/000/get-c1/B11/latencies.u64le"),
        b"forbidden",
    )
    .expect("forbidden member");
    fs::remove_file(forbidden_latency.join("seal.json")).expect("fixture reseal");
    seal::create_seal(&forbidden_latency).expect("reseal invalid class fixture");
    assert!(raw::validate_evidence_tree(&forbidden_latency).is_err());

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
