use crate::archive::{self, ArchiveMember};
use crate::codec;
use crate::evidence;
use crate::json;
use crate::raw;
use crate::schema::{
    validate_identifier, validate_non_placeholder_sha256, CodecIdentity, EvidenceKind, Intent,
    ResolvedZstdParameters, TerminalState, ARCHIVE_SCHEMA, BUNDLE_SCHEMA, CHUNK_BYTES,
    DELIVERY_SCHEMA, EXECUTION_SCHEMA, JSON_MAX_BYTES, MAX_ARCHIVE_MEMBERS, TASK_CAP_BYTES,
};
use crate::seal::{self, sha256_hex, validate_relative_path, SealManifest};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};

struct OutputDirectoryGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for OutputDirectoryGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkEntry {
    pub ordinal: u32,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

impl ChunkEntry {
    pub fn validate(&self, expected_ordinal: u32, is_last: bool) -> Result<()> {
        if self.ordinal != expected_ordinal
            || self.path != format!("chunks/{expected_ordinal:06}.tar.zst.part")
        {
            return Err(Error::new(
                "chunk ordinal/path is not canonical and contiguous",
            ));
        }
        validate_relative_path(&self.path)?;
        validate_non_placeholder_sha256("chunk sha256", &self.sha256)?;
        if self.bytes == 0 || self.bytes > CHUNK_BYTES || (!is_last && self.bytes != CHUNK_BYTES) {
            return Err(Error::new(
                "chunk length violates the fixed 48 MiB partition",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleIndex {
    pub schema: String,
    pub archive_schema: String,
    pub evidence_schema: String,
    pub evidence_kind: EvidenceKind,
    pub evidence_id: String,
    pub terminal_state: TerminalState,
    pub baseline_commit: String,
    pub candidate_commit: String,
    pub intent_sha256: String,
    pub uncompressed_seal_root_sha256: String,
    pub seal_entry_count: u64,
    pub archive_member_count: u64,
    pub source_payload_bytes: u64,
    pub canonical_archive_bytes: u64,
    pub canonical_archive_sha256: String,
    pub encoder: CodecIdentity,
    pub producer_executable_sha256: String,
    pub parameters: ResolvedZstdParameters,
    pub compressed_stream_bytes: u64,
    pub compressed_stream_sha256: String,
    pub chunk_bytes: u64,
    pub chunk_total_bytes: u64,
    pub chunks: Vec<ChunkEntry>,
    pub compression_profile_path: Option<String>,
    pub compression_profile_bytes: Option<u64>,
    pub compression_profile_sha256: Option<String>,
}

impl BundleIndex {
    pub fn validate(&self) -> Result<()> {
        if self.schema != BUNDLE_SCHEMA
            || self.archive_schema != ARCHIVE_SCHEMA
            || self.evidence_schema != EXECUTION_SCHEMA
            || self.chunk_bytes != CHUNK_BYTES
        {
            return Err(Error::new(
                "unsupported bundle/archive/evidence/chunk schema",
            ));
        }
        validate_identifier("evidence_id", &self.evidence_id)?;
        crate::schema::validate_commit("baseline_commit", &self.baseline_commit)?;
        crate::schema::validate_commit("candidate_commit", &self.candidate_commit)?;
        for (name, value) in [
            ("intent_sha256", &self.intent_sha256),
            ("seal root", &self.uncompressed_seal_root_sha256),
            ("archive sha256", &self.canonical_archive_sha256),
            ("compressed sha256", &self.compressed_stream_sha256),
            (
                "producer executable sha256",
                &self.producer_executable_sha256,
            ),
        ] {
            validate_non_placeholder_sha256(name, value)?;
        }
        self.encoder.validate()?;
        self.parameters.validate()?;
        let expected_members = self.seal_entry_count.checked_add(1);
        let minimum_archive_bytes = self
            .archive_member_count
            .checked_mul(512)
            .and_then(|headers| headers.checked_add(1_024))
            .and_then(|base| {
                self.source_payload_bytes
                    .checked_add(511)
                    .map(|value| (value / 512) * 512)
                    .and_then(|payload| base.checked_add(payload))
            });
        if self.parameters.pledged_source_size != self.canonical_archive_bytes
            || expected_members != Some(self.archive_member_count)
            || self.chunks.is_empty()
            || self.archive_member_count > MAX_ARCHIVE_MEMBERS
            || self.canonical_archive_bytes > TASK_CAP_BYTES
            || self.compressed_stream_bytes > TASK_CAP_BYTES
            || self.chunk_total_bytes > TASK_CAP_BYTES
            || self.source_payload_bytes > self.canonical_archive_bytes
            || minimum_archive_bytes.is_none_or(|minimum| minimum > self.canonical_archive_bytes)
        {
            return Err(Error::new(
                "bundle counts or pledged source size are inconsistent",
            ));
        }
        let mut chunk_total = 0_u64;
        for (index, chunk) in self.chunks.iter().enumerate() {
            chunk.validate(
                u32::try_from(index).map_err(|_| Error::new("chunk index overflow"))?,
                index + 1 == self.chunks.len(),
            )?;
            chunk_total = chunk_total
                .checked_add(chunk.bytes)
                .ok_or_else(|| Error::new("chunk byte total overflow"))?;
        }
        if chunk_total != self.chunk_total_bytes || chunk_total != self.compressed_stream_bytes {
            return Err(Error::new("chunk/compressed byte totals differ"));
        }
        match (
            &self.compression_profile_path,
            self.compression_profile_bytes,
            &self.compression_profile_sha256,
        ) {
            (Some(path), Some(bytes), Some(hash)) => {
                if self.evidence_kind != EvidenceKind::Calibration
                    || path != "compression-profile.json"
                    || bytes == 0
                    || bytes > JSON_MAX_BYTES
                {
                    return Err(Error::new(
                        "invalid calibration compression-profile identity",
                    ));
                }
                validate_relative_path(path)?;
                validate_non_placeholder_sha256("compression profile sha256", hash)?;
            }
            (None, None, None) => {}
            _ => {
                return Err(Error::new(
                    "compression profile path/length/hash optionality differs",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReceipt {
    pub schema: String,
    pub bundle_index_sha256: String,
    pub evidence_id: String,
    pub seal_root_sha256: String,
    pub extracted_intent_sha256: String,
    pub expected_encoder: CodecIdentity,
    pub verifier_encoder: CodecIdentity,
    pub producer_executable_sha256: String,
    pub verifier_executable_sha256: String,
    pub parameter_map_sha256: String,
    pub terminal_state: TerminalState,
    pub canonical_archive_bytes: u64,
    pub canonical_archive_sha256: String,
    pub recompressed_bytes: u64,
    pub recompressed_sha256: String,
    pub byte_equal: bool,
    pub raw_arm_count: u64,
    pub compression_profile_root_sha256: Option<String>,
    pub analysis_input_ignored: bool,
    pub ordered_steps: Vec<String>,
    pub success: bool,
}

impl VerificationReceipt {
    pub fn validate(&self) -> Result<()> {
        if self.schema != BUNDLE_SCHEMA
            || !self.success
            || !self.byte_equal
            || !self.analysis_input_ignored
        {
            return Err(Error::new(
                "verification receipt is not a structural success",
            ));
        }
        validate_identifier("evidence_id", &self.evidence_id)?;
        for value in [
            &self.bundle_index_sha256,
            &self.seal_root_sha256,
            &self.extracted_intent_sha256,
            &self.canonical_archive_sha256,
            &self.recompressed_sha256,
            &self.producer_executable_sha256,
            &self.verifier_executable_sha256,
            &self.parameter_map_sha256,
        ] {
            validate_non_placeholder_sha256("receipt hash", value)?;
        }
        self.expected_encoder.validate()?;
        self.verifier_encoder.validate()?;
        if self.expected_encoder != self.verifier_encoder {
            return Err(Error::new(
                "verification receipt encoder source identities differ",
            ));
        }
        if let Some(root) = &self.compression_profile_root_sha256 {
            validate_non_placeholder_sha256("receipt compression profile root", root)?;
        }
        let expected_steps = [
            "index-and-chunks",
            "decode-and-parse",
            "seal-and-intent",
            "canonical-reconstruction",
            "exact-recompression",
            "independent-raw-recomputation",
        ];
        if self
            .ordered_steps
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_steps
        {
            return Err(Error::new("verification steps are missing or out of order"));
        }
        Ok(())
    }
}

pub fn chunk_ranges(length: u64) -> Result<Vec<Range<u64>>> {
    if length == 0 {
        return Err(Error::new("empty compressed stream cannot be chunked"));
    }
    let count = length
        .checked_add(CHUNK_BYTES - 1)
        .map(|value| value / CHUNK_BYTES)
        .ok_or_else(|| Error::new("chunk count overflow"))?;
    let capacity =
        usize::try_from(count).map_err(|_| Error::new("chunk count does not fit usize"))?;
    let mut ranges = Vec::with_capacity(capacity);
    for ordinal in 0..count {
        let start = ordinal
            .checked_mul(CHUNK_BYTES)
            .ok_or_else(|| Error::new("chunk start overflow"))?;
        let end = start
            .checked_add(CHUNK_BYTES)
            .map(|candidate| candidate.min(length))
            .ok_or_else(|| Error::new("chunk end overflow"))?;
        if start >= end {
            return Err(Error::new("chunk projection emitted an empty range"));
        }
        ranges.push(start..end);
    }
    Ok(ranges)
}

pub fn create_bundle(
    source: &Path,
    output_directory: &Path,
    terminal_state: TerminalState,
) -> Result<BundleIndex> {
    let index = create_bundle_derived(source, output_directory)?;
    if index.terminal_state != terminal_state {
        return Err(Error::new(
            "caller terminal label differs from the sealed raw-derived terminal state",
        ));
    }
    Ok(index)
}

pub fn create_bundle_derived(source: &Path, output_directory: &Path) -> Result<BundleIndex> {
    let repository = repository_root(source)?;
    let output_directory = ensure_repository_local(output_directory, &repository)?;
    if fs::symlink_metadata(&output_directory).is_ok() {
        return Err(Error::new(
            "bundle output already exists; overwrite is forbidden",
        ));
    }
    let source_verification = verify_source_structural(source)?;
    let structural_terminal = source_verification.terminal_state;
    let seal = source_verification.seal;
    let intent_bytes = source_verification.intent_bytes;
    let intent = source_verification.intent;
    let current_encoder = codec::current_identity();
    let producer_executable_sha256 = intent.producer_executable_sha256.clone();
    let canonical = archive::canonical_archive(source, &seal)?;
    let canonical_len = u64::try_from(canonical.len())
        .map_err(|_| Error::new("canonical archive length overflow"))?;
    let parameters = codec::resolve_parameters(canonical_len)?;
    let compressed = codec::encode(&canonical, &parameters)?;
    let ranges = chunk_ranges(
        u64::try_from(compressed.len()).map_err(|_| Error::new("compressed length overflow"))?,
    )?;

    create_secure_repository_parents(
        output_directory
            .parent()
            .ok_or_else(|| Error::new("bundle output directory has no parent"))?,
        &repository,
    )?;
    fs::create_dir(&output_directory).map_err(|error| {
        Error::new(format!(
            "cannot create bundle output {}: {error}",
            output_directory.display()
        ))
    })?;
    let mut output_guard = OutputDirectoryGuard {
        path: output_directory.clone(),
        armed: true,
    };
    set_directory_mode(&output_directory, 0o700)?;
    let chunks_directory = output_directory.join("chunks");
    fs::create_dir(&chunks_directory)?;
    set_directory_mode(&chunks_directory, 0o700)?;
    let mut chunks = Vec::with_capacity(ranges.len());
    for (ordinal, range) in ranges.iter().enumerate() {
        let start = usize::try_from(range.start).map_err(|_| Error::new("chunk start overflow"))?;
        let end = usize::try_from(range.end).map_err(|_| Error::new("chunk end overflow"))?;
        let bytes = &compressed[start..end];
        let ordinal_u32 =
            u32::try_from(ordinal).map_err(|_| Error::new("chunk ordinal overflow"))?;
        let relative = format!("chunks/{ordinal_u32:06}.tar.zst.part");
        write_new(&output_directory.join(&relative), bytes)?;
        chunks.push(ChunkEntry {
            ordinal: ordinal_u32,
            path: relative,
            bytes: u64::try_from(bytes.len()).map_err(|_| Error::new("chunk length overflow"))?,
            sha256: sha256_hex(bytes),
        });
    }
    let source_payload_bytes = seal.entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.bytes)
            .ok_or_else(|| Error::new("source payload total overflow"))
    })?;
    let compressed_len =
        u64::try_from(compressed.len()).map_err(|_| Error::new("compressed length overflow"))?;
    let compression_profile = build_compression_profile(source, &intent, &intent_bytes)?;
    let (compression_profile_path, compression_profile_bytes, compression_profile_sha256) =
        if let Some(profile) = &compression_profile {
            let bytes = json::canonical_bytes(profile)?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > JSON_MAX_BYTES {
                return Err(Error::new("compression profile exceeds 1 MiB"));
            }
            write_new(&output_directory.join("compression-profile.json"), &bytes)?;
            (
                Some("compression-profile.json".to_owned()),
                Some(
                    u64::try_from(bytes.len())
                        .map_err(|_| Error::new("compression profile length does not fit u64"))?,
                ),
                Some(sha256_hex(&bytes)),
            )
        } else {
            (None, None, None)
        };
    let index = BundleIndex {
        schema: BUNDLE_SCHEMA.to_owned(),
        archive_schema: ARCHIVE_SCHEMA.to_owned(),
        evidence_schema: EXECUTION_SCHEMA.to_owned(),
        evidence_kind: intent.evidence_kind,
        evidence_id: intent.evidence_id.clone(),
        terminal_state: structural_terminal,
        baseline_commit: intent.baseline_commit,
        candidate_commit: intent.candidate_commit,
        intent_sha256: sha256_hex(&intent_bytes),
        uncompressed_seal_root_sha256: seal.root_sha256,
        seal_entry_count: u64::try_from(seal.entries.len())
            .map_err(|_| Error::new("seal entry count overflow"))?,
        archive_member_count: u64::try_from(seal.entries.len() + 1)
            .map_err(|_| Error::new("archive member count overflow"))?,
        source_payload_bytes,
        canonical_archive_bytes: canonical_len,
        canonical_archive_sha256: sha256_hex(&canonical),
        encoder: current_encoder,
        producer_executable_sha256,
        parameters,
        compressed_stream_bytes: compressed_len,
        compressed_stream_sha256: sha256_hex(&compressed),
        chunk_bytes: CHUNK_BYTES,
        chunk_total_bytes: compressed_len,
        chunks,
        compression_profile_path,
        compression_profile_bytes,
        compression_profile_sha256,
    };
    enforce_actual_task_cap(source, &output_directory, JSON_MAX_BYTES)?;
    let derived = evidence::verify_raw_closure(source)?;
    let terminal_state = derived.terminal_state;
    let mut index = index;
    index.terminal_state = terminal_state;
    index.validate()?;
    json::write_new_canonical(&output_directory.join("bundle-index.json"), &index)?;
    enforce_actual_task_cap(source, &output_directory, 0)?;
    File::open(&output_directory)?.sync_all()?;
    File::open(
        output_directory
            .parent()
            .ok_or_else(|| Error::new("bundle output directory has no parent"))?,
    )?
    .sync_all()?;
    output_guard.armed = false;
    Ok(index)
}

pub fn verify_bundle(index_path: &Path, scratch: &Path) -> Result<VerificationReceipt> {
    let repository = repository_root(index_path)?;
    let scratch = ensure_repository_local(scratch, &repository)?;
    if fs::symlink_metadata(&scratch).is_ok() {
        return Err(Error::new(
            "verification scratch already exists or is stale",
        ));
    }
    let index_bytes = fs::read(index_path)?;
    if u64::try_from(index_bytes.len()).unwrap_or(u64::MAX) > JSON_MAX_BYTES {
        return Err(Error::new("bundle index exceeds 1 MiB"));
    }
    let index: BundleIndex = json::require_canonical(&index_bytes)?;
    index.validate()?;
    let bundle_root = index_path
        .parent()
        .ok_or_else(|| Error::new("bundle index has no parent"))?;
    let compressed = read_exact_chunks(bundle_root, &index)?;
    let canonical = codec::decode(&compressed, index.canonical_archive_bytes)?;
    if sha256_hex(&canonical) != index.canonical_archive_sha256 {
        return Err(Error::new("decoded canonical archive hash mismatch"));
    }
    let members = archive::parse_canonical_archive(&canonical)?;
    if u64::try_from(members.len()).unwrap_or(u64::MAX) != index.archive_member_count {
        return Err(Error::new("canonical archive member count mismatch"));
    }

    create_secure_repository_parents(
        scratch
            .parent()
            .ok_or_else(|| Error::new("verification scratch has no parent"))?,
        &repository,
    )?;
    fs::create_dir(&scratch).map_err(|error| {
        Error::new(format!(
            "cannot create verification scratch {}: {error}",
            scratch.display()
        ))
    })?;
    set_directory_mode(&scratch, 0o700)?;
    extract_members(&scratch, &members)?;
    let seal_bytes = fs::read(scratch.join("seal.json"))?;
    let seal: SealManifest = json::require_canonical(&seal_bytes)?;
    seal.validate()?;
    if seal.root_sha256 != index.uncompressed_seal_root_sha256
        || u64::try_from(seal.entries.len()).unwrap_or(u64::MAX) != index.seal_entry_count
    {
        return Err(Error::new(
            "extracted seal root/count differs from bundle index",
        ));
    }
    let verified_seal = seal::verify_seal(&scratch)?;
    if verified_seal != seal {
        return Err(Error::new(
            "extracted seal verification changed the manifest",
        ));
    }
    let intent_bytes = fs::read(scratch.join("intent.json"))?;
    let intent: Intent = json::require_canonical(&intent_bytes)?;
    intent.validate()?;
    if sha256_hex(&intent_bytes) != index.intent_sha256
        || intent.evidence_id != index.evidence_id
        || intent.evidence_kind != index.evidence_kind
        || intent.baseline_commit != index.baseline_commit
        || intent.candidate_commit != index.candidate_commit
        || intent.producer_executable_sha256 != index.producer_executable_sha256
    {
        return Err(Error::new(
            "extracted intent identity differs from bundle index",
        ));
    }
    let verifier_encoder = codec::current_identity();
    if intent.encoder != verifier_encoder || index.encoder != intent.encoder {
        return Err(Error::new(
            "extracted intent/index/local encoder identities differ",
        ));
    }
    let expected_parameters = codec::resolve_parameters(index.canonical_archive_bytes)?;
    if expected_parameters != index.parameters || intent.zstd != expected_parameters.program {
        return Err(Error::new(
            "intent-derived Zstandard parameter vector differs from index",
        ));
    }

    let reconstructed = archive::canonical_archive(&scratch, &seal)?;
    if reconstructed != canonical
        || u64::try_from(reconstructed.len()).unwrap_or(u64::MAX) != index.canonical_archive_bytes
        || sha256_hex(&reconstructed) != index.canonical_archive_sha256
    {
        return Err(Error::new(
            "canonical reconstruction byte/length/hash mismatch",
        ));
    }
    let recompressed = codec::encode(&reconstructed, &expected_parameters)?;
    if recompressed != compressed
        || u64::try_from(recompressed.len()).unwrap_or(u64::MAX) != index.compressed_stream_bytes
        || sha256_hex(&recompressed) != index.compressed_stream_sha256
    {
        return Err(Error::new(
            "exact intent-derived recompression byte/length/hash mismatch",
        ));
    }
    verify_chunk_projection(&recompressed, &index)?;

    // This deliberately occurs only after exact recompression succeeds and after the
    // staged bundle's fresh-walk actual-cap check.
    enforce_actual_task_cap(index_path, bundle_root, 0)?;
    let verified = evidence::verify_raw_closure(&scratch)?;
    if verified.terminal_state != index.terminal_state {
        return Err(Error::new(
            "bundle terminal label differs from sealed raw-derived evidence",
        ));
    }
    let verified_profile =
        verify_compression_profile(bundle_root, &scratch, &intent, &intent_bytes, &index)?;
    let receipt = VerificationReceipt {
        schema: BUNDLE_SCHEMA.to_owned(),
        bundle_index_sha256: sha256_hex(&index_bytes),
        evidence_id: index.evidence_id,
        seal_root_sha256: seal.root_sha256,
        extracted_intent_sha256: sha256_hex(&intent_bytes),
        expected_encoder: intent.encoder,
        verifier_encoder,
        producer_executable_sha256: index.producer_executable_sha256,
        verifier_executable_sha256: codec::current_executable_sha256()?,
        parameter_map_sha256: expected_parameters.parameter_map_sha256.clone(),
        terminal_state: verified.terminal_state,
        canonical_archive_bytes: index.canonical_archive_bytes,
        canonical_archive_sha256: index.canonical_archive_sha256,
        recompressed_bytes: u64::try_from(recompressed.len())
            .map_err(|_| Error::new("recompressed length overflow"))?,
        recompressed_sha256: sha256_hex(&recompressed),
        byte_equal: true,
        raw_arm_count: u64::try_from(verified.arms.len())
            .map_err(|_| Error::new("raw arm count overflow"))?,
        compression_profile_root_sha256: verified_profile
            .as_ref()
            .map(|profile| profile.root_sha256.clone()),
        analysis_input_ignored: true,
        ordered_steps: [
            "index-and-chunks",
            "decode-and-parse",
            "seal-and-intent",
            "canonical-reconstruction",
            "exact-recompression",
            "independent-raw-recomputation",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        success: true,
    };
    receipt.validate()?;
    fs::remove_dir_all(&scratch)?;
    Ok(receipt)
}

#[derive(Debug)]
pub struct SourceVerification {
    pub seal: SealManifest,
    pub intent: Intent,
    pub intent_bytes: Vec<u8>,
    pub raw_arm_count: u64,
    pub terminal_state: TerminalState,
    pub reasons: Vec<String>,
}

pub fn verify_source(source: &Path) -> Result<SourceVerification> {
    verify_source_mode(source, true)
}

fn verify_source_structural(source: &Path) -> Result<SourceVerification> {
    verify_source_mode(source, false)
}

fn verify_source_mode(source: &Path, analyze: bool) -> Result<SourceVerification> {
    let verified = if analyze {
        evidence::verify_raw_closure(source)?
    } else {
        evidence::verify_raw_closure_structural(source)?
    };
    let seal = verified.seal;
    let intent_bytes = verified.intent_bytes;
    let intent = verified.intent;
    if intent.encoder != codec::current_identity() {
        return Err(Error::new(
            "intent encoder identity differs from the current pinned encoder",
        ));
    }
    Ok(SourceVerification {
        seal,
        intent,
        intent_bytes,
        raw_arm_count: u64::try_from(verified.arms.len())
            .map_err(|_| Error::new("raw arm count overflow"))?,
        terminal_state: verified.terminal_state,
        reasons: verified.reasons,
    })
}

#[derive(Debug)]
struct CompressionAccumulator {
    arm_bytes: u64,
    arm_records: u64,
    arm_hash: String,
    per_record_bytes: u64,
    record_hash: String,
}

fn build_compression_profile(
    source: &Path,
    intent: &Intent,
    intent_bytes: &[u8],
) -> Result<Option<crate::storage::CompressionProfile>> {
    if intent.evidence_kind != EvidenceKind::Calibration {
        return Ok(None);
    }
    let inspection = raw::inspect_evidence_tree(source)?;
    if !inspection.blockers.is_empty() {
        return Err(Error::new(inspection.blockers.join("; ")));
    }
    let arms = inspection.arms;
    let eligible = arms
        .iter()
        .filter(|arm| {
            matches!(
                arm.metadata.class,
                crate::schema::EvidenceClass::C | crate::schema::EvidenceClass::D
            )
        })
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return Ok(None);
    }
    let mut maxima: BTreeMap<(String, String), CompressionAccumulator> = BTreeMap::new();
    for arm in eligible {
        let match_key = compression_match_key(arm);
        let mut members = raw::COMMON_ARM_MEMBERS.to_vec();
        if arm.metadata.class.has_latencies() {
            members.push("latencies.u64le");
        }
        for member in members {
            let member_path = arm.leaf.join(member);
            let bytes = fs::read(&member_path)?;
            let member_hash = sha256_hex(&bytes);
            let archive_path = member_path
                .strip_prefix(source)
                .map_err(|_| Error::new("compression-profile member escaped source root"))?
                .to_str()
                .ok_or_else(|| Error::new("compression-profile path is not UTF-8"))?
                .replace('\\', "/");
            let mini_archive = archive::canonical_archive_from_members(&[ArchiveMember {
                path: archive_path,
                bytes,
            }])?;
            let parameters = codec::resolve_parameters(
                u64::try_from(mini_archive.len())
                    .map_err(|_| Error::new("component mini-archive length overflow"))?,
            )?;
            let compressed = codec::encode(&mini_archive, &parameters)?;
            let compressed_bytes = u64::try_from(compressed.len())
                .map_err(|_| Error::new("component compressed length overflow"))?;
            let records = component_record_count(arm, member)?;
            let per_record = compressed_bytes
                .checked_add(records - 1)
                .map(|value| value / records)
                .ok_or_else(|| Error::new("component per-record ceiling overflow"))?;
            let entry = maxima
                .entry((match_key.clone(), member.to_owned()))
                .or_insert_with(|| CompressionAccumulator {
                    arm_bytes: compressed_bytes,
                    arm_records: records,
                    arm_hash: member_hash.clone(),
                    per_record_bytes: per_record,
                    record_hash: member_hash.clone(),
                });
            if compressed_bytes > entry.arm_bytes
                || (compressed_bytes == entry.arm_bytes && member_hash < entry.arm_hash)
            {
                entry.arm_bytes = compressed_bytes;
                entry.arm_records = records;
                entry.arm_hash.clone_from(&member_hash);
            }
            if per_record > entry.per_record_bytes
                || (per_record == entry.per_record_bytes && member_hash < entry.record_hash)
            {
                entry.per_record_bytes = per_record;
                entry.record_hash = member_hash;
            }
        }
    }
    let witnesses = maxima
        .into_iter()
        .map(
            |((match_key, component), value)| crate::storage::CompressionWitness {
                match_key,
                component,
                compressed_bytes_per_arm: value.arm_bytes,
                compressed_record_count: value.arm_records,
                witness_sha256: value.arm_hash,
                compressed_bytes_per_record: value.per_record_bytes,
                record_witness_sha256: value.record_hash,
            },
        )
        .collect::<Vec<_>>();
    let profile = crate::storage::CompressionProfile {
        schema: crate::storage::COMPRESSION_PROFILE_SCHEMA.to_owned(),
        evidence_id: intent.evidence_id.clone(),
        intent_sha256: sha256_hex(intent_bytes),
        root_sha256: crate::storage::compression_profile_root(&witnesses)?,
        witnesses,
    };
    profile.validate()?;
    Ok(Some(profile))
}

fn compression_match_key(arm: &raw::ParsedArm) -> String {
    let downstream_policy = connection_policy(
        arm.endpoints.downstream_protocol,
        arm.metadata.cell.workload,
        true,
        arm.metadata.class == crate::schema::EvidenceClass::D,
    );
    let upstream_policy = connection_policy(
        arm.endpoints.upstream_protocol,
        arm.metadata.cell.workload,
        false,
        arm.metadata.class == crate::schema::EvidenceClass::D,
    );
    match arm.metadata.class {
        crate::schema::EvidenceClass::C => format!(
            "gateway:{}:{}:c{}:down-{}-{}:up-{}-{}",
            arm.metadata.arm.map_or("missing", crate::schema::Arm::code),
            arm.metadata.cell.workload.code(),
            arm.metadata.cell.concurrency,
            protocol_code(arm.endpoints.downstream_protocol),
            downstream_policy,
            protocol_code(arm.endpoints.upstream_protocol),
            upstream_policy,
        ),
        crate::schema::EvidenceClass::D => format!(
            "direct:{}:{}:c{}:{}",
            protocol_code(
                arm.metadata
                    .direct_protocol
                    .unwrap_or(crate::schema::RawProtocol::H1),
            ),
            arm.metadata.cell.workload.code(),
            arm.metadata.cell.concurrency,
            downstream_policy,
        ),
        _ => "ineligible".to_owned(),
    }
}

fn protocol_code(protocol: crate::schema::RawProtocol) -> &'static str {
    match protocol {
        crate::schema::RawProtocol::H1 => "h1",
        crate::schema::RawProtocol::H2 => "h2",
    }
}

fn connection_policy(
    protocol: crate::schema::RawProtocol,
    workload: crate::schema::Workload,
    downstream: bool,
    direct: bool,
) -> &'static str {
    match (protocol, workload, downstream, direct) {
        (crate::schema::RawProtocol::H1, crate::schema::Workload::Upload1Mib, true, _) => {
            "fresh-close-eof"
        }
        (crate::schema::RawProtocol::H1, crate::schema::Workload::Upload1Mib, false, true) => {
            "fresh-close-eof"
        }
        (_, crate::schema::Workload::WebSocket, _, _) => "preestablished-tunnel",
        (crate::schema::RawProtocol::H2, _, _, _) => "persistent-multiplexed",
        (crate::schema::RawProtocol::H1, _, _, _) => "persistent",
    }
}

fn component_record_count(arm: &raw::ParsedArm, member: &str) -> Result<u64> {
    let count = match member {
        "metadata.json" | "quiet.json" | "operation-summary.bin" => 1,
        "materialization.json" => arm
            .materialization
            .as_ref()
            .map(|evidence| evidence.waves.len() as u64)
            .ok_or_else(|| Error::new("materialization profile member lacks parsed evidence"))?,
        "thread-map.json" => u64::try_from(arm.thread_map.threads.len())
            .map_err(|_| Error::new("thread-map record count overflow"))?,
        "thread-lifecycle.bin" => u64::try_from(arm.lifecycle.stages.len())
            .map_err(|_| Error::new("lifecycle record count overflow"))?
            .checked_add(arm.lifecycle.births_before_freeze)
            .and_then(|value| value.checked_add(arm.lifecycle.deaths_before_freeze))
            .ok_or_else(|| Error::new("lifecycle record count overflow"))?,
        "session-clock.bin" => u64::try_from(arm.session_clock.samples.len())
            .map_err(|_| Error::new("session-clock record count overflow"))?,
        "resources.bin" => u64::try_from(arm.resources.buckets.len())
            .ok()
            .and_then(|value| {
                u64::try_from(arm.resources.utilization.len())
                    .ok()
                    .and_then(|extra| value.checked_add(extra))
            })
            .ok_or_else(|| Error::new("resource record count overflow"))?,
        "endpoints.bin" => u64::try_from(arm.endpoints.phases.len())
            .map_err(|_| Error::new("endpoint record count overflow"))?,
        "latencies.u64le" => u64::try_from(arm.latencies_ns.len())
            .map_err(|_| Error::new("latency record count overflow"))?,
        _ => return Err(Error::new("unknown compression-profile component")),
    };
    Ok(count.max(1))
}

fn verify_compression_profile(
    bundle_root: &Path,
    extracted: &Path,
    intent: &Intent,
    intent_bytes: &[u8],
    index: &BundleIndex,
) -> Result<Option<crate::storage::CompressionProfile>> {
    let expected = build_compression_profile(extracted, intent, intent_bytes)?;
    match (
        expected,
        &index.compression_profile_path,
        index.compression_profile_bytes,
        &index.compression_profile_sha256,
    ) {
        (None, None, None, None) => Ok(None),
        (Some(expected), Some(relative), Some(length), Some(hash)) => {
            let path = bundle_root.join(relative);
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file() || metadata.len() != length {
                return Err(Error::new("compression profile type/length mismatch"));
            }
            let bytes = fs::read(path)?;
            if sha256_hex(&bytes) != *hash {
                return Err(Error::new("compression profile hash mismatch"));
            }
            let actual: crate::storage::CompressionProfile = json::require_canonical(&bytes)?;
            actual.validate()?;
            if actual != expected {
                return Err(Error::new(
                    "compression profile does not reproduce from extracted raw components",
                ));
            }
            Ok(Some(actual))
        }
        _ => Err(Error::new(
            "bundle compression-profile inventory differs from reached raw evidence",
        )),
    }
}

fn read_exact_chunks(bundle_root: &Path, index: &BundleIndex) -> Result<Vec<u8>> {
    let chunks_root = bundle_root.join("chunks");
    let metadata = fs::symlink_metadata(&chunks_root)?;
    if !metadata.file_type().is_dir() {
        return Err(Error::new("bundle chunks path is not a directory"));
    }
    let declared: BTreeSet<_> = index
        .chunks
        .iter()
        .map(|chunk| chunk.path.clone())
        .collect();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(&chunks_root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file() {
            return Err(Error::new("chunk directory contains a non-regular member"));
        }
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| Error::new("chunk name is not UTF-8"))?
            .to_owned();
        actual.insert(format!("chunks/{name}"));
    }
    if actual != declared {
        return Err(Error::new(
            "chunk directory has missing, extra, or reordered names",
        ));
    }
    let capacity = usize::try_from(index.compressed_stream_bytes)
        .map_err(|_| Error::new("compressed stream does not fit memory"))?;
    let mut compressed = Vec::with_capacity(capacity);
    for chunk in &index.chunks {
        let path = bundle_root.join(&chunk.path);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.len() != chunk.bytes {
            return Err(Error::new("chunk type/length mismatch"));
        }
        let bytes = fs::read(&path)?;
        if sha256_hex(&bytes) != chunk.sha256 {
            return Err(Error::new("chunk SHA-256 mismatch"));
        }
        compressed.extend_from_slice(&bytes);
    }
    if u64::try_from(compressed.len()).unwrap_or(u64::MAX) != index.compressed_stream_bytes
        || sha256_hex(&compressed) != index.compressed_stream_sha256
    {
        return Err(Error::new("compressed stream length/hash mismatch"));
    }
    Ok(compressed)
}

fn verify_chunk_projection(bytes: &[u8], index: &BundleIndex) -> Result<()> {
    let ranges = chunk_ranges(u64::try_from(bytes.len()).unwrap_or(u64::MAX))?;
    if ranges.len() != index.chunks.len() {
        return Err(Error::new("recompressed chunk count mismatch"));
    }
    for (range, chunk) in ranges.iter().zip(&index.chunks) {
        let start = usize::try_from(range.start).map_err(|_| Error::new("range overflow"))?;
        let end = usize::try_from(range.end).map_err(|_| Error::new("range overflow"))?;
        let projected = &bytes[start..end];
        if u64::try_from(projected.len()).unwrap_or(u64::MAX) != chunk.bytes
            || sha256_hex(projected) != chunk.sha256
        {
            return Err(Error::new("recompressed chunk boundary/hash mismatch"));
        }
    }
    Ok(())
}

fn extract_members(scratch: &Path, members: &[ArchiveMember]) -> Result<()> {
    let mut paths = BTreeSet::new();
    for member in members {
        validate_relative_path(&member.path)?;
        if !paths.insert(member.path.clone()) {
            return Err(Error::new("duplicate extraction path"));
        }
        let destination = scratch.join(&member.path);
        let parent = destination
            .parent()
            .ok_or_else(|| Error::new("extracted path has no parent"))?;
        fs::create_dir_all(parent)?;
        let parent_canonical = fs::canonicalize(parent)?;
        let scratch_canonical = fs::canonicalize(scratch)?;
        if !parent_canonical.starts_with(&scratch_canonical) {
            return Err(Error::new("extracted path escapes scratch root"));
        }
        write_new(&destination, &member.bytes)?;
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    json::write_new_bytes(path, bytes)
}

fn enforce_actual_task_cap(
    repository_path: &Path,
    staged_bundle: &Path,
    remaining_formal_maximum: u64,
) -> Result<()> {
    let repository = repository_root(repository_path)?;
    let artifact_root =
        repository.join(".legion/tasks/prove-http2-performance-regression/artifacts");
    let artifact_bytes = crate::storage::actual_regular_bytes_if_exists(&artifact_root)?;
    let staged_bytes = if staged_bundle.starts_with(&artifact_root) {
        0
    } else {
        crate::storage::actual_regular_bytes(staged_bundle)?
    };
    let actual = artifact_bytes
        .checked_add(staged_bytes)
        .ok_or_else(|| Error::new("actual tracked/staged byte total overflow"))?;
    if !crate::storage::actual_checkpoint_allows(actual, remaining_formal_maximum)? {
        return Err(Error::new(
            "fresh-walk task artifacts plus staged/formal bytes exceed 512 MiB",
        ));
    }
    Ok(())
}

pub fn repository_root(start: &Path) -> Result<PathBuf> {
    let absolute = fs::canonicalize(start)
        .map_err(|error| Error::new(format!("cannot canonicalize {}: {error}", start.display())))?;
    let mut current = if absolute.is_dir() {
        absolute
    } else {
        absolute
            .parent()
            .ok_or_else(|| Error::new("start path has no parent"))?
            .to_path_buf()
    };
    loop {
        if fs::symlink_metadata(current.join(".git")).is_ok() {
            return Ok(current);
        }
        if !current.pop() {
            return Err(Error::new("path is not inside a Git worktree"));
        }
    }
}

pub fn ensure_repository_local(path: &Path, repository: &Path) -> Result<PathBuf> {
    let repository = fs::canonicalize(repository)?;
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let normalized = lexical_normalize(&candidate)?;
    if !normalized.starts_with(&repository) {
        return Err(Error::new(format!(
            "path is outside repository: {}",
            path.display()
        )));
    }
    let mut existing_ancestor = normalized.clone();
    loop {
        match fs::symlink_metadata(&existing_ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !existing_ancestor.pop() {
                    return Err(Error::new("path has no existing ancestor"));
                }
            }
            Err(error) => {
                return Err(Error::new(format!(
                    "cannot inspect path ancestor {}: {error}",
                    existing_ancestor.display()
                )));
            }
        }
    }
    let resolved_ancestor = fs::canonicalize(&existing_ancestor)?;
    if !resolved_ancestor.starts_with(&repository) {
        return Err(Error::new(format!(
            "path resolves outside repository through an existing link: {}",
            path.display()
        )));
    }
    Ok(normalized)
}

pub fn ensure_cli_scratch(path: &Path, repository: &Path) -> Result<PathBuf> {
    let local = ensure_repository_local(path, repository)?;
    let required = repository
        .join(".perf")
        .join("prove-http2-performance-regression")
        .join("bundle-verify");
    if !local.starts_with(required) {
        return Err(Error::new(
            "verify-bundle scratch must be below .perf/prove-http2-performance-regression/bundle-verify",
        ));
    }
    Ok(local)
}

fn create_secure_repository_parents(directory: &Path, repository: &Path) -> Result<()> {
    let repository = fs::canonicalize(repository)?;
    let directory = ensure_repository_local(directory, &repository)?;
    let relative = directory
        .strip_prefix(&repository)
        .map_err(|_| Error::new("repository-local directory lost its prefix"))?;
    let mut current = repository.clone();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(Error::new(
                "secure repository parent contains a non-normal component",
            ));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err(Error::new(format!(
                        "bundle parent is not a real directory: {}",
                        current.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {
                        set_directory_mode(&current, 0o700)?;
                        File::open(
                            current
                                .parent()
                                .ok_or_else(|| Error::new("created parent has no parent"))?,
                        )?
                        .sync_all()?;
                    }
                    Err(race) if race.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(&current)?;
                        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                            return Err(Error::new(
                                "bundle parent creation raced with a non-directory",
                            ));
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
        let canonical = fs::canonicalize(&current)?;
        if !canonical.starts_with(&repository) || canonical != current {
            return Err(Error::new(
                "bundle parent resolves through a link or outside the repository",
            ));
        }
    }
    Ok(())
}

fn set_directory_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        let actual = fs::symlink_metadata(path)?.permissions().mode() & 0o777;
        if actual != mode {
            return Err(Error::new("strict bundle directory mode did not persist"));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Err(Error::new("strict bundle directory modes require Unix"))
    }
}

fn lexical_normalize(path: &Path) -> Result<PathBuf> {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(value) => output.push(value.as_os_str()),
            Component::RootDir => output.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if !output.pop() {
                    return Err(Error::new("path normalization escaped its root"));
                }
            }
            Component::Normal(value) => output.push(value),
        }
    }
    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryEntry {
    pub evidence_kind: EvidenceKind,
    pub evidence_id: String,
    pub bundle_index_path: String,
    pub bundle_index_sha256: String,
    pub verification_path: String,
    pub verification_sha256: String,
    pub result_path: Option<String>,
    pub result_sha256: Option<String>,
    pub report_path: Option<String>,
    pub report_sha256: Option<String>,
    pub seal_root_sha256: String,
    pub outcome: TerminalState,
    pub tracked_bytes: u64,
}

impl DeliveryEntry {
    pub fn validate(&self) -> Result<()> {
        validate_identifier("delivery evidence_id", &self.evidence_id)?;
        for path in [&self.bundle_index_path, &self.verification_path] {
            validate_relative_path(path)?;
        }
        for hash in [
            &self.bundle_index_sha256,
            &self.verification_sha256,
            &self.seal_root_sha256,
        ] {
            validate_non_placeholder_sha256("delivery hash", hash)?;
        }
        match (&self.result_path, &self.result_sha256) {
            (Some(path), Some(hash)) => {
                validate_relative_path(path)?;
                validate_non_placeholder_sha256("result hash", hash)?;
            }
            (None, None) => {}
            _ => return Err(Error::new("delivery result path/hash optionality differs")),
        }
        match (&self.report_path, &self.report_sha256) {
            (Some(path), Some(hash)) => {
                validate_relative_path(path)?;
                validate_non_placeholder_sha256("report hash", hash)?;
            }
            (None, None) => {}
            _ => return Err(Error::new("delivery report path/hash optionality differs")),
        }
        if self.tracked_bytes == 0 {
            return Err(Error::new("delivery entry tracked bytes must be nonzero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryLedger {
    pub schema: String,
    pub predecessor: Option<LedgerPredecessor>,
    pub entries: Vec<DeliveryEntry>,
    pub aggregate_bytes_excluding_ledger: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerPredecessor {
    pub path: String,
    pub sha256: String,
}

impl LedgerPredecessor {
    pub fn validate(&self) -> Result<()> {
        if self.path != "delivery-index.json" {
            return Err(Error::new("delivery predecessor path is not canonical"));
        }
        validate_relative_path(&self.path)?;
        validate_non_placeholder_sha256("delivery predecessor sha256", &self.sha256)
    }
}

impl DeliveryLedger {
    pub fn empty() -> Self {
        Self {
            schema: DELIVERY_SCHEMA.to_owned(),
            predecessor: None,
            entries: Vec::new(),
            aggregate_bytes_excluding_ledger: 0,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != DELIVERY_SCHEMA {
            return Err(Error::new("unsupported delivery ledger schema"));
        }
        if let Some(predecessor) = &self.predecessor {
            predecessor.validate()?;
        }
        if self.entries.is_empty() != self.predecessor.is_none() {
            return Err(Error::new(
                "only the empty genesis ledger may omit its predecessor binding",
            ));
        }
        let mut previous: Option<(u8, &str)> = None;
        let mut roots = BTreeSet::new();
        let mut aggregate = 0_u64;
        for entry in &self.entries {
            entry.validate()?;
            let key = (kind_order(entry.evidence_kind), entry.evidence_id.as_str());
            if previous.is_some_and(|value| value >= key) {
                return Err(Error::new(
                    "delivery ledger is not strictly sorted and unique",
                ));
            }
            previous = Some(key);
            if !roots.insert(entry.seal_root_sha256.clone()) {
                return Err(Error::new("delivery ledger repeats a seal root"));
            }
            aggregate = aggregate
                .checked_add(entry.tracked_bytes)
                .ok_or_else(|| Error::new("delivery aggregate overflow"))?;
        }
        if aggregate != self.aggregate_bytes_excluding_ledger {
            return Err(Error::new("delivery aggregate differs from entry bytes"));
        }
        Ok(())
    }
}

pub fn append_delivery_entry(
    previous: &DeliveryLedger,
    entry: DeliveryEntry,
) -> Result<DeliveryLedger> {
    previous.validate()?;
    entry.validate()?;
    if previous.entries.iter().any(|existing| {
        existing.evidence_id == entry.evidence_id
            || existing.seal_root_sha256 == entry.seal_root_sha256
    }) {
        return Err(Error::new(
            "delivery identity/root already exists; replacement is forbidden",
        ));
    }
    let mut entries = previous.entries.clone();
    entries.push(entry);
    entries.sort_by(|left, right| {
        (kind_order(left.evidence_kind), left.evidence_id.as_bytes()).cmp(&(
            kind_order(right.evidence_kind),
            right.evidence_id.as_bytes(),
        ))
    });
    let aggregate_bytes_excluding_ledger = entries.iter().try_fold(0_u64, |total, item| {
        total
            .checked_add(item.tracked_bytes)
            .ok_or_else(|| Error::new("delivery aggregate overflow"))
    })?;
    let next = DeliveryLedger {
        schema: DELIVERY_SCHEMA.to_owned(),
        predecessor: Some(LedgerPredecessor {
            path: "delivery-index.json".to_owned(),
            sha256: sha256_hex(&json::canonical_bytes(previous)?),
        }),
        entries,
        aggregate_bytes_excluding_ledger,
    };
    validate_additive_successor(previous, &next)?;
    Ok(next)
}

pub fn validate_additive_successor(previous: &DeliveryLedger, next: &DeliveryLedger) -> Result<()> {
    previous.validate()?;
    next.validate()?;
    let expected_predecessor = LedgerPredecessor {
        path: "delivery-index.json".to_owned(),
        sha256: sha256_hex(&json::canonical_bytes(previous)?),
    };
    if next.predecessor.as_ref() != Some(&expected_predecessor) {
        return Err(Error::new(
            "delivery successor does not bind the exact parent-ledger bytes",
        ));
    }
    for old in &previous.entries {
        if !next.entries.contains(old) {
            return Err(Error::new(
                "delivery successor removed or mutated prior evidence",
            ));
        }
    }
    if next.entries.len() < previous.entries.len() {
        return Err(Error::new("delivery successor shrank"));
    }
    Ok(())
}

pub fn validate_additive_successor_files(previous: &Path, next: &Path) -> Result<()> {
    if previous.file_name().and_then(|value| value.to_str()) != Some("delivery-index.json")
        || next.file_name().and_then(|value| value.to_str()) != Some("delivery-index.json")
    {
        return Err(Error::new(
            "delivery predecessor/successor files must use the canonical ledger path",
        ));
    }
    let previous_metadata = fs::symlink_metadata(previous)?;
    let next_metadata = fs::symlink_metadata(next)?;
    if !previous_metadata.file_type().is_file()
        || !next_metadata.file_type().is_file()
        || previous_metadata.len() > JSON_MAX_BYTES
        || next_metadata.len() > JSON_MAX_BYTES
    {
        return Err(Error::new(
            "delivery parent/successor must be bounded regular files",
        ));
    }
    let previous_bytes = fs::read(previous)?;
    let next_bytes = fs::read(next)?;
    let previous_ledger: DeliveryLedger = json::require_canonical(&previous_bytes)?;
    let next_ledger: DeliveryLedger = json::require_canonical(&next_bytes)?;
    validate_additive_successor(&previous_ledger, &next_ledger)?;
    let previous_sha256 = sha256_hex(&previous_bytes);
    if next_ledger
        .predecessor
        .as_ref()
        .map(|value| value.sha256.as_str())
        != Some(previous_sha256.as_str())
    {
        return Err(Error::new(
            "delivery successor predecessor hash differs from the parent file",
        ));
    }
    Ok(())
}

pub fn validate_delivery_ledger_files(
    artifact_root: &Path,
    ledger_path: &Path,
    predecessor_path: Option<&Path>,
) -> Result<DeliveryLedger> {
    let ledger_bytes = read_bounded_regular(ledger_path, JSON_MAX_BYTES)?;
    let ledger: DeliveryLedger = json::require_canonical(&ledger_bytes)?;
    ledger.validate()?;
    match (&ledger.predecessor, predecessor_path) {
        (None, None) => {}
        (Some(expected), Some(path)) => {
            if path.file_name().and_then(|value| value.to_str()) != Some(expected.path.as_str()) {
                return Err(Error::new("parent-ledger file path mismatch"));
            }
            let bytes = read_bounded_regular(path, JSON_MAX_BYTES)?;
            if sha256_hex(&bytes) != expected.sha256 {
                return Err(Error::new("parent-ledger file hash mismatch"));
            }
            let parent: DeliveryLedger = json::require_canonical(&bytes)?;
            validate_additive_successor(&parent, &ledger)?;
        }
        _ => {
            return Err(Error::new(
                "parent-ledger file presence differs from the successor binding",
            ));
        }
    }

    let mut aggregate = 0_u64;
    let mut bundle_directories = BTreeSet::new();
    for entry in &ledger.entries {
        let index_path = artifact_root.join(&entry.bundle_index_path);
        let index_bytes = read_bounded_regular(&index_path, JSON_MAX_BYTES)?;
        if sha256_hex(&index_bytes) != entry.bundle_index_sha256 {
            return Err(Error::new("delivery bundle-index file hash mismatch"));
        }
        let index: BundleIndex = json::require_canonical(&index_bytes)?;
        index.validate()?;
        if index.evidence_id != entry.evidence_id
            || index.evidence_kind != entry.evidence_kind
            || index.terminal_state != entry.outcome
            || index.uncompressed_seal_root_sha256 != entry.seal_root_sha256
        {
            return Err(Error::new("delivery entry differs from its bundle index"));
        }
        let verification_path = artifact_root.join(&entry.verification_path);
        let verification_bytes = read_bounded_regular(&verification_path, JSON_MAX_BYTES)?;
        if sha256_hex(&verification_bytes) != entry.verification_sha256 {
            return Err(Error::new("delivery verification file hash mismatch"));
        }
        let receipt: VerificationReceipt = json::require_canonical(&verification_bytes)?;
        receipt.validate()?;
        if receipt.bundle_index_sha256 != entry.bundle_index_sha256
            || receipt.evidence_id != entry.evidence_id
            || receipt.terminal_state != entry.outcome
        {
            return Err(Error::new(
                "delivery verification receipt identity mismatch",
            ));
        }
        let bundle_directory = index_path
            .parent()
            .ok_or_else(|| Error::new("bundle-index delivery path has no parent"))?;
        let canonical_bundle_directory = fs::canonicalize(bundle_directory)?;
        if !canonical_bundle_directory.starts_with(fs::canonicalize(artifact_root)?)
            || !bundle_directories.insert(canonical_bundle_directory.clone())
        {
            return Err(Error::new("delivery bundle directory escapes or is reused"));
        }
        let mut entry_bytes = crate::storage::actual_regular_bytes(&canonical_bundle_directory)?;
        for (path, hash) in [
            (&entry.result_path, &entry.result_sha256),
            (&entry.report_path, &entry.report_sha256),
        ] {
            if let (Some(relative), Some(expected_hash)) = (path, hash) {
                let bytes = read_bounded_regular(&artifact_root.join(relative), JSON_MAX_BYTES)?;
                if sha256_hex(&bytes) != *expected_hash {
                    return Err(Error::new("delivery result/report file hash mismatch"));
                }
                entry_bytes = entry_bytes
                    .checked_add(
                        u64::try_from(bytes.len())
                            .map_err(|_| Error::new("delivery result/report length overflow"))?,
                    )
                    .ok_or_else(|| Error::new("delivery entry byte total overflow"))?;
            }
        }
        if entry_bytes != entry.tracked_bytes {
            return Err(Error::new(
                "delivery entry tracked bytes differ from fresh file lengths",
            ));
        }
        aggregate = aggregate
            .checked_add(entry_bytes)
            .ok_or_else(|| Error::new("delivery aggregate file bytes overflow"))?;
    }
    if aggregate != ledger.aggregate_bytes_excluding_ledger {
        return Err(Error::new(
            "delivery aggregate differs from fresh entry file lengths",
        ));
    }
    let actual = crate::storage::actual_regular_bytes(artifact_root)?;
    if actual > TASK_CAP_BYTES {
        return Err(Error::new("actual delivery artifact tree exceeds 512 MiB"));
    }
    Ok(ledger)
}

fn read_bounded_regular(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(Error::new(format!(
            "delivery path is not a bounded regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(Error::new("delivery hard link is forbidden"));
        }
    }
    let bytes = fs::read(path)?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(Error::new("delivery file changed while reading"));
    }
    Ok(bytes)
}

fn kind_order(kind: EvidenceKind) -> u8 {
    match kind {
        EvidenceKind::Calibration => 0,
        EvidenceKind::Campaign => 1,
        EvidenceKind::Diagnostic => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, kind: EvidenceKind, outcome: TerminalState, byte: &str) -> DeliveryEntry {
        let hash_byte = match byte {
            "0" => "3",
            "f" => "4",
            value => value,
        };
        DeliveryEntry {
            evidence_kind: kind,
            evidence_id: id.to_owned(),
            bundle_index_path: format!("bundles/{id}/bundle-index.json"),
            bundle_index_sha256: hash_byte.repeat(64),
            verification_path: format!("bundles/{id}/verification.json"),
            verification_sha256: hash_byte.repeat(64),
            result_path: None,
            result_sha256: None,
            report_path: None,
            report_sha256: None,
            seal_root_sha256: match byte {
                "0" => "1".repeat(64),
                "f" => "2".repeat(64),
                value => value.repeat(64),
            },
            outcome,
            tracked_bytes: 10,
        }
    }

    fn minimal_index() -> BundleIndex {
        BundleIndex {
            schema: BUNDLE_SCHEMA.to_owned(),
            archive_schema: ARCHIVE_SCHEMA.to_owned(),
            evidence_schema: EXECUTION_SCHEMA.to_owned(),
            evidence_kind: EvidenceKind::Campaign,
            evidence_id: "campaign-fixture".to_owned(),
            terminal_state: TerminalState::Blocked,
            baseline_commit: crate::schema::BASELINE_COMMIT.to_owned(),
            candidate_commit: crate::schema::INITIAL_CANDIDATE_COMMIT.to_owned(),
            intent_sha256: "01".repeat(32),
            uncompressed_seal_root_sha256: "02".repeat(32),
            seal_entry_count: 0,
            archive_member_count: 1,
            source_payload_bytes: 0,
            canonical_archive_bytes: 1_536,
            canonical_archive_sha256: "03".repeat(32),
            encoder: codec::current_identity(),
            producer_executable_sha256: codec::current_executable_sha256()
                .expect("test executable"),
            parameters: codec::resolve_parameters(1_536).expect("parameters"),
            compressed_stream_bytes: 1,
            compressed_stream_sha256: "04".repeat(32),
            chunk_bytes: CHUNK_BYTES,
            chunk_total_bytes: 1,
            chunks: vec![ChunkEntry {
                ordinal: 0,
                path: "chunks/000000.tar.zst.part".to_owned(),
                bytes: 1,
                sha256: "05".repeat(32),
            }],
            compression_profile_path: None,
            compression_profile_bytes: None,
            compression_profile_sha256: None,
        }
    }

    #[test]
    fn chunk_boundaries_cover_every_fixed_edge_without_empty_tail() {
        assert!(chunk_ranges(0).is_err());
        assert_eq!(chunk_ranges(1).expect("one byte"), vec![0..1]);
        assert_eq!(
            chunk_ranges(CHUNK_BYTES - 1).expect("below chunk"),
            vec![0..CHUNK_BYTES - 1]
        );
        assert_eq!(
            chunk_ranges(CHUNK_BYTES).expect("exact chunk"),
            vec![0..CHUNK_BYTES]
        );
        assert_eq!(
            chunk_ranges(CHUNK_BYTES * 2).expect("exact multiple"),
            vec![0..CHUNK_BYTES, CHUNK_BYTES..CHUNK_BYTES * 2]
        );
        assert_eq!(
            chunk_ranges(CHUNK_BYTES + 1).expect("one over"),
            vec![0..CHUNK_BYTES, CHUNK_BYTES..CHUNK_BYTES + 1]
        );
    }

    #[test]
    fn failed_and_blocked_evidence_remains_additive() {
        let empty = DeliveryLedger::empty();
        let failed = append_delivery_entry(
            &empty,
            entry(
                "campaign-failed",
                EvidenceKind::Campaign,
                TerminalState::Fail,
                "0",
            ),
        )
        .expect("failed entry");
        let blocked = append_delivery_entry(
            &failed,
            entry(
                "cal-blocked",
                EvidenceKind::Calibration,
                TerminalState::Blocked,
                "f",
            ),
        )
        .expect("blocked entry");
        let diagnostic = append_delivery_entry(
            &blocked,
            entry(
                "diag-b11-upload-failed",
                EvidenceKind::Diagnostic,
                TerminalState::Blocked,
                "a",
            ),
        )
        .expect("diagnostic entry");
        assert_eq!(diagnostic.entries.len(), 3);
        assert!(diagnostic
            .entries
            .iter()
            .any(|item| item.evidence_id == "campaign-failed"));
        assert!(validate_additive_successor(&failed, &blocked).is_ok());
        assert!(validate_additive_successor(&blocked, &diagnostic).is_ok());
        assert!(validate_additive_successor(&diagnostic, &failed).is_err());
        assert!(append_delivery_entry(
            &diagnostic,
            entry(
                "campaign-failed",
                EvidenceKind::Campaign,
                TerminalState::Pass,
                "a"
            )
        )
        .is_err());
    }

    #[test]
    fn scratch_and_outputs_must_be_repository_local_and_policy_scoped() {
        let repository = repository_root(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("repo");
        assert!(
            ensure_repository_local(Path::new("/outside-auth-mini-http2/x"), &repository).is_err()
        );
        assert!(ensure_cli_scratch(&repository.join("target/x"), &repository).is_err());
        let valid =
            repository.join(".perf/prove-http2-performance-regression/bundle-verify/fixture");
        assert_eq!(
            ensure_cli_scratch(&valid, &repository).expect("policy path"),
            valid
        );
    }

    #[test]
    fn declared_size_expansion_and_member_count_bombs_are_rejected() {
        let index = minimal_index();
        index.validate().expect("minimal bounded index");

        let mut expansion = index.clone();
        expansion.canonical_archive_bytes = TASK_CAP_BYTES + 1;
        expansion.parameters = codec::resolve_parameters(1_536).expect("parameters");
        expansion.parameters.pledged_source_size = expansion.canonical_archive_bytes;
        assert!(expansion.validate().is_err());

        let mut members = index.clone();
        members.seal_entry_count = MAX_ARCHIVE_MEMBERS;
        members.archive_member_count = MAX_ARCHIVE_MEMBERS + 1;
        assert!(members.validate().is_err());

        let mut compressed = index;
        compressed.compressed_stream_bytes = TASK_CAP_BYTES + 1;
        compressed.chunk_total_bytes = TASK_CAP_BYTES + 1;
        assert!(compressed.validate().is_err());
    }

    #[test]
    fn additive_successor_checks_the_actual_parent_ledger_file_hash() {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("ledger-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(directory.join("parent")).expect("parent ledger test directory");
        fs::create_dir_all(directory.join("next")).expect("next ledger test directory");
        let parent_path = directory.join("parent/delivery-index.json");
        let next_path = directory.join("next/delivery-index.json");
        let parent = DeliveryLedger::empty();
        let next = append_delivery_entry(
            &parent,
            entry(
                "campaign-parent-check",
                EvidenceKind::Campaign,
                TerminalState::Blocked,
                "6",
            ),
        )
        .expect("successor");
        json::write_new_canonical(&parent_path, &parent).expect("parent file");
        json::write_new_canonical(&next_path, &next).expect("next file");
        validate_additive_successor_files(&parent_path, &next_path)
            .expect("exact parent file binding");
        fs::write(&parent_path, b"{}\n").expect("mutate predecessor");
        assert!(validate_additive_successor_files(&parent_path, &next_path).is_err());
        fs::remove_dir_all(directory).expect("clean ledger fixture");
    }
}
