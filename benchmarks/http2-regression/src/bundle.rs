use crate::archive::{self, ArchiveMember};
use crate::codec;
use crate::json;
use crate::raw;
use crate::schema::{
    validate_identifier, validate_sha256, AuthoritativeManifest, CalibrationManifest,
    CodecIdentity, DesignLock, EvidenceKind, Intent, ResolvedZstdParameters, TerminalState,
    ARCHIVE_SCHEMA, BUNDLE_SCHEMA, CHUNK_BYTES, DELIVERY_SCHEMA, EXECUTION_SCHEMA, JSON_MAX_BYTES,
};
use crate::seal::{self, sha256_hex, validate_relative_path, SealManifest};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::ops::Range;
use std::path::{Component, Path, PathBuf};

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
        validate_sha256("chunk sha256", &self.sha256)?;
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
    pub parameters: ResolvedZstdParameters,
    pub compressed_stream_bytes: u64,
    pub compressed_stream_sha256: String,
    pub chunk_bytes: u64,
    pub chunk_total_bytes: u64,
    pub chunks: Vec<ChunkEntry>,
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
        ] {
            validate_sha256(name, value)?;
        }
        self.encoder.validate()?;
        self.parameters.validate()?;
        if self.parameters.pledged_source_size != self.canonical_archive_bytes
            || self.archive_member_count != self.seal_entry_count + 1
            || self.chunks.is_empty()
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
    pub canonical_archive_bytes: u64,
    pub canonical_archive_sha256: String,
    pub recompressed_bytes: u64,
    pub recompressed_sha256: String,
    pub byte_equal: bool,
    pub raw_arm_count: u64,
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
        ] {
            validate_sha256("receipt hash", value)?;
        }
        self.expected_encoder.validate()?;
        self.verifier_encoder.validate()?;
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
    if fs::symlink_metadata(output_directory).is_ok() {
        return Err(Error::new(
            "bundle output already exists; overwrite is forbidden",
        ));
    }
    let source_verification = verify_source(source)?;
    let seal = source_verification.seal;
    let intent_bytes = source_verification.intent_bytes;
    let intent = source_verification.intent;
    let current_encoder = codec::current_identity();
    let canonical = archive::canonical_archive(source, &seal)?;
    let canonical_len = u64::try_from(canonical.len())
        .map_err(|_| Error::new("canonical archive length overflow"))?;
    let parameters = codec::resolve_parameters(canonical_len)?;
    let compressed = codec::encode(&canonical, &parameters)?;
    let ranges = chunk_ranges(
        u64::try_from(compressed.len()).map_err(|_| Error::new("compressed length overflow"))?,
    )?;

    fs::create_dir(output_directory).map_err(|error| {
        Error::new(format!(
            "cannot create bundle output {}: {error}",
            output_directory.display()
        ))
    })?;
    let chunks_directory = output_directory.join("chunks");
    fs::create_dir(&chunks_directory)?;
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
    let index = BundleIndex {
        schema: BUNDLE_SCHEMA.to_owned(),
        archive_schema: ARCHIVE_SCHEMA.to_owned(),
        evidence_schema: EXECUTION_SCHEMA.to_owned(),
        evidence_kind: intent.evidence_kind,
        evidence_id: intent.evidence_id.clone(),
        terminal_state,
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
        parameters,
        compressed_stream_bytes: compressed_len,
        compressed_stream_sha256: sha256_hex(&compressed),
        chunk_bytes: CHUNK_BYTES,
        chunk_total_bytes: compressed_len,
        chunks,
    };
    index.validate()?;
    json::write_new_canonical(&output_directory.join("bundle-index.json"), &index)?;
    Ok(index)
}

pub fn verify_bundle(index_path: &Path, scratch: &Path) -> Result<VerificationReceipt> {
    if fs::symlink_metadata(scratch).is_ok() {
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

    fs::create_dir(scratch).map_err(|error| {
        Error::new(format!(
            "cannot create verification scratch {}: {error}",
            scratch.display()
        ))
    })?;
    extract_members(scratch, &members)?;
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
    let verified_seal = seal::verify_seal(scratch)?;
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

    let reconstructed = archive::canonical_archive(scratch, &seal)?;
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

    // This deliberately occurs only after exact recompression succeeds.
    validate_optional_domain_manifests(scratch, &intent_bytes)?;
    let raw_metadata = raw::validate_evidence_tree(scratch)?;
    let receipt = VerificationReceipt {
        schema: BUNDLE_SCHEMA.to_owned(),
        bundle_index_sha256: sha256_hex(&index_bytes),
        evidence_id: index.evidence_id,
        seal_root_sha256: seal.root_sha256,
        extracted_intent_sha256: sha256_hex(&intent_bytes),
        expected_encoder: intent.encoder,
        verifier_encoder,
        canonical_archive_bytes: index.canonical_archive_bytes,
        canonical_archive_sha256: index.canonical_archive_sha256,
        recompressed_bytes: u64::try_from(recompressed.len())
            .map_err(|_| Error::new("recompressed length overflow"))?,
        recompressed_sha256: sha256_hex(&recompressed),
        byte_equal: true,
        raw_arm_count: u64::try_from(raw_metadata.len())
            .map_err(|_| Error::new("raw arm count overflow"))?,
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
    fs::remove_dir_all(scratch)?;
    Ok(receipt)
}

#[derive(Debug)]
pub struct SourceVerification {
    pub seal: SealManifest,
    pub intent: Intent,
    pub intent_bytes: Vec<u8>,
    pub raw_arm_count: u64,
}

pub fn verify_source(source: &Path) -> Result<SourceVerification> {
    let seal = seal::verify_seal(source)?;
    let intent_bytes = fs::read(source.join("intent.json"))?;
    let intent: Intent = json::require_canonical(&intent_bytes)?;
    intent.validate()?;
    if intent.encoder != codec::current_identity() {
        return Err(Error::new(
            "intent encoder identity differs from the current pinned encoder",
        ));
    }
    validate_optional_domain_manifests(source, &intent_bytes)?;
    let raw_arms = raw::validate_evidence_tree(source)?;
    Ok(SourceVerification {
        seal,
        intent,
        intent_bytes,
        raw_arm_count: u64::try_from(raw_arms.len())
            .map_err(|_| Error::new("raw arm count overflow"))?,
    })
}

fn validate_optional_domain_manifests(source: &Path, intent_bytes: &[u8]) -> Result<()> {
    let intent_hash = sha256_hex(intent_bytes);
    let design_path = source.join("design-lock.json");
    let design = read_optional_canonical::<DesignLock>(&design_path)?;
    let design_hash = if let Some(design) = &design {
        design.validate()?;
        if design.intent_sha256 != intent_hash {
            return Err(Error::new("design-lock intent hash mismatch"));
        }
        Some(sha256_hex(&fs::read(&design_path)?))
    } else {
        None
    };

    if let Some(calibration) =
        read_optional_canonical::<CalibrationManifest>(&source.join("calibration.json"))?
    {
        calibration.validate()?;
    }
    if let Some(authoritative) =
        read_optional_canonical::<AuthoritativeManifest>(&source.join("authoritative.json"))?
    {
        authoritative.validate()?;
        if design_hash.as_deref() != Some(authoritative.design_lock_sha256.as_str()) {
            return Err(Error::new(
                "authoritative manifest lacks its exact design-lock hash",
            ));
        }
    }
    Ok(())
}

fn read_optional_canonical<T>(path: &Path) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.len() > JSON_MAX_BYTES {
                return Err(Error::new(format!(
                    "optional manifest is not a bounded regular file: {}",
                    path.display()
                )));
            }
            Ok(Some(json::require_canonical(&fs::read(path)?)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::new(format!(
            "cannot inspect optional manifest {}: {error}",
            path.display()
        ))),
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
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| Error::new(format!("cannot create {}: {error}", path.display())))?;
    file.write_all(bytes)?;
    file.sync_all()?;
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
            validate_sha256("delivery hash", hash)?;
        }
        match (&self.result_path, &self.result_sha256) {
            (Some(path), Some(hash)) => {
                validate_relative_path(path)?;
                validate_sha256("result hash", hash)?;
            }
            (None, None) => {}
            _ => return Err(Error::new("delivery result path/hash optionality differs")),
        }
        match (&self.report_path, &self.report_sha256) {
            (Some(path), Some(hash)) => {
                validate_relative_path(path)?;
                validate_sha256("report hash", hash)?;
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
    pub entries: Vec<DeliveryEntry>,
    pub aggregate_bytes_excluding_ledger: u64,
}

impl DeliveryLedger {
    pub fn empty() -> Self {
        Self {
            schema: DELIVERY_SCHEMA.to_owned(),
            entries: Vec::new(),
            aggregate_bytes_excluding_ledger: 0,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != DELIVERY_SCHEMA {
            return Err(Error::new("unsupported delivery ledger schema"));
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
        entries,
        aggregate_bytes_excluding_ledger,
    };
    validate_additive_successor(previous, &next)?;
    Ok(next)
}

pub fn validate_additive_successor(previous: &DeliveryLedger, next: &DeliveryLedger) -> Result<()> {
    previous.validate()?;
    next.validate()?;
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

fn kind_order(kind: EvidenceKind) -> u8 {
    match kind {
        EvidenceKind::Calibration => 0,
        EvidenceKind::Campaign => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, kind: EvidenceKind, outcome: TerminalState, byte: &str) -> DeliveryEntry {
        DeliveryEntry {
            evidence_kind: kind,
            evidence_id: id.to_owned(),
            bundle_index_path: format!("bundles/{id}/bundle-index.json"),
            bundle_index_sha256: byte.repeat(64),
            verification_path: format!("bundles/{id}/verification.json"),
            verification_sha256: byte.repeat(64),
            result_path: None,
            result_sha256: None,
            report_path: None,
            report_sha256: None,
            seal_root_sha256: if byte == "0" {
                "1".repeat(64)
            } else {
                "2".repeat(64)
            },
            outcome,
            tracked_bytes: 10,
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
        assert_eq!(blocked.entries.len(), 2);
        assert!(blocked
            .entries
            .iter()
            .any(|item| item.evidence_id == "campaign-failed"));
        assert!(validate_additive_successor(&failed, &blocked).is_ok());
        assert!(validate_additive_successor(&blocked, &failed).is_err());
        assert!(append_delivery_entry(
            &blocked,
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
}
