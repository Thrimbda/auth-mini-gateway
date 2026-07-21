//! Crash-resumable post-seal delivery and committed-retention verification.

use crate::build::{self, BuildSet, CleanRebuildReceipt};
use crate::bundle::{self, DeliveryEntry, DeliveryLedger, VerificationReceipt};
use crate::json;
use crate::schema::{EvidenceKind, TerminalState, JSON_MAX_BYTES, TASK_CAP_BYTES};
use crate::seal::sha256_hex;
use crate::storage;
use crate::{Error, Result, ResultContext};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

pub const DELIVERY_TRANSACTION_SCHEMA: &str = "amg-http2-perf/delivery-transaction/v1";
pub const DELIVERY_READY_SCHEMA: &str = "amg-http2-perf/delivery-ready/v1";
pub const DELIVERY_RETAINED_SCHEMA: &str = "amg-http2-perf/delivery-retained/v1";
const ARTIFACT_RELATIVE: &str = ".legion/tasks/prove-http2-performance-regression/artifacts";
static NEXT_CHECK: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryPhase {
    SourceVerified,
    BundleCreated,
    BundleVerified,
    DerivedProducts,
    PrepublishCap,
    BundleInstalled,
    ConclusionInstalled,
    LedgerPublished,
    FinalCap,
    OutcomePublished,
}

impl DeliveryPhase {
    pub const ALL: [Self; 10] = [
        Self::SourceVerified,
        Self::BundleCreated,
        Self::BundleVerified,
        Self::DerivedProducts,
        Self::PrepublishCap,
        Self::BundleInstalled,
        Self::ConclusionInstalled,
        Self::FinalCap,
        Self::LedgerPublished,
        Self::OutcomePublished,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::SourceVerified => "source-verified",
            Self::BundleCreated => "bundle-created",
            Self::BundleVerified => "bundle-verified",
            Self::DerivedProducts => "derived-products",
            Self::PrepublishCap => "prepublish-cap",
            Self::BundleInstalled => "bundle-installed",
            Self::ConclusionInstalled => "conclusion-installed",
            Self::LedgerPublished => "ledger-published",
            Self::FinalCap => "final-cap",
            Self::OutcomePublished => "outcome-published",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryBinding {
    pub path: String,
    pub sha256: String,
}

impl DeliveryBinding {
    pub fn from_file(repository: &Path, path: &Path) -> Result<Self> {
        let relative = path
            .strip_prefix(repository)
            .map_err(|_| Error::new("delivery transaction binding escaped repository"))?
            .to_str()
            .ok_or_else(|| Error::new("delivery transaction binding is not UTF-8"))?
            .replace('\\', "/");
        validate_relative(&relative)?;
        Ok(Self {
            path: relative,
            sha256: sha256_hex(&fs::read(path)?),
        })
    }

    pub fn from_file_at(logical_path: &str, path: &Path) -> Result<Self> {
        validate_relative(logical_path)?;
        Ok(Self {
            path: logical_path.to_owned(),
            sha256: sha256_hex(&fs::read(path)?),
        })
    }

    fn validate(&self) -> Result<()> {
        validate_relative(&self.path)?;
        crate::schema::validate_non_placeholder_sha256("delivery transaction binding", &self.sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryTransactionRecord {
    pub schema: String,
    pub evidence_kind: EvidenceKind,
    pub evidence_id: String,
    pub seal_root_sha256: String,
    pub sequence: u8,
    pub phase: DeliveryPhase,
    pub predecessor_sha256: Option<String>,
    pub bindings: Vec<DeliveryBinding>,
}

impl DeliveryTransactionRecord {
    fn validate(&self) -> Result<()> {
        if self.schema != DELIVERY_TRANSACTION_SCHEMA
            || usize::from(self.sequence) >= DeliveryPhase::ALL.len()
            || DeliveryPhase::ALL[usize::from(self.sequence)] != self.phase
        {
            return Err(Error::new("delivery transaction phase/sequence is invalid"));
        }
        crate::schema::validate_identifier("delivery transaction identity", &self.evidence_id)?;
        crate::schema::validate_non_placeholder_sha256(
            "delivery transaction seal root",
            &self.seal_root_sha256,
        )?;
        if self.sequence == 0 {
            if self.predecessor_sha256.is_some() {
                return Err(Error::new("genesis delivery transaction has a predecessor"));
            }
        } else {
            crate::schema::validate_non_placeholder_sha256(
                "delivery transaction predecessor",
                self.predecessor_sha256
                    .as_deref()
                    .ok_or_else(|| Error::new("delivery transaction predecessor is missing"))?,
            )?;
        }
        let mut previous: Option<&[u8]> = None;
        for binding in &self.bindings {
            binding.validate()?;
            if previous.is_some_and(|path| path >= binding.path.as_bytes()) {
                return Err(Error::new(
                    "delivery transaction bindings are not strictly sorted and unique",
                ));
            }
            previous = Some(binding.path.as_bytes());
        }
        Ok(())
    }
}

pub struct DeliveryTransaction {
    repository: PathBuf,
    root: PathBuf,
    records_root: PathBuf,
    evidence_kind: EvidenceKind,
    evidence_id: String,
    seal_root_sha256: String,
    records: Vec<DeliveryTransactionRecord>,
}

impl DeliveryTransaction {
    pub fn open(
        repository: &Path,
        evidence_kind: EvidenceKind,
        evidence_id: &str,
        seal_root_sha256: &str,
    ) -> Result<Self> {
        crate::schema::validate_identifier("delivery transaction identity", evidence_id)?;
        crate::schema::validate_non_placeholder_sha256(
            "delivery transaction seal root",
            seal_root_sha256,
        )?;
        let repository = fs::canonicalize(repository)?;
        let root = execution_root(&repository)
            .join("delivery-transactions")
            .join(kind_label(evidence_kind))
            .join(evidence_id);
        fs::create_dir_all(&root)?;
        let records_root = root.join("records");
        fs::create_dir_all(&records_root)?;
        let mut files = fs::read_dir(&records_root)?
            .map(|entry| entry.map(|value| value.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        files.sort();
        let mut records = Vec::new();
        for (sequence, path) in files.iter().enumerate() {
            let expected = format!(
                "{sequence:02}-{}.json",
                DeliveryPhase::ALL
                    .get(sequence)
                    .ok_or_else(|| Error::new("delivery transaction has extra records"))?
                    .label()
            );
            if path.file_name().and_then(|value| value.to_str()) != Some(expected.as_str()) {
                return Err(Error::new(
                    "delivery transaction record path is not canonical",
                ));
            }
            let record: DeliveryTransactionRecord = json::read_strict(path, JSON_MAX_BYTES)?;
            record.validate()?;
            if record.evidence_kind != evidence_kind
                || record.evidence_id != evidence_id
                || record.seal_root_sha256 != seal_root_sha256
                || usize::from(record.sequence) != sequence
                || record.predecessor_sha256
                    != records
                        .last()
                        .map(json::canonical_bytes)
                        .transpose()?
                        .map(|bytes| sha256_hex(&bytes))
            {
                return Err(Error::new(
                    "delivery transaction identity or hash chain changed",
                ));
            }
            records.push(record);
        }
        Ok(Self {
            repository,
            root,
            records_root,
            evidence_kind,
            evidence_id: evidence_id.to_owned(),
            seal_root_sha256: seal_root_sha256.to_owned(),
            records,
        })
    }

    pub fn completed(&self, phase: DeliveryPhase) -> bool {
        self.records.iter().any(|record| record.phase == phase)
    }

    pub fn require_complete(&self) -> Result<()> {
        if self.records.len() == DeliveryPhase::ALL.len()
            && self.completed(DeliveryPhase::OutcomePublished)
        {
            Ok(())
        } else {
            Err(Error::new("post-seal delivery transaction is incomplete"))
        }
    }

    pub fn record(
        &mut self,
        phase: DeliveryPhase,
        mut bindings: Vec<DeliveryBinding>,
    ) -> Result<()> {
        bindings.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        if let Some(existing) = self.records.iter().find(|record| record.phase == phase) {
            if existing.bindings != bindings {
                return Err(Error::new(
                    "completed delivery transaction phase has stale or changed bindings",
                ));
            }
            return Ok(());
        }
        let sequence = self.records.len();
        if DeliveryPhase::ALL.get(sequence) != Some(&phase) {
            return Err(Error::new(
                "delivery transaction attempted an out-of-order phase",
            ));
        }
        let predecessor_sha256 = self
            .records
            .last()
            .map(json::canonical_bytes)
            .transpose()?
            .map(|bytes| sha256_hex(&bytes));
        let record = DeliveryTransactionRecord {
            schema: DELIVERY_TRANSACTION_SCHEMA.to_owned(),
            evidence_kind: self.evidence_kind,
            evidence_id: self.evidence_id.clone(),
            seal_root_sha256: self.seal_root_sha256.clone(),
            sequence: u8::try_from(sequence)
                .map_err(|_| Error::new("delivery transaction sequence exceeds u8"))?,
            phase,
            predecessor_sha256,
            bindings,
        };
        record.validate()?;
        let path = self.records_root.join(format!(
            "{sequence:02}-{}.json",
            DeliveryPhase::ALL[sequence].label()
        ));
        json::write_new_canonical(&path, &record)?;
        File::open(&self.records_root)?.sync_all()?;
        self.records.push(record);
        Ok(())
    }

    pub fn repository(&self) -> &Path {
        &self.repository
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn next_attempt(&self, category: &str) -> Result<PathBuf> {
        if category.is_empty() || !category.bytes().all(|byte| byte.is_ascii_lowercase()) {
            return Err(Error::new("delivery attempt category is invalid"));
        }
        let parent = self.root.join("attempts").join(category);
        fs::create_dir_all(&parent)?;
        for ordinal in 0_u32..=u16::MAX.into() {
            let path = parent.join(format!("{ordinal:06}"));
            if !path.exists() {
                return Ok(path);
            }
        }
        Err(Error::new(
            "delivery transaction exhausted bounded attempts",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryIdentity {
    pub evidence_kind: EvidenceKind,
    pub evidence_id: String,
    pub seal_root_sha256: String,
    pub bundle_index_sha256: String,
    pub verification_sha256: String,
    pub result_sha256: Option<String>,
    pub report_sha256: Option<String>,
    pub design_lock_sha256: Option<String>,
    pub continuation_projection_sha256: Option<String>,
    pub outcome: TerminalState,
    pub tracked_bytes: u64,
}

impl From<&DeliveryEntry> for DeliveryIdentity {
    fn from(entry: &DeliveryEntry) -> Self {
        Self {
            evidence_kind: entry.evidence_kind,
            evidence_id: entry.evidence_id.clone(),
            seal_root_sha256: entry.seal_root_sha256.clone(),
            bundle_index_sha256: entry.bundle_index_sha256.clone(),
            verification_sha256: entry.verification_sha256.clone(),
            result_sha256: entry.result_sha256.clone(),
            report_sha256: entry.report_sha256.clone(),
            design_lock_sha256: entry.design_lock_sha256.clone(),
            continuation_projection_sha256: entry.continuation_projection_sha256.clone(),
            outcome: entry.outcome,
            tracked_bytes: entry.tracked_bytes,
        }
    }
}

impl DeliveryIdentity {
    fn validate(&self) -> Result<()> {
        crate::schema::validate_identifier("delivery identity", &self.evidence_id)?;
        for hash in [
            Some(&self.seal_root_sha256),
            Some(&self.bundle_index_sha256),
            Some(&self.verification_sha256),
            self.result_sha256.as_ref(),
            self.report_sha256.as_ref(),
            self.design_lock_sha256.as_ref(),
            self.continuation_projection_sha256.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            crate::schema::validate_non_placeholder_sha256("delivery identity hash", hash)?;
        }
        if self.tracked_bytes == 0 {
            return Err(Error::new("delivery identity tracked bytes are zero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReadyReceipt {
    pub schema: String,
    pub artifact_commit: String,
    pub verifier_source_tree: String,
    pub artifact_tree_sha256: String,
    pub ledger_sha256: String,
    pub ledger_entries: Vec<DeliveryIdentity>,
    pub actual_tracked_bytes: u64,
    pub bundle_receipt_sha256: Vec<String>,
    pub clean_rebuilds: Vec<CleanRebuildReceipt>,
    pub success: bool,
}

impl DeliveryReadyReceipt {
    fn validate(&self) -> Result<()> {
        if self.schema != DELIVERY_READY_SCHEMA || !self.success {
            return Err(Error::new("delivery-ready receipt is not a success"));
        }
        crate::schema::validate_commit("delivery-ready artifact commit", &self.artifact_commit)?;
        if self.verifier_source_tree.len() != 40
            || !self
                .verifier_source_tree
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::new(
                "delivery-ready verifier tree is not a Git object ID",
            ));
        }
        for hash in [&self.artifact_tree_sha256, &self.ledger_sha256] {
            crate::schema::validate_non_placeholder_sha256("delivery-ready hash", hash)?;
        }
        if self.actual_tracked_bytes > TASK_CAP_BYTES || self.ledger_entries.is_empty() {
            return Err(Error::new(
                "delivery-ready receipt has no evidence or exceeds 512 MiB",
            ));
        }
        for identity in &self.ledger_entries {
            identity.validate()?;
        }
        for hash in &self.bundle_receipt_sha256 {
            crate::schema::validate_non_placeholder_sha256("delivery-ready bundle receipt", hash)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupAuthorization {
    pub fetched_base_commit: String,
    pub merge_commit: String,
    pub ready_receipt_sha256: String,
    pub merged_ledger_sha256: String,
    pub merged_artifact_tree_sha256: String,
    pub retained_entries: Vec<DeliveryIdentity>,
    pub delete_only_matching_perf_evidence: bool,
}

impl CleanupAuthorization {
    fn validate(&self) -> Result<()> {
        for (name, commit) in [
            ("cleanup fetched base", &self.fetched_base_commit),
            ("cleanup merge", &self.merge_commit),
        ] {
            crate::schema::validate_commit(name, commit)?;
        }
        for hash in [
            &self.ready_receipt_sha256,
            &self.merged_ledger_sha256,
            &self.merged_artifact_tree_sha256,
        ] {
            crate::schema::validate_non_placeholder_sha256("cleanup authorization hash", hash)?;
        }
        if !self.delete_only_matching_perf_evidence || self.retained_entries.is_empty() {
            return Err(Error::new(
                "cleanup authorization is not limited to retained content identities",
            ));
        }
        for identity in &self.retained_entries {
            identity.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryRetainedReceipt {
    pub schema: String,
    pub ready_artifact_commit: String,
    pub fetched_base_commit: String,
    pub merge_commit: String,
    pub ready_receipt_sha256: String,
    pub merged_ledger_sha256: String,
    pub merged_artifact_tree_sha256: String,
    pub actual_tracked_bytes: u64,
    pub cleanup_authorization: CleanupAuthorization,
    pub success: bool,
}

impl DeliveryRetainedReceipt {
    fn validate(&self) -> Result<()> {
        self.cleanup_authorization.validate()?;
        if self.schema != DELIVERY_RETAINED_SCHEMA
            || !self.success
            || self.actual_tracked_bytes > TASK_CAP_BYTES
            || self.fetched_base_commit != self.cleanup_authorization.fetched_base_commit
            || self.merge_commit != self.cleanup_authorization.merge_commit
            || self.ready_receipt_sha256 != self.cleanup_authorization.ready_receipt_sha256
            || self.merged_ledger_sha256 != self.cleanup_authorization.merged_ledger_sha256
            || self.merged_artifact_tree_sha256
                != self.cleanup_authorization.merged_artifact_tree_sha256
        {
            return Err(Error::new(
                "delivery-retained receipt differs from its content-bound cleanup authorization",
            ));
        }
        Ok(())
    }
}

struct VerifiedTree {
    ledger: DeliveryLedger,
    ledger_sha256: String,
    artifact_tree_sha256: String,
    actual_bytes: u64,
    bundle_receipts: Vec<String>,
    builds: Vec<BuildSet>,
}

pub fn validate_local_delivery(
    repository: &Path,
    evidence_kind: EvidenceKind,
    evidence_id: &str,
    seal_root_sha256: &str,
) -> Result<DeliveryEntry> {
    let repository = fs::canonicalize(repository)?;
    let transaction =
        DeliveryTransaction::open(&repository, evidence_kind, evidence_id, seal_root_sha256)?;
    transaction.require_complete()?;
    let artifacts = repository.join(ARTIFACT_RELATIVE);
    let ledger_path = artifacts.join("delivery-index.json");
    let ledger: DeliveryLedger = json::read_strict(&ledger_path, JSON_MAX_BYTES)?;
    let predecessor = ledger
        .predecessor
        .as_ref()
        .map(|value| artifacts.join(&value.path));
    let ledger =
        bundle::validate_delivery_ledger_files(&artifacts, &ledger_path, predecessor.as_deref())?;
    let entry = ledger
        .entries
        .iter()
        .find(|entry| {
            entry.evidence_kind == evidence_kind
                && entry.evidence_id == evidence_id
                && entry.seal_root_sha256 == seal_root_sha256
        })
        .ok_or_else(|| Error::new("completed delivery transaction lacks its exact ledger entry"))?
        .clone();
    let scratch = transaction.next_attempt("revalidate")?;
    let (receipt, extracted) =
        bundle::verify_bundle_retained(&artifacts.join(&entry.bundle_index_path), &scratch)?;
    let stored: VerificationReceipt =
        json::read_strict(&artifacts.join(&entry.verification_path), JSON_MAX_BYTES)?;
    if stored != receipt
        || sha256_hex(&json::canonical_bytes(&stored)?) != entry.verification_sha256
    {
        return Err(Error::new(
            "completed delivery transaction has a stale verification receipt",
        ));
    }
    if storage::actual_regular_bytes(&artifacts)? > TASK_CAP_BYTES {
        return Err(Error::new(
            "completed delivery transaction now exceeds 512 MiB",
        ));
    }
    if evidence_kind == EvidenceKind::Campaign {
        let result_path = entry
            .result_path
            .as_deref()
            .ok_or_else(|| Error::new("campaign delivery lacks a result"))?;
        let verified = crate::evidence::verify_raw_closure(&extracted)?;
        if json::canonical_bytes(&verified.derived_analysis()?)?
            != fs::read(artifacts.join(result_path))?
        {
            return Err(Error::new(
                "campaign delivery result differs from fresh source-independent analysis",
            ));
        }
    }
    fs::remove_dir_all(&scratch)?;
    Ok(entry)
}

pub fn delivery_ready(repository: &Path, commit: &str) -> Result<DeliveryReadyReceipt> {
    let repository = fs::canonicalize(repository)?;
    let commit = resolve_commit(&repository, commit)?;
    let verifier_source_tree = verify_running_source_at_commit(&repository, &commit)?;
    let scratch = fresh_check_root(&repository, "ready", &commit)?;
    let checkout = scratch.join("checkout");
    fs::create_dir(&checkout)?;
    extract_commit_path(&repository, &commit, ARTIFACT_RELATIVE, &checkout)?;
    let artifacts = checkout.join(ARTIFACT_RELATIVE);
    let verified = verify_artifact_tree(&repository, &artifacts, &scratch.join("bundles"))?;

    let mut manifests = BTreeMap::new();
    for builds in &verified.builds {
        for manifest in [&builds.baseline, &builds.candidate] {
            manifests
                .entry(manifest.binary_sha256.clone())
                .or_insert_with(|| manifest.clone());
        }
    }
    let mut clean_rebuilds = Vec::new();
    for (ordinal, manifest) in manifests.values().enumerate() {
        clean_rebuilds.push(build::verify_clean_scratch_rebuild(
            manifest,
            &repository,
            &scratch.join(format!("clean-rebuild-{ordinal:03}")),
        )?);
    }
    let receipt = DeliveryReadyReceipt {
        schema: DELIVERY_READY_SCHEMA.to_owned(),
        artifact_commit: commit.clone(),
        verifier_source_tree,
        artifact_tree_sha256: verified.artifact_tree_sha256,
        ledger_sha256: verified.ledger_sha256,
        ledger_entries: verified.ledger.entries.iter().map(Into::into).collect(),
        actual_tracked_bytes: verified.actual_bytes,
        bundle_receipt_sha256: verified.bundle_receipts,
        clean_rebuilds,
        success: true,
    };
    receipt.validate()?;
    write_receipt(
        &execution_root(&repository)
            .join("delivery-receipts/ready")
            .join(format!("{commit}.json")),
        &receipt,
    )?;
    Ok(receipt)
}

pub fn delivery_retained(
    repository: &Path,
    fetched_base: &str,
    merge: &str,
) -> Result<DeliveryRetainedReceipt> {
    let repository = fs::canonicalize(repository)?;
    let fetched_base = resolve_commit(&repository, fetched_base)?;
    let merge = resolve_commit(&repository, merge)?;
    if !is_ancestor(&repository, &merge, &fetched_base)? {
        return Err(Error::new(
            "merge commit is not reachable from the fetched durable base",
        ));
    }
    let scratch = fresh_check_root(&repository, "retained", &merge)?;
    let checkout = scratch.join("checkout");
    fs::create_dir(&checkout)?;
    extract_commit_path(&repository, &merge, ARTIFACT_RELATIVE, &checkout)?;
    let artifacts = checkout.join(ARTIFACT_RELATIVE);
    let verified = verify_artifact_tree(&repository, &artifacts, &scratch.join("bundles"))?;
    let ready = select_ready_receipt(&repository, &verified.ledger)?;
    verify_ready_receipt_binding(&repository, &ready)?;
    let ready_bytes = json::canonical_bytes(&ready)?;
    let ready_sha256 = sha256_hex(&ready_bytes);
    let merged_identities = verified
        .ledger
        .entries
        .iter()
        .map(DeliveryIdentity::from)
        .collect::<Vec<_>>();
    for expected in &ready.ledger_entries {
        if !merged_identities.contains(expected) {
            return Err(Error::new(
                "merged delivery removed or mutated premerge evidence",
            ));
        }
    }
    let authorization = CleanupAuthorization {
        fetched_base_commit: fetched_base.clone(),
        merge_commit: merge.clone(),
        ready_receipt_sha256: ready_sha256.clone(),
        merged_ledger_sha256: verified.ledger_sha256.clone(),
        merged_artifact_tree_sha256: verified.artifact_tree_sha256.clone(),
        retained_entries: ready.ledger_entries.clone(),
        delete_only_matching_perf_evidence: true,
    };
    let receipt = DeliveryRetainedReceipt {
        schema: DELIVERY_RETAINED_SCHEMA.to_owned(),
        ready_artifact_commit: ready.artifact_commit,
        fetched_base_commit: fetched_base.clone(),
        merge_commit: merge.clone(),
        ready_receipt_sha256: ready_sha256,
        merged_ledger_sha256: verified.ledger_sha256,
        merged_artifact_tree_sha256: verified.artifact_tree_sha256,
        actual_tracked_bytes: verified.actual_bytes,
        cleanup_authorization: authorization,
        success: true,
    };
    receipt.validate()?;
    write_receipt(
        &execution_root(&repository)
            .join("delivery-receipts/retained")
            .join(format!("{fetched_base}-{merge}.json")),
        &receipt,
    )?;
    Ok(receipt)
}

fn verify_artifact_tree(
    source_repository: &Path,
    artifact_root: &Path,
    scratch_root: &Path,
) -> Result<VerifiedTree> {
    let ledger_path = artifact_root.join("delivery-index.json");
    let ledger_bytes = fs::read(&ledger_path)?;
    let ledger: DeliveryLedger = json::require_canonical(&ledger_bytes)?;
    let predecessor = ledger
        .predecessor
        .as_ref()
        .map(|value| artifact_root.join(&value.path));
    let ledger = bundle::validate_delivery_ledger_files(
        artifact_root,
        &ledger_path,
        predecessor.as_deref(),
    )?;
    let mut bundle_receipts = Vec::new();
    let mut builds = Vec::new();
    fs::create_dir_all(scratch_root)?;
    let actual_bytes = storage::actual_regular_bytes(artifact_root)?;
    if actual_bytes > TASK_CAP_BYTES {
        return Err(Error::new("committed delivery exceeds 512 MiB"));
    }
    for (ordinal, entry) in ledger.entries.iter().enumerate() {
        let index_path = artifact_root.join(&entry.bundle_index_path);
        let bundle_scratch = scratch_root.join(format!("{ordinal:06}"));
        let (receipt, extracted) = bundle::verify_bundle_retained(&index_path, &bundle_scratch)?;
        let stored: VerificationReceipt = json::read_strict(
            &artifact_root.join(&entry.verification_path),
            JSON_MAX_BYTES,
        )?;
        if stored != receipt
            || sha256_hex(&json::canonical_bytes(&stored)?) != entry.verification_sha256
        {
            return Err(Error::new(
                "committed verification receipt is stale or differs from recomputation",
            ));
        }
        bundle_receipts.push(entry.verification_sha256.clone());
        if extracted.join("build-set.json").is_file() {
            let build_set: BuildSet =
                json::read_strict(&extracted.join("build-set.json"), JSON_MAX_BYTES)?;
            build_set
                .baseline
                .validate_portable_sealed_evidence(source_repository)?;
            build_set
                .candidate
                .validate_portable_sealed_evidence(source_repository)?;
            builds.push(build_set);
        }
        if entry.evidence_kind == EvidenceKind::Campaign {
            let verified = crate::evidence::verify_raw_closure(&extracted)?;
            let analysis = verified.derived_analysis()?;
            let result_path = entry
                .result_path
                .as_deref()
                .ok_or_else(|| Error::new("campaign delivery lacks result path"))?;
            if json::canonical_bytes(&analysis)? != fs::read(artifact_root.join(result_path))? {
                return Err(Error::new(
                    "committed campaign result differs from source-independent analysis",
                ));
            }
        }
    }
    Ok(VerifiedTree {
        ledger,
        ledger_sha256: sha256_hex(&ledger_bytes),
        artifact_tree_sha256: tree_root(artifact_root)?,
        actual_bytes,
        bundle_receipts,
        builds,
    })
}

fn select_ready_receipt(
    repository: &Path,
    ledger: &DeliveryLedger,
) -> Result<DeliveryReadyReceipt> {
    let directory = execution_root(repository).join("delivery-receipts/ready");
    let merged = ledger
        .entries
        .iter()
        .map(DeliveryIdentity::from)
        .collect::<Vec<_>>();
    let mut matching = Vec::new();
    for entry in fs::read_dir(&directory).context("read premerge delivery-ready receipts")? {
        let path = entry?.path();
        let receipt: DeliveryReadyReceipt = json::read_strict(&path, JSON_MAX_BYTES)?;
        if receipt.validate().is_ok()
            && receipt
                .ledger_entries
                .iter()
                .all(|identity| merged.contains(identity))
        {
            matching.push(receipt);
        }
    }
    matching.sort_by(|left, right| {
        left.ledger_entries
            .len()
            .cmp(&right.ledger_entries.len())
            .then_with(|| left.artifact_commit.cmp(&right.artifact_commit))
    });
    let selected = matching
        .pop()
        .ok_or_else(|| Error::new("no content-matching delivery-ready receipt exists"))?;
    if matching.last().is_some_and(|other| {
        other.ledger_entries.len() == selected.ledger_entries.len()
            && other.ledger_entries != selected.ledger_entries
    }) {
        return Err(Error::new(
            "multiple divergent maximal delivery-ready receipts match the merge",
        ));
    }
    Ok(selected)
}

fn verify_ready_receipt_binding(repository: &Path, receipt: &DeliveryReadyReceipt) -> Result<()> {
    receipt.validate()?;
    let commit = resolve_commit(repository, &receipt.artifact_commit)?;
    let source_tree = git_output(
        repository,
        &[
            "rev-parse",
            &format!("{commit}:benchmarks/http2-regression"),
        ],
    )?;
    if source_tree != receipt.verifier_source_tree {
        return Err(Error::new(
            "delivery-ready verifier source tree is stale or changed",
        ));
    }
    let scratch = fresh_check_root(repository, "ready-recheck", &commit)?;
    let checkout = scratch.join("checkout");
    fs::create_dir(&checkout)?;
    extract_commit_path(repository, &commit, ARTIFACT_RELATIVE, &checkout)?;
    let verified = verify_artifact_tree(
        repository,
        &checkout.join(ARTIFACT_RELATIVE),
        &scratch.join("bundles"),
    )?;
    let identities = verified
        .ledger
        .entries
        .iter()
        .map(DeliveryIdentity::from)
        .collect::<Vec<_>>();
    let expected_rebuilds = expected_clean_rebuilds(&verified.builds);
    require_ready_matches_verified(receipt, &verified, &identities, &expected_rebuilds)
}

fn require_ready_matches_verified(
    receipt: &DeliveryReadyReceipt,
    verified: &VerifiedTree,
    identities: &[DeliveryIdentity],
    expected_rebuilds: &[CleanRebuildReceipt],
) -> Result<()> {
    if verified.ledger_sha256 != receipt.ledger_sha256
        || verified.artifact_tree_sha256 != receipt.artifact_tree_sha256
        || verified.actual_bytes != receipt.actual_tracked_bytes
        || identities != receipt.ledger_entries.as_slice()
        || verified.bundle_receipts != receipt.bundle_receipt_sha256
        || expected_rebuilds != receipt.clean_rebuilds.as_slice()
    {
        return Err(Error::new(
            "delivery-ready receipt is stale or not bound to its exact committed artifacts",
        ));
    }
    Ok(())
}

fn expected_clean_rebuilds(builds: &[BuildSet]) -> Vec<CleanRebuildReceipt> {
    let mut manifests = BTreeMap::new();
    for builds in builds {
        for manifest in [&builds.baseline, &builds.candidate] {
            manifests
                .entry(manifest.binary_sha256.clone())
                .or_insert_with(|| manifest.clone());
        }
    }
    manifests
        .into_values()
        .map(|manifest| CleanRebuildReceipt {
            commit: manifest.commit,
            tree: manifest.tree,
            archive_sha256: manifest.archive_sha256,
            source_tree_sha256: manifest.source_tree_sha256,
            vendor_tree_sha256: manifest.vendor_tree_sha256,
            cargo_config_sha256: manifest.cargo_config_sha256,
            binary_bytes: manifest.binary_bytes,
            binary_sha256: manifest.binary_sha256,
            elf_build_id: manifest.elf_build_id,
        })
        .collect()
}

fn write_receipt<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = json::canonical_bytes(value)?;
    if path.exists() {
        if fs::read(path)? != bytes {
            return Err(Error::new(
                "delivery receipt path contains different content",
            ));
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    json::write_new_bytes(path, &bytes)?;
    Ok(())
}

fn verify_running_source_at_commit(repository: &Path, commit: &str) -> Result<String> {
    let identity = crate::codec::current_identity();
    let lock = git_file(repository, commit, "benchmarks/http2-regression/Cargo.lock")?;
    let codec = git_file(
        repository,
        commit,
        "benchmarks/http2-regression/src/codec.rs",
    )?;
    if sha256_hex(&lock) != identity.nested_lock_sha256
        || sha256_hex(&codec) != identity.codec_module_sha256
    {
        return Err(Error::new(
            "delivery-ready verifier codec/lock differs from the exact artifact commit",
        ));
    }
    let paths = [
        "benchmarks/http2-regression/Cargo.toml",
        "benchmarks/http2-regression/Cargo.lock",
        "benchmarks/http2-regression/src",
    ];
    ensure_paths_match_commit(repository, commit, &paths)?;
    git_output(
        repository,
        &[
            "rev-parse",
            &format!("{commit}:benchmarks/http2-regression"),
        ],
    )
}

fn ensure_paths_match_commit(repository: &Path, commit: &str, paths: &[&str]) -> Result<()> {
    let status = git_command(repository)
        .args(["diff", "--quiet", commit, "--"])
        .args(paths.iter().copied())
        .status()?;
    if !status.success() {
        return Err(Error::new(
            "delivery-ready verifier source has uncommitted or stale tracked changes",
        ));
    }
    let untracked = git_command(repository)
        .args(["ls-files", "--others", "--exclude-standard", "--"])
        .args(paths.iter().copied())
        .output()?;
    if !untracked.status.success() || !untracked.stdout.is_empty() {
        return Err(Error::new(
            "delivery-ready verifier source contains uncommitted files",
        ));
    }
    Ok(())
}

fn fresh_check_root(repository: &Path, kind: &str, commit: &str) -> Result<PathBuf> {
    let parent = execution_root(repository)
        .join("delivery-checks")
        .join(kind)
        .join(commit);
    fs::create_dir_all(&parent)?;
    loop {
        let ordinal = NEXT_CHECK.fetch_add(1, Ordering::Relaxed);
        let root = parent.join(format!("{}-{ordinal:016x}", std::process::id()));
        match fs::create_dir(&root) {
            Ok(()) => return Ok(root),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn extract_commit_path(
    repository: &Path,
    commit: &str,
    relative: &str,
    destination: &Path,
) -> Result<()> {
    validate_relative(relative)?;
    let mut child = git_command(repository)
        .args(["archive", "--format=tar", commit, relative])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start exact-commit delivery archive")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::new("Git archive stdout is unavailable"))?;
    let mut archive = tar::Archive::new(stdout);
    for entry in archive
        .entries()
        .context("read exact-commit delivery archive")?
    {
        let mut entry = entry.context("read exact-commit delivery member")?;
        let kind = entry.header().entry_type();
        if kind.is_pax_global_extensions() || kind.is_pax_local_extensions() {
            continue;
        }
        let path = entry.path().context("decode committed delivery path")?;
        validate_archive_path(&path)?;
        let output = destination.join(&path);
        if kind.is_dir() {
            fs::create_dir_all(&output)?;
        } else if kind.is_file() {
            let parent = output
                .parent()
                .ok_or_else(|| Error::new("committed delivery member has no parent"))?;
            fs::create_dir_all(parent)?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&output)?;
            std::io::copy(&mut entry, &mut file)?;
            file.sync_all()?;
        } else {
            return Err(Error::new(
                "committed delivery archive contains a link or special file",
            ));
        }
    }
    drop(archive);
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(Error::new(format!(
            "exact-commit delivery archive failed: {}",
            detail.chars().take(4_096).collect::<String>()
        )));
    }
    Ok(())
}

fn validate_archive_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::new("committed delivery archive path is unsafe"));
    }
    Ok(())
}

fn tree_root(root: &Path) -> Result<String> {
    fn collect(
        root: &Path,
        directory: &Path,
        output: &mut Vec<(String, u64, String)>,
    ) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_dir() {
                collect(root, &path, output)?;
            } else if metadata.file_type().is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| Error::new("artifact tree member escaped root"))?
                    .to_str()
                    .ok_or_else(|| Error::new("artifact tree path is not UTF-8"))?
                    .replace('\\', "/");
                output.push((relative, metadata.len(), sha256_hex(&fs::read(&path)?)));
            } else {
                return Err(Error::new("artifact tree contains a non-regular member"));
            }
        }
        Ok(())
    }
    let mut entries = Vec::new();
    collect(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"amg-http2-perf/artifact-tree/v1\0");
    for (path, length, hash) in entries {
        bytes.extend_from_slice(&(path.len() as u64).to_be_bytes());
        bytes.extend_from_slice(path.as_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(hash.as_bytes());
    }
    Ok(sha256_hex(&bytes))
}

fn resolve_commit(repository: &Path, commit: &str) -> Result<String> {
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::new(
            "delivery Git object must be a full 40-hex commit",
        ));
    }
    let kind = git_output(repository, &["cat-file", "-t", commit])?;
    if kind != "commit" {
        return Err(Error::new("delivery Git object is not a commit"));
    }
    let resolved = git_output(repository, &["rev-parse", &format!("{commit}^{{commit}}")])?;
    if resolved != commit {
        return Err(Error::new("delivery commit does not resolve exactly"));
    }
    Ok(resolved)
}

fn is_ancestor(repository: &Path, ancestor: &str, descendant: &str) -> Result<bool> {
    Ok(git_command(repository)
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .status()?
        .success())
}

fn git_file(repository: &Path, commit: &str, relative: &str) -> Result<Vec<u8>> {
    validate_relative(relative)?;
    let output = git_command(repository)
        .args(["show", &format!("{commit}:{relative}")])
        .output()?;
    if !output.status.success() {
        return Err(Error::new(
            "exact commit lacks a required delivery source file",
        ));
    }
    Ok(output.stdout)
}

fn git_output(repository: &Path, arguments: &[&str]) -> Result<String> {
    let output = git_command(repository).args(arguments).output()?;
    if !output.status.success() {
        return Err(Error::new(format!(
            "Git delivery command failed with {}",
            output.status
        )));
    }
    Ok(String::from_utf8(output.stdout)
        .map_err(|_| Error::new("Git delivery output is not UTF-8"))?
        .trim()
        .to_owned())
}

fn git_command(repository: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .current_dir(repository)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", repository)
        .env("LC_ALL", "C.UTF-8");
    command
}

fn validate_relative(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::new("delivery path is not safe and relative"));
    }
    Ok(())
}

fn execution_root(repository: &Path) -> PathBuf {
    repository.join(".perf/prove-http2-performance-regression")
}

const fn kind_label(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Calibration => "calibration",
        EvidenceKind::Campaign => "campaign",
        EvidenceKind::Diagnostic => "diagnostic",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::DELIVERY_SCHEMA;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-scratch");
            fs::create_dir_all(&parent).expect("delivery unit scratch parent");
            let path = parent.join(format!(
                "{name}-{}-{:016x}",
                std::process::id(),
                NEXT_CHECK.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("exclusive delivery unit scratch");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn git(repository: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(repository)
            .args(arguments)
            .output()
            .expect("run test Git");
        assert!(
            output.status.success(),
            "Git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("UTF-8 Git output")
            .trim()
            .to_owned()
    }

    #[test]
    fn exact_commit_source_gate_rejects_tracked_and_untracked_changes() {
        let scratch = Scratch::new("delivery-uncommitted");
        git(&scratch.0, &["init", "-q"]);
        fs::create_dir(scratch.0.join("scope")).expect("scope");
        fs::write(scratch.0.join("scope/tracked"), b"committed").expect("tracked source");
        git(&scratch.0, &["add", "scope/tracked"]);
        git(
            &scratch.0,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
        );
        let commit = git(&scratch.0, &["rev-parse", "HEAD"]);
        ensure_paths_match_commit(&scratch.0, &commit, &["scope"]).expect("clean source");

        fs::write(scratch.0.join("scope/tracked"), b"changed").expect("tracked mutation");
        assert!(ensure_paths_match_commit(&scratch.0, &commit, &["scope"]).is_err());
        fs::write(scratch.0.join("scope/tracked"), b"committed").expect("restore fixture");
        fs::write(scratch.0.join("scope/untracked"), b"uncommitted").expect("untracked source");
        assert!(ensure_paths_match_commit(&scratch.0, &commit, &["scope"]).is_err());
    }

    #[test]
    fn artifact_tree_tamper_and_stale_ready_receipt_are_rejected() {
        let scratch = Scratch::new("delivery-stale");
        fs::write(scratch.0.join("artifact"), b"one").expect("artifact");
        let original = tree_root(&scratch.0).expect("tree root");
        fs::write(scratch.0.join("artifact"), b"two").expect("tamper artifact");
        assert_ne!(original, tree_root(&scratch.0).expect("tampered tree root"));

        let entry = DeliveryEntry {
            evidence_kind: EvidenceKind::Calibration,
            evidence_id: "cal-fixture".to_owned(),
            bundle_index_path: "bundles/calibration/cal-fixture/bundle-index.json".to_owned(),
            bundle_index_sha256: "11".repeat(32),
            verification_path: "bundles/calibration/cal-fixture/verification.json".to_owned(),
            verification_sha256: "22".repeat(32),
            result_path: None,
            result_sha256: None,
            report_path: None,
            report_sha256: None,
            design_lock_path: None,
            design_lock_sha256: None,
            continuation_projection_path: None,
            continuation_projection_sha256: None,
            seal_root_sha256: "33".repeat(32),
            outcome: TerminalState::Blocked,
            tracked_bytes: 1,
        };
        let ledger = DeliveryLedger {
            schema: DELIVERY_SCHEMA.to_owned(),
            predecessor: None,
            entries: vec![entry.clone()],
            aggregate_bytes_excluding_ledger: 1,
        };
        let verified = VerifiedTree {
            ledger,
            ledger_sha256: "44".repeat(32),
            artifact_tree_sha256: "55".repeat(32),
            actual_bytes: 1,
            bundle_receipts: vec![entry.verification_sha256.clone()],
            builds: Vec::new(),
        };
        let identities = vec![DeliveryIdentity::from(&entry)];
        let mut receipt = DeliveryReadyReceipt {
            schema: DELIVERY_READY_SCHEMA.to_owned(),
            artifact_commit: "66".repeat(20),
            verifier_source_tree: "77".repeat(20),
            artifact_tree_sha256: verified.artifact_tree_sha256.clone(),
            ledger_sha256: verified.ledger_sha256.clone(),
            ledger_entries: identities.clone(),
            actual_tracked_bytes: 1,
            bundle_receipt_sha256: verified.bundle_receipts.clone(),
            clean_rebuilds: Vec::new(),
            success: true,
        };
        receipt.validate().expect("ready receipt");
        require_ready_matches_verified(&receipt, &verified, &identities, &[])
            .expect("fresh receipt");
        receipt.ledger_sha256 = "88".repeat(32);
        assert!(require_ready_matches_verified(&receipt, &verified, &identities, &[]).is_err());
    }

    #[test]
    fn postmerge_reachability_direction_is_fail_closed() {
        let scratch = Scratch::new("delivery-reachability");
        git(&scratch.0, &["init", "-q"]);
        fs::write(scratch.0.join("file"), b"first").expect("first");
        git(&scratch.0, &["add", "file"]);
        git(
            &scratch.0,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "first",
            ],
        );
        let first = git(&scratch.0, &["rev-parse", "HEAD"]);
        fs::write(scratch.0.join("file"), b"second").expect("second");
        git(&scratch.0, &["add", "file"]);
        git(
            &scratch.0,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "second",
            ],
        );
        let second = git(&scratch.0, &["rev-parse", "HEAD"]);
        assert!(is_ancestor(&scratch.0, &first, &second).expect("ancestor"));
        assert!(!is_ancestor(&scratch.0, &second, &first).expect("reverse ancestor"));
    }

    #[test]
    fn cleanup_authorization_is_content_bound_and_never_deletes() {
        let scratch = Scratch::new("delivery-cleanup-authorization");
        let retained = scratch.0.join("retained-perf-marker");
        fs::write(&retained, b"retain").expect("retained marker");
        let identity = DeliveryIdentity {
            evidence_kind: EvidenceKind::Campaign,
            evidence_id: "run-fixture".to_owned(),
            seal_root_sha256: "11".repeat(32),
            bundle_index_sha256: "22".repeat(32),
            verification_sha256: "33".repeat(32),
            result_sha256: Some("44".repeat(32)),
            report_sha256: Some("55".repeat(32)),
            design_lock_sha256: None,
            continuation_projection_sha256: None,
            outcome: TerminalState::Pass,
            tracked_bytes: 1,
        };
        let mut authorization = CleanupAuthorization {
            fetched_base_commit: "66".repeat(20),
            merge_commit: "77".repeat(20),
            ready_receipt_sha256: "88".repeat(32),
            merged_ledger_sha256: "99".repeat(32),
            merged_artifact_tree_sha256: "aa".repeat(32),
            retained_entries: vec![identity],
            delete_only_matching_perf_evidence: true,
        };
        authorization.validate().expect("cleanup authorization");
        assert!(retained.is_file(), "authorization must not perform cleanup");
        authorization.merged_ledger_sha256 = "stale".to_owned();
        assert!(authorization.validate().is_err());
        assert!(
            retained.is_file(),
            "failed authorization must not perform cleanup"
        );
    }
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub mod test_support {
    use super::*;

    pub fn run_fake_delivery(
        repository: &Path,
        evidence_kind: EvidenceKind,
        evidence_id: &str,
        crash_before: Option<DeliveryPhase>,
        cap_allows: bool,
    ) -> Result<TerminalState> {
        let seal = sha256_hex(format!("seal:{evidence_id}").as_bytes());
        let mut transaction =
            DeliveryTransaction::open(repository, evidence_kind, evidence_id, &seal)?;
        for phase in DeliveryPhase::ALL {
            if crash_before == Some(phase) {
                return Err(Error::new("injected bounded delivery crash"));
            }
            if phase == DeliveryPhase::FinalCap && !cap_allows {
                return Ok(TerminalState::Blocked);
            }
            transaction.record(phase, Vec::new())?;
        }
        transaction.require_complete()?;
        Ok(TerminalState::Pass)
    }

    pub fn fake_delivery_complete(
        repository: &Path,
        evidence_kind: EvidenceKind,
        evidence_id: &str,
    ) -> Result<bool> {
        let seal = sha256_hex(format!("seal:{evidence_id}").as_bytes());
        let transaction = DeliveryTransaction::open(repository, evidence_kind, evidence_id, &seal)?;
        Ok(transaction.require_complete().is_ok())
    }
}
