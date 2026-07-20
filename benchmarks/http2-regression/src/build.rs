//! Exact Git-object archive extraction and isolated offline release builds.

use crate::json;
use crate::linux::{command_identity, CommandIdentity};
use crate::schema::{BASELINE_COMMIT, INITIAL_CANDIDATE_COMMIT, JSON_MAX_BYTES};
use crate::seal::sha256_hex;
use crate::{Error, Result, ResultContext};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

pub const BUILD_SCHEMA: &str = "amg-http2-perf/build/v2";
pub const BUILD_CACHE_SCHEMA: &str = "amg-http2-perf/build-cache/v2";

static NEXT_BUILD_ATTEMPT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeEntryHash {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCacheInput {
    pub name: String,
    pub version: String,
    pub lock_checksum: String,
    pub crate_relative_path: String,
    pub crate_bytes: u64,
    pub crate_sha256: String,
    pub source_relative_path: String,
    pub source_entries: u64,
    pub source_tree_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BuildCacheAddress {
    schema: String,
    build_schema: String,
    commit: String,
    tree: String,
    cargo_toml_sha256: String,
    cargo_lock_sha256: String,
    harness_executable_sha256: String,
    provenance_sha256: String,
    git: CommandIdentity,
    cargo: CommandIdentity,
    rustc: CommandIdentity,
    frozen: bool,
    offline: bool,
    rustflags_added: bool,
    source_injection: bool,
}

impl BuildCacheAddress {
    fn key_sha256(&self) -> Result<String> {
        Ok(sha256_hex(&json::canonical_bytes(self)?))
    }

    fn namespace(&self, execution_root: &Path) -> Result<PathBuf> {
        Ok(execution_root
            .join("builds")
            .join("cache-v2")
            .join(sha256_hex(self.schema.as_bytes()))
            .join(&self.harness_executable_sha256)
            .join(&self.provenance_sha256)
            .join(&self.commit)
            .join(self.key_sha256()?))
    }
}

#[derive(Serialize)]
struct BuildCacheProvenance<'a> {
    schema: &'static str,
    external_cargo_home: &'a str,
    registry_cache_inputs: &'a [RegistryCacheInput],
}

struct BuildInputs {
    git_path: PathBuf,
    cargo_path: PathBuf,
    rustc_path: PathBuf,
    address: BuildCacheAddress,
    external_cargo_home: PathBuf,
    registry_cache_inputs: Vec<RegistryCacheInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildManifest {
    pub schema: String,
    pub cache_schema: String,
    pub cache_key_sha256: String,
    pub harness_executable_sha256: String,
    pub provenance_sha256: String,
    pub commit: String,
    pub tree: String,
    pub archive_bytes: u64,
    pub archive_sha256: String,
    pub cargo_toml_sha256: String,
    pub cargo_lock_sha256: String,
    pub source_tree_sha256: String,
    pub source_entries: u64,
    pub vendor_tree_sha256: String,
    pub vendor_entries: u64,
    pub external_cargo_home: String,
    pub registry_cache_inputs: Vec<RegistryCacheInput>,
    pub cargo_config_sha256: String,
    pub binary_relative_path: String,
    pub binary_bytes: u64,
    pub binary_sha256: String,
    pub elf_build_id: Option<String>,
    pub git: CommandIdentity,
    pub cargo: CommandIdentity,
    pub rustc: CommandIdentity,
    pub execution_root_relative_path: String,
    pub object_relative_path: String,
    pub cargo_home_relative_path: String,
    pub target_relative_path: String,
    pub source_relative_path: String,
    pub frozen: bool,
    pub offline: bool,
    pub rustflags_added: bool,
    pub source_injection: bool,
}

impl BuildManifest {
    pub fn validate(&self, repository: &Path) -> Result<PathBuf> {
        self.validate_mode(repository, true)
    }

    /// Revalidates a build manifest sealed by an older harness executable.
    /// The sealed executable hash remains part of the immutable cache address;
    /// only equality with the currently executing verifier is intentionally not
    /// required.
    pub fn validate_sealed_evidence(&self, repository: &Path) -> Result<PathBuf> {
        self.validate_mode(repository, false)
    }

    fn validate_mode(&self, repository: &Path, require_current_harness: bool) -> Result<PathBuf> {
        if self.schema != BUILD_SCHEMA
            || self.cache_schema != BUILD_CACHE_SCHEMA
            || !self.frozen
            || !self.offline
            || self.rustflags_added
            || self.source_injection
        {
            return Err(Error::new("invalid release build policy manifest"));
        }
        validate_object_id("commit", &self.commit)?;
        validate_object_id("tree", &self.tree)?;
        for (name, value) in [
            ("cache key", &self.cache_key_sha256),
            ("harness executable", &self.harness_executable_sha256),
            ("build provenance", &self.provenance_sha256),
            ("archive", &self.archive_sha256),
            ("Cargo.toml", &self.cargo_toml_sha256),
            ("Cargo.lock", &self.cargo_lock_sha256),
            ("source tree", &self.source_tree_sha256),
            ("vendor tree", &self.vendor_tree_sha256),
            ("Cargo config", &self.cargo_config_sha256),
            ("binary", &self.binary_sha256),
        ] {
            validate_hash(name, value)?;
        }
        let repository = fs::canonicalize(repository)?;
        let execution_root =
            checked_repository_path(&repository, &self.execution_root_relative_path, true)?;
        let object_root = checked_repository_path(&repository, &self.object_relative_path, true)?;
        let source = checked_repository_path(&repository, &self.source_relative_path, true)?;
        let cargo_home =
            checked_repository_path(&repository, &self.cargo_home_relative_path, true)?;
        let target = checked_repository_path(&repository, &self.target_relative_path, true)?;
        let binary = checked_repository_path(&repository, &self.binary_relative_path, true)?;
        if source != object_root.join("source")
            || cargo_home != object_root.join("cargo-home")
            || target != object_root.join("target")
            || binary != object_root.join("binary/auth-mini-gateway")
        {
            return Err(Error::new(
                "cached build paths do not match the immutable cache object",
            ));
        }

        let git_path = find_executable("git")?;
        let commit = resolve_commit(&git_path, &repository, &self.commit)?;
        if commit != self.commit {
            return Err(Error::new("cached build commit no longer resolves exactly"));
        }
        let tree = git_output(
            &git_path,
            &repository,
            &["rev-parse", &format!("{}^{{tree}}", self.commit)],
        )?;
        if tree != self.tree {
            return Err(Error::new("cached build tree differs from Git object data"));
        }
        let archive = git_command(&git_path, &repository)
            .args(["archive", "--format=tar", &self.commit])
            .output()
            .context("rederive exact Git archive for cached build")?;
        if !archive.status.success() {
            return Err(command_failure("git archive reuse verification", &archive));
        }
        if archive.stdout.len() as u64 != self.archive_bytes
            || sha256_hex(&archive.stdout) != self.archive_sha256
        {
            return Err(Error::new(
                "cached archive length/hash differs from fresh Git object archive",
            ));
        }

        let source_entries = tree_entries(&source)?;
        if source_entries.len() as u64 != self.source_entries
            || entry_root(&source_entries) != self.source_tree_sha256
        {
            return Err(Error::new("cached extracted source tree mutated"));
        }
        let cargo_toml = fs::read(source.join("Cargo.toml"))?;
        let cargo_lock = fs::read(source.join("Cargo.lock"))?;
        if sha256_hex(&cargo_toml) != self.cargo_toml_sha256
            || sha256_hex(&cargo_lock) != self.cargo_lock_sha256
        {
            return Err(Error::new("cached archived Cargo source/lock mutated"));
        }
        let archive_path = object_root.join("source.tar");
        let cached_archive = fs::read(&archive_path)?;
        if cached_archive.len() as u64 != self.archive_bytes
            || sha256_hex(&cached_archive) != self.archive_sha256
        {
            return Err(Error::new("cached Git archive mutated"));
        }
        let vendor = object_root.join("vendor");
        require_canonical_below(&vendor, &repository)?;
        let vendor_entries = tree_entries(&vendor)?;
        if vendor_entries.len() as u64 != self.vendor_entries
            || entry_root(&vendor_entries) != self.vendor_tree_sha256
        {
            return Err(Error::new("cached vendored dependency closure mutated"));
        }
        validate_cargo_config(&cargo_home.join("config.toml"), &vendor, &repository)?;
        if sha256_hex(&fs::read(cargo_home.join("config.toml"))?) != self.cargo_config_sha256 {
            return Err(Error::new("cached repository-local Cargo config mutated"));
        }
        let external_cargo_home = PathBuf::from(&self.external_cargo_home);
        let external_cargo_home = fs::canonicalize(&external_cargo_home)?;
        if self.external_cargo_home != external_cargo_home.to_string_lossy() {
            return Err(Error::new("external Cargo cache path is not canonical"));
        }
        validate_registry_cache_inputs(&external_cargo_home, &self.registry_cache_inputs)?;
        if provenance_sha256(&self.external_cargo_home, &self.registry_cache_inputs)?
            != self.provenance_sha256
        {
            return Err(Error::new("cached build provenance identity changed"));
        }

        if require_current_harness && current_executable_sha256()? != self.harness_executable_sha256
        {
            return Err(Error::new(
                "cached build was created by a different harness executable",
            ));
        }

        let git_identity = command_identity(&git_path, &["--version"])?;
        let (cargo_path, rustc_path) = direct_toolchain_paths()?;
        let cargo_identity = command_identity(&cargo_path, &["-vV"])?;
        let rustc_identity = command_identity(&rustc_path, &["-vV"])?;
        require_toolchain(&cargo_identity, &rustc_identity)?;
        if self.git != git_identity || self.cargo != cargo_identity || self.rustc != rustc_identity
        {
            return Err(Error::new(
                "cached build toolchain executable/version identity changed",
            ));
        }
        let address = self.cache_address();
        if address.key_sha256()? != self.cache_key_sha256 {
            return Err(Error::new("cached build input address changed"));
        }
        let expected_namespace = address.namespace(&execution_root)?;
        let expected_objects = expected_namespace.join("objects");
        if object_root.parent() != Some(expected_objects.as_path()) {
            return Err(Error::new(
                "cached build object is outside its schema/harness/provenance address",
            ));
        }

        let metadata = fs::symlink_metadata(&binary)?;
        if !metadata.file_type().is_file() || metadata.len() != self.binary_bytes {
            return Err(Error::new("cached build binary type or length changed"));
        }
        if sha256_hex(&fs::read(&binary)?) != self.binary_sha256 {
            return Err(Error::new("cached build binary hash changed"));
        }
        let bytes = fs::read(&binary)?;
        if elf_build_id(&bytes) != self.elf_build_id {
            return Err(Error::new("cached build ELF build ID changed"));
        }
        let manifest_bytes = fs::read(object_root.join("build-manifest.json"))?;
        if json::canonical_bytes(self)? != manifest_bytes {
            return Err(Error::new(
                "cached build object manifest is not the exact canonical install record",
            ));
        }
        Ok(binary)
    }

    fn cache_address(&self) -> BuildCacheAddress {
        BuildCacheAddress {
            schema: self.cache_schema.clone(),
            build_schema: self.schema.clone(),
            commit: self.commit.clone(),
            tree: self.tree.clone(),
            cargo_toml_sha256: self.cargo_toml_sha256.clone(),
            cargo_lock_sha256: self.cargo_lock_sha256.clone(),
            harness_executable_sha256: self.harness_executable_sha256.clone(),
            provenance_sha256: self.provenance_sha256.clone(),
            git: self.git.clone(),
            cargo: self.cargo.clone(),
            rustc: self.rustc.clone(),
            frozen: self.frozen,
            offline: self.offline,
            rustflags_added: self.rustflags_added,
            source_injection: self.source_injection,
        }
    }

    fn matches_address(&self, address: &BuildCacheAddress) -> Result<bool> {
        Ok(self.cache_schema == address.schema
            && self.schema == address.build_schema
            && self.cache_key_sha256 == address.key_sha256()?
            && self.harness_executable_sha256 == address.harness_executable_sha256
            && self.provenance_sha256 == address.provenance_sha256
            && self.commit == address.commit
            && self.tree == address.tree
            && self.cargo_toml_sha256 == address.cargo_toml_sha256
            && self.cargo_lock_sha256 == address.cargo_lock_sha256
            && self.git == address.git
            && self.cargo == address.cargo
            && self.rustc == address.rustc
            && self.frozen == address.frozen
            && self.offline == address.offline
            && self.rustflags_added == address.rustflags_added
            && self.source_injection == address.source_injection)
    }

    pub fn validate_binary_reuse(&self, repository: &Path) -> Result<PathBuf> {
        let repository = fs::canonicalize(repository)?;
        let binary = checked_repository_path(&repository, &self.binary_relative_path, true)?;
        let metadata = fs::symlink_metadata(&binary)?;
        if !metadata.file_type().is_file()
            || metadata.len() != self.binary_bytes
            || sha256_hex(&fs::read(&binary)?) != self.binary_sha256
        {
            return Err(Error::new(
                "immutable gateway binary changed between validated reuses",
            ));
        }
        Ok(binary)
    }
}

fn checked_repository_path(repository: &Path, relative: &str, must_exist: bool) -> Result<PathBuf> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::new(
            "cached build manifest contains an unsafe relative path",
        ));
    }
    let path = repository.join(relative);
    if must_exist {
        require_canonical_below(&path, repository)?;
    } else {
        require_below_repository(&path, repository)?;
    }
    Ok(path)
}

fn require_canonical_below(path: &Path, repository: &Path) -> Result<()> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.starts_with(repository) {
        return Err(Error::new(
            "cached build path canonicalized outside repository",
        ));
    }
    Ok(())
}

fn validate_cargo_config(path: &Path, vendor: &Path, repository: &Path) -> Result<()> {
    require_canonical_below(path, repository)?;
    let text = fs::read_to_string(path)?;
    if text.contains("http://")
        || text.contains("https://")
        || text.contains("git =")
        || text.contains("rustc-wrapper")
        || text.contains("rustc-workspace-wrapper")
        || !text.contains("replace-with")
        || !text.contains("vendored-sources")
    {
        return Err(Error::new(
            "cached Cargo config has network/wrapper/unsealed source input",
        ));
    }
    let canonical_vendor = fs::canonicalize(vendor)?;
    let mut directories = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("directory = "));
    let directory = directories
        .next()
        .ok_or_else(|| Error::new("cached Cargo config lacks vendor directory"))?
        .trim_matches('"');
    if directories.next().is_some()
        || fs::canonicalize(directory)? != canonical_vendor
        || !canonical_vendor.starts_with(repository)
    {
        return Err(Error::new(
            "cached Cargo vendor config path escaped or aliased",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSet {
    pub schema: String,
    pub baseline: BuildManifest,
    pub candidate: BuildManifest,
}

pub fn build_pair(repository: &Path, execution_root: &Path, candidate: &str) -> Result<BuildSet> {
    validate_object_id("candidate", candidate)?;
    let git = find_executable("git")?;
    ensure_ancestor(&git, repository, INITIAL_CANDIDATE_COMMIT, candidate)?;
    let baseline = build_gateway(repository, execution_root, BASELINE_COMMIT)?;
    let candidate = build_gateway(repository, execution_root, candidate)?;
    Ok(BuildSet {
        schema: "amg-http2-perf/build-set/v1".to_owned(),
        baseline,
        candidate,
    })
}

pub fn build_gateway(
    repository: &Path,
    execution_root: &Path,
    requested_commit: &str,
) -> Result<BuildManifest> {
    validate_object_id("commit", requested_commit)?;
    require_below_repository(execution_root, repository)?;
    ensure_plain_directory(execution_root)?;
    let repository = fs::canonicalize(repository)?;
    let execution_root = fs::canonicalize(execution_root)?;
    if !execution_root.starts_with(&repository) {
        return Err(Error::new(
            "execution root canonicalized outside repository",
        ));
    }
    let inputs = BuildInputs::capture(&repository, requested_commit)?;
    let namespace = inputs.address.namespace(&execution_root)?;
    resolve_build_cache_with(
        &namespace,
        |bytes| {
            parse_cache_candidate(bytes, &inputs.address, |manifest| {
                manifest.validate(&repository).map(|_| ())
            })
        },
        |object_root| derive_gateway_build(&repository, &execution_root, object_root, &inputs),
        |manifest| manifest.validate(&repository).map(|_| ()),
    )
}

impl BuildInputs {
    fn capture(repository: &Path, requested_commit: &str) -> Result<Self> {
        let git_path = find_executable("git").context("resolve Git for build-cache address")?;
        let (cargo_path, rustc_path) =
            direct_toolchain_paths().context("resolve direct toolchain for build-cache address")?;
        let commit = resolve_commit(&git_path, repository, requested_commit)
            .context("resolve exact build-cache commit")?;
        if commit != requested_commit {
            return Err(Error::new(
                "build input must already be the exact full commit ID",
            ));
        }
        let tree = git_output(
            &git_path,
            repository,
            &["rev-parse", &format!("{commit}^{{tree}}")],
        )
        .context("resolve exact build-cache tree")?;
        validate_object_id("tree", &tree)?;
        let cargo_toml_bytes = git_file_bytes(&git_path, repository, &commit, "Cargo.toml")
            .context("address exact archived Cargo.toml")?;
        let cargo_lock_bytes = git_file_bytes(&git_path, repository, &commit, "Cargo.lock")
            .context("address exact archived Cargo.lock")?;
        let git_identity = command_identity(&git_path, &["--version"])
            .context("address Git executable identity")?;
        let cargo_identity =
            command_identity(&cargo_path, &["-vV"]).context("address Cargo identity")?;
        let rustc_identity =
            command_identity(&rustc_path, &["-vV"]).context("address rustc identity")?;
        require_toolchain(&cargo_identity, &rustc_identity)?;
        let external_cargo_home =
            external_cargo_home().context("resolve external Cargo cache provenance root")?;
        let registry_packages = registry_packages_from_lock(&cargo_lock_bytes)
            .context("derive lock-resolved registry package inventory")?;
        let registry_cache_inputs =
            capture_registry_cache_inputs(&external_cargo_home, &registry_packages)
                .context("capture external Cargo cache provenance")?;
        let external_cargo_home_text = external_cargo_home.to_string_lossy().into_owned();
        let provenance_sha256 =
            provenance_sha256(&external_cargo_home_text, &registry_cache_inputs)?;
        let address = BuildCacheAddress {
            schema: BUILD_CACHE_SCHEMA.to_owned(),
            build_schema: BUILD_SCHEMA.to_owned(),
            commit,
            tree,
            cargo_toml_sha256: sha256_hex(&cargo_toml_bytes),
            cargo_lock_sha256: sha256_hex(&cargo_lock_bytes),
            harness_executable_sha256: current_executable_sha256()
                .context("address current harness executable")?,
            provenance_sha256,
            git: git_identity,
            cargo: cargo_identity,
            rustc: rustc_identity,
            frozen: true,
            offline: true,
            rustflags_added: false,
            source_injection: false,
        };
        Ok(Self {
            git_path,
            cargo_path,
            rustc_path,
            address,
            external_cargo_home,
            registry_cache_inputs,
        })
    }
}

fn parse_cache_candidate<F>(
    bytes: &[u8],
    address: &BuildCacheAddress,
    revalidate: F,
) -> Option<BuildManifest>
where
    F: FnOnce(&BuildManifest) -> Result<()>,
{
    let manifest: BuildManifest = json::require_canonical(bytes).ok()?;
    if !manifest.matches_address(address).ok()? || revalidate(&manifest).is_err() {
        return None;
    }
    Some(manifest)
}

fn resolve_build_cache_with<Accept, Derive, Revalidate>(
    namespace: &Path,
    mut accept: Accept,
    derive: Derive,
    revalidate: Revalidate,
) -> Result<BuildManifest>
where
    Accept: FnMut(&[u8]) -> Option<BuildManifest>,
    Derive: FnOnce(&Path) -> Result<BuildManifest>,
    Revalidate: FnOnce(&BuildManifest) -> Result<()>,
{
    let entries = namespace.join("entries");
    if let Some(manifest) = first_reusable_entry(&entries, &mut accept) {
        return Ok(manifest);
    }

    let objects = namespace.join("objects");
    ensure_plain_directory(&entries)?;
    ensure_plain_directory(&objects)?;
    let object_root = create_build_object(&objects)?;
    let manifest = derive(&object_root)?;
    let manifest_bytes = json::canonical_bytes(&manifest)?;
    json::write_new_bytes(&object_root.join("build-manifest.json"), &manifest_bytes)?;
    revalidate(&manifest)?;
    File::open(&object_root)?.sync_all()?;
    install_cache_entry(&entries, &manifest_bytes)?;
    Ok(manifest)
}

fn first_reusable_entry<Accept>(entries: &Path, accept: &mut Accept) -> Option<BuildManifest>
where
    Accept: FnMut(&[u8]) -> Option<BuildManifest>,
{
    let metadata = fs::symlink_metadata(entries).ok()?;
    if !metadata.file_type().is_dir() {
        return None;
    }
    let mut candidates = fs::read_dir(entries)
        .ok()?
        .collect::<std::io::Result<Vec<_>>>()
        .ok()?;
    candidates.sort_by_key(std::fs::DirEntry::file_name);
    for candidate in candidates {
        match fs::symlink_metadata(candidate.path()) {
            Ok(metadata) if metadata.file_type().is_file() && metadata.len() <= JSON_MAX_BYTES => {}
            _ => continue,
        }
        let bytes = match fs::read(candidate.path()) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let expected_name = format!("{}.json", sha256_hex(&bytes));
        if candidate.file_name() != std::ffi::OsStr::new(&expected_name) {
            continue;
        }
        if let Some(manifest) = accept(&bytes) {
            return Some(manifest);
        }
    }
    None
}

fn install_cache_entry(entries: &Path, manifest_bytes: &[u8]) -> Result<()> {
    let destination = entries.join(format!("{}.json", sha256_hex(manifest_bytes)));
    match json::write_new_bytes(&destination, manifest_bytes) {
        Ok(()) => Ok(()),
        Err(error) => {
            if fs::read(&destination).ok().as_deref() == Some(manifest_bytes) {
                Ok(())
            } else {
                Err(error.context(format!(
                    "atomically install build cache entry {} without replacement",
                    destination.display()
                )))
            }
        }
    }
}

fn create_build_object(objects: &Path) -> Result<PathBuf> {
    loop {
        let ordinal = NEXT_BUILD_ATTEMPT.fetch_add(1, Ordering::Relaxed);
        let object = objects.join(format!("attempt-{}-{ordinal:016x}", std::process::id()));
        match fs::create_dir(&object) {
            Ok(()) => {
                set_mode(&object, 0o700)?;
                return Ok(object);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn derive_gateway_build(
    repository: &Path,
    execution_root: &Path,
    object_root: &Path,
    inputs: &BuildInputs,
) -> Result<BuildManifest> {
    let source = object_root.join("source");
    let vendor = object_root.join("vendor");
    let cargo_home = object_root.join("cargo-home");
    let target = object_root.join("target");
    let temporary = object_root.join("tmp");
    let immutable_binary = object_root.join("binary").join("auth-mini-gateway");
    for directory in [
        &source,
        &vendor,
        &cargo_home,
        &target,
        &temporary,
        immutable_binary
            .parent()
            .ok_or_else(|| Error::new("binary path has no parent"))?,
    ] {
        create_private_dir(directory)?;
    }

    let archive_path = object_root.join("source.tar");
    run_git_archive(
        &inputs.git_path,
        repository,
        &inputs.address.commit,
        &archive_path,
    )?;
    let archive_bytes = fs::read(&archive_path)?;
    let archive_sha256 = sha256_hex(&archive_bytes);
    extract_git_archive(&archive_path, &source)?;
    let cargo_toml = source.join("Cargo.toml");
    let cargo_lock = source.join("Cargo.lock");
    let cargo_toml_bytes = fs::read(&cargo_toml).context("read archived Cargo.toml")?;
    let cargo_lock_bytes = fs::read(&cargo_lock).context("read archived Cargo.lock")?;
    if sha256_hex(&cargo_toml_bytes) != inputs.address.cargo_toml_sha256
        || sha256_hex(&cargo_lock_bytes) != inputs.address.cargo_lock_sha256
    {
        return Err(Error::new(
            "fresh Git archive Cargo source/lock differs from addressed object input",
        ));
    }
    let source_entries = tree_entries(&source)?;
    let source_tree_sha256 = entry_root(&source_entries);

    let registry_packages = registry_packages_from_lock(&cargo_lock_bytes)?;
    let registry_cache_before =
        capture_registry_cache_inputs(&inputs.external_cargo_home, &registry_packages)?;
    if registry_cache_before != inputs.registry_cache_inputs {
        return Err(Error::new(
            "external dependency cache changed after build-cache addressing",
        ));
    }
    vendor_dependencies(
        &inputs.cargo_path,
        &cargo_toml,
        &vendor,
        &cargo_home,
        &inputs.external_cargo_home,
        &temporary,
        object_root,
    )?;
    let registry_cache_after =
        capture_registry_cache_inputs(&inputs.external_cargo_home, &registry_packages)?;
    if registry_cache_after != inputs.registry_cache_inputs {
        return Err(Error::new(
            "external dependency cache changed while materializing the build closure",
        ));
    }
    let vendor_entries = tree_entries(&vendor)?;
    let vendor_tree_sha256 = entry_root(&vendor_entries);
    let cargo_config_sha256 = sha256_hex(&fs::read(cargo_home.join("config.toml"))?);
    make_tree_read_only(&source)?;
    make_tree_read_only(&vendor)?;
    build_release(
        &inputs.cargo_path,
        &inputs.rustc_path,
        &cargo_toml,
        &cargo_home,
        &target,
        &temporary,
        object_root,
    )?;
    let produced = target.join("release").join("auth-mini-gateway");
    let produced_metadata = fs::symlink_metadata(&produced)
        .context(format!("stat built gateway {}", produced.display()))?;
    if !produced_metadata.file_type().is_file() {
        return Err(Error::new("release gateway output is not a regular file"));
    }
    copy_new(&produced, &immutable_binary)?;
    set_mode(&immutable_binary, 0o555)?;
    let binary_bytes = fs::read(&immutable_binary)?;
    let binary_relative_path = relative_utf8(repository, &immutable_binary)?;
    let external_cargo_home = inputs.external_cargo_home.to_string_lossy().into_owned();
    let manifest = BuildManifest {
        schema: BUILD_SCHEMA.to_owned(),
        cache_schema: BUILD_CACHE_SCHEMA.to_owned(),
        cache_key_sha256: inputs.address.key_sha256()?,
        harness_executable_sha256: inputs.address.harness_executable_sha256.clone(),
        provenance_sha256: inputs.address.provenance_sha256.clone(),
        commit: inputs.address.commit.clone(),
        tree: inputs.address.tree.clone(),
        archive_bytes: u64::try_from(archive_bytes.len())
            .map_err(|_| Error::new("archive length overflow"))?,
        archive_sha256,
        cargo_toml_sha256: sha256_hex(&cargo_toml_bytes),
        cargo_lock_sha256: sha256_hex(&cargo_lock_bytes),
        source_tree_sha256,
        source_entries: u64::try_from(source_entries.len())
            .map_err(|_| Error::new("source entry count overflow"))?,
        vendor_tree_sha256,
        vendor_entries: u64::try_from(vendor_entries.len())
            .map_err(|_| Error::new("vendor entry count overflow"))?,
        external_cargo_home,
        registry_cache_inputs: inputs.registry_cache_inputs.clone(),
        cargo_config_sha256,
        binary_relative_path,
        binary_bytes: u64::try_from(binary_bytes.len())
            .map_err(|_| Error::new("binary length overflow"))?,
        binary_sha256: sha256_hex(&binary_bytes),
        elf_build_id: elf_build_id(&binary_bytes),
        git: inputs.address.git.clone(),
        cargo: inputs.address.cargo.clone(),
        rustc: inputs.address.rustc.clone(),
        execution_root_relative_path: relative_utf8(repository, execution_root)?,
        object_relative_path: relative_utf8(repository, object_root)?,
        cargo_home_relative_path: relative_utf8(repository, &cargo_home)?,
        target_relative_path: relative_utf8(repository, &target)?,
        source_relative_path: relative_utf8(repository, &source)?,
        frozen: true,
        offline: true,
        rustflags_added: false,
        source_injection: false,
    };
    Ok(manifest)
}

fn require_toolchain(cargo: &CommandIdentity, rustc: &CommandIdentity) -> Result<()> {
    if !cargo
        .version
        .lines()
        .next()
        .is_some_and(|line| line.starts_with("cargo 1.96.0 "))
    {
        return Err(Error::new(format!(
            "Cargo identity is not 1.96.0: {}",
            cargo.version.lines().next().unwrap_or_default()
        )));
    }
    if !rustc
        .version
        .lines()
        .next()
        .is_some_and(|line| line.starts_with("rustc 1.96.0 "))
    {
        return Err(Error::new(format!(
            "rustc identity is not 1.96.0: {}",
            rustc.version.lines().next().unwrap_or_default()
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RegistryPackage {
    name: String,
    version: String,
    checksum: String,
}

fn registry_packages_from_lock(bytes: &[u8]) -> Result<Vec<RegistryPackage>> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::new("Cargo.lock is not UTF-8"))?;
    let mut packages = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut source: Option<String> = None;
    let mut checksum: Option<String> = None;
    let finish = |name: &mut Option<String>,
                  version: &mut Option<String>,
                  source: &mut Option<String>,
                  checksum: &mut Option<String>,
                  packages: &mut Vec<RegistryPackage>|
     -> Result<()> {
        let Some(package_name) = name.take() else {
            *version = None;
            *source = None;
            *checksum = None;
            return Ok(());
        };
        let package_version = version
            .take()
            .ok_or_else(|| Error::new("Cargo.lock package lacks a version"))?;
        let package_source = source.take();
        let package_checksum = checksum.take();
        if package_source
            .as_deref()
            .is_some_and(|value| value.starts_with("registry+"))
        {
            let checksum = package_checksum
                .ok_or_else(|| Error::new("registry Cargo.lock package lacks a checksum"))?;
            validate_hash("registry package checksum", &checksum)?;
            if package_name.is_empty()
                || package_version.is_empty()
                || package_name.contains(['/', '\\'])
                || package_version.contains(['/', '\\'])
            {
                return Err(Error::new("Cargo.lock registry package identity is unsafe"));
            }
            packages.push(RegistryPackage {
                name: package_name,
                version: package_version,
                checksum,
            });
        } else if package_source.is_some() {
            return Err(Error::new(
                "exact gateway build supports only lock-resolved registry dependencies",
            ));
        }
        Ok(())
    };
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            finish(
                &mut name,
                &mut version,
                &mut source,
                &mut checksum,
                &mut packages,
            )?;
            continue;
        }
        if name.is_none() && !line.starts_with("name = ") {
            continue;
        }
        if let Some(value) = lock_string(line, "name")? {
            name = Some(value);
        } else if let Some(value) = lock_string(line, "version")? {
            version = Some(value);
        } else if let Some(value) = lock_string(line, "source")? {
            source = Some(value);
        } else if let Some(value) = lock_string(line, "checksum")? {
            checksum = Some(value);
        }
    }
    finish(
        &mut name,
        &mut version,
        &mut source,
        &mut checksum,
        &mut packages,
    )?;
    packages.sort();
    if packages.is_empty() || packages.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::new(
            "Cargo.lock registry dependency inventory is empty or duplicated",
        ));
    }
    Ok(packages)
}

fn lock_string(line: &str, key: &str) -> Result<Option<String>> {
    let prefix = format!("{key} = \"");
    let Some(value) = line.strip_prefix(&prefix) else {
        return Ok(None);
    };
    let value = value
        .strip_suffix('"')
        .ok_or_else(|| Error::new(format!("Cargo.lock {key} string is malformed")))?;
    if value.contains('"') || value.contains('\\') {
        return Err(Error::new(format!(
            "Cargo.lock {key} uses unsupported escaping"
        )));
    }
    Ok(Some(value.to_owned()))
}

fn external_cargo_home() -> Result<PathBuf> {
    let path = match std::env::var_os("CARGO_HOME") {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(std::env::var_os("HOME").ok_or_else(|| Error::new("HOME is not set"))?)
            .join(".cargo"),
    };
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(Error::new("external Cargo cache root is not a directory"));
    }
    Ok(canonical)
}

fn provenance_sha256(
    external_cargo_home: &str,
    registry_cache_inputs: &[RegistryCacheInput],
) -> Result<String> {
    let provenance = BuildCacheProvenance {
        schema: "amg-http2-perf/build-cache-provenance/v1",
        external_cargo_home,
        registry_cache_inputs,
    };
    Ok(sha256_hex(&json::canonical_bytes(&provenance)?))
}

fn current_executable_sha256() -> Result<String> {
    let executable = std::env::current_exe()?;
    let canonical = fs::canonicalize(&executable)?;
    let metadata = fs::symlink_metadata(&canonical)?;
    if !metadata.file_type().is_file() {
        return Err(Error::new(
            "current harness executable is not a regular file",
        ));
    }
    Ok(sha256_hex(&fs::read(canonical)?))
}

fn capture_registry_cache_inputs(
    cargo_home: &Path,
    packages: &[RegistryPackage],
) -> Result<Vec<RegistryCacheInput>> {
    let cache_root = cargo_home.join("registry/cache");
    let source_root = cargo_home.join("registry/src");
    let mut registries = fs::read_dir(&cache_root)
        .context(format!(
            "read Cargo registry archive root {}",
            cache_root.display()
        ))?
        .collect::<std::io::Result<Vec<_>>>()
        .context("enumerate Cargo registry archive roots")?;
    registries.sort_by_key(std::fs::DirEntry::file_name);
    if registries.is_empty() {
        return Err(Error::new("Cargo registry cache has no registry roots"));
    }
    let mut inputs = Vec::with_capacity(packages.len());
    for package in packages {
        let filename = format!("{}-{}.crate", package.name, package.version);
        let directory = format!("{}-{}", package.name, package.version);
        let mut matches = Vec::new();
        for registry in &registries {
            let registry_metadata = registry.metadata().context(format!(
                "stat Cargo registry archive root {}",
                registry.path().display()
            ))?;
            if !registry_metadata.is_dir() || registry_metadata.file_type().is_symlink() {
                return Err(Error::new(
                    "Cargo registry cache root is not a plain directory",
                ));
            }
            let crate_path = registry.path().join(&filename);
            let Ok(metadata) = fs::symlink_metadata(&crate_path) else {
                continue;
            };
            if !metadata.file_type().is_file() {
                return Err(Error::new("Cargo registry archive is not a regular file"));
            }
            let crate_bytes = fs::read(&crate_path)
                .context(format!("read registry archive {}", crate_path.display()))?;
            let crate_sha256 = sha256_hex(&crate_bytes);
            if crate_sha256 != package.checksum {
                continue;
            }
            let registry_name = registry.file_name();
            let source_path = source_root.join(registry_name).join(&directory);
            let source_metadata = fs::symlink_metadata(&source_path).context(format!(
                "stat cached registry source {}",
                source_path.display()
            ))?;
            if !source_metadata.file_type().is_dir() || source_metadata.file_type().is_symlink() {
                return Err(Error::new(
                    "cached registry source is not a plain directory",
                ));
            }
            let source_entries = tree_entries(&source_path).context(format!(
                "hash cached registry source {}",
                source_path.display()
            ))?;
            let checksum_path = source_path.join(".cargo-checksum.json");
            match fs::read(&checksum_path) {
                Ok(checksum_bytes) => {
                    let checksum_value: serde_json::Value = serde_json::from_slice(&checksum_bytes)
                        .map_err(|error| {
                            Error::new(format!("parse .cargo-checksum.json: {error}"))
                        })?;
                    if checksum_value
                        .get("package")
                        .and_then(serde_json::Value::as_str)
                        != Some(package.checksum.as_str())
                    {
                        return Err(Error::new(
                            "cached source package checksum differs from Cargo.lock",
                        ));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // Cargo 1.96 may omit this redundant extraction marker. The
                    // lock-bound `.crate` hash and complete source-tree hash below
                    // still bind both external inputs, including marker absence.
                }
                Err(error) => {
                    return Err(error.into());
                }
            }
            matches.push(RegistryCacheInput {
                name: package.name.clone(),
                version: package.version.clone(),
                lock_checksum: package.checksum.clone(),
                crate_relative_path: relative_utf8(cargo_home, &crate_path)?,
                crate_bytes: metadata.len(),
                crate_sha256,
                source_relative_path: relative_utf8(cargo_home, &source_path)?,
                source_entries: u64::try_from(source_entries.len())
                    .map_err(|_| Error::new("cached source entry count overflow"))?,
                source_tree_sha256: entry_root(&source_entries),
            });
        }
        if matches.len() != 1 {
            return Err(Error::new(format!(
                "expected one checksum-matching cache/source pair for {} {}, found {}",
                package.name,
                package.version,
                matches.len()
            )));
        }
        inputs.push(matches.remove(0));
    }
    inputs.sort_by(|left, right| {
        left.name
            .as_bytes()
            .cmp(right.name.as_bytes())
            .then(left.version.as_bytes().cmp(right.version.as_bytes()))
            .then(
                left.crate_relative_path
                    .as_bytes()
                    .cmp(right.crate_relative_path.as_bytes()),
            )
    });
    validate_registry_cache_inputs(cargo_home, &inputs)?;
    Ok(inputs)
}

fn validate_registry_cache_inputs(cargo_home: &Path, inputs: &[RegistryCacheInput]) -> Result<()> {
    if inputs.is_empty() {
        return Err(Error::new("build cache provenance inventory is empty"));
    }
    let mut identities = BTreeSet::new();
    for input in inputs {
        for (name, value) in [
            ("lock checksum", &input.lock_checksum),
            ("crate hash", &input.crate_sha256),
            ("source tree hash", &input.source_tree_sha256),
        ] {
            validate_hash(name, value)?;
        }
        if input.name.is_empty()
            || input.version.is_empty()
            || input.lock_checksum != input.crate_sha256
            || !identities.insert((input.name.clone(), input.version.clone()))
        {
            return Err(Error::new(
                "invalid or duplicate build cache provenance entry",
            ));
        }
        let crate_path = checked_cache_path(cargo_home, &input.crate_relative_path)?;
        let metadata = fs::symlink_metadata(&crate_path)?;
        if !metadata.file_type().is_file()
            || metadata.len() != input.crate_bytes
            || sha256_hex(&fs::read(&crate_path)?) != input.crate_sha256
        {
            return Err(Error::new("cached registry archive mutated"));
        }
        let source_path = checked_cache_path(cargo_home, &input.source_relative_path)?;
        let entries = tree_entries(&source_path)?;
        if entries.len() as u64 != input.source_entries
            || entry_root(&entries) != input.source_tree_sha256
        {
            return Err(Error::new("cached registry source tree mutated"));
        }
    }
    Ok(())
}

fn checked_cache_path(cargo_home: &Path, relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::new("cache provenance path is unsafe"));
    }
    let path = cargo_home.join(relative);
    require_canonical_below(&path, cargo_home)?;
    Ok(path)
}

fn vendor_dependencies(
    cargo: &Path,
    manifest: &Path,
    vendor: &Path,
    cargo_home: &Path,
    external_cargo_home: &Path,
    temporary: &Path,
    working_directory: &Path,
) -> Result<()> {
    let path = std::env::var_os("PATH").ok_or_else(|| Error::new("PATH is not set"))?;
    let output = Command::new(cargo)
        .current_dir(working_directory)
        .args(["vendor", "--frozen", "--versioned-dirs", "--manifest-path"])
        .arg(manifest)
        .arg(vendor)
        .env_clear()
        .env("CARGO_HOME", external_cargo_home)
        .env("CARGO_NET_OFFLINE", "true")
        .env("HOME", cargo_home)
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("PATH", path)
        .env("TMPDIR", temporary)
        .output()
        .context("materialize repository-local vendored dependency copy")?;
    if !output.status.success() {
        return Err(command_failure("cargo vendor", &output));
    }
    let config = String::from_utf8(output.stdout)
        .map_err(|_| Error::new("cargo vendor config output is not UTF-8"))?;
    if !config.contains("replace-with") || !config.contains("vendored-sources") {
        return Err(Error::new(
            "cargo vendor did not emit source replacement config",
        ));
    }
    let config_path = cargo_home.join("config.toml");
    write_new(&config_path, config.as_bytes(), 0o600)?;
    Ok(())
}

fn build_release(
    cargo: &Path,
    rustc: &Path,
    manifest: &Path,
    cargo_home: &Path,
    target: &Path,
    temporary: &Path,
    working_directory: &Path,
) -> Result<()> {
    let path = std::env::var_os("PATH").ok_or_else(|| Error::new("PATH is not set"))?;
    let status = Command::new(cargo)
        .current_dir(working_directory)
        .args([
            "build",
            "--frozen",
            "--release",
            "--bin",
            "auth-mini-gateway",
            "--manifest-path",
        ])
        .arg(manifest)
        .env_clear()
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", target)
        .env("HOME", cargo_home)
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("PATH", path)
        .env("RUSTC", rustc)
        .env("TMPDIR", temporary)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("offline frozen release gateway build")?;
    if !status.status.success() {
        return Err(command_failure("cargo build", &status));
    }
    Ok(())
}

fn run_git_archive(git: &Path, repository: &Path, commit: &str, output: &Path) -> Result<()> {
    let status = git_command(git, repository)
        .args(["archive", "--format=tar", "--output"])
        .arg(output)
        .arg(commit)
        .status()
        .context("git archive exact commit")?;
    if !status.success() {
        return Err(Error::new(format!("git archive failed with {status}")));
    }
    Ok(())
}

fn extract_git_archive(archive_path: &Path, destination: &Path) -> Result<()> {
    let file = File::open(archive_path)?;
    let mut archive = tar::Archive::new(file);
    let mut seen = BTreeSet::new();
    for entry in archive.entries().context("read git archive entries")? {
        let mut entry = entry.context("read git archive entry")?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_pax_global_extensions() || entry_type.is_pax_local_extensions() {
            continue;
        }
        let path = entry
            .path()
            .context("decode git archive path")?
            .into_owned();
        validate_archive_path(&path)?;
        let path_text = path
            .to_str()
            .ok_or_else(|| Error::new("git archive path is not UTF-8"))?
            .replace('\\', "/");
        if !seen.insert(path_text) {
            return Err(Error::new("duplicate git archive path"));
        }
        let output = destination.join(&path);
        if entry_type.is_dir() {
            fs::create_dir_all(&output)?;
            set_mode(&output, 0o700)?;
        } else if entry_type.is_file() {
            let parent = output
                .parent()
                .ok_or_else(|| Error::new("archive output has no parent"))?;
            fs::create_dir_all(parent)?;
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let source_mode = entry.header().mode().context("read archive mode")?;
            let mode = if source_mode & 0o111 == 0 {
                0o600
            } else {
                0o700
            };
            write_new(&output, &bytes, mode)?;
        } else {
            return Err(Error::new(format!(
                "git archive contains unsupported entry type for {}",
                output.display()
            )));
        }
    }
    Ok(())
}

fn validate_archive_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(Error::new("empty or absolute git archive path"));
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(Error::new("unsafe git archive path component"));
        }
    }
    Ok(())
}

fn tree_entries(root: &Path) -> Result<Vec<TreeEntryHash>> {
    let mut entries = Vec::new();
    collect_tree_entries(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    Ok(entries)
}

fn collect_tree_entries(
    root: &Path,
    directory: &Path,
    output: &mut Vec<TreeEntryHash>,
) -> Result<()> {
    let mut children = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for entry in children {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::new(format!(
                "tree symlink is forbidden: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_tree_entries(root, &path, output)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&path)?;
            output.push(TreeEntryHash {
                path: relative_utf8(root, &path)?,
                bytes: metadata.len(),
                sha256: sha256_hex(&bytes),
            });
        } else {
            return Err(Error::new("tree contains non-regular entry"));
        }
    }
    Ok(())
}

fn entry_root(entries: &[TreeEntryHash]) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"amg-http2-perf/tree/v1\0");
    for entry in entries {
        bytes.extend_from_slice(&(entry.path.len() as u64).to_be_bytes());
        bytes.extend_from_slice(entry.path.as_bytes());
        bytes.extend_from_slice(&entry.bytes.to_be_bytes());
        bytes.extend_from_slice(entry.sha256.as_bytes());
    }
    sha256_hex(&bytes)
}

fn make_tree_read_only(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            make_tree_read_only(&entry?.path())?;
        }
        set_mode(path, 0o500)
    } else if metadata.is_file() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let executable = metadata.permissions().mode() & 0o111 != 0;
            set_mode(path, if executable { 0o500 } else { 0o400 })
        }
        #[cfg(not(unix))]
        {
            Err(Error::new("release construction requires Unix permissions"))
        }
    } else {
        Err(Error::new("read-only tree contains non-file entry"))
    }
}

fn copy_new(source: &Path, destination: &Path) -> Result<()> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    set_mode(path, mode)
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    set_mode(path, 0o700)
}

fn ensure_plain_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_dir() {
                Ok(())
            } else {
                Err(Error::new(format!(
                    "cache directory path is not a plain directory: {}",
                    path.display()
                )))
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| Error::new("cache directory has no parent"))?;
            ensure_plain_directory(parent)?;
            match fs::create_dir(path) {
                Ok(()) => set_mode(path, 0o700),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure_plain_directory(path)
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Err(Error::new("benchmark requires Unix file permissions"))
    }
}

fn resolve_commit(git: &Path, repository: &Path, object: &str) -> Result<String> {
    let kind = git_output(git, repository, &["cat-file", "-t", object])?;
    if kind != "commit" {
        return Err(Error::new(format!("Git object {object} is not a commit")));
    }
    git_output(
        git,
        repository,
        &["rev-parse", &format!("{object}^{{commit}}")],
    )
}

fn ensure_ancestor(git: &Path, repository: &Path, ancestor: &str, commit: &str) -> Result<()> {
    let status = git_command(git, repository)
        .args(["merge-base", "--is-ancestor", ancestor, commit])
        .status()?;
    if !status.success() {
        return Err(Error::new(format!(
            "candidate {commit} does not descend from {ancestor}"
        )));
    }
    Ok(())
}

fn git_output(git: &Path, repository: &Path, arguments: &[&str]) -> Result<String> {
    let output = git_command(git, repository).args(arguments).output()?;
    if !output.status.success() {
        return Err(command_failure("git", &output));
    }
    Ok(String::from_utf8(output.stdout)
        .map_err(|_| Error::new("Git output is not UTF-8"))?
        .trim()
        .to_owned())
}

fn git_file_bytes(
    git: &Path,
    repository: &Path,
    commit: &str,
    relative_path: &str,
) -> Result<Vec<u8>> {
    if relative_path.is_empty()
        || Path::new(relative_path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::new("unsafe Git object file path"));
    }
    let object = format!("{commit}:{relative_path}");
    let output = git_command(git, repository)
        .args(["show", &object])
        .output()
        .context(format!("read {relative_path} from exact Git object"))?;
    if !output.status.success() {
        return Err(command_failure("git show exact object file", &output));
    }
    Ok(output.stdout)
}

fn git_command(git: &Path, repository: &Path) -> Command {
    let mut command = Command::new(git);
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

fn find_executable(name: &str) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").ok_or_else(|| Error::new("PATH is not set"))?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(Error::new(format!(
        "cannot find executable `{name}` in PATH"
    )))
}

fn direct_toolchain_paths() -> Result<(PathBuf, PathBuf)> {
    let rustc_shim = find_executable("rustc")?;
    let output = Command::new(&rustc_shim)
        .args(["--print", "sysroot"])
        .output()
        .context("resolve active Rust sysroot")?;
    if !output.status.success() {
        return Err(command_failure("rustc --print sysroot", &output));
    }
    let sysroot = PathBuf::from(
        String::from_utf8(output.stdout)
            .map_err(|_| Error::new("Rust sysroot is not UTF-8"))?
            .trim(),
    );
    let cargo = sysroot.join("bin/cargo");
    let rustc = sysroot.join("bin/rustc");
    if !cargo.is_file() || !rustc.is_file() {
        return Err(Error::new(
            "active Rust sysroot lacks direct Cargo/rustc binaries",
        ));
    }
    Ok((cargo, rustc))
}

fn command_failure(name: &str, output: &std::process::Output) -> Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let bounded: String = stderr.chars().take(4_096).collect();
    Error::new(format!("{name} failed with {}: {bounded}", output.status))
}

fn require_below_repository(path: &Path, repository: &Path) -> Result<()> {
    let repository = fs::canonicalize(repository)?;
    let parent = path
        .ancestors()
        .find(|ancestor| ancestor.exists())
        .ok_or_else(|| Error::new("execution root has no existing ancestor"))?;
    let canonical_parent = fs::canonicalize(parent)?;
    if !canonical_parent.starts_with(&repository) {
        return Err(Error::new("execution root is outside repository"));
    }
    Ok(())
}

fn relative_utf8(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .map_err(|_| Error::new("path is outside repository"))?
        .to_str()
        .ok_or_else(|| Error::new("path is not UTF-8"))?
        .replace('\\', "/"))
}

fn validate_object_id(name: &str, value: &str) -> Result<()> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::new(format!(
            "{name} is not a full 40-hex Git object ID"
        )));
    }
    Ok(())
}

fn validate_hash(name: &str, value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::new(format!("{name} is not a SHA-256 hash")));
    }
    Ok(())
}

fn elf_build_id(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return None;
    }
    let phoff = read_u64_le(bytes, 32)? as usize;
    let phentsize = usize::from(read_u16_le(bytes, 54)?);
    let phnum = usize::from(read_u16_le(bytes, 56)?);
    for index in 0..phnum {
        let offset = phoff.checked_add(index.checked_mul(phentsize)?)?;
        if read_u32_le(bytes, offset)? != 4 {
            continue;
        }
        let note_offset = read_u64_le(bytes, offset + 8)? as usize;
        let note_size = read_u64_le(bytes, offset + 32)? as usize;
        let end = note_offset.checked_add(note_size)?.min(bytes.len());
        let mut cursor = note_offset;
        while cursor.checked_add(12)? <= end {
            let name_size = read_u32_le(bytes, cursor)? as usize;
            let descriptor_size = read_u32_le(bytes, cursor + 4)? as usize;
            let note_type = read_u32_le(bytes, cursor + 8)?;
            cursor += 12;
            let name_end = cursor.checked_add(name_size)?;
            let name = bytes.get(cursor..name_end)?;
            cursor = align_four(name_end)?;
            let descriptor_end = cursor.checked_add(descriptor_size)?;
            let descriptor = bytes.get(cursor..descriptor_end)?;
            cursor = align_four(descriptor_end)?;
            if note_type == 3 && name.starts_with(b"GNU") {
                return Some(
                    descriptor
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                );
            }
        }
    }
    None
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn align_four(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::symlink;

    fn fixture_command(name: &str) -> CommandIdentity {
        CommandIdentity {
            path: format!("/fixture/{name}"),
            bytes: 1,
            sha256: sha256_hex(name.as_bytes()),
            version: format!("{name} fixture"),
        }
    }

    fn fixture_address(provenance: &str) -> BuildCacheAddress {
        BuildCacheAddress {
            schema: BUILD_CACHE_SCHEMA.to_owned(),
            build_schema: BUILD_SCHEMA.to_owned(),
            commit: "11".repeat(20),
            tree: "22".repeat(20),
            cargo_toml_sha256: sha256_hex(b"Cargo.toml"),
            cargo_lock_sha256: sha256_hex(b"Cargo.lock"),
            harness_executable_sha256: sha256_hex(b"harness"),
            provenance_sha256: sha256_hex(provenance.as_bytes()),
            git: fixture_command("git"),
            cargo: fixture_command("cargo"),
            rustc: fixture_command("rustc"),
            frozen: true,
            offline: true,
            rustflags_added: false,
            source_injection: false,
        }
    }

    fn fixture_manifest(
        address: &BuildCacheAddress,
        execution_root: &Path,
        object_root: &Path,
    ) -> BuildManifest {
        let object = |path: &str| object_root.join(path).to_string_lossy().into_owned();
        BuildManifest {
            schema: BUILD_SCHEMA.to_owned(),
            cache_schema: BUILD_CACHE_SCHEMA.to_owned(),
            cache_key_sha256: address.key_sha256().expect("cache key"),
            harness_executable_sha256: address.harness_executable_sha256.clone(),
            provenance_sha256: address.provenance_sha256.clone(),
            commit: address.commit.clone(),
            tree: address.tree.clone(),
            archive_bytes: 1,
            archive_sha256: sha256_hex(b"archive"),
            cargo_toml_sha256: address.cargo_toml_sha256.clone(),
            cargo_lock_sha256: address.cargo_lock_sha256.clone(),
            source_tree_sha256: sha256_hex(b"source-tree"),
            source_entries: 1,
            vendor_tree_sha256: sha256_hex(b"vendor-tree"),
            vendor_entries: 1,
            external_cargo_home: "/fixture/cargo-home".to_owned(),
            registry_cache_inputs: Vec::new(),
            cargo_config_sha256: sha256_hex(b"cargo-config"),
            binary_relative_path: object("binary/auth-mini-gateway"),
            binary_bytes: 1,
            binary_sha256: sha256_hex(b"binary"),
            elf_build_id: None,
            git: address.git.clone(),
            cargo: address.cargo.clone(),
            rustc: address.rustc.clone(),
            execution_root_relative_path: execution_root.to_string_lossy().into_owned(),
            object_relative_path: object_root.to_string_lossy().into_owned(),
            cargo_home_relative_path: object("cargo-home"),
            target_relative_path: object("target"),
            source_relative_path: object("source"),
            frozen: true,
            offline: true,
            rustflags_added: false,
            source_injection: false,
        }
    }

    fn fixture_root(name: &str) -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("build-cache-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        ensure_plain_directory(&root).expect("fixture root");
        root
    }

    fn derive_fixture(
        address: &BuildCacheAddress,
        execution_root: &Path,
        object_root: &Path,
        stages: &Cell<u8>,
    ) -> Result<BuildManifest> {
        for (path, bytes) in [
            ("source/rederived", b"authoritative source".as_slice()),
            ("vendor/rederived", b"authoritative vendor".as_slice()),
            (
                "binary/auth-mini-gateway",
                b"authoritative binary".as_slice(),
            ),
        ] {
            let output = object_root.join(path);
            fs::create_dir_all(output.parent().expect("fixture output parent"))?;
            fs::write(output, bytes)?;
            stages.set(stages.get() + 1);
        }
        stages.set(stages.get() + 1);
        Ok(fixture_manifest(address, execution_root, object_root))
    }

    fn revalidate_fixture(manifest: &BuildManifest) -> Result<()> {
        let object = PathBuf::from(&manifest.object_relative_path);
        for (path, bytes) in [
            ("source/rederived", b"authoritative source".as_slice()),
            ("vendor/rederived", b"authoritative vendor".as_slice()),
            (
                "binary/auth-mini-gateway",
                b"authoritative binary".as_slice(),
            ),
        ] {
            if fs::read(object.join(path))? != bytes {
                return Err(Error::new("fixture was not fully rederived"));
            }
        }
        if fs::read(object.join("build-manifest.json"))? != json::canonical_bytes(manifest)? {
            return Err(Error::new("fixture manifest was not atomically finalized"));
        }
        Ok(())
    }

    fn write_untrusted_entry(entries: &Path, bytes: &[u8]) -> PathBuf {
        ensure_plain_directory(entries).expect("entry directory");
        let path = entries.join(format!("{}.json", sha256_hex(bytes)));
        fs::write(&path, bytes).expect("untrusted entry");
        path
    }

    #[test]
    fn rejects_non_commit_width_and_unsafe_archive_paths() {
        assert!(validate_object_id("commit", "abc").is_err());
        assert!(validate_archive_path(Path::new("../src/main.rs")).is_err());
        assert!(validate_archive_path(Path::new("/src/main.rs")).is_err());
        assert!(validate_archive_path(Path::new("src/main.rs")).is_ok());
    }

    #[test]
    fn tree_root_is_path_and_length_bound() {
        let one = vec![TreeEntryHash {
            path: "a".to_owned(),
            bytes: 1,
            sha256: "00".repeat(32),
        }];
        let mut two = one.clone();
        two[0].path = "b".to_owned();
        assert_ne!(entry_root(&one), entry_root(&two));
        two[0].path = "a".to_owned();
        two[0].bytes = 2;
        assert_ne!(entry_root(&one), entry_root(&two));
    }

    #[test]
    fn build_cache_mutation_path_escape_and_config_injection_suite() {
        let package = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = package
            .join("target")
            .join(format!("build-cache-mutation-suite-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("vendor/pkg")).unwrap();
        fs::create_dir_all(root.join("cargo-home")).unwrap();
        fs::write(root.join("vendor/pkg/source.rs"), b"one").unwrap();
        let before = entry_root(&tree_entries(&root.join("vendor")).unwrap());
        fs::write(root.join("vendor/pkg/source.rs"), b"two").unwrap();
        let after = entry_root(&tree_entries(&root.join("vendor")).unwrap());
        assert_ne!(
            before, after,
            "vendored source mutation must change closure"
        );

        let vendor = fs::canonicalize(root.join("vendor")).unwrap();
        fs::write(
            root.join("cargo-home/config.toml"),
            format!(
                "[source.crates-io]\nreplace-with = \"vendored-sources\"\n[source.vendored-sources]\ndirectory = \"{}\"\n",
                vendor.display()
            ),
        )
        .unwrap();
        let repository = fs::canonicalize(&package).unwrap();
        validate_cargo_config(&root.join("cargo-home/config.toml"), &vendor, &repository)
            .expect("repository-local vendor config");
        fs::write(
            root.join("cargo-home/config.toml"),
            "[source.crates-io]\nreplace-with = \"remote\"\n[source.remote]\nregistry = \"https://example.invalid/index\"\n",
        )
        .unwrap();
        assert!(
            validate_cargo_config(&root.join("cargo-home/config.toml"), &vendor, &repository)
                .is_err()
        );
        assert!(checked_repository_path(&repository, "../escape", false).is_err());
        assert!(checked_repository_path(&repository, "/tmp/escape", false).is_err());

        let cache_home = root.join("cache-home");
        let registry_name = "index.crates.io-test";
        fs::create_dir_all(cache_home.join("registry/cache").join(registry_name)).unwrap();
        fs::create_dir_all(
            cache_home
                .join("registry/src")
                .join(registry_name)
                .join("demo-1.2.3"),
        )
        .unwrap();
        let crate_bytes = b"deterministic crate archive";
        let checksum = sha256_hex(crate_bytes);
        fs::write(
            cache_home
                .join("registry/cache")
                .join(registry_name)
                .join("demo-1.2.3.crate"),
            crate_bytes,
        )
        .unwrap();
        let source = cache_home
            .join("registry/src")
            .join(registry_name)
            .join("demo-1.2.3");
        fs::write(source.join("lib.rs"), b"pub fn demo() {}\n").unwrap();
        fs::write(
            source.join(".cargo-checksum.json"),
            format!("{{\"files\":{{}},\"package\":\"{checksum}\"}}"),
        )
        .unwrap();
        let package = RegistryPackage {
            name: "demo".to_owned(),
            version: "1.2.3".to_owned(),
            checksum,
        };
        let captured = capture_registry_cache_inputs(&cache_home, std::slice::from_ref(&package))
            .expect("capture exact cache provenance");
        validate_registry_cache_inputs(&cache_home, &captured).expect("unchanged cache provenance");
        fs::write(source.join("lib.rs"), b"pub fn mutated() {}\n").unwrap();
        assert!(validate_registry_cache_inputs(&cache_home, &captured).is_err());
        assert!(checked_cache_path(&cache_home, "../escape").is_err());

        let parsed = registry_packages_from_lock(
            format!(
                "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n",
                package.checksum
            )
            .as_bytes(),
        )
        .expect("parse lock registry provenance");
        assert_eq!(parsed, vec![package]);

        let link = root.join("vendor/link");
        symlink("/etc/passwd", &link).unwrap();
        assert!(tree_entries(&root.join("vendor")).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn old_manifest_missing_external_cargo_home_is_a_non_destructive_cache_miss() {
        let execution_root = fixture_root("old-schema-miss");
        let address = fixture_address("current-provenance");
        let legacy = execution_root.join("builds").join(&address.commit);
        fs::create_dir_all(legacy.join("binary")).expect("legacy cache");
        fs::write(legacy.join("binary/auth-mini-gateway"), b"legacy binary")
            .expect("legacy binary");
        let legacy_manifest = fixture_manifest(&address, &execution_root, &legacy);
        let mut legacy_value = serde_json::to_value(&legacy_manifest).expect("legacy value");
        legacy_value
            .as_object_mut()
            .expect("legacy object")
            .remove("external_cargo_home");
        let legacy_bytes = json::canonical_bytes(&legacy_value).expect("legacy bytes");
        fs::write(legacy.join("build-manifest.json"), &legacy_bytes).expect("legacy manifest");
        assert!(json::require_canonical::<BuildManifest>(&legacy_bytes).is_err());

        let namespace = address.namespace(&execution_root).expect("namespace");
        let partial = namespace.join("objects/attempt-stale-partial");
        fs::create_dir_all(&partial).expect("partial object");
        fs::write(partial.join("partial"), b"do not reuse or remove").expect("partial bytes");
        let legacy_root_before = entry_root(&tree_entries(&legacy).expect("legacy tree"));
        let partial_root_before = entry_root(&tree_entries(&partial).expect("partial tree"));
        let stages = Cell::new(0);
        let rebuilt = resolve_build_cache_with(
            &namespace,
            |bytes| parse_cache_candidate(bytes, &address, |_| Ok(())),
            |object| derive_fixture(&address, &execution_root, object, &stages),
            revalidate_fixture,
        )
        .expect("old cache is a miss, not a blocker");

        assert_eq!(stages.get(), 4, "all fresh derivation stages must run");
        assert_ne!(Path::new(&rebuilt.object_relative_path), legacy);
        assert_eq!(
            entry_root(&tree_entries(&legacy).expect("legacy tree after")),
            legacy_root_before,
            "the old cache entry must remain byte-for-byte untouched"
        );
        assert_eq!(
            entry_root(&tree_entries(&partial).expect("partial tree after")),
            partial_root_before,
            "an unrelated partial cache object must remain untouched"
        );
        revalidate_fixture(&rebuilt).expect("fully rederived object");
        fs::remove_dir_all(execution_root).expect("fixture cleanup");
    }

    #[test]
    fn malformed_cache_json_is_a_miss_and_atomic_install_never_replaces() {
        let execution_root = fixture_root("malformed-miss");
        let address = fixture_address("malformed-provenance");
        let namespace = address.namespace(&execution_root).expect("namespace");
        let entries = namespace.join("entries");
        let malformed = b"{not-json\n";
        let malformed_path = write_untrusted_entry(&entries, malformed);
        let stages = Cell::new(0);
        let rebuilt = resolve_build_cache_with(
            &namespace,
            |bytes| parse_cache_candidate(bytes, &address, |_| Ok(())),
            |object| derive_fixture(&address, &execution_root, object, &stages),
            revalidate_fixture,
        )
        .expect("malformed cache is a miss");
        assert_eq!(stages.get(), 4);
        assert_eq!(
            fs::read(&malformed_path).expect("malformed bytes"),
            malformed
        );
        revalidate_fixture(&rebuilt).expect("fully rederived object");

        let intended = b"content-addressed install";
        let occupied = entries.join(format!("{}.json", sha256_hex(intended)));
        fs::write(&occupied, b"concurrent occupant").expect("occupied destination");
        assert!(install_cache_entry(&entries, intended).is_err());
        assert_eq!(
            fs::read(occupied).expect("occupied bytes"),
            b"concurrent occupant",
            "atomic cache installation must never replace a concurrent entry"
        );
        fs::remove_dir_all(execution_root).expect("fixture cleanup");
    }

    #[test]
    fn structurally_valid_mutated_provenance_is_rejected_and_rederived() {
        let execution_root = fixture_root("mutated-provenance");
        let address = fixture_address("expected-provenance");
        let namespace = address.namespace(&execution_root).expect("namespace");
        let stale_object = namespace.join("objects/stale-object");
        fs::create_dir_all(&stale_object).expect("stale object");
        let mut stale = fixture_manifest(&address, &execution_root, &stale_object);
        stale.provenance_sha256 = sha256_hex(b"mutated-provenance");
        let stale_bytes = json::canonical_bytes(&stale).expect("stale bytes");
        let stale_path = write_untrusted_entry(&namespace.join("entries"), &stale_bytes);
        let cache_revalidations = Cell::new(0);
        let stages = Cell::new(0);
        let rebuilt = resolve_build_cache_with(
            &namespace,
            |bytes| {
                parse_cache_candidate(bytes, &address, |_| {
                    cache_revalidations.set(cache_revalidations.get() + 1);
                    Ok(())
                })
            },
            |object| derive_fixture(&address, &execution_root, object, &stages),
            revalidate_fixture,
        )
        .expect("mutated provenance is a miss");

        assert_eq!(
            cache_revalidations.get(),
            0,
            "wrong address is never trusted"
        );
        assert_eq!(stages.get(), 4);
        assert_eq!(fs::read(stale_path).expect("stale entry"), stale_bytes);
        assert_eq!(rebuilt.provenance_sha256, address.provenance_sha256);
        revalidate_fixture(&rebuilt).expect("fully rederived object");
        fs::remove_dir_all(execution_root).expect("fixture cleanup");
    }

    #[test]
    fn current_valid_cache_is_fully_revalidated_and_reused_without_rebuild() {
        let execution_root = fixture_root("valid-reuse");
        let address = fixture_address("valid-provenance");
        let namespace = address.namespace(&execution_root).expect("namespace");
        let object = namespace.join("objects/current-object");
        fs::create_dir_all(&object).expect("current object");
        let setup_stages = Cell::new(0);
        let current =
            derive_fixture(&address, &execution_root, &object, &setup_stages).expect("fixture");
        let bytes = json::canonical_bytes(&current).expect("manifest bytes");
        json::write_new_bytes(&object.join("build-manifest.json"), &bytes)
            .expect("object manifest");
        let entries = namespace.join("entries");
        ensure_plain_directory(&entries).expect("entries");
        install_cache_entry(&entries, &bytes).expect("cache entry");

        let cache_revalidations = Cell::new(0);
        let rebuilds = Cell::new(0);
        let reused = resolve_build_cache_with(
            &namespace,
            |candidate| {
                parse_cache_candidate(candidate, &address, |manifest| {
                    cache_revalidations.set(cache_revalidations.get() + 1);
                    revalidate_fixture(manifest)
                })
            },
            |_| {
                rebuilds.set(rebuilds.get() + 1);
                Err(Error::new("valid cache unexpectedly rebuilt"))
            },
            |_| Err(Error::new("new-build validation unexpectedly ran")),
        )
        .expect("valid current cache reuse");

        assert_eq!(reused, current);
        assert_eq!(cache_revalidations.get(), 1);
        assert_eq!(rebuilds.get(), 0);
        fs::remove_dir_all(execution_root).expect("fixture cleanup");
    }
}
