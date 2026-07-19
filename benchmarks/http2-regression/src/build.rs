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

pub const BUILD_SCHEMA: &str = "amg-http2-perf/build/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeEntryHash {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildManifest {
    pub schema: String,
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
    pub binary_relative_path: String,
    pub binary_bytes: u64,
    pub binary_sha256: String,
    pub elf_build_id: Option<String>,
    pub git: CommandIdentity,
    pub cargo: CommandIdentity,
    pub rustc: CommandIdentity,
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
        if self.schema != BUILD_SCHEMA
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
            ("archive", &self.archive_sha256),
            ("Cargo.toml", &self.cargo_toml_sha256),
            ("Cargo.lock", &self.cargo_lock_sha256),
            ("source tree", &self.source_tree_sha256),
            ("vendor tree", &self.vendor_tree_sha256),
            ("binary", &self.binary_sha256),
        ] {
            validate_hash(name, value)?;
        }
        let binary = repository.join(&self.binary_relative_path);
        let metadata = fs::symlink_metadata(&binary)?;
        if !metadata.file_type().is_file() || metadata.len() != self.binary_bytes {
            return Err(Error::new("cached build binary type or length changed"));
        }
        if sha256_hex(&fs::read(&binary)?) != self.binary_sha256 {
            return Err(Error::new("cached build binary hash changed"));
        }
        Ok(binary)
    }
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
    let git_path = find_executable("git")?;
    let (cargo_path, rustc_path) = direct_toolchain_paths()?;
    let commit = resolve_commit(&git_path, repository, requested_commit)?;
    if commit != requested_commit {
        return Err(Error::new(
            "build input must already be the exact full commit ID",
        ));
    }
    let build_root = execution_root.join("builds").join(&commit);
    let manifest_path = build_root.join("build-manifest.json");
    if manifest_path.is_file() {
        let manifest: BuildManifest = json::read_strict(&manifest_path, JSON_MAX_BYTES)?;
        if manifest.commit != commit {
            return Err(Error::new("cached build manifest commit mismatch"));
        }
        manifest.validate(repository)?;
        return Ok(manifest);
    }
    if build_root.exists() {
        make_tree_writable(&build_root)?;
        fs::remove_dir_all(&build_root)
            .context("remove incomplete unsealed build directory before exact rebuild")?;
    }
    create_private_dir(&build_root)?;
    let source = build_root.join("source");
    let vendor = build_root.join("vendor");
    let cargo_home = build_root.join("cargo-home");
    let target = build_root.join("target");
    let temporary = build_root.join("tmp");
    let immutable_binary = build_root.join("binary").join("auth-mini-gateway");
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

    let tree = git_output(
        &git_path,
        repository,
        &["rev-parse", &format!("{commit}^{{tree}}")],
    )?;
    validate_object_id("tree", &tree)?;
    let archive_path = build_root.join("source.tar");
    run_git_archive(&git_path, repository, &commit, &archive_path)?;
    let archive_bytes = fs::read(&archive_path)?;
    let archive_sha256 = sha256_hex(&archive_bytes);
    extract_git_archive(&archive_path, &source)?;
    let cargo_toml = source.join("Cargo.toml");
    let cargo_lock = source.join("Cargo.lock");
    let cargo_toml_bytes = fs::read(&cargo_toml).context("read archived Cargo.toml")?;
    let cargo_lock_bytes = fs::read(&cargo_lock).context("read archived Cargo.lock")?;
    let source_entries = tree_entries(&source)?;
    let source_tree_sha256 = entry_root(&source_entries);

    let git_identity = command_identity(&git_path, &["--version"])?;
    let cargo_identity = command_identity(&cargo_path, &["-vV"])?;
    let rustc_identity = command_identity(&rustc_path, &["-vV"])?;
    require_toolchain(&cargo_identity, &rustc_identity)?;

    vendor_dependencies(
        &cargo_path,
        &cargo_toml,
        &vendor,
        &cargo_home,
        &temporary,
        &build_root,
    )?;
    let vendor_entries = tree_entries(&vendor)?;
    let vendor_tree_sha256 = entry_root(&vendor_entries);
    make_tree_read_only(&source)?;
    make_tree_read_only(&vendor)?;
    build_release(
        &cargo_path,
        &rustc_path,
        &cargo_toml,
        &cargo_home,
        &target,
        &temporary,
        &build_root,
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
    let manifest = BuildManifest {
        schema: BUILD_SCHEMA.to_owned(),
        commit,
        tree,
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
        binary_relative_path,
        binary_bytes: u64::try_from(binary_bytes.len())
            .map_err(|_| Error::new("binary length overflow"))?,
        binary_sha256: sha256_hex(&binary_bytes),
        elf_build_id: elf_build_id(&binary_bytes),
        git: git_identity,
        cargo: cargo_identity,
        rustc: rustc_identity,
        cargo_home_relative_path: relative_utf8(repository, &cargo_home)?,
        target_relative_path: relative_utf8(repository, &target)?,
        source_relative_path: relative_utf8(repository, &source)?,
        frozen: true,
        offline: true,
        rustflags_added: false,
        source_injection: false,
    };
    json::write_new_canonical(&manifest_path, &manifest)?;
    manifest.validate(repository)?;
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

fn vendor_dependencies(
    cargo: &Path,
    manifest: &Path,
    vendor: &Path,
    cargo_home: &Path,
    temporary: &Path,
    working_directory: &Path,
) -> Result<()> {
    let output = Command::new(cargo)
        .current_dir(working_directory)
        .args(["vendor", "--frozen", "--versioned-dirs", "--manifest-path"])
        .arg(manifest)
        .arg(vendor)
        .env("CARGO_NET_OFFLINE", "true")
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

fn make_tree_writable(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        set_mode(path, 0o700)?;
        for entry in fs::read_dir(path)? {
            make_tree_writable(&entry?.path())?;
        }
        Ok(())
    } else if metadata.is_file() {
        set_mode(path, 0o600)
    } else {
        Err(Error::new("writable cleanup tree contains non-file entry"))
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

fn git_command(git: &Path, repository: &Path) -> Command {
    let mut command = Command::new(git);
    command
        .current_dir(repository)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
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
}
