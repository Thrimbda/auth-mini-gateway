use crate::json;
use crate::schema::{
    validate_non_placeholder_sha256, validate_sha256, EXECUTION_SCHEMA, JSON_MAX_BYTES,
};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

const SEAL_DOMAIN: &[u8] = b"amg-http2-perf/seal/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealEntry {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

impl SealEntry {
    pub fn validate(&self) -> Result<()> {
        validate_relative_path(&self.path)?;
        validate_non_placeholder_sha256("seal entry sha256", &self.sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealManifest {
    pub schema: String,
    pub hash_algorithm: String,
    pub entries: Vec<SealEntry>,
    pub root_sha256: String,
}

impl SealManifest {
    pub fn validate(&self) -> Result<()> {
        if self.schema != EXECUTION_SCHEMA || self.hash_algorithm != "sha256" {
            return Err(Error::new("unsupported seal schema or hash algorithm"));
        }
        validate_non_placeholder_sha256("seal root", &self.root_sha256)?;
        let mut previous: Option<&[u8]> = None;
        let mut unique = BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            let path = entry.path.as_bytes();
            if previous.is_some_and(|value| value >= path) || !unique.insert(entry.path.clone()) {
                return Err(Error::new(
                    "seal entries are not strictly byte-sorted and unique",
                ));
            }
            previous = Some(path);
        }
        let computed = seal_root(&self.entries)?;
        if computed != self.root_sha256 {
            return Err(Error::new("seal root does not match its entries"));
        }
        Ok(())
    }
}

pub fn create_seal(root: &Path) -> Result<SealManifest> {
    let seal_path = root.join("seal.json");
    if fs::symlink_metadata(&seal_path).is_ok() {
        return Err(Error::new(
            "seal.json already exists; evidence is write-once",
        ));
    }
    let entries = collect_source_entries(root)?;
    let manifest = SealManifest {
        schema: EXECUTION_SCHEMA.to_owned(),
        hash_algorithm: "sha256".to_owned(),
        root_sha256: seal_root(&entries)?,
        entries,
    };
    manifest.validate()?;
    json::write_new_canonical(&seal_path, &manifest)?;
    Ok(manifest)
}

pub fn verify_seal(root: &Path) -> Result<SealManifest> {
    let seal_path = root.join("seal.json");
    let bytes = fs::read(&seal_path)
        .map_err(|error| Error::new(format!("cannot read {}: {error}", seal_path.display())))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > JSON_MAX_BYTES {
        return Err(Error::new("seal.json exceeds the 1 MiB schema cap"));
    }
    let manifest: SealManifest = json::require_canonical(&bytes)?;
    manifest.validate()?;
    let actual = collect_source_entries(root)?;
    if actual != manifest.entries {
        return Err(Error::new(
            "seal closure has missing, extra, length, or hash differences",
        ));
    }
    Ok(manifest)
}

pub fn collect_source_entries(root: &Path) -> Result<Vec<SealEntry>> {
    let root_metadata = fs::symlink_metadata(root).map_err(|error| {
        Error::new(format!(
            "cannot stat source root {}: {error}",
            root.display()
        ))
    })?;
    if !root_metadata.file_type().is_dir() {
        return Err(Error::new("source root is not a directory"));
    }
    let mut paths = Vec::new();
    collect_regular_paths(root, root, &mut paths)?;
    paths.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut entries = Vec::with_capacity(paths.len());
    for (relative, absolute) in paths {
        let bytes = fs::read(&absolute)?;
        if relative.ends_with(".json")
            && u64::try_from(bytes.len()).unwrap_or(u64::MAX) > JSON_MAX_BYTES
        {
            return Err(Error::new(format!("JSON member exceeds 1 MiB: {relative}")));
        }
        scan_secret_free(&relative, &bytes)?;
        entries.push(SealEntry {
            path: relative,
            bytes: u64::try_from(bytes.len()).map_err(|_| Error::new("member length overflow"))?,
            sha256: sha256_hex(&bytes),
        });
    }
    Ok(entries)
}

fn collect_regular_paths(
    root: &Path,
    directory: &Path,
    output: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let kind = metadata.file_type();
        if kind.is_symlink() {
            return Err(Error::new(format!(
                "source symlink is forbidden: {}",
                path.display()
            )));
        }
        if kind.is_dir() {
            collect_regular_paths(root, &path, output)?;
        } else if kind.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(Error::new(format!(
                        "source hard link is forbidden: {}",
                        path.display()
                    )));
                }
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| Error::new("source path escaped root"))?;
            let relative = path_to_archive_string(relative)?;
            if relative == "seal.json" {
                continue;
            }
            validate_relative_path(&relative)?;
            output.push((relative, path));
        } else {
            return Err(Error::new(format!(
                "source contains a non-regular member: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

pub fn seal_root(entries: &[SealEntry]) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(SEAL_DOMAIN);
    for entry in entries {
        entry.validate()?;
        let path_len = u32::try_from(entry.path.len())
            .map_err(|_| Error::new("seal path length exceeds u32"))?;
        hasher.update(path_len.to_be_bytes());
        hasher.update(entry.path.as_bytes());
        hasher.update(entry.bytes.to_be_bytes());
        hasher.update(decode_hash(&entry.sha256)?);
    }
    Ok(hex_lower(&hasher.finalize()))
}

pub fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(Error::new(format!("unsafe archive path `{path}`")));
    }
    let parsed = Path::new(path);
    for component in parsed.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(Error::new(format!(
                    "unsafe archive path component in `{path}`"
                )));
            }
        }
    }
    if path
        .split('/')
        .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(Error::new(format!(
            "empty or dot archive path component in `{path}`"
        )));
    }
    if ustar_path_parts(path).is_none() {
        return Err(Error::new(format!(
            "path does not fit canonical ustar fields: `{path}`"
        )));
    }
    Ok(())
}

pub fn ustar_path_parts(path: &str) -> Option<(&str, &str)> {
    if path.len() <= 100 {
        return Some(("", path));
    }
    for (index, byte) in path.bytes().enumerate().rev() {
        if byte == b'/' {
            let prefix = &path[..index];
            let suffix = &path[index + 1..];
            if !prefix.is_empty()
                && prefix.len() <= 155
                && !suffix.is_empty()
                && suffix.len() <= 100
            {
                return Some((prefix, suffix));
            }
        }
    }
    None
}

pub fn scan_secret_free(path: &str, bytes: &[u8]) -> Result<()> {
    let lower_path = path.to_ascii_lowercase();
    let forbidden_components = [
        "cookie",
        "cookies",
        "token",
        "tokens",
        "secret",
        "secrets",
        "keys",
        "cache",
        "target",
        "database",
        "databases",
        "payloads",
    ];
    if lower_path == "analysis.json"
        || lower_path.ends_with("/analysis.json")
        || lower_path.ends_with("report.md")
        || lower_path.ends_with(".sqlite")
        || lower_path.ends_with(".sqlite-wal")
        || lower_path.ends_with(".sqlite-shm")
        || lower_path
            .split('/')
            .any(|component| forbidden_components.contains(&component))
    {
        return Err(Error::new(format!(
            "forbidden secret/cache/derived path `{path}`"
        )));
    }
    let lower = bytes.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    for pattern in [
        b"\"cookie\"".as_slice(),
        b"\"token\"".as_slice(),
        b"\"password\"".as_slice(),
        b"\"secret\"".as_slice(),
        b"\"private_key\"".as_slice(),
        b"\"signing_key\"".as_slice(),
        b"authorization:".as_slice(),
        b"-----begin private key-----".as_slice(),
        b"-----begin rsa private key-----".as_slice(),
    ] {
        if contains_bytes(&lower, pattern) {
            return Err(Error::new(format!(
                "secret-bearing evidence member `{path}`"
            )));
        }
    }
    reject_external_urls(path, &lower)?;
    Ok(())
}

fn reject_external_urls(path: &str, bytes: &[u8]) -> Result<()> {
    if contains_bytes(bytes, b"https://") {
        return Err(Error::new(format!(
            "external/TLS endpoint is forbidden in evidence member `{path}`"
        )));
    }
    let marker = b"http://";
    let mut remaining = bytes;
    while let Some(index) = remaining
        .windows(marker.len())
        .position(|window| window == marker)
    {
        let endpoint = &remaining[index + marker.len()..];
        if !endpoint.starts_with(b"127.0.0.1") && !endpoint.starts_with(b"[::1]") {
            return Err(Error::new(format!(
                "non-loopback endpoint is forbidden in evidence member `{path}`"
            )));
        }
        remaining = endpoint;
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn path_to_archive_string(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(
                value
                    .to_str()
                    .ok_or_else(|| Error::new("source path is not valid UTF-8"))?,
            ),
            _ => return Err(Error::new("source path is not relative and normalized")),
        }
    }
    Ok(parts.join("/"))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn decode_hash(value: &str) -> Result<[u8; 32]> {
    validate_sha256("hash", value)?;
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(Error::new("invalid lowercase hexadecimal digit")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_paths_and_canonical_ustar_splits_are_strict() {
        assert!(validate_relative_path("intent.json").is_ok());
        assert!(validate_relative_path("arms/0/get-c1/B11/metadata.json").is_ok());
        for path in ["", "/x", "x/", "x//y", "x/../y", "x/./y", "x\\y"] {
            assert!(validate_relative_path(path).is_err(), "accepted {path:?}");
        }
        let prefix = "a".repeat(155);
        let suffix = "b".repeat(100);
        let fitting = format!("{prefix}/{suffix}");
        assert_eq!(
            ustar_path_parts(&fitting),
            Some((prefix.as_str(), suffix.as_str()))
        );
        assert!(validate_relative_path(&format!("{}/{}", "a".repeat(156), suffix)).is_err());
    }

    #[test]
    fn seal_root_golden_vector_is_stable_and_order_sensitive() {
        let entries = vec![
            SealEntry {
                path: "a".to_owned(),
                bytes: 1,
                sha256: sha256_hex(b"x"),
            },
            SealEntry {
                path: "b/c".to_owned(),
                bytes: 2,
                sha256: sha256_hex(b"yz"),
            },
        ];
        assert_eq!(
            seal_root(&entries).expect("seal root"),
            "b23fd700cfb6c85196a436a624da73c161375284ed4c3428c6e589fc58f6afd2"
        );
        let mut reversed = entries;
        reversed.reverse();
        assert_ne!(
            seal_root(&reversed).expect("reversed root"),
            "b23fd700cfb6c85196a436a624da73c161375284ed4c3428c6e589fc58f6afd2"
        );
    }

    #[test]
    fn secret_and_cache_names_or_content_fail_closed() {
        assert!(scan_secret_free("tokens/value", b"hash").is_err());
        assert!(scan_secret_free("raw.json", br#"{"token":"abc"}"#).is_err());
        assert!(scan_secret_free("analysis.json", b"{}").is_err());
        assert!(scan_secret_free("safe.json", b"http://example.com").is_err());
        assert!(scan_secret_free("safe.json", b"https://127.0.0.1").is_err());
        assert!(scan_secret_free("safe.json", b"http://127.0.0.1:8080").is_ok());
        assert!(scan_secret_free("safe.bin", b"opaque counters").is_ok());
    }
}
