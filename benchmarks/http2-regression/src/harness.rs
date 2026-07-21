use crate::schema::HarnessProvenance;
use crate::seal::sha256_hex;
use crate::{Error, Result};
use std::path::Path;
use std::process::Command;

const EMBEDDED_COMMIT: &str = env!("AMG_HARNESS_COMMIT");
const EMBEDDED_TREE: &str = env!("AMG_HARNESS_TREE");

pub fn require_exact_committed_harness(repository: &Path) -> Result<HarnessProvenance> {
    let head = git_text(repository, &["rev-parse", "HEAD"])?;
    let tree = git_text(
        repository,
        &["rev-parse", "HEAD:benchmarks/http2-regression"],
    )?;
    let ancestry = Command::new("git")
        .args(["merge-base", "--is-ancestor", EMBEDDED_COMMIT, &head])
        .current_dir(repository)
        .status()?;
    if !ancestry.success() || tree != EMBEDDED_TREE {
        return Err(Error::new(
            "measurement executable was not built from an ancestor exact harness commit/tree",
        ));
    }
    let status = git_bytes(
        repository,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            "benchmarks/http2-regression",
        ],
    )?;
    if !status.is_empty() {
        return Err(Error::new(
            "benchmark source has tracked or untracked drift from the exact harness commit",
        ));
    }
    provenance_for_commit(repository, EMBEDDED_COMMIT)
}

pub fn verify_recorded_provenance(repository: &Path, provenance: &HarnessProvenance) -> Result<()> {
    provenance.validate()?;
    if &provenance_for_commit(repository, &provenance.commit)? != provenance {
        return Err(Error::new(
            "recorded harness provenance differs from the exact Git object",
        ));
    }
    Ok(())
}

fn provenance_for_commit(repository: &Path, commit: &str) -> Result<HarnessProvenance> {
    let commit = git_text(repository, &["rev-parse", &format!("{commit}^{{commit}}")])?;
    let tree = git_text(
        repository,
        &[
            "rev-parse",
            &format!("{commit}:benchmarks/http2-regression"),
        ],
    )?;
    let archive = git_bytes(
        repository,
        &[
            "archive",
            "--format=tar",
            &commit,
            "benchmarks/http2-regression",
        ],
    )?;
    let lock = git_bytes(
        repository,
        &[
            "show",
            &format!("{commit}:benchmarks/http2-regression/Cargo.lock"),
        ],
    )?;
    let provenance = HarnessProvenance {
        commit,
        tree_object: tree,
        source_archive_sha256: sha256_hex(&archive),
        cargo_lock_sha256: sha256_hex(&lock),
    };
    provenance.validate()?;
    Ok(provenance)
}

fn git_text(repository: &Path, arguments: &[&str]) -> Result<String> {
    let bytes = git_bytes(repository, arguments)?;
    Ok(String::from_utf8(bytes)
        .map_err(|_| Error::new("Git provenance output is not UTF-8"))?
        .trim()
        .to_owned())
}

fn git_bytes(repository: &Path, arguments: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .output()?;
    if !output.status.success() {
        return Err(Error::new("Git harness provenance command failed"));
    }
    Ok(output.stdout)
}
