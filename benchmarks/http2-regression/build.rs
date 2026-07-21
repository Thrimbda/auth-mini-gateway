use std::process::Command;

fn git(arguments: &[&str]) -> String {
    let output = Command::new("git")
        .args(arguments)
        .output()
        .expect("run git for harness provenance");
    assert!(output.status.success(), "git provenance command failed");
    String::from_utf8(output.stdout)
        .expect("git provenance is UTF-8")
        .trim()
        .to_owned()
}

fn main() {
    let commit = git(&["rev-parse", "HEAD"]);
    let tree = git(&["rev-parse", "HEAD:benchmarks/http2-regression"]);
    println!("cargo:rustc-env=AMG_HARNESS_COMMIT={commit}");
    println!("cargo:rustc-env=AMG_HARNESS_TREE={tree}");
    println!(
        "cargo:rerun-if-changed={}",
        git(&["rev-parse", "--git-path", "HEAD"])
    );
    if let Ok(reference) = std::panic::catch_unwind(|| git(&["symbolic-ref", "HEAD"])) {
        println!(
            "cargo:rerun-if-changed={}",
            git(&["rev-parse", "--git-path", &reference])
        );
    }
}
