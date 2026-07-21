use auth_mini_http2_regression::delivery::test_support::{
    fake_delivery_complete, run_fake_delivery,
};
use auth_mini_http2_regression::delivery::{DeliveryBinding, DeliveryPhase, DeliveryTransaction};
use auth_mini_http2_regression::schema::{EvidenceKind, TerminalState};
use auth_mini_http2_regression::seal::sha256_hex;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-scratch");
        fs::create_dir_all(&parent).expect("delivery scratch parent");
        let path = parent.join(format!(
            "{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("exclusive delivery scratch");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn every_calibration_and_campaign_delivery_phase_resumes_after_a_bounded_crash() {
    let scratch = Scratch::new("delivery-crash-resume");
    for kind in [EvidenceKind::Calibration, EvidenceKind::Campaign] {
        for (ordinal, phase) in DeliveryPhase::ALL.into_iter().enumerate() {
            let id = format!("fake-{kind:?}-{ordinal}").to_ascii_lowercase();
            assert!(run_fake_delivery(&scratch.0, kind, &id, Some(phase), true).is_err());
            assert_eq!(
                run_fake_delivery(&scratch.0, kind, &id, None, true).expect("resume delivery"),
                TerminalState::Pass
            );
            assert!(fake_delivery_complete(&scratch.0, kind, &id).expect("complete state"));
        }
    }
}

#[test]
fn final_cap_failure_never_replays_a_stale_pass() {
    let scratch = Scratch::new("delivery-cap-failure");
    let id = "fake-cap-failure";
    for _ in 0..2 {
        assert_eq!(
            run_fake_delivery(&scratch.0, EvidenceKind::Campaign, id, None, false)
                .expect("bounded cap decision"),
            TerminalState::Blocked
        );
        assert!(
            !fake_delivery_complete(&scratch.0, EvidenceKind::Campaign, id)
                .expect("incomplete transaction")
        );
        let seal = sha256_hex(format!("seal:{id}").as_bytes());
        let transaction = DeliveryTransaction::open(&scratch.0, EvidenceKind::Campaign, id, &seal)
            .expect("inspect cap-failed transaction");
        assert!(!transaction.completed(DeliveryPhase::LedgerPublished));
        assert!(!transaction.completed(DeliveryPhase::OutcomePublished));
    }
    assert_eq!(
        run_fake_delivery(&scratch.0, EvidenceKind::Campaign, id, None, true)
            .expect("cap recovery"),
        TerminalState::Pass
    );
}

#[test]
fn completed_phase_bindings_are_write_once_and_revalidated() {
    let scratch = Scratch::new("delivery-binding");
    let id = "fake-binding";
    let seal = sha256_hex(format!("seal:{id}").as_bytes());
    let mut transaction =
        DeliveryTransaction::open(&scratch.0, EvidenceKind::Calibration, id, &seal)
            .expect("transaction");
    let original = DeliveryBinding {
        path: "source/seal.json".to_owned(),
        sha256: sha256_hex(b"original"),
    };
    transaction
        .record(DeliveryPhase::SourceVerified, vec![original.clone()])
        .expect("first record");
    transaction
        .record(DeliveryPhase::SourceVerified, vec![original])
        .expect("idempotent record");
    let changed = DeliveryBinding {
        path: "source/seal.json".to_owned(),
        sha256: sha256_hex(b"tampered"),
    };
    assert!(transaction
        .record(DeliveryPhase::SourceVerified, vec![changed])
        .expect_err("changed binding")
        .to_string()
        .contains("stale or changed"));
}

#[test]
fn run_command_requires_candidate_and_accepts_only_u64_seed_without_starting_measurement() {
    let binary = env!("CARGO_BIN_EXE_auth-mini-http2-regression");
    let missing = Command::new(binary)
        .arg("run")
        .output()
        .expect("run missing-candidate command");
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("missing required --candidate"));

    let invalid_seed = Command::new(binary)
        .args([
            "run",
            "--candidate",
            "0000000000000000000000000000000000000000",
            "--seed",
            "not-u64",
        ])
        .output()
        .expect("run invalid-seed command");
    assert!(!invalid_seed.status.success());
    assert!(String::from_utf8_lossy(&invalid_seed.stderr).contains("unsigned integer"));
}
