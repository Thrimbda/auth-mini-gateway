use auth_mini_http2_regression::campaign_coordinator::test_support::{
    fake_design, run_fake_campaign, FakeCampaignExecutor, FakeResumeState, FakeVerdict,
};
use auth_mini_http2_regression::process_plan::{campaign_plan, CampaignDirectKey, PlannedArm};
use auth_mini_http2_regression::schema::EvidenceClass;
use auth_mini_http2_regression::Result;

#[derive(Clone)]
struct Executor {
    signature_mismatch: Option<u64>,
    direct_rate: u64,
    baseline_rate: u64,
    gateway_rate: u64,
    runtime_stop: Option<u64>,
    storage_stop: Option<u64>,
    performance_passes: bool,
}

impl Default for Executor {
    fn default() -> Self {
        Self {
            signature_mismatch: None,
            direct_rate: 10_000,
            baseline_rate: 10_000,
            gateway_rate: 8_000,
            runtime_stop: None,
            storage_stop: None,
            performance_passes: true,
        }
    }
}

impl FakeCampaignExecutor for Executor {
    fn signature_matches(&self, arm: &PlannedArm) -> bool {
        self.signature_mismatch != Some(arm.ordinal)
    }

    fn direct_rate(&self, _epoch: u32, _key: CampaignDirectKey) -> u64 {
        self.direct_rate
    }

    fn baseline_direct_rate(&self, _key: CampaignDirectKey) -> u64 {
        self.baseline_rate
    }

    fn gateway_rate(&self, _arm: &PlannedArm) -> u64 {
        self.gateway_rate
    }

    fn runtime_allowed(&self, next_ordinal: u64) -> bool {
        self.runtime_stop.is_none_or(|stop| next_ordinal < stop)
    }

    fn storage_allowed(&self, next_ordinal: u64) -> bool {
        self.storage_stop.is_none_or(|stop| next_ordinal < stop)
    }

    fn performance_passes(&self) -> bool {
        self.performance_passes
    }
}

#[test]
fn n30_and_n50_have_exact_d_before_a_epoch_inventory() -> Result<()> {
    for n in [30, 50] {
        let (design, direct_order) = fake_design(n)?;
        let plan = campaign_plan("fake-campaign", &design, &"ab".repeat(32), &direct_order)?;
        assert_eq!(plan.direct_arms, 3 * u64::from(n));
        assert_eq!(plan.authoritative_arms, 75 * u64::from(n));
        assert_eq!(plan.arms.len() as u64, 78 * u64::from(n));
        for (epoch_index, epoch) in plan.arms.chunks_exact(780).enumerate() {
            let epoch_number = epoch_index as u32 + 1;
            assert!(epoch[..30].iter().all(|arm| {
                arm.evidence_class == EvidenceClass::D && arm.round == Some(epoch_number)
            }));
            assert!(epoch[30..]
                .iter()
                .all(|arm| arm.evidence_class == EvidenceClass::A));
            for round in 0..10 {
                let offset = 30 + round * 75;
                let planned_round = &design.rounds[epoch_index * 10 + round];
                let raw_round = &epoch[offset..offset + 75];
                assert!(raw_round
                    .iter()
                    .all(|arm| arm.round == Some(planned_round.round)));
                for (position, treatment) in planned_round.arm_order.iter().enumerate() {
                    assert_eq!(raw_round[position].arm, Some(*treatment));
                }
            }
        }
        let result = run_fake_campaign(
            &design,
            &direct_order,
            &Executor::default(),
            Default::default(),
        )?;
        assert_eq!(result.completed_arms, 78 * u64::from(n));
        assert_eq!(result.pair_identities, 45 * u64::from(n));
        assert_eq!(result.verdict, FakeVerdict::Pass);
    }
    Ok(())
}

#[test]
fn signature_drift_headroom_runtime_and_storage_fail_closed() -> Result<()> {
    let (design, direct_order) = fake_design(30)?;
    let mismatch = Executor {
        signature_mismatch: Some(30),
        ..Default::default()
    };
    assert!(
        run_fake_campaign(&design, &direct_order, &mismatch, Default::default())
            .expect_err("signature mismatch")
            .to_string()
            .contains("signature")
    );

    let drift = Executor {
        direct_rate: 8_999,
        ..Default::default()
    };
    assert!(
        run_fake_campaign(&design, &direct_order, &drift, Default::default())
            .expect_err("direct drift")
            .to_string()
            .contains("drift")
    );

    let headroom = Executor {
        gateway_rate: 8_001,
        ..Default::default()
    };
    assert!(
        run_fake_campaign(&design, &direct_order, &headroom, Default::default())
            .expect_err("direct headroom")
            .to_string()
            .contains("headroom")
    );

    for executor in [
        Executor {
            runtime_stop: Some(31),
            ..Default::default()
        },
        Executor {
            storage_stop: Some(31),
            ..Default::default()
        },
    ] {
        let result = run_fake_campaign(&design, &direct_order, &executor, Default::default())?;
        assert_eq!(result.verdict, FakeVerdict::Blocked);
        assert_eq!(result.completed_arms, 31);
    }
    Ok(())
}

#[test]
fn partial_resume_and_analysis_verdict_are_bounded() -> Result<()> {
    let (design, direct_order) = fake_design(30)?;
    let partial = run_fake_campaign(
        &design,
        &direct_order,
        &Executor::default(),
        FakeResumeState {
            completed_prefix: 17,
            partially_started_ordinal: Some(17),
        },
    )?;
    assert_eq!(partial.verdict, FakeVerdict::Blocked);
    assert_eq!(partial.completed_arms, 17);

    let resumed = run_fake_campaign(
        &design,
        &direct_order,
        &Executor::default(),
        FakeResumeState {
            completed_prefix: 780,
            partially_started_ordinal: None,
        },
    )?;
    assert_eq!(resumed.verdict, FakeVerdict::Pass);
    assert_eq!(resumed.completed_arms, resumed.total_arms);

    let failed = run_fake_campaign(
        &design,
        &direct_order,
        &Executor {
            performance_passes: false,
            ..Default::default()
        },
        Default::default(),
    )?;
    assert_eq!(failed.verdict, FakeVerdict::Fail);
    Ok(())
}
