use crate::rng::{fisher_yates, SplitMix64};
use crate::schema::{
    all_cells, comparison_id, validate_identifier, validate_non_placeholder_sha256, Arm, Cell,
    ComparisonKind, RoundPlan,
};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const BASE_ROWS: [[usize; 5]; 5] = [
    [0, 1, 4, 2, 3],
    [1, 2, 0, 3, 4],
    [2, 3, 1, 4, 0],
    [3, 4, 2, 0, 1],
    [4, 0, 3, 1, 2],
];

#[must_use]
pub fn williams_rows() -> [[Arm; 5]; 10] {
    let mut rows = [[Arm::B11; 5]; 10];
    for (index, source) in BASE_ROWS.iter().enumerate() {
        for (position, arm) in source.iter().copied().enumerate() {
            rows[index][position] = Arm::ALL[arm];
            rows[index + 5][position] = Arm::ALL[source[4 - position]];
        }
    }
    rows
}

pub fn validate_williams_balance(rows: &[[Arm; 5]; 10]) -> Result<()> {
    let mut positions = [[0_u8; 5]; 5];
    let mut carryover = [[0_u8; 5]; 5];
    let mut pair_order = [[[0_u8; 2]; 5]; 5];
    for row in rows {
        let mut seen = [false; 5];
        for (position, arm) in row.iter().copied().enumerate() {
            let arm_index = arm.index();
            if seen[arm_index] {
                return Err(Error::new("Williams row repeats a treatment"));
            }
            seen[arm_index] = true;
            positions[arm_index][position] += 1;
        }
        for adjacent in row.windows(2) {
            carryover[adjacent[0].index()][adjacent[1].index()] += 1;
        }
        for (left, right_orders) in pair_order.iter_mut().enumerate() {
            for (right, order_counts) in right_orders.iter_mut().enumerate().skip(left + 1) {
                let left_position = row
                    .iter()
                    .position(|arm| arm.index() == left)
                    .ok_or_else(|| Error::new("missing treatment in Williams row"))?;
                let right_position = row
                    .iter()
                    .position(|arm| arm.index() == right)
                    .ok_or_else(|| Error::new("missing treatment in Williams row"))?;
                order_counts[usize::from(left_position > right_position)] += 1;
            }
        }
    }
    if positions.iter().flatten().any(|count| *count != 2) {
        return Err(Error::new("Williams position balance mismatch"));
    }
    for (left, row) in carryover.iter().enumerate() {
        for (right, count) in row.iter().copied().enumerate() {
            if left != right && count != 2 {
                return Err(Error::new("Williams directed carryover mismatch"));
            }
        }
    }
    for (left, right_orders) in pair_order.iter().enumerate() {
        for order_counts in right_orders.iter().skip(left + 1) {
            if *order_counts != [5, 5] {
                return Err(Error::new("Williams AB/BA order mismatch"));
            }
        }
    }
    Ok(())
}

pub fn generate_rounds(seed: u64, n: u32) -> Result<Vec<RoundPlan>> {
    if !matches!(n, 30 | 50 | 70 | 100) {
        return Err(Error::new("schedule N must be one of 30, 50, 70, or 100"));
    }
    let repetitions = n / 10;
    let mut row_instances = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
    for _ in 0..repetitions {
        row_instances.extend(0_u8..10);
    }
    let mut rng = SplitMix64::new(seed);
    fisher_yates(&mut row_instances, &mut rng)?;

    let mut rounds = Vec::with_capacity(row_instances.len());
    for (round, row) in row_instances.into_iter().enumerate() {
        let mut cells = all_cells();
        fisher_yates(&mut cells, &mut rng)?;
        rounds.push(RoundPlan {
            round: u32::try_from(round).map_err(|_| Error::new("round index overflow"))?,
            row,
            arm_order: williams_rows()[usize::from(row)].to_vec(),
            cells,
        });
    }
    validate_rounds(&rounds, n)?;
    Ok(rounds)
}

pub fn validate_rounds(rounds: &[RoundPlan], n: u32) -> Result<()> {
    if rounds.len() != usize::try_from(n).unwrap_or(usize::MAX) {
        return Err(Error::new("schedule round count differs from N"));
    }
    let mut row_counts = [0_u32; 10];
    for (index, round) in rounds.iter().enumerate() {
        round.validate()?;
        if round.round != u32::try_from(index).unwrap_or(u32::MAX) {
            return Err(Error::new("schedule rounds are not contiguous"));
        }
        row_counts[usize::from(round.row)] += 1;
    }
    if row_counts.iter().any(|count| *count != n / 10) {
        return Err(Error::new(
            "schedule does not use every Williams row equally",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairIdentity {
    pub comparison_id: String,
    pub round: u32,
    pub cell: Cell,
    pub treatment: Arm,
    pub reference: Arm,
    pub treatment_observation_id: String,
    pub reference_observation_id: String,
    pub treatment_raw_sha256: String,
    pub reference_raw_sha256: String,
    pub treatment_position: u8,
    pub reference_position: u8,
    pub treatment_before_reference: bool,
}

impl PairIdentity {
    pub fn validate(&self) -> Result<()> {
        self.cell.validate()?;
        validate_identifier("pair comparison_id", &self.comparison_id)?;
        validate_identifier(
            "pair treatment_observation_id",
            &self.treatment_observation_id,
        )?;
        validate_identifier(
            "pair reference_observation_id",
            &self.reference_observation_id,
        )?;
        validate_non_placeholder_sha256("pair treatment_raw_sha256", &self.treatment_raw_sha256)?;
        validate_non_placeholder_sha256("pair reference_raw_sha256", &self.reference_raw_sha256)?;
        if self.treatment_position >= 5
            || self.reference_position >= 5
            || self.treatment_position == self.reference_position
            || self.treatment_before_reference
                != (self.treatment_position < self.reference_position)
        {
            return Err(Error::new("pair position identity is invalid"));
        }
        Ok(())
    }
}

pub fn pair_identity(
    round: u32,
    cell: Cell,
    kind: ComparisonKind,
    observation_ids: &BTreeMap<Arm, String>,
    raw_hashes: &BTreeMap<Arm, String>,
    row: u8,
) -> Result<PairIdentity> {
    let (treatment, reference) = match kind {
        ComparisonKind::CandidateH1 => (Arm::C11, Arm::B11),
        ComparisonKind::H2ToH1 => (Arm::C21, Arm::C11),
        ComparisonKind::H1ToH2 => (Arm::C12, Arm::C11),
        ComparisonKind::H2ToH2 => (Arm::C22, Arm::C11),
    };
    let rows = williams_rows();
    let row_arms = rows
        .get(usize::from(row))
        .ok_or_else(|| Error::new("pair references an invalid Williams row"))?;
    let treatment_position = row_arms
        .iter()
        .position(|arm| *arm == treatment)
        .ok_or_else(|| Error::new("treatment absent from Williams row"))?;
    let reference_position = row_arms
        .iter()
        .position(|arm| *arm == reference)
        .ok_or_else(|| Error::new("reference absent from Williams row"))?;
    let identity = PairIdentity {
        comparison_id: comparison_id(cell, kind),
        round,
        cell,
        treatment,
        reference,
        treatment_observation_id: observation_ids
            .get(&treatment)
            .cloned()
            .ok_or_else(|| Error::new("missing treatment observation identity"))?,
        reference_observation_id: observation_ids
            .get(&reference)
            .cloned()
            .ok_or_else(|| Error::new("missing reference observation identity"))?,
        treatment_raw_sha256: raw_hashes
            .get(&treatment)
            .cloned()
            .ok_or_else(|| Error::new("missing treatment raw identity"))?,
        reference_raw_sha256: raw_hashes
            .get(&reference)
            .cloned()
            .ok_or_else(|| Error::new("missing reference raw identity"))?,
        treatment_position: u8::try_from(treatment_position)
            .map_err(|_| Error::new("treatment position exceeds u8"))?,
        reference_position: u8::try_from(reference_position)
            .map_err(|_| Error::new("reference position exceeds u8"))?,
        treatment_before_reference: treatment_position < reference_position,
    };
    identity.validate()?;
    Ok(identity)
}

pub fn self_test() -> Result<()> {
    let rows = williams_rows();
    validate_williams_balance(&rows)?;
    let rounds = generate_rounds(0x0123_4567_89ab_cdef, 30)?;
    if rounds[0].row != 0
        || rounds[0].cells[0].id() != "upload-1mib-c1"
        || rounds[29].row != 5
        || rounds[29].cells[14].id() != "upload-1mib-c16"
    {
        return Err(Error::new(format!(
            "round/cell schedule golden vector mismatch: row0={}, cell0={}, row29={}, cell29={}",
            rounds[0].row,
            rounds[0].cells[0].id(),
            rounds[29].row,
            rounds[29].cells[14].id()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_rows_match_rfc_and_all_balance_properties() {
        let rows = williams_rows();
        assert_eq!(rows[0], [Arm::B11, Arm::C11, Arm::C22, Arm::C21, Arm::C12]);
        assert_eq!(rows[5], [Arm::C12, Arm::C21, Arm::C22, Arm::C11, Arm::B11]);
        validate_williams_balance(&rows).expect("balanced Williams design");
    }

    #[test]
    fn row_and_cell_order_golden_vector_is_stable() {
        self_test().expect("schedule golden vector");
    }

    #[test]
    fn every_allowed_n_repeats_each_row_exactly() {
        for n in [30, 50, 70, 100] {
            validate_rounds(&generate_rounds(42, n).expect("schedule"), n)
                .expect("balanced rounds");
        }
    }

    #[test]
    fn candidate_h2_pairs_share_the_same_c11_identity() {
        let ids: BTreeMap<_, _> = Arm::ALL
            .into_iter()
            .map(|arm| (arm, format!("obs-{}", arm.code())))
            .collect();
        let hashes: BTreeMap<_, _> = Arm::ALL
            .into_iter()
            .map(|arm| (arm, format!("{:064x}", arm.index() + 1)))
            .collect();
        let cell = all_cells()[4];
        let pairs: Vec<_> = [
            ComparisonKind::H2ToH1,
            ComparisonKind::H1ToH2,
            ComparisonKind::H2ToH2,
        ]
        .into_iter()
        .map(|kind| pair_identity(3, cell, kind, &ids, &hashes, 7).expect("pair"))
        .collect();
        assert!(pairs
            .iter()
            .all(|pair| pair.reference_observation_id == "obs-C11"));
        assert!(pairs
            .iter()
            .all(|pair| pair.reference_raw_sha256 == hashes[&Arm::C11]));
        assert_eq!(
            pairs.iter().map(|pair| pair.round).collect::<Vec<_>>(),
            vec![3; 3]
        );

        let mut drifted = pairs[0].clone();
        drifted.reference_raw_sha256 = "00".repeat(32);
        assert!(drifted.validate().is_err());
        assert_ne!(drifted.reference_raw_sha256, pairs[0].reference_raw_sha256);
        drifted.reference_position = drifted.treatment_position;
        assert!(drifted.validate().is_err());
    }
}
