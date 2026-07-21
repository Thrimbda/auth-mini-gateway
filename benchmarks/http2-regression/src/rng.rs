use crate::{Error, Result};

const SPLITMIX64_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;

pub trait WordRng {
    fn next_u64(&mut self) -> u64;
}

/// Fully specified SplitMix64 stream used for schedules and bootstrap draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    #[must_use]
    pub const fn state(self) -> u64 {
        self.state
    }
}

impl WordRng for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(SPLITMIX64_GAMMA);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

/// Draws uniformly from `0..bound`, rejecting the modulo-biased low tail.
pub fn bounded<R: WordRng>(rng: &mut R, bound: u64) -> Result<u64> {
    if bound == 0 {
        return Err(Error::new("bounded draw requires a nonzero bound"));
    }
    let rejection_threshold = bound.wrapping_neg() % bound;
    loop {
        let word = rng.next_u64();
        if word >= rejection_threshold {
            return Ok(word % bound);
        }
    }
}

pub fn fisher_yates<T, R: WordRng>(values: &mut [T], rng: &mut R) -> Result<()> {
    for upper in (1..values.len()).rev() {
        let bound = u64::try_from(upper + 1).map_err(|_| Error::new("shuffle length overflow"))?;
        let selected = usize::try_from(bounded(rng, bound)?)
            .map_err(|_| Error::new("bounded index does not fit usize"))?;
        values.swap(upper, selected);
    }
    Ok(())
}

pub fn self_test() -> Result<()> {
    let mut rng = SplitMix64::new(0);
    let expected = [
        0xe220_a839_7b1d_cdaf,
        0x6e78_9e6a_a1b9_65f4,
        0x06c4_5d18_8009_454f,
        0xf88b_b8a8_724c_81ec,
    ];
    for word in expected {
        if rng.next_u64() != word {
            return Err(Error::new("SplitMix64 golden vector mismatch"));
        }
    }
    let mut values = [0_u8, 1, 2, 3, 4];
    fisher_yates(&mut values, &mut SplitMix64::new(0x0123_4567_89ab_cdef))?;
    if values != [1, 4, 2, 3, 0] {
        return Err(Error::new(format!(
            "Fisher-Yates golden vector mismatch: {values:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    struct Scripted {
        words: Vec<u64>,
        index: usize,
    }

    impl WordRng for Scripted {
        fn next_u64(&mut self) -> u64 {
            let word = self.words[self.index];
            self.index += 1;
            word
        }
    }

    #[test]
    fn splitmix64_golden_words_are_stable() {
        self_test().expect("golden vectors");
    }

    #[test]
    fn rejection_sampling_rejects_biased_tail() {
        let mut rng = Scripted {
            words: vec![0, 5],
            index: 0,
        };
        assert_eq!(bounded(&mut rng, 3).expect("draw"), 2);
        assert_eq!(rng.index, 2);
        assert!(bounded(&mut rng, 0).is_err());
    }

    #[test]
    fn bounded_draws_stay_in_range_and_cover_small_domain() {
        let mut rng = SplitMix64::new(17);
        let draws: BTreeSet<_> = (0..10_000)
            .map(|_| bounded(&mut rng, 7).expect("bounded draw"))
            .collect();
        assert_eq!(draws, BTreeSet::from([0, 1, 2, 3, 4, 5, 6]));
    }
}
