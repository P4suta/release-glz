//! The one configuration that every property test of the integration suites runs with.
//!
//! Each property fixes its own case count, so `PROPTEST_CASES` can't stretch a gate run.
//! The seed is fixed unless `PROPTEST_RNG_SEED` names another one, so a gate run is reproducible and an exploration run needs only that variable.
//! No run writes a regression file; a counterexample stays as an example test beside its property.

use proptest::prelude::{Strategy, any, prop_oneof};
use proptest::sample::{Index, select};
use proptest::test_runner::{Config, RngSeed};

/// The seed of every run that `PROPTEST_RNG_SEED` doesn't replace.
pub const SEED: u64 = 0x7265_6c65_6173_6521;

/// Shrink steps a failing property takes before it reports the smallest case found so far.
///
/// A case that seals a Candidate writes files, so an unbounded shrink of one failure could outlast the gate.
const MAX_SHRINK_ITERS: u32 = 1_024;

/// A configuration that runs `cases` generated cases from the fixed seed and writes no regression file.
#[must_use]
pub fn config(cases: u32) -> Config {
    let environment = Config::default();
    let rng_seed = match environment.rng_seed {
        RngSeed::Random => RngSeed::Fixed(SEED),
        chosen @ RngSeed::Fixed(_) => chosen,
    };
    Config {
        cases,
        failure_persistence: None,
        max_shrink_iters: MAX_SHRINK_ITERS,
        rng_seed,
        ..environment
    }
}

/// One changed, removed, or added byte of a file.
#[derive(Debug, Clone, Copy)]
pub enum ByteChange {
    /// Invert the one bit of the mask in one byte.
    Flip(Index, u8),
    /// Keep only the bytes before one position.
    Truncate(Index),
    /// Append one byte.
    Extend(u8),
}

impl ByteChange {
    /// `bytes` after this change.
    ///
    /// # Panics
    ///
    /// When a flip or a truncation meets no bytes to change.
    #[must_use]
    pub fn apply(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Flip(offset, mask) => {
                let offset = offset.index(bytes.len());
                bytes
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| if index == offset { byte ^ mask } else { *byte })
                    .collect()
            }
            Self::Truncate(length) => bytes
                .iter()
                .take(length.index(bytes.len()))
                .copied()
                .collect(),
            Self::Extend(byte) => bytes.iter().copied().chain([byte]).collect(),
        }
    }
}

/// Changes of one byte, which flip a bit six times as often as they remove or add bytes.
pub fn byte_change() -> impl Strategy<Value = ByteChange> {
    prop_oneof![
        6 => (any::<Index>(), select(&[1_u8, 2, 4, 8, 16, 32, 64, 128][..]))
            .prop_map(|(offset, mask)| ByteChange::Flip(offset, mask)),
        1 => any::<Index>().prop_map(ByteChange::Truncate),
        1 => any::<u8>().prop_map(ByteChange::Extend),
    ]
}

#[cfg(test)]
mod tests {
    use super::{ByteChange, config};
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::{RngSeed, TestRunner};

    #[test]
    fn a_property_runs_its_own_case_count_from_a_seed_without_writing_a_file() {
        let config = config(7);
        assert_eq!(config.cases, 7);
        assert!(config.failure_persistence.is_none());
        assert!(matches!(config.rng_seed, RngSeed::Fixed(_)));
    }

    #[test]
    fn a_change_flips_one_bit_removes_bytes_or_adds_one() {
        let mut runner = TestRunner::deterministic();
        let bytes = b"sealed".as_slice();
        for _ in 0..256 {
            let change = super::byte_change()
                .new_tree(&mut runner)
                .unwrap()
                .current();
            let changed = change.apply(bytes);
            match change {
                ByteChange::Flip(_, mask) => {
                    assert_eq!(mask.count_ones(), 1);
                    assert_eq!(changed.len(), bytes.len());
                    let differences: u32 = bytes
                        .iter()
                        .zip(&changed)
                        .map(|(before, after)| (before ^ after).count_ones())
                        .sum();
                    assert_eq!(differences, 1, "{change:?}");
                }
                ByteChange::Truncate(_) => {
                    assert!(changed.len() < bytes.len());
                    assert!(bytes.starts_with(&changed));
                }
                ByteChange::Extend(byte) => {
                    assert_eq!(changed, [bytes, &[byte]].concat());
                }
            }
        }
    }
}
