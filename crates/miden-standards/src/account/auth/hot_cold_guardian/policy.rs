use miden_protocol::Word;

/// The policy of an account procedure in [`AuthHotColdGuardian`](super::AuthHotColdGuardian): the
/// user key categories that must sign a transaction calling it.
///
/// Policies count signed key categories, not keys: the hot category counts once any hot key
/// signed, the cold category once the cold key signed. The guardian co-signs every transaction
/// and is not part of the policy.
///
/// The policy is encoded into the procedure-policy storage word as
/// `[immediate_threshold, delayed_threshold, cold_required, 0]`, where `immediate_threshold` is
/// the number of signed categories required and `cold_required` narrows a single-category
/// threshold to the cold key. The delayed threshold is reserved for the delayed path and stays 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HotColdPolicy {
    /// Either category suffices: any hot key or the cold key.
    HotOrCold,
    /// Both categories must sign.
    HotAndCold,
    /// Only the cold key counts; the hot keys cannot call the procedure.
    ColdOnly,
}

impl HotColdPolicy {
    /// Returns the number of signed categories the policy requires.
    pub fn immediate_threshold(self) -> u32 {
        match self {
            Self::HotOrCold | Self::ColdOnly => 1,
            Self::HotAndCold => 2,
        }
    }

    /// Returns whether the cold category must be among the signed ones.
    pub fn cold_required(self) -> bool {
        matches!(self, Self::ColdOnly)
    }

    /// Returns the storage word of the policy.
    pub fn to_word(self) -> Word {
        Word::from([self.immediate_threshold(), 0, self.cold_required() as u32, 0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hot_cold_policy_word_encoding_matches_storage_layout() {
        assert_eq!(HotColdPolicy::HotOrCold.to_word(), [1u32, 0, 0, 0].into());
        assert_eq!(HotColdPolicy::HotAndCold.to_word(), [2u32, 0, 0, 0].into());
        assert_eq!(HotColdPolicy::ColdOnly.to_word(), [1u32, 0, 1, 0].into());
    }
}
