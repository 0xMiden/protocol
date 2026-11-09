use miden_protocol::Word;
use miden_protocol::errors::AccountError;

use super::config::NUM_USER_KEY_CATEGORIES;

/// The policy of an account procedure in [`AuthHotColdGuardian`](super::AuthHotColdGuardian).
///
/// Thresholds count signed key categories, not keys: the hot category contributes one once any
/// hot key signed, the cold category one once the cold key signed. A policy therefore requires
/// either one category (hot or cold, together with the guardian) or both. `cold_required` narrows
/// a single-category threshold to the cold category, which is how device management is reserved
/// for the cold key while the hot keys keep every other procedure at the default.
///
/// The policy is encoded into the procedure-policy storage word as
/// `[immediate_threshold, delayed_threshold, cold_required, 0]`. The delayed threshold is reserved
/// for the delayed path and stays 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotColdPolicy {
    immediate_threshold: u32,
    cold_required: bool,
}

impl HotColdPolicy {
    /// Creates a policy requiring `immediate_threshold` signed categories.
    ///
    /// # Errors
    ///
    /// Returns an error if the threshold is zero or exceeds [`NUM_USER_KEY_CATEGORIES`].
    pub fn new(immediate_threshold: u32) -> Result<Self, AccountError> {
        if immediate_threshold == 0 {
            return Err(AccountError::other("procedure policy threshold must be at least 1"));
        }
        if immediate_threshold > NUM_USER_KEY_CATEGORIES {
            return Err(AccountError::other(
                "procedure policy threshold cannot exceed the number of user key categories",
            ));
        }
        Ok(Self {
            immediate_threshold,
            cold_required: false,
        })
    }

    /// Requires the cold category on top of the threshold.
    ///
    /// # Errors
    ///
    /// Returns an error if the threshold is not 1: with both categories required the cold key is
    /// required anyway.
    pub fn with_cold_required(mut self) -> Result<Self, AccountError> {
        if self.immediate_threshold != 1 {
            return Err(AccountError::other(
                "cold required applies only to a single-category threshold",
            ));
        }
        self.cold_required = true;
        Ok(self)
    }

    /// Returns the number of signed categories the procedure requires.
    pub const fn immediate_threshold(&self) -> u32 {
        self.immediate_threshold
    }

    /// Returns whether the cold category is required.
    pub const fn cold_required(&self) -> bool {
        self.cold_required
    }

    /// Returns the storage word of the policy.
    pub fn to_word(self) -> Word {
        Word::from([self.immediate_threshold, 0, self.cold_required as u32, 0])
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn hot_cold_policy_word_encoding_matches_storage_layout() {
        let policy = HotColdPolicy::new(1).unwrap().with_cold_required().unwrap();

        assert_eq!(policy.to_word(), [1u32, 0, 1, 0].into());
        assert_eq!(HotColdPolicy::new(2).unwrap().to_word(), [2u32, 0, 0, 0].into());
    }

    #[test]
    fn hot_cold_policy_rejects_invalid_thresholds() {
        assert!(
            HotColdPolicy::new(0)
                .unwrap_err()
                .to_string()
                .contains("procedure policy threshold must be at least 1")
        );
        assert!(
            HotColdPolicy::new(3)
                .unwrap_err()
                .to_string()
                .contains("cannot exceed the number of user key categories")
        );
    }

    #[test]
    fn hot_cold_policy_rejects_cold_required_with_both_categories() {
        assert!(
            HotColdPolicy::new(2)
                .unwrap()
                .with_cold_required()
                .unwrap_err()
                .to_string()
                .contains("cold required applies only to a single-category threshold")
        );
    }
}
