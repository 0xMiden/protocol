use miden_protocol::account::{AccountStorage, StorageSlot, StorageSlotContent, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

// CONSTANTS
// ================================================================================================

static SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::network_account::sponsor_at_most_collected_fees")
        .expect("storage slot name should be valid")
});

// SPONSORSHIP POLICY
// ================================================================================================

/// How much of its own funds a network account is willing to spend sponsoring the network notes it
/// creates.
///
/// Paying the transaction fee also creates a `FEE_SPONSORSHIP` note for every network output note
/// of the transaction, funded from the account's vault, so that the target account is prepaid for
/// consuming it. Independently, the account collects the fees prepaid by the `FEE_SPONSORSHIP`
/// notes among its own input notes. This policy decides whether the former is bounded by the
/// latter.
///
/// It is fixed at deployment: the auth procedure reads it from the transaction's initial storage
/// state and there is no account procedure to change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
#[non_exhaustive]
pub enum SponsorshipPolicy {
    /// Sponsorships must not exceed the fees collected in the same transaction, so the account
    /// never subsidises a downstream consumer out of its own funds.
    ///
    /// A transaction that sponsors anything additionally requires the account's configured fee
    /// asset to be the chain's native fee asset, since collected fees are denominated in the
    /// former while sponsorship notes are funded in the latter and the two amounts would
    /// otherwise not be comparable. An account that never creates network notes is unaffected
    /// by that requirement.
    #[default]
    AtMostCollectedFees = Self::AT_MOST_COLLECTED_FEES,

    /// Sponsorships are funded from the account's vault without bound, so the account pays for
    /// outgoing notes that the fees it collected do not cover.
    Unlimited = Self::UNLIMITED,
}

impl SponsorshipPolicy {
    /// The discriminant of [`Unlimited`](Self::Unlimited) in the policy's storage encoding.
    const UNLIMITED: u8 = 0;
    /// The discriminant of [`AtMostCollectedFees`](Self::AtMostCollectedFees).
    const AT_MOST_COLLECTED_FEES: u8 = 1;

    /// Returns the [`StorageSlotName`] of the standardized sponsorship policy slot.
    pub fn slot_name() -> &'static StorageSlotName {
        &SLOT_NAME
    }

    /// Returns the [`StorageSlot`] encoding this policy, suitable for inclusion in an
    /// [`AccountComponent`](miden_protocol::account::AccountComponent)'s storage layout.
    pub fn into_storage_slot(self) -> StorageSlot {
        StorageSlot::with_value(Self::slot_name().clone(), self.to_word())
    }

    /// Returns the storage encoding of this policy.
    ///
    /// The policy is encoded as `[discriminant, 0, 0, 0]`.
    pub fn to_word(self) -> Word {
        Word::new([Felt::from(self as u8), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl TryFrom<Word> for SponsorshipPolicy {
    type Error = SponsorshipPolicyError;

    /// Decodes a policy from its storage encoding, see [`SponsorshipPolicy::to_word`].
    ///
    /// # Errors
    /// Returns an error if the word's first element is not a known discriminant or any of its
    /// reserved elements is non-zero.
    fn try_from(word: Word) -> Result<Self, Self::Error> {
        if word[1..4] != [Felt::ZERO; 3] {
            return Err(SponsorshipPolicyError::InvalidEncoding(word));
        }

        match u8::try_from(word[0].as_canonical_u64()).ok() {
            Some(Self::AT_MOST_COLLECTED_FEES) => Ok(Self::AtMostCollectedFees),
            Some(Self::UNLIMITED) => Ok(Self::Unlimited),
            _ => Err(SponsorshipPolicyError::InvalidEncoding(word)),
        }
    }
}

impl TryFrom<&AccountStorage> for SponsorshipPolicy {
    type Error = SponsorshipPolicyError;

    /// Reads the sponsorship policy from account storage.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The standardized policy slot is not present in storage.
    /// - The slot is present but is not a [`StorageSlotContent::Value`].
    /// - The slot's value is not a valid policy encoding.
    fn try_from(storage: &AccountStorage) -> Result<Self, Self::Error> {
        let slot = storage.get(Self::slot_name()).ok_or(SponsorshipPolicyError::SlotNotFound)?;

        let StorageSlotContent::Value(value) = slot.content() else {
            return Err(SponsorshipPolicyError::UnexpectedSlotType);
        };

        Self::try_from(*value)
    }
}

// SPONSORSHIP POLICY ERROR
// ================================================================================================

/// Errors that can occur when reading a [`SponsorshipPolicy`] from storage.
#[derive(Debug, thiserror::Error)]
pub enum SponsorshipPolicyError {
    #[error(
        "network account sponsorship policy storage slot {} not found in account storage",
        SponsorshipPolicy::slot_name()
    )]
    SlotNotFound,
    #[error(
        "network account sponsorship policy storage slot {} must be a value",
        SponsorshipPolicy::slot_name()
    )]
    UnexpectedSlotType,
    #[error("word {0} is not a valid network account sponsorship policy encoding")]
    InvalidEncoding(Word),
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use assert_matches::assert_matches;

    use super::*;

    #[rstest::rstest]
    #[case(SponsorshipPolicy::AtMostCollectedFees, Word::from([1u32, 0, 0, 0]))]
    #[case(SponsorshipPolicy::Unlimited, Word::empty())]
    fn policy_round_trips_through_its_storage_encoding(
        #[case] policy: SponsorshipPolicy,
        #[case] expected_word: Word,
    ) -> anyhow::Result<()> {
        assert_eq!(policy.to_word(), expected_word);
        assert_eq!(
            SponsorshipPolicy::try_from(policy.to_word()).context("decoding the policy failed")?,
            policy
        );

        Ok(())
    }

    #[rstest::rstest]
    #[case::unknown_discriminant(Word::from([2u32, 0, 0, 0]))]
    #[case::non_zero_reserved_element_1(Word::from([1u32, 5, 0, 0]))]
    #[case::non_zero_reserved_element_2(Word::from([1u32, 0, 5, 0]))]
    #[case::non_zero_reserved_element_3(Word::from([1u32, 0, 0, 5]))]
    fn decoding_an_invalid_encoding_fails(#[case] word: Word) {
        assert_matches!(
            SponsorshipPolicy::try_from(word),
            Err(SponsorshipPolicyError::InvalidEncoding(invalid)) if invalid == word
        );
    }
}
