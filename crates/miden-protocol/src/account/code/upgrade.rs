use alloc::vec::Vec;

use crate::account::AccountCode;
use crate::crypto::utils::{bytes_to_elements_with_padding, padded_elements_to_bytes};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, WORD_SIZE, Word};

// ACCOUNT CODE UPGRADE
// ================================================================================================

/// An upgrade of the [`AccountCode`] of an existing account.
///
/// The kernel only learns the commitment of the new code, so the host must obtain the new code when
/// the kernel initializes the upgrade. It looks for the code, encoded by
/// [`AccountCodeUpgrade::to_elements`], in:
/// 1. the advice map, under [`AccountCodeUpgrade::advice_map_key`], which is how local transactions
///    provide it, e.g. via
///    [`TransactionArgs::with_account_code_upgrade`](crate::transaction::TransactionArgs::with_account_code_upgrade).
/// 2. the attachments of the transaction's input notes, which is how a note carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCodeUpgrade {
    code: AccountCode,
}

impl AccountCodeUpgrade {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Domain separator for [`AccountCodeUpgrade::advice_map_key`].
    ///
    /// It keeps the key distinct from the keys of other advice map entries that hash the same
    /// elements without a domain, such as note storage or note attachment content. See
    /// [`AccountDelta`](crate::account::AccountDelta) for where the value is allocated from.
    const ADVICE_MAP_KEY_DOMAIN: Felt = Felt::new_unchecked(0x02_0002);

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`AccountCodeUpgrade`] that upgrades the account to `code`.
    pub fn new(code: AccountCode) -> Self {
        Self { code }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the advice map key under which the upgrade to the code with `new_code_commitment` is
    /// provided.
    ///
    /// The code commitment itself maps to the procedure roots of the code, so the upgrade is keyed
    /// by a domain-separated hash of the commitment instead.
    pub fn advice_map_key(new_code_commitment: Word) -> Word {
        Hasher::hash_elements_in_domain(
            new_code_commitment.as_elements(),
            Self::ADVICE_MAP_KEY_DOMAIN,
        )
    }

    /// Returns a reference to the new account code.
    pub fn code(&self) -> &AccountCode {
        &self.code
    }

    /// Returns the commitment of the new account code.
    pub fn commitment(&self) -> Word {
        self.code.commitment()
    }

    /// Consumes self and returns the new account code.
    pub fn into_code(self) -> AccountCode {
        self.code
    }

    /// Returns the encoding of the new code as field elements.
    ///
    /// The serialized code is packed into field elements, 7 bytes per element, and padded with
    /// zero elements to a whole number of words, so that it can also be carried as words, e.g. in
    /// a note attachment.
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut elements = bytes_to_elements_with_padding(&self.code.to_bytes());
        elements.resize(elements.len().next_multiple_of(WORD_SIZE), Felt::ZERO);
        elements
    }

    /// Returns the advice map entry that provides this upgrade to a transaction.
    pub fn to_advice_map_entry(&self) -> (Word, Vec<Felt>) {
        (Self::advice_map_key(self.commitment()), self.to_elements())
    }

    /// Decodes an [`AccountCodeUpgrade`] from the elements produced by
    /// [`AccountCodeUpgrade::to_elements`].
    ///
    /// # Errors
    ///
    /// Returns an error if `elements` do not encode valid account code.
    pub fn try_from_elements(elements: &[Felt]) -> Result<Self, DeserializationError> {
        // The last packed element holds a non-zero padding marker, so any trailing zero elements
        // are word padding.
        let packed_len = elements
            .iter()
            .rposition(|element| *element != Felt::ZERO)
            .map_or(0, |last_packed_idx| last_packed_idx + 1);
        let bytes = padded_elements_to_bytes(&elements[..packed_len]).ok_or_else(|| {
            DeserializationError::InvalidValue("encoded account code is not padded".into())
        })?;

        AccountCode::read_from_bytes(&bytes).map(Self::new)
    }
}

impl Serializable for AccountCodeUpgrade {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.code.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.code.get_size_hint()
    }
}

impl Deserializable for AccountCodeUpgrade {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        AccountCode::read_from(source).map(Self::new)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::AccountCodeUpgrade;
    use crate::WORD_SIZE;
    use crate::account::AccountCode;

    #[test]
    fn advice_map_entry_roundtrips() -> anyhow::Result<()> {
        let upgrade = AccountCodeUpgrade::new(AccountCode::mock());

        let (key, elements) = upgrade.to_advice_map_entry();

        assert_eq!(key, AccountCodeUpgrade::advice_map_key(upgrade.commitment()));
        assert_eq!(elements.len() % WORD_SIZE, 0);
        assert_eq!(AccountCodeUpgrade::try_from_elements(&elements)?, upgrade);

        Ok(())
    }
}
