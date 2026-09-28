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
use crate::{Felt, Hasher, Word};

// ACCOUNT CODE UPGRADE
// ================================================================================================

/// An upgrade of the [`AccountCode`] of an existing account.
///
/// The kernel only learns the commitment of the new code, so the transaction advice inputs provide
/// the new code under [`AccountCodeUpgrade::advice_map_key`]. The host reads it from there when the
/// kernel initializes the upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCodeUpgrade {
    code: AccountCode,
}

impl AccountCodeUpgrade {
    /// Returns a new [`AccountCodeUpgrade`] that upgrades the account to `code`.
    pub fn new(code: AccountCode) -> Self {
        Self { code }
    }

    /// Returns the advice map key under which the upgrade to the code with `new_code_commitment` is
    /// provided.
    ///
    /// The code commitment itself maps to the procedure roots of the code, so the upgrade is keyed
    /// by the hash of the commitment instead.
    pub fn advice_map_key(new_code_commitment: Word) -> Word {
        Hasher::hash_elements(new_code_commitment.as_elements())
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

    /// Returns the advice map entry that provides this upgrade to a transaction.
    pub fn to_advice_map_entry(&self) -> (Word, Vec<Felt>) {
        (
            Self::advice_map_key(self.commitment()),
            bytes_to_elements_with_padding(&self.code.to_bytes()),
        )
    }

    /// Reads an [`AccountCodeUpgrade`] from the value of the advice map entry that provides it.
    ///
    /// # Errors
    ///
    /// Returns an error if `elements` do not encode valid account code.
    pub fn try_from_elements(elements: &[Felt]) -> Result<Self, DeserializationError> {
        let bytes = padded_elements_to_bytes(elements).ok_or_else(|| {
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
    use crate::account::AccountCode;

    #[test]
    fn advice_map_entry_roundtrips() -> anyhow::Result<()> {
        let upgrade = AccountCodeUpgrade::new(AccountCode::mock());

        let (key, elements) = upgrade.to_advice_map_entry();

        assert_eq!(key, AccountCodeUpgrade::advice_map_key(upgrade.commitment()));
        assert_eq!(AccountCodeUpgrade::try_from_elements(&elements)?, upgrade);

        Ok(())
    }
}
