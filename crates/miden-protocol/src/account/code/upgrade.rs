use crate::Word;
use crate::account::AccountCode;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// ACCOUNT CODE UPGRADE
// ================================================================================================

/// An upgrade of the [`AccountCode`] of an existing account.
///
/// The kernel only learns the commitment of the new code, so the executor must provide the code
/// itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCodeUpgrade {
    code: AccountCode,
}

impl AccountCodeUpgrade {
    /// Returns a new [`AccountCodeUpgrade`] that upgrades the account to `code`.
    pub fn new(code: AccountCode) -> Self {
        Self { code }
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
