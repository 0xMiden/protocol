use alloc::string::String;
use alloc::sync::Arc;

use miden_core::mast::MastForest;
use miden_core::prettier::PrettyPrint;
use miden_processor::{MastNode, MastNodeExt, MastNodeId};
use miden_protocol_macros::WordWrapper;

use super::Felt;
use crate::Word;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// ACCOUNT PROCEDURE ROOT
// ================================================================================================

/// The MAST root of a public procedure in an account's interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, WordWrapper)]
pub struct AccountProcedureRoot(Word);

impl AccountProcedureRoot {
    /// The number of field elements that represent an [`AccountProcedureRoot`] in kernel memory.
    pub const NUM_ELEMENTS: usize = 4;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the procedure's mast root.
    pub fn mast_root(&self) -> &Word {
        &self.0
    }
}

impl From<AccountProcedureRoot> for Word {
    fn from(root: AccountProcedureRoot) -> Self {
        *root.mast_root()
    }
}

impl Serializable for AccountProcedureRoot {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.0);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl Deserializable for AccountProcedureRoot {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mast_root: Word = source.read()?;
        Ok(Self::from_raw(mast_root))
    }
}

// PRINTABLE PROCEDURE
// ================================================================================================

/// A printable representation of a single account procedure.
#[derive(Debug, Clone)]
pub struct PrintableProcedure {
    mast: Arc<MastForest>,
    procedure_root: AccountProcedureRoot,
    entrypoint: MastNodeId,
}

impl PrintableProcedure {
    /// Creates a new PrintableProcedure instance from its components.
    pub(crate) fn new(
        mast: Arc<MastForest>,
        procedure_root: AccountProcedureRoot,
        entrypoint: MastNodeId,
    ) -> Self {
        Self { mast, procedure_root, entrypoint }
    }

    fn entrypoint(&self) -> &MastNode {
        &self.mast[self.entrypoint]
    }

    pub(crate) fn mast_root(&self) -> &Word {
        self.procedure_root.mast_root()
    }
}

impl PrettyPrint for PrintableProcedure {
    fn render(&self) -> miden_core::prettier::Document {
        use miden_core::prettier::*;

        indent(
            4,
            const_text("begin") + nl() + self.entrypoint().to_pretty_print(&self.mast).render(),
        ) + nl()
            + const_text("end")
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use miden_crypto::utils::{Deserializable, Serializable};

    use crate::account::{AccountCode, AccountProcedureRoot};

    #[test]
    fn test_serde_account_procedure() {
        let account_code = AccountCode::mock();

        let serialized = account_code.procedures()[0].to_bytes();
        let deserialized = AccountProcedureRoot::read_from_bytes(&serialized).unwrap();

        assert_eq!(account_code.procedures()[0], deserialized);
    }
}
