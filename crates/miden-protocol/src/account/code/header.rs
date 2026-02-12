use alloc::vec::Vec;

use miden_core::{
    Felt,
    utils::{Deserializable, Serializable},
};
use miden_processor::Digest;

use super::{AccountCode, build_procedure_commitment, procedures_as_elements};
use crate::account::AccountProcedureInfo;

/// A lightweight representation of account code that contains only procedure metadata without the
/// actual program instructions.
///
/// Account code header consists of the following components:
/// - Code commitment, which uniquely identifies the account code.
/// - Procedure information, which contains metadata about each procedure in the account code,
///   including MAST roots, storage access permissions, and other relevant attributes.
///
/// The header is used to provide verifiable information about account code structure and
/// storage access patterns without the need to include the full program instructions.
/// This is particularly useful for verification purposes and when the actual code execution
/// is not required.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountCodeHeader {
    commitment: Digest,
    procedures: Vec<AccountProcedureInfo>,
}

impl AccountCodeHeader {
    /// Returns a new instance of account code header with the specified procedures.
    ///
    /// The code commitment is computed during instantiation based on the provided procedures.
    pub fn new(procedures: Vec<AccountProcedureInfo>) -> Self {
        let commitment = build_procedure_commitment(&procedures);
        AccountCodeHeader { procedures, commitment }
    }

    /// Returns the commitment of this account code header.
    pub fn commitment(&self) -> Digest {
        self.commitment
    }

    /// Returns a reference to the procedure information stored in this account code header.
    pub fn procedures(&self) -> &[AccountProcedureInfo] {
        &self.procedures
    }

    /// Converts procedure information in this [AccountCodeHeader] into a vector of field elements.
    ///
    /// This is done by first converting each procedure into 8 field elements as follows:
    /// ```text
    /// [PROCEDURE_MAST_ROOT, storage_offset, storage_size, 0, 0]
    /// ```
    /// And then concatenating the resulting elements into a single vector.
    pub fn as_elements(&self) -> Vec<Felt> {
        procedures_as_elements(&self.procedures)
    }
}

impl From<AccountCode> for AccountCodeHeader {
    fn from(value: AccountCode) -> Self {
        AccountCodeHeader::new(value.procedures)
    }
}

impl Serializable for AccountCodeHeader {
    fn write_into<W: miden_core::utils::ByteWriter>(&self, target: &mut W) {
        target.write(&self.procedures);
    }
}

impl Deserializable for AccountCodeHeader {
    fn read_from<R: miden_core::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_processor::DeserializationError> {
        let procedures: Vec<AccountProcedureInfo> = source.read()?;
        let commitment = build_procedure_commitment(&procedures);

        Ok(AccountCodeHeader { procedures, commitment })
    }
}
