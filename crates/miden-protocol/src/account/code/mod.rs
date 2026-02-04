use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_core::mast::MastForest;
use miden_core::prettier::PrettyPrint;

use super::{
    AccountError,
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Felt,
    Hasher,
    Serializable,
};
use crate::Word;
use crate::account::AccountComponent;
#[cfg(any(feature = "testing", test))]
use crate::account::AccountType;

pub mod procedure;
use procedure::{AccountProcedureRoot, PrintableProcedure};

// ACCOUNT CODE
// ================================================================================================

/// The public interface of an account.
///
/// An account's public interface consists of a set of account procedures, each of which is
/// identified and committed to by a MAST root. They are represented by [`AccountProcedureRoot`].
///
/// The set of procedures has an arbitrary order, i.e. they are not sorted. The only exception is
/// the authentication procedure of the account, which is always at index 0. This procedure is
/// automatically called at the end of a transaction to validate an account's state transition.
///
/// The code commits to the entire account interface by building a sequential hash of all procedure
/// MAST roots. Specifically, each procedure contributes exactly 4 field elements to the sequence of
/// elements to be hashed. Each procedure is represented by its MAST root:
///
/// ```text
/// [PROCEDURE_MAST_ROOT]
/// ```
#[derive(Debug, Clone)]
pub struct AccountCode {
    mast: Arc<MastForest>,
    procedures: Vec<AccountProcedureRoot>,
    commitment: Word,
}

impl AccountCode {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The minimum number of account interface procedures (one auth and at least one non-auth).
    pub const MIN_NUM_PROCEDURES: usize = 2;

    /// The maximum number of account interface procedures.
    pub const MAX_NUM_PROCEDURES: usize = 256;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AccountCode`] from the provided components' libraries.
    ///
    /// For testing use only.
    #[cfg(any(feature = "testing", test))]
    pub fn from_components(
        components: &[AccountComponent],
        account_type: AccountType,
    ) -> Result<Self, AccountError> {
        super::validate_components_support_account_type(components, account_type)?;
        Self::from_components_unchecked(components)
    }

    /// Creates a new [`AccountCode`] from the provided components' libraries.
    ///
    /// # Warning
    ///
    /// This does not check whether the provided components are valid when combined.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of procedures in all merged libraries is 0 or exceeds
    ///   [`AccountCode::MAX_NUM_PROCEDURES`].
    /// - Two or more libraries export a procedure with the same MAST root.
    /// - The first component doesn't contain exactly one authentication procedure.
    /// - Other components contain authentication procedures.
    /// - The number of [`StorageSlot`](crate::account::StorageSlot)s of a component or of all
    ///   components exceeds 255.
    /// - [`MastForest::merge`] fails on all libraries.
    pub(super) fn from_components_unchecked(
        components: &[AccountComponent],
    ) -> Result<Self, AccountError> {
        let (merged_mast_forest, _) =
            MastForest::merge(components.iter().map(|component| component.mast_forest()))
                .map_err(AccountError::AccountComponentMastForestMergeError)?;

        let mut builder = AccountProcedureBuilder::new();
        let mut components_iter = components.iter();

        let first_component =
            components_iter.next().ok_or(AccountError::AccountCodeNoAuthComponent)?;
        builder.add_auth_component(first_component)?;

        for component in components_iter {
            builder.add_component(component)?;
        }

        let procedures = builder.build()?;

        Ok(Self {
            commitment: build_procedure_commitment(&procedures),
            procedures,
            mast: Arc::new(merged_mast_forest),
        })
    }

    /// Returns a new [AccountCode] deserialized from the provided bytes.
    ///
    /// # Errors
    /// Returns an error if account code deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AccountError> {
        Self::read_from_bytes(bytes).map_err(AccountError::AccountCodeDeserializationError)
    }

    /// Returns a new [`AccountCode`] instantiated from the provided [`MastForest`] and a list of
    /// [`AccountProcedureRoot`]s.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The number of procedures is smaller than 2 or greater than 256.
    pub fn from_parts(mast: Arc<MastForest>, procedures: Vec<AccountProcedureRoot>) -> Self {
        assert!(procedures.len() >= Self::MIN_NUM_PROCEDURES, "not enough account procedures");
        assert!(procedures.len() <= Self::MAX_NUM_PROCEDURES, "too many account procedures");

        Self {
            commitment: build_procedure_commitment(&procedures),
            procedures,
            mast,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a commitment to an account's public interface.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// Returns a reference to the [MastForest] backing this account code.
    pub fn mast(&self) -> Arc<MastForest> {
        self.mast.clone()
    }

    /// Returns a reference to the account procedure roots.
    pub fn procedures(&self) -> &[AccountProcedureRoot] {
        &self.procedures
    }

    /// Returns an iterator over the procedure MAST roots of this account code.
    pub fn procedure_roots(&self) -> impl Iterator<Item = Word> + '_ {
        self.procedures().iter().map(|procedure| *procedure.mast_root())
    }

    /// Returns the number of public interface procedures defined in this account code.
    pub fn num_procedures(&self) -> usize {
        self.procedures.len()
    }

    /// Returns true if a procedure with the specified MAST root is defined in this account code.
    pub fn has_procedure(&self, mast_root: Word) -> bool {
        self.procedures.iter().any(|procedure| procedure.mast_root() == &mast_root)
    }

    /// Returns the procedure root at the specified index.
    pub fn get(&self, index: usize) -> Option<&AccountProcedureRoot> {
        self.procedures.get(index)
    }

    /// Converts the procedure root in this [`AccountCode`] into a vector of field elements.
    ///
    /// This is done by first converting each procedure into 4 field elements as follows:
    ///
    /// ```text
    /// [PROCEDURE_MAST_ROOT]
    /// ```
    ///
    /// And then concatenating the resulting elements into a single vector.
    pub fn as_elements(&self) -> Vec<Felt> {
        procedures_as_elements(self.procedures())
    }

    /// Returns an iterator of printable representations for all procedures in this account code.
    ///
    /// # Returns
    ///
    /// An iterator yielding [`PrintableProcedure`] instances for all procedures in this account
    /// code.
    pub fn printable_procedures(&self) -> impl Iterator<Item = PrintableProcedure> {
        self.procedures()
            .iter()
            .filter_map(move |proc_root| self.printable_procedure(proc_root).ok())
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns a printable representation of the procedure with the specified MAST root.
    ///
    /// # Errors
    /// Returns an error if no procedure with the specified root exists in this account code.
    fn printable_procedure(
        &self,
        proc_root: &AccountProcedureRoot,
    ) -> Result<PrintableProcedure, AccountError> {
        let node_id = self
            .mast
            .find_procedure_root(*proc_root.mast_root())
            .expect("procedure root should be present in the mast forest");

        Ok(PrintableProcedure::new(self.mast.clone(), *proc_root, node_id))
    }
}

// EQUALITY
// ================================================================================================

impl PartialEq for AccountCode {
    fn eq(&self, other: &Self) -> bool {
        // TODO: consider checking equality based only on the set of procedures
        self.mast == other.mast && self.procedures == other.procedures
    }
}

impl Ord for AccountCode {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.commitment.cmp(&other.commitment)
    }
}

impl PartialOrd for AccountCode {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for AccountCode {}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountCode {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.mast.write_into(target);
        // since the number of procedures is guaranteed to be between 2 and 256, we can store the
        // number as a single byte - but we do have to subtract 1 to store 256 as 255.
        target.write_u8((self.procedures.len() - 1) as u8);
        target.write_many(self.procedures());
    }

    fn get_size_hint(&self) -> usize {
        // TODO: Replace with proper calculation.
        let mut mast_forest_target = Vec::new();
        self.mast.write_into(&mut mast_forest_target);

        // Size of the serialized procedures length.
        let u8_size = 0u8.get_size_hint();
        let mut size = u8_size + mast_forest_target.len();

        for procedure in self.procedures() {
            size += procedure.get_size_hint();
        }

        size
    }
}

impl Deserializable for AccountCode {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let module = Arc::new(MastForest::read_from(source)?);
        let num_procedures = (source.read_u8()? as usize) + 1;
        let procedures = source.read_many::<AccountProcedureRoot>(num_procedures)?;

        Ok(Self::from_parts(module, procedures))
    }
}

// PRETTY PRINT
// ================================================================================================

impl PrettyPrint for AccountCode {
    fn render(&self) -> miden_core::prettier::Document {
        use miden_core::prettier::*;
        let mut partial = Document::Empty;
        let len_procedures = self.num_procedures();

        for (index, printable_procedure) in self.printable_procedures().enumerate() {
            partial += indent(
                0,
                indent(
                    4,
                    text(format!("proc {}", printable_procedure.mast_root()))
                        + nl()
                        + printable_procedure.render(),
                ) + nl()
                    + const_text("end"),
            );
            if index < len_procedures - 1 {
                partial += nl();
            }
        }
        partial
    }
}

// ACCOUNT PROCEDURE BUILDER
// ================================================================================================

/// A helper type for building the set of account procedures from account components.
///
/// In particular, this ensures that the auth procedure ends up at index 0.
struct AccountProcedureBuilder {
    procedures: Vec<AccountProcedureRoot>,
}

impl AccountProcedureBuilder {
    fn new() -> Self {
        Self { procedures: Vec::new() }
    }

    /// This method must be called before add_component is called.
    fn add_auth_component(&mut self, component: &AccountComponent) -> Result<(), AccountError> {
        let mut auth_proc_count = 0;

        for (proc_root, is_auth) in component.get_procedures() {
            self.add_procedure(proc_root);

            if is_auth {
                let auth_proc_idx = self.procedures.len() - 1;
                self.procedures.swap(0, auth_proc_idx);
                auth_proc_count += 1;
            }
        }

        if auth_proc_count == 0 {
            return Err(AccountError::AccountCodeNoAuthComponent);
        } else if auth_proc_count > 1 {
            return Err(AccountError::AccountComponentMultipleAuthProcedures);
        }

        Ok(())
    }

    fn add_component(&mut self, component: &AccountComponent) -> Result<(), AccountError> {
        for (proc_mast_root, is_auth) in component.get_procedures() {
            if is_auth {
                return Err(AccountError::AccountCodeMultipleAuthComponents);
            }
            self.add_procedure(proc_mast_root);
        }

        Ok(())
    }

    fn add_procedure(&mut self, proc_mast_root: Word) {
        // Allow procedures with the same MAST root from different components, but only add them
        // once.
        let proc_root = AccountProcedureRoot::from_raw(proc_mast_root);
        if !self.procedures.contains(&proc_root) {
            self.procedures.push(proc_root);
        }
    }

    fn build(self) -> Result<Vec<AccountProcedureRoot>, AccountError> {
        if self.procedures.len() < AccountCode::MIN_NUM_PROCEDURES {
            Err(AccountError::AccountCodeNoProcedures)
        } else if self.procedures.len() > AccountCode::MAX_NUM_PROCEDURES {
            Err(AccountError::AccountCodeTooManyProcedures(self.procedures.len()))
        } else {
            Ok(self.procedures)
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes the commitment to the given procedures
pub(crate) fn build_procedure_commitment(procedures: &[AccountProcedureRoot]) -> Word {
    let elements = procedures_as_elements(procedures);
    Hasher::hash_elements(&elements)
}

/// Converts given procedures into field elements
pub(crate) fn procedures_as_elements(procedures: &[AccountProcedureRoot]) -> Vec<Felt> {
    procedures.iter().flat_map(AccountProcedureRoot::as_elements).copied().collect()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use assert_matches::assert_matches;
    use miden_assembly::Assembler;

    use super::{AccountCode, Deserializable, Serializable};
    use crate::account::code::build_procedure_commitment;
    use crate::account::{AccountComponent, AccountType};
    use crate::errors::AccountError;
    use crate::testing::account_code::CODE;
    use crate::testing::noop_auth_component::NoopAuthComponent;

    #[test]
    fn test_serde_account_code() {
        let code = AccountCode::mock();
        let serialized = code.to_bytes();
        let deserialized = AccountCode::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, code)
    }

    #[test]
    fn test_account_code_procedure_root() {
        let code = AccountCode::mock();
        let procedure_root = build_procedure_commitment(code.procedures());
        assert_eq!(procedure_root, code.commitment())
    }

    #[test]
    fn test_account_code_only_auth_component() {
        let err = AccountCode::from_components(
            &[NoopAuthComponent.into()],
            AccountType::RegularAccountUpdatableCode,
        )
        .unwrap_err();

        assert_matches!(err, AccountError::AccountCodeNoProcedures);
    }

    #[test]
    fn test_account_code_no_auth_component() {
        let library = Assembler::default().assemble_library([CODE]).unwrap();
        let component = AccountComponent::new(library, vec![]).unwrap().with_supports_all_types();

        let err =
            AccountCode::from_components(&[component], AccountType::RegularAccountUpdatableCode)
                .unwrap_err();

        assert_matches!(err, AccountError::AccountCodeNoAuthComponent);
    }

    #[test]
    fn test_account_code_multiple_auth_components() {
        let err = AccountCode::from_components(
            &[NoopAuthComponent.into(), NoopAuthComponent.into()],
            AccountType::RegularAccountUpdatableCode,
        )
        .unwrap_err();

        assert_matches!(err, AccountError::AccountCodeMultipleAuthComponents);
    }

    #[test]
    fn test_account_component_multiple_auth_procedures() {
        use miden_assembly::Assembler;

        let code_with_multiple_auth = "
            pub proc auth_basic
                push.1 drop
            end

            pub proc auth_secondary
                push.0 drop
            end
        ";

        let library = Assembler::default().assemble_library([code_with_multiple_auth]).unwrap();
        let component = AccountComponent::new(library, vec![]).unwrap().with_supports_all_types();

        let err =
            AccountCode::from_components(&[component], AccountType::RegularAccountUpdatableCode)
                .unwrap_err();

        assert_matches!(err, AccountError::AccountComponentMultipleAuthProcedures);
    }
}
