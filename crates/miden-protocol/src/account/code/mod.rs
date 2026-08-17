use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::Ordering;

use miden_core::mast::MastForest;
use miden_core::prettier::PrettyPrint;
use miden_mast_package::debug_info::PackageDebugInfo;
use miden_processor::LoadedMastForest;

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
use crate::account::{AccountCodeInterface, AccountComponent, AccountId};
use crate::package::{loaded_mast_forest, package_debug_info};

pub mod procedure;
use procedure::{AccountProcedureRoot, PrintableProcedure};

// ACCOUNT CODE
// ================================================================================================

/// The public interface of an account.
///
/// An account's public interface consists of a set of account procedures, each of which is
/// identified and committed to by a MAST root. They are represented by [`AccountProcedureRoot`].
///
/// The authentication procedure of the account is always at index 0. It is automatically called at
/// the end of a transaction to validate an account's state transition. The remaining procedures are
/// sorted in ascending order, which makes the code commitment independent of the order in which the
/// account's components were provided.
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
    package_debug_info: Option<Arc<PackageDebugInfo>>,
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

    /// Returns a new [`AccountCode`] instantiated from the provided [`MastForest`] and a list of
    /// [`AccountProcedureRoot`]s.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of procedures is smaller than 2 or greater than 256.
    /// - The procedures after the authentication procedure at index 0 are not sorted in ascending
    ///   order.
    /// - The procedure roots are not unique.
    /// - Any provided procedure root is not in the provided [`MastForest`].
    pub fn from_parts(
        mast: Arc<MastForest>,
        procedures: Vec<AccountProcedureRoot>,
    ) -> Result<Self, AccountError> {
        if procedures.len() < Self::MIN_NUM_PROCEDURES {
            return Err(AccountError::AccountCodeNoProcedures);
        }
        if procedures.len() > Self::MAX_NUM_PROCEDURES {
            return Err(AccountError::AccountCodeTooManyProcedures(procedures.len()));
        }

        // The authentication procedure at index 0 is exempt from the ordering invariant, so the
        // remaining procedures are checked to be strictly increasing, which also makes them unique.
        // Each of them is also compared against the authentication procedure, which must not appear
        // a second time.
        let (auth_proc, other_procs) = procedures
            .split_first()
            .expect("account code should contain at least two procedures");

        let mut previous_proc: Option<&AccountProcedureRoot> = None;
        for procedure in other_procs {
            if procedure == auth_proc {
                return Err(AccountError::AccountCodeDuplicateProcedureRoot(*procedure));
            }

            if let Some(previous_proc) = previous_proc {
                match previous_proc.cmp(procedure) {
                    Ordering::Less => {},
                    Ordering::Equal => {
                        return Err(AccountError::AccountCodeDuplicateProcedureRoot(*procedure));
                    },
                    Ordering::Greater => return Err(AccountError::AccountCodeProceduresUnsorted),
                }
            }

            previous_proc = Some(procedure);
        }

        // make sure that all account procedures are in the MAST forest
        for procedure in procedures.iter() {
            if mast.find_procedure_root(procedure.as_word()).is_none() {
                return Err(AccountError::AccountCodeProcedureNotInMastForest(*procedure));
            }
        }

        Ok(Self {
            commitment: build_procedure_commitment(&procedures),
            procedures,
            mast,
            package_debug_info: None,
        })
    }

    /// Creates a new [`AccountCode`] from the provided components' packages.
    ///
    /// For testing use only.
    #[cfg(any(feature = "testing", test))]
    pub fn from_components(components: &[AccountComponent]) -> Result<Self, AccountError> {
        Self::from_components_unchecked(components)
    }

    /// Creates a new [`AccountCode`] from the provided components' packages.
    ///
    /// # Warning
    ///
    /// This does not check whether the provided components are valid when combined.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of procedures in all merged packages is 0 or exceeds
    ///   [`AccountCode::MAX_NUM_PROCEDURES`].
    /// - The components don't contain exactly one authentication component with exactly one
    ///   authentication procedure.
    /// - The number of [`StorageSlot`](crate::account::StorageSlot)s of a component or of all
    ///   components exceeds 255.
    /// - [`MastForest::merge`] fails on all packages.
    pub(super) fn from_components_unchecked(
        components: &[AccountComponent],
    ) -> Result<Self, AccountError> {
        let (merged_mast_forest, root_map) =
            MastForest::merge(components.iter().map(|component| component.mast_forest()))
                .map_err(AccountError::AccountComponentMastForestMergeError)?;
        let package_debug_info = merge_component_debug_info(components, &root_map)?;

        let mut builder = AccountProcedureBuilder::new();
        let mut num_auth_components = 0;

        for component in components {
            if component.is_auth_component() {
                num_auth_components += 1;
                builder.add_auth_component(component)?
            } else {
                builder.add_component(component)?;
            }
        }

        if num_auth_components == 0 {
            return Err(AccountError::AccountCodeNoAuthComponent);
        } else if num_auth_components > 1 {
            return Err(AccountError::AccountCodeMultipleAuthComponents);
        }

        let procedures = builder.build()?;

        Self::from_parts(Arc::new(merged_mast_forest), procedures).map(|mut code| {
            code.package_debug_info = package_debug_info;
            code
        })
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

    /// Returns the MAST forest and package-owned debug information backing this account code.
    pub fn loaded_mast_forest(&self) -> LoadedMastForest {
        loaded_mast_forest(self.mast.clone(), self.package_debug_info.clone())
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
    pub fn to_elements(&self) -> Vec<Felt> {
        procedures_as_elements(self.procedures())
    }

    /// Returns the public interface of this account code: the given account ID and the set of
    /// procedure roots exposed by this code.
    pub fn interface(&self, account_id: AccountId) -> AccountCodeInterface {
        AccountCodeInterface::new(account_id, self.procedures.iter().copied().collect())
            .expect("account code procedure count is enforced by AccountCode invariants")
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
        let mast = Arc::new(MastForest::read_from(source)?);
        let num_procedures = (source.read_u8()? as usize) + 1;

        let procedures = source
            .read_many_iter(num_procedures)?
            .collect::<Result<Vec<AccountProcedureRoot>, _>>()?;

        Self::from_parts(mast, procedures)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
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
/// In particular, this ensures that the auth procedure ends up at index 0 and that the remaining
/// procedures are sorted.
struct AccountProcedureBuilder {
    procedures: Vec<AccountProcedureRoot>,
}

impl AccountProcedureBuilder {
    fn new() -> Self {
        Self { procedures: Vec::new() }
    }

    fn add_auth_component(&mut self, component: &AccountComponent) -> Result<(), AccountError> {
        let mut auth_proc_count = 0;

        for (proc_root, is_auth) in component.procedures() {
            let proc_idx = self.add_procedure(proc_root);

            if is_auth {
                self.procedures.swap(0, proc_idx);
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
        for (proc_root, is_auth) in component.procedures() {
            if is_auth {
                return Err(AccountError::AccountCodeMultipleAuthComponents);
            }
            self.add_procedure(proc_root);
        }

        Ok(())
    }

    /// Adds the procedure and returns its index, which is the index of the existing entry if the
    /// procedure was added before.
    ///
    /// Different components may export procedures with the same MAST root, but the set of
    /// procedures must not contain duplicates.
    fn add_procedure(&mut self, proc_root: AccountProcedureRoot) -> usize {
        match self.procedures.iter().position(|existing_root| existing_root == &proc_root) {
            Some(existing_idx) => existing_idx,
            None => {
                self.procedures.push(proc_root);
                self.procedures.len() - 1
            },
        }
    }

    fn build(mut self) -> Result<Vec<AccountProcedureRoot>, AccountError> {
        // Sorting makes the account code commitment independent of the order in which components
        // were provided. The auth procedure at index 0 is excluded from the sort so it keeps the
        // position the transaction kernel expects.
        self.procedures[1..].sort_unstable();

        Ok(self.procedures)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes the commitment to the given procedures
fn build_procedure_commitment(procedures: &[AccountProcedureRoot]) -> Word {
    let elements = procedures_as_elements(procedures);
    Hasher::hash_elements(&elements)
}

fn merge_component_debug_info(
    components: &[AccountComponent],
    root_map: &miden_core::mast::MastForestRootMap,
) -> Result<Option<Arc<PackageDebugInfo>>, AccountError> {
    let component_debug_info = components
        .iter()
        .enumerate()
        .filter_map(|(idx, component)| {
            package_debug_info(component.component_code().as_package()).map(|debug| (idx, debug))
        })
        .collect::<Vec<_>>();

    if component_debug_info.is_empty() {
        return Ok(None);
    }

    let debug_info = PackageDebugInfo::merge_source_debug(
        component_debug_info.iter().map(|(idx, debug)| (*idx, debug.as_ref())),
        root_map,
    )
    .map_err(|err| {
        AccountError::other_with_source("failed to merge account component debug info", err)
    })?;

    Ok(Some(Arc::new(debug_info)))
}

/// Converts given procedures into field elements
fn procedures_as_elements(procedures: &[AccountProcedureRoot]) -> Vec<Felt> {
    procedures.iter().flat_map(AccountProcedureRoot::as_elements).copied().collect()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use anyhow::Context;
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::{AccountCode, ByteWriter, Deserializable, DeserializationError, Serializable};
    use crate::Word;
    use crate::account::code::build_procedure_commitment;
    use crate::account::component::AccountComponentMetadata;
    use crate::account::{AccountComponent, AccountProcedureRoot};
    use crate::errors::AccountError;
    use crate::testing::account_code::CODE;
    use crate::testing::assembler::assemble_test_package;
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
        let err = AccountCode::from_components(&[NoopAuthComponent.into()]).unwrap_err();

        assert_matches!(err, AccountError::AccountCodeNoProcedures);
    }

    #[test]
    fn test_account_code_no_auth_component() {
        let package =
            assemble_test_package("test-account-code-no-auth", "test::account_code", CODE);
        let metadata = AccountComponentMetadata::new("test::no_auth");
        let component = AccountComponent::new(package, vec![], metadata).unwrap();

        let err = AccountCode::from_components(&[component]).unwrap_err();

        assert_matches!(err, AccountError::AccountCodeNoAuthComponent);
    }

    #[test]
    fn test_account_code_preserves_component_debug_info() {
        let package =
            assemble_test_package("test-account-code-debug-info", "test::account_code", CODE);
        let metadata = AccountComponentMetadata::new("test::debug_info");
        let component = AccountComponent::new(package, vec![], metadata).unwrap();

        let code = AccountCode::from_components(&[NoopAuthComponent.into(), component]).unwrap();

        assert!(code.loaded_mast_forest().package_debug_info().unwrap().is_some());
    }

    #[test]
    fn test_account_code_multiple_auth_components() {
        let err =
            AccountCode::from_components(&[NoopAuthComponent.into(), NoopAuthComponent.into()])
                .unwrap_err();

        assert_matches!(err, AccountError::AccountCodeMultipleAuthComponents);
    }

    #[test]
    fn test_account_component_multiple_auth_procedures() {
        let code_with_multiple_auth = "
            @auth_script
            pub proc auth_basic
                push.1 drop
            end

            @auth_script
            pub proc auth_secondary
                push.0 drop
            end
        ";

        let package = assemble_test_package(
            "test-account-code-multiple-auth",
            "test::account_code_multiple_auth",
            code_with_multiple_auth,
        );
        let metadata = AccountComponentMetadata::new("test::multiple_auth");
        let component = AccountComponent::new(package, vec![], metadata).unwrap();

        let err = AccountCode::from_components(&[component]).unwrap_err();

        assert_matches!(err, AccountError::AccountComponentMultipleAuthProcedures);
    }

    /// Tests that the auth procedure is at index 0 even if its MAST root was already added by a
    /// previously processed non-auth component, no matter at which index that component sits.
    #[rstest]
    #[case::duplicate_first(true)]
    #[case::duplicate_second(false)]
    fn test_account_code_auth_procedure_at_index_zero_on_duplicate_root(
        #[case] duplicate_first: bool,
    ) -> anyhow::Result<()> {
        // Same body as the auth procedure of NoopAuthComponent, so it has the same MAST root.
        let duplicate_of_auth = "
            @account_procedure
            pub proc noop
                push.0 drop
            end
        ";
        let duplicate_component = AccountComponent::new(
            assemble_test_package(
                "test-account-code-duplicate-auth-root",
                "test::duplicate_auth_root",
                duplicate_of_auth,
            ),
            vec![],
            AccountComponentMetadata::new("test::duplicate_auth_root"),
        )?;

        let other_component = AccountComponent::new(
            assemble_test_package("test-account-code-other", "test::other", CODE),
            vec![],
            AccountComponentMetadata::new("test::other"),
        )?;

        let auth_component = AccountComponent::from(NoopAuthComponent);
        let auth_proc_root = auth_component
            .procedures()
            .find_map(|(proc_root, is_auth)| is_auth.then_some(proc_root))
            .context("auth component should export an auth procedure")?;

        // Without this the test would not cover the deduplication path it guards.
        let duplicate_proc_root = duplicate_component
            .procedures()
            .next()
            .context("duplicate component should export a procedure")?
            .0;
        assert_eq!(duplicate_proc_root, auth_proc_root);

        let components = if duplicate_first {
            [duplicate_component, other_component, auth_component]
        } else {
            [other_component, duplicate_component, auth_component]
        };

        let code = AccountCode::from_components(&components)?;

        assert_eq!(code.procedures()[0], auth_proc_root);
        // The procedure displaced by moving the auth procedure to index 0 must be retained.
        assert_eq!(code.num_procedures(), 3);

        Ok(())
    }

    #[test]
    fn test_account_code_from_parts_rejects_duplicate_roots() {
        let code = AccountCode::mock();
        let procedures = code.procedures();

        // repeat the non-auth procedure root at a second index
        let duplicated = vec![procedures[0], procedures[1], procedures[1]];
        let err = AccountCode::from_parts(code.mast(), duplicated).unwrap_err();

        assert_matches!(
            err,
            AccountError::AccountCodeDuplicateProcedureRoot(root) if root == procedures[1]
        );
    }

    #[test]
    fn test_account_code_from_parts_rejects_missing_root() {
        let code = AccountCode::mock();
        let procedures = code.procedures();
        let non_existent_root = AccountProcedureRoot::from_raw(Word::from([1, 2, 3, 4u32]));

        // provide a procedure root that is not in the mast forest
        let procedures = vec![procedures[0], non_existent_root];
        let err = AccountCode::from_parts(code.mast(), procedures).unwrap_err();

        assert_matches!(
            err,
            AccountError::AccountCodeProcedureNotInMastForest(root) if root == non_existent_root
        );
    }

    #[test]
    fn test_account_code_deserialization_rejects_duplicate_roots() {
        let code = AccountCode::mock();
        let procedures = code.procedures();

        let mut bytes = Vec::new();
        code.mast().write_into(&mut bytes);
        bytes.write_u8(3 - 1); // num_procedures is serialized as count - 1
        procedures[0].write_into(&mut bytes);
        procedures[1].write_into(&mut bytes);
        procedures[1].write_into(&mut bytes);

        let err = AccountCode::read_from_bytes(&bytes).unwrap_err();

        assert_matches!(
            err,
            DeserializationError::InvalidValue(msg) if msg.contains("duplicate procedure with root")
        );
    }

    #[test]
    fn account_code_procedures_are_sorted_after_the_auth_procedure() {
        let code = AccountCode::mock();

        assert!(code.procedures()[1..].is_sorted());
    }

    #[test]
    fn account_code_commitment_is_independent_of_component_order() -> anyhow::Result<()> {
        let first = mock_component("test-account-code-first", "test::first", 1);
        let second = mock_component("test-account-code-second", "test::second", 2);

        let mut components = vec![NoopAuthComponent.into(), first.clone(), second.clone()];

        let code = AccountCode::from_components(&components)?;
        components.reverse();
        let reversed_code = AccountCode::from_components(&components)?;

        assert_eq!(code.commitment(), reversed_code.commitment());
        assert_eq!(
            code.procedures()[0],
            reversed_code.procedures()[0],
            "the auth procedure should stay at index 0"
        );

        Ok(())
    }

    #[test]
    fn account_code_from_parts_rejects_unsorted_procedures() -> anyhow::Result<()> {
        let code = AccountCode::mock();
        let procedures = code.procedures();

        // the procedures of the mock code are sorted, so swapping two of them breaks the invariant
        let unsorted = vec![procedures[0], procedures[2], procedures[1]];
        let err = AccountCode::from_parts(code.mast(), unsorted).unwrap_err();

        assert_matches!(err, AccountError::AccountCodeProceduresUnsorted);

        Ok(())
    }

    #[test]
    fn account_code_from_parts_rejects_duplicated_auth_procedure() -> anyhow::Result<()> {
        let code = AccountCode::mock();
        let procedures = code.procedures();

        // the auth procedure must not reappear among the sorted procedures
        let mut duplicated_auth = vec![procedures[0], procedures[1], procedures[0]];
        duplicated_auth[1..].sort_unstable();
        let err = AccountCode::from_parts(code.mast(), duplicated_auth).unwrap_err();

        assert_matches!(
            err,
            AccountError::AccountCodeDuplicateProcedureRoot(root) if root == procedures[0]
        );

        Ok(())
    }

    /// Creates a component exporting a single account procedure whose MAST root is made unique by
    /// the provided value.
    fn mock_component(
        package_name: &str,
        module_path: &str,
        unique_value: u32,
    ) -> AccountComponent {
        let code = format!(
            "
            @account_procedure
            pub proc account_procedure
                push.{unique_value} drop
            end
            "
        );
        let package = assemble_test_package(package_name, module_path, &code);
        let metadata = AccountComponentMetadata::new(module_path);

        AccountComponent::new(package, vec![], metadata).expect("component should be valid")
    }
}
