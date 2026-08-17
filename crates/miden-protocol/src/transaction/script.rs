use alloc::sync::Arc;
use core::fmt::Display;

use miden_crypto_derive::WordWrapper;
use miden_mast_package::Package;
use miden_processor::LoadedMastForest;

use crate::Word;
use crate::assembly::Path;
use crate::assembly::mast::{MastForest, MastNodeId};
use crate::script::{MastForestScript, MastForestScriptError};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::vm::AdviceMap;

// TRANSACTION SCRIPT ROOT
// ================================================================================================

/// The MAST root of a [`TransactionScript`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, WordWrapper)]
pub struct TransactionScriptRoot(Word);

impl From<TransactionScriptRoot> for Word {
    fn from(root: TransactionScriptRoot) -> Self {
        root.0
    }
}

impl Display for TransactionScriptRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Serializable for TransactionScriptRoot {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.0);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl Deserializable for TransactionScriptRoot {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let word: Word = source.read()?;
        Ok(Self::from_raw(word))
    }
}

// TRANSACTION SCRIPT
// ================================================================================================

/// The attribute name used to mark the entrypoint procedure in a transaction script package.
pub const TRANSACTION_SCRIPT_ATTRIBUTE: &str = "transaction_script";

/// Transaction script.
///
/// A transaction script is a program that is executed in a transaction after all input notes
/// have been executed.
///
/// The [TransactionScript] object is composed of an executable program defined by a [MastForest]
/// and an associated entrypoint.
#[derive(Clone, Debug)]
pub struct TransactionScript(MastForestScript);

impl TransactionScript {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [TransactionScript] instantiated from the provided MAST forest and entrypoint.
    ///
    /// # Errors
    /// Returns an error if the specified entrypoint is not in the provided MAST forest.
    pub fn from_parts(
        mast: Arc<MastForest>,
        entrypoint: MastNodeId,
    ) -> Result<Self, MastForestScriptError> {
        MastForestScript::from_parts(mast, entrypoint).map(Self)
    }

    /// Creates a [TransactionScript] from a [`Package`].
    ///
    /// The package must contain exactly one procedure with the `@transaction_script` attribute,
    /// which will be used as the entrypoint.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The package is an executable (i.e., its target type is
    ///   [`TargetType::Executable`](miden_mast_package::TargetType::Executable)).
    /// - The package does not contain a procedure with the `@transaction_script` attribute.
    /// - The package contains multiple procedures with the `@transaction_script` attribute.
    pub fn from_package(package: &Package) -> Result<Self, MastForestScriptError> {
        MastForestScript::from_package(package, TRANSACTION_SCRIPT_ATTRIBUTE).map(Self)
    }

    /// Returns a new [TransactionScript] containing only a reference to a procedure in the
    /// provided package.
    ///
    /// This method is useful when a package contains multiple transaction scripts and you need
    /// to extract a specific one by its fully qualified path (e.g.,
    /// `::miden::standards::tx_scripts::send_notes::main`).
    ///
    /// The procedure at the specified path must have the `@transaction_script` attribute.
    ///
    /// Note: This method creates a minimal [MastForest] containing only an external node
    /// referencing the procedure's digest, rather than copying the entire package. The actual
    /// procedure code will be resolved at runtime via the `MastForestStore`.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The package does not contain a procedure at the specified path.
    /// - The procedure at the specified path does not have the `@transaction_script` attribute.
    pub fn from_package_reference(
        package: &Package,
        path: &Path,
    ) -> Result<Self, MastForestScriptError> {
        MastForestScript::from_package_reference(package, path, TRANSACTION_SCRIPT_ATTRIBUTE)
            .map(Self)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the [MastForest] backing this transaction script.
    pub fn mast(&self) -> Arc<MastForest> {
        self.0.mast()
    }

    /// Returns the MAST forest and package-owned debug information backing this transaction script.
    pub fn loaded_mast_forest(&self) -> LoadedMastForest {
        self.0.loaded_mast_forest()
    }

    /// Returns the commitment of this transaction script (i.e., the script's MAST root).
    pub fn root(&self) -> TransactionScriptRoot {
        TransactionScriptRoot::from_raw(self.0.digest())
    }

    /// Returns a new [TransactionScript] with the provided advice map entries merged into the
    /// underlying [MastForest].
    ///
    /// This allows adding advice map entries to an already-compiled transaction script,
    /// which is useful when the entries are determined after script compilation.
    pub fn with_advice_map(self, advice_map: AdviceMap) -> Self {
        Self(self.0.with_advice_map(advice_map))
    }
}

impl PartialEq for TransactionScript {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for TransactionScript {}

// SERIALIZATION
// ================================================================================================

impl Serializable for TransactionScript {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl Deserializable for TransactionScript {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(MastForestScript::read_from(source)?))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::advice::AdviceMap;

    use super::TransactionScript;

    /// A minimal transaction script source with a single `@transaction_script` procedure.
    const TX_SCRIPT_SOURCE: &str = "
        @transaction_script
        pub proc main
            push.1 drop
        end
    ";

    #[test]
    fn test_transaction_script_preserves_package_debug_info() {
        use crate::testing::assembler::assemble_test_package;

        let package = assemble_test_package(
            "test-tx-script-debug-info",
            "test::tx_script_debug_info",
            TX_SCRIPT_SOURCE,
        );
        let script = TransactionScript::from_package(&package).unwrap();

        assert!(script.loaded_mast_forest().package_debug_info().unwrap().is_some());
    }

    #[test]
    fn test_transaction_script_with_advice_map() {
        use miden_core::{Felt, Word};

        use crate::testing::assembler::assemble_test_package;

        let package = assemble_test_package(
            "test-tx-script-with-advice-map",
            "test::tx_script_with_advice_map",
            TX_SCRIPT_SOURCE,
        );
        let script = TransactionScript::from_package(&package).unwrap();
        assert!(script.mast().advice_map().is_empty());

        // Empty advice map should be a no-op
        let original_root = script.root();
        let script = script.with_advice_map(AdviceMap::default());
        assert_eq!(original_root, script.root());

        // Non-empty advice map should add entries
        let key = Word::from([1u32, 2, 3, 4]);
        let value = vec![Felt::new_unchecked(42), Felt::new_unchecked(43)];
        let mut advice_map = AdviceMap::default();
        advice_map.insert(key, value.clone());

        let script = script.with_advice_map(advice_map);

        let mast = script.mast();
        let stored = mast.advice_map().get(&key).expect("entry should be present");
        assert_eq!(stored.as_ref(), value.as_slice());
    }

    #[test]
    fn test_transaction_script_from_library_package() {
        use assert_matches::assert_matches;

        use crate::script::MastForestScriptError;
        use crate::testing::assembler::assemble_test_package;
        use crate::utils::serde::{Deserializable, Serializable};

        let package = assemble_test_package("test-tx-script", "test::tx_script", TX_SCRIPT_SOURCE);

        let script = TransactionScript::from_package(&package).unwrap();

        // the script must round-trip through serialization unchanged
        let bytes = script.to_bytes();
        let decoded = TransactionScript::read_from_bytes(&bytes).unwrap();
        assert_eq!(script, decoded);

        // a package without the attribute is rejected
        let no_attr = assemble_test_package(
            "test-tx-script-no-attr",
            "test::tx_script_no_attr",
            "pub proc main push.1 drop end",
        );
        assert_matches!(
            TransactionScript::from_package(&no_attr),
            Err(MastForestScriptError::NoProcedureWithAttribute(_))
        );

        // a package with multiple tagged procedures is rejected
        let multiple = assemble_test_package(
            "test-tx-script-multiple",
            "test::tx_script_multiple",
            "@transaction_script pub proc main_a push.1 drop end
             @transaction_script pub proc main_b push.2 drop end",
        );
        assert_matches!(
            TransactionScript::from_package(&multiple),
            Err(MastForestScriptError::MultipleProceduresWithAttribute(_))
        );
    }

    #[test]
    fn test_transaction_script_from_executable_package() {
        use assert_matches::assert_matches;

        use crate::assembly::Assembler;
        use crate::script::MastForestScriptError;

        // an executable package is rejected: transaction scripts are identified only by the
        // @transaction_script attribute
        let package = Assembler::default()
            .assemble_program("test-tx-script-executable", "begin nop end")
            .unwrap();
        assert_matches!(
            TransactionScript::from_package(&package),
            Err(MastForestScriptError::ExecutablePackage)
        );
    }

    #[test]
    fn test_transaction_script_from_package_reference() {
        use alloc::string::ToString;

        use assert_matches::assert_matches;

        use crate::Word;
        use crate::assembly::Path;
        use crate::script::MastForestScriptError;
        use crate::testing::assembler::assemble_test_package;

        let source = "
            @transaction_script
            pub proc main_a
                push.1 drop
            end

            @transaction_script
            pub proc main_b
                push.2 drop
            end

            pub proc helper
                push.3 drop
            end
        ";
        let package =
            assemble_test_package("test-tx-script-reference", "test::tx_script_reference", source);

        // each tagged procedure can be extracted selectively, and the resulting script's root
        // matches the digest of the referenced procedure
        for proc_name in ["main_a", "main_b"] {
            let export = package
                .manifest
                .exports()
                .find(|e| e.path().as_ref().to_string().ends_with(proc_name))
                .unwrap();
            let digest = export.as_procedure().unwrap().digest;

            let script =
                TransactionScript::from_package_reference(&package, export.path().as_ref())
                    .unwrap();
            assert_eq!(Word::from(script.root()), digest);
        }

        // an unknown path is rejected
        assert_matches!(
            TransactionScript::from_package_reference(&package, Path::new("::foo::bar::main")),
            Err(MastForestScriptError::ProcedureNotFound(_))
        );

        // a procedure without the attribute is rejected
        let helper = package
            .manifest
            .exports()
            .find(|e| e.path().as_ref().to_string().ends_with("helper"))
            .unwrap();
        assert_matches!(
            TransactionScript::from_package_reference(&package, helper.path().as_ref()),
            Err(MastForestScriptError::ProcedureMissingAttribute(_))
        );
    }
}
