use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_assembly::library::ProcedureExport;
use miden_assembly::{Library, Path};
use miden_core::Word;
use miden_core::mast::{ExternalNodeBuilder, MastForest, MastForestContributor, MastNodeExt};

use crate::account::AccountProcedureRoot;
use crate::vm::AdviceMap;

// ACCOUNT COMPONENT CODE
// ================================================================================================

/// The code associated with an account component, consisting of a [`MastForest`] and the set of
/// procedures exported by the component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountComponentCode {
    mast: Arc<MastForest>,
    exports: Vec<ProcedureExport>,
}

impl AccountComponentCode {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AccountComponentCode`] from the provided [`Library`].
    pub fn from_library(library: Library) -> Self {
        let mast = library.mast_forest().clone();
        let exports: Vec<ProcedureExport> =
            library.exports().filter_map(|export| export.as_procedure().cloned()).collect();

        Self { mast, exports }
    }

    /// Returns a new [`AccountComponentCode`] containing only external node references to the
    /// procedures in the provided [`Library`].
    ///
    /// Note: This method creates a minimal [`MastForest`] where each exported procedure is
    /// represented by an external node referencing its digest, rather than copying the entire
    /// library's MAST forest. The actual procedure code will be resolved at runtime via the
    /// `MastForestStore`.
    pub fn from_library_reference(library: &Library) -> Self {
        let mut mast = MastForest::new();
        let mut exports = Vec::new();

        for export in library.exports() {
            if let Some(proc_export) = export.as_procedure() {
                // Get the digest of the procedure from the library
                let digest = library.mast_forest()[proc_export.node].digest();

                // Create an external node referencing the digest
                let node_id = ExternalNodeBuilder::new(digest)
                    .add_to_forest(&mut mast)
                    .expect("adding external node to forest should not fail");
                mast.make_root(node_id);

                exports.push(ProcedureExport {
                    node: node_id,
                    path: proc_export.path.clone(),
                    signature: proc_export.signature.clone(),
                    attributes: proc_export.attributes.clone(),
                });
            }
        }

        Self { mast: Arc::new(mast), exports }
    }

    /// Creates a new [`AccountComponentCode`] from the provided MAST forest and procedure exports.
    ///
    /// # Panics
    ///
    /// Panics if any of the exported procedure node IDs are not found in the MAST forest.
    pub fn from_parts(mast: Arc<MastForest>, exports: Vec<ProcedureExport>) -> Self {
        for export in &exports {
            assert!(
                mast.get_node_by_id(export.node).is_some(),
                "exported procedure node not found in the MAST forest"
            );
        }

        Self { mast, exports }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`MastForest`] wrapped in an [`Arc`].
    pub fn mast(&self) -> Arc<MastForest> {
        self.mast.clone()
    }

    /// Returns the procedure exports of this component.
    pub fn exports(&self) -> &[ProcedureExport] {
        &self.exports
    }

    /// Returns an iterator over the [`AccountProcedureRoot`]s of this component's exported
    /// procedures.
    pub fn procedure_roots(&self) -> impl Iterator<Item = AccountProcedureRoot> + '_ {
        self.exports
            .iter()
            .map(|export| AccountProcedureRoot::from_raw(self.mast[export.node].digest()))
    }

    /// Returns the digest of the procedure with the specified path, or `None` if it was not found
    /// in this component.
    pub fn get_procedure_root_by_path(&self, path: impl AsRef<Path>) -> Option<Word> {
        let path = path.as_ref().to_absolute();
        self.exports
            .iter()
            .find(|export| export.path.as_ref() == path.as_ref())
            .map(|export| self.mast[export.node].digest())
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`AccountComponentCode`] with the provided advice map entries merged into the
    /// underlying [`MastForest`].
    ///
    /// This allows adding advice map entries to an already-compiled account component,
    /// which is useful when the entries are determined after compilation.
    pub fn with_advice_map(self, advice_map: AdviceMap) -> Self {
        if advice_map.is_empty() {
            return self;
        }

        let mut mast = Arc::unwrap_or_clone(self.mast);
        mast.advice_map_mut().extend(advice_map);

        Self {
            mast: Arc::new(mast),
            exports: self.exports,
        }
    }

    /// Clears the debug info from the underlying [`MastForest`].
    pub fn clear_debug_info(&mut self) {
        let mut mast = self.mast.clone();
        Arc::make_mut(&mut mast).clear_debug_info();
        self.mast = mast;
    }
}

// CONVERSIONS
// ================================================================================================

impl From<Library> for AccountComponentCode {
    fn from(library: Library) -> Self {
        Self::from_library(library)
    }
}

impl From<AccountComponentCode> for Library {
    fn from(value: AccountComponentCode) -> Self {
        let exports: BTreeMap<_, _> =
            value.exports.into_iter().map(|e| (e.path.clone(), e.into())).collect();

        Library::new(value.mast, exports)
            .expect("AccountComponentCode should have at least one export")
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::{Felt, Word};

    use super::*;
    use crate::assembly::Assembler;

    #[test]
    fn test_account_component_code_with_advice_map() {
        let assembler = Assembler::default();
        let library = assembler
            .assemble_library(["pub proc test nop end"])
            .expect("failed to assemble library");
        let component_code = AccountComponentCode::from(library);

        assert!(component_code.mast().advice_map().is_empty());

        // Empty advice map should be a no-op (digest stays the same)
        let original_digest = *Library::from(component_code.clone()).digest();
        let component_code = component_code.with_advice_map(AdviceMap::default());
        assert_eq!(&original_digest, Library::from(component_code.clone()).digest());

        // Non-empty advice map should add entries
        let key = Word::from([10u32, 20, 30, 40]);
        let value = vec![Felt::new(200)];
        let mut advice_map = AdviceMap::default();
        advice_map.insert(key, value.clone());

        let component_code = component_code.with_advice_map(advice_map);

        let mast = component_code.mast();
        let stored = mast.advice_map().get(&key).expect("entry should be present");
        assert_eq!(stored.as_ref(), value.as_slice());
    }
}
