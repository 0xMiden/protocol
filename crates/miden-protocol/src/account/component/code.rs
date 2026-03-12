use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_assembly::library::ProcedureExport;
use miden_assembly::{Library, Path};
use miden_core::Word;
use miden_core::mast::{MastForest, MastNodeExt};

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

    /// Creates a new [`AccountComponentCode`] from the provided MAST forest and procedure exports.
    pub fn new(mast: Arc<MastForest>, exports: Vec<ProcedureExport>) -> Self {
        Self { mast, exports }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the code's [`MastForest`].
    pub fn mast_forest(&self) -> &MastForest {
        self.mast.as_ref()
    }

    /// Returns the [`MastForest`] wrapped in an [`Arc`].
    pub fn mast(&self) -> Arc<MastForest> {
        self.mast.clone()
    }

    /// Returns the procedure exports of this component.
    pub fn exports(&self) -> &[ProcedureExport] {
        &self.exports
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

    /// Returns a new [`AccountComponentCode`] with the provided advice map entries merged into the
    /// underlying [`MastForest`].
    ///
    /// This allows adding advice map entries to an already-compiled account component,
    /// which is useful when the entries are determined after compilation.
    pub fn with_advice_map(self, advice_map: AdviceMap) -> Self {
        if advice_map.is_empty() {
            return self;
        }

        let mut mast = (*self.mast).clone();
        mast.advice_map_mut().extend(advice_map);

        Self {
            mast: Arc::new(mast),
            exports: self.exports,
        }
    }
}

// CONVERSIONS
// ================================================================================================

impl From<Library> for AccountComponentCode {
    fn from(library: Library) -> Self {
        let mast = library.mast_forest().clone();
        let exports: Vec<ProcedureExport> =
            library.exports().filter_map(|export| export.as_procedure().cloned()).collect();

        Self { mast, exports }
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

impl From<&AccountComponentCode> for Library {
    fn from(value: &AccountComponentCode) -> Self {
        let exports: BTreeMap<_, _> =
            value.exports.iter().cloned().map(|e| (e.path.clone(), e.into())).collect();

        Library::new(value.mast.clone(), exports)
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

        assert!(component_code.mast_forest().advice_map().is_empty());

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

        let mast = component_code.mast_forest();
        let stored = mast.advice_map().get(&key).expect("entry should be present");
        assert_eq!(stored.as_ref(), value.as_slice());
    }
}
