use miden_assembly::Library;
use miden_processor::MastForest;

use crate::vm::AdviceMap;

// ACCOUNT COMPONENT CODE
// ================================================================================================

/// A [`Library`] that has been assembled for use as component code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountComponentCode(Library);

impl AccountComponentCode {
    /// Returns a reference to the underlying [`Library`]
    pub fn as_library(&self) -> &Library {
        &self.0
    }

    /// Returns a reference to the code's [`MastForest`]
    pub fn mast_forest(&self) -> &MastForest {
        self.0.mast_forest().as_ref()
    }

    /// Consumes `self` and returns the underlying [`Library`]
    pub fn into_library(self) -> Library {
        self.0
    }

    /// Returns a new [AccountComponentCode] with the provided advice map entries merged into the
    /// underlying [Library]'s [MastForest].
    ///
    /// This allows adding advice map entries to an already-compiled account component,
    /// which is useful when the entries are determined after compilation.
    pub fn with_advice_map(self, advice_map: AdviceMap) -> Self {
        if advice_map.is_empty() {
            return self;
        }

        Self(self.0.with_advice_map(advice_map))
    }
}

impl AsRef<Library> for AccountComponentCode {
    fn as_ref(&self) -> &Library {
        self.as_library()
    }
}

// CONVERSIONS
// ================================================================================================

impl From<Library> for AccountComponentCode {
    fn from(value: Library) -> Self {
        Self(value)
    }
}

impl From<AccountComponentCode> for Library {
    fn from(value: AccountComponentCode) -> Self {
        value.into_library()
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
        let cloned = component_code.clone();
        let original_digest = cloned.as_library().digest();
        let component_code = component_code.with_advice_map(AdviceMap::default());
        assert_eq!(original_digest, component_code.as_library().digest());

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
