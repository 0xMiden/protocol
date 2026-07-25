use miden_mast_package::{Package, ProcedureExport};
use miden_processor::mast::{MastForest, MastNodeExt};

use crate::account::AccountProcedureRoot;
use crate::assembly::Path;
use crate::vm::AdviceMap;

// ACCOUNT COMPONENT CODE
// ================================================================================================

/// A [`Package`] that has been assembled for use as component code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountComponentCode(Package);

impl AccountComponentCode {
    /// Returns a reference to the underlying [`Package`]
    pub fn as_package(&self) -> &Package {
        &self.0
    }

    /// Returns a reference to the code's [`MastForest`]
    pub fn mast_forest(&self) -> &MastForest {
        self.0.mast_forest().as_ref()
    }

    /// Consumes `self` and returns the underlying [`Package`]
    pub fn into_package(self) -> Package {
        self.0
    }

    /// Returns an iterator over the [`AccountProcedureRoot`]s of this component's interface
    /// procedures.
    pub fn procedure_roots(&self) -> impl Iterator<Item = AccountProcedureRoot> + '_ {
        self.exports().map(|proc_export| {
            let digest = if let Some(node) = proc_export.node {
                self.0.mast_forest()[node].digest()
            } else {
                proc_export.digest
            };
            AccountProcedureRoot::from_raw(digest)
        })
    }

    /// Returns the interface procedure exports of this component.
    ///
    /// A procedure is part of the interface if it has the `@account_procedure` or `@auth_script`
    /// attributes.
    pub fn exports(&self) -> impl Iterator<Item = &ProcedureExport> + '_ {
        self.0
            .manifest
            .exports()
            .filter_map(|export| export.as_procedure())
            .filter(|proc_export| {
                proc_export.attributes.has(super::ACCOUNT_PROCEDURE_ATTRIBUTE)
                    || proc_export.attributes.has(super::AUTH_SCRIPT_ATTRIBUTE)
            })
    }

    /// Returns the [`AccountProcedureRoot`] of the procedure with the specified path, or `None`
    /// if it was not found in this component's code.
    pub fn get_procedure_root_by_path(
        &self,
        proc_name: impl AsRef<Path>,
    ) -> Option<AccountProcedureRoot> {
        let proc_name = proc_name.as_ref();
        let absolute_proc_name = proc_name.to_absolute().ok();
        self.0
            .manifest
            .exports()
            .filter_map(|export| export.as_procedure())
            .find(|export| {
                absolute_proc_name.as_ref().is_some_and(|absolute_proc_name| {
                    export.path.as_ref() == absolute_proc_name.as_ref()
                })
            })
            .map(|export| AccountProcedureRoot::from_raw(export.digest))
    }

    /// Returns a new [AccountComponentCode] with the provided advice map entries merged into the
    /// underlying [Package]'s [MastForest].
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

impl AsRef<Package> for AccountComponentCode {
    fn as_ref(&self) -> &Package {
        self.as_package()
    }
}

// CONVERSIONS
// ================================================================================================

impl From<Package> for AccountComponentCode {
    fn from(value: Package) -> Self {
        Self(value)
    }
}

impl From<AccountComponentCode> for Package {
    fn from(value: AccountComponentCode) -> Self {
        value.into_package()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_core::{Felt, Word};

    use super::*;
    use crate::testing::assembler::assemble_test_package;

    #[test]
    fn test_account_component_code_with_advice_map() {
        let package = assemble_test_package(
            "test-component-code-advice-map",
            "test::component_code_advice_map",
            "@account_procedure pub proc test nop end",
        );
        let component_code = AccountComponentCode::from(package);

        assert!(component_code.mast_forest().advice_map().is_empty());

        // Empty advice map should be a no-op (digest stays the same)
        let cloned = component_code.clone();
        let original_digest = cloned.as_package().digest();
        let component_code = component_code.with_advice_map(AdviceMap::default());
        assert_eq!(original_digest, component_code.as_package().digest());

        // Non-empty advice map should add entries
        let key = Word::from([10u32, 20, 30, 40]);
        let value = vec![Felt::from(200_u8)];
        let mut advice_map = AdviceMap::default();
        advice_map.insert(key, value.clone());

        let component_code = component_code.with_advice_map(advice_map);

        let mast = component_code.mast_forest();
        let stored = mast.advice_map().get(&key).expect("entry should be present");
        assert_eq!(stored.as_ref(), value.as_slice());
    }

    #[test]
    fn test_get_procedure_root_by_path() {
        let package = assemble_test_package(
            "test-component-code-procedure-root",
            "test::component_code_procedure_root",
            "@account_procedure pub proc test_proc nop end",
        );
        let component_code = AccountComponentCode::from(package);

        // The test package exports exactly one procedure.
        assert_eq!(component_code.procedure_roots().count(), 1);
        let expected = component_code.procedure_roots().next().expect("one procedure exported");

        let package_namespace = component_code
            .as_package()
            .module_infos()
            .next()
            .expect("package should have one module")
            .path()
            .to_string();
        let proc_path = alloc::format!("{package_namespace}::test_proc");

        let root = component_code
            .get_procedure_root_by_path(&*proc_path)
            .expect("test_proc should be present");
        assert_eq!(root, expected);

        let relative_proc_path =
            proc_path.strip_prefix("::").expect("test procedure path should be absolute");
        let root = component_code
            .get_procedure_root_by_path(relative_proc_path)
            .expect("relative test_proc path should be present");
        assert_eq!(root, expected);

        assert!(component_code.get_procedure_root_by_path("bogus::missing").is_none());
    }
}
