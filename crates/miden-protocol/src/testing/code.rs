use alloc::sync::Arc;
use alloc::{format, vec};

use crate::block::code_tree::CodePatch;
use crate::code::ProcedureRoot;
use crate::testing::assembler::assemble_test_package;
use crate::vm::AdviceMap;
use crate::{Felt, Hasher, Word};

impl ProcedureRoot {
    /// Returns a procedure root whose leaf is distinct for every `value`.
    pub fn mock(value: u32) -> ProcedureRoot {
        ProcedureRoot::from_raw(Word::from([value, value, value, value]))
    }
}

impl CodePatch {
    /// Returns a mock [`CodePatch`] with created procedures, a dependency and an advice map entry.
    pub fn mock() -> CodePatch {
        let external_procedure = ProcedureRoot::mock(1);
        let source = format!(
            "
            pub proc foo
                push.1 drop
            end

            pub proc bar
                call.{external_procedure}
            end
            "
        );
        let mast =
            assemble_test_package("miden-testing-mock-code-patch", "test::code_patch", &source)
                .mast_forest()
                .as_ref()
                .clone();

        let advice_value = vec![Felt::from(7_u32)];
        let mut advice_map = AdviceMap::default();
        advice_map.insert(Hasher::hash_elements(&advice_value), advice_value);
        let mast = mast.with_advice_map(advice_map);

        let created_procedures = mast.procedure_digests().map(ProcedureRoot::from_raw).collect();

        CodePatch::new(created_procedures, vec![external_procedure], Arc::new(mast))
            .expect("mock code patch should be valid")
    }
}
