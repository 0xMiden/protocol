use alloc::format;

use crate::Word;
use crate::code::ProcedureRoot;
use crate::testing::assembler::assemble_test_package;
use crate::transaction::TransactionCodePatch;

impl ProcedureRoot {
    /// Returns a procedure root whose leaf is distinct for every `value`.
    pub fn mock(value: u32) -> ProcedureRoot {
        ProcedureRoot::from_raw(Word::from([value, value, value, value]))
    }
}

impl TransactionCodePatch {
    /// Returns a mock [`TransactionCodePatch`] with created procedures and a dependency.
    pub fn mock() -> TransactionCodePatch {
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
                .clone();

        TransactionCodePatch::new(mast).expect("mock code patch should be valid")
    }
}
