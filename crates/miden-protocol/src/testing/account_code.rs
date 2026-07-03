// ACCOUNT CODE
// ================================================================================================

use crate::account::component::AccountComponentMetadata;
use crate::account::{AccountCode, AccountComponent};
use crate::testing::assembler::assemble_test_library;
use crate::testing::noop_auth_component::NoopAuthComponent;

pub const CODE: &str = "
    @account_procedure
    pub proc foo
        push.1.2 mul
    end

    @account_procedure
    pub proc bar
        push.1.2 add
    end
";

impl AccountCode {
    /// Creates a mock [AccountCode] with default assembler and mock code
    pub fn mock() -> AccountCode {
        let library = assemble_test_library(
            "miden-testing-mock-account",
            "miden::testing::mock_account",
            CODE,
        );
        let metadata = AccountComponentMetadata::new("miden::testing::mock");
        let component = AccountComponent::new(library, vec![], metadata).unwrap();

        Self::from_components(&[NoopAuthComponent.into(), component]).unwrap()
    }
}
