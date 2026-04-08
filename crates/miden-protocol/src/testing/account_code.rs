// ACCOUNT CODE
// ================================================================================================

use alloc::sync::Arc;

use miden_assembly::Assembler;

use crate::account::component::AccountComponentMetadata;
use crate::account::{AccountCode, AccountComponent, AccountType};
use crate::testing::noop_auth_component::NoopAuthComponent;

pub const CODE: &str = "
    pub proc foo
        push.1.2 mul
    end

    pub proc bar
        push.1.2 add
    end
";

impl AccountCode {
    /// Creates a mock [AccountCode] with default assembler and mock code
    pub fn mock() -> AccountCode {
        let library = Arc::unwrap_or_clone(
            Assembler::default()
                .assemble_library([CODE])
                .expect("mock account component should assemble"),
        );
        let metadata = AccountComponentMetadata::new("miden::testing::mock", AccountType::all());
        let component = AccountComponent::new(library, vec![], metadata).unwrap();

        Self::from_components(
            &[NoopAuthComponent.into(), component],
            AccountType::RegularAccountUpdatableCode,
        )
        .unwrap()
    }
}
