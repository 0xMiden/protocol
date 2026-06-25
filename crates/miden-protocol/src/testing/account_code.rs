// ACCOUNT CODE
// ================================================================================================

use alloc::sync::Arc;

use crate::account::component::AccountComponentMetadata;
use crate::account::{AccountCode, AccountComponent};
use crate::assembly::{Assembler, DefaultSourceManager, ModuleKind, ModuleParser, Path};
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
        let source_manager = Arc::new(DefaultSourceManager::default());
        let root = ModuleParser::new(Some(ModuleKind::Library))
            .parse_str(
                Some(Path::new("miden::testing::mock_account")),
                CODE,
                source_manager.clone(),
            )
            .expect("mock account component should parse");
        let library = *Assembler::new(source_manager)
            .assemble_library("miden-testing-mock-account", root, None::<&str>)
            .expect("mock account component should assemble");
        let metadata = AccountComponentMetadata::new("miden::testing::mock");
        let component = AccountComponent::new(library, vec![], metadata).unwrap();

        Self::from_components(&[NoopAuthComponent.into(), component]).unwrap()
    }
}
