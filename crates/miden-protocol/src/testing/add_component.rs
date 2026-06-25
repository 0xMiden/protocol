use alloc::sync::Arc;

use crate::account::AccountComponent;
use crate::account::component::AccountComponentMetadata;
use crate::assembly::{Assembler, DefaultSourceManager, Library, ModuleKind, ModuleParser, Path};
use crate::utils::sync::LazyLock;

// ADD COMPONENT
// ================================================================================================

const ADD_CODE: &str = "
    @account_procedure
    pub proc add5
        add.5
    end
";

static ADD_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let root = ModuleParser::new(Some(ModuleKind::Library))
        .parse_str(Some(Path::new("miden::testing::add")), ADD_CODE, source_manager.clone())
        .expect("add code should parse");

    *Assembler::new(source_manager)
        .assemble_library("miden-testing-add", root, None::<&str>)
        .expect("add code should be valid")
});

/// Creates a mock authentication [`AccountComponent`] for testing purposes.
///
/// The component defines an `add5` procedure that adds 5 to its input.
pub struct AddComponent;

impl From<AddComponent> for AccountComponent {
    fn from(_: AddComponent) -> Self {
        let metadata = AccountComponentMetadata::new("miden::testing::add")
            .with_description("Add component for testing");

        AccountComponent::new(ADD_LIBRARY.clone(), vec![], metadata)
            .expect("component should be valid")
    }
}
