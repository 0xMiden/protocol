use alloc::sync::Arc;

use crate::account::component::AccountComponentMetadata;
use crate::account::{AccountComponent, AccountType};
use crate::assembly::{Assembler, Library};
use crate::utils::sync::LazyLock;

// ADD COMPONENT
// ================================================================================================

const ADD_CODE: &str = "
    pub proc add5
        add.5
    end
";

static ADD_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    Arc::unwrap_or_clone(
        Assembler::default()
            .assemble_library([ADD_CODE])
            .expect("add code should be valid"),
    )
});

/// Creates a mock authentication [`AccountComponent`] for testing purposes.
///
/// The component defines an `add5` procedure that adds 5 to its input.
pub struct AddComponent;

impl From<AddComponent> for AccountComponent {
    fn from(_: AddComponent) -> Self {
        let metadata = AccountComponentMetadata::new("miden::testing::add", AccountType::all())
            .with_description("Add component for testing");

        AccountComponent::new(ADD_LIBRARY.clone(), vec![], metadata)
            .expect("component should be valid")
    }
}
