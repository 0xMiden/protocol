use crate::account::AccountComponent;
use crate::account::component::AccountComponentMetadata;
use crate::assembly::Package;
use crate::testing::assembler::assemble_test_library;
use crate::utils::sync::LazyLock;

// ADD COMPONENT
// ================================================================================================

const ADD_CODE: &str = "
    @account_procedure
    pub proc add5
        add.5
    end
";

static ADD_LIBRARY: LazyLock<Package> =
    LazyLock::new(|| assemble_test_library("miden-testing-add", "miden::testing::add", ADD_CODE));

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
