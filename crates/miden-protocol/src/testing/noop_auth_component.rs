use crate::account::AccountComponent;
use crate::account::component::AccountComponentMetadata;
use crate::assembly::Package;
use crate::testing::assembler::assemble_test_package_with_protocol;
use crate::utils::sync::LazyLock;

// NOOP AUTH COMPONENT
// ================================================================================================

const NOOP_AUTH_CODE: &str = "
    use miden::protocol::tx

    @auth_script
    pub proc auth_noop
        exec.tx::create_code_patch drop drop drop
    end
";

static NOOP_AUTH_PACKAGE: LazyLock<Package> = LazyLock::new(|| {
    assemble_test_package_with_protocol(
        "miden-testing-noop-auth",
        "miden::testing::noop_auth",
        NOOP_AUTH_CODE,
    )
});

/// Creates a mock authentication [`AccountComponent`] for testing purposes.
///
/// The component defines an `auth_noop` procedure that only creates the code patch, which every
/// authentication procedure must do (always succeeds).
pub struct NoopAuthComponent;

impl From<NoopAuthComponent> for AccountComponent {
    fn from(_: NoopAuthComponent) -> Self {
        let metadata = AccountComponentMetadata::new("miden::testing::noop_auth")
            .with_description("No-op auth component for testing");

        AccountComponent::new(NOOP_AUTH_PACKAGE.clone(), vec![], metadata)
            .expect("component should be valid")
    }
}
