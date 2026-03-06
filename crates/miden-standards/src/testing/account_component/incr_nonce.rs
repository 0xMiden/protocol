use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};
use miden_protocol::assembly::Library;
use miden_protocol::utils::sync::LazyLock;

use crate::code_builder::CodeBuilder;

const INCR_NONCE_AUTH_CODE: &str = "
    use miden::protocol::native_account

    @auth_script
    pub proc auth_incr_nonce
        exec.native_account::incr_nonce drop
    end
";

static INCR_NONCE_AUTH_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code("incr_nonce", INCR_NONCE_AUTH_CODE)
        .expect("incr nonce code should be valid")
        .into_library()
});

/// Creates a mock authentication [`AccountComponent`] for testing purposes under the "incr_nonce"
/// namespace.
///
/// The component defines an `auth_incr_nonce` procedure that always increments the nonce by 1.
pub struct IncrNonceAuthComponent;

impl From<IncrNonceAuthComponent> for AccountComponent {
    fn from(_: IncrNonceAuthComponent) -> Self {
        let metadata =
            AccountComponentMetadata::new("miden::testing::incr_nonce_auth", AccountType::all())
                .with_description("Testing auth component that always increments nonce");

        AccountComponent::new(INCR_NONCE_AUTH_LIBRARY.clone(), vec![], metadata)
            .expect("component should be valid")
    }
}
