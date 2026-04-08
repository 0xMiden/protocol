use alloc::sync::Arc;

use crate::account::component::AccountComponentMetadata;
use crate::account::{AccountComponent, AccountType};
use crate::assembly::{Assembler, Library};
use crate::utils::sync::LazyLock;

// NOOP AUTH COMPONENT
// ================================================================================================

const NOOP_AUTH_CODE: &str = "
    @auth_script
    pub proc auth_noop
        push.0 drop
    end
";

static NOOP_AUTH_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    Arc::unwrap_or_clone(
        Assembler::default()
            .assemble_library([NOOP_AUTH_CODE])
            .expect("noop auth code should be valid"),
    )
});

/// Creates a mock authentication [`AccountComponent`] for testing purposes.
///
/// The component defines an `auth_noop` procedure that does nothing (always succeeds).
pub struct NoopAuthComponent;

impl From<NoopAuthComponent> for AccountComponent {
    fn from(_: NoopAuthComponent) -> Self {
        let metadata =
            AccountComponentMetadata::new("miden::testing::noop_auth", AccountType::all())
                .with_description("No-op auth component for testing");

        AccountComponent::new(NOOP_AUTH_LIBRARY.clone(), vec![], metadata)
            .expect("component should be valid")
    }
}
