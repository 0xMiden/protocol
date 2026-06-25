use alloc::sync::Arc;

use crate::account::AccountComponent;
use crate::account::component::AccountComponentMetadata;
use crate::assembly::{Assembler, DefaultSourceManager, Library, ModuleKind, ModuleParser, Path};
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
    let source_manager = Arc::new(DefaultSourceManager::default());
    let root = ModuleParser::new(Some(ModuleKind::Library))
        .parse_str(
            Some(Path::new("miden::testing::noop_auth")),
            NOOP_AUTH_CODE,
            source_manager.clone(),
        )
        .expect("noop auth code should parse");

    *Assembler::new(source_manager)
        .assemble_library("miden-testing-noop-auth", root, None::<&str>)
        .expect("noop auth code should be valid")
});

/// Creates a mock authentication [`AccountComponent`] for testing purposes.
///
/// The component defines an `auth_noop` procedure that does nothing (always succeeds).
pub struct NoopAuthComponent;

impl From<NoopAuthComponent> for AccountComponent {
    fn from(_: NoopAuthComponent) -> Self {
        let metadata = AccountComponentMetadata::new("miden::testing::noop_auth")
            .with_description("No-op auth component for testing");

        AccountComponent::new(NOOP_AUTH_LIBRARY.clone(), vec![], metadata)
            .expect("component should be valid")
    }
}
