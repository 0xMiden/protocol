use miden_protocol::account::component::{AccountComponentMetadata, SchemaType, StorageSlotSchema};
use miden_protocol::account::{AccountComponent, AccountType, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;

use crate::account::components::blocklist_owner_library;

// BLOCKLIST STORAGE NAMESPACE
// ================================================================================================

static BLOCKED_USERS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::restrictions::blocklist::blocked_users")
        .expect("storage slot name should be valid")
});

/// Namespace exposing accessors for the per-faucet `blocked_users` storage slot.
///
/// `Blocklist` is **not** an installable account component on its own. The underlying storage
/// slot is provided by [`crate::account::policies::TransferIfNotBlocklisted`], which is the
/// only built-in policy reading from it. The `block_user` / `unblock_user` / `is_blocked` /
/// `assert_not_blocked` procedures live in the standards library
/// (`miden::standards::faucets::restrictions::blocklist`) as `Invocation: exec` helpers — they
/// perform no authorization and must be wrapped by an auth-checking admin component (see
/// [`OwnerOnlyBlocklistAdmin`]) before being exposed on a faucet.
///
/// ## Storage
///
/// - [`Self::blocked_users_slot()`]: storage map keyed by account ID (word layout `[0, 0,
///   account_id_suffix, account_id_prefix]`). A user is considered blocked when its entry is the
///   word `[1, 0, 0, 0]`; the zero word (including the default for unset entries) means not
///   blocked.
#[derive(Debug, Clone, Copy)]
pub struct Blocklist;

impl Blocklist {
    /// Storage slot name for the blocked-users map.
    pub fn blocked_users_slot() -> &'static StorageSlotName {
        &BLOCKED_USERS_SLOT_NAME
    }

    /// Schema entry for the blocked-users map slot (documentation / tooling).
    pub fn blocked_users_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::blocked_users_slot().clone(),
            StorageSlotSchema::map(
                "Per-user blocked flag; zero word is not blocked, [1,0,0,0] is blocked",
                SchemaType::native_word(),
                SchemaType::bool(),
            ),
        )
    }
}

// OWNER-CONTROLLED ADMIN COMPONENT
// ================================================================================================

/// Account component that exposes `block_user` and `unblock_user` admin procedures gated by the
/// [`crate::account::access::Ownable2Step`] owner.
///
/// The wrapper procedures live in `miden::standards::faucets::restrictions::blocklist_owner` and
/// call `ownable2step::assert_sender_is_owner` before delegating to the standards-library helpers
/// in `miden::standards::faucets::restrictions::blocklist`.
///
/// Companion components required:
/// - [`crate::account::access::Ownable2Step`] — provides the owner storage slot the auth check
///   reads.
/// - A component that installs the `blocked_users` storage slot — typically
///   [`crate::account::policies::TransferIfNotBlocklisted`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnerOnlyBlocklistAdmin;

impl OwnerOnlyBlocklistAdmin {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::restrictions::blocklist_owner";

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(
            Self::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "Owner-controlled blocklist admin: wraps `blocklist::block_user` / `unblock_user` \
             with Ownable2Step authorization.",
        )
    }
}

impl From<OwnerOnlyBlocklistAdmin> for AccountComponent {
    fn from(_: OwnerOnlyBlocklistAdmin) -> Self {
        let metadata = OwnerOnlyBlocklistAdmin::component_metadata();
        AccountComponent::new(blocklist_owner_library(), vec![], metadata)
            .expect("owner-controlled Blocklist admin component should be valid")
    }
}
