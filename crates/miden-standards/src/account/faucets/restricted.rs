use miden_protocol::account::component::{AccountComponentMetadata, SchemaType, StorageSlotSchema};
use miden_protocol::account::{AccountComponent, AccountType, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;

use crate::account::components::restricted_owner_library;

// RESTRICTED STORAGE NAMESPACE
// ================================================================================================

static BLOCKED_ACCOUNTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::restricted::blocked_accounts")
        .expect("storage slot name should be valid")
});

/// Namespace exposing accessors for the per-faucet `blocked_accounts` storage slot.
///
/// `Restricted` is **not** an installable account component on its own. The underlying storage
/// slot is provided by [`crate::account::policies::TransferIfNotBlocklisted`], which is the
/// only built-in policy reading from it. The `block` / `unblock` / `is_blocked` /
/// `assert_not_blocked` procedures live in the standards library
/// (`miden::standards::faucets::restricted`) as `Invocation: exec` helpers — they perform no
/// authorization and must be wrapped by an auth-checking admin component (see
/// [`OwnerOnlyRestrictedAdmin`]) before being exposed on a faucet.
///
/// ## Storage
///
/// - [`Self::blocked_accounts_slot()`]: storage map keyed by account ID (word layout `[0, 0,
///   account_id_suffix, account_id_prefix]`). An account is considered blocked when its entry is
///   the word `[1, 0, 0, 0]`; the zero word (including the default for unset entries) means not
///   blocked.
#[derive(Debug, Clone, Copy)]
pub struct Restricted;

impl Restricted {
    /// Storage slot name for the blocked-accounts map.
    pub fn blocked_accounts_slot() -> &'static StorageSlotName {
        &BLOCKED_ACCOUNTS_SLOT_NAME
    }

    /// Schema entry for the blocked-accounts map slot (documentation / tooling).
    pub fn blocked_accounts_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::blocked_accounts_slot().clone(),
            StorageSlotSchema::map(
                "Per-account blocked flag; zero word is not blocked, [1,0,0,0] is blocked",
                SchemaType::native_word(),
                SchemaType::bool(),
            ),
        )
    }
}

// OWNER-CONTROLLED ADMIN COMPONENT
// ================================================================================================

/// Account component that exposes `block` and `unblock` admin procedures gated by the
/// [`crate::account::access::Ownable2Step`] owner.
///
/// The wrapper procedures live in `miden::standards::faucets::restricted_owner` and call
/// `ownable2step::assert_sender_is_owner` before delegating to the standards-library helpers
/// in `miden::standards::faucets::restricted`.
///
/// Companion components required:
/// - [`crate::account::access::Ownable2Step`] — provides the owner storage slot the auth check
///   reads.
/// - A component that installs the `blocked_accounts` storage slot — typically
///   [`crate::account::policies::TransferIfNotBlocklisted`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnerOnlyRestrictedAdmin;

impl OwnerOnlyRestrictedAdmin {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::faucets::restricted_owner";

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(
            Self::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "Owner-controlled blocklist admin: wraps `restricted::block` / `unblock` with \
             Ownable2Step authorization.",
        )
    }
}

impl From<OwnerOnlyRestrictedAdmin> for AccountComponent {
    fn from(_: OwnerOnlyRestrictedAdmin) -> Self {
        let metadata = OwnerOnlyRestrictedAdmin::component_metadata();
        AccountComponent::new(restricted_owner_library(), vec![], metadata)
            .expect("owner-controlled Restricted admin component should be valid")
    }
}
