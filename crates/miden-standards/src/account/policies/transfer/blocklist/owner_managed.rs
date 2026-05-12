use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::blocklist_owner_managed_library;

/// Account component that exposes `block_account` and `unblock_account` admin procedures gated
/// by the [`crate::account::access::Ownable2Step`] owner.
///
/// The wrapper procedures live in `miden::standards::faucets::policies::transfer::blocklist::
/// owner_managed` and call `ownable2step::assert_sender_is_owner` before delegating to the
/// standards-library helpers in `miden::standards::faucets::policies::transfer::blocklist`.
///
/// Companion components required:
/// - [`crate::account::access::Ownable2Step`] — provides the owner storage slot the auth check
///   reads.
/// - A component that installs the `blocked_accounts` storage slot — typically
///   [`crate::account::policies::BasicBlocklist`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnerManagedBlocklist;

impl OwnerManagedBlocklist {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::blocklist::owner_managed";

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(
            Self::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "Owner-managed blocklist admin: wraps `blocklist::block_account` / `unblock_account` \
             with Ownable2Step authorization.",
        )
    }
}

impl From<OwnerManagedBlocklist> for AccountComponent {
    fn from(_: OwnerManagedBlocklist) -> Self {
        let metadata = OwnerManagedBlocklist::component_metadata();
        AccountComponent::new(blocklist_owner_managed_library(), vec![], metadata)
            .expect("owner-managed blocklist admin component should be valid")
    }
}
