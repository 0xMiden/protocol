use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::account_component_code;

account_component_code!(
    BLOCKLIST_OWNER_CONTROLLED_CODE,
    "faucets/policies/transfer/blocklist/owner_controlled.masl"
);

/// Account component that exposes `block_account` and `unblock_account` admin procedures gated
/// by the [`crate::account::access::Ownable2Step`] owner.
///
/// The wrapper procedures live in `miden::standards::faucets::policies::transfer::blocklist::
/// owner_controlled` and call `ownable2step::assert_sender_is_owner` before delegating to the
/// standards-library helpers in `miden::standards::faucets::policies::transfer::blocklist`.
///
/// Companion components required:
/// - [`crate::account::access::Ownable2Step`] — provides the owner storage slot the auth check
///   reads.
/// - A component that installs the `blocked_accounts` storage slot — typically
///   [`crate::account::policies::BasicBlocklist`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnerControlledBlocklist;

impl OwnerControlledBlocklist {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::blocklist::owner_controlled";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &BLOCKLIST_OWNER_CONTROLLED_CODE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(
            Self::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "Owner-controlled blocklist admin: wraps `blocklist::block_account` / \
             `unblock_account` with Ownable2Step authorization.",
        )
    }
}

impl From<OwnerControlledBlocklist> for AccountComponent {
    fn from(_: OwnerControlledBlocklist) -> Self {
        let metadata = OwnerControlledBlocklist::component_metadata();
        AccountComponent::new(OwnerControlledBlocklist::code().clone(), vec![], metadata)
            .expect("owner-controlled blocklist admin component should be valid")
    }
}
