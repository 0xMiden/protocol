use miden_protocol::account::AccountComponent;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};

use crate::account::account_component_code;

account_component_code!(
    ALLOWLIST_OWNER_CONTROLLED_CODE,
    "faucets/policies/transfer/allowlist/owner_controlled.masl"
);

/// Account component that exposes `allow_account` and `disallow_account` admin procedures gated
/// by the [`crate::account::access::Ownable2Step`] owner.
///
/// The wrapper procedures live in `miden::standards::faucets::policies::transfer::allowlist::
/// owner_controlled` and call `ownable2step::assert_sender_is_owner` before delegating to the
/// standards-library helpers in `miden::standards::faucets::policies::transfer::allowlist`.
///
/// Companion components required:
/// - [`crate::account::access::Ownable2Step`] — provides the owner storage slot the auth check
///   reads.
/// - A component that installs the `allowed_accounts` storage slot — typically
///   [`crate::account::policies::BasicAllowlist`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowlistOwnerControlled;

impl AllowlistOwnerControlled {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::allowlist::owner_controlled";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &ALLOWLIST_OWNER_CONTROLLED_CODE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME).with_description(
            "Owner-controlled allowlist admin: wraps `allowlist::allow_account` / \
             `disallow_account` with Ownable2Step authorization.",
        )
    }
}

impl From<AllowlistOwnerControlled> for AccountComponent {
    fn from(_: AllowlistOwnerControlled) -> Self {
        let metadata = AllowlistOwnerControlled::component_metadata();
        AccountComponent::new(AllowlistOwnerControlled::code().clone(), vec![], metadata)
            .expect("owner-controlled allowlist admin component should be valid")
    }
}
