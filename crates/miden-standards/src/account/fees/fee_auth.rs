use alloc::vec;

use miden_protocol::account::AccountComponent;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};

use crate::account::account_component_code;

account_component_code!(FEE_AUTH_CODE, "miden-standards-fees-fee-auth.masp");

/// An [`AccountComponent`] providing authentication for a fee-managed network account.
///
/// It settles the transaction's fees, then increments the nonce if the account state changed.
///
/// Settlement lives in the auth procedure because the kernel invokes it unconditionally. A note
/// script could not be trusted to call it: a feature note that skipped the call would be exactly
/// the note that never paid. This is the mirror image of the presence check inside the
/// [`NetworkSponsorshipNote`](crate::note::NetworkSponsorshipNote)'s own script, which protects the
/// sponsor rather than the account.
///
/// # Dependencies
///
/// The account must also install the [`FeeManager`](crate::account::fees::FeeManager) component,
/// which holds the fee schedule this reads.
///
/// # Warning
///
/// This component performs **no cryptographic authentication**. A production network account would
/// compose fee settlement with the note-script and transaction-script allowlists of
/// [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount).
#[derive(Debug, Clone, Copy, Default)]
pub struct FeeAuth;

impl FeeAuth {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::fees::fee_auth";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &FEE_AUTH_CODE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME).with_description(
            "Settles the transaction's fees, then increments the nonce if the account changed",
        )
    }
}

impl From<FeeAuth> for AccountComponent {
    fn from(_: FeeAuth) -> Self {
        AccountComponent::new(FeeAuth::code().clone(), vec![], FeeAuth::component_metadata())
            .expect("FeeAuth component should satisfy the requirements of a valid component")
    }
}
