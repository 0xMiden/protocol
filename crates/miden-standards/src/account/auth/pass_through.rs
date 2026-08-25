use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName};

use crate::account::account_component_code;

account_component_code!(AUTH_PASS_THROUGH_CODE, "miden-standards-auth-pass-through.masp");

/// An [`AccountComponent`] implementing the authentication scheme of a pass-through account.
///
/// This component provides **no authentication**. It makes an account stateless: any transaction
/// that would change its commitment fails, and the nonce is never incremented. Nothing can
/// therefore alter the account, so transactions against it never conflict with one another and
/// can be built concurrently - which is what a pass-through transaction runs on, since assets
/// enter the vault through the input notes and leave it again through the output notes within the
/// same transaction.
///
/// It exports the procedure `auth_pass_through`, which:
/// - Asserts the account's commitment is the one it had at the start of the transaction
/// - Never increments the nonce
/// - Creates no TX_FEE note, so a transaction using a pass-through script pays no fee and is only
///   includable by a batch builder that accepts fee-less transactions. This bounds the procedure,
///   not the transaction: the assert allows a zero net vault delta, not the absence of withdrawals,
///   so another script could still route assets an input note deposited into a fee note of its own
/// - Provides no cryptographic authentication
///
/// Since the nonce is never incremented, an account with this component cannot be created by a
/// transaction, and any asset it holds is permanently unspendable.
///
/// # Security
///
/// The account authenticates nothing, so anyone can execute a transaction against it and choose
/// where the assets passing through it go. Assets are only safe in transit if the input note's own
/// script constrains its destination; a note that lets its consumer pick the output note, such as
/// [`P2idNote`](crate::note::P2idNote) or [`TxFeeNote`](crate::note::TxFeeNote), can be redirected
/// by whoever gets there first.
pub struct AuthPassThrough;

impl AuthPassThrough {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::auth::pass_through";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &AUTH_PASS_THROUGH_CODE
    }

    /// Creates a new [`AuthPassThrough`] component.
    pub fn new() -> Self {
        Self
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME)
            .with_description("Pass-through authentication component")
    }
}

impl Default for AuthPassThrough {
    fn default() -> Self {
        Self::new()
    }
}

impl From<AuthPassThrough> for AccountComponent {
    fn from(_: AuthPassThrough) -> Self {
        let metadata = AuthPassThrough::component_metadata();

        AccountComponent::new(AuthPassThrough::code().clone(), vec![], metadata).expect(
            "AuthPassThrough component should satisfy the requirements of a valid account \
             component",
        )
    }
}
