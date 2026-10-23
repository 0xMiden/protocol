use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName};

use crate::account::account_component_package;

account_component_package!(PASSTHROUGH_PACKAGE, "miden-standards-auth-passthrough.masp");

/// Permissionless authentication for a stateless passthrough account.
///
/// Transactions must preserve the account state and leave the vault empty. Deployment alone
/// increments the nonce once. Anyone with the input witnesses can execute against this account.
/// Public notes must enforce their spending conditions. Private CREATE notes assume the creator
/// keeps the witness private and checks the transaction locally.
///
/// Authentication arguments are unused. This component neither creates fee outputs nor checks
/// their funding. [`CreateNote`](crate::note::CreateNote) can supply a fee note.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuthPassthrough;

impl AuthPassthrough {
    /// The canonical component name.
    pub const NAME: &'static str = "miden::standards::auth::passthrough";

    /// Returns the component name.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the compiled component code.
    pub fn code() -> &'static AccountComponentCode {
        &PASSTHROUGH_PACKAGE.code
    }

    /// Returns the component metadata.
    pub fn component_metadata() -> AccountComponentMetadata {
        PASSTHROUGH_PACKAGE.metadata.clone()
    }
}

impl From<AuthPassthrough> for AccountComponent {
    fn from(_: AuthPassthrough) -> Self {
        AccountComponent::new(
            AuthPassthrough::code().clone(),
            vec![],
            AuthPassthrough::component_metadata(),
        )
        .expect("passthrough auth is a valid account component")
    }
}
