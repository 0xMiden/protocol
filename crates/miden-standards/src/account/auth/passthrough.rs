use miden_protocol::Word;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName};

use crate::account::account_component_code;

account_component_code!(PASSTHROUGH_CODE, "miden-standards-auth-passthrough.masp");

/// Permissionless authentication for a stateless passthrough account.
///
/// Transactions must preserve the account state and leave the vault empty. Deployment alone
/// increments the nonce once. Anyone with the input witnesses can execute against a public
/// account, so input note scripts must constrain their outputs; plain P2ID funding is unsuitable.
///
/// [`Self::auth_args`] selects a public TX_FEE output covering the transaction's native
/// fee. [`CreateNote`](crate::note::CreateNote) can fund it. This component creates no fee output;
/// the selected note must cover the fee in full. On chains with zero fees, the index is ignored.
/// The check runs after the transaction script, so the selected output need not be sealed.
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
        &PASSTHROUGH_CODE
    }

    /// Returns the component metadata.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME)
            .with_description("Permissionless stateless passthrough authentication")
    }

    /// Selects the output that pays for this transaction. All other auth arguments are zero.
    pub fn auth_args(fee_note_index: u16) -> Word {
        Word::from([u32::from(fee_note_index), 0, 0, 0])
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
