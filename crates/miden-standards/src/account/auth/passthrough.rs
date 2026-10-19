use miden_protocol::Word;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName};

use crate::account::account_component_code;

account_component_code!(PASSTHROUGH_CODE, "miden-standards-auth-passthrough.masp");

/// Permissionless authentication for a stateless passthrough account.
///
/// Transactions must leave the vault empty and the entire account state unchanged, including
/// storage, code, nonce and pending upgrades. Deployment alone increments the nonce once, after
/// checking these invariants. With a public account, anyone with the input witnesses can execute
/// a transaction; there is no signing key. Input note scripts must therefore constrain where
/// their assets go. Plain P2ID funding does not supply that protection.
///
/// A transaction must supply a sealed public TX_FEE output containing enough of the native fee
/// asset. [`Self::auth_args`] identifies that output. CREATE_NOTE can carry and create it. This
/// component never creates a second fee note. On a chain with zero fees, the index is ignored.
/// Consume private inputs with authentication and prove locally to keep their contents private.
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
