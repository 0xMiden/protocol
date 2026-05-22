use alloc::string::String;

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountComponentName,
    AccountProcedureRoot,
    AccountType,
};
use miden_protocol::errors::AccountError;
use thiserror::Error;

use crate::account::account_component_code;
use crate::account::auth::{AccountAuthComponent, AccountAuthScheme};
use crate::procedure_root;

// BASIC WALLET
// ================================================================================================

account_component_code!(BASIC_WALLET_CODE, "wallets/basic_wallet.masl");

// Initialize the procedure root of the `receive_asset` procedure of the Basic Wallet only once.
procedure_root!(
    BASIC_WALLET_RECEIVE_ASSET,
    BasicWallet::NAME,
    BasicWallet::RECEIVE_ASSET_PROC_NAME,
    BasicWallet::code()
);

// Initialize the procedure root of the `move_asset_to_note` procedure of the Basic Wallet only
// once.
procedure_root!(
    BASIC_WALLET_MOVE_ASSET_TO_NOTE,
    BasicWallet::NAME,
    BasicWallet::MOVE_ASSET_TO_NOTE_PROC_NAME,
    BasicWallet::code()
);

/// An [`AccountComponent`] implementing a basic wallet.
///
/// It reexports the procedures from `miden::standards::wallets::basic`. When linking against this
/// component, the `miden` library (i.e. [`ProtocolLib`](miden_protocol::ProtocolLib)) must be
/// available to the assembler which is the case when using [`CodeBuilder`][builder]. The procedures
/// of this component are:
/// - `receive_asset`, which can be used to add an asset to the account.
/// - `move_asset_to_note`, which can be used to remove the specified asset from the account and add
///   it to the output note with the specified index.
///
/// All methods require authentication. Thus, this component must be combined with a component
/// providing authentication.
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct BasicWallet;

impl BasicWallet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::wallets::basic_wallet";

    const RECEIVE_ASSET_PROC_NAME: &str = "receive_asset";
    const MOVE_ASSET_TO_NOTE_PROC_NAME: &str = "move_asset_to_note";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &BASIC_WALLET_CODE
    }

    /// Returns the procedure root of the `receive_asset` wallet procedure.
    pub fn receive_asset_root() -> AccountProcedureRoot {
        *BASIC_WALLET_RECEIVE_ASSET
    }

    /// Returns the procedure root of the `move_asset_to_note` wallet procedure.
    pub fn move_asset_to_note_root() -> AccountProcedureRoot {
        *BASIC_WALLET_MOVE_ASSET_TO_NOTE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME)
            .with_description("Basic wallet component for receiving and sending assets")
    }
}

impl From<BasicWallet> for AccountComponent {
    fn from(_: BasicWallet) -> Self {
        let metadata = BasicWallet::component_metadata();

        AccountComponent::new(BasicWallet::code().clone(), vec![], metadata).expect(
            "basic wallet component should satisfy the requirements of a valid account component",
        )
    }
}

// BASIC WALLET ERROR
// ================================================================================================

/// Basic wallet related errors.
#[derive(Debug, Error)]
pub enum BasicWalletError {
    #[error("unsupported authentication method: {0}")]
    UnsupportedAuthMethod(String),
    #[error("account creation failed")]
    AccountError(#[source] AccountError),
}

/// Creates a new account with the basic wallet interface and the specified authentication
/// component.
///
/// The basic wallet interface exposes two procedures:
/// - `receive_asset`, which can be used to add an asset to the account.
/// - `move_asset_to_note`, which can be used to remove the specified asset from the account and add
///   it to the output note with the specified index.
///
/// All methods require authentication. The caller provides any [`AccountAuthComponent`]; this
/// factory rejects schemes that don't make sense for a basic wallet (`NoAuth` and
/// `NetworkAccount`), and accepts SingleSig, Multisig variants, and Custom components.
pub fn create_basic_wallet(
    init_seed: [u8; 32],
    auth_component: AccountAuthComponent,
    account_type: AccountType,
) -> Result<Account, BasicWalletError> {
    match auth_component.scheme() {
        AccountAuthScheme::SingleSig
        | AccountAuthScheme::SingleSigAcl
        | AccountAuthScheme::Multisig
        | AccountAuthScheme::GuardedMultisig
        | AccountAuthScheme::MultisigSmart
        | AccountAuthScheme::Custom => {},
        AccountAuthScheme::NoAuth => {
            return Err(BasicWalletError::UnsupportedAuthMethod(
                "basic wallets cannot be created with NoAuth authentication method".into(),
            ));
        },
        AccountAuthScheme::NetworkAccount => {
            return Err(BasicWalletError::UnsupportedAuthMethod(
                "basic wallets cannot be created with NetworkAccount authentication method".into(),
            ));
        },
    }

    let account = AccountBuilder::new(init_seed)
        .account_type(account_type)
        .with_auth_component(auth_component.into_inner())
        .with_component(BasicWallet)
        .build()
        .map_err(BasicWalletError::AccountError)?;

    Ok(account)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::auth::{self, PublicKeyCommitment};
    use miden_protocol::utils::serde::{Deserializable, Serializable};
    use miden_protocol::{ONE, Word};

    use super::{Account, AccountType, create_basic_wallet};
    use crate::account::auth::AccountAuthComponent;
    use crate::account::wallets::BasicWallet;

    #[test]
    fn test_create_basic_wallet() {
        let pub_key = PublicKeyCommitment::from(Word::from([ONE; 4]));
        let auth_scheme = auth::AuthScheme::Falcon512Poseidon2;
        let wallet = create_basic_wallet(
            [1; 32],
            AccountAuthComponent::single_sig(pub_key, auth_scheme),
            AccountType::Public,
        );

        wallet.unwrap_or_else(|err| {
            panic!("{}", err);
        });
    }

    #[test]
    fn test_serialize_basic_wallet() {
        let pub_key = PublicKeyCommitment::from(Word::from([ONE; 4]));
        let auth_scheme = auth::AuthScheme::EcdsaK256Keccak;
        let wallet = create_basic_wallet(
            [1; 32],
            AccountAuthComponent::single_sig(pub_key, auth_scheme),
            AccountType::Public,
        )
        .unwrap();

        let bytes = wallet.to_bytes();
        let deserialized_wallet = Account::read_from_bytes(&bytes).unwrap();
        assert_eq!(wallet, deserialized_wallet);
    }

    /// Check that the obtaining of the basic wallet procedure roots does not panic.
    #[test]
    fn get_faucet_procedures() {
        let _receive_asset_root = BasicWallet::receive_asset_root();
        let _move_asset_to_note_root = BasicWallet::move_asset_to_note_root();
    }
}
