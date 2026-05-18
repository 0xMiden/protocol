use alloc::string::String;

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountProcedureRoot,
    AccountStorageMode,
};
use miden_protocol::errors::AccountError;
use thiserror::Error;

use super::AuthMethod;
use crate::account::account_component_code;
use crate::account::auth::{AuthMultisig, AuthMultisigConfig, AuthSingleSig};
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
/// This component supports all account types.
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

/// Creates a new account with basic wallet interface, the specified authentication scheme and the
/// account storage type. Basic wallets can be specified to have either mutable or immutable code.
///
/// The basic wallet interface exposes three procedures:
/// - `receive_asset`, which can be used to add an asset to the account.
/// - `move_asset_to_note`, which can be used to remove the specified asset from the account and add
///   it to the output note with the specified index.
///
/// All methods require authentication. The authentication procedure is defined by the specified
/// authentication scheme.
pub fn create_basic_wallet(
    init_seed: [u8; 32],
    auth_method: AuthMethod,
    account_storage_mode: AccountStorageMode,
) -> Result<Account, BasicWalletError> {
    let auth_component: AccountComponent = match auth_method {
        AuthMethod::SingleSig { approver: (pub_key, auth_scheme) } => {
            AuthSingleSig::new(pub_key, auth_scheme).into()
        },
        AuthMethod::Multisig { threshold, approvers } => {
            let config = AuthMultisigConfig::new(approvers, threshold)
                .and_then(|cfg| {
                    cfg.with_proc_thresholds(vec![(BasicWallet::receive_asset_root(), 1)])
                })
                .map_err(BasicWalletError::AccountError)?;
            AuthMultisig::new(config).map_err(BasicWalletError::AccountError)?.into()
        },
        AuthMethod::NoAuth => {
            return Err(BasicWalletError::UnsupportedAuthMethod(
                "basic wallets cannot be created with NoAuth authentication method".into(),
            ));
        },
        AuthMethod::NetworkAccount { .. } => {
            return Err(BasicWalletError::UnsupportedAuthMethod(
                "basic wallets cannot be created with NetworkAccount authentication method".into(),
            ));
        },
        AuthMethod::Unknown => {
            return Err(BasicWalletError::UnsupportedAuthMethod(
                "basic wallets cannot be created with Unknown authentication method".into(),
            ));
        },
    };

    let account = AccountBuilder::new(init_seed)
        .storage_mode(account_storage_mode)
        .with_auth_component(auth_component)
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

    use super::{Account, AccountStorageMode, AuthMethod, create_basic_wallet};
    use crate::account::wallets::BasicWallet;

    #[test]
    fn test_create_basic_wallet() {
        let pub_key = PublicKeyCommitment::from(Word::from([ONE; 4]));
        let auth_scheme = auth::AuthScheme::Falcon512Poseidon2;
        let wallet = create_basic_wallet(
            [1; 32],
            AuthMethod::SingleSig { approver: (pub_key, auth_scheme) },
            AccountStorageMode::Public,
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
            AuthMethod::SingleSig { approver: (pub_key, auth_scheme) },
            AccountStorageMode::Public,
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
