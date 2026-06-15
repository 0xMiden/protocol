use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
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
use crate::account::auth::{
    AuthGuardedMultisig,
    AuthGuardedMultisigConfig,
    AuthMultisig,
    AuthMultisigConfig,
    AuthSingleSig,
    GuardianConfig,
};
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

// WALLET ERROR
// ================================================================================================

/// Wallet creation related errors.
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("account creation failed")]
    AccountError(#[source] AccountError),
    #[error(
        "private multisig wallets require uniform thresholds, per-procedure threshold overrides \
         are not allowed for private accounts without a guardian"
    )]
    PrivateMultisigNonUniformThreshold,
}

// WALLET CREATION
// ================================================================================================

/// Creates a new account with a basic wallet interface, single signature authentication and the
/// specified account storage type.
///
/// The basic wallet interface exposes two procedures:
/// - `receive_asset`, which can be used to add an asset to the account.
/// - `move_asset_to_note`, which can be used to remove the specified asset from the account and add
///   it to the output note with the specified index.
///
/// All methods require authentication, which is provided by an [`AuthSingleSig`] component
/// configured with the given approver.
pub fn create_basic_wallet(
    init_seed: [u8; 32],
    approver: (PublicKeyCommitment, AuthScheme),
    account_storage_mode: AccountType,
) -> Result<Account, WalletError> {
    let (pub_key, auth_scheme) = approver;
    let auth_component: AccountComponent = AuthSingleSig::new(pub_key, auth_scheme).into();

    build_wallet(init_seed, auth_component, account_storage_mode)
}

/// Creates a new account with a basic wallet interface, multi-signature authentication and the
/// specified account storage type.
///
/// Authentication is provided by an [`AuthMultisig`] component requiring `threshold` approver
/// signatures by default, with optional per-procedure threshold overrides in `proc_thresholds`.
///
/// # Security
///
/// For private accounts, all thresholds must be uniform: per-procedure overrides that differ from
/// the default `threshold` are rejected with [`WalletError::PrivateMultisigNonUniformThreshold`].
/// A lower per-procedure threshold (e.g. `1` for `receive_asset`) would allow a single approver to
/// advance the private account state and withhold the update from the other approvers, locking
/// them out. Public accounts store their full state on-chain, so non-uniform thresholds are
/// permitted there. To use non-uniform thresholds on a private account, create a guarded wallet
/// with [`create_guarded_wallet`] instead.
pub fn create_multisig_wallet(
    init_seed: [u8; 32],
    threshold: u32,
    approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
    proc_thresholds: Vec<(AccountProcedureRoot, u32)>,
    account_storage_mode: AccountType,
) -> Result<Account, WalletError> {
    if account_storage_mode == AccountType::Private
        && proc_thresholds.iter().any(|(_, proc_threshold)| *proc_threshold != threshold)
    {
        return Err(WalletError::PrivateMultisigNonUniformThreshold);
    }

    let config = AuthMultisigConfig::new(approvers, threshold)
        .and_then(|cfg| cfg.with_proc_thresholds(proc_thresholds))
        .map_err(WalletError::AccountError)?;
    let auth_component: AccountComponent =
        AuthMultisig::new(config).map_err(WalletError::AccountError)?.into();

    build_wallet(init_seed, auth_component, account_storage_mode)
}

/// Creates a new account with a basic wallet interface, guarded multi-signature authentication and
/// the specified account storage type.
///
/// Authentication is provided by an [`AuthGuardedMultisig`] component: every operation requires
/// both `threshold` approver signatures (with optional per-procedure overrides in
/// `proc_thresholds`) and a valid signature from the configured `guardian`.
///
/// Because the guardian is expected to forward state updates to the other approvers, non-uniform
/// thresholds (including a per-procedure threshold of `1`) are safe even for private accounts, so
/// no uniformity check is applied here.
pub fn create_guarded_wallet(
    init_seed: [u8; 32],
    threshold: u32,
    approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
    proc_thresholds: Vec<(AccountProcedureRoot, u32)>,
    guardian: GuardianConfig,
    account_storage_mode: AccountType,
) -> Result<Account, WalletError> {
    let config = AuthGuardedMultisigConfig::new(approvers, threshold, guardian)
        .and_then(|cfg| cfg.with_proc_thresholds(proc_thresholds))
        .map_err(WalletError::AccountError)?;
    let auth_component: AccountComponent =
        AuthGuardedMultisig::new(config).map_err(WalletError::AccountError)?.into();

    build_wallet(init_seed, auth_component, account_storage_mode)
}

/// Builds a basic wallet account from the given authentication component and storage mode.
fn build_wallet(
    init_seed: [u8; 32],
    auth_component: AccountComponent,
    account_storage_mode: AccountType,
) -> Result<Account, WalletError> {
    AccountBuilder::new(init_seed)
        .account_type(account_storage_mode)
        .with_auth_component(auth_component)
        .with_component(BasicWallet)
        .build()
        .map_err(WalletError::AccountError)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::auth::{self, PublicKeyCommitment};
    use miden_protocol::utils::serde::{Deserializable, Serializable};
    use miden_protocol::{ONE, Word};

    use super::{
        Account,
        AccountType,
        GuardianConfig,
        WalletError,
        create_basic_wallet,
        create_guarded_wallet,
        create_multisig_wallet,
    };
    use crate::account::wallets::BasicWallet;

    fn pub_key(seed: u32) -> PublicKeyCommitment {
        PublicKeyCommitment::from(Word::from([seed, seed, seed, seed]))
    }

    #[test]
    fn test_create_basic_wallet() {
        let auth_scheme = auth::AuthScheme::Falcon512Poseidon2;
        let wallet = create_basic_wallet([1; 32], (pub_key(1), auth_scheme), AccountType::Public);

        wallet.unwrap_or_else(|err| {
            panic!("{}", err);
        });
    }

    #[test]
    fn test_serialize_basic_wallet() {
        let auth_scheme = auth::AuthScheme::EcdsaK256Keccak;
        let wallet = create_basic_wallet(
            [1; 32],
            (PublicKeyCommitment::from(Word::from([ONE; 4])), auth_scheme),
            AccountType::Public,
        )
        .unwrap();

        let bytes = wallet.to_bytes();
        let deserialized_wallet = Account::read_from_bytes(&bytes).unwrap();
        assert_eq!(wallet, deserialized_wallet);
    }

    #[test]
    fn test_create_multisig_wallet_public_allows_overrides() {
        let auth_scheme = auth::AuthScheme::Falcon512Poseidon2;
        let approvers = vec![(pub_key(1), auth_scheme), (pub_key(2), auth_scheme)];
        let proc_thresholds = vec![(BasicWallet::receive_asset_root(), 1)];

        // A public account may use a per-procedure threshold lower than the default.
        create_multisig_wallet([1; 32], 2, approvers, proc_thresholds, AccountType::Public)
            .unwrap_or_else(|err| panic!("{}", err));
    }

    #[test]
    fn test_create_multisig_wallet_private_uniform_succeeds() {
        let auth_scheme = auth::AuthScheme::Falcon512Poseidon2;
        let approvers = vec![(pub_key(1), auth_scheme), (pub_key(2), auth_scheme)];

        // No overrides => uniform thresholds, allowed for private accounts.
        create_multisig_wallet([1; 32], 2, approvers, vec![], AccountType::Private)
            .unwrap_or_else(|err| panic!("{}", err));
    }

    #[test]
    fn test_create_multisig_wallet_private_override_rejected() {
        let auth_scheme = auth::AuthScheme::Falcon512Poseidon2;
        let approvers = vec![(pub_key(1), auth_scheme), (pub_key(2), auth_scheme)];
        let proc_thresholds = vec![(BasicWallet::receive_asset_root(), 1)];

        let err =
            create_multisig_wallet([1; 32], 2, approvers, proc_thresholds, AccountType::Private)
                .expect_err("private multisig with a non-uniform threshold must be rejected");

        assert!(matches!(err, WalletError::PrivateMultisigNonUniformThreshold));
    }

    #[test]
    fn test_create_guarded_wallet_private_override_allowed() {
        let auth_scheme = auth::AuthScheme::Falcon512Poseidon2;
        let approvers = vec![(pub_key(1), auth_scheme), (pub_key(2), auth_scheme)];
        let proc_thresholds = vec![(BasicWallet::receive_asset_root(), 1)];
        let guardian = GuardianConfig::new(pub_key(3), auth_scheme);

        // The guardian forwards state, so a private guarded wallet may use overrides.
        create_guarded_wallet(
            [1; 32],
            2,
            approvers,
            proc_thresholds,
            guardian,
            AccountType::Private,
        )
        .unwrap_or_else(|err| panic!("{}", err));
    }

    /// Check that the obtaining of the basic wallet procedure roots does not panic.
    #[test]
    fn get_faucet_procedures() {
        let _receive_asset_root = BasicWallet::receive_asset_root();
        let _move_asset_to_note_root = BasicWallet::move_asset_to_note_root();
    }
}
