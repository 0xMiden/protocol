use alloc::vec::Vec;

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

use crate::account::account_component_code;
use crate::account::auth::{
    Approver,
    ApproverSet,
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

// WALLET CREATION
// ================================================================================================

/// Creates a new account with a basic wallet interface, single signature authentication and the
/// specified account type.
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
    approver: Approver,
    account_type: AccountType,
) -> Result<Account, AccountError> {
    let auth_component: AccountComponent = AuthSingleSig::new(approver).into();

    create_wallet(init_seed, auth_component, account_type)
}

/// Creates a new account with a basic wallet interface, multi-signature authentication and the
/// specified account type.
///
/// Authentication is provided by an [`AuthMultisig`] component requiring the default threshold of
/// `approver_set` approver signatures, with optional per-procedure threshold overrides in
/// `proc_thresholds`.
///
/// # Security
///
/// See [`AuthMultisig`] for important caveats regarding per-procedure thresholds and private
/// account state withholding. For private accounts this constructor rejects per-procedure
/// thresholds below the default threshold (a lower threshold would let a sub-quorum advance and
/// withhold the private account state); public accounts allow any per-procedure threshold.
pub fn create_multisig_wallet(
    init_seed: [u8; 32],
    approver_set: ApproverSet,
    proc_thresholds: Vec<(AccountProcedureRoot, u32)>,
    account_type: AccountType,
) -> Result<Account, AccountError> {
    let default_threshold = approver_set.threshold().get();
    if account_type == AccountType::Private
        && proc_thresholds
            .iter()
            .any(|(_, proc_threshold)| *proc_threshold < default_threshold)
    {
        return Err(AccountError::other(
            "private multisig wallets do not allow per-procedure thresholds below the default \
             threshold, as a lower threshold would let a sub-quorum advance and withhold the \
             private account state; use a guarded wallet to lower thresholds safely",
        ));
    }

    let config = AuthMultisigConfig::new(approver_set).with_proc_thresholds(proc_thresholds)?;
    let auth_component: AccountComponent = AuthMultisig::new(config)?.into();

    create_wallet(init_seed, auth_component, account_type)
}

/// Creates a new account with a basic wallet interface, guarded multi-signature authentication and
/// the specified account type.
///
/// Authentication is provided by an [`AuthGuardedMultisig`] component: every operation requires
/// both the default threshold of `approver_set` approver signatures (with optional per-procedure
/// overrides in `proc_thresholds`) and a valid signature from the configured `guardian`.
pub fn create_guarded_wallet(
    init_seed: [u8; 32],
    approver_set: ApproverSet,
    proc_thresholds: Vec<(AccountProcedureRoot, u32)>,
    guardian: GuardianConfig,
    account_type: AccountType,
) -> Result<Account, AccountError> {
    let config = AuthGuardedMultisigConfig::new(approver_set, guardian)?
        .with_proc_thresholds(proc_thresholds)?;
    let auth_component: AccountComponent = AuthGuardedMultisig::new(config)?.into();

    create_wallet(init_seed, auth_component, account_type)
}

/// Creates a basic wallet account from the given authentication component and account type.
fn create_wallet(
    init_seed: [u8; 32],
    auth_component: AccountComponent,
    account_type: AccountType,
) -> Result<Account, AccountError> {
    AccountBuilder::new(init_seed)
        .account_type(account_type)
        .with_auth_component(auth_component)
        .with_component(BasicWallet)
        .build()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_protocol::account::auth::{self, PublicKeyCommitment};
    use miden_protocol::utils::serde::{Deserializable, Serializable};
    use miden_protocol::{ONE, Word};

    use super::{
        Account,
        AccountType,
        Approver,
        ApproverSet,
        GuardianConfig,
        create_basic_wallet,
        create_guarded_wallet,
        create_multisig_wallet,
    };
    use crate::account::wallets::BasicWallet;

    fn approver(seed: u32) -> Approver {
        Approver::new(
            PublicKeyCommitment::from(Word::from([seed, seed, seed, seed])),
            auth::AuthScheme::Falcon512Poseidon2,
        )
    }

    #[test]
    fn test_create_basic_wallet() -> anyhow::Result<()> {
        create_basic_wallet([1; 32], approver(1), AccountType::Public)?;
        Ok(())
    }

    #[test]
    fn test_serialize_basic_wallet() -> anyhow::Result<()> {
        let approver = Approver::new(
            PublicKeyCommitment::from(Word::from([ONE; 4])),
            auth::AuthScheme::EcdsaK256Keccak,
        );
        let wallet = create_basic_wallet([1; 32], approver, AccountType::Public)?;

        let bytes = wallet.to_bytes();
        let deserialized_wallet = Account::read_from_bytes(&bytes)?;
        assert_eq!(wallet, deserialized_wallet);

        Ok(())
    }

    #[test]
    fn test_create_multisig_wallet_public_allows_lower_override() -> anyhow::Result<()> {
        let approver_set = ApproverSet::new(vec![approver(1), approver(2)], 2)?;
        let proc_thresholds = vec![(BasicWallet::receive_asset_root(), 1)];

        // A public account may use a per-procedure threshold below the default.
        create_multisig_wallet([1; 32], approver_set, proc_thresholds, AccountType::Public)?;

        Ok(())
    }

    #[test]
    fn test_create_multisig_wallet_private_no_override_succeeds() -> anyhow::Result<()> {
        let approver_set = ApproverSet::new(vec![approver(1), approver(2)], 2)?;

        // No overrides is always allowed for private accounts.
        create_multisig_wallet([1; 32], approver_set, vec![], AccountType::Private)?;

        Ok(())
    }

    #[test]
    fn test_create_multisig_wallet_private_higher_override_succeeds() -> anyhow::Result<()> {
        let approver_set = ApproverSet::new(vec![approver(1), approver(2), approver(3)], 2)?;
        // Hardening a procedure above the default (2 -> 3) is safe for private accounts.
        let proc_thresholds = vec![(BasicWallet::move_asset_to_note_root(), 3)];

        create_multisig_wallet([1; 32], approver_set, proc_thresholds, AccountType::Private)?;

        Ok(())
    }

    #[test]
    fn test_create_multisig_wallet_private_lower_override_rejected() -> anyhow::Result<()> {
        let approver_set = ApproverSet::new(vec![approver(1), approver(2)], 2)?;
        let proc_thresholds = vec![(BasicWallet::receive_asset_root(), 1)];

        let err =
            create_multisig_wallet([1; 32], approver_set, proc_thresholds, AccountType::Private)
                .expect_err("private multisig with a below-default threshold must be rejected");

        assert!(
            err.to_string()
                .contains("do not allow per-procedure thresholds below the default threshold")
        );

        Ok(())
    }

    #[test]
    fn test_create_guarded_wallet_private_override_allowed() -> anyhow::Result<()> {
        let approver_set = ApproverSet::new(vec![approver(1), approver(2)], 2)?;
        let proc_thresholds = vec![(BasicWallet::receive_asset_root(), 1)];
        let guardian = GuardianConfig::new(approver(3));

        // The guardian forwards state, so a private guarded wallet may use overrides.
        create_guarded_wallet(
            [1; 32],
            approver_set,
            proc_thresholds,
            guardian,
            AccountType::Private,
        )?;

        Ok(())
    }

    /// Check that the obtaining of the basic wallet procedure roots does not panic.
    #[test]
    fn get_faucet_procedures() {
        let _receive_asset_root = BasicWallet::receive_asset_root();
        let _move_asset_to_note_root = BasicWallet::move_asset_to_note_root();
    }
}
