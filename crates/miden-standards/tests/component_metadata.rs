//! Checks the account component metadata that the components declare in their `miden-project.toml`
//! manifests and that the build script embeds into their packages.

use miden_protocol::account::component::AccountComponentMetadata;
use miden_standards::account::access::{
    Authority,
    Ownable2Step,
    Pausable,
    PausableManager,
    RoleBasedAccessControl,
};
use miden_standards::account::auth::{
    AuthGuardedMultisig,
    AuthMultisig,
    AuthMultisigSmart,
    AuthNetworkAccount,
    AuthSingleSig,
    NoAuth,
};
use miden_standards::account::faucets::{FungibleFaucet, NonFungibleFaucet};
use miden_standards::account::fees::{BasicConstantFeePolicy, ConstantFeeManager};
use miden_standards::account::inspection::{AccountSchemaCommitment, CodeInspection};
use miden_standards::account::note_creator::NoteCreator;
use miden_standards::account::policies::{
    AllowlistManager,
    BasicAllowlist,
    BasicBlocklist,
    BlocklistManager,
    BurnAllowAll,
    BurnOwnerOnly,
    MinBurnAmount,
    MintAllowAll,
    MintOwnerOnly,
    TokenPolicyManager,
    TransferAllowAll,
};
use miden_standards::account::upgrade::UpgradeManager;
use miden_standards::account::wallets::BasicWallet;

/// Returns every standard component's declared name paired with the metadata read back from its
/// package.
fn components() -> Vec<(&'static str, AccountComponentMetadata)> {
    vec![
        (Authority::NAME, Authority::AuthControlled.component_metadata()),
        (Ownable2Step::NAME, Ownable2Step::component_metadata()),
        (Pausable::NAME, Pausable::component_metadata()),
        (PausableManager::NAME, PausableManager::component_metadata()),
        (RoleBasedAccessControl::NAME, RoleBasedAccessControl::component_metadata()),
        (AuthGuardedMultisig::NAME, AuthGuardedMultisig::component_metadata()),
        (AuthMultisig::NAME, AuthMultisig::component_metadata()),
        (AuthMultisigSmart::NAME, AuthMultisigSmart::component_metadata()),
        (AuthNetworkAccount::NAME, AuthNetworkAccount::component_metadata()),
        (NoAuth::NAME, NoAuth::component_metadata()),
        (AuthSingleSig::NAME, AuthSingleSig::component_metadata()),
        (FungibleFaucet::NAME, FungibleFaucet::component_metadata()),
        (NonFungibleFaucet::NAME, NonFungibleFaucet::component_metadata()),
        (BurnAllowAll::NAME, BurnAllowAll::component_metadata()),
        (MinBurnAmount::NAME, MinBurnAmount::component_metadata()),
        (BurnOwnerOnly::NAME, BurnOwnerOnly::component_metadata()),
        (MintAllowAll::NAME, MintAllowAll::component_metadata()),
        (MintOwnerOnly::NAME, MintOwnerOnly::component_metadata()),
        (TokenPolicyManager::NAME, TokenPolicyManager::component_metadata()),
        (TransferAllowAll::NAME, TransferAllowAll::component_metadata()),
        (AllowlistManager::NAME, AllowlistManager::component_metadata()),
        (BasicAllowlist::NAME, BasicAllowlist::component_metadata()),
        (BasicBlocklist::NAME, BasicBlocklist::component_metadata()),
        (BlocklistManager::NAME, BlocklistManager::component_metadata()),
        (BasicConstantFeePolicy::NAME, BasicConstantFeePolicy::component_metadata()),
        (ConstantFeeManager::NAME, ConstantFeeManager::component_metadata()),
        (CodeInspection::NAME, CodeInspection::component_metadata()),
        (AccountSchemaCommitment::NAME, AccountSchemaCommitment::component_metadata()),
        (NoteCreator::NAME, NoteCreator::component_metadata()),
        (UpgradeManager::NAME, UpgradeManager::component_metadata()),
        (BasicWallet::NAME, BasicWallet::component_metadata()),
    ]
}

/// The name a component declares in its manifest is what the rest of the crate refers to it by, so
/// the two must not drift apart.
#[test]
fn manifest_name_matches_component_name() {
    for (name, metadata) in components() {
        assert_eq!(metadata.name(), name);
    }
}

/// Every component must describe itself, otherwise the metadata carried by its package tells a
/// consumer nothing about what it does.
#[test]
fn every_component_is_described() {
    for (name, metadata) in components() {
        assert!(!metadata.description().is_empty(), "{name} declares no description");
    }
}
