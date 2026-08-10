//! Tests that the faucet factories wire up asset callbacks consistently with the
//! [`TokenPolicyManager`] they are given.
//!
//! The kernel decides whether to invoke a faucet's `on_before_asset_added_to_*` callbacks purely
//! from the `AssetCallbackFlag` encoded in the issuing faucet's account ID, and those callbacks are
//! the only path that reaches a `TokenPolicyManager`'s send / receive policies. Since the flag is
//! ground into the ID at creation and is immutable, a factory that leaves it disabled while
//! installing the callback slots produces a faucet whose transfer policies (and the pause check
//! they carry) can never be enforced, for its entire supply. These tests therefore drive a
//! factory-built faucet's policy through a real transaction rather than only inspecting storage.

extern crate alloc;

use alloc::vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::{Account, AccountId, AccountType, AssetCallbackFlag};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{Approver, GuardianConfig};
use miden_standards::account::faucets::{
    FungibleFaucet,
    TokenName,
    create_guarded_user_fungible_faucet,
    create_multisig_user_fungible_faucet,
};
use miden_standards::account::policies::{
    AllowlistStorage,
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::errors::standards::ERR_ACCOUNT_IS_NOT_ALLOWED;
use miden_standards::testing::faucet::{user_faucet_guarded, user_faucet_multisig};
use miden_testing::{
    Auth,
    MockChain,
    MockChainBuilder,
    MockTransaction,
    assert_transaction_executor_error,
};

// HELPERS
// ================================================================================================

/// Builds `n` distinct approvers for the multisig / guarded auth components.
fn sample_approvers(n: u32) -> vec::Vec<(PublicKeyCommitment, AuthScheme)> {
    (0..n)
        .map(|i| {
            (
                PublicKeyCommitment::from(Word::new([Felt::from(i + 1); 4])),
                AuthScheme::Falcon512Poseidon2,
            )
        })
        .collect()
}

/// A [`TokenPolicyManager`] whose send and receive policies are an allowlist seeded with
/// `initial_allowed`, so `has_transfer_policy` is true and the factory must enable asset callbacks.
fn allowlist_policy_manager(
    initial_allowed: impl IntoIterator<Item = AccountId>,
) -> TokenPolicyManager {
    let allow_list = AllowlistStorage::with_allowed_accounts(initial_allowed);

    TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(TransferPolicy::with_basic_allowlist(allow_list.clone()))
        .active_receive_policy(TransferPolicy::with_basic_allowlist(allow_list))
        .build()
}

fn sample_faucet() -> anyhow::Result<FungibleFaucet> {
    Ok(FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?)
}

/// Registers a factory-built faucet in the chain's genesis state. The faucet never executes a
/// transaction in these tests, it is only read as a foreign account when the kernel dispatches the
/// receive callback, so it needs no authenticator.
///
/// Genesis accounts must be existing accounts, so the nonce is bumped to drop the creation seed.
/// The account ID is left untouched, which is what carries the asset callback flag under test.
fn add_factory_faucet(builder: &mut MockChainBuilder, mut faucet: Account) -> anyhow::Result<()> {
    faucet.set_nonce(Felt::ONE)?;
    builder.add_account(faucet)
}

/// Builds the transaction in which `recipient` consumes a P2ID note carrying `faucet_id`'s asset.
/// The kernel runs the faucet's `on_before_asset_added_to_account` callback (and thus its receive
/// policy) while the recipient adds the asset to its vault.
fn build_receive_asset_tx(
    mut builder: MockChainBuilder,
    faucet_id: AccountId,
    recipient: AccountId,
) -> anyhow::Result<MockTransaction> {
    let asset = FungibleAsset::new(faucet_id, 100)?;
    let note =
        builder.add_p2id_note(faucet_id, recipient, &[Asset::Fungible(asset)], NoteType::Public)?;

    let mock_chain = builder.build()?;
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet_id)?;

    mock_chain
        .build_transaction(recipient)
        .authenticated_input_note(note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()
}

// TESTS
// ================================================================================================

/// A faucet built by [`create_multisig_user_fungible_faucet`] with an allowlist receive policy must
/// actually block a recipient that is not on the allowlist. This fails if the factory omits the
/// asset callback flag, because the kernel then skips the callback and the policy never runs.
#[tokio::test]
async fn multisig_factory_faucet_enforces_receive_allowlist() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet = create_multisig_user_fungible_faucet(
        [43u8; 32],
        sample_faucet()?,
        user_faucet_multisig(sample_approvers(3), 2)?,
        allowlist_policy_manager([]),
        AccountType::Public,
    )?;
    assert_eq!(faucet.id().asset_callback_flag(), AssetCallbackFlag::Enabled);

    let faucet_id = faucet.id();
    add_factory_faucet(&mut builder, faucet)?;

    let result = build_receive_asset_tx(builder, faucet_id, target_account.id())?.execute().await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_NOT_ALLOWED);

    Ok(())
}

/// The same faucet accepts a recipient that is on the allowlist, so the previous test pins policy
/// enforcement rather than an unrelated failure.
#[tokio::test]
async fn multisig_factory_faucet_allows_allowlisted_recipient() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet = create_multisig_user_fungible_faucet(
        [43u8; 32],
        sample_faucet()?,
        user_faucet_multisig(sample_approvers(3), 2)?,
        allowlist_policy_manager([target_account.id()]),
        AccountType::Public,
    )?;

    let faucet_id = faucet.id();
    add_factory_faucet(&mut builder, faucet)?;

    build_receive_asset_tx(builder, faucet_id, target_account.id())?
        .execute()
        .await?;

    Ok(())
}

/// Same as [`multisig_factory_faucet_enforces_receive_allowlist`] for the guarded-multisig factory.
#[tokio::test]
async fn guarded_factory_faucet_enforces_receive_allowlist() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let guardian = GuardianConfig::new(Approver::new(
        PublicKeyCommitment::from(Word::new([Felt::from(99_u32); 4])),
        AuthScheme::Falcon512Poseidon2,
    ));
    let faucet = create_guarded_user_fungible_faucet(
        [44u8; 32],
        sample_faucet()?,
        user_faucet_guarded(sample_approvers(3), 2, guardian)?,
        allowlist_policy_manager([]),
        AccountType::Public,
    )?;
    assert_eq!(faucet.id().asset_callback_flag(), AssetCallbackFlag::Enabled);

    let faucet_id = faucet.id();
    add_factory_faucet(&mut builder, faucet)?;

    let result = build_receive_asset_tx(builder, faucet_id, target_account.id())?.execute().await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_NOT_ALLOWED);

    Ok(())
}
