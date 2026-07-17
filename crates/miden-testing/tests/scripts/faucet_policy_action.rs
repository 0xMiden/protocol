//! Tests for the `FaucetPolicyAction` note, which switches a faucet's active `TokenPolicyManager`
//! policy (mint / burn / send / receive) to an allowed alternative.
//!
//! Integration coverage exercises the mint and burn dispatch branches (each switching `allow_all`
//! to `owner_only`) plus the note-level guards. The send and receive branches run the identical
//! script path (`load_policy_root_window` + a `set_*_policy` call) and differ only in selector and
//! call target, which are covered by the `faucet_policy_action` unit storage tests; there is no
//! built-in alternative `TransferPolicy` to switch to without bespoke policy setup.

extern crate alloc;

use alloc::vec::Vec;
use core::slice;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, AssetCallbackFlag};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::errors::standards::{
    ERR_FAUCET_POLICY_ACTION_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_FAUCET_POLICY_ACTION_UNKNOWN_SELECTOR,
};
use miden_standards::note::{FaucetPolicyAction, FaucetPolicyActionNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

// HELPERS
// ================================================================================================

/// Builds a fungible faucet whose `TokenPolicyManager` has an `owner_only` mint and burn policy
/// registered as an allowed alternative to the active `allow_all` policy. Pause / policy switches
/// are gated by `owner` via `Authority::OwnerControlled`.
fn create_faucet_with_policies(
    builder: &mut MockChainBuilder,
    owner: AccountId,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .allowed_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::allow_all())
        .allowed_burn_policy(BurnPolicy::owner_only())
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build();

    let account_builder = AccountBuilder::new([43; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner))
        .with_component(Authority::OwnerControlled)
        .with_asset_callbacks(AssetCallbackFlag::from(token_policy_manager.has_transfer_policy()))
        .with_components(token_policy_manager);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

fn active_mint_policy_root(account: &Account) -> anyhow::Result<Word> {
    Ok(account.storage().get_item(TokenPolicyManager::active_mint_policy_slot())?)
}

fn active_burn_policy_root(account: &Account) -> anyhow::Result<Word> {
    Ok(account.storage().get_item(TokenPolicyManager::active_burn_policy_slot())?)
}

/// Builds a [`FaucetPolicyActionNote`] for `action` sent by `sender` and targeting `account`.
fn faucet_policy_action_note(
    sender: AccountId,
    account: AccountId,
    action: FaucetPolicyAction,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = FaucetPolicyActionNote::builder()
        .sender(sender)
        .account(account)
        .action(action)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the FaucetPolicyAction script with hand-crafted storage, bypassing the
/// builder so malformed inputs can be exercised.
fn malformed_faucet_policy_action_note(
    sender: AccountId,
    storage: Vec<Felt>,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(FaucetPolicyActionNote::script())
        .note_storage(storage)?
        .build()?;
    Ok(note)
}

async fn execute_note_and_apply(
    mock_chain: &MockChain,
    account: &Account,
    note: &Note,
) -> anyhow::Result<Account> {
    let tx = mock_chain
        .build_tx_context(account.clone(), &[], slice::from_ref(note))?
        .build()?;
    let executed = tx.execute().await?;

    let mut updated = account.clone();
    updated.apply_patch(executed.account_patch())?;

    Ok(updated)
}

// TESTS
// ================================================================================================

/// The note dispatches SetMintPolicy: the owner switches the active mint policy to the allowed
/// `owner_only` alternative.
#[tokio::test]
async fn set_mint_policy_dispatch() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let mut builder = MockChain::builder();
    let faucet = create_faucet_with_policies(&mut builder, owner)?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let owner_only_root = MintPolicy::owner_only().root();
    assert_ne!(active_mint_policy_root(&faucet)?, owner_only_root.as_word());

    let note = faucet_policy_action_note(
        owner,
        faucet.id(),
        FaucetPolicyAction::SetMintPolicy { policy_root: owner_only_root },
        &mut rng,
    )?;
    let updated = execute_note_and_apply(&mock_chain, &faucet, &note).await?;

    assert_eq!(active_mint_policy_root(&updated)?, owner_only_root.as_word());
    Ok(())
}

/// The note dispatches SetBurnPolicy: the owner switches the active burn policy to the allowed
/// `owner_only` alternative.
#[tokio::test]
async fn set_burn_policy_dispatch() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let mut builder = MockChain::builder();
    let faucet = create_faucet_with_policies(&mut builder, owner)?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let owner_only_root = BurnPolicy::owner_only().root();
    assert_ne!(active_burn_policy_root(&faucet)?, owner_only_root.as_word());

    let note = faucet_policy_action_note(
        owner,
        faucet.id(),
        FaucetPolicyAction::SetBurnPolicy { policy_root: owner_only_root },
        &mut rng,
    )?;
    let updated = execute_note_and_apply(&mock_chain, &faucet, &note).await?;

    assert_eq!(active_burn_policy_root(&updated)?, owner_only_root.as_word());
    Ok(())
}

/// A note whose selector matches no known action is rejected by the script's dispatch guard.
#[tokio::test]
async fn unknown_selector_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let mut builder = MockChain::builder();
    let faucet = create_faucet_with_policies(&mut builder, owner)?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // selector 99 with a root-sized payload; 99 is not a known action
    let storage = vec![Felt::from(99u32), Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO];
    let note = malformed_faucet_policy_action_note(owner, storage, &mut rng)?;
    let tx = mock_chain
        .build_tx_context(faucet.clone(), &[], slice::from_ref(&note))?
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_FAUCET_POLICY_ACTION_UNKNOWN_SELECTOR);
    Ok(())
}

/// A note whose storage item count does not match its selector is rejected by the count guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let mut builder = MockChain::builder();
    let faucet = create_faucet_with_policies(&mut builder, owner)?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // SetMintPolicy selector (0) but only one storage item instead of the expected five
    let note = malformed_faucet_policy_action_note(owner, vec![Felt::from(0u32)], &mut rng)?;
    let tx = mock_chain
        .build_tx_context(faucet.clone(), &[], slice::from_ref(&note))?
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(
        result,
        ERR_FAUCET_POLICY_ACTION_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
    );
    Ok(())
}
