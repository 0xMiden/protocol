//! Tests for the `MinBurnAmountConfig` note, which updates the threshold of a faucet's
//! `min_burn_amount` burn policy.
//!
//! The policy behaviour itself (a burn below / at the threshold, the non-owner rejection of
//! `set_min_burn_amount`, and the getter) is covered by the `min_burn_amount` tests in the
//! `faucet` suite; this suite covers what the note adds on top: the storage payload the script
//! forwards and the guards that reject a malformed or wrongly targeted note.

extern crate alloc;

use alloc::vec::Vec;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::AssetAmount;
use miden_protocol::errors::protocol::ERR_NOTE_TOO_MANY_STORAGE_ITEMS;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS, Word};
use miden_standards::account::access::AccessControl;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicy,
    MinBurnAmount,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::errors::standards::{
    ERR_MIN_BURN_AMOUNT_CONFIG_NOTE_IS_NOT_PUBLIC,
    ERR_MIN_BURN_AMOUNT_CONFIG_TARGET_ACCOUNT_MISMATCH,
    ERR_MIN_BURN_AMOUNT_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
};
use miden_standards::note::{MinBurnAmountConfigNote, NetworkAccountTarget, NoteExecutionHint};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use crate::into_private_note;

// HELPERS
// ================================================================================================

/// The minimum burn amount the faucet fixture is created with.
const INITIAL_MIN_BURN_AMOUNT: u64 = 50;

/// Builds a fungible faucet whose active burn policy is `min_burn_amount`, gated by `owner` via
/// `Authority::OwnerControlled` (installed by `AccessControl::Ownable2Step`).
fn create_faucet_with_min_burn_amount(owner: AccountId) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::min_burn_amount(AssetAmount::new(INITIAL_MIN_BURN_AMOUNT)?))
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build();

    let account = AccountBuilder::new([43; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(faucet)
        .with_components(token_policy_manager)
        .build_existing()?;

    Ok(account)
}

/// Returns the minimum burn amount configured on `account`.
fn min_burn_amount(account: &Account) -> anyhow::Result<Word> {
    Ok(account.storage().get_item(MinBurnAmount::slot_name())?)
}

/// Builds a [`MinBurnAmountConfigNote`] setting `amount` on `account`, sent by `sender`.
fn min_burn_amount_config_note(
    sender: AccountId,
    account: AccountId,
    amount: u64,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = MinBurnAmountConfigNote::builder()
        .sender(sender)
        .target(account)
        .min_burn_amount(AssetAmount::new(amount)?)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the MinBurnAmountConfig script with hand-crafted storage, bypassing the
/// builder so malformed inputs can be exercised.
///
/// It carries a `NetworkAccountTarget` for the consuming account, like a real config note, so the
/// note passes the script's target check and reaches the guard under test.
fn malformed_min_burn_amount_config_note(
    sender: AccountId,
    target: AccountId,
    storage: Vec<Felt>,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(MinBurnAmountConfigNote::script())
        .note_storage(storage)?
        .attachment(NetworkAccountTarget::new(target, NoteExecutionHint::Always)?)
        .build()?;
    Ok(note)
}

// TESTS
// ================================================================================================

/// The note forwards its stored threshold to `set_min_burn_amount`: the owner lowers the faucet's
/// minimum burn amount, and the component's slot holds the new value afterwards.
#[tokio::test]
async fn owner_sets_min_burn_amount() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let faucet = create_faucet_with_min_burn_amount(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    assert_eq!(min_burn_amount(&faucet)?, Word::from([INITIAL_MIN_BURN_AMOUNT as u32, 0, 0, 0]));

    let note = min_burn_amount_config_note(owner, faucet.id(), 5, &mut rng)?;
    let executed = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await?;

    let mut updated = faucet.clone();
    updated.apply_patch(executed.account_patch())?;

    assert_eq!(min_burn_amount(&updated)?, Word::from([5u32, 0, 0, 0]));
    Ok(())
}

/// A note whose storage does not carry exactly the single threshold item is rejected by the count
/// guard, before anything is written to the faucet.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let faucet = create_faucet_with_min_burn_amount(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // no threshold at all instead of the expected single item
    let note = malformed_min_burn_amount_config_note(owner, faucet.id(), Vec::new(), &mut rng)?;
    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_MIN_BURN_AMOUNT_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
    );
    Ok(())
}

/// A note carrying more storage items than the script accepts is rejected before its storage is
/// loaded, so the work an oversized note can impose on whoever attempts to consume it is bounded by
/// the layout the script accepts rather than by `MAX_NOTE_STORAGE_ITEMS`.
#[tokio::test]
async fn oversized_storage_is_rejected_before_the_storage_is_loaded() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let faucet = create_faucet_with_min_burn_amount(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let storage = vec![Felt::from(0u32); MAX_NOTE_STORAGE_ITEMS];
    let note = malformed_min_burn_amount_config_note(owner, faucet.id(), storage, &mut rng)?;
    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_TOO_MANY_STORAGE_ITEMS);
    Ok(())
}

/// The note is bound to its target account, so a decoy account cannot consume a note meant for
/// another account. The decoy carries the same `min_burn_amount` setup with the same owner, so the
/// sender-based authorization would pass; consuming a note targeted at a different account aborts
/// at the target check before the threshold changes.
#[tokio::test]
async fn decoy_account_cannot_consume_note_of_another_account() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let decoy = create_faucet_with_min_burn_amount(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(decoy.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // The note's intended target. It need not be built: the note only references its ID.
    let target = AccountId::builder().account_type(AccountType::Public).build_with_seed([9; 32]);

    let note = min_burn_amount_config_note(owner, target, 5, &mut rng)?;
    let result = mock_chain
        .build_transaction(decoy.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_MIN_BURN_AMOUNT_CONFIG_TARGET_ACCOUNT_MISMATCH);
    Ok(())
}

/// The management action must stay publicly auditable: a private note carrying the same script and
/// storage as a legitimate config note is rejected before the threshold changes.
#[tokio::test]
async fn private_note_cannot_dispatch_the_action() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let account = create_faucet_with_min_burn_amount(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let note = min_burn_amount_config_note(owner, account.id(), 5, &mut rng)?;
    let result = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(into_private_note(note))
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_MIN_BURN_AMOUNT_CONFIG_NOTE_IS_NOT_PUBLIC);
    Ok(())
}
