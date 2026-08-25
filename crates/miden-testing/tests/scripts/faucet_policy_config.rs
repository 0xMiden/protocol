//! Tests for the `FaucetPolicyConfig` note, which switches a faucet's active `TokenPolicyManager`
//! policy (mint / burn / send / receive) to an allowed alternative.
//!
//! Integration coverage exercises the mint and burn dispatch branches (each switching `allow_all`
//! to `owner_only`) plus the note-level guards. The send and receive branches run the identical
//! script path (`load_policy_root_window` + a `set_*_policy` call) and differ only in selector and
//! call target, which are covered by the `faucet_policy_config` unit storage tests; there is no
//! built-in alternative `TransferPolicy` to switch to without bespoke policy setup.

extern crate alloc;

use alloc::vec::Vec;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, AssetCallbackFlag};
use miden_protocol::asset::AssetAmount;
use miden_protocol::errors::protocol::ERR_NOTE_TOO_MANY_STORAGE_ITEMS;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS, Word};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::errors::standards::{
    ERR_FAUCET_POLICY_CONFIG_TARGET_ACCOUNT_MISMATCH,
    ERR_FAUCET_POLICY_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_FAUCET_POLICY_CONFIG_UNKNOWN_SELECTOR,
};
use miden_standards::note::{
    FaucetPolicyConfig,
    FaucetPolicyConfigNote,
    NetworkAccountTarget,
    NoteExecutionHint,
};
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

/// Builds a [`FaucetPolicyConfigNote`] for `config` sent by `sender` and targeting `account`.
fn faucet_policy_config_note(
    sender: AccountId,
    account: AccountId,
    config: FaucetPolicyConfig,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = FaucetPolicyConfigNote::builder()
        .sender(sender)
        .target(account)
        .config(config)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the FaucetPolicyConfig script with hand-crafted storage, bypassing the
/// builder so malformed inputs can be exercised.
///
/// It carries a `NetworkAccountTarget` for the consuming account, like a real config note, so
/// the note passes the script's target check and reaches the guard under test.
fn malformed_faucet_policy_config_note(
    sender: AccountId,
    target: AccountId,
    storage: Vec<Felt>,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(FaucetPolicyConfigNote::script())
        .note_storage(storage)?
        .attachment(NetworkAccountTarget::new(target, NoteExecutionHint::Always)?)
        .build()?;
    Ok(note)
}

async fn execute_note_and_apply(
    mock_chain: &MockChain,
    account: &Account,
    note: &Note,
) -> anyhow::Result<Account> {
    let tx = mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
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

    let note = faucet_policy_config_note(
        owner,
        faucet.id(),
        FaucetPolicyConfig::SetMintPolicy { policy_root: owner_only_root },
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

    let note = faucet_policy_config_note(
        owner,
        faucet.id(),
        FaucetPolicyConfig::SetBurnPolicy { policy_root: owner_only_root },
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

    // a root-sized payload followed by selector 99, which is not a known action
    let storage = vec![Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(99u32)];
    let note = malformed_faucet_policy_config_note(owner, faucet.id(), storage, &mut rng)?;
    let tx = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_FAUCET_POLICY_CONFIG_UNKNOWN_SELECTOR);
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

    // a single storage item instead of the expected five; the selector position reads as an
    // uninitialized zero, dispatching to SetMintPolicy, whose count guard then rejects the note
    let note =
        malformed_faucet_policy_config_note(owner, faucet.id(), vec![Felt::from(0u32)], &mut rng)?;
    let tx = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(
        result,
        ERR_FAUCET_POLICY_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
    );
    Ok(())
}

/// A note carrying more storage items than any action accepts is rejected before its storage is
/// loaded, so the work an oversized note can impose on whoever attempts to consume it is bounded by
/// the layout the script accepts rather than by `MAX_NOTE_STORAGE_ITEMS`.
#[tokio::test]
async fn oversized_storage_is_rejected_before_the_storage_is_loaded() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let mut builder = MockChain::builder();
    let faucet = create_faucet_with_policies(&mut builder, owner)?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    let storage = vec![Felt::from(0u32); MAX_NOTE_STORAGE_ITEMS];
    let note = malformed_faucet_policy_config_note(owner, faucet.id(), storage, &mut rng)?;
    let tx = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?;
    let result = tx.execute().await;

    assert_transaction_executor_error!(result, ERR_NOTE_TOO_MANY_STORAGE_ITEMS);
    Ok(())
}

/// The note is bound to its target faucet, so a decoy faucet cannot consume a note meant for
/// another one. The decoy carries the same `TokenPolicyManager` setup with the same owner, so the
/// sender-based authorization would pass; consuming a note targeted at a different faucet aborts at
/// the target check before any policy switch runs.
#[tokio::test]
async fn decoy_faucet_cannot_consume_note_of_another_faucet() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let mut builder = MockChain::builder();
    let decoy = create_faucet_with_policies(&mut builder, owner)?;
    let mock_chain = builder.build()?;
    let mut rng = RandomCoin::new([Felt::from(100u32); 4].into());

    // The note's intended target. It need not be built: the note only references its ID.
    let target = AccountId::builder().account_type(AccountType::Public).build_with_seed([9; 32]);

    let note = faucet_policy_config_note(
        owner,
        target,
        FaucetPolicyConfig::SetMintPolicy {
            policy_root: MintPolicy::owner_only().root(),
        },
        &mut rng,
    )?;
    let result = mock_chain
        .build_transaction(decoy.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FAUCET_POLICY_CONFIG_TARGET_ACCOUNT_MISMATCH);
    Ok(())
}
