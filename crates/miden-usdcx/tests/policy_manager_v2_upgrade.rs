//! The upgrade of the faucet from the V1 to the V2 token policy manager.
//!
//! The faucet issues the network's fee asset, and every fee note triggers its send callback. The V1
//! callback checks the pause flag, so a paused faucet blocks every fee payment, including the one
//! of the transaction that creates the unpause note. The V2 callback does not check the pause
//! flag.
//!
//! In these tests, the faucet is the chain's fee faucet and pays its own fees from its vault, and a
//! wallet pays its fees in the faucet's asset.

mod support;

use anyhow::Result;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountCode, AccountId, AccountType};
use miden_protocol::asset::{AssetCallbacks, AssetVault, FungibleAsset};
use miden_protocol::errors::tx_kernel::ERR_FAUCET_CALLBACK_PROC_ROOT_NOT_PART_OF_ACCOUNT_CODE;
use miden_protocol::note::Note;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_standards::account::access::PausableStorage;
use miden_standards::account::auth::NoAuth;
use miden_standards::account::policies::{TokenPolicyManager, TokenPolicyManagerV2};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::ERR_PAUSABLE_IS_PAUSED;
use miden_standards::note::config::{
    ConstantFeePolicyConfigNote,
    NetworkAccountConfig,
    NetworkAccountConfigNote,
    PauseConfig,
    PauseConfigNote,
    TokenPolicyManagerV2MigrationNote,
};
use miden_standards::note::{TxFeeNote, UpgradeNote};
use miden_testing::{MockChain, MockChainBuilder, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_usdcx::account::xreserve::XReserveStablecoinBuilder;
use support::{TEST_DOMAIN, production_builder, test_account_id, test_fee_faucet_id};

const VERIFICATION_BASE_FEE: u32 = 500;
const FAUCET_FEE_BALANCE: u64 = 1_000_000_000;
const WALLET_BALANCE: u64 = 1_000_000_000;

fn administrator() -> AccountId {
    test_account_id(1)
}

fn dom_pauser() -> AccountId {
    test_account_id(2)
}

fn dom_unpauser() -> AccountId {
    test_account_id(3)
}

fn serial_number(seed: u32) -> Word {
    Word::from([seed, 0, 0, 0])
}

// FIXTURE
// ================================================================================================

/// Builds the network faucet from the V1 components with its own asset in its vault, so it can pay
/// its fees as the chain's fee faucet.
fn native_fee_faucet(
    builder: &XReserveStablecoinBuilder,
    pause: PausableStorage,
) -> Result<Account> {
    let account = support::build_network_faucet_account(
        builder.build_components()?,
        support::test_fee_parameters(),
        support::test_fee_asset_id(),
    )?;
    let (id, _vault, mut storage, code, nonce, _seed) = account.into_parts();
    storage.set_item(PausableStorage::is_paused_slot(), pause.to_word())?;
    let vault = AssetVault::new(&[FungibleAsset::new(id, FAUCET_FEE_BALANCE)?.into()])?;
    Ok(Account::new(id, vault, storage, code, nonce, None)?)
}

/// Builds a wallet that holds the faucet's asset and pays its fees with it.
fn fee_paying_wallet(faucet_id: AccountId) -> Result<Account> {
    Ok(AccountBuilder::new([11; 32])
        .with_component(NoAuth)
        .with_component(BasicWallet)
        .with_assets([FungibleAsset::new(faucet_id, WALLET_BALANCE)?.into()])
        .account_type(AccountType::Public)
        .build_existing()?)
}

/// Returns a chain whose fee faucet is `faucet`, with `wallet` and `notes` committed.
fn native_fee_chain(faucet: &Account, wallet: &Account, notes: &[&Note]) -> Result<MockChain> {
    let mut chain_builder: MockChainBuilder = MockChain::builder()
        .fee_faucet_id(faucet.id())
        .verification_base_fee(VERIFICATION_BASE_FEE);
    chain_builder.add_account(faucet.clone())?;
    chain_builder.add_account(wallet.clone())?;
    for note in notes {
        chain_builder.add_output_note(RawOutputNote::Full((*note).clone()));
    }
    let mut mock_chain = chain_builder.build()?;
    mock_chain.prove_next_block()?;
    Ok(mock_chain)
}

fn pause_note(
    sender: AccountId,
    faucet_id: AccountId,
    config: PauseConfig,
    seed: u32,
) -> Result<Note> {
    Ok(PauseConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(config)
        .serial_number(serial_number(seed))
        .build()?
        .into())
}

fn upgrade_note(faucet_id: AccountId, code: AccountCode, seed: u32) -> Result<Note> {
    Ok(UpgradeNote::builder()
        .sender(administrator())
        .target(faucet_id)
        .code(code)
        .serial_number(serial_number(seed))
        .build()?
        .into())
}

/// Executes a faucet transaction that consumes `notes`, without committing it.
async fn try_faucet_tx(
    mock_chain: &MockChain,
    faucet_id: AccountId,
    notes: &[&Note],
) -> Result<std::result::Result<ExecutedTransaction, TransactionExecutorError>> {
    Ok(mock_chain
        .build_transaction(faucet_id)
        .authenticated_input_notes(notes.iter().map(|note| note.id()))
        .build()?
        .execute()
        .await)
}

/// Asserts that `executed_tx` paid its fee with a fee note in the faucet's asset, which triggered
/// the faucet's send callback.
fn assert_fee_note_in_faucet_asset(executed_tx: &ExecutedTransaction, faucet_id: AccountId) {
    let pays_fee = executed_tx.output_notes().iter().any(|note| {
        note.metadata().tag() == TxFeeNote::TAG
            && note.assets().iter().any(|asset| asset.faucet_id() == faucet_id)
    });
    assert!(pays_fee, "the transaction must pay its fee in the faucet's asset");
}

/// Executes and commits a faucet transaction that consumes `notes`.
async fn commit_faucet_tx(
    mock_chain: &mut MockChain,
    faucet_id: AccountId,
    notes: &[&Note],
) -> Result<()> {
    let executed_tx = try_faucet_tx(mock_chain, faucet_id, notes).await??;
    assert_fee_note_in_faucet_asset(&executed_tx, faucet_id);
    mock_chain.add_pending_executed_transaction(&executed_tx)?;
    mock_chain.prove_next_block()?;
    Ok(())
}

/// Executes a wallet transaction that only pays its fee, which triggers the faucet's send callback.
async fn try_wallet_fee_payment(
    mock_chain: &MockChain,
    wallet_id: AccountId,
    faucet_id: AccountId,
) -> Result<std::result::Result<ExecutedTransaction, TransactionExecutorError>> {
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet_id)?;
    Ok(mock_chain
        .build_transaction(wallet_id)
        .foreign_accounts([faucet_inputs])
        .build()?
        .execute()
        .await)
}

fn callback_roots(account: &Account) -> Result<(Word, Word)> {
    let storage = account.storage();
    Ok((
        storage.get_item(AssetCallbacks::on_before_asset_added_to_note_slot())?,
        storage.get_item(AssetCallbacks::on_before_asset_added_to_account_slot())?,
    ))
}

// TESTS
// ================================================================================================

/// With the V1 manager, a paused faucet blocks the fee payment of every account, so the unpauser
/// cannot create the unpause note either.
#[tokio::test]
async fn paused_v1_faucet_blocks_every_fee_payment() -> Result<()> {
    let builder = production_builder(0, TEST_DOMAIN)?;
    let faucet = native_fee_faucet(&builder, PausableStorage::paused())?;
    let wallet = fee_paying_wallet(faucet.id())?;
    let mock_chain = native_fee_chain(&faucet, &wallet, &[])?;

    let result = try_wallet_fee_payment(&mock_chain, wallet.id(), faucet.id()).await?;
    assert_transaction_executor_error!(result, ERR_PAUSABLE_IS_PAUSED);

    Ok(())
}

/// The faucet upgrades to the V2 manager in two transactions without an outage. Afterwards, fee
/// payments work while the faucet is paused, and the faucet can unpause itself.
#[tokio::test]
async fn upgrade_to_v2_keeps_fee_payments_working_while_paused() -> Result<()> {
    let builder = production_builder(0, TEST_DOMAIN)?;
    let faucet = native_fee_faucet(&builder, PausableStorage::unpaused())?;
    let faucet_id = faucet.id();
    let wallet = fee_paying_wallet(faucet_id)?;
    let intermediate_code = builder.build_code(builder.build_components_v2_upgrade()?)?;
    let final_code = builder.build_code(builder.build_components_v2()?)?;

    let migration_root = TokenPolicyManagerV2MigrationNote::script_root();
    let allow_migration: Note = NetworkAccountConfigNote::builder()
        .sender(administrator())
        .target(faucet_id)
        .config(NetworkAccountConfig::AddAllowedNoteScript { script_root: migration_root })
        .serial_number(serial_number(1))
        .build()?
        .into();
    let price_migration: Note = ConstantFeePolicyConfigNote::builder()
        .sender(administrator())
        .target(faucet_id)
        .note_script_root(migration_root)
        .fee_asset(FungibleAsset::new(test_fee_faucet_id(), 0)?)
        .serial_number(serial_number(2))
        .build()?
        .into();
    let upgrade_to_intermediate = upgrade_note(faucet_id, intermediate_code.clone(), 3)?;
    let migration: Note = TokenPolicyManagerV2MigrationNote::builder()
        .sender(administrator())
        .target(faucet_id)
        .serial_number(serial_number(4))
        .build()?
        .into();
    let upgrade_to_final = upgrade_note(faucet_id, final_code.clone(), 5)?;
    let pause = pause_note(dom_pauser(), faucet_id, PauseConfig::Pause, 6)?;
    let unpause = pause_note(dom_unpauser(), faucet_id, PauseConfig::Unpause, 7)?;

    let mut mock_chain = native_fee_chain(
        &faucet,
        &wallet,
        &[
            &allow_migration,
            &price_migration,
            &upgrade_to_intermediate,
            &migration,
            &upgrade_to_final,
            &pause,
            &unpause,
        ],
    )?;

    // Step 1: allow the migration note and install the intermediate code, which still contains the
    // V1 callbacks the slots point to.
    commit_faucet_tx(
        &mut mock_chain,
        faucet_id,
        &[&allow_migration, &price_migration, &upgrade_to_intermediate],
    )
    .await?;
    let faucet = mock_chain.committed_account(faucet_id)?;
    assert_eq!(faucet.code(), &intermediate_code);
    assert_eq!(
        callback_roots(faucet)?,
        (
            TokenPolicyManager::invoke_send_policy_root().as_word(),
            TokenPolicyManager::invoke_receive_policy_root().as_word(),
        ),
    );
    let executed_tx = try_wallet_fee_payment(&mock_chain, wallet.id(), faucet_id).await??;
    assert_fee_note_in_faucet_asset(&executed_tx, faucet_id);

    // Step 2: point the callback slots at the V2 callbacks and drop the V1 manager.
    commit_faucet_tx(&mut mock_chain, faucet_id, &[&migration, &upgrade_to_final]).await?;
    let faucet = mock_chain.committed_account(faucet_id)?;
    assert_eq!(faucet.code(), &final_code);
    assert_eq!(
        callback_roots(faucet)?,
        (
            TokenPolicyManagerV2::invoke_send_policy_root().as_word(),
            TokenPolicyManagerV2::invoke_receive_policy_root().as_word(),
        ),
    );

    // The pause transaction pays its fee after the pause flag is set.
    commit_faucet_tx(&mut mock_chain, faucet_id, &[&pause]).await?;
    assert_eq!(
        mock_chain
            .committed_account(faucet_id)?
            .storage()
            .get_item(PausableStorage::is_paused_slot())?,
        PausableStorage::paused().to_word(),
    );

    let executed_tx = try_wallet_fee_payment(&mock_chain, wallet.id(), faucet_id).await??;
    assert_fee_note_in_faucet_asset(&executed_tx, faucet_id);
    commit_faucet_tx(&mut mock_chain, faucet_id, &[&unpause]).await?;
    assert_eq!(
        mock_chain
            .committed_account(faucet_id)?
            .storage()
            .get_item(PausableStorage::is_paused_slot())?,
        PausableStorage::unpaused().to_word(),
    );

    Ok(())
}

/// An upgrade directly to the V2 code leaves the V1 callback roots in the callback slots, so every
/// transfer of the faucet's asset fails until the slots are migrated. This is why the upgrade goes
/// through the intermediate code.
#[tokio::test]
async fn direct_upgrade_to_v2_breaks_transfers() -> Result<()> {
    let builder = production_builder(0, TEST_DOMAIN)?;
    let faucet = native_fee_faucet(&builder, PausableStorage::unpaused())?;
    let wallet = fee_paying_wallet(faucet.id())?;
    let upgrade =
        upgrade_note(faucet.id(), builder.build_code(builder.build_components_v2()?)?, 1)?;
    let mut mock_chain = native_fee_chain(&faucet, &wallet, &[&upgrade])?;

    commit_faucet_tx(&mut mock_chain, faucet.id(), &[&upgrade]).await?;

    let result = try_wallet_fee_payment(&mock_chain, wallet.id(), faucet.id()).await?;
    assert_transaction_executor_error!(
        result,
        ERR_FAUCET_CALLBACK_PROC_ROOT_NOT_PART_OF_ACCOUNT_CODE
    );

    Ok(())
}
