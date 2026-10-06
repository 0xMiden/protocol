//! The token policy manager V2 of the faucet.
//!
//! The faucet issues the network's fee asset, and every fee note triggers its send callback. The V1
//! callback checks the pause flag, so a paused faucet blocks every fee payment, including the one
//! of the transaction that creates the unpause note. The V2 callback does not check the pause
//! flag.
//!
//! The tests cover a faucet built with the V2 manager and a V1 faucet upgraded to it. In the pause
//! flow, the faucet is the chain's fee faucet and pays its own fees from its vault, and
//! the unpauser is a wallet that pays its fees in the faucet's asset.

mod support;

use anyhow::Result;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::{AssetAmount, AssetCallbacks, AssetVault, FungibleAsset};
use miden_protocol::errors::AccountError;
use miden_protocol::note::Note;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_standards::account::access::PausableStorage;
use miden_standards::account::auth::NoAuth;
use miden_standards::account::policies::TokenPolicyManagerV2;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::TxFeeNote;
use miden_standards::note::config::{PauseConfig, PauseConfigNote};
use miden_testing::MockChain;
use miden_usdcx::account::xreserve::{
    PolicyManagerVersion,
    XReserveStablecoinBuilder,
    XReserveStablecoinBuilderError,
};
use miden_usdcx::upgrade_to_token_policy_manager_v2;
use rstest::rstest;
use support::{TEST_DOMAIN, test_account_id};

const VERIFICATION_BASE_FEE: u32 = 500;
const FAUCET_FEE_BALANCE: u64 = 1_000_000_000;
const WALLET_BALANCE: u64 = 1_000_000_000;

fn dom_pauser() -> AccountId {
    test_account_id(2)
}

fn serial_number(seed: u32) -> Word {
    Word::from([seed, 0, 0, 0])
}

// FIXTURE
// ================================================================================================

/// Returns the production builder with `unpauser` as the only `DOM_UNPAUSER`.
fn production_builder_with_unpauser(
    unpauser: AccountId,
    policy_manager: PolicyManagerVersion,
) -> Result<XReserveStablecoinBuilder> {
    Ok(XReserveStablecoinBuilder::builder()
        .token_supply(AssetAmount::ZERO)
        .owner(test_account_id(1))
        .attest_admin_holders(vec![test_account_id(1)])
        .pauser_holders(vec![dom_pauser()])
        .unpauser_holders(vec![unpauser])
        .blocklist_manager_holders(vec![test_account_id(4)])
        .fee_parameters(support::test_fee_parameters())
        .fee_asset_id(support::test_fee_asset_id())
        .domain(TEST_DOMAIN)
        .policy_manager(policy_manager)
        .build()?)
}

/// Builds the network faucet with the V2 manager, either directly or by upgrading a V1 faucet.
fn v2_faucet(unpauser: AccountId, upgraded: bool) -> Result<Account> {
    let policy_manager = if upgraded {
        PolicyManagerVersion::V1
    } else {
        PolicyManagerVersion::V2
    };
    let builder = production_builder_with_unpauser(unpauser, policy_manager)?;
    let faucet = support::build_network_faucet_account(
        builder.build_components()?,
        support::test_fee_parameters(),
        support::test_fee_asset_id(),
    )?;
    if upgraded {
        Ok(upgrade_to_token_policy_manager_v2(faucet)?)
    } else {
        Ok(faucet)
    }
}

/// Returns `account` with a vault that holds `amount` of the asset issued by `faucet_id`.
fn with_balance(account: Account, faucet_id: AccountId, amount: u64) -> Result<Account> {
    let (id, _vault, storage, code, nonce, _seed) = account.into_parts();
    let vault = AssetVault::new(&[FungibleAsset::new(faucet_id, amount)?.into()])?;
    Ok(Account::new(id, vault, storage, code, nonce, None)?)
}

/// Builds a wallet that pays its fees with the assets in its vault.
fn fee_paying_wallet() -> Result<Account> {
    Ok(AccountBuilder::new([11; 32])
        .with_component(NoAuth)
        .with_component(BasicWallet)
        .account_type(AccountType::Public)
        .build_existing()?)
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

/// Asserts that `executed_tx` paid its fee with a fee note in the faucet's asset, which triggered
/// the faucet's send callback.
fn assert_fee_note_in_faucet_asset(executed_tx: &ExecutedTransaction, faucet_id: AccountId) {
    let pays_fee = executed_tx.output_notes().iter().any(|note| {
        note.metadata().tag() == TxFeeNote::TAG
            && note.assets().iter().any(|asset| asset.faucet_id() == faucet_id)
    });
    assert!(pays_fee, "the transaction must pay its fee in the faucet's asset");
}

/// Executes and commits a transaction of `account_id` that consumes `note` and creates
/// `created_notes`, with the faucet as a foreign account for its callbacks.
async fn commit_tx(
    mock_chain: &mut MockChain,
    account_id: AccountId,
    faucet_id: AccountId,
    note: &Note,
    created_notes: &[&Note],
) -> Result<()> {
    let mut tx_builder = mock_chain
        .build_transaction(account_id)
        .authenticated_input_note(note.id())
        .expected_output_notes(
            created_notes.iter().map(|note| RawOutputNote::Full((*note).clone())).collect(),
        );
    if account_id != faucet_id {
        tx_builder =
            tx_builder.foreign_accounts([mock_chain.get_foreign_account_inputs(faucet_id)?]);
    }
    let executed_tx = tx_builder.build()?.execute().await?;
    assert_fee_note_in_faucet_asset(&executed_tx, faucet_id);
    mock_chain.add_pending_executed_transaction(&executed_tx)?;
    mock_chain.prove_next_block()?;
    Ok(())
}

fn is_paused(mock_chain: &MockChain, faucet_id: AccountId) -> Result<bool> {
    let is_paused_word = mock_chain
        .committed_account(faucet_id)?
        .storage()
        .get_item(PausableStorage::is_paused_slot())?;
    Ok(is_paused_word == PausableStorage::paused().to_word())
}

// TESTS
// ================================================================================================

/// With the V2 manager, fee payments work while the faucet is paused, so the unpauser can create
/// the unpause note and the faucet can consume it.
#[rstest]
#[case::built_directly(false)]
#[case::upgraded_from_v1(true)]
#[tokio::test]
async fn paused_v2_faucet_keeps_fee_payments_working(#[case] upgraded: bool) -> Result<()> {
    let wallet = fee_paying_wallet()?;
    let faucet = v2_faucet(wallet.id(), upgraded)?;
    let faucet_id = faucet.id();
    let faucet = with_balance(faucet, faucet_id, FAUCET_FEE_BALANCE)?;
    let wallet = with_balance(wallet, faucet_id, WALLET_BALANCE)?;
    let callback_slots = (
        faucet
            .storage()
            .get_item(AssetCallbacks::on_before_asset_added_to_note_slot())?,
        faucet
            .storage()
            .get_item(AssetCallbacks::on_before_asset_added_to_account_slot())?,
    );
    assert_eq!(
        callback_slots,
        (
            TokenPolicyManagerV2::invoke_send_policy_root().as_word(),
            TokenPolicyManagerV2::invoke_receive_policy_root().as_word(),
        ),
    );

    let pause = pause_note(dom_pauser(), faucet_id, PauseConfig::Pause, 1)?;
    let unpause = pause_note(wallet.id(), faucet_id, PauseConfig::Unpause, 2)?;
    let mut chain_builder = MockChain::builder()
        .fee_faucet_id(faucet_id)
        .verification_base_fee(VERIFICATION_BASE_FEE);
    chain_builder.add_account(faucet)?;
    chain_builder.add_account(wallet.clone())?;
    chain_builder.add_output_note(RawOutputNote::Full(pause.clone()));
    let spawn_unpause = chain_builder.add_spawn_note([&unpause])?;
    let mut mock_chain = chain_builder.build()?;
    mock_chain.prove_next_block()?;

    // The pause transaction pays its fee after the pause flag is set.
    commit_tx(&mut mock_chain, faucet_id, faucet_id, &pause, &[]).await?;
    assert!(is_paused(&mock_chain, faucet_id)?);

    // The unpauser creates the unpause note and pays its fee while the faucet is paused.
    commit_tx(&mut mock_chain, wallet.id(), faucet_id, &spawn_unpause, &[&unpause]).await?;
    assert!(is_paused(&mock_chain, faucet_id)?);

    commit_tx(&mut mock_chain, faucet_id, faucet_id, &unpause, &[]).await?;
    assert!(!is_paused(&mock_chain, faucet_id)?);

    Ok(())
}

/// Builds an existing network faucet (nonce one, no seed) with the given manager version.
fn existing_faucet(policy_manager: PolicyManagerVersion) -> Result<Account> {
    let builder = production_builder_with_unpauser(test_account_id(3), policy_manager)?;
    support::build_network_faucet_account(
        builder.build_components()?,
        support::test_fee_parameters(),
        support::test_fee_asset_id(),
    )
}

/// The upgrade keeps the account ID, vault and nonce, and yields the code and storage of a faucet
/// built directly with the V2 manager.
#[test]
fn upgrade_matches_direct_v2_build() -> Result<()> {
    let v1_faucet = existing_faucet(PolicyManagerVersion::V1)?;
    let direct_v2_faucet = existing_faucet(PolicyManagerVersion::V2)?;

    let upgraded_faucet = upgrade_to_token_policy_manager_v2(v1_faucet.clone())?;

    assert_eq!(upgraded_faucet.id(), v1_faucet.id());
    assert_eq!(upgraded_faucet.vault(), v1_faucet.vault());
    assert_eq!(upgraded_faucet.nonce(), v1_faucet.nonce());
    assert_eq!(upgraded_faucet.code().commitment(), direct_v2_faucet.code().commitment());
    assert_eq!(
        upgraded_faucet.storage().to_commitment(),
        direct_v2_faucet.storage().to_commitment()
    );

    Ok(())
}

/// The upgrade rejects a faucet that does not have the V1 token policy manager.
#[test]
fn upgrade_rejects_non_v1_faucet() -> Result<()> {
    let result = upgrade_to_token_policy_manager_v2(existing_faucet(PolicyManagerVersion::V2)?);

    assert!(matches!(
        result,
        Err(XReserveStablecoinBuilderError::AccountComposition(AccountError::Other { .. }))
    ));

    Ok(())
}

/// The upgrade rejects a new account, whose seed derives its ID from the V1 code.
#[test]
fn upgrade_rejects_new_account() -> Result<()> {
    let new_v1_faucet =
        production_builder_with_unpauser(test_account_id(3), PolicyManagerVersion::V1)?
            .build_account([7; 32])?;

    let result = upgrade_to_token_policy_manager_v2(new_v1_faucet);

    assert!(matches!(result, Err(XReserveStablecoinBuilderError::AccountComposition(_))));

    Ok(())
}
