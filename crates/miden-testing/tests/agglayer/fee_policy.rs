use alloc::collections::BTreeSet;

use miden_agglayer::testing::bridge_admin_account_id;
use miden_agglayer::{AggLayerBridge, AggLayerFaucet, BridgeRoles};
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, StorageMapKey};
use miden_protocol::asset::{AssetId, FungibleAsset};
use miden_protocol::note::{Note, NoteAssets, NoteScriptRoot};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::NetworkAccount;
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::errors::standards::ERR_SENDER_LACKS_ROLE;
use miden_standards::note::{
    BurnNote,
    ConstantFeePolicyConfigNote,
    FeeSponsorshipNote,
    MintNote,
    NetworkAccountConfigNote,
    PauseConfig,
    StandardNote,
};
use miden_testing::{MockChain, assert_transaction_executor_error};
use rstest::rstest;

use super::test_utils::{
    MIDEN_NETWORK_ID,
    VERIFICATION_BASE_FEE,
    add_fee_sponsorship,
    fee_faucet_id,
    find_output_note,
    is_bridge_paused,
    network_note_pricer,
};
use crate::consume_note;

fn assert_priced_account(account: &Account, roots: BTreeSet<NoteScriptRoot>) -> anyhow::Result<()> {
    let pricer = network_note_pricer(VERIFICATION_BASE_FEE);
    let network_account = NetworkAccount::new(account.clone())?;
    assert_eq!(network_account.allowed_notes().allowed_script_roots(), &roots);

    assert_eq!(
        account.storage().get_item(FeePolicyManager::active_fee_policy_slot())?,
        BasicConstantFeePolicy::root().as_word()
    );
    assert_eq!(
        account.storage().get_item(FeePolicyManager::fee_asset_id_slot())?,
        AssetId::new_fungible(fee_faucet_id()).to_word()
    );

    for root in roots {
        let entry = account.storage().get_map_item(
            BasicConstantFeePolicy::fee_schedule_slot_name(),
            StorageMapKey::new(root.as_word()),
        )?;
        // Consuming a config note is the only route to `set_note_fee`, so it is scheduled free
        // even though it has a benchmarked cost: a priced one could put repricing out of reach.
        let expected_fee = if root == ConstantFeePolicyConfigNote::script_root() {
            assert!(pricer.price(root)?.as_u64() > 0, "the config note should have a real price");
            0
        } else {
            pricer.price(root)?.as_u64()
        };
        assert_eq!(entry[0].as_canonical_u64(), expected_fee);
        assert_eq!(entry[3].as_canonical_u64(), 1, "the schedule entry must carry its set marker");
    }

    Ok(())
}

#[test]
fn agglayer_accounts_install_priced_basic_constant_fee_policies() -> anyhow::Result<()> {
    assert_priced_account(
        &build_managed_account(ManagedAccount::Bridge)?,
        AggLayerBridge::allowed_notes(),
    )?;
    assert_priced_account(
        &build_managed_account(ManagedAccount::Faucet)?,
        AggLayerFaucet::allowed_notes(),
    )
}

/// Pins the faucet's input-note allowlist. The allowlist decides which notes can drive an account
/// that holds an `ADMIN` role, so it should not grow silently.
#[test]
fn faucet_allowed_notes_pin() {
    let expected = BTreeSet::from([
        MintNote::script_root(),
        BurnNote::script_root(),
        ConstantFeePolicyConfigNote::script_root(),
        NetworkAccountConfigNote::script_root(),
        FeeSponsorshipNote::script_root(),
    ]);
    assert_eq!(AggLayerFaucet::allowed_notes(), expected);
}

// POST-DEPLOYMENT FEE SCHEDULE UPDATES
// ================================================================================================

/// Which AggLayer network account a repricing case runs against. Both install the
/// `ConstantFeeManager` behind the same `ADMIN`-gated authority, so the cases are shared.
#[derive(Clone, Copy, Debug)]
enum ManagedAccount {
    Bridge,
    Faucet,
}

/// An account ID that holds no role on either AggLayer account.
fn outsider_id() -> AccountId {
    AccountId::builder().account_type(AccountType::Public).build_with_seed([42; 32])
}

/// Returns the production-priced bridge account builder shared by [`build_managed_account`] and
/// the scenarios that need extra account settings (e.g. a pre-funded vault).
fn bridge_account_builder() -> anyhow::Result<AccountBuilder> {
    let admin = bridge_admin_account_id();
    let roles = BridgeRoles::new([admin].into(), [admin].into(), [admin].into())?;
    Ok(AggLayerBridge::account_builder(
        Word::default(),
        admin,
        roles,
        MIDEN_NETWORK_ID,
        network_note_pricer(VERIFICATION_BASE_FEE).agglayer_bridge_fee_policy_manager()?,
    ))
}

/// Builds the requested AggLayer account with its production-priced fee schedule, administered by
/// [`bridge_admin_account_id`].
fn build_managed_account(managed: ManagedAccount) -> anyhow::Result<Account> {
    let pricer = network_note_pricer(VERIFICATION_BASE_FEE);
    let admin = bridge_admin_account_id();
    let bridge = bridge_account_builder()?.build_existing()?;

    Ok(match managed {
        ManagedAccount::Bridge => bridge,
        ManagedAccount::Faucet => AggLayerFaucet::account_builder(
            Word::from([1u32, 0, 0, 0]),
            "AGG",
            6,
            1_000u32.into(),
            Felt::ZERO,
            admin,
            bridge.id(),
            pricer.agglayer_faucet_fee_policy_manager()?,
        )
        .build_existing()?,
    })
}

/// Builds a config note repricing `repriced_root()` on `account` to `amount`, authored by `sender`.
///
/// `serial_seed` keeps otherwise-identical notes from sharing a note ID.
fn build_repricing_note(
    sender: AccountId,
    account: AccountId,
    amount: u64,
    serial_seed: u32,
) -> anyhow::Result<Note> {
    let note = ConstantFeePolicyConfigNote::builder()
        .sender(sender)
        .target(account)
        .note_script_root(repriced_root())
        .fee_asset(FungibleAsset::new(fee_faucet_id(), amount)?)
        .serial_number(Word::from([serial_seed, 0, 0, 0]))
        .build()?;
    Ok(Note::from(note))
}

/// The root the repricing cases rewrite. Every network account schedules it, so the bridge and
/// faucet cases can share it, and it is not the config note's own root, which must stay free.
fn repriced_root() -> NoteScriptRoot {
    NetworkAccountConfigNote::script_root()
}

/// Reads the committed fee schedule entry for [`repriced_root`] on `account_id`.
fn committed_fee(mock_chain: &MockChain, account_id: AccountId) -> anyhow::Result<Word> {
    let account = mock_chain.committed_account(account_id)?;
    let entry = account.storage().get_map_item(
        BasicConstantFeePolicy::fee_schedule_slot_name(),
        StorageMapKey::new(repriced_root().as_word()),
    )?;
    Ok(entry)
}

/// An `ADMIN`-authored config note reprices a scheduled note, both upwards and back down, on the
/// bridge and on the faucet. Repricing downwards matters as much as upwards: it is how an
/// operator walks fees back after the chain's verification base fee falls, and it exercises the
/// manager overwriting a set-marked entry rather than filling an empty one.
///
/// The chain runs at a zero verification base fee so the transactions themselves cost nothing and
/// no sponsorship plumbing is needed; the schedule under test is still the production-priced one.
#[rstest]
#[case::bridge(ManagedAccount::Bridge)]
#[case::faucet(ManagedAccount::Faucet)]
#[tokio::test]
async fn admin_reprices_the_fee_schedule(#[case] managed: ManagedAccount) -> anyhow::Result<()> {
    const RAISED_FEE: u64 = 9_000;
    const LOWERED_FEE: u64 = 12;

    let admin = bridge_admin_account_id();
    let account = build_managed_account(managed)?;
    let deployed_fee = network_note_pricer(VERIFICATION_BASE_FEE).price(repriced_root())?.as_u64();

    let raise = build_repricing_note(admin, account.id(), RAISED_FEE, 1)?;
    let lower = build_repricing_note(admin, account.id(), LOWERED_FEE, 2)?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(raise.clone()));
    builder.add_output_note(RawOutputNote::Full(lower.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        committed_fee(&mock_chain, account.id())?,
        Word::from([deployed_fee as u32, 0, 0, 1]),
        "the account should start at its deployment price"
    );

    consume_note(&mut mock_chain, account.id(), &raise).await?;
    assert_eq!(
        committed_fee(&mock_chain, account.id())?,
        Word::from([RAISED_FEE as u32, 0, 0, 1]),
        "the raised fee should replace the deployment price"
    );

    consume_note(&mut mock_chain, account.id(), &lower).await?;
    assert_eq!(
        committed_fee(&mock_chain, account.id())?,
        Word::from([LOWERED_FEE as u32, 0, 0, 1]),
        "the lowered fee should replace the raised one"
    );

    Ok(())
}

/// A config note authored by an account outside the `ADMIN` role cannot reprice either account:
/// `set_note_fee` runs `authority::assert_authorized`, which under `Authority::RbacControlled`
/// resolves the unmapped procedure to `ADMIN` and rejects a sender that does not hold it. The
/// schedule is left untouched.
#[rstest]
#[case::bridge(ManagedAccount::Bridge)]
#[case::faucet(ManagedAccount::Faucet)]
#[tokio::test]
async fn non_admin_cannot_reprice_the_fee_schedule(
    #[case] managed: ManagedAccount,
) -> anyhow::Result<()> {
    let account = build_managed_account(managed)?;
    let deployed_fee = network_note_pricer(VERIFICATION_BASE_FEE).price(repriced_root())?.as_u64();
    let attacker_note = build_repricing_note(outsider_id(), account.id(), 1, 3)?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(attacker_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(attacker_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);
    assert_eq!(
        committed_fee(&mock_chain, account.id())?,
        Word::from([deployed_fee as u32, 0, 0, 1]),
        "a rejected config note must leave the schedule untouched"
    );

    Ok(())
}

/// A paused bridge can still be repriced. `set_note_fee` belongs to the standards
/// `ConstantFeeManager`, not to the bridge component, so it carries no
/// `pausable::assert_not_paused` - repricing stays available alongside the other management
/// notes while every bridging entry point is halted.
///
/// The pause note needs a `FEE_SPONSORSHIP` covering its scheduled fee, because a priced schedule
/// requires every consumed note's fee to be prepaid regardless of the chain's own base fee. The
/// repricing note needs none at the policy level: it is scheduled free so that repricing is
/// never gated on covering a schedule entry, which a mistaken repricing could set beyond
/// anything a sponsor can pay. On a fee-charging chain the repricing transaction's own fee must
/// still be funded, from the account's vault or a voluntary sponsorship - see
/// [`sponsored_repricing_note_reimburses_the_bridge`].
#[tokio::test]
async fn paused_bridge_allows_repricing() -> anyhow::Result<()> {
    const REPRICED_FEE: u64 = 4_242;

    let admin = bridge_admin_account_id();
    let bridge = build_managed_account(ManagedAccount::Bridge)?;

    let mut builder = MockChain::builder();
    builder.add_account(bridge.clone())?;
    let pause =
        AggLayerBridge::pause_note(PauseConfig::Pause, admin, bridge.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(pause.clone()));
    let pause_sponsorship =
        add_fee_sponsorship(&mut builder, &pause, bridge.id(), VERIFICATION_BASE_FEE)?
            .expect("a non-zero base fee should produce a sponsorship");
    let reprice = build_repricing_note(admin, bridge.id(), REPRICED_FEE, 4)?;
    builder.add_output_note(RawOutputNote::Full(reprice.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let paused = mock_chain
        .build_transaction(bridge.id())
        .authenticated_input_note(pause.id())
        .authenticated_input_note(pause_sponsorship.id())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&paused)?;
    mock_chain.prove_next_block()?;
    assert!(is_bridge_paused(&mock_chain, bridge.id())?, "the bridge should be paused");

    consume_note(&mut mock_chain, bridge.id(), &reprice).await?;
    assert_eq!(
        committed_fee(&mock_chain, bridge.id())?,
        Word::from([REPRICED_FEE as u32, 0, 0, 1]),
        "a paused bridge should still accept a repricing note"
    );

    Ok(())
}

/// Sums the fungible amounts carried by `assets`.
fn fungible_total(assets: &NoteAssets) -> u64 {
    assets.iter().map(|asset| asset.unwrap_fungible().amount().as_u64()).sum()
}

/// A repricing note can still pay for itself despite its zero schedule entry. Sponsorship
/// coverage is checked as *at least* the scheduled amount, so an operator can voluntarily attach
/// a `FEE_SPONSORSHIP` sized at the config note's real benchmarked price - which
/// `NetworkNotePricer::price` still computes, the zero living only in the on-chain schedule. The
/// sponsorship is credited to the bridge's vault before the transaction pays its fee, so on a
/// fee-charging chain the repricing costs the bridge nothing of its own.
///
/// The bridge's vault is pre-funded so that a sponsorship falling short of the paid fee surfaces
/// as the named coverage assertion below instead of an opaque vault abort inside `execute()`.
/// The coverage assertion is deliberately `>=` rather than exact: today the benchmarked price
/// and the actual fee land in the same log-cycle bracket, so the bridge breaks exactly even, but
/// benchmark drift or kernel growth may open bounded slack, which stays in the vault.
#[tokio::test]
async fn sponsored_repricing_note_reimburses_the_bridge() -> anyhow::Result<()> {
    const REPRICED_FEE: u64 = 777;
    const PREFUND: u64 = 100_000;

    let admin = bridge_admin_account_id();
    let fee_asset_id = AssetId::new_fungible(fee_faucet_id());
    let bridge = bridge_account_builder()?
        .with_assets([FungibleAsset::new(fee_faucet_id(), PREFUND)?.into()])
        .build_existing()?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    builder.add_account(bridge.clone())?;
    let reprice = build_repricing_note(admin, bridge.id(), REPRICED_FEE, 5)?;
    builder.add_output_note(RawOutputNote::Full(reprice.clone()));
    let sponsorship =
        add_fee_sponsorship(&mut builder, &reprice, bridge.id(), VERIFICATION_BASE_FEE)?
            .expect("a non-zero base fee should produce a sponsorship");
    let sponsored = fungible_total(sponsorship.assets());
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let initial_balance = mock_chain
        .committed_account(bridge.id())?
        .vault()
        .get_balance(fee_asset_id)?
        .as_u64();
    assert_eq!(initial_balance, PREFUND, "the bridge should start with its pre-funded balance");

    let executed = mock_chain
        .build_transaction(bridge.id())
        .authenticated_input_note(reprice.id())
        .authenticated_input_note(sponsorship.id())
        .build()?
        .execute()
        .await?;
    let fee_note = find_output_note(&executed, StandardNote::TX_FEE.script_root())
        .expect("a fee-charging chain should emit a TX_FEE note");
    let paid_fee = fungible_total(fee_note.assets());
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        committed_fee(&mock_chain, bridge.id())?,
        Word::from([REPRICED_FEE as u32, 0, 0, 1]),
        "the sponsored repricing note should have taken effect"
    );

    // The voluntary sponsorship covers the transaction's whole fee, and every unit of it is
    // accounted for: whatever the fee did not consume stays in the bridge's vault on top of the
    // pre-funded balance.
    assert!(paid_fee > 0, "the transaction should have paid a non-zero fee");
    assert!(
        sponsored >= paid_fee,
        "the sponsorship ({sponsored}) should cover the paid fee ({paid_fee})"
    );
    let final_balance = mock_chain
        .committed_account(bridge.id())?
        .vault()
        .get_balance(fee_asset_id)?
        .as_u64();
    assert_eq!(
        initial_balance + sponsored,
        final_balance + paid_fee,
        "the bridge's vault should change by exactly the sponsorship minus the paid fee"
    );

    Ok(())
}
