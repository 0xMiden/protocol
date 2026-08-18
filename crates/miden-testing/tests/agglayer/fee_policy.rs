use alloc::collections::BTreeSet;

use miden_agglayer::testing::bridge_admin_account_id;
use miden_agglayer::{AggLayerBridge, AggLayerFaucet, BridgeRoles};
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, StorageMapKey};
use miden_protocol::asset::{AssetId, FungibleAsset};
use miden_protocol::note::{Note, NoteScriptRoot};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{AuthNetworkAccount, NetworkAccount};
use miden_standards::account::fees::{
    BasicConstantFeePolicy,
    ConstantFeeManager,
    FeePolicyManager,
};
use miden_standards::errors::standards::ERR_SENDER_LACKS_ROLE;
use miden_standards::note::{
    BurnNote,
    ConstantFeePolicyConfigNote,
    FeeSponsorshipNote,
    MintNote,
    NetworkAccountConfigNote,
    PauseConfig,
    RbacConfigNote,
};
use miden_testing::{MockChain, MockChainBuilder, assert_transaction_executor_error};
use rstest::rstest;

use super::test_utils::{
    MIDEN_NETWORK_ID,
    VERIFICATION_BASE_FEE,
    add_fee_sponsorship,
    fee_faucet_id,
    is_bridge_paused,
    network_note_pricer,
};

// DEPLOYMENT-PRICED FEE POLICIES
// ================================================================================================

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
        let expected_fee = pricer.price(root)?.as_u64();
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

#[test]
fn faucet_allowed_notes_pin() {
    let expected = BTreeSet::from([
        MintNote::script_root(),
        BurnNote::script_root(),
        ConstantFeePolicyConfigNote::script_root(),
        RbacConfigNote::script_root(),
        NetworkAccountConfigNote::script_root(),
        FeeSponsorshipNote::script_root(),
    ]);
    assert_eq!(AggLayerFaucet::allowed_notes(), expected);
}

#[test]
fn fee_management_procedure_role_mappings() {
    let bridge_roles = AggLayerBridge::procedure_roles();
    let faucet_roles = AggLayerFaucet::procedure_roles();

    assert_eq!(
        bridge_roles.get(&ConstantFeeManager::set_note_fee_root()),
        Some(&AggLayerBridge::fee_manager_role()),
    );
    assert_eq!(
        faucet_roles.get(&ConstantFeeManager::set_note_fee_root()),
        Some(&AggLayerFaucet::fee_manager_role()),
    );
    assert_eq!(faucet_roles.len(), 1, "only note repricing uses the faucet FEE_MNGR role");

    for admin_root in [
        AuthNetworkAccount::set_fee_policy_root(),
        AuthNetworkAccount::add_allowed_fee_policy_root(),
        AuthNetworkAccount::remove_allowed_fee_policy_root(),
    ] {
        assert!(!bridge_roles.contains_key(&admin_root));
        assert!(!faucet_roles.contains_key(&admin_root));
    }
}

// POST-DEPLOYMENT FEE SCHEDULE UPDATES
// ================================================================================================

#[derive(Clone, Copy, Debug)]
enum ManagedAccount {
    Bridge,
    Faucet,
}

fn fee_manager_id() -> AccountId {
    AccountId::builder().account_type(AccountType::Public).build_with_seed([41; 32])
}

fn bridge_account_builder() -> anyhow::Result<AccountBuilder> {
    let bridge_admin = bridge_admin_account_id();
    let roles = BridgeRoles::new(
        [bridge_admin].into(),
        [bridge_admin].into(),
        [bridge_admin].into(),
        [fee_manager_id()].into(),
    )?;
    let pricer = network_note_pricer(VERIFICATION_BASE_FEE);
    let fee_policy = pricer.basic_constant_fee_policy(AggLayerBridge::allowed_notes())?;
    Ok(AggLayerBridge::account_builder(
        Word::default(),
        bridge_admin,
        roles,
        MIDEN_NETWORK_ID,
        pricer.fee_parameters().fee_faucet_id(),
        fee_policy,
    ))
}

fn build_managed_account(managed: ManagedAccount) -> anyhow::Result<Account> {
    let pricer = network_note_pricer(VERIFICATION_BASE_FEE);
    let account_admin = bridge_admin_account_id();
    let bridge = bridge_account_builder()?.build_existing()?;

    Ok(match managed {
        ManagedAccount::Bridge => bridge,
        ManagedAccount::Faucet => AggLayerFaucet::account_builder(
            Word::from([1u32, 0, 0, 0]),
            "AGG",
            6,
            1_000u32.into(),
            Felt::ZERO,
            account_admin,
            fee_manager_id(),
            bridge.id(),
            pricer.fee_parameters().fee_faucet_id(),
            pricer.basic_constant_fee_policy(AggLayerFaucet::allowed_notes())?,
        )
        .build_existing()?,
    })
}

fn build_repricing_note(
    sender: AccountId,
    account: AccountId,
    note_script_root: NoteScriptRoot,
    amount: u64,
    serial_seed: u32,
) -> anyhow::Result<Note> {
    let note = ConstantFeePolicyConfigNote::builder()
        .sender(sender)
        .target(account)
        .note_script_root(note_script_root)
        .fee_asset(FungibleAsset::new(fee_faucet_id(), amount)?)
        .serial_number(Word::from([serial_seed, 0, 0, 0]))
        .build()?;
    Ok(Note::from(note))
}

fn repriced_root() -> NoteScriptRoot {
    NetworkAccountConfigNote::script_root()
}

fn fee_schedule_entry(amount: u64) -> anyhow::Result<Word> {
    Ok(Word::new([Felt::new(amount)?, Felt::ZERO, Felt::ZERO, Felt::from(1u32)]))
}

fn add_required_sponsorship(
    builder: &mut MockChainBuilder,
    feature_note: &Note,
    target: AccountId,
) -> anyhow::Result<Note> {
    add_fee_sponsorship(builder, feature_note, target, VERIFICATION_BASE_FEE)?
        .ok_or_else(|| anyhow::anyhow!("expected a fee sponsorship note"))
}

fn committed_fee(
    mock_chain: &MockChain,
    account_id: AccountId,
    note_script_root: NoteScriptRoot,
) -> anyhow::Result<Word> {
    let account = mock_chain.committed_account(account_id)?;
    let entry = account.storage().get_map_item(
        BasicConstantFeePolicy::fee_schedule_slot_name(),
        StorageMapKey::new(note_script_root.as_word()),
    )?;
    Ok(entry)
}

async fn consume_sponsored_note(
    mock_chain: &mut MockChain,
    account_id: AccountId,
    feature_note: &Note,
    sponsorship: &Note,
) -> anyhow::Result<()> {
    let executed = mock_chain
        .build_transaction(account_id)
        .authenticated_input_note(feature_note.id())
        .authenticated_input_note(sponsorship.id())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    Ok(())
}

#[rstest]
#[case::bridge(ManagedAccount::Bridge)]
#[case::faucet(ManagedAccount::Faucet)]
#[tokio::test]
async fn fee_manager_reprices_the_fee_schedule(
    #[case] managed: ManagedAccount,
) -> anyhow::Result<()> {
    const RAISED_FEE: u64 = 9_000;
    const LOWERED_FEE: u64 = 12;

    let fee_manager = fee_manager_id();
    let account = build_managed_account(managed)?;
    let deployed_fee = network_note_pricer(VERIFICATION_BASE_FEE).price(repriced_root())?.as_u64();

    let raise = build_repricing_note(fee_manager, account.id(), repriced_root(), RAISED_FEE, 1)?;
    let lower = build_repricing_note(fee_manager, account.id(), repriced_root(), LOWERED_FEE, 2)?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(raise.clone()));
    builder.add_output_note(RawOutputNote::Full(lower.clone()));
    let raise_sponsorship = add_required_sponsorship(&mut builder, &raise, account.id())?;
    let lower_sponsorship = add_required_sponsorship(&mut builder, &lower, account.id())?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        committed_fee(&mock_chain, account.id(), repriced_root())?,
        fee_schedule_entry(deployed_fee)?,
        "the account should start at its deployment price"
    );

    consume_sponsored_note(&mut mock_chain, account.id(), &raise, &raise_sponsorship).await?;
    assert_eq!(
        committed_fee(&mock_chain, account.id(), repriced_root())?,
        fee_schedule_entry(RAISED_FEE)?,
        "the raised fee should replace the deployment price"
    );

    consume_sponsored_note(&mut mock_chain, account.id(), &lower, &lower_sponsorship).await?;
    assert_eq!(
        committed_fee(&mock_chain, account.id(), repriced_root())?,
        fee_schedule_entry(LOWERED_FEE)?,
        "the lowered fee should replace the raised one"
    );

    Ok(())
}

#[rstest]
#[case::bridge(ManagedAccount::Bridge)]
#[case::faucet(ManagedAccount::Faucet)]
#[tokio::test]
async fn admin_without_fee_manager_role_cannot_reprice_the_fee_schedule(
    #[case] managed: ManagedAccount,
) -> anyhow::Result<()> {
    let account = build_managed_account(managed)?;
    let deployed_fee = network_note_pricer(VERIFICATION_BASE_FEE).price(repriced_root())?.as_u64();
    let attacker_note =
        build_repricing_note(bridge_admin_account_id(), account.id(), repriced_root(), 1, 3)?;

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
        committed_fee(&mock_chain, account.id(), repriced_root())?,
        fee_schedule_entry(deployed_fee)?,
        "a rejected config note must leave the schedule untouched"
    );

    Ok(())
}

#[tokio::test]
async fn paused_bridge_allows_repricing() -> anyhow::Result<()> {
    const REPRICED_FEE: u64 = 4_242;

    let bridge_admin = bridge_admin_account_id();
    let bridge = build_managed_account(ManagedAccount::Bridge)?;

    let mut builder = MockChain::builder();
    builder.add_account(bridge.clone())?;
    let pause = AggLayerBridge::pause_note(
        PauseConfig::Pause,
        bridge_admin,
        bridge.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(pause.clone()));
    let pause_sponsorship = add_required_sponsorship(&mut builder, &pause, bridge.id())?;
    let reprice =
        build_repricing_note(fee_manager_id(), bridge.id(), repriced_root(), REPRICED_FEE, 4)?;
    builder.add_output_note(RawOutputNote::Full(reprice.clone()));
    let reprice_sponsorship = add_required_sponsorship(&mut builder, &reprice, bridge.id())?;
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

    consume_sponsored_note(&mut mock_chain, bridge.id(), &reprice, &reprice_sponsorship).await?;
    assert_eq!(
        committed_fee(&mock_chain, bridge.id(), repriced_root())?,
        fee_schedule_entry(REPRICED_FEE)?,
        "a paused bridge should still accept a repricing note"
    );

    Ok(())
}
