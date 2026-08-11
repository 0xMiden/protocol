use alloc::collections::BTreeSet;

use miden_agglayer::testing::bridge_admin_account_id;
use miden_agglayer::{AggLayerBridge, AggLayerFaucet, BridgeRoles};
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, StorageMapKey};
use miden_protocol::asset::{AssetId, FungibleAsset};
use miden_protocol::note::{Note, NoteScriptRoot};
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
};
use miden_testing::{MockChain, assert_transaction_executor_error};
use rstest::rstest;

use super::test_utils::{
    MIDEN_NETWORK_ID,
    VERIFICATION_BASE_FEE,
    add_fee_sponsorship,
    fee_faucet_id,
    is_bridge_paused,
    network_note_pricer,
};
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

/// Builds a config note repricing `note_script_root` on `account` to `amount`, authored by
/// `sender`.
///
/// `serial_seed` keeps otherwise-identical notes from sharing a note ID.
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

/// The root the repricing cases rewrite. Every network account schedules it, so the bridge and
/// faucet cases can share it. Keeping the config note's own root unchanged makes these tests cover
/// ordinary schedule administration independently of the self-repricing recovery path.
fn repriced_root() -> NoteScriptRoot {
    NetworkAccountConfigNote::script_root()
}

/// Returns the storage-map value for a set fee-schedule entry.
fn fee_schedule_entry(amount: u64) -> Word {
    Word::new([
        Felt::new(amount).expect("a fee amount should fit in a field element"),
        Felt::ZERO,
        Felt::ZERO,
        Felt::from(1u32),
    ])
}

/// Reads the committed fee schedule entry for `note_script_root` on `account_id`.
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

/// Consumes a priced feature note together with the sponsorship bound to it, then commits the
/// resulting account state.
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

/// An `ADMIN`-authored config note reprices a scheduled note, both upwards and back down, on the
/// bridge and on the faucet. Repricing downwards matters as much as upwards: it is how an
/// operator walks fees back after the chain's verification base fee falls, and it exercises the
/// manager overwriting a set-marked entry rather than filling an empty one.
///
/// The chain runs at a zero verification base fee so the transactions themselves cost nothing.
/// The config notes still require sponsorships for their production schedule price, independently
/// of the transaction fee.
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

    let raise = build_repricing_note(admin, account.id(), repriced_root(), RAISED_FEE, 1)?;
    let lower = build_repricing_note(admin, account.id(), repriced_root(), LOWERED_FEE, 2)?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(raise.clone()));
    builder.add_output_note(RawOutputNote::Full(lower.clone()));
    let raise_sponsorship =
        add_fee_sponsorship(&mut builder, &raise, account.id(), VERIFICATION_BASE_FEE)?
            .expect("the priced config note should require sponsorship");
    let lower_sponsorship =
        add_fee_sponsorship(&mut builder, &lower, account.id(), VERIFICATION_BASE_FEE)?
            .expect("the priced config note should require sponsorship");
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        committed_fee(&mock_chain, account.id(), repriced_root())?,
        fee_schedule_entry(deployed_fee),
        "the account should start at its deployment price"
    );

    consume_sponsored_note(&mut mock_chain, account.id(), &raise, &raise_sponsorship).await?;
    assert_eq!(
        committed_fee(&mock_chain, account.id(), repriced_root())?,
        fee_schedule_entry(RAISED_FEE),
        "the raised fee should replace the deployment price"
    );

    consume_sponsored_note(&mut mock_chain, account.id(), &lower, &lower_sponsorship).await?;
    assert_eq!(
        committed_fee(&mock_chain, account.id(), repriced_root())?,
        fee_schedule_entry(LOWERED_FEE),
        "the lowered fee should replace the raised one"
    );

    Ok(())
}

/// A config note that updates its own script-root entry is charged the value it writes, not the
/// value present before the transaction. Note scripts execute before network authentication, and
/// fee collection reads the updated account map. The first transaction deliberately installs an
/// extreme self-price and sponsors that new price. The second restores the benchmarked deployment
/// price while sponsoring only that lower value; it would fail if fee collection still read the
/// extreme previous entry.
#[rstest]
#[case::bridge(ManagedAccount::Bridge)]
#[case::faucet(ManagedAccount::Faucet)]
#[tokio::test]
async fn config_note_recovers_from_extreme_self_price(
    #[case] managed: ManagedAccount,
) -> anyhow::Result<()> {
    const EXTREME_FEE: u64 = 1_000_000_000_000_000;

    let admin = bridge_admin_account_id();
    let account = build_managed_account(managed)?;
    let config_root = ConstantFeePolicyConfigNote::script_root();
    let deployment_fee = network_note_pricer(VERIFICATION_BASE_FEE).price(config_root)?.as_u64();

    let raise = build_repricing_note(admin, account.id(), config_root, EXTREME_FEE, 5)?;
    let restore = build_repricing_note(admin, account.id(), config_root, deployment_fee, 6)?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(raise.clone()));
    builder.add_output_note(RawOutputNote::Full(restore.clone()));

    let raise_sponsorship: Note = FeeSponsorshipNote::builder()
        .sender(admin)
        .target_account(account.id())
        .feature_note_id(raise.id())
        .asset(FungibleAsset::new(fee_faucet_id(), EXTREME_FEE)?)
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(raise_sponsorship.clone()));
    let restore_sponsorship =
        add_fee_sponsorship(&mut builder, &restore, account.id(), VERIFICATION_BASE_FEE)?
            .expect("the restored config-note price should require sponsorship");

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        committed_fee(&mock_chain, account.id(), config_root)?,
        fee_schedule_entry(deployment_fee),
        "the config note should start at its benchmarked deployment price"
    );

    consume_sponsored_note(&mut mock_chain, account.id(), &raise, &raise_sponsorship).await?;
    assert_eq!(
        committed_fee(&mock_chain, account.id(), config_root)?,
        fee_schedule_entry(EXTREME_FEE),
        "the config note should be able to install an extreme self-price"
    );

    consume_sponsored_note(&mut mock_chain, account.id(), &restore, &restore_sponsorship).await?;
    assert_eq!(
        committed_fee(&mock_chain, account.id(), config_root)?,
        fee_schedule_entry(deployment_fee),
        "the lower new price should recover from the extreme previous entry"
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
    let attacker_note = build_repricing_note(outsider_id(), account.id(), repriced_root(), 1, 3)?;

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
        fee_schedule_entry(deployed_fee),
        "a rejected config note must leave the schedule untouched"
    );

    Ok(())
}

/// A paused bridge can still be repriced. `set_note_fee` belongs to the standards
/// `ConstantFeeManager`, not to the bridge component, so it carries no
/// `pausable::assert_not_paused` - repricing stays available alongside the other management
/// notes while every bridging entry point is halted.
///
/// Both the pause and repricing notes need a `FEE_SPONSORSHIP` covering their scheduled fees,
/// because a priced schedule requires every consumed feature note's fee to be prepaid regardless
/// of the chain's own base fee.
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
    let reprice = build_repricing_note(admin, bridge.id(), repriced_root(), REPRICED_FEE, 4)?;
    builder.add_output_note(RawOutputNote::Full(reprice.clone()));
    let reprice_sponsorship =
        add_fee_sponsorship(&mut builder, &reprice, bridge.id(), VERIFICATION_BASE_FEE)?
            .expect("the priced config note should require sponsorship");
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
        fee_schedule_entry(REPRICED_FEE),
        "a paused bridge should still accept a repricing note"
    );

    Ok(())
}
