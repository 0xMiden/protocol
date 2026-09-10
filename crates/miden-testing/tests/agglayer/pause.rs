use miden_agglayer::{
    AggLayerBridge,
    B2AggNote,
    ClaimNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    ConversionMetadata,
    DeregisterAggFaucetNote,
    ExitRoot,
    MetadataHash,
    RemoveGerNote,
    UpdateGerNote,
};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Felt;
use miden_protocol::account::{AccountId, AccountType, StorageMapKey};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::note::{Note, NoteAssets};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::errors::standards::{
    ERR_PAUSABLE_IS_PAUSED,
    ERR_PAUSE_CONFIG_TARGET_ACCOUNT_MISMATCH,
    ERR_SENDER_LACKS_ROLE,
};
use miden_standards::interop::eth::EthAddress;
use miden_standards::note::config::PauseConfig;
use miden_standards::note::{NetworkAccountTarget, NetworkNoteExt};
use miden_testing::{MockChain, MockChainBuilder, assert_transaction_executor_error};

use super::test_utils::{
    BridgeSetup,
    ClaimDataSource,
    bridge_admin_account_id,
    is_bridge_paused,
    setup_bridge,
};
use crate::consume_note;

// CONSTANTS
// ================================================================================================

const DUMMY_ETH_ADDRESS: &str = "0x00000000000000000000000000000000000000aa";

// HELPERS
// ================================================================================================

/// Builds a bridge-targeted [`PauseConfigNote`] for `action` sent by `sender`.
fn pause_config_note(
    sender: AccountId,
    bridge_id: AccountId,
    action: PauseConfig,
) -> anyhow::Result<Note> {
    // Vary the rng seed by action so a pause and an unpause note built in the same test get
    // distinct serial numbers.
    let seed = match action {
        PauseConfig::Pause => 41u32,
        PauseConfig::Unpause => 42u32,
    };
    let mut rng = RandomCoin::new([Felt::from(seed); 4].into());
    Ok(AggLayerBridge::pause_note(action, sender, bridge_id, &mut rng)?)
}

/// Builds an authorized [`PauseConfigNote`] for `action` and stages it on the chain so it can later
/// be consumed as an authenticated note. The pauser sends `Pause`; the admin sends `Unpause`.
fn stage_pause_note(
    builder: &mut MockChainBuilder,
    setup: &BridgeSetup,
    action: PauseConfig,
) -> anyhow::Result<Note> {
    let sender = match action {
        PauseConfig::Pause => setup.pauser.id(),
        PauseConfig::Unpause => bridge_admin_account_id(),
    };
    let note = pause_config_note(sender, setup.bridge.id(), action)?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    Ok(note)
}

/// Builds the note a "paused bridge rejects <entry point>" test stages against the bridge.
type BuildNote<'a> = &'a dyn Fn(&mut MockChainBuilder, &BridgeSetup) -> anyhow::Result<Note>;

/// Shared skeleton for the "paused bridge rejects <entry point>" tests: sets up the bridge,
/// stages the note produced by `build_note`, pauses the bridge, and asserts that consuming the
/// note fails with `ERR_PAUSABLE_IS_PAUSED`.
async fn assert_note_rejected_while_paused(build_note: BuildNote<'_>) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let note = build_note(&mut builder, &setup)?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let pause_note = stage_pause_note(&mut builder, &setup, PauseConfig::Pause)?;
    let mut mock_chain = builder.build()?;

    consume_note(&mut mock_chain, setup.bridge.id(), &pause_note).await?;

    let result = mock_chain
        .build_transaction(setup.bridge.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_IS_PAUSED);
    Ok(())
}

/// Returns a stable account ID used as a faucet fixture in pause tests.
fn dummy_faucet_id() -> AccountId {
    AccountIdBuilder::new().build_with_seed([7; 32])
}

// TESTS
// ================================================================================================

/// A PAUSER-sent PAUSE_CONFIG note pauses the bridge and an ADMIN-sent one unpauses it. This also
/// proves the notes pass the bridge's note allowlist and are routable as network notes.
#[tokio::test]
async fn pause_config_note_pauses_and_unpauses_bridge() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let pause_note = stage_pause_note(&mut builder, &setup, PauseConfig::Pause)?;
    let unpause_note = stage_pause_note(&mut builder, &setup, PauseConfig::Unpause)?;
    let mut mock_chain = builder.build()?;

    // The note must be discoverable by network-note routing, and routed to the bridge: the same
    // attachment that delivers the pause to the bridge is what the PAUSE_CONFIG script asserts
    // against the consuming account.
    assert!(pause_note.is_network_note(), "pause note should be a routable network note");
    let target = NetworkAccountTarget::try_from(pause_note.attachments())?;
    assert_eq!(target.target_id(), setup.bridge.id(), "pause note must be routed to the bridge");

    consume_note(&mut mock_chain, setup.bridge.id(), &pause_note).await?;
    assert!(is_bridge_paused(&mock_chain, setup.bridge.id())?);

    consume_note(&mut mock_chain, setup.bridge.id(), &unpause_note).await?;
    assert!(!is_bridge_paused(&mock_chain, setup.bridge.id())?);

    Ok(())
}

/// The bridge admin cannot pause unless it separately holds the `PAUSER` role.
#[tokio::test]
async fn admin_without_pauser_role_cannot_pause() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let mock_chain = builder.build()?;

    let note = pause_config_note(bridge_admin_account_id(), setup.bridge.id(), PauseConfig::Pause)?;
    let result = mock_chain
        .build_transaction(setup.bridge.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);
    Ok(())
}

/// Holding the `PAUSER` role does not authorize unpause, which remains admin-only.
#[tokio::test]
async fn pauser_cannot_unpause_a_paused_bridge() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let pause_note = stage_pause_note(&mut builder, &setup, PauseConfig::Pause)?;
    let mut mock_chain = builder.build()?;

    consume_note(&mut mock_chain, setup.bridge.id(), &pause_note).await?;
    assert!(is_bridge_paused(&mock_chain, setup.bridge.id())?);

    let note = pause_config_note(setup.pauser.id(), setup.bridge.id(), PauseConfig::Unpause)?;
    let result = mock_chain
        .build_transaction(setup.bridge.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);
    assert!(is_bridge_paused(&mock_chain, setup.bridge.id())?);
    Ok(())
}

/// The `PAUSE_CONFIG` script asserts its target, so a `PAUSER`-issued pause note built for a
/// *different* account is rejected by the bridge even though its sender is authorized.
#[tokio::test]
async fn pause_note_targeting_another_account_is_rejected() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let mock_chain = builder.build()?;

    // Pauser-sent, but built for an unrelated account: the attachment names that account, not the
    // bridge, so the script's target check rejects it.
    let other_account = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_seed([9; 32]);
    let mut rng = RandomCoin::new([Felt::from(45u32); 4].into());
    let note =
        AggLayerBridge::pause_note(PauseConfig::Pause, setup.pauser.id(), other_account, &mut rng)?;

    let result = mock_chain
        .build_transaction(setup.bridge.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSE_CONFIG_TARGET_ACCOUNT_MISMATCH);
    assert!(!is_bridge_paused(&mock_chain, setup.bridge.id())?);
    Ok(())
}

/// A paused bridge rejects GER injection via UPDATE_GER.
#[tokio::test]
async fn paused_bridge_rejects_update_ger() -> anyhow::Result<()> {
    assert_note_rejected_while_paused(&|builder, setup| {
        Ok(UpdateGerNote::create(
            ExitRoot::from([0x11; 32]),
            setup.ger_injector.id(),
            setup.bridge.id(),
            builder.rng_mut(),
        )?)
    })
    .await
}

/// A paused bridge rejects faucet registration via CONFIG_AGG_BRIDGE (`register_faucet` panics
/// before any storage write).
#[tokio::test]
async fn paused_bridge_rejects_register_faucet() -> anyhow::Result<()> {
    assert_note_rejected_while_paused(&|builder, setup| {
        Ok(ConfigAggBridgeNote::create(
            ConversionMetadata {
                faucet_account_id: dummy_faucet_id(),
                origin_token_address: EthAddress::from_hex(DUMMY_ETH_ADDRESS)?,
                scale: 0,
                origin_network: 1,
                is_native: false,
                metadata_hash: MetadataHash::from_token_info("Token", "TOK", 8),
            },
            setup.faucet_manager.id(),
            setup.bridge.id(),
            builder.rng_mut(),
        )?)
    })
    .await
}

/// Faucet deregistration remains available while paused so an operator can revoke a compromised
/// faucet without reopening claims and bridge-outs.
#[tokio::test]
async fn paused_bridge_allows_deregister_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let faucet_id = dummy_faucet_id();

    let register_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: faucet_id,
            origin_token_address: EthAddress::from_hex(DUMMY_ETH_ADDRESS)?,
            scale: 0,
            origin_network: 1,
            is_native: false,
            metadata_hash: MetadataHash::from_token_info("Token", "TOK", 8),
        },
        setup.faucet_manager.id(),
        setup.bridge.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(register_note.clone()));

    let deregister_note = DeregisterAggFaucetNote::create(
        faucet_id,
        setup.faucet_manager.id(),
        setup.bridge.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(deregister_note.clone()));
    let pause_note = stage_pause_note(&mut builder, &setup, PauseConfig::Pause)?;
    let mut mock_chain = builder.build()?;

    consume_note(&mut mock_chain, setup.bridge.id(), &register_note).await?;
    consume_note(&mut mock_chain, setup.bridge.id(), &pause_note).await?;
    consume_note(&mut mock_chain, setup.bridge.id(), &deregister_note).await?;

    let bridge = mock_chain.committed_account(setup.bridge.id())?;
    let faucet_key = StorageMapKey::from_raw(AccountIdKey::new(faucet_id).as_word());
    assert_eq!(
        bridge
            .storage()
            .get_map_item(AggLayerBridge::faucet_registry_map_slot_name(), faucet_key)?,
        [Felt::ZERO; 4].into(),
        "faucet should be deregistered while the bridge remains paused"
    );
    assert!(is_bridge_paused(&mock_chain, setup.bridge.id())?);

    Ok(())
}

/// A paused bridge rejects bridging out via B2AGG (the pause guard fires before the faucet
/// registry lookup).
#[tokio::test]
async fn paused_bridge_rejects_bridge_out() -> anyhow::Result<()> {
    assert_note_rejected_while_paused(&|builder, setup| {
        let faucet_id = dummy_faucet_id();
        let asset: Asset = FungibleAsset::new(faucet_id, 100)?.into();
        Ok(B2AggNote::create(
            1,
            EthAddress::from_hex(DUMMY_ETH_ADDRESS)?,
            NoteAssets::new(vec![asset])?,
            setup.bridge.id(),
            faucet_id,
            builder.rng_mut(),
        )?)
    })
    .await
}

/// A paused bridge rejects claims via CLAIM (the pause guard fires before proof validation).
#[tokio::test]
async fn paused_bridge_rejects_claim() -> anyhow::Result<()> {
    assert_note_rejected_while_paused(&|builder, setup| {
        let (proof_data, leaf_data, _ger, _cgi_chain_hash) = ClaimDataSource::L1ToMiden.get_data();
        let miden_claim_amount = leaf_data.amount.scale_to_asset_amount(10)?;
        let storage = ClaimNoteStorage {
            proof_data,
            leaf_data,
            miden_claim_amount,
        };
        Ok(ClaimNote::create(
            storage,
            setup.bridge.id(),
            setup.faucet_manager.id(),
            builder.rng_mut(),
        )?)
    })
    .await
}

/// `remove_ger` is deliberately exempt from the pause: a paused bridge can still revoke a
/// registered GER, the emergency remediation this control exists for.
#[tokio::test]
async fn paused_bridge_allows_remove_ger() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;

    let ger = ExitRoot::from([0x22; 32]);
    let update_note =
        UpdateGerNote::create(ger, setup.ger_injector.id(), setup.bridge.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_note.clone()));
    let remove_note =
        RemoveGerNote::create(ger, setup.ger_remover.id(), setup.bridge.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(remove_note.clone()));
    let pause_note = stage_pause_note(&mut builder, &setup, PauseConfig::Pause)?;

    let mut mock_chain = builder.build()?;

    // Register the GER while the bridge is live, then pause.
    consume_note(&mut mock_chain, setup.bridge.id(), &update_note).await?;
    consume_note(&mut mock_chain, setup.bridge.id(), &pause_note).await?;

    // The GER remover can still revoke the GER while the bridge is paused.
    consume_note(&mut mock_chain, setup.bridge.id(), &remove_note).await?;

    let bridge = mock_chain.committed_account(setup.bridge.id())?;
    assert!(is_bridge_paused(&mock_chain, setup.bridge.id())?);
    assert!(
        !AggLayerBridge::is_ger_registered(ger, bridge)?,
        "GER should have been removed while the bridge was paused"
    );

    Ok(())
}

/// Unpausing restores normal operation: a gated procedure that would have aborted while paused
/// succeeds after the unpause.
#[tokio::test]
async fn unpause_restores_operation() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;

    let ger = ExitRoot::from([0x33; 32]);
    let update_note =
        UpdateGerNote::create(ger, setup.ger_injector.id(), setup.bridge.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_note.clone()));
    let pause_note = stage_pause_note(&mut builder, &setup, PauseConfig::Pause)?;
    let unpause_note = stage_pause_note(&mut builder, &setup, PauseConfig::Unpause)?;

    let mut mock_chain = builder.build()?;

    consume_note(&mut mock_chain, setup.bridge.id(), &pause_note).await?;
    consume_note(&mut mock_chain, setup.bridge.id(), &unpause_note).await?;

    consume_note(&mut mock_chain, setup.bridge.id(), &update_note).await?;

    let bridge = mock_chain.committed_account(setup.bridge.id())?;
    assert!(
        AggLayerBridge::is_ger_registered(ger, bridge)?,
        "GER injection should succeed after unpausing"
    );

    Ok(())
}
