extern crate alloc;

use miden_agglayer::{
    AggLayerBridge,
    EmergencyPauseNote,
    ExitRoot,
    UpdateGerNote,
    create_existing_bridge_account,
};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::transaction::RawOutputNote;
use miden_testing::{Auth, MockChain};

/// Tests that pausing the bridge blocks update_ger.
///
/// Flow:
/// 1. Create admin and GER manager accounts
/// 2. Create bridge account
/// 3. Admin pauses the bridge via EMERGENCY_PAUSE note
/// 4. GER manager sends UPDATE_GER note - should panic because bridge is paused
#[tokio::test]
async fn test_pause_blocks_update_ger() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account =
        create_existing_bridge_account(bridge_seed, bridge_admin.id(), ger_manager.id());
    builder.add_account(bridge_account.clone())?;

    // Step 1: Pause the bridge
    let pause_note = EmergencyPauseNote::create(
        true,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    let mock_chain = builder.build()?;

    let tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[pause_note.id()], &[])?
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    let mut paused_bridge = bridge_account.clone();
    paused_bridge.apply_delta(executed_transaction.account_delta())?;
    assert!(AggLayerBridge::is_paused(&paused_bridge)?, "bridge should be paused");

    // Step 2: Try to update GER while paused - should fail
    let mut builder2 = MockChain::builder();
    builder2.add_account(ger_manager.clone())?;
    builder2.add_account(paused_bridge.clone())?;

    let ger_bytes: [u8; 32] = [0xab; 32];
    let ger = ExitRoot::from(ger_bytes);
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), paused_bridge.id(), builder2.rng_mut())?;
    builder2.add_output_note(RawOutputNote::Full(update_ger_note.clone()));
    let mock_chain2 = builder2.build()?;

    let tx_context2 = mock_chain2
        .build_tx_context(paused_bridge.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let result = tx_context2.execute().await;
    assert!(result.is_err(), "update_ger should fail when bridge is paused");

    Ok(())
}

/// Tests that unpausing the bridge restores operations.
///
/// Flow:
/// 1. Admin pauses the bridge
/// 2. Admin unpauses the bridge
/// 3. GER manager sends UPDATE_GER note - should succeed
#[tokio::test]
async fn test_unpause_restores_operations() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account =
        create_existing_bridge_account(bridge_seed, bridge_admin.id(), ger_manager.id());
    builder.add_account(bridge_account.clone())?;

    // Step 1: Pause the bridge
    let pause_note = EmergencyPauseNote::create(
        true,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    let mock_chain = builder.build()?;

    let tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[pause_note.id()], &[])?
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    let mut paused_bridge = bridge_account.clone();
    paused_bridge.apply_delta(executed_transaction.account_delta())?;
    assert!(AggLayerBridge::is_paused(&paused_bridge)?, "bridge should be paused");

    // Step 2: Unpause the bridge
    let mut builder2 = MockChain::builder();
    builder2.add_account(bridge_admin.clone())?;
    builder2.add_account(paused_bridge.clone())?;

    let unpause_note = EmergencyPauseNote::create(
        false,
        bridge_admin.id(),
        paused_bridge.id(),
        builder2.rng_mut(),
    )?;
    builder2.add_output_note(RawOutputNote::Full(unpause_note.clone()));
    let mock_chain2 = builder2.build()?;

    // Execute unpause
    let tx_context2 = mock_chain2
        .build_tx_context(paused_bridge.id(), &[unpause_note.id()], &[])?
        .build()?;
    let executed_transaction2 = tx_context2.execute().await?;

    let mut unpaused_bridge = paused_bridge.clone();
    unpaused_bridge.apply_delta(executed_transaction2.account_delta())?;
    assert!(!AggLayerBridge::is_paused(&unpaused_bridge)?, "bridge should be unpaused");

    // Step 3: Verify update_ger succeeds on the unpaused bridge
    let ger_bytes: [u8; 32] = [0xcd; 32];
    let ger = ExitRoot::from(ger_bytes);

    let mut builder3 = MockChain::builder();
    builder3.add_account(ger_manager.clone())?;
    builder3.add_account(unpaused_bridge.clone())?;

    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), unpaused_bridge.id(), builder3.rng_mut())?;
    builder3.add_output_note(RawOutputNote::Full(update_ger_note.clone()));
    let mock_chain3 = builder3.build()?;

    let tx_context3 = mock_chain3
        .build_tx_context(unpaused_bridge.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let executed_transaction3 = tx_context3.execute().await?;

    let mut final_bridge = unpaused_bridge.clone();
    final_bridge.apply_delta(executed_transaction3.account_delta())?;
    assert!(
        AggLayerBridge::is_ger_registered(ger, final_bridge)?,
        "GER should be registered after unpause"
    );

    Ok(())
}

/// Tests that a non-admin cannot pause the bridge.
///
/// Flow:
/// 1. Create admin, GER manager, and a random non-admin account
/// 2. Non-admin sends EMERGENCY_PAUSE note - should panic with ERR_SENDER_NOT_BRIDGE_ADMIN
#[tokio::test]
async fn test_non_admin_cannot_pause() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Non-admin account
    let non_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account =
        create_existing_bridge_account(bridge_seed, bridge_admin.id(), ger_manager.id());
    builder.add_account(bridge_account.clone())?;

    // Non-admin tries to pause
    let pause_note =
        EmergencyPauseNote::create(true, non_admin.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    let mock_chain = builder.build()?;

    let tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[pause_note.id()], &[])?
        .build()?;
    let result = tx_context.execute().await;
    assert!(result.is_err(), "non-admin should not be able to pause the bridge");

    Ok(())
}
