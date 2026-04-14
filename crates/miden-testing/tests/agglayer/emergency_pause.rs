extern crate alloc;

use miden_agglayer::errors::{ERR_BRIDGE_IS_PAUSED, ERR_SENDER_NOT_BRIDGE_ADMIN};
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
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// Tests that pausing the bridge blocks update_ger operations.
///
/// Flow:
/// 1. Create bridge admin, GER manager, and bridge account
/// 2. Pause the bridge via an EMERGENCY_PAUSE note
/// 3. Verify that an UPDATE_GER note fails with ERR_BRIDGE_IS_PAUSED
#[tokio::test]
async fn test_pause_blocks_update_ger() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Verify bridge starts unpaused
    assert!(!AggLayerBridge::is_paused(&bridge_account)?);

    // Create both notes upfront
    let pause_note = EmergencyPauseNote::create(
        true,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let ger = ExitRoot::from([0x42u8; 32]);
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mut mock_chain = builder.build()?;

    // TX0: Pause the bridge
    let pause_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[pause_note.id()], &[])?
        .build()?;
    let pause_executed = pause_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&pause_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: Attempt update_ger while paused - should fail
    let update_ger_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let result = update_ger_tx.execute().await;

    assert_transaction_executor_error!(result, ERR_BRIDGE_IS_PAUSED);

    Ok(())
}

/// Tests that unpausing the bridge restores operations.
///
/// Flow:
/// 1. Pause the bridge
/// 2. Unpause the bridge via another EMERGENCY_PAUSE note (paused=false)
/// 3. Verify that update_ger succeeds
#[tokio::test]
async fn test_unpause_restores_operations() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Create all three notes upfront
    let pause_note = EmergencyPauseNote::create(
        true,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let unpause_note = EmergencyPauseNote::create(
        false,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(unpause_note.clone()));

    let ger = ExitRoot::from([0x42u8; 32]);
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mut mock_chain = builder.build()?;

    // TX0: Pause
    let pause_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[pause_note.id()], &[])?
        .build()?;
    let pause_executed = pause_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&pause_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: Unpause
    let unpause_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[unpause_note.id()], &[])?
        .build()?;
    let unpause_executed = unpause_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&unpause_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: update_ger should succeed now
    let update_ger_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    update_ger_tx.execute().await?;

    Ok(())
}

/// Tests that a non-admin account cannot pause the bridge.
///
/// Flow:
/// 1. Create a non-admin account
/// 2. Send an EMERGENCY_PAUSE note from the non-admin
/// 3. Verify the transaction fails with ERR_SENDER_NOT_BRIDGE_ADMIN
#[tokio::test]
async fn test_non_admin_cannot_pause() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let non_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Send pause note from non-admin
    let pause_note =
        EmergencyPauseNote::create(true, non_admin.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    let mock_chain = builder.build()?;

    let tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[pause_note.id()], &[])?
        .build()?;
    let result = tx_context.execute().await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_BRIDGE_ADMIN);

    Ok(())
}
