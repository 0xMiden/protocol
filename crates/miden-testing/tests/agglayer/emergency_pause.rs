extern crate alloc;

use miden_agglayer::errors::{ERR_BRIDGE_IS_PAUSED, ERR_SENDER_NOT_BRIDGE_ADMIN};
use miden_agglayer::{
    AggLayerBridge,
    ConfigAggBridgeNote,
    EmergencyPauseNote,
    EthAddress,
    UpdateGerNote,
    create_existing_bridge_account,
};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::transaction::RawOutputNote;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// Tests that consuming an EMERGENCY_PAUSE note with paused=true sets the pause flag,
/// and that consuming one with paused=false clears it.
#[tokio::test]
async fn test_emergency_pause_and_unpause() -> anyhow::Result<()> {
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

    // Verify the bridge is NOT paused initially
    assert!(
        !AggLayerBridge::is_paused(&bridge_account)?,
        "Bridge should not be paused initially"
    );

    // --- PAUSE the bridge ---
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

    let mut updated_bridge = bridge_account.clone();
    updated_bridge.apply_delta(executed_transaction.account_delta())?;

    // Verify the bridge IS paused
    assert!(
        AggLayerBridge::is_paused(&updated_bridge)?,
        "Bridge should be paused after consuming EMERGENCY_PAUSE note"
    );

    // --- UNPAUSE the bridge ---
    let mut builder2 = MockChain::builder();

    let _bridge_admin2 = builder2.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // We need to re-add the updated bridge and create a new unpause note from the same admin
    // For simplicity, create a fresh chain with the paused bridge
    let unpause_note = EmergencyPauseNote::create(
        false,
        bridge_admin.id(),
        updated_bridge.id(),
        builder2.rng_mut(),
    )?;

    builder2.add_account(updated_bridge.clone())?;
    builder2.add_output_note(RawOutputNote::Full(unpause_note.clone()));

    // We need the bridge_admin account to be the sender, so we need it in the mock chain.
    // Re-add the admin account from the first chain's state.
    let mock_chain2 = builder2.build()?;

    let tx_context2 = mock_chain2
        .build_tx_context(updated_bridge.id(), &[unpause_note.id()], &[])?
        .build()?;
    let executed_transaction2 = tx_context2.execute().await?;

    let mut unpaused_bridge = updated_bridge.clone();
    unpaused_bridge.apply_delta(executed_transaction2.account_delta())?;

    // Verify the bridge is NOT paused
    assert!(
        !AggLayerBridge::is_paused(&unpaused_bridge)?,
        "Bridge should not be paused after unpause"
    );

    Ok(())
}

/// Tests that a non-admin sender cannot pause the bridge.
#[tokio::test]
async fn test_emergency_pause_rejects_non_admin() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    // A non-admin account that will try to pause the bridge
    let non_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Create an EMERGENCY_PAUSE note from the non-admin
    let pause_note =
        EmergencyPauseNote::create(true, non_admin.id(), bridge_account.id(), builder.rng_mut())?;

    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[pause_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_BRIDGE_ADMIN);

    Ok(())
}

/// Tests that update_ger is blocked when the bridge is paused.
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

    // First, pause the bridge
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

    // Now try to send an UPDATE_GER note to the paused bridge
    let mut builder2 = MockChain::builder();
    builder2.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    builder2.add_account(paused_bridge.clone())?;

    let ger_bytes: [u8; 32] = [0xab; 32];
    let ger = miden_agglayer::ExitRoot::from(ger_bytes);
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), paused_bridge.id(), builder2.rng_mut())?;

    builder2.add_output_note(RawOutputNote::Full(update_ger_note.clone()));
    let mock_chain2 = builder2.build()?;

    let result = mock_chain2
        .build_tx_context(paused_bridge.id(), &[update_ger_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_BRIDGE_IS_PAUSED);

    Ok(())
}

/// Tests that register_faucet (CONFIG_AGG_BRIDGE) is blocked when the bridge is paused.
#[tokio::test]
async fn test_pause_blocks_register_faucet() -> anyhow::Result<()> {
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

    // First, pause the bridge
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

    // Now try to send a CONFIG_AGG_BRIDGE note to the paused bridge
    let mut builder2 = MockChain::builder();
    builder2.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    builder2.add_account(paused_bridge.clone())?;

    let faucet_to_register = AccountId::dummy(
        [42; 15],
        AccountIdVersion::Version0,
        AccountType::FungibleFaucet,
        AccountStorageMode::Network,
    );
    let origin_token_address =
        EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let config_note = ConfigAggBridgeNote::create(
        faucet_to_register,
        &origin_token_address,
        bridge_admin.id(),
        paused_bridge.id(),
        builder2.rng_mut(),
    )?;

    builder2.add_output_note(RawOutputNote::Full(config_note.clone()));
    let mock_chain2 = builder2.build()?;

    let result = mock_chain2
        .build_tx_context(paused_bridge.id(), &[config_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_BRIDGE_IS_PAUSED);

    Ok(())
}
