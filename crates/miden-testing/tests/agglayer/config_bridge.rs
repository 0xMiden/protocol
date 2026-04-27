extern crate alloc;

use miden_agglayer::errors::{ERR_FAUCET_NOT_REGISTERED, ERR_SENDER_NOT_BRIDGE_ADMIN};
use miden_agglayer::{
    AggLayerBridge,
    ConfigAggBridgeNote,
    DeregisterAggBridgeNote,
    EthAddress,
    create_existing_bridge_account,
};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Hasher};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// Tests that a CONFIG_AGG_BRIDGE note registers a faucet in the bridge's faucet registry.
///
/// Flow:
/// 1. Create an admin (sender) account
/// 2. Create a bridge account with the admin as authorized operator
/// 3. Create a CONFIG_AGG_BRIDGE note carrying a faucet ID, sent by the admin
/// 4. Consume the note with the bridge account
/// 5. Verify the faucet is now in the bridge's faucet_registry map
#[tokio::test]
async fn test_config_agg_bridge_registers_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT (note sender)
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT (not used in this test, but distinct from admin)
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT (starts with empty faucet registry)
    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Use a dummy faucet ID to register (any valid AccountId will do)
    let faucet_to_register = AccountId::dummy(
        [42; 15],
        AccountIdVersion::Version0,
        AccountType::FungibleFaucet,
        AccountStorageMode::Network,
    );

    // Verify the faucet is NOT in the registry before registration
    let registry_slot_name = AggLayerBridge::faucet_registry_map_slot_name();
    let key = AccountIdKey::new(faucet_to_register).as_word();
    let value_before = bridge_account.storage().get_map_item(registry_slot_name, key)?;
    assert_eq!(
        value_before,
        [Felt::ZERO; 4].into(),
        "Faucet should not be in registry before registration"
    );

    // CREATE CONFIG_AGG_BRIDGE NOTE
    // Use a dummy origin token address for this test
    let origin_token_address =
        EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let config_note = ConfigAggBridgeNote::create(
        faucet_to_register,
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(RawOutputNote::Full(config_note.clone()));
    let mock_chain = builder.build()?;

    // CONSUME THE CONFIG_AGG_BRIDGE NOTE WITH THE BRIDGE ACCOUNT
    let tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    // VERIFY FAUCET IS NOW REGISTERED
    let mut updated_bridge = bridge_account.clone();
    updated_bridge.apply_delta(executed_transaction.account_delta())?;

    let value_after = updated_bridge.storage().get_map_item(registry_slot_name, key)?;
    // TODO: use a getter helper on AggLayerBridge once available
    // (see https://github.com/0xMiden/protocol/issues/2548)
    let expected_value = [Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO].into();
    assert_eq!(
        value_after, expected_value,
        "Faucet should be registered with value [1, 0, 0, 0]"
    );

    Ok(())
}

/// Tests that a DEREGISTER_AGG_BRIDGE note clears a previously-registered faucet from BOTH
/// the faucet registry and the token registry maps.
///
/// Flow:
/// 1. Create admin + bridge accounts
/// 2. Register a faucet via CONFIG_AGG_BRIDGE
/// 3. Verify both registries hold the expected non-zero values
/// 4. Deregister via DEREGISTER_AGG_BRIDGE
/// 5. Verify both registries hold [0, 0, 0, 0]
#[tokio::test]
async fn test_deregister_agg_bridge_clears_both_registries() -> anyhow::Result<()> {
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

    let faucet_to_register = AccountId::dummy(
        [42; 15],
        AccountIdVersion::Version0,
        AccountType::FungibleFaucet,
        AccountStorageMode::Network,
    );
    let origin_token_address =
        EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

    // ---- Build registration + deregistration notes ----
    let config_note = ConfigAggBridgeNote::create(
        faucet_to_register,
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    let deregister_note = DeregisterAggBridgeNote::create(
        faucet_to_register,
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));
    builder.add_output_note(RawOutputNote::Full(deregister_note.clone()));

    let mut mock_chain = builder.build()?;

    // ---- TX0: consume CONFIG_AGG_BRIDGE to register ----
    let register_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let register_executed = register_tx.execute().await?;

    let mut updated_bridge = bridge_account.clone();
    updated_bridge.apply_delta(register_executed.account_delta())?;

    let faucet_slot = AggLayerBridge::faucet_registry_map_slot_name();
    let token_slot = AggLayerBridge::token_registry_map_slot_name();
    let faucet_key = AccountIdKey::new(faucet_to_register).as_word();
    let token_key = Hasher::hash_elements(&origin_token_address.to_elements());

    assert_eq!(
        updated_bridge.storage().get_map_item(faucet_slot, faucet_key)?,
        [Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO].into(),
        "faucet_registry should be [1, 0, 0, 0] after registration"
    );
    assert_eq!(
        updated_bridge.storage().get_map_item(token_slot, token_key)?,
        [
            Felt::ZERO,
            Felt::ZERO,
            faucet_to_register.suffix(),
            faucet_to_register.prefix().as_felt(),
        ]
        .into(),
        "token_registry should hold the faucet ID after registration"
    );

    mock_chain.add_pending_executed_transaction(&register_executed)?;
    mock_chain.prove_next_block()?;

    // ---- TX1: consume DEREGISTER_AGG_BRIDGE to clear ----
    let deregister_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[deregister_note.id()], &[])?
        .build()?;
    let deregister_executed = deregister_tx.execute().await?;

    updated_bridge.apply_delta(deregister_executed.account_delta())?;

    assert_eq!(
        updated_bridge.storage().get_map_item(faucet_slot, faucet_key)?,
        [Felt::ZERO; 4].into(),
        "faucet_registry should be cleared to [0, 0, 0, 0] after deregistration"
    );
    assert_eq!(
        updated_bridge.storage().get_map_item(token_slot, token_key)?,
        [Felt::ZERO; 4].into(),
        "token_registry should be cleared to [0, 0, 0, 0] after deregistration"
    );

    Ok(())
}

/// Tests that DEREGISTER_AGG_BRIDGE panics with `ERR_FAUCET_NOT_REGISTERED` when the
/// targeted faucet was never registered (or has already been deregistered).
#[tokio::test]
async fn test_deregister_agg_bridge_fails_when_not_registered() -> anyhow::Result<()> {
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

    let faucet_id = AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version0,
        AccountType::FungibleFaucet,
        AccountStorageMode::Network,
    );
    let origin_token_address =
        EthAddress::from_hex("0xdeadbeefcafebabe0000111122223333deadbeef").unwrap();

    let deregister_note = DeregisterAggBridgeNote::create(
        faucet_id,
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(deregister_note.clone()));
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[deregister_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FAUCET_NOT_REGISTERED);

    Ok(())
}

/// Tests that DEREGISTER_AGG_BRIDGE panics with `ERR_SENDER_NOT_BRIDGE_ADMIN` when the note
/// sender is not the bridge admin, even if the faucet is currently registered.
#[tokio::test]
async fn test_deregister_agg_bridge_fails_when_sender_not_admin() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let attacker = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let faucet_id = AccountId::dummy(
        [99; 15],
        AccountIdVersion::Version0,
        AccountType::FungibleFaucet,
        AccountStorageMode::Network,
    );
    let origin_token_address =
        EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

    // Register the faucet legitimately first, so the panic must come from the auth check rather
    // than the assert_faucet_registered check.
    let config_note = ConfigAggBridgeNote::create(
        faucet_id,
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    let attacker_deregister_note = DeregisterAggBridgeNote::create(
        faucet_id,
        &origin_token_address,
        attacker.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));
    builder.add_output_note(RawOutputNote::Full(attacker_deregister_note.clone()));
    let mut mock_chain = builder.build()?;

    let register_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let register_executed = register_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&register_executed)?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[attacker_deregister_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_BRIDGE_ADMIN);

    Ok(())
}
