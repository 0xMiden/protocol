extern crate alloc;

use alloc::vec::Vec;

use miden_agglayer::{
    AggLayerBridge,
    ConfigAggBridgeNote,
    EthAddress,
    create_existing_bridge_account,
};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Hasher, Word};
use miden_testing::{Auth, MockChain};

/// Computes the `token_registry_map` key for a given (origin_token_address, origin_network) pair.
///
/// Mirrors `bridge_config::hash_token_address` in `bridge_config.masm`: hashes the 5-felt token
/// address concatenated with the origin network felt (LE-packed u32), using Poseidon2.
fn token_registry_key(origin_token_address: &EthAddress, origin_network: u32) -> Word {
    let mut elements: Vec<Felt> = origin_token_address.to_elements();
    let origin_network_packed = u32::from_le_bytes(origin_network.to_be_bytes());
    elements.push(Felt::from(origin_network_packed));
    Hasher::hash_elements(&elements)
}

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
    let origin_network = 1u32;
    let config_note = ConfigAggBridgeNote::create(
        faucet_to_register,
        &origin_token_address,
        origin_network,
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

/// Regression test for issue #2799.
///
/// Two faucets registered for the same `origin_token_address` but different `origin_network`
/// values must coexist as independent entries in the bridge's `token_registry_map`. Before the
/// fix, the registry was keyed on `Poseidon2(origin_token_address)` alone, so registering the
/// second faucet would silently overwrite the first and a CLAIM bound to one network could
/// resolve to the faucet of the other. This test confirms each `(origin_token_address,
/// origin_network)` pair maps to its own faucet ID after registration.
#[tokio::test]
async fn test_config_agg_bridge_distinguishes_origin_network() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT (note sender)
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT (unused here, but distinct from admin)
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT (starts with empty token registry)
    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Two distinct faucet IDs that both share the same origin token address but live on
    // different origin networks.
    let faucet_network_1 = AccountId::dummy(
        [11; 15],
        AccountIdVersion::Version0,
        AccountType::FungibleFaucet,
        AccountStorageMode::Network,
    );
    let faucet_network_2 = AccountId::dummy(
        [22; 15],
        AccountIdVersion::Version0,
        AccountType::FungibleFaucet,
        AccountStorageMode::Network,
    );

    let origin_token_address =
        EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let origin_network_1: u32 = 1;
    let origin_network_2: u32 = 2;

    let config_note_1 = ConfigAggBridgeNote::create(
        faucet_network_1,
        &origin_token_address,
        origin_network_1,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    let config_note_2 = ConfigAggBridgeNote::create(
        faucet_network_2,
        &origin_token_address,
        origin_network_2,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(RawOutputNote::Full(config_note_1.clone()));
    builder.add_output_note(RawOutputNote::Full(config_note_2.clone()));
    let mut mock_chain = builder.build()?;

    // Consume the two registration notes in two separate transactions so each one writes its
    // own delta to the bridge account.
    let tx1 = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note_1.id()], &[])?
        .build()?;
    let executed_1 = tx1.execute().await?;
    mock_chain.add_pending_executed_transaction(&executed_1)?;
    mock_chain.prove_next_block()?;

    let tx2 = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note_2.id()], &[])?
        .build()?;
    let executed_2 = tx2.execute().await?;

    // Apply both deltas onto a single bridge account view.
    let mut updated_bridge = bridge_account.clone();
    updated_bridge.apply_delta(executed_1.account_delta())?;
    updated_bridge.apply_delta(executed_2.account_delta())?;

    // VERIFY both (address, network) pairs resolve to their own faucet, and the keys are distinct.
    let token_registry_slot = AggLayerBridge::token_registry_map_slot_name();
    let key_1 = token_registry_key(&origin_token_address, origin_network_1);
    let key_2 = token_registry_key(&origin_token_address, origin_network_2);
    assert_ne!(key_1, key_2, "registry keys for distinct origin networks must differ");

    let value_1 = updated_bridge.storage().get_map_item(token_registry_slot, key_1)?;
    let value_2 = updated_bridge.storage().get_map_item(token_registry_slot, key_2)?;

    let expected_1: Word = [
        Felt::ZERO,
        Felt::ZERO,
        faucet_network_1.suffix(),
        faucet_network_1.prefix().as_felt(),
    ]
    .into();
    let expected_2: Word = [
        Felt::ZERO,
        Felt::ZERO,
        faucet_network_2.suffix(),
        faucet_network_2.prefix().as_felt(),
    ]
    .into();
    assert_eq!(value_1, expected_1, "(addr, network=1) must resolve to faucet_network_1");
    assert_eq!(value_2, expected_2, "(addr, network=2) must resolve to faucet_network_2");

    Ok(())
}
