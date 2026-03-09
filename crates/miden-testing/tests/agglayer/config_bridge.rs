extern crate alloc;

use miden_agglayer::{
    AggLayerBridge,
    ConfigAggBridgeNote,
    create_existing_bridge_account,
    faucet_registry_key,
};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::transaction::OutputNote;
use miden_protocol::{Felt, FieldElement};
use miden_testing::{Auth, MockChain};

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
    let bridge_admin =
        builder.add_existing_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Poseidon2 })?;

    // CREATE GER MANAGER ACCOUNT (not used in this test, but distinct from admin)
    let ger_manager =
        builder.add_existing_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Poseidon2 })?;

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
    let registry_slot_name = AggLayerBridge::faucet_registry_slot_name();
    let key = faucet_registry_key(faucet_to_register);
    let value_before = bridge_account.storage().get_map_item(registry_slot_name, key)?;
    assert_eq!(
        value_before,
        [Felt::ZERO; 4].into(),
        "Faucet should not be in registry before registration"
    );

    // CREATE CONFIG_AGG_BRIDGE NOTE
    let config_note = ConfigAggBridgeNote::create(
        faucet_to_register,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(OutputNote::Full(config_note.clone()));
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
    let expected_value = [Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO].into();
    assert_eq!(
        value_after, expected_value,
        "Faucet should be registered with value [0, 0, 0, 1]"
    );

    Ok(())
}
