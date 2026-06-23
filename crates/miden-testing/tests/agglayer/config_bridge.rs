extern crate alloc;

use alloc::vec::Vec;

use miden_agglayer::errors::{ERR_FAUCET_NOT_REGISTERED, ERR_SENDER_NOT_BRIDGE_ADMIN};
use miden_agglayer::{
    AggLayerBridge,
    ConfigAggBridgeNote,
    ConversionMetadata,
    DeregisterAggFaucetNote,
    EthAddress,
    MetadataHash,
    create_existing_bridge_account,
};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, StorageMapKey};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Hasher, Word};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// Computes the `token_registry_map` key for a given (origin_token_address, origin_network) pair.
///
/// Mirrors `bridge_config::hash_token_address` in `bridge_config.masm`: hashes the 5-felt token
/// address concatenated with the origin network felt (LE-packed u32), using Poseidon2.
fn token_registry_key(origin_token_address: &EthAddress, origin_network: u32) -> StorageMapKey {
    let mut elements: Vec<Felt> = origin_token_address.to_elements();
    let origin_network_packed = u32::from_le_bytes(origin_network.to_be_bytes());
    elements.push(Felt::from(origin_network_packed));
    StorageMapKey::from_raw(Hasher::hash_elements(&elements))
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

    // CREATE GER INJECTOR ACCOUNT (not used in this test, but distinct from admin)
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER REMOVER ACCOUNT (not used in this test, but distinct from admin and injector)
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT (starts with empty faucet registry)
    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_injector.id(),
        ger_remover.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Use a dummy faucet ID to register (any valid AccountId will do)
    let faucet_to_register =
        AccountId::dummy([42; 15], AccountIdVersion::Version1, AccountType::Public);

    // Verify the faucet is NOT in the registry before registration
    let registry_slot_name = AggLayerBridge::faucet_registry_map_slot_name();
    let key = StorageMapKey::from_raw(AccountIdKey::new(faucet_to_register).as_word());
    let value_before = bridge_account.storage().get_map_item(registry_slot_name, key)?;
    assert_eq!(
        value_before,
        [Felt::ZERO; 4].into(),
        "Faucet should not be in registry before registration"
    );

    // CREATE CONFIG_AGG_BRIDGE NOTE
    let origin_token_address =
        EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let scale = 0u8;
    let origin_network = 1u32;
    let metadata_hash = MetadataHash::from_token_info("USD Coin", "USDC", 6);
    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: faucet_to_register,
            origin_token_address,
            scale,
            origin_network,
            is_native: false,
            metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(RawOutputNote::Full(config_note.clone()));
    let mock_chain = builder.build()?;

    // CONSUME THE CONFIG_AGG_BRIDGE NOTE WITH THE BRIDGE ACCOUNT
    let tx_context =
        mock_chain.build_tx_context(bridge_account.id(), &[], &[config_note])?.build()?;
    let executed_transaction = tx_context.execute().await?;

    // VERIFY FAUCET IS NOW REGISTERED
    let mut updated_bridge = bridge_account.clone();
    updated_bridge.apply_patch(executed_transaction.account_patch())?;

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

    // CREATE GER INJECTOR ACCOUNT (unused here, but distinct from admin)
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT (starts with empty token registry)
    let bridge_seed = builder.rng_mut().draw_word();
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_injector.id(),
        ger_remover.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Two distinct faucet IDs that both share the same origin token address but live on
    // different origin networks.
    let faucet_network_1 =
        AccountId::dummy([11; 15], AccountIdVersion::Version1, AccountType::Public);
    let faucet_network_2 =
        AccountId::dummy([22; 15], AccountIdVersion::Version1, AccountType::Public);

    let origin_token_address =
        EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let origin_network_1: u32 = 1;
    let origin_network_2: u32 = 2;

    let metadata_hash = MetadataHash::from_token_info("USD Coin", "USDC", 6);
    let config_note_1 = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: faucet_network_1,
            origin_token_address,
            scale: 0,
            origin_network: origin_network_1,
            is_native: false,
            metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    let config_note_2 = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: faucet_network_2,
            origin_token_address,
            scale: 0,
            origin_network: origin_network_2,
            is_native: false,
            metadata_hash,
        },
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
    updated_bridge.apply_patch(executed_1.account_patch())?;
    updated_bridge.apply_patch(executed_2.account_patch())?;

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

/// Builds the `faucet_metadata_map` sub-key for a faucet: `[sub_key, 0, suffix, prefix]`.
///
/// Mirrors the key layout written by `register_faucet` / read by `get_faucet_conversion_info`.
fn faucet_metadata_key(faucet: AccountId, sub_key: u8) -> StorageMapKey {
    StorageMapKey::from_raw(
        [Felt::from(sub_key), Felt::ZERO, faucet.suffix(), faucet.prefix().as_felt()].into(),
    )
}

/// Tests that a DEREGISTER_AGG_FAUCET note clears a previously-registered faucet from the faucet
/// registry, the token registry, AND the faucet metadata map.
///
/// Flow:
/// 1. Create admin + bridge accounts
/// 2. Register a faucet via CONFIG_AGG_BRIDGE
/// 3. Verify all three maps hold the expected non-zero values
/// 4. Deregister via DEREGISTER_AGG_FAUCET
/// 5. Verify all three maps hold [0, 0, 0, 0]
#[tokio::test]
async fn test_deregister_agg_faucet_clears_both_registries() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_injector.id(),
        ger_remover.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let faucet_to_register =
        AccountId::dummy([42; 15], AccountIdVersion::Version1, AccountType::Public);
    let origin_token_address =
        EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let origin_network = 1u32;
    let metadata_hash = MetadataHash::from_token_info("USD Coin", "USDC", 6);

    // ---- Build registration + deregistration notes ----
    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: faucet_to_register,
            origin_token_address,
            scale: 0,
            origin_network,
            is_native: false,
            metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    let deregister_note = DeregisterAggFaucetNote::create(
        faucet_to_register,
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
    updated_bridge.apply_patch(register_executed.account_patch())?;

    let faucet_slot = AggLayerBridge::faucet_registry_map_slot_name();
    let token_slot = AggLayerBridge::token_registry_map_slot_name();
    let metadata_slot = AggLayerBridge::faucet_metadata_map_slot_name();
    let faucet_key = StorageMapKey::from_raw(AccountIdKey::new(faucet_to_register).as_word());
    let token_key = token_registry_key(&origin_token_address, origin_network);
    // Sub-key 0 (ADDR_LO) holds the first four felts of the origin token address.
    let metadata_addr_lo_key = faucet_metadata_key(faucet_to_register, 0);
    let expected_addr_lo: Word = origin_token_address.to_elements()[0..4]
        .try_into()
        .map(|a: [Felt; 4]| a.into())
        .expect("origin token address has at least 4 felts");

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
    // This both verifies metadata was written and validates the key layout used below.
    assert_eq!(
        updated_bridge.storage().get_map_item(metadata_slot, metadata_addr_lo_key)?,
        expected_addr_lo,
        "faucet_metadata sub-key 0 should hold the origin address after registration"
    );

    mock_chain.add_pending_executed_transaction(&register_executed)?;
    mock_chain.prove_next_block()?;

    // ---- TX1: consume DEREGISTER_AGG_FAUCET to clear ----
    let deregister_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[deregister_note.id()], &[])?
        .build()?;
    let deregister_executed = deregister_tx.execute().await?;

    updated_bridge.apply_patch(deregister_executed.account_patch())?;

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
    // All four metadata sub-keys (0/1 origin address+network, 2/3 metadata hash lo/hi) are cleared.
    for sub_key in 0..4u8 {
        assert_eq!(
            updated_bridge
                .storage()
                .get_map_item(metadata_slot, faucet_metadata_key(faucet_to_register, sub_key))?,
            [Felt::ZERO; 4].into(),
            "faucet_metadata sub-key {sub_key} should be cleared after deregistration"
        );
    }

    Ok(())
}

/// Tests that DEREGISTER_AGG_FAUCET clears a Miden-native (`is_native = true`) faucet just like a
/// wrapped one. `deregister_faucet` does not branch on `is_native` (it overwrites the whole
/// `[1, is_native, 0, 0]` registry word with zeros), so this guards against a regression that would
/// make deregistration `is_native`-dependent.
#[tokio::test]
async fn test_deregister_agg_faucet_clears_native_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_injector.id(),
        ger_remover.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let faucet_to_register =
        AccountId::dummy([77; 15], AccountIdVersion::Version1, AccountType::Public);
    let origin_token_address =
        EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let origin_network = 1u32;
    let metadata_hash = MetadataHash::from_token_info("USD Coin", "USDC", 6);

    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: faucet_to_register,
            origin_token_address,
            scale: 0,
            origin_network,
            is_native: true,
            metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    let deregister_note = DeregisterAggFaucetNote::create(
        faucet_to_register,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));
    builder.add_output_note(RawOutputNote::Full(deregister_note.clone()));

    let mut mock_chain = builder.build()?;

    let register_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?
        .execute()
        .await?;

    let mut updated_bridge = bridge_account.clone();
    updated_bridge.apply_patch(register_executed.account_patch())?;

    let faucet_slot = AggLayerBridge::faucet_registry_map_slot_name();
    let token_slot = AggLayerBridge::token_registry_map_slot_name();
    let faucet_key = StorageMapKey::from_raw(AccountIdKey::new(faucet_to_register).as_word());
    let token_key = token_registry_key(&origin_token_address, origin_network);

    // A native faucet registers with the is_native flag set: [1, 1, 0, 0].
    assert_eq!(
        updated_bridge.storage().get_map_item(faucet_slot, faucet_key)?,
        [Felt::ONE, Felt::ONE, Felt::ZERO, Felt::ZERO].into(),
        "faucet_registry should be [1, 1, 0, 0] after native registration"
    );

    mock_chain.add_pending_executed_transaction(&register_executed)?;
    mock_chain.prove_next_block()?;

    let deregister_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[deregister_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    updated_bridge.apply_patch(deregister_executed.account_patch())?;

    assert_eq!(
        updated_bridge.storage().get_map_item(faucet_slot, faucet_key)?,
        [Felt::ZERO; 4].into(),
        "faucet_registry should be cleared after deregistering a native faucet"
    );
    assert_eq!(
        updated_bridge.storage().get_map_item(token_slot, token_key)?,
        [Felt::ZERO; 4].into(),
        "token_registry should be cleared after deregistering a native faucet"
    );
    assert_eq!(
        updated_bridge.storage().get_map_item(
            AggLayerBridge::faucet_metadata_map_slot_name(),
            faucet_metadata_key(faucet_to_register, 0)
        )?,
        [Felt::ZERO; 4].into(),
        "faucet_metadata should be cleared after deregistering a native faucet"
    );

    Ok(())
}

/// Tests that DEREGISTER_AGG_FAUCET rejects invalid deregistrations:
/// - an unregistered faucet panics with `ERR_FAUCET_NOT_REGISTERED`;
/// - a non-admin sender panics with `ERR_SENDER_NOT_BRIDGE_ADMIN`, even when the faucet is
///   registered (so the panic comes from the auth check, not the registration check).
#[rstest::rstest]
#[case::unregistered_faucet(false, false, ERR_FAUCET_NOT_REGISTERED)]
#[case::non_admin_sender(true, true, ERR_SENDER_NOT_BRIDGE_ADMIN)]
#[tokio::test]
async fn test_deregister_agg_faucet_rejects_invalid(
    #[case] register_first: bool,
    #[case] sender_is_attacker: bool,
    #[case] expected_err: MasmError,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let attacker = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_injector.id(),
        ger_remover.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let faucet_id = AccountId::dummy([7; 15], AccountIdVersion::Version1, AccountType::Public);

    // Register the faucet first only for the non-admin case, so its panic comes from the auth check
    // rather than the assert_faucet_registered check.
    let config_note = if register_first {
        Some(ConfigAggBridgeNote::create(
            ConversionMetadata {
                faucet_account_id: faucet_id,
                origin_token_address: EthAddress::from_hex(
                    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                )
                .unwrap(),
                scale: 0,
                origin_network: 1,
                is_native: false,
                metadata_hash: MetadataHash::from_token_info("USD Coin", "USDC", 6),
            },
            bridge_admin.id(),
            bridge_account.id(),
            builder.rng_mut(),
        )?)
    } else {
        None
    };

    let sender = if sender_is_attacker {
        attacker.id()
    } else {
        bridge_admin.id()
    };
    let deregister_note =
        DeregisterAggFaucetNote::create(faucet_id, sender, bridge_account.id(), builder.rng_mut())?;

    if let Some(note) = &config_note {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }
    builder.add_output_note(RawOutputNote::Full(deregister_note.clone()));
    let mut mock_chain = builder.build()?;

    if let Some(note) = config_note {
        let register_executed = mock_chain
            .build_tx_context(bridge_account.id(), &[note.id()], &[])?
            .build()?
            .execute()
            .await?;
        mock_chain.add_pending_executed_transaction(&register_executed)?;
        mock_chain.prove_next_block()?;
    }

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[deregister_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, expected_err);

    Ok(())
}

/// Tests that deregistration revokes the faucet end-to-end: after a faucet is deregistered, the
/// bridge no longer treats it as registered, so a second DEREGISTER_AGG_FAUCET for the same faucet
/// fails the `assert_faucet_registered` check with `ERR_FAUCET_NOT_REGISTERED`. That is the exact
/// check in-flight B2AGG / CLAIM notes rely on, so its failure demonstrates the faucet is revoked.
#[tokio::test]
async fn test_deregister_agg_faucet_revokes_registration() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_injector.id(),
        ger_remover.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let faucet_id = AccountId::dummy([55; 15], AccountIdVersion::Version1, AccountType::Public);
    let origin_token_address =
        EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let metadata_hash = MetadataHash::from_token_info("USD Coin", "USDC", 6);

    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: faucet_id,
            origin_token_address,
            scale: 0,
            origin_network: 1,
            is_native: false,
            metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    // Two deregister notes for the same faucet: the first revokes it, the second must then fail.
    let deregister_note = DeregisterAggFaucetNote::create(
        faucet_id,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    let second_deregister_note = DeregisterAggFaucetNote::create(
        faucet_id,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));
    builder.add_output_note(RawOutputNote::Full(deregister_note.clone()));
    builder.add_output_note(RawOutputNote::Full(second_deregister_note.clone()));
    let mut mock_chain = builder.build()?;

    // Register, then deregister.
    let register_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&register_executed)?;
    mock_chain.prove_next_block()?;

    let deregister_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[deregister_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&deregister_executed)?;
    mock_chain.prove_next_block()?;

    // The faucet is now unregistered: deregistering it again fails the registration check.
    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[second_deregister_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FAUCET_NOT_REGISTERED);

    Ok(())
}
