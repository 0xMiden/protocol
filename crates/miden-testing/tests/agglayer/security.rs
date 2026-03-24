extern crate alloc;

use alloc::vec;

use miden_agglayer::errors::{
    ERR_REMAINDER_TOO_LARGE, ERR_SMT_ROOT_VERIFICATION_FAILED, ERR_UNDERFLOW,
};
use miden_agglayer::{
    AggLayerBridge, ClaimNoteStorage, ConfigAggBridgeNote, EthAddress, EthAmount, UpdateGerNote,
    create_claim_note, create_existing_agglayer_faucet, create_existing_bridge_account,
};
use miden_protocol::Felt;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::transaction::RawOutputNote;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use primitive_types::U256;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::test_utils::{ClaimDataSource, assert_execution_fails_with};

// ================================================================================================
// TEST 1: INVALID MERKLE PROOF REJECTION
// ================================================================================================

/// Tests that a claim with a corrupted Merkle proof is rejected.
///
/// This test modifies one node in the SMT proof for the local exit root, which should
/// cause the Merkle proof verification to fail with ERR_SMT_ROOT_VERIFICATION_FAILED.
#[tokio::test]
async fn test_claim_with_corrupted_merkle_proof_rejected() -> anyhow::Result<()> {
    let data_source = ClaimDataSource::Simulated;
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account =
        create_existing_bridge_account(bridge_seed, bridge_admin.id(), ger_manager.id());
    builder.add_account(bridge_account.clone())?;

    // GET CLAIM DATA FROM JSON
    let (mut proof_data, leaf_data, ger, _cgi_chain_hash) = data_source.get_data();

    // CORRUPT THE MERKLE PROOF: flip one byte in the second SMT proof node
    let mut corrupted_bytes = *proof_data.smt_proof_local_exit_root[1].as_bytes();
    corrupted_bytes[0] ^= 0x01; // flip one bit
    proof_data.smt_proof_local_exit_root[1] = miden_agglayer::SmtNode::new(corrupted_bytes);

    // CREATE AGGLAYER FAUCET ACCOUNT
    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT);
    let agglayer_faucet_seed = builder.rng_mut().draw_word();

    let origin_token_address = leaf_data.origin_token_address;
    let origin_network = leaf_data.origin_network;
    let scale = 10u8;

    let agglayer_faucet = create_existing_agglayer_faucet(
        agglayer_faucet_seed,
        token_symbol,
        decimals,
        max_supply,
        Felt::ZERO,
        bridge_account.id(),
        &origin_token_address,
        origin_network,
        scale,
        leaf_data.metadata_hash,
    );
    builder.add_account(agglayer_faucet.clone())?;

    // Calculate the scaled-down Miden amount
    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");

    // CREATE CLAIM NOTE WITH CORRUPTED PROOF
    let claim_inputs = ClaimNoteStorage {
        proof_data,
        leaf_data,
        miden_claim_amount,
    };

    let claim_note = create_claim_note(
        claim_inputs,
        bridge_account.id(),
        bridge_admin.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(claim_note.clone()));

    // CREATE CONFIG_AGG_BRIDGE NOTE
    let config_note = ConfigAggBridgeNote::create(
        agglayer_faucet.id(),
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // CREATE UPDATE_GER NOTE
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    // BUILD MOCK CHAIN
    let mut mock_chain = builder.build()?;

    // TX0: CONFIG_AGG_BRIDGE
    let config_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let config_executed = config_tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: UPDATE_GER
    let update_ger_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_ger_executed = update_ger_tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: CLAIM WITH CORRUPTED PROOF (SHOULD FAIL)
    let faucet_foreign_inputs = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let claim_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[claim_note])?
        .foreign_accounts(vec![faucet_foreign_inputs])
        .build()?;

    let result = claim_tx_context.execute().await;

    assert_transaction_executor_error!(result, ERR_SMT_ROOT_VERIFICATION_FAILED);

    Ok(())
}

// ================================================================================================
// TEST 2: INFLATED MIDEN_CLAIM_AMOUNT REJECTION
// ================================================================================================

/// Tests that a claim with an inflated miden_claim_amount (y+1) is rejected.
///
/// This test creates a CLAIM note where the miden_claim_amount is set to a value
/// higher than what the leaf data amount would produce after scaling. The bridge's
/// verify_claim_amount procedure should detect the mismatch and reject the claim
/// with ERR_UNDERFLOW (because y_scaled = (y+1)*10^scale > x).
#[tokio::test]
async fn test_claim_with_inflated_amount_rejected() -> anyhow::Result<()> {
    let data_source = ClaimDataSource::Simulated;
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account =
        create_existing_bridge_account(bridge_seed, bridge_admin.id(), ger_manager.id());
    builder.add_account(bridge_account.clone())?;

    // GET CLAIM DATA FROM JSON
    let (proof_data, leaf_data, ger, _cgi_chain_hash) = data_source.get_data();

    // CREATE AGGLAYER FAUCET ACCOUNT
    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT);
    let agglayer_faucet_seed = builder.rng_mut().draw_word();

    let origin_token_address = leaf_data.origin_token_address;
    let origin_network = leaf_data.origin_network;
    let scale = 10u8;

    let agglayer_faucet = create_existing_agglayer_faucet(
        agglayer_faucet_seed,
        token_symbol,
        decimals,
        max_supply,
        Felt::ZERO,
        bridge_account.id(),
        &origin_token_address,
        origin_network,
        scale,
        leaf_data.metadata_hash,
    );
    builder.add_account(agglayer_faucet.clone())?;

    // Calculate the correct scaled-down Miden amount, then INFLATE it by 1
    let correct_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");
    let inflated_amount = Felt::new(correct_amount.as_canonical_u64() + 1);

    // CREATE CLAIM NOTE WITH INFLATED AMOUNT
    let claim_inputs = ClaimNoteStorage {
        proof_data,
        leaf_data,
        miden_claim_amount: inflated_amount,
    };

    let claim_note = create_claim_note(
        claim_inputs,
        bridge_account.id(),
        bridge_admin.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(claim_note.clone()));

    // CREATE CONFIG_AGG_BRIDGE NOTE
    let config_note = ConfigAggBridgeNote::create(
        agglayer_faucet.id(),
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // CREATE UPDATE_GER NOTE
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    // BUILD MOCK CHAIN
    let mut mock_chain = builder.build()?;

    // TX0: CONFIG_AGG_BRIDGE
    let config_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let config_executed = config_tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: UPDATE_GER
    let update_ger_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_ger_executed = update_ger_tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: CLAIM WITH INFLATED AMOUNT (SHOULD FAIL)
    let faucet_foreign_inputs = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let claim_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[claim_note])?
        .foreign_accounts(vec![faucet_foreign_inputs])
        .build()?;

    let result = claim_tx_context.execute().await;

    // y+1 causes underflow in the verification: y_scaled > x
    assert_transaction_executor_error!(result, ERR_UNDERFLOW);

    Ok(())
}

/// Tests that a claim with a deflated miden_claim_amount (y-1) is rejected.
///
/// When y is too small, the remainder z = x - y*10^scale exceeds 10^scale,
/// which should trigger ERR_REMAINDER_TOO_LARGE.
#[tokio::test]
async fn test_claim_with_deflated_amount_rejected() -> anyhow::Result<()> {
    let data_source = ClaimDataSource::Simulated;
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account =
        create_existing_bridge_account(bridge_seed, bridge_admin.id(), ger_manager.id());
    builder.add_account(bridge_account.clone())?;

    // GET CLAIM DATA FROM JSON
    let (proof_data, leaf_data, ger, _cgi_chain_hash) = data_source.get_data();

    // CREATE AGGLAYER FAUCET ACCOUNT
    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT);
    let agglayer_faucet_seed = builder.rng_mut().draw_word();

    let origin_token_address = leaf_data.origin_token_address;
    let origin_network = leaf_data.origin_network;
    let scale = 10u8;

    let agglayer_faucet = create_existing_agglayer_faucet(
        agglayer_faucet_seed,
        token_symbol,
        decimals,
        max_supply,
        Felt::ZERO,
        bridge_account.id(),
        &origin_token_address,
        origin_network,
        scale,
        leaf_data.metadata_hash,
    );
    builder.add_account(agglayer_faucet.clone())?;

    // Calculate the correct scaled-down Miden amount, then DEFLATE it by 1
    let correct_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");
    let deflated_amount = Felt::new(correct_amount.as_canonical_u64() - 1);

    // CREATE CLAIM NOTE WITH DEFLATED AMOUNT
    let claim_inputs = ClaimNoteStorage {
        proof_data,
        leaf_data,
        miden_claim_amount: deflated_amount,
    };

    let claim_note = create_claim_note(
        claim_inputs,
        bridge_account.id(),
        bridge_admin.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(claim_note.clone()));

    // CREATE CONFIG_AGG_BRIDGE NOTE
    let config_note = ConfigAggBridgeNote::create(
        agglayer_faucet.id(),
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // CREATE UPDATE_GER NOTE
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    // BUILD MOCK CHAIN
    let mut mock_chain = builder.build()?;

    // TX0: CONFIG_AGG_BRIDGE
    let config_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let config_executed = config_tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: UPDATE_GER
    let update_ger_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_ger_executed = update_ger_tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: CLAIM WITH DEFLATED AMOUNT (SHOULD FAIL)
    let faucet_foreign_inputs = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let claim_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[claim_note])?
        .foreign_accounts(vec![faucet_foreign_inputs])
        .build()?;

    let result = claim_tx_context.execute().await;

    // y-1 causes remainder to exceed 10^scale
    assert_transaction_executor_error!(result, ERR_REMAINDER_TOO_LARGE);

    Ok(())
}

// ================================================================================================
// TEST 3: ASSET CONVERSION FUZZING (y+1 and y-1 for random amounts)
// ================================================================================================

/// Build MASM script for verify_u256_to_native_amount_conversion
fn build_scale_down_script(x: EthAmount, scale_exp: u32, y: u64) -> String {
    let x_felts = x.to_elements();
    format!(
        r#"
        use miden::core::sys
        use agglayer::common::asset_conversion
        
        begin
            push.{}.{}.{}.{}.{}.{}.{}.{}.{}.{}
            exec.asset_conversion::verify_u256_to_native_amount_conversion
            exec.sys::truncate_stack
        end
        "#,
        y,
        scale_exp,
        x_felts[7].as_canonical_u64(),
        x_felts[6].as_canonical_u64(),
        x_felts[5].as_canonical_u64(),
        x_felts[4].as_canonical_u64(),
        x_felts[3].as_canonical_u64(),
        x_felts[2].as_canonical_u64(),
        x_felts[1].as_canonical_u64(),
        x_felts[0].as_canonical_u64(),
    )
}

/// Fuzz test that validates verify_u256_to_native_amount_conversion rejects y+1 and y-1
/// for random realistic amounts across all scale exponents (0..=18).
///
/// For each random (x, scale) pair:
/// - Computes the correct y = floor(x / 10^scale)
/// - Asserts that y+1 fails with ERR_UNDERFLOW
/// - Asserts that y-1 fails with ERR_REMAINDER_TOO_LARGE (when y > 0)
#[tokio::test]
async fn test_scale_down_wrong_y_fuzzing() -> anyhow::Result<()> {
    const CASES_PER_SCALE: usize = 3;
    const MAX_SCALE: u32 = 18;

    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);

    let min_x = U256::from(10_000_000_000_000u64); // 1e13
    let desired_max_x = U256::from_dec_str("1000000000000000000000000").unwrap(); // 1e24
    let max_y = U256::from(FungibleAsset::MAX_AMOUNT);

    for scale in 0..=MAX_SCALE {
        let scale_factor = U256::from(10u64).pow(U256::from(scale));
        let max_x = desired_max_x.min(max_y * scale_factor);

        if max_x <= min_x {
            continue;
        }

        let span: u128 = (max_x - min_x).try_into().expect("span fits in u128");

        for _ in 0..CASES_PER_SCALE {
            let offset: u128 = rng.random_range(0..span);
            let x = EthAmount::from_u256(min_x + U256::from(offset));
            let y = x.scale_to_token_amount(scale).unwrap().as_canonical_u64();

            // y+1 should always fail with underflow
            let script_y_plus_1 = build_scale_down_script(x, scale, y + 1);
            assert_execution_fails_with(&script_y_plus_1, "x < y*10^s (underflow detected)").await;

            // y-1 should fail with remainder too large (when y > 0)
            if y > 0 {
                let script_y_minus_1 = build_scale_down_script(x, scale, y - 1);
                assert_execution_fails_with(&script_y_minus_1, "remainder z must be < 10^s").await;
            }
        }
    }

    Ok(())
}

// ================================================================================================
// TEST 4: TOKEN REGISTRY OVERWRITE
// ================================================================================================

/// Tests that registering a second faucet for the same token address overwrites the first.
///
/// This test verifies the behavior documented in audit finding F-06:
/// 1. Register faucet_A for token_address_X
/// 2. Register faucet_B for the same token_address_X
/// 3. Verify that the token registry now maps token_address_X → faucet_B (overwritten)
/// 4. Verify that faucet_A is still in the faucet registry (not removed)
///
/// This demonstrates that the bridge admin can redirect claims to a different faucet
/// by re-registering the same token address.
#[tokio::test]
async fn test_token_registry_overwrite() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT
    let mut bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Create two different faucet IDs
    let faucet_a = AccountId::dummy(
        [42; 15],
        AccountIdVersion::Version0,
        AccountType::FungibleFaucet,
        AccountStorageMode::Network,
    );
    let faucet_b = AccountId::dummy(
        [43; 15],
        AccountIdVersion::Version0,
        AccountType::FungibleFaucet,
        AccountStorageMode::Network,
    );

    // Use the same origin token address for both registrations
    let origin_token_address =
        EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

    // CREATE FIRST CONFIG NOTE (registers faucet_A for token_address)
    let config_note_a = ConfigAggBridgeNote::create(
        faucet_a,
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note_a.clone()));

    // CREATE SECOND CONFIG NOTE (registers faucet_B for the SAME token_address)
    let config_note_b = ConfigAggBridgeNote::create(
        faucet_b,
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note_b.clone()));

    let mut mock_chain = builder.build()?;

    // TX0: Register faucet_A
    let tx0_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note_a.id()], &[])?
        .build()?;
    let tx0_executed = tx0_context.execute().await?;
    bridge_account.apply_delta(tx0_executed.account_delta())?;
    mock_chain.add_pending_executed_transaction(&tx0_executed)?;
    mock_chain.prove_next_block()?;

    // VERIFY: faucet_A is registered in the faucet registry
    let registry_slot = AggLayerBridge::faucet_registry_map_slot_name();
    let key_a = AccountIdKey::new(faucet_a).as_word();
    let value_a = bridge_account.storage().get_map_item(registry_slot, key_a)?;
    assert_eq!(
        value_a,
        [Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO].into(),
        "Faucet A should be registered after TX0"
    );

    // TX1: Register faucet_B for the SAME token address (overwrites token registry)
    let tx1_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note_b.id()], &[])?
        .build()?;
    let tx1_executed = tx1_context.execute().await?;
    bridge_account.apply_delta(tx1_executed.account_delta())?;
    mock_chain.add_pending_executed_transaction(&tx1_executed)?;
    mock_chain.prove_next_block()?;

    // VERIFY: faucet_A is STILL in the faucet registry (not removed)
    let value_a_after = bridge_account.storage().get_map_item(registry_slot, key_a)?;
    assert_eq!(
        value_a_after,
        [Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO].into(),
        "Faucet A should still be registered (faucet registry is not cleared on overwrite)"
    );

    // VERIFY: faucet_B is also in the faucet registry
    let key_b = AccountIdKey::new(faucet_b).as_word();
    let value_b = bridge_account.storage().get_map_item(registry_slot, key_b)?;
    assert_eq!(
        value_b,
        [Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO].into(),
        "Faucet B should be registered after TX1"
    );

    // VERIFY: token registry now maps to faucet_B (overwritten)
    // The token registry maps hash(token_address) -> [0, 0, faucet_id_suffix, faucet_id_prefix]
    let token_registry_slot = AggLayerBridge::token_registry_map_slot_name();

    // Compute the token address hash the same way the MASM code does
    // (Poseidon2::hash_elements of the 5 address felts)
    use miden_protocol::crypto::hash::poseidon2::Poseidon2;
    let addr_elements = origin_token_address.to_elements();
    let token_addr_hash = Poseidon2::hash_elements(&addr_elements);

    let token_value = bridge_account
        .storage()
        .get_map_item(token_registry_slot, token_addr_hash)?;

    // The value should contain faucet_B's ID, not faucet_A's
    // Token registry value format: [0, 0, faucet_id_suffix, faucet_id_prefix]
    let faucet_b_key = AccountIdKey::new(faucet_b).as_word();
    assert_eq!(
        token_value, faucet_b_key,
        "Token registry should now map to faucet_B (overwritten), not faucet_A. \
         This demonstrates that re-registering the same token address overwrites the mapping."
    );

    // Also verify it's NOT faucet_A anymore
    let faucet_a_key = AccountIdKey::new(faucet_a).as_word();
    assert_ne!(
        token_value, faucet_a_key,
        "Token registry should no longer map to faucet_A"
    );

    Ok(())
}
