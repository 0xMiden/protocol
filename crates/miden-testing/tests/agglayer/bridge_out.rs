extern crate alloc;

use miden_agglayer::errors::{ERR_B2AGG_TARGET_ACCOUNT_MISMATCH, ERR_FAUCET_NOT_REGISTERED};
use miden_agglayer::{
    AggLayerBridge,
    B2AggNote,
    ConfigAggBridgeNote,
    EthAddressFormat,
    ExitRoot,
    MetadataHash,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_crypto::rand::FeltRng;
use miden_protocol::Felt;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::{NoteAssets, NoteScript, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::faucets::TokenMetadata;
use miden_standards::account::mint_policies::OwnerControlledInitConfig;
use miden_standards::note::StandardNote;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::utils::hex_to_bytes;

use super::test_utils::SOLIDITY_MMR_FRONTIER_VECTORS;

/// Tests that 32 sequential B2AGG note consumptions match all 32 Solidity MMR roots.
///
/// This test exercises the complete bridge-out lifecycle:
/// 1. Creates a bridge account (empty faucet registry) and an agglayer faucet with conversion
///    metadata (origin token address, network, scale)
/// 2. Registers the faucet in the bridge's faucet registry via a CONFIG_AGG_BRIDGE note
/// 3. Creates a B2AGG note with assets from the agglayer faucet
/// 4. Consumes the B2AGG note against the bridge account — the bridge's `bridge_out` procedure:
///    - Validates the faucet is registered via `convert_asset`
///    - Calls the faucet's `asset_to_origin_asset` via FPI to get the scaled amount, origin token
///      address, and origin network
///    - Writes the leaf data and computes the Keccak hash for the MMR
///    - Creates a BURN note addressed to the faucet
/// 5. Verifies the BURN note was created with the correct asset, tag, and script
/// 6. Consumes the BURN note with the faucet to burn the tokens
#[tokio::test]
async fn bridge_out_consecutive() -> anyhow::Result<()> {
    let vectors = &*SOLIDITY_MMR_FRONTIER_VECTORS;
    let note_count = 32usize;
    assert_eq!(vectors.amounts.len(), note_count, "amount vectors should contain 32 entries");
    assert_eq!(vectors.roots.len(), note_count, "root vectors should contain 32 entries");
    assert_eq!(
        vectors.destination_networks.len(),
        note_count,
        "destination network vectors should contain 32 entries"
    );
    assert_eq!(
        vectors.destination_addresses.len(),
        note_count,
        "destination address vectors should contain 32 entries"
    );

    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT (sends CONFIG_AGG_BRIDGE notes)
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT (not used in this test, but distinct from admin)
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let mut bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let expected_amounts = vectors
        .amounts
        .iter()
        .map(|amount| amount.parse::<u64>().expect("valid amount decimal string"))
        .collect::<Vec<_>>();
    let total_burned: u64 = expected_amounts.iter().sum();

    // CREATE AGGLAYER FAUCET ACCOUNT (with conversion metadata for FPI)
    // --------------------------------------------------------------------------------------------
    let origin_token_address = EthAddressFormat::from_hex(&vectors.origin_token_address)
        .expect("valid shared origin token address");
    let origin_network = 64u32;
    let scale = 0u8;
    let metadata_hash = MetadataHash::from_token_info(
        &vectors.token_name,
        &vectors.token_symbol,
        vectors.token_decimals,
    );
    let faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        &vectors.token_symbol,
        vectors.token_decimals,
        Felt::new(FungibleAsset::MAX_AMOUNT),
        Felt::new(total_burned),
        bridge_account.id(),
        &origin_token_address,
        origin_network,
        scale,
        metadata_hash,
    );
    builder.add_account(faucet.clone())?;

    // CONFIG_AGG_BRIDGE note to register the faucet in the bridge (sent by bridge admin)
    let config_note = ConfigAggBridgeNote::create(
        faucet.id(),
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // CREATE ALL B2AGG NOTES UPFRONT (before building mock chain)
    // --------------------------------------------------------------------------------------------
    let mut notes = Vec::with_capacity(note_count);
    for (i, &amount) in expected_amounts.iter().enumerate().take(note_count) {
        let destination_network = vectors.destination_networks[i];
        let eth_address = EthAddressFormat::from_hex(&vectors.destination_addresses[i])
            .expect("valid destination address");

        let bridge_asset: Asset = FungibleAsset::new(faucet.id(), amount).unwrap().into();
        let note = B2AggNote::create(
            destination_network,
            eth_address,
            NoteAssets::new(vec![bridge_asset])?,
            bridge_account.id(),
            faucet.id(),
            builder.rng_mut(),
        )?;
        builder.add_output_note(RawOutputNote::Full(note.clone()));
        notes.push(note);
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // STEP 1: REGISTER FAUCET VIA CONFIG_AGG_BRIDGE NOTE
    // --------------------------------------------------------------------------------------------
    let config_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    bridge_account.apply_delta(config_executed.account_delta())?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // STEP 2: CONSUME 32 B2AGG NOTES AND VERIFY FRONTIER EVOLUTION
    // --------------------------------------------------------------------------------------------
    let burn_note_script: NoteScript = StandardNote::BURN.script();
    let mut burn_note_ids = Vec::with_capacity(note_count);

    for (i, note) in notes.iter().enumerate() {
        let foreign_account_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

        let executed_tx = mock_chain
            .build_tx_context(bridge_account.clone(), &[note.id()], &[])?
            .add_note_script(burn_note_script.clone())
            .foreign_accounts(vec![foreign_account_inputs])
            .build()?
            .execute()
            .await?;

        assert_eq!(
            executed_tx.output_notes().num_notes(),
            1,
            "Expected one BURN note after consume #{}",
            i + 1
        );
        let burn_note = match executed_tx.output_notes().get_note(0) {
            RawOutputNote::Full(note) => note,
            _ => panic!("Expected OutputNote::Full variant for BURN note"),
        };
        burn_note_ids.push(burn_note.id());

        let expected_asset = Asset::from(FungibleAsset::new(faucet.id(), expected_amounts[i])?);
        assert!(
            burn_note.assets().iter().any(|asset| asset == &expected_asset),
            "BURN note after consume #{} should contain the bridged asset",
            i + 1
        );
        assert_eq!(
            burn_note.metadata().note_type(),
            NoteType::Public,
            "BURN note should be public"
        );
        let attachment = burn_note.metadata().attachment();
        let network_target = miden_standards::note::NetworkAccountTarget::try_from(attachment)
            .expect("BURN note attachment should be a valid NetworkAccountTarget");
        assert_eq!(
            network_target.target_id(),
            faucet.id(),
            "BURN note attachment should target the faucet"
        );
        assert_eq!(
            burn_note.recipient().script().root(),
            StandardNote::BURN.script_root(),
            "BURN note should use the BURN script"
        );

        bridge_account.apply_delta(executed_tx.account_delta())?;
        assert_eq!(
            AggLayerBridge::read_let_num_leaves(&bridge_account),
            (i + 1) as u64,
            "LET leaf count should match consumed notes"
        );

        let expected_ler =
            ExitRoot::new(hex_to_bytes(&vectors.roots[i]).expect("valid root hex")).to_elements();
        assert_eq!(
            AggLayerBridge::read_local_exit_root(&bridge_account)?,
            expected_ler,
            "Local Exit Root after {} leaves should match the Solidity-generated root",
            i + 1
        );

        mock_chain.add_pending_executed_transaction(&executed_tx)?;
        mock_chain.prove_next_block()?;
    }

    // STEP 3: CONSUME ALL BURN NOTES WITH THE AGGLAYER FAUCET
    // --------------------------------------------------------------------------------------------
    let initial_token_supply = TokenMetadata::try_from(faucet.storage())?.token_supply();
    assert_eq!(
        initial_token_supply,
        Felt::new(total_burned),
        "Initial issuance should match all pending burns"
    );

    let mut faucet = faucet;
    for burn_note_id in burn_note_ids {
        let burn_executed_tx = mock_chain
            .build_tx_context(faucet.id(), &[burn_note_id], &[])?
            .build()?
            .execute()
            .await?;
        assert_eq!(
            burn_executed_tx.output_notes().num_notes(),
            0,
            "Burn transaction should not create output notes"
        );
        faucet.apply_delta(burn_executed_tx.account_delta())?;
        mock_chain.add_pending_executed_transaction(&burn_executed_tx)?;
        mock_chain.prove_next_block()?;
    }

    let final_token_supply = TokenMetadata::try_from(faucet.storage())?.token_supply();
    assert_eq!(
        final_token_supply,
        Felt::new(initial_token_supply.as_canonical_u64() - total_burned),
        "Token supply should decrease by the sum of 32 bridged amounts"
    );

    Ok(())
}

/// Tests that bridging out fails when the faucet is not registered in the bridge's registry.
///
/// This test verifies the faucet allowlist check in bridge_out's `convert_asset` procedure:
/// 1. Creates a bridge account with an empty faucet registry (no faucets registered)
/// 2. Creates a B2AGG note with an asset from an agglayer faucet
/// 3. Attempts to consume the B2AGG note against the bridge — this should fail because
///    `convert_asset` checks the faucet registry and panics with ERR_FAUCET_NOT_REGISTERED when the
///    faucet is not found
#[tokio::test]
async fn test_bridge_out_fails_with_unregistered_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT (not used in this test, but distinct from admin)
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT (empty faucet registry — no faucets registered)
    // --------------------------------------------------------------------------------------------
    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // CREATE AGGLAYER FAUCET ACCOUNT (NOT registered in the bridge)
    // --------------------------------------------------------------------------------------------
    let vectors = &*SOLIDITY_MMR_FRONTIER_VECTORS;
    let origin_token_address = EthAddressFormat::new([0u8; 20]);
    let metadata_hash = MetadataHash::from_token_info(
        &vectors.token_name,
        &vectors.token_symbol,
        vectors.token_decimals,
    );
    let faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        &vectors.token_symbol,
        vectors.token_decimals,
        Felt::new(FungibleAsset::MAX_AMOUNT),
        Felt::new(100),
        bridge_account.id(),
        &origin_token_address,
        0, // origin_network
        0, // scale
        metadata_hash,
    );
    builder.add_account(faucet.clone())?;

    // CREATE B2AGG NOTE WITH ASSETS FROM THE UNREGISTERED FAUCET
    // --------------------------------------------------------------------------------------------
    let amount = Felt::new(100);
    let bridge_asset: Asset =
        FungibleAsset::new(faucet.id(), amount.as_canonical_u64()).unwrap().into();

    let destination_address = "0x1234567890abcdef1122334455667788990011aa";
    let eth_address =
        EthAddressFormat::from_hex(destination_address).expect("valid Ethereum address");

    let b2agg_note = B2AggNote::create(
        1u32, // destination_network
        eth_address,
        NoteAssets::new(vec![bridge_asset])?,
        bridge_account.id(),
        faucet.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(RawOutputNote::Full(b2agg_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // ATTEMPT TO BRIDGE OUT WITHOUT REGISTERING THE FAUCET (SHOULD FAIL)
    // --------------------------------------------------------------------------------------------
    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[b2agg_note.id()], &[])?
        .foreign_accounts(vec![foreign_account_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FAUCET_NOT_REGISTERED);

    Ok(())
}

/// Tests the B2AGG (Bridge to AggLayer) note script reclaim functionality.
///
/// This test covers the "reclaim" branch where the note creator consumes their own B2AGG note.
/// In this scenario, the assets are simply added back to the account without creating a BURN note.
///
/// Test flow:
/// 1. Creates a network faucet to provide assets
/// 2. Creates a user account that will create and consume the B2AGG note
/// 3. Creates a B2AGG note with the user account as sender
/// 4. The same user account consumes the B2AGG note (triggering reclaim branch)
/// 5. Verifies that assets are added back to the account and no BURN note is created
#[tokio::test]
async fn b2agg_note_reclaim_scenario() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Create a network faucet owner account
    let faucet_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    // Create a network faucet to provide assets for the B2AGG note
    let faucet = builder.add_existing_network_faucet(
        "AGG",
        1000,
        faucet_owner_account_id,
        Some(100),
        OwnerControlledInitConfig::OwnerOnly,
    )?;

    // Create a bridge admin account
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Create a GER manager account (not used in this test, but distinct from admin)
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Create a bridge account (includes a `bridge` component)
    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Create a user account that will create and consume the B2AGG note
    let mut user_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE B2AGG NOTE WITH USER ACCOUNT AS SENDER
    // --------------------------------------------------------------------------------------------
    let amount = Felt::new(50);
    let bridge_asset: Asset =
        FungibleAsset::new(faucet.id(), amount.as_canonical_u64()).unwrap().into();

    let destination_network = 1u32;
    let destination_address = "0x1234567890abcdef1122334455667788990011aa";
    let eth_address =
        EthAddressFormat::from_hex(destination_address).expect("valid Ethereum address");

    let assets = NoteAssets::new(vec![bridge_asset])?;

    // Create the B2AGG note with the USER ACCOUNT as the sender.
    // This is the key difference — the note sender will be the same as the consuming account.
    let b2agg_note = B2AggNote::create(
        destination_network,
        eth_address,
        assets,
        bridge_account.id(),
        user_account.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(RawOutputNote::Full(b2agg_note.clone()));
    let mut mock_chain = builder.build()?;

    // Store the initial asset balance of the user account
    let initial_balance = user_account.vault().get_balance(faucet.id()).unwrap_or(0u64);

    // EXECUTE B2AGG NOTE WITH THE SAME USER ACCOUNT (RECLAIM SCENARIO)
    // --------------------------------------------------------------------------------------------
    let tx_context = mock_chain
        .build_tx_context(user_account.id(), &[b2agg_note.id()], &[])?
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    // VERIFY NO BURN NOTE WAS CREATED (RECLAIM BRANCH)
    // --------------------------------------------------------------------------------------------
    assert_eq!(
        executed_transaction.output_notes().num_notes(),
        0,
        "Reclaim scenario should not create any output notes"
    );

    // Apply the delta to the user account
    user_account.apply_delta(executed_transaction.account_delta())?;

    // VERIFY ASSETS WERE ADDED BACK TO THE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let final_balance = user_account.vault().get_balance(faucet.id()).unwrap_or(0u64);
    assert_eq!(
        final_balance,
        initial_balance + amount.as_canonical_u64(),
        "User account should have received the assets back from the B2AGG note"
    );

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    Ok(())
}

/// Tests that a non-target account cannot consume a B2AGG note (non-reclaim branch).
///
/// This test covers the security check in the B2AGG note script that ensures only the
/// designated target account (specified in the note attachment) can consume the note
/// when not in reclaim mode.
///
/// Test flow:
/// 1. Creates a network faucet to provide assets
/// 2. Creates a bridge account as the designated target for the B2AGG note
/// 3. Creates a user account as the sender (creator) of the B2AGG note
/// 4. Creates a "malicious" account with a bridge interface
/// 5. Attempts to consume the B2AGG note with the malicious account
/// 6. Verifies that the transaction fails with ERR_B2AGG_TARGET_ACCOUNT_MISMATCH
#[tokio::test]
async fn b2agg_note_non_target_account_cannot_consume() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Create a network faucet owner account
    let faucet_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    // Create a network faucet to provide assets for the B2AGG note
    let faucet = builder.add_existing_network_faucet(
        "AGG",
        1000,
        faucet_owner_account_id,
        Some(100),
        OwnerControlledInitConfig::OwnerOnly,
    )?;

    // Create a bridge admin account
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Create a GER manager account (not used in this test, but distinct from admin)
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Create a bridge account as the designated TARGET for the B2AGG note
    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Create a user account as the SENDER of the B2AGG note
    let sender_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Create a "malicious" account with a bridge interface
    let malicious_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(malicious_account.clone())?;

    // CREATE B2AGG NOTE
    // --------------------------------------------------------------------------------------------
    let amount = Felt::new(50);
    let bridge_asset: Asset =
        FungibleAsset::new(faucet.id(), amount.as_canonical_u64()).unwrap().into();

    let destination_network = 1u32;
    let destination_address = "0x1234567890abcdef1122334455667788990011aa";
    let eth_address =
        EthAddressFormat::from_hex(destination_address).expect("valid Ethereum address");

    let assets = NoteAssets::new(vec![bridge_asset])?;

    // Create the B2AGG note targeting the real bridge account
    let b2agg_note = B2AggNote::create(
        destination_network,
        eth_address,
        assets,
        bridge_account.id(),
        sender_account.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(RawOutputNote::Full(b2agg_note.clone()));
    let mock_chain = builder.build()?;

    // ATTEMPT TO CONSUME B2AGG NOTE WITH MALICIOUS ACCOUNT (SHOULD FAIL)
    // --------------------------------------------------------------------------------------------
    let result = mock_chain
        .build_tx_context(malicious_account.id(), &[], &[b2agg_note])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_B2AGG_TARGET_ACCOUNT_MISMATCH);

    Ok(())
}
