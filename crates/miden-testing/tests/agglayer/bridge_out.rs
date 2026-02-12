extern crate alloc;

use miden_agglayer::errors::{ERR_B2AGG_TARGET_ACCOUNT_MISMATCH, ERR_FAUCET_NOT_REGISTERED};
use miden_agglayer::{
    B2AggNote,
    ConfigAggBridgeNote,
    EthAddressFormat,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
    ExitRoot,
};
use miden_crypto::rand::FeltRng;
use miden_protocol::Felt;
use miden_protocol::account::{
    Account,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::{NoteAssets, NoteScript, NoteTag, NoteType};
use miden_protocol::transaction::OutputNote;
use miden_standards::account::faucets::TokenMetadata;
use miden_standards::note::StandardNote;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::utils::hex_to_bytes;

use super::mmr_frontier::SOLIDITY_MMR_FRONTIER_VECTORS;

/// Reads the Local Exit Root (double-word) from the bridge account's storage.
///
/// The Local Exit Root is stored in two dedicated value slots:
/// - `"miden::agglayer::let::root_lo"` — low word of the root
/// - `"miden::agglayer::let::root_hi"` — high word of the root
///
/// Returns `[root_lo, root_hi]`. For an empty/uninitialized tree, both words are zeros.
fn read_local_exit_root(account: &Account) -> Vec<Felt> {
    let root_lo_slot =
        StorageSlotName::new("miden::agglayer::let::root_lo").expect("slot name should be valid");
    let root_hi_slot =
        StorageSlotName::new("miden::agglayer::let::root_hi").expect("slot name should be valid");

    let root_lo = account
        .storage()
        .get_item(&root_lo_slot)
        .expect("should be able to read LET root lo");
    let root_hi = account
        .storage()
        .get_item(&root_hi_slot)
        .expect("should be able to read LET root hi");

    let mut root = Vec::with_capacity(8);
    root.extend(root_lo.to_vec().into_iter().rev());
    root.extend(root_hi.to_vec().into_iter().rev());
    root
}

/// Tests that consuming a single B2AGG note produces the correct Local Exit Root.
///
/// The leaf data parameters (destination network, address, amount) are taken from the
/// Solidity-generated `mmr_frontier_vectors.json` so that the resulting LER can be compared
/// against the expected root produced by the Solidity `DepositContractV2`.
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
async fn test_bridge_out_consumes_b2agg_note() -> anyhow::Result<()> {
    let vectors = &*SOLIDITY_MMR_FRONTIER_VECTORS;
    let destination_network = vectors.destination_network;
    let eth_address =
        EthAddressFormat::from_hex(&vectors.destination_address).expect("Valid Ethereum address");

    let mut builder = MockChain::builder();

    // CREATE BRIDGE ACCOUNT (empty faucet registry)
    // --------------------------------------------------------------------------------------------
    let mut bridge_account = create_existing_bridge_account(builder.rng_mut().draw_word());
    builder.add_account(bridge_account.clone())?;

    // CREATE AGGLAYER FAUCET ACCOUNT (with conversion metadata for FPI)
    // --------------------------------------------------------------------------------------------
    let origin_token_address = EthAddressFormat::new([0u8; 20]);
    let origin_network = 64u32;
    let scale = 0u8;
    let amount = Felt::new(100);
    let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT);

    let faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        "AGG",
        8,
        max_supply,
        amount,
        bridge_account.id(),
        &origin_token_address,
        origin_network,
        scale,
    );
    builder.add_account(faucet.clone())?;

    // CREATE SENDER ACCOUNT
    // --------------------------------------------------------------------------------------------
    let sender_account = builder.add_existing_wallet(Auth::BasicAuth)?;

    // CREATE ALL NOTES UPFRONT (before building mock chain)
    // --------------------------------------------------------------------------------------------
    // Use the first vector entry: amount from vectors.amounts[0] (bytes32 hex, matching
    // ClaimAssetTestVectors)
    let amount_bytes: [u8; 32] = hex_to_bytes(&vectors.amounts[0]).expect("valid amount hex");

    // TODO this probably needs a util in Rust
    let amount: u64 =
        u64::from_be_bytes(amount_bytes[24..32].try_into().expect("amount bytes 24..32"));
    let bridge_asset: Asset = FungibleAsset::new(faucet.id(), amount).unwrap().into();

    // CONFIG_AGG_BRIDGE note to register the faucet in the bridge
    let config_note = ConfigAggBridgeNote::create(
        faucet.id(),
        sender_account.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;

    let assets = NoteAssets::new(vec![bridge_asset])?;

    let b2agg_note = B2AggNote::create(
        destination_network,
        eth_address,
        assets,
        bridge_account.id(),
        faucet.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(OutputNote::Full(config_note.clone()));
    builder.add_output_note(OutputNote::Full(b2agg_note.clone()));

    let mut mock_chain = builder.clone().build()?;
    mock_chain.prove_next_block()?;

    // STEP 1: REGISTER FAUCET VIA CONFIG_AGG_BRIDGE NOTE
    // --------------------------------------------------------------------------------------------
    let config_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let config_executed = config_tx_context.execute().await?;

    // Apply bridge state changes (faucet is now registered)
    bridge_account.apply_delta(config_executed.account_delta())?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // STEP 2: BRIDGE OUT VIA B2AGG NOTE (with faucet as foreign account for FPI)
    // --------------------------------------------------------------------------------------------
    let burn_note_script: NoteScript = StandardNote::BURN.script();
    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    // Pass the updated bridge_account directly (not by ID) so the transaction
    // uses the account state that includes the faucet registry update.
    let tx_context = mock_chain
        .build_tx_context(bridge_account.clone(), &[b2agg_note.id()], &[])?
        .add_note_script(burn_note_script.clone())
        .foreign_accounts(vec![foreign_account_inputs])
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    // VERIFY PUBLIC BURN NOTE WAS CREATED
    // --------------------------------------------------------------------------------------------
    assert_eq!(
        executed_transaction.output_notes().num_notes(),
        1,
        "Expected one BURN note to be created"
    );

    let output_note = executed_transaction.output_notes().get_note(0);
    let burn_note = match output_note {
        OutputNote::Full(note) => note,
        _ => panic!("Expected OutputNote::Full variant for BURN note"),
    };
    assert_eq!(burn_note.metadata().note_type(), NoteType::Public, "BURN note should be public");

    // Verify the BURN note contains the bridged asset
    let expected_asset = FungibleAsset::new(faucet.id(), amount.into())?;
    assert!(
        burn_note.assets().iter().any(|asset| asset == &Asset::from(expected_asset)),
        "BURN note should contain the bridged asset"
    );

    // Verify the BURN note tag targets the faucet
    assert_eq!(
        burn_note.metadata().tag(),
        NoteTag::with_account_target(faucet.id()),
        "BURN note should have the correct tag"
    );
    assert_eq!(
        burn_note.recipient().script().root(),
        StandardNote::BURN.script_root(),
        "BURN note should use the BURN script"
    );

    // STEP 3: CONSUME BURN NOTE WITH THE AGGLAYER FAUCET
    // --------------------------------------------------------------------------------------------
    bridge_account.apply_delta(executed_transaction.account_delta())?;

    // VERIFY LOCAL EXIT ROOT MATCHES SOLIDITY VECTOR
    // --------------------------------------------------------------------------------------------
    let computed_ler = read_local_exit_root(&bridge_account);

    let expected_ler =
        ExitRoot::new(hex_to_bytes(&vectors.roots[0]).expect("valid root hex")).to_elements();
    assert_eq!(
        computed_ler, expected_ler,
        "Local Exit Root after 1 leaf should match the Solidity-generated root"
    );

    // Apply the transaction to the mock chain
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // CONSUME THE BURN NOTE WITH THE NETWORK FAUCET
    // --------------------------------------------------------------------------------------------
    // Check the initial token issuance before burning
    let initial_token_supply = TokenMetadata::try_from(faucet.storage())?.token_supply();
    assert_eq!(initial_token_supply, Felt::new(100), "Initial issuance should be 100");

    // Execute the BURN note against the network faucet
    let burn_tx_context =
        mock_chain.build_tx_context(faucet.id(), &[burn_note.id()], &[])?.build()?;
    let burn_executed = burn_tx_context.execute().await?;

    // Verify the burn transaction was successful — no output notes should be created
    assert_eq!(
        burn_executed.output_notes().num_notes(),
        0,
        "Burn transaction should not create output notes"
    );

    let mut faucet = faucet;
    faucet.apply_delta(burn_executed.account_delta())?;

    let final_token_supply = TokenMetadata::try_from(faucet.storage())?.token_supply();
    assert_eq!(
        final_token_supply,
        Felt::new(initial_token_supply.as_int() - amount),
        "Token issuance should decrease by the burned amount"
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

    // CREATE BRIDGE ACCOUNT (empty faucet registry — no faucets registered)
    // --------------------------------------------------------------------------------------------
    let bridge_account = create_existing_bridge_account(builder.rng_mut().draw_word());
    builder.add_account(bridge_account.clone())?;

    // CREATE AGGLAYER FAUCET ACCOUNT (NOT registered in the bridge)
    // --------------------------------------------------------------------------------------------
    let origin_token_address = EthAddressFormat::new([0u8; 20]);
    let faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        "AGG",
        8,
        Felt::new(FungibleAsset::MAX_AMOUNT),
        Felt::new(100),
        bridge_account.id(),
        &origin_token_address,
        0, // origin_network
        0, // scale
    );
    builder.add_account(faucet.clone())?;

    // CREATE B2AGG NOTE WITH ASSETS FROM THE UNREGISTERED FAUCET
    // --------------------------------------------------------------------------------------------
    let amount = Felt::new(100);
    let bridge_asset: Asset = FungibleAsset::new(faucet.id(), amount.into()).unwrap().into();

    let destination_address = "0x1234567890abcdef1122334455667788990011aa";
    let eth_address =
        EthAddressFormat::from_hex(destination_address).expect("Valid Ethereum address");

    let b2agg_note = B2AggNote::create(
        1u32, // destination_network
        eth_address,
        NoteAssets::new(vec![bridge_asset])?,
        bridge_account.id(),
        faucet.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(OutputNote::Full(b2agg_note.clone()));
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
async fn test_b2agg_note_reclaim_scenario() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Create a network faucet owner account
    let faucet_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    // Create a network faucet to provide assets for the B2AGG note
    let faucet =
        builder.add_existing_network_faucet("AGG", 1000, faucet_owner_account_id, Some(100))?;

    // Create a bridge account (includes a `bridge_out` component)
    let bridge_account = create_existing_bridge_account(builder.rng_mut().draw_word());
    builder.add_account(bridge_account.clone())?;

    // Create a user account that will create and consume the B2AGG note
    let mut user_account = builder.add_existing_wallet(Auth::BasicAuth)?;

    // CREATE B2AGG NOTE WITH USER ACCOUNT AS SENDER
    // --------------------------------------------------------------------------------------------
    let amount = Felt::new(50);
    let bridge_asset: Asset = FungibleAsset::new(faucet.id(), amount.into()).unwrap().into();

    let destination_network = 1u32;
    let destination_address = "0x1234567890abcdef1122334455667788990011aa";
    let eth_address =
        EthAddressFormat::from_hex(destination_address).expect("Valid Ethereum address");

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

    builder.add_output_note(OutputNote::Full(b2agg_note.clone()));
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
        initial_balance + amount.as_int(),
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
async fn test_b2agg_note_non_target_account_cannot_consume() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Create a network faucet owner account
    let faucet_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    // Create a network faucet to provide assets for the B2AGG note
    let faucet =
        builder.add_existing_network_faucet("AGG", 1000, faucet_owner_account_id, Some(100))?;

    // Create a bridge account as the designated TARGET for the B2AGG note
    let bridge_account = create_existing_bridge_account(builder.rng_mut().draw_word());
    builder.add_account(bridge_account.clone())?;

    // Create a user account as the SENDER of the B2AGG note
    let sender_account = builder.add_existing_wallet(Auth::BasicAuth)?;

    // Create a "malicious" account with a bridge interface
    let malicious_account = create_existing_bridge_account(builder.rng_mut().draw_word());
    builder.add_account(malicious_account.clone())?;

    // CREATE B2AGG NOTE
    // --------------------------------------------------------------------------------------------
    let amount = Felt::new(50);
    let bridge_asset: Asset = FungibleAsset::new(faucet.id(), amount.into()).unwrap().into();

    let destination_network = 1u32;
    let destination_address = "0x1234567890abcdef1122334455667788990011aa";
    let eth_address =
        EthAddressFormat::from_hex(destination_address).expect("Valid Ethereum address");

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

    builder.add_output_note(OutputNote::Full(b2agg_note.clone()));
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
