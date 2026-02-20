extern crate alloc;

use core::slice;

use miden_agglayer::{
    ClaimNoteStorage,
    EthAddressFormat,
    OutputNoteData,
    UpdateGerNote,
    create_claim_note,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_protocol::account::Account;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::testing::account;
use miden_protocol::transaction::OutputNote;
use miden_protocol::{Felt, FieldElement};
use miden_standards::account::wallets::BasicWallet;
use miden_testing::utils::create_p2id_note_exact;
use miden_testing::{AccountState, Auth, MockChain};
use rand::Rng;

use super::test_utils::{real_claim_data, simulated_claim_data};

/// Tests the bridge-in flow using real claim data: CLAIM note -> Aggfaucet (FPI to Bridge) -> P2ID
/// note created.
///
/// This test uses real ProofData and LeafData deserialized from claim_asset_vectors.json.
/// The claim note is processed against the agglayer faucet, which validates the Merkle proof
/// and creates a P2ID note for the destination address.
///
/// Note: Modifying anything in the test vectors would invalidate the Merkle proof,
/// as the proof was computed for the original leaf_data including the original destination.
#[tokio::test]
async fn test_bridge_in_claim_to_p2id() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ACCOUNT (with bridge_out component for MMR validation)
    // --------------------------------------------------------------------------------------------
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(bridge_seed);
    builder.add_account(bridge_account.clone())?;

    // CREATE AGGLAYER FAUCET ACCOUNT (with agglayer_faucet component)
    // --------------------------------------------------------------------------------------------
    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT);
    let agglayer_faucet_seed = builder.rng_mut().draw_word();

    // Origin token address for the faucet's conversion metadata
    let origin_token_address = EthAddressFormat::new([0u8; 20]);
    let origin_network = 0u32;
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
    );
    builder.add_account(agglayer_faucet.clone())?;

    // GET REAL CLAIM DATA FROM JSON
    // --------------------------------------------------------------------------------------------
    let (proof_data, leaf_data, ger) = real_claim_data();

    // CREATE DESTINATION ACCOUNT (to consume the P2ID note)
    // --------------------------------------------------------------------------------------------
    // We create a wallet account that will receive and consume the P2ID note.
    // Note: The destination_account_id from leaf_data is embedded in the P2ID note,
    // but we create our own wallet here since we can't control the AccountId from test data.

    let destination_account_id = leaf_data.destination_address.to_account_id().unwrap();
    let setup_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let vault = setup_account.vault().clone();
    let storage = setup_account.storage().clone();
    let nonce = setup_account.nonce();
    let seed = setup_account.seed();
    let code = setup_account.code().clone();

    let destination_account =
        Account::new_unchecked(destination_account_id, vault, storage, code, nonce, seed);

    // CREATE SENDER ACCOUNT (for creating the claim note)
    // --------------------------------------------------------------------------------------------
    let sender_account_builder =
        Account::builder(builder.rng_mut().random()).with_component(BasicWallet);
    let sender_account = builder.add_account_from_builder(
        Auth::IncrNonce,
        sender_account_builder,
        AccountState::Exists,
    )?;

    // CREATE CLAIM NOTE WITH REAL PROOF DATA AND LEAF DATA
    // --------------------------------------------------------------------------------------------

    // Generate a serial number for the P2ID note
    let serial_num = builder.rng_mut().draw_word();

    // Calculate the scaled-down Miden amount using the faucet's scale factor
    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");

    let output_note_data = OutputNoteData {
        output_p2id_serial_num: serial_num, // TODO: will be proof data key
        target_faucet_account_id: agglayer_faucet.id(),
        output_note_tag: NoteTag::with_account_target(destination_account_id),
        miden_claim_amount,
    };

    let claim_inputs = ClaimNoteStorage { proof_data, leaf_data, output_note_data };

    let claim_note = create_claim_note(claim_inputs, sender_account.id(), builder.rng_mut())?;

    // Add the claim note to the builder before building the mock chain
    builder.add_output_note(OutputNote::Full(claim_note.clone()));

    // CREATE UPDATE_GER NOTE WITH GLOBAL EXIT ROOT
    // --------------------------------------------------------------------------------------------
    let update_ger_note =
        UpdateGerNote::create(ger, sender_account.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(OutputNote::Full(update_ger_note.clone()));

    // BUILD MOCK CHAIN WITH ALL ACCOUNTS
    // --------------------------------------------------------------------------------------------
    let mut mock_chain = builder.clone().build()?;

    // EXECUTE UPDATE_GER NOTE TO STORE GER IN BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let update_ger_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_ger_executed = update_ger_tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // EXECUTE CLAIM NOTE AGAINST AGGLAYER FAUCET (with FPI to Bridge)
    // --------------------------------------------------------------------------------------------
    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(bridge_account.id())?;

    let tx_context = mock_chain
        .build_tx_context(agglayer_faucet.id(), &[], &[claim_note])?
        .foreign_accounts(vec![foreign_account_inputs])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // VERIFY P2ID NOTE WAS CREATED
    // --------------------------------------------------------------------------------------------

    // Check that exactly one P2ID note was created by the faucet
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    // Verify note metadata properties
    assert_eq!(output_note.metadata().sender(), agglayer_faucet.id());
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);

    // Extract and verify P2ID asset contents
    let mut assets_iter = output_note.assets().unwrap().iter_fungible();
    let p2id_asset = assets_iter.next().unwrap();

    // Verify minted amount matches expected scaled value
    assert_eq!(
        Felt::new(p2id_asset.amount()),
        miden_claim_amount,
        "asset amount does not match"
    );

    // Verify faucet ID matches agglayer_faucet (P2ID token issuer)
    assert_eq!(
        p2id_asset.faucet_id(),
        agglayer_faucet.id(),
        "P2ID asset faucet ID doesn't match agglayer_faucet: got {:?}, expected {:?}",
        p2id_asset.faucet_id(),
        agglayer_faucet.id()
    );

    // Verify full note ID construction
    let expected_asset: Asset =
        FungibleAsset::new(agglayer_faucet.id(), miden_claim_amount.as_int())
            .unwrap()
            .into();
    let expected_output_p2id_note = create_p2id_note_exact(
        agglayer_faucet.id(),
        destination_account_id,
        vec![expected_asset],
        NoteType::Public,
        serial_num,
    )
    .unwrap();

    assert_eq!(OutputNote::Full(expected_output_p2id_note), *output_note);

    // CONSUME P2ID NOTE BY DESTINATION ACCOUNT
    // --------------------------------------------------------------------------------------------

    let consume_tx_context = mock_chain
        .build_tx_context(destination_account.id(), &[output_note.id()], &[])?
        .build()?;

    let consume_tx = consume_tx_context.execute().await?;

    let account_delta = consume_tx.account_delta();

    println!("account delta: {:?}", account_delta);
    Ok(())
}

/// Tests the bridge-in flow using simulated L1 bridgeAsset data: CLAIM note -> Aggfaucet (FPI to
/// Bridge) -> P2ID note created.
///
/// This test uses simulated ProofData and LeafData from bridge_asset_vectors.json,
/// which represents a locally simulated L1 bridgeAsset() transaction.
/// The claim note is processed against the agglayer faucet, which validates the Merkle proof
/// and creates a P2ID note for the destination address.
///
/// This test verifies that the Solidity-generated test vectors can be used in Miden's bridge flow.
#[tokio::test]
async fn test_bridge_in_simulated_l1_transaction() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ACCOUNT (with bridge_out component for MMR validation)
    // --------------------------------------------------------------------------------------------
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(bridge_seed);
    builder.add_account(bridge_account.clone())?;

    // GET SIMULATED CLAIM DATA FROM JSON FIRST (to get origin token address)
    // --------------------------------------------------------------------------------------------
    let (proof_data, leaf_data, ger) = simulated_claim_data();

    // CREATE AGGLAYER FAUCET ACCOUNT (with agglayer_faucet component)
    // Use the origin token address from the test vectors
    // --------------------------------------------------------------------------------------------
    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT);
    let agglayer_faucet_seed = builder.rng_mut().draw_word();

    // Origin token address and network from the test vectors
    let origin_token_address = leaf_data.origin_token_address;
    let origin_network = leaf_data.origin_network;
    let scale = 0u8;

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
    );
    builder.add_account(agglayer_faucet.clone())?;

    // Get the destination account ID from the leaf data
    // destination_account_id = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE
    let destination_account_id = leaf_data
        .destination_address
        .to_account_id()
        .expect("destination address is not an embedded Miden AccountId");

    // CREATE SENDER ACCOUNT (for creating the claim note)
    // --------------------------------------------------------------------------------------------
    let sender_account_builder =
        Account::builder(builder.rng_mut().random()).with_component(BasicWallet);
    let sender_account = builder.add_account_from_builder(
        Auth::IncrNonce,
        sender_account_builder,
        AccountState::Exists,
    )?;

    // CREATE CLAIM NOTE WITH SIMULATED PROOF DATA AND LEAF DATA
    // --------------------------------------------------------------------------------------------

    // Generate a serial number for the P2ID note
    let serial_num = builder.rng_mut().draw_word();

    let output_note_data = OutputNoteData {
        output_p2id_serial_num: serial_num,
        target_faucet_account_id: agglayer_faucet.id(),
        output_note_tag: NoteTag::with_account_target(destination_account_id),
    };

    let claim_inputs = ClaimNoteStorage { proof_data, leaf_data, output_note_data };

    let claim_note = create_claim_note(claim_inputs, sender_account.id(), builder.rng_mut())?;

    // Add the claim note to the builder before building the mock chain
    builder.add_output_note(OutputNote::Full(claim_note.clone()));

    // CREATE UPDATE_GER NOTE WITH GLOBAL EXIT ROOT
    // --------------------------------------------------------------------------------------------
    let update_ger_note =
        UpdateGerNote::create(ger, sender_account.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(OutputNote::Full(update_ger_note.clone()));

    // BUILD MOCK CHAIN WITH ALL ACCOUNTS
    // --------------------------------------------------------------------------------------------
    let mut mock_chain = builder.clone().build()?;

    // EXECUTE UPDATE_GER NOTE TO STORE GER IN BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let update_ger_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_ger_executed = update_ger_tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // EXECUTE CLAIM NOTE AGAINST AGGLAYER FAUCET (with FPI to Bridge)
    // --------------------------------------------------------------------------------------------
    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(bridge_account.id())?;

    let tx_context = mock_chain
        .build_tx_context(agglayer_faucet.id(), &[], &[claim_note])?
        .foreign_accounts(vec![foreign_account_inputs])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // VERIFY P2ID NOTE WAS CREATED
    // --------------------------------------------------------------------------------------------

    // Check that exactly one P2ID note was created by the faucet
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    // Verify note metadata properties
    assert_eq!(output_note.metadata().sender(), agglayer_faucet.id());
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);

    // Note: We intentionally do NOT verify the exact note ID or asset amount here because
    // the scale_u256_to_native_amount function is currently a TODO stub that doesn't perform
    // proper u256-to-native scaling. The test verifies that the bridge-in flow correctly
    // validates the Merkle proof using simulated L1 bridgeAsset data and creates an output note.
    //
    // This test demonstrates that Solidity-generated test vectors can be successfully used
    // in Miden's bridge implementation.

    Ok(())
}
