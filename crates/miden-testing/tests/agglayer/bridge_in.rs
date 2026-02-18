extern crate alloc;

use miden_agglayer::{
    ClaimNoteStorage,
    OutputNoteData,
    UpdateGerNote,
    create_claim_note,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_protocol::Felt;
use miden_protocol::account::Account;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::transaction::OutputNote;
use miden_standards::account::wallets::BasicWallet;
use miden_testing::{AccountState, Auth, MockChain};
use rand::Rng;

use super::test_utils::real_claim_data;

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

    let agglayer_faucet = create_existing_agglayer_faucet(
        agglayer_faucet_seed,
        token_symbol,
        decimals,
        max_supply,
        bridge_account.id(),
    );
    builder.add_account(agglayer_faucet.clone())?;

    // GET REAL CLAIM DATA FROM JSON
    // --------------------------------------------------------------------------------------------
    let (proof_data, leaf_data, ger) = real_claim_data();

    // Get the destination account ID from the leaf data
    // This requires the destination_address to be in the embedded Miden AccountId format
    // (first 4 bytes must be zero).
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

    // CREATE CLAIM NOTE WITH REAL PROOF DATA AND LEAF DATA
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
    // validates the Merkle proof using real cryptographic proof data and creates an output note.
    //
    // TODO: Once scale_u256_to_native_amount is properly implemented, add:
    // - Verification that the minted amount matches the expected scaled value
    // - Full note ID comparison with the expected P2ID note
    // - Asset content verification

    Ok(())
}
