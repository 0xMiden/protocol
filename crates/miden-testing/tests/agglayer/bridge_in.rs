extern crate alloc;

use miden_agglayer::{
    ClaimNoteStorage,
    OutputNoteData,
    create_claim_note,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_protocol::Felt;
use miden_protocol::account::Account;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteMetadata,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_protocol::transaction::OutputNote;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::StandardNote;
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
    let (proof_data, leaf_data) = real_claim_data();

    // Extract the claim amount from the real leaf data
    // The amount is stored as a 32-byte big-endian value
    let amount_bytes = leaf_data.amount.as_bytes();
    // Convert the last 8 bytes to u64 (the amount should fit in u64 for fungible assets)
    let claim_amount: u64 = u64::from_be_bytes(amount_bytes[24..32].try_into().unwrap());

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

    // Use the original leaf_data without modification to preserve Merkle proof validity
    let claim_inputs = ClaimNoteStorage { proof_data, leaf_data, output_note_data };

    let claim_note = create_claim_note(claim_inputs, sender_account.id(), builder.rng_mut())?;

    // Create P2ID note script and recipient for expected note verification
    let p2id_script = StandardNote::P2ID.script();
    let p2id_inputs =
        vec![destination_account_id.suffix(), destination_account_id.prefix().as_felt()];
    let note_storage = NoteStorage::new(p2id_inputs)?;
    let p2id_recipient = NoteRecipient::new(serial_num, p2id_script.clone(), note_storage);

    // Add the claim note to the builder before building the mock chain
    builder.add_output_note(OutputNote::Full(claim_note.clone()));

    // BUILD MOCK CHAIN WITH ALL ACCOUNTS
    // --------------------------------------------------------------------------------------------
    let mut mock_chain = builder.clone().build()?;
    mock_chain.prove_next_block()?;

    // CREATE EXPECTED P2ID NOTE FOR VERIFICATION
    // --------------------------------------------------------------------------------------------
    // TODO check that the claim amount is correct
    let mint_asset: Asset = FungibleAsset::new(agglayer_faucet.id(), claim_amount)?.into();
    let output_note_tag = NoteTag::with_account_target(destination_account_id);
    let expected_p2id_note = Note::new(
        NoteAssets::new(vec![mint_asset])?,
        NoteMetadata::new(agglayer_faucet.id(), NoteType::Public).with_tag(output_note_tag),
        p2id_recipient,
    );

    // EXECUTE CLAIM NOTE AGAINST AGGLAYER FAUCET (with FPI to Bridge)
    // --------------------------------------------------------------------------------------------
    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(bridge_account.id())?;

    let tx_context = mock_chain
        .build_tx_context(agglayer_faucet.id(), &[], &[claim_note])?
        .add_note_script(p2id_script.clone())
        .foreign_accounts(vec![foreign_account_inputs])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // VERIFY P2ID NOTE WAS CREATED
    // --------------------------------------------------------------------------------------------

    // Check that exactly one P2ID note was created by the faucet
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    // Verify the output note contains the minted fungible asset
    let expected_asset = FungibleAsset::new(agglayer_faucet.id(), claim_amount)?;

    // Verify note metadata properties
    assert_eq!(output_note.metadata().sender(), agglayer_faucet.id());
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);
    assert_eq!(output_note.id(), expected_p2id_note.id());

    // Extract the full note from the OutputNote enum for detailed verification
    let full_note = match output_note {
        OutputNote::Full(note) => note,
        _ => panic!("Expected OutputNote::Full variant for public note"),
    };

    // Verify note structure and asset content
    let expected_asset_obj = Asset::from(expected_asset);
    assert_eq!(full_note, &expected_p2id_note);
    assert!(full_note.assets().iter().any(|asset| asset == &expected_asset_obj));

    // Note: We intentionally do NOT consume the P2ID note here because the destination
    // address from the real on-chain data doesn't correspond to an account we have an
    // authenticator for. The test verifies that the bridge-in flow correctly creates
    // the P2ID note using real cryptographic proof data.

    Ok(())
}
