extern crate alloc;

use core::slice;

use miden_agglayer::{
    ClaimNoteParams,
    claim_note_test_inputs,
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

/// Tests the bridge-in flow: CLAIM note -> Aggfaucet (FPI to Bridge) -> P2ID note created.
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
    let max_supply = Felt::new(1000000);
    let agglayer_faucet_seed = builder.rng_mut().draw_word();

    let agglayer_faucet = create_existing_agglayer_faucet(
        agglayer_faucet_seed,
        token_symbol,
        decimals,
        max_supply,
        bridge_account.id(),
    );
    builder.add_account(agglayer_faucet.clone())?;

    // CREATE USER ACCOUNT TO RECEIVE P2ID NOTE
    // --------------------------------------------------------------------------------------------
    let user_account_builder =
        Account::builder(builder.rng_mut().random()).with_component(BasicWallet);
    let user_account = builder.add_account_from_builder(
        Auth::IncrNonce,
        user_account_builder,
        AccountState::Exists,
    )?;

    // CREATE CLAIM NOTE WITH P2ID OUTPUT NOTE DETAILS
    // --------------------------------------------------------------------------------------------

    // Define amount values for the test
    let amount_felt = Felt::new(100);

    // Create CLAIM note using the helper function with new agglayer claimAsset inputs
    let (
        smt_proof_local_exit_root,
        smt_proof_rollup_exit_root,
        global_index,
        mainnet_exit_root,
        rollup_exit_root,
        origin_network,
        origin_token_address,
        destination_network,
        destination_address,
        amount_u256,
        metadata,
    ) = claim_note_test_inputs(amount_felt, user_account.id());

    // Generate a serial number for the P2ID note
    let serial_num = builder.rng_mut().draw_word();

    let claim_params = ClaimNoteParams {
        smt_proof_local_exit_root,
        smt_proof_rollup_exit_root,
        global_index,
        mainnet_exit_root: &mainnet_exit_root,
        rollup_exit_root: &rollup_exit_root,
        origin_network,
        origin_token_address: &origin_token_address,
        destination_network,
        destination_address: &destination_address,
        amount: amount_u256,
        metadata,
        claim_note_creator_account_id: user_account.id(),
        agglayer_faucet_account_id: agglayer_faucet.id(),
        output_note_tag: NoteTag::with_account_target(user_account.id()),
        p2id_serial_number: serial_num,
        destination_account_id: user_account.id(),
        rng: builder.rng_mut(),
    };

    // Create P2ID note for the user account (similar to network faucet test)
    let p2id_script = StandardNote::P2ID.script();
    let p2id_inputs = vec![user_account.id().suffix(), user_account.id().prefix().as_felt()];
    let note_inputs = NoteStorage::new(p2id_inputs)?;
    let p2id_recipient = NoteRecipient::new(serial_num, p2id_script.clone(), note_inputs);

    let claim_note = create_claim_note(claim_params)?;

    // Add the claim note to the builder before building the mock chain
    builder.add_output_note(OutputNote::Full(claim_note.clone()));

    // BUILD MOCK CHAIN WITH ALL ACCOUNTS
    // --------------------------------------------------------------------------------------------
    let mut mock_chain = builder.clone().build()?;
    mock_chain.prove_next_block()?;

    // CREATE EXPECTED P2ID NOTE FOR VERIFICATION
    // --------------------------------------------------------------------------------------------
    let mint_asset: Asset = FungibleAsset::new(agglayer_faucet.id(), amount_felt.into())?.into();
    let output_note_tag = NoteTag::with_account_target(user_account.id());
    let expected_p2id_note = Note::new(
        NoteAssets::new(vec![mint_asset])?,
        NoteMetadata::new(agglayer_faucet.id(), NoteType::Public, output_note_tag),
        p2id_recipient,
    );

    // EXECUTE CLAIM NOTE AGAINST AGGLAYER FAUCET (with FPI to Bridge)
    // --------------------------------------------------------------------------------------------
    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(bridge_account.id())?;

    let tx_context = mock_chain
        .build_tx_context(agglayer_faucet.id(), &[], &[claim_note])?
        .add_note_script(p2id_script)
        .foreign_accounts(vec![foreign_account_inputs])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // VERIFY P2ID NOTE WAS CREATED
    // --------------------------------------------------------------------------------------------

    // Check that exactly one P2ID note was created by the faucet
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    // Verify the output note contains the minted fungible asset
    let expected_asset = FungibleAsset::new(agglayer_faucet.id(), amount_felt.into())?;

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

    // Apply the transaction to the mock chain
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // CONSUME THE OUTPUT NOTE WITH TARGET ACCOUNT
    // --------------------------------------------------------------------------------------------
    // Consume the output note with target account
    let mut user_account_mut = user_account.clone();
    let consume_tx_context = mock_chain
        .build_tx_context(user_account_mut.clone(), &[], slice::from_ref(&expected_p2id_note))?
        .build()?;
    let consume_executed_transaction = consume_tx_context.execute().await?;

    user_account_mut.apply_delta(consume_executed_transaction.account_delta())?;

    // Verify the account's vault now contains the expected fungible asset
    let balance = user_account_mut.vault().get_balance(agglayer_faucet.id())?;
    assert_eq!(balance, expected_asset.amount());

    Ok(())
}
