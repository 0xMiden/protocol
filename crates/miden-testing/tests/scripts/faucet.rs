use miden_core::field::PrimeField64;
extern crate alloc;

use alloc::sync::Arc;
use core::slice;

use miden_core::crypto::random::RpoRandomCoin;
use miden_protocol::account::{
    Account,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteExecutionHint,
    NoteExecutionMode,
    NoteId,
    NoteInputs,
    NoteMetadata,
    NoteRecipient,
    NoteTag,
    NoteType,
};
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use miden_protocol::transaction::{ExecutedTransaction, OutputNote};
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::{
    BasicFungibleFaucet,
    FungibleFaucetExt,
    NetworkFungibleFaucet,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_FUNGIBLE_ASSET_DISTRIBUTE_WOULD_CAUSE_MAX_SUPPLY_TO_BE_EXCEEDED;
use miden_standards::note::{MintNoteInputs, WellKnownNote, create_burn_note, create_mint_note};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use crate::scripts::swap::create_p2id_note_exact;
use crate::{get_note_with_fungible_asset_and_script, prove_and_verify_transaction};

// Shared test utilities for faucet tests
// ================================================================================================

/// Common test parameters for faucet tests
pub struct FaucetTestParams {
    pub recipient: Word,
    pub tag: NoteTag,
    pub aux: Felt,
    pub note_execution_hint: NoteExecutionHint,
    pub note_type: NoteType,
    pub amount: Felt,
}

/// Creates minting script code for fungible asset distribution
pub fn create_mint_script_code(params: &FaucetTestParams) -> String {
    format!(
        "
            begin
                # pad the stack before call
                push.0.0.0 padw

                push.{recipient}
                push.{note_execution_hint}
                push.{note_type}
                push.{aux}
                push.{tag}
                push.{amount}
                # => [amount, tag, aux, note_type, execution_hint, RECIPIENT, pad(7)]

                call.::miden::standards::faucets::basic_fungible::distribute
                # => [note_idx, pad(15)]

                # truncate the stack
                dropw dropw dropw dropw
            end
            ",
        note_type = params.note_type as u8,
        recipient = params.recipient,
        aux = params.aux,
        tag = u32::from(params.tag),
        note_execution_hint = Felt::from(params.note_execution_hint),
        amount = params.amount,
    )
}

/// Executes a minting transaction with the given faucet and parameters
pub async fn execute_mint_transaction(
    mock_chain: &mut MockChain,
    faucet: Account,
    params: &FaucetTestParams,
) -> anyhow::Result<ExecutedTransaction> {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script_code = create_mint_script_code(params);
    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_tx_script(tx_script_code)?;
    let tx_context = mock_chain
        .build_tx_context(faucet, &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    Ok(tx_context.execute().await?)
}

/// Verifies minted output note matches expectations
pub fn verify_minted_output_note(
    executed_transaction: &ExecutedTransaction,
    faucet: &Account,
    params: &FaucetTestParams,
) -> anyhow::Result<()> {
    let fungible_asset: Asset =
        FungibleAsset::new(faucet.id(), params.amount.as_canonical_u64())?.into();

    let output_note = executed_transaction.output_notes().get_note(0).clone();
    let assets = NoteAssets::new(vec![fungible_asset])?;
    let id = NoteId::new(params.recipient, assets.commitment());

    assert_eq!(output_note.id(), id);
    assert_eq!(
        output_note.metadata(),
        &NoteMetadata::new(
            faucet.id(),
            params.note_type,
            params.tag,
            params.note_execution_hint,
            params.aux
        )?
    );

    Ok(())
}

// TESTS MINT FUNGIBLE ASSET
// ================================================================================================

/// Tests that minting assets on an existing faucet succeeds.
#[tokio::test]
async fn minting_fungible_asset_on_existing_faucet_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(Auth::BasicAuth, "TST", 200, None)?;
    let mut mock_chain = builder.build()?;

    let params = FaucetTestParams {
        recipient: Word::from([0, 1, 2, 3u32]),
        tag: NoteTag::for_local_use_case(0, 0).unwrap(),
        aux: Felt::new(27),
        note_execution_hint: NoteExecutionHint::on_block_slot(5, 6, 7),
        note_type: NoteType::Private,
        amount: Felt::new(100),
    };

    params
        .tag
        .validate(params.note_type)
        .expect("note tag should support private notes");

    let executed_transaction =
        execute_mint_transaction(&mut mock_chain, faucet.clone(), &params).await?;
    verify_minted_output_note(&executed_transaction, &faucet, &params)?;

    Ok(())
}

#[tokio::test]
async fn faucet_contract_mint_fungible_asset_fails_exceeds_max_supply() -> anyhow::Result<()> {
    // CONSTRUCT AND EXECUTE TX (Failure)
    // --------------------------------------------------------------------------------------------
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(Auth::BasicAuth, "TST", 200, None)?;
    let mock_chain = builder.build()?;

    let recipient = Word::from([0, 1, 2, 3u32]);
    let aux = Felt::new(27);
    let tag = Felt::new(4);
    let amount = Felt::new(250);

    let tx_script_code = format!(
        "
            begin
                # pad the stack before call
                push.0.0.0 padw

                push.{recipient}
                push.{note_type}
                push.{aux}
                push.{tag}
                push.{amount}
                # => [amount, tag, aux, note_type, execution_hint, RECIPIENT, pad(7)]

                call.::miden::standards::faucets::basic_fungible::distribute
                # => [note_idx, pad(15)]

                # truncate the stack
                dropw dropw dropw dropw

            end
            ",
        note_type = NoteType::Private as u8,
        recipient = recipient,
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;
    let tx = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    // Execute the transaction and get the witness
    assert_transaction_executor_error!(
        tx,
        ERR_FUNGIBLE_ASSET_DISTRIBUTE_WOULD_CAUSE_MAX_SUPPLY_TO_BE_EXCEEDED
    );
    Ok(())
}

// TESTS FOR NEW FAUCET EXECUTION ENVIRONMENT
// ================================================================================================

/// Tests that minting assets on a new faucet succeeds.
#[tokio::test]
async fn minting_fungible_asset_on_new_faucet_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.create_new_faucet(Auth::BasicAuth, "TST", 200)?;
    let mut mock_chain = builder.build()?;

    let params = FaucetTestParams {
        recipient: Word::from([0, 1, 2, 3u32]),
        tag: NoteTag::for_local_use_case(0, 0).unwrap(),
        aux: Felt::new(27),
        note_execution_hint: NoteExecutionHint::on_block_slot(5, 6, 7),
        note_type: NoteType::Private,
        amount: Felt::new(100),
    };

    params
        .tag
        .validate(params.note_type)
        .expect("note tag should support private notes");

    let executed_transaction =
        execute_mint_transaction(&mut mock_chain, faucet.clone(), &params).await?;
    verify_minted_output_note(&executed_transaction, &faucet, &params)?;

    Ok(())
}

// TESTS BURN FUNGIBLE ASSET
// ================================================================================================

/// Tests that burning a fungible asset on an existing faucet succeeds and proves the transaction.
#[tokio::test]
async fn prove_burning_fungible_asset_on_existing_faucet_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(Auth::BasicAuth, "TST", 200, Some(100))?;

    let fungible_asset = FungibleAsset::new(faucet.id(), 100).unwrap();

    // need to create a note with the fungible asset to be burned
    let burn_note_script_code = "
        # burn the asset
        begin
            dropw
            # => []

            call.::miden::standards::faucets::basic_fungible::burn
            # => [ASSET]

            # truncate the stack
            dropw
        end
        ";

    let note = get_note_with_fungible_asset_and_script(fungible_asset, burn_note_script_code);

    builder.add_output_note(OutputNote::Full(note.clone()));
    let mock_chain = builder.build()?;

    // Check that max_supply at the word's index 0 is 200. The remainder of the word is initialized
    // with the metadata of the faucet which we don't need to check.
    assert_eq!(
        faucet.storage().get_item(BasicFungibleFaucet::metadata_slot()).unwrap()[0],
        Felt::new(200)
    );

    // Check that the faucet reserved slot has been correctly initialized.
    // The already issued amount should be 100.
    assert_eq!(faucet.get_token_issuance().unwrap(), Felt::new(100));

    // CONSTRUCT AND EXECUTE TX (Success)
    // --------------------------------------------------------------------------------------------
    // Execute the transaction and get the witness
    let executed_transaction = mock_chain
        .build_tx_context(faucet.id(), &[note.id()], &[])?
        .build()?
        .execute()
        .await?;

    // Prove, serialize/deserialize and verify the transaction
    prove_and_verify_transaction(executed_transaction.clone()).await?;

    assert_eq!(executed_transaction.account_delta().nonce_delta(), Felt::new(1));
    assert_eq!(executed_transaction.input_notes().get_note(0).id(), note.id());
    Ok(())
}

// TEST PUBLIC NOTE CREATION DURING NOTE CONSUMPTION
// ================================================================================================

/// Tests that a public note can be created during note consumption by fetching the note script
/// from the data store. This test verifies the functionality added in issue #1972.
///
/// The test creates a note that calls the faucet's `distribute` function to create a PUBLIC
/// P2ID output note. The P2ID script is fetched from the data store during transaction execution.
#[tokio::test]
async fn test_public_note_creation_with_script_from_datastore() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(Auth::BasicAuth, "TST", 200, None)?;

    // Parameters for the PUBLIC note that will be created by the faucet
    let recipient_account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;
    let amount = Felt::new(75);
    let tag = NoteTag::for_public_use_case(0, 0, NoteExecutionMode::Local)?;
    let aux = Felt::new(27);
    let note_execution_hint = NoteExecutionHint::on_block_slot(5, 6, 7);
    let note_type = NoteType::Public;

    // Create a simple output note script
    let output_note_script_code = "begin push.1 drop end";
    let source_manager = Arc::new(DefaultSourceManager::default());
    let output_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(output_note_script_code)?;

    let serial_num = Word::default();
    let target_account_suffix = recipient_account_id.suffix();
    let target_account_prefix = recipient_account_id.prefix().as_felt();

    // Use a length that is not a multiple of 8 (double word size) to make sure note inputs padding
    // is correctly handled
    let note_inputs = NoteInputs::new(vec![
        target_account_suffix,
        target_account_prefix,
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(1),
        Felt::new(0),
    ])?;

    let note_recipient =
        NoteRecipient::new(serial_num, output_note_script.clone(), note_inputs.clone());

    let output_script_root = note_recipient.script().root();

    let asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())?;
    let metadata = NoteMetadata::new(faucet.id(), note_type, tag, note_execution_hint, aux)?;
    let expected_note = Note::new(NoteAssets::new(vec![asset.into()])?, metadata, note_recipient);

    let trigger_note_script_code = format!(
        "
            use miden::protocol::note
            
            begin
                # Build recipient hash from SERIAL_NUM, SCRIPT_ROOT, and INPUTS_COMMITMENT
                push.{script_root}
                # => [SCRIPT_ROOT]

                push.{serial_num}
                # => [SERIAL_NUM, SCRIPT_ROOT]

                # Store note inputs in memory
                push.{input0} mem_store.0
                push.{input1} mem_store.1
                push.{input2} mem_store.2
                push.{input3} mem_store.3
                push.{input4} mem_store.4
                push.{input5} mem_store.5
                push.{input6} mem_store.6

                push.7 push.0
                # => [inputs_ptr, num_inputs = 7, SERIAL_NUM, SCRIPT_ROOT]

                exec.note::build_recipient
                # => [RECIPIENT]

                # Now call distribute with the computed recipient
                push.{note_execution_hint}
                push.{note_type}
                push.{aux}
                push.{tag}
                push.{amount}
                # => [amount, tag, aux, note_type, execution_hint, RECIPIENT]

                call.::miden::standards::faucets::basic_fungible::distribute
                # => [note_idx, pad(15)]

                # Truncate the stack
                dropw dropw dropw dropw
            end
            ",
        note_type = note_type as u8,
        input0 = note_inputs.values()[0],
        input1 = note_inputs.values()[1],
        input2 = note_inputs.values()[2],
        input3 = note_inputs.values()[3],
        input4 = note_inputs.values()[4],
        input5 = note_inputs.values()[5],
        input6 = note_inputs.values()[6],
        script_root = output_script_root,
        serial_num = serial_num,
        aux = aux,
        tag = u32::from(tag),
        note_execution_hint = Felt::from(note_execution_hint),
        amount = amount,
    );

    // Create the trigger note that will call distribute
    let mut rng = RpoRandomCoin::new([Felt::new(1); 4].into());
    let trigger_note = NoteBuilder::new(faucet.id(), &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::for_local_use_case(0, 0)?.into())
        .note_execution_hint(NoteExecutionHint::always())
        .aux(Felt::new(0))
        .serial_number(Word::from([1, 2, 3, 4u32]))
        .code(trigger_note_script_code)
        .build()?;

    builder.add_output_note(OutputNote::Full(trigger_note.clone()));
    let mock_chain = builder.build()?;

    // Execute the transaction - this should fetch the output note script from the data store.
    // Note: There is intentionally no call to extend_expected_output_notes here, so the
    // transaction host is forced to request the script from the data store during execution.
    let executed_transaction = mock_chain
        .build_tx_context(faucet.id(), &[trigger_note.id()], &[])?
        .add_note_script(output_note_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    // Verify that a PUBLIC note was created
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    // Extract the full note from the OutputNote enum
    let full_note = match output_note {
        OutputNote::Full(note) => note,
        _ => panic!("Expected OutputNote::Full variant"),
    };

    // Verify the output note is public
    assert_eq!(full_note.metadata().note_type(), NoteType::Public);

    // Verify the output note contains the minted fungible asset
    let expected_asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())?;
    let expected_asset_obj = Asset::from(expected_asset);
    assert!(full_note.assets().iter().any(|asset| asset == &expected_asset_obj));

    // Verify the note was created by the faucet
    assert_eq!(full_note.metadata().sender(), faucet.id());

    // Verify the note inputs commitment matches the expected commitment
    assert_eq!(
        full_note.recipient().inputs().commitment(),
        note_inputs.commitment(),
        "Output note inputs commitment should match expected inputs commitment"
    );
    assert_eq!(
        full_note.recipient().inputs().num_values(),
        note_inputs.num_values(),
        "Output note inputs length should match expected inputs length"
    );

    // Verify the output note ID matches the expected note ID
    assert_eq!(full_note.id(), expected_note.id());

    // Verify nonce was incremented
    assert_eq!(executed_transaction.account_delta().nonce_delta(), Felt::new(1));

    Ok(())
}

// TESTS NETWORK FAUCET
// ================================================================================================

/// Tests minting on network faucet
#[tokio::test]
async fn network_faucet_mint() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let faucet_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet =
        builder.add_existing_network_faucet("NET", 1000, faucet_owner_account_id, Some(50))?;

    // Create a target account to consume the minted note
    let mut target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    // The Network Fungible Faucet component is added as the second component after auth, so its
    // storage slot offset will be 2. Check that max_supply at the word's index 0 is 200.
    assert_eq!(
        faucet.storage().get_item(NetworkFungibleFaucet::metadata_slot()).unwrap()[0],
        Felt::new(1000)
    );

    // Check that the creator account ID is stored in slot 2 (second storage slot of the component)
    // The owner_account_id is stored as Word [0, 0, suffix, prefix]
    let stored_owner_id =
        faucet.storage().get_item(NetworkFungibleFaucet::owner_config_slot()).unwrap();
    assert_eq!(stored_owner_id[3], faucet_owner_account_id.prefix().as_felt());
    assert_eq!(
        stored_owner_id[2],
        Felt::new(faucet_owner_account_id.suffix().as_canonical_u64())
    );

    // Check that the faucet reserved slot has been correctly initialized.
    // The already issued amount should be 50.
    assert_eq!(faucet.get_token_issuance().unwrap(), Felt::new(50));

    // CREATE MINT NOTE USING STANDARD NOTE
    // --------------------------------------------------------------------------------------------

    let amount = Felt::new(75);
    let mint_asset: Asset =
        FungibleAsset::new(faucet.id(), amount.as_canonical_u64()).unwrap().into();
    let aux = Felt::new(27);
    let serial_num = Word::default();

    let output_note_tag = NoteTag::from_account_id(target_account.id());
    let p2id_mint_output_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset],
        NoteType::Private,
        aux,
        serial_num,
    )
    .unwrap();
    let recipient = p2id_mint_output_note.recipient().digest();

    // Create the MINT note using the helper function
    let mint_inputs = MintNoteInputs::new_private(
        recipient,
        amount,
        output_note_tag.into(),
        NoteExecutionHint::always(),
        aux,
    );

    let mut rng = RpoRandomCoin::new([Felt::new(42); 4].into());
    let mint_note =
        create_mint_note(faucet.id(), faucet_owner_account_id, mint_inputs, aux, &mut rng)?;

    // Add the MINT note to the mock chain
    builder.add_output_note(OutputNote::Full(mint_note.clone()));
    let mut mock_chain = builder.build()?;

    // EXECUTE MINT NOTE AGAINST NETWORK FAUCET
    // --------------------------------------------------------------------------------------------
    let tx_context = mock_chain.build_tx_context(faucet.id(), &[mint_note.id()], &[])?.build()?;
    let executed_transaction = tx_context.execute().await?;

    // Check that a P2ID note was created by the faucet
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    // Verify the output note contains the minted fungible asset
    let expected_asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())?;
    let assets = NoteAssets::new(vec![expected_asset.into()])?;
    let expected_note_id = NoteId::new(recipient, assets.commitment());

    assert_eq!(output_note.id(), expected_note_id);
    assert_eq!(output_note.metadata().sender(), faucet.id());

    // Apply the transaction to the mock chain
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // CONSUME THE OUTPUT NOTE WITH TARGET ACCOUNT
    // --------------------------------------------------------------------------------------------
    // Execute transaction to consume the output note with the target account
    let consume_tx_context = mock_chain
        .build_tx_context(target_account.id(), &[], slice::from_ref(&p2id_mint_output_note))?
        .build()?;
    let consume_executed_transaction = consume_tx_context.execute().await?;

    // Apply the delta to the target account and verify the asset was added to the account's vault
    target_account.apply_delta(consume_executed_transaction.account_delta())?;

    // Verify the account's vault now contains the expected fungible asset
    let balance = target_account.vault().get_balance(faucet.id())?;
    assert_eq!(balance, expected_asset.amount(),);

    Ok(())
}

// TESTS FOR FAUCET PROCEDURE COMPATIBILITY
// ================================================================================================

/// Tests that basic and network fungible faucets have the same burn procedure digest.
/// This is required for BURN notes to work with both faucet types.
#[test]
fn test_faucet_burn_procedures_are_identical() {
    // Both faucet types must export the same burn procedure with identical MAST roots
    // so that a single BURN note script can work with either faucet type
    assert_eq!(
        BasicFungibleFaucet::burn_digest(),
        NetworkFungibleFaucet::burn_digest(),
        "Basic and network fungible faucets must have the same burn procedure digest"
    );
}

/// Tests burning on network faucet
#[tokio::test]
async fn network_faucet_burn() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let faucet_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let mut faucet =
        builder.add_existing_network_faucet("NET", 200, faucet_owner_account_id, Some(100))?;

    let burn_amount = 100u64;
    let fungible_asset = FungibleAsset::new(faucet.id(), burn_amount).unwrap();

    // CREATE BURN NOTE
    // --------------------------------------------------------------------------------------------
    let mut rng = RpoRandomCoin::new([Felt::new(99); 4].into());
    let note = create_burn_note(
        faucet_owner_account_id,
        faucet.id(),
        fungible_asset.into(),
        Felt::new(0),
        &mut rng,
    )?;

    builder.add_output_note(OutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Check the initial token issuance before burning
    let initial_issuance = faucet.get_token_issuance().unwrap();
    assert_eq!(initial_issuance, Felt::new(100));

    // EXECUTE BURN NOTE AGAINST NETWORK FAUCET
    // --------------------------------------------------------------------------------------------
    let tx_context = mock_chain.build_tx_context(faucet.id(), &[note.id()], &[])?.build()?;
    let executed_transaction = tx_context.execute().await?;

    // Check that the burn was successful - no output notes should be created for burn
    assert_eq!(executed_transaction.output_notes().num_notes(), 0);

    // Verify the transaction was executed successfully
    assert_eq!(executed_transaction.account_delta().nonce_delta(), Felt::new(1));
    assert_eq!(executed_transaction.input_notes().get_note(0).id(), note.id());

    // Apply the delta to the faucet account and verify the token issuance decreased
    faucet.apply_delta(executed_transaction.account_delta())?;
    let final_issuance = faucet.get_token_issuance().unwrap();
    assert_eq!(final_issuance, Felt::new(initial_issuance.as_canonical_u64() - burn_amount));

    Ok(())
}

// TESTS FOR MINT NOTE WITH PRIVATE AND PUBLIC OUTPUT MODES
// ================================================================================================

/// Tests creating a MINT note with different output note types (private/public)
/// The MINT note can create output notes with variable-length inputs for public notes.
#[rstest::rstest]
#[case::private(NoteType::Private)]
#[case::public(NoteType::Public)]
#[tokio::test]
async fn test_mint_note_output_note_types(#[case] note_type: NoteType) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let faucet_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet =
        builder.add_existing_network_faucet("NET", 1000, faucet_owner_account_id, Some(50))?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let amount = Felt::new(75);
    let mint_asset: Asset =
        FungibleAsset::new(faucet.id(), amount.as_canonical_u64()).unwrap().into();
    let aux = Felt::new(27);
    let serial_num = Word::from([1, 2, 3, 4u32]);

    // Create the expected P2ID output note
    let p2id_mint_output_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset],
        note_type,
        aux,
        serial_num,
    )
    .unwrap();

    // Create MINT note based on note type
    let mint_inputs = match note_type {
        NoteType::Private => {
            let output_note_tag = NoteTag::from_account_id(target_account.id());
            let recipient = p2id_mint_output_note.recipient().digest();
            MintNoteInputs::new_private(
                recipient,
                amount,
                output_note_tag.into(),
                NoteExecutionHint::always(),
                aux,
            )
        },
        NoteType::Public => {
            let output_note_tag = NoteTag::from_account_id(target_account.id());
            let p2id_script = WellKnownNote::P2ID.script();
            let p2id_inputs =
                vec![target_account.id().suffix(), target_account.id().prefix().as_felt()];
            let note_inputs = NoteInputs::new(p2id_inputs)?;
            let recipient = NoteRecipient::new(serial_num, p2id_script, note_inputs);
            MintNoteInputs::new_public(
                recipient,
                amount,
                output_note_tag.into(),
                NoteExecutionHint::always(),
                aux,
            )?
        },
        NoteType::Encrypted => unreachable!("Encrypted note type not used in this test"),
    };

    let mut rng = RpoRandomCoin::new([Felt::new(42); 4].into());
    let mint_note =
        create_mint_note(faucet.id(), faucet_owner_account_id, mint_inputs.clone(), aux, &mut rng)?;

    builder.add_output_note(OutputNote::Full(mint_note.clone()));
    let mut mock_chain = builder.build()?;

    let mut tx_context_builder =
        mock_chain.build_tx_context(faucet.id(), &[mint_note.id()], &[])?;

    if note_type == NoteType::Public {
        let p2id_script = WellKnownNote::P2ID.script();
        tx_context_builder = tx_context_builder.add_note_script(p2id_script);
    }

    let tx_context = tx_context_builder.build()?;
    let executed_transaction = tx_context.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    match note_type {
        NoteType::Private => {
            // For private notes, we can only compare basic properties since we get
            // OutputNote::Partial
            assert_eq!(output_note.id(), p2id_mint_output_note.id());
            assert_eq!(output_note.metadata().sender(), p2id_mint_output_note.metadata().sender());
            assert_eq!(
                output_note.metadata().note_type(),
                p2id_mint_output_note.metadata().note_type()
            );
            assert_eq!(output_note.metadata().aux(), p2id_mint_output_note.metadata().aux());
        },
        NoteType::Public => {
            // For public notes, we get OutputNote::Full and can compare key properties
            let created_note = match output_note {
                OutputNote::Full(note) => note,
                _ => panic!("Expected OutputNote::Full variant for public note"),
            };

            assert_eq!(created_note, &p2id_mint_output_note);
        },
        NoteType::Encrypted => unreachable!("Encrypted note type not used in this test"),
    }

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // Consume the output note with target account
    let mut target_account_mut = target_account.clone();
    let consume_tx_context = mock_chain
        .build_tx_context(target_account.id(), &[], slice::from_ref(&p2id_mint_output_note))?
        .build()?;
    let consume_executed_transaction = consume_tx_context.execute().await?;

    target_account_mut.apply_delta(consume_executed_transaction.account_delta())?;

    let expected_asset = FungibleAsset::new(faucet.id(), amount.as_canonical_u64())?;
    let balance = target_account_mut.vault().get_balance(faucet.id())?;
    assert_eq!(balance, expected_asset.amount());

    Ok(())
}
