extern crate alloc;

use alloc::sync::Arc;
use core::slice;

use miden_processor::crypto::RpoRandomCoin;
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
    NoteAttachment,
    NoteId,
    NoteMetadata,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use miden_protocol::transaction::{ExecutedTransaction, OutputNote};
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::{BasicFungibleFaucet, NetworkFungibleFaucet};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FAUCET_BURN_AMOUNT_EXCEEDS_TOKEN_SUPPLY,
    ERR_FUNGIBLE_ASSET_DISTRIBUTE_AMOUNT_EXCEEDS_MAX_SUPPLY,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::note::{BurnNote, MintNote, MintNoteStorage, StandardNote};
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
    pub note_type: NoteType,
    pub amount: Felt,
}

/// Creates minting script code for fungible asset distribution
pub fn create_mint_script_code(params: &FaucetTestParams) -> String {
    format!(
        "
            begin
                # pad the stack before call
                padw padw push.0

                push.{recipient}
                push.{note_type}
                push.{tag}
                push.{amount}
                # => [amount, tag, note_type, RECIPIENT, pad(9)]

                call.::miden::standards::faucets::basic_fungible::distribute
                # => [note_idx, pad(15)]

                # truncate the stack
                dropw dropw dropw dropw
            end
            ",
        note_type = params.note_type as u8,
        recipient = params.recipient,
        tag = u32::from(params.tag),
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
    let fungible_asset: Asset = FungibleAsset::new(faucet.id(), params.amount.into())?.into();

    let output_note = executed_transaction.output_notes().get_note(0).clone();
    let assets = NoteAssets::new(vec![fungible_asset])?;
    let id = NoteId::new(params.recipient, assets.commitment());

    assert_eq!(output_note.id(), id);
    assert_eq!(
        output_note.metadata(),
        &NoteMetadata::new(faucet.id(), params.note_type, params.tag)
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
        tag: NoteTag::default(),
        note_type: NoteType::Private,
        amount: Felt::new(100),
    };

    let executed_transaction =
        execute_mint_transaction(&mut mock_chain, faucet.clone(), &params).await?;
    verify_minted_output_note(&executed_transaction, &faucet, &params)?;

    Ok(())
}

/// Tests that distribute fails when the minted amount would exceed the max supply.
#[tokio::test]
async fn faucet_contract_mint_fungible_asset_fails_exceeds_max_supply() -> anyhow::Result<()> {
    // CONSTRUCT AND EXECUTE TX (Failure)
    // --------------------------------------------------------------------------------------------
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(Auth::BasicAuth, "TST", 200, None)?;
    let mock_chain = builder.build()?;

    let recipient = Word::from([0, 1, 2, 3u32]);
    let tag = Felt::new(4);
    let amount = Felt::new(250);

    let tx_script_code = format!(
        "
            begin
                # pad the stack before call
                padw padw push.0

                push.{recipient}
                push.{note_type}
                push.{tag}
                push.{amount}
                # => [amount, tag, note_type, RECIPIENT, pad(9)]

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

    assert_transaction_executor_error!(tx, ERR_FUNGIBLE_ASSET_DISTRIBUTE_AMOUNT_EXCEEDS_MAX_SUPPLY);
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
        tag: NoteTag::default(),
        note_type: NoteType::Private,
        amount: Felt::new(100),
    };

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
    let max_supply = 200u32;
    let token_supply = 100u32;

    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth,
        "TST",
        max_supply.into(),
        Some(token_supply.into()),
    )?;

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

    let basic_faucet = BasicFungibleFaucet::try_from(&faucet)?;

    // Check that max_supply at the word's index 0 is 200. The remainder of the word is initialized
    // with the metadata of the faucet which we don't need to check.
    assert_eq!(basic_faucet.max_supply(), Felt::from(max_supply));

    // Check that the faucet's token supply has been correctly initialized.
    // The already issued amount should be 100.
    assert_eq!(basic_faucet.token_supply(), Felt::from(token_supply));

    // CONSTRUCT AND EXECUTE TX (Success)
    // --------------------------------------------------------------------------------------------
    // Execute the transaction and get the witness
    let executed_transaction = mock_chain
        .build_tx_context(faucet.id(), &[note.id()], &[])?
        .build()?
        .execute()
        .await?;

    // Prove, serialize/deserialize and verify the transaction
    prove_and_verify_transaction(executed_transaction.clone())?;

    assert_eq!(executed_transaction.account_delta().nonce_delta(), Felt::new(1));
    assert_eq!(executed_transaction.input_notes().get_note(0).id(), note.id());
    Ok(())
}

/// Tests that burning a fungible asset fails when the amount exceeds the token supply.
#[tokio::test]
async fn faucet_burn_fungible_asset_fails_amount_exceeds_token_supply() -> anyhow::Result<()> {
    let max_supply = 200u32;
    let token_supply = 50u32;

    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth,
        "TST",
        max_supply.into(),
        Some(token_supply.into()),
    )?;

    // Try to burn 100 tokens when only 50 have been issued
    let burn_amount = 100u64;
    let fungible_asset = FungibleAsset::new(faucet.id(), burn_amount).unwrap();

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

    let tx = mock_chain
        .build_tx_context(faucet.id(), &[note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(tx, ERR_FAUCET_BURN_AMOUNT_EXCEEDS_TOKEN_SUPPLY);
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
    let tag = NoteTag::default();
    let note_type = NoteType::Public;

    // Create a simple output note script
    let output_note_script_code = "begin push.1 drop end";
    let source_manager = Arc::new(DefaultSourceManager::default());
    let output_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(output_note_script_code)?;

    let serial_num = Word::default();
    let target_account_suffix = recipient_account_id.suffix();
    let target_account_prefix = recipient_account_id.prefix().as_felt();

    // Use a length that is not a multiple of 8 (double word size) to make sure note storage padding
    // is correctly handled
    let note_storage = NoteStorage::new(vec![
        target_account_suffix,
        target_account_prefix,
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(1),
        Felt::new(0),
    ])?;

    let note_recipient =
        NoteRecipient::new(serial_num, output_note_script.clone(), note_storage.clone());

    let output_script_root = note_recipient.script().root();

    let asset = FungibleAsset::new(faucet.id(), amount.into())?;
    let metadata = NoteMetadata::new(faucet.id(), note_type, tag);
    let expected_note = Note::new(NoteAssets::new(vec![asset.into()])?, metadata, note_recipient);

    let trigger_note_script_code = format!(
        "
            use miden::protocol::note
            
            begin
                # Build recipient hash from SERIAL_NUM, SCRIPT_ROOT, and STORAGE_COMMITMENT
                push.{script_root}
                # => [SCRIPT_ROOT]

                push.{serial_num}
                # => [SERIAL_NUM, SCRIPT_ROOT]

                # Store note storage in memory
                push.{input0} mem_store.0
                push.{input1} mem_store.1
                push.{input2} mem_store.2
                push.{input3} mem_store.3
                push.{input4} mem_store.4
                push.{input5} mem_store.5
                push.{input6} mem_store.6

                push.7 push.0
                # => [storage_ptr, num_storage_items = 7, SERIAL_NUM, SCRIPT_ROOT]

                exec.note::build_recipient
                # => [RECIPIENT]

                # Now call distribute with the computed recipient
                push.{note_type}
                push.{tag}
                push.{amount}
                # => [amount, tag, note_type, RECIPIENT]

                call.::miden::standards::faucets::basic_fungible::distribute
                # => [note_idx, pad(15)]

                # Truncate the stack
                dropw dropw dropw dropw
            end
            ",
        note_type = note_type as u8,
        input0 = note_storage.items()[0],
        input1 = note_storage.items()[1],
        input2 = note_storage.items()[2],
        input3 = note_storage.items()[3],
        input4 = note_storage.items()[4],
        input5 = note_storage.items()[5],
        input6 = note_storage.items()[6],
        script_root = output_script_root,
        serial_num = serial_num,
        tag = u32::from(tag),
        amount = amount,
    );

    // Create the trigger note that will call distribute
    let mut rng = RpoRandomCoin::new([Felt::from(1u32); 4].into());
    let trigger_note = NoteBuilder::new(faucet.id(), &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
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
    let expected_asset = FungibleAsset::new(faucet.id(), amount.into())?;
    let expected_asset_obj = Asset::from(expected_asset);
    assert!(full_note.assets().iter().any(|asset| asset == &expected_asset_obj));

    // Verify the note was created by the faucet
    assert_eq!(full_note.metadata().sender(), faucet.id());

    // Verify the note storage commitment matches the expected commitment
    assert_eq!(
        full_note.recipient().storage().commitment(),
        note_storage.commitment(),
        "Output note storage commitment should match expected storage commitment"
    );
    assert_eq!(
        full_note.recipient().storage().num_items(),
        note_storage.num_items(),
        "Output note number of storage items should match expected number of storage items"
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
    let max_supply = 1000u64;
    let token_supply = 50u64;

    let mut builder = MockChain::builder();

    let faucet_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet(
        "NET",
        max_supply,
        faucet_owner_account_id,
        Some(token_supply),
    )?;

    // Create a target account to consume the minted note
    let mut target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    // Check the Network Fungible Faucet's max supply.
    let actual_max_supply = NetworkFungibleFaucet::try_from(&faucet)?.max_supply();
    assert_eq!(actual_max_supply.as_int(), max_supply);

    // Check that the creator account ID is stored in slot 2 (second storage slot of the component)
    // The owner_account_id is stored as Word [0, 0, suffix, prefix]
    let stored_owner_id =
        faucet.storage().get_item(NetworkFungibleFaucet::owner_config_slot()).unwrap();
    assert_eq!(stored_owner_id[3], faucet_owner_account_id.prefix().as_felt());
    assert_eq!(stored_owner_id[2], Felt::new(faucet_owner_account_id.suffix().as_int()));

    // Check that the faucet's token supply has been correctly initialized.
    // The already issued amount should be 50.
    let initial_token_supply = NetworkFungibleFaucet::try_from(&faucet)?.token_supply();
    assert_eq!(initial_token_supply.as_int(), token_supply);

    // CREATE MINT NOTE USING STANDARD NOTE
    // --------------------------------------------------------------------------------------------

    let amount = Felt::new(75);
    let mint_asset: Asset = FungibleAsset::new(faucet.id(), amount.into()).unwrap().into();
    let serial_num = Word::default();

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_mint_output_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset],
        NoteType::Private,
        serial_num,
    )
    .unwrap();
    let recipient = p2id_mint_output_note.recipient().digest();

    // Create the MINT note using the helper function
    let mint_storage = MintNoteStorage::new_private(recipient, amount, output_note_tag.into());

    let mut rng = RpoRandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = MintNote::create(
        faucet.id(),
        faucet_owner_account_id,
        mint_storage,
        NoteAttachment::default(),
        &mut rng,
    )?;

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
    let expected_asset = FungibleAsset::new(faucet.id(), amount.into())?;
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

// TESTS FOR NETWORK FAUCET OWNERSHIP
// ================================================================================================

/// Tests that the owner can mint assets on network faucet.
#[tokio::test]
async fn test_network_faucet_owner_can_mint() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet("NET", 1000, owner_account_id, Some(50))?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    let amount = Felt::new(75);
    let mint_asset: Asset = FungibleAsset::new(faucet.id(), amount.into())?.into();

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset],
        NoteType::Private,
        Word::default(),
    )?;
    let recipient = p2id_note.recipient().digest();

    let mint_inputs = MintNoteStorage::new_private(recipient, amount, output_note_tag.into());

    let mut rng = RpoRandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = MintNote::create(
        faucet.id(),
        owner_account_id,
        mint_inputs,
        NoteAttachment::default(),
        &mut rng,
    )?;

    let tx_context = mock_chain.build_tx_context(faucet.id(), &[], &[mint_note])?.build()?;
    let executed_transaction = tx_context.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 1);

    Ok(())
}

/// Tests that a non-owner cannot mint assets on network faucet.
#[tokio::test]
async fn test_network_faucet_non_owner_cannot_mint() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let non_owner_account_id = AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet("NET", 1000, owner_account_id, Some(50))?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    let amount = Felt::new(75);
    let mint_asset: Asset = FungibleAsset::new(faucet.id(), amount.into())?.into();

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset],
        NoteType::Private,
        Word::default(),
    )?;
    let recipient = p2id_note.recipient().digest();

    let mint_inputs = MintNoteStorage::new_private(recipient, amount, output_note_tag.into());

    // Create mint note from NON-OWNER
    let mut rng = RpoRandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = MintNote::create(
        faucet.id(),
        non_owner_account_id,
        mint_inputs,
        NoteAttachment::default(),
        &mut rng,
    )?;

    let tx_context = mock_chain.build_tx_context(faucet.id(), &[], &[mint_note])?.build()?;
    let result = tx_context.execute().await;

    // The distribute function uses ERR_ONLY_OWNER, which is "note sender is not the owner"
    let expected_error = ERR_SENDER_NOT_OWNER;
    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// Tests that the owner is correctly stored and can be read from storage.
#[tokio::test]
async fn test_network_faucet_owner_storage() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet("NET", 1000, owner_account_id, Some(50))?;
    let _mock_chain = builder.build()?;

    // Verify owner is stored correctly
    let stored_owner = faucet.storage().get_item(NetworkFungibleFaucet::owner_config_slot())?;

    // Storage format: [0, 0, suffix, prefix]
    assert_eq!(stored_owner[3], owner_account_id.prefix().as_felt());
    assert_eq!(stored_owner[2], Felt::new(owner_account_id.suffix().as_int()));
    assert_eq!(stored_owner[1], Felt::new(0));
    assert_eq!(stored_owner[0], Felt::new(0));

    Ok(())
}

/// Tests that transfer_ownership updates the owner correctly.
#[tokio::test]
async fn test_network_faucet_transfer_ownership() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Setup: Create initial owner and new owner accounts
    let initial_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let new_owner_account_id = AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet =
        builder.add_existing_network_faucet("NET", 1000, initial_owner_account_id, Some(50))?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let amount = Felt::new(75);
    let mint_asset: Asset = FungibleAsset::new(faucet.id(), amount.into())?.into();

    let output_note_tag = NoteTag::with_account_target(target_account.id());
    let p2id_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset],
        NoteType::Private,
        Word::default(),
    )?;
    let recipient = p2id_note.recipient().digest();

    // Sanity Check: Prove that the initial owner can mint assets
    let mint_inputs = MintNoteStorage::new_private(recipient, amount, output_note_tag.into());

    let mut rng = RpoRandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = MintNote::create(
        faucet.id(),
        initial_owner_account_id,
        mint_inputs.clone(),
        NoteAttachment::default(),
        &mut rng,
    )?;

    // Action: Create transfer_ownership note script
    let transfer_note_script_code = format!(
        r#"
        use miden::standards::faucets::network_fungible->network_faucet

        begin
            repeat.14 push.0 end
            push.{new_owner_suffix}
            push.{new_owner_prefix}
            call.network_faucet::transfer_ownership
            dropw dropw dropw dropw
        end
        "#,
        new_owner_prefix = new_owner_account_id.prefix().as_felt(),
        new_owner_suffix = Felt::new(new_owner_account_id.suffix().as_int()),
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let transfer_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(transfer_note_script_code.clone())?;

    // Create the transfer note and add it to the builder so it exists on-chain
    let mut rng = RpoRandomCoin::new([Felt::from(200u32); 4].into());
    let transfer_note = NoteBuilder::new(initial_owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([11, 22, 33, 44u32]))
        .code(transfer_note_script_code.clone())
        .build()?;

    // Add the transfer note to the builder before building the chain
    builder.add_output_note(OutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;

    // Prove the block to make the transfer note exist on-chain
    mock_chain.prove_next_block()?;

    // Sanity Check: Execute mint transaction to verify initial owner can mint
    let tx_context = mock_chain.build_tx_context(faucet.id(), &[], &[mint_note])?.build()?;
    let executed_transaction = tx_context.execute().await?;
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);

    // Action: Execute transfer_ownership via note script
    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[transfer_note.id()], &[])?
        .add_note_script(transfer_note_script.clone())
        .with_source_manager(source_manager.clone())
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    // Persistence: Apply the transaction to update the faucet state
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // Apply the delta to the faucet account to reflect the ownership change
    let mut updated_faucet = faucet.clone();
    updated_faucet.apply_delta(executed_transaction.account_delta())?;

    // Validation 1: Try to mint using the old owner - should fail
    let mut rng = RpoRandomCoin::new([Felt::from(300u32); 4].into());
    let mint_note_old_owner = MintNote::create(
        updated_faucet.id(),
        initial_owner_account_id,
        mint_inputs.clone(),
        NoteAttachment::default(),
        &mut rng,
    )?;

    // Use the note as an unauthenticated note (full note object) - it will be created in this
    // transaction
    let tx_context = mock_chain
        .build_tx_context(updated_faucet.id(), &[], &[mint_note_old_owner])?
        .build()?;
    let result = tx_context.execute().await;

    // The distribute function uses ERR_ONLY_OWNER, which is "note sender is not the owner"
    let expected_error = ERR_SENDER_NOT_OWNER;
    assert_transaction_executor_error!(result, expected_error);

    // Validation 2: Try to mint using the new owner - should succeed
    let mut rng = RpoRandomCoin::new([Felt::from(400u32); 4].into());
    let mint_note_new_owner = MintNote::create(
        updated_faucet.id(),
        new_owner_account_id,
        mint_inputs,
        NoteAttachment::default(),
        &mut rng,
    )?;

    let tx_context = mock_chain
        .build_tx_context(updated_faucet.id(), &[], &[mint_note_new_owner])?
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    // Verify that minting succeeded
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);

    Ok(())
}

/// Tests that only the owner can transfer ownership.
#[tokio::test]
async fn test_network_faucet_only_owner_can_transfer() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let non_owner_account_id = AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let new_owner_account_id = AccountId::dummy(
        [3; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet("NET", 1000, owner_account_id, Some(50))?;
    let mock_chain = builder.build()?;

    // Create transfer ownership note script
    let transfer_note_script_code = format!(
        r#"
        use miden::standards::faucets::network_fungible->network_faucet

        begin
            repeat.14 push.0 end
            push.{new_owner_suffix}
            push.{new_owner_prefix}
            call.network_faucet::transfer_ownership
            dropw dropw dropw dropw
        end
        "#,
        new_owner_prefix = new_owner_account_id.prefix().as_felt(),
        new_owner_suffix = Felt::new(new_owner_account_id.suffix().as_int()),
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let transfer_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(transfer_note_script_code.clone())?;

    // Create a note from NON-OWNER that tries to transfer ownership
    let mut rng = RpoRandomCoin::new([Felt::from(100u32); 4].into());
    let transfer_note = NoteBuilder::new(non_owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([10, 20, 30, 40u32]))
        .code(transfer_note_script_code.clone())
        .build()?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[transfer_note])?
        .add_note_script(transfer_note_script.clone())
        .with_source_manager(source_manager.clone())
        .build()?;
    let result = tx_context.execute().await;

    // Verify that the transaction failed with ERR_ONLY_OWNER
    let expected_error = ERR_SENDER_NOT_OWNER;
    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// Tests that renounce_ownership clears the owner correctly.
#[tokio::test]
async fn test_network_faucet_renounce_ownership() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let new_owner_account_id = AccountId::dummy(
        [2; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    let faucet = builder.add_existing_network_faucet("NET", 1000, owner_account_id, Some(50))?;

    // Check stored value before renouncing
    let stored_owner_before =
        faucet.storage().get_item(NetworkFungibleFaucet::owner_config_slot())?;
    assert_eq!(stored_owner_before[3], owner_account_id.prefix().as_felt());
    assert_eq!(stored_owner_before[2], Felt::new(owner_account_id.suffix().as_int()));

    // Create renounce_ownership note script
    let renounce_note_script_code = r#"
        use miden::standards::faucets::network_fungible->network_faucet

        begin
            repeat.16 push.0 end
            call.network_faucet::renounce_ownership
            dropw dropw dropw dropw
        end
        "#;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let renounce_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(renounce_note_script_code)?;

    // Create transfer note script (will be used after renounce)
    let transfer_note_script_code = format!(
        r#"
        use miden::standards::faucets::network_fungible->network_faucet

        begin
            repeat.14 push.0 end
            push.{new_owner_suffix}
            push.{new_owner_prefix}
            call.network_faucet::transfer_ownership
            dropw dropw dropw dropw
        end
        "#,
        new_owner_prefix = new_owner_account_id.prefix().as_felt(),
        new_owner_suffix = Felt::new(new_owner_account_id.suffix().as_int()),
    );

    let transfer_note_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_note_script(transfer_note_script_code.clone())?;

    let mut rng = RpoRandomCoin::new([Felt::from(200u32); 4].into());
    let renounce_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([11, 22, 33, 44u32]))
        .code(renounce_note_script_code)
        .build()?;

    let mut rng = RpoRandomCoin::new([Felt::from(300u32); 4].into());
    let transfer_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .tag(NoteTag::default().into())
        .serial_number(Word::from([50, 60, 70, 80u32]))
        .code(transfer_note_script_code.clone())
        .build()?;

    builder.add_output_note(OutputNote::Full(renounce_note.clone()));
    builder.add_output_note(OutputNote::Full(transfer_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Execute renounce_ownership
    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[renounce_note.id()], &[])?
        .add_note_script(renounce_note_script.clone())
        .with_source_manager(source_manager.clone())
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    let mut updated_faucet = faucet.clone();
    updated_faucet.apply_delta(executed_transaction.account_delta())?;

    // Check stored value after renouncing - should be zero
    let stored_owner_after =
        updated_faucet.storage().get_item(NetworkFungibleFaucet::owner_config_slot())?;
    assert_eq!(stored_owner_after[0], Felt::new(0));
    assert_eq!(stored_owner_after[1], Felt::new(0));
    assert_eq!(stored_owner_after[2], Felt::new(0));
    assert_eq!(stored_owner_after[3], Felt::new(0));

    // Try to transfer ownership - should fail because there's no owner
    // The transfer note was already added to the builder, so we need to prove another block
    // to make it available on-chain after the renounce transaction
    mock_chain.prove_next_block()?;

    let tx_context = mock_chain
        .build_tx_context(updated_faucet.id(), &[transfer_note.id()], &[])?
        .add_note_script(transfer_note_script.clone())
        .with_source_manager(source_manager.clone())
        .build()?;
    let result = tx_context.execute().await;

    let expected_error = ERR_SENDER_NOT_OWNER;
    assert_transaction_executor_error!(result, expected_error);

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
    let mut rng = RpoRandomCoin::new([Felt::from(99u32); 4].into());
    let note = BurnNote::create(
        faucet_owner_account_id,
        faucet.id(),
        fungible_asset.into(),
        NoteAttachment::default(),
        &mut rng,
    )?;

    builder.add_output_note(OutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Check the initial token issuance before burning
    let initial_token_supply = NetworkFungibleFaucet::try_from(&faucet)?.token_supply();
    assert_eq!(initial_token_supply, Felt::new(100));

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
    let final_token_supply = NetworkFungibleFaucet::try_from(&faucet)?.token_supply();
    assert_eq!(final_token_supply, Felt::new(initial_token_supply.as_int() - burn_amount));

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
    let mint_asset: Asset = FungibleAsset::new(faucet.id(), amount.into()).unwrap().into();
    let serial_num = Word::from([1, 2, 3, 4u32]);

    // Create the expected P2ID output note
    let p2id_mint_output_note = create_p2id_note_exact(
        faucet.id(),
        target_account.id(),
        vec![mint_asset],
        note_type,
        serial_num,
    )
    .unwrap();

    // Create MINT note based on note type
    let mint_storage = match note_type {
        NoteType::Private => {
            let output_note_tag = NoteTag::with_account_target(target_account.id());
            let recipient = p2id_mint_output_note.recipient().digest();
            MintNoteStorage::new_private(recipient, amount, output_note_tag.into())
        },
        NoteType::Public => {
            let output_note_tag = NoteTag::with_account_target(target_account.id());
            let p2id_script = StandardNote::P2ID.script();
            let p2id_storage =
                vec![target_account.id().suffix(), target_account.id().prefix().as_felt()];
            let note_storage = NoteStorage::new(p2id_storage)?;
            let recipient = NoteRecipient::new(serial_num, p2id_script, note_storage);
            MintNoteStorage::new_public(recipient, amount, output_note_tag.into())?
        },
    };

    let mut rng = RpoRandomCoin::new([Felt::from(42u32); 4].into());
    let mint_note = MintNote::create(
        faucet.id(),
        faucet_owner_account_id,
        mint_storage.clone(),
        NoteAttachment::default(),
        &mut rng,
    )?;

    builder.add_output_note(OutputNote::Full(mint_note.clone()));
    let mut mock_chain = builder.build()?;

    let mut tx_context_builder =
        mock_chain.build_tx_context(faucet.id(), &[mint_note.id()], &[])?;

    if note_type == NoteType::Public {
        let p2id_script = StandardNote::P2ID.script();
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
            assert_eq!(output_note.metadata(), p2id_mint_output_note.metadata());
        },
        NoteType::Public => {
            // For public notes, we get OutputNote::Full and can compare key properties
            let created_note = match output_note {
                OutputNote::Full(note) => note,
                _ => panic!("Expected OutputNote::Full variant for public note"),
            };

            assert_eq!(created_note, &p2id_mint_output_note);
        },
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

    let expected_asset = FungibleAsset::new(faucet.id(), amount.into())?;
    let balance = target_account_mut.vault().get_balance(faucet.id())?;
    assert_eq!(balance, expected_asset.amount());

    Ok(())
}
