use miden_protocol::account::Account;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, AssetVault, FungibleAsset};
use miden_protocol::note::{Note, NoteRecipient, NoteStorage, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::TxFeeNote;
use miden_testing::{Auth, MockChain};

/// A TX_FEE note imposes no target restriction, so an account unrelated to the note can consume
/// it and claim its assets. We use two assets to test the loop inside the script.
#[tokio::test]
async fn tx_fee_note_consumable_by_any_account() -> anyhow::Result<()> {
    // Create assets
    let fungible_asset_1: Asset = FungibleAsset::mock(123);
    let fungible_asset_2: Asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?, 456)?.into();

    let mut builder = MockChain::builder();

    // Create accounts; the consumer is completely unrelated to the note
    let sender_account = builder.create_new_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let consumer_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Create the note
    let note =
        builder.add_tx_fee_note(sender_account.id(), &[fungible_asset_1, fungible_asset_2])?;

    assert_eq!(note.metadata().tag(), TxFeeNote::TAG);
    assert_eq!(note.metadata().note_type(), NoteType::Public);

    let mock_chain = builder.build()?;

    // CONSTRUCT AND EXECUTE TX (Success)
    // --------------------------------------------------------------------------------------------
    // Execute the transaction and get the witness
    let executed_transaction = mock_chain
        .build_transaction(consumer_account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;

    // vault delta
    let consumer_account_after: Account = Account::new_existing(
        consumer_account.id(),
        AssetVault::new(&[fungible_asset_1, fungible_asset_2]).unwrap(),
        consumer_account.storage().clone(),
        consumer_account.code().clone(),
        Felt::new_unchecked(2),
    );

    assert_eq!(
        executed_transaction.final_account().to_commitment(),
        consumer_account_after.to_commitment()
    );

    Ok(())
}

/// Tests the TX_FEE `create_output_note` MASM constructor procedure.
/// This test verifies that calling `tx_fee::create_output_note` from a transaction script
/// creates an output note with the same recipient as the Rust `TxFeeNote` implementation would
/// create, and that the MASM note tag constant matches [`TxFeeNote::TAG`].
#[tokio::test]
async fn test_tx_fee_create_output_note_constructor() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let sender_account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [FungibleAsset::mock(100)],
    )?;

    let mock_chain = builder.build()?;

    // Create a serial number for the note
    let serial_num = Word::from([1u32, 2u32, 3u32, 4u32]);

    // Build the expected recipient using the Rust implementation
    let expected_recipient =
        NoteRecipient::new(serial_num, TxFeeNote::script(), NoteStorage::default());

    // Build a transaction script that uses tx_fee::create_output_note to create a note
    let tx_script_src = format!(
        r#"
        use miden::standards::notes::tx_fee

        @transaction_script
        pub proc main
            # Push inputs for tx_fee::create_output_note
            push.{serial_num}
            # => [SERIAL_NUM]

            exec.tx_fee::create_output_note
            # => [note_idx]

            # Add an asset to the created note
            push.{ASSET_VALUE}
            push.{ASSET_ID}
            call.::miden::standards::wallets::basic::move_asset_to_note

            # Clean up stack
            dropw dropw dropw dropw
        end
        "#,
        serial_num = serial_num,
        ASSET_ID = FungibleAsset::mock(50).to_id_word(),
        ASSET_VALUE = FungibleAsset::mock(50).to_value_word(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(&tx_script_src)?;

    // Build expected output note
    let expected_output_note: Note = TxFeeNote::builder()
        .sender(sender_account.id())
        .asset(FungibleAsset::mock(50))
        .serial_number(serial_num)
        .build()?
        .into();

    let tx_context = mock_chain
        .build_transaction(sender_account.id())
        .expected_output_note(RawOutputNote::Full(expected_output_note))
        .tx_script(tx_script)
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify that one note was created
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);

    // Get the created note's recipient and verify it matches
    let output_note = executed_transaction.output_notes().get_note(0);
    let created_recipient = output_note.recipient().expect("output note should have recipient");

    // Verify the recipient matches what we expected
    assert_eq!(
        created_recipient.digest(),
        expected_recipient.digest(),
        "The recipient created by tx_fee::create_output_note should match the Rust TxFeeNote \
         implementation"
    );

    // Verify the MASM TX_FEE_NOTE_TAG constant matches the Rust TxFeeNote::TAG and the note
    // is public
    assert_eq!(output_note.metadata().tag(), TxFeeNote::TAG);
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);

    Ok(())
}
