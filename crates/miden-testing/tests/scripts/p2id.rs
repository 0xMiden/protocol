use miden_protocol::account::Account;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, AssetVault, FungibleAsset};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_TARGET_ACCOUNT;
use miden_standards::note::P2idNote;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use crate::prove_and_verify_transaction_complete;

/// We test the Pay to script with 2 assets to test the loop inside the script.
/// So we create a note containing two assets that can only be consumed by the target account.
#[tokio::test]
async fn p2id_script_multiple_assets() -> anyhow::Result<()> {
    // Create assets
    let fungible_asset_1: Asset = FungibleAsset::mock(123);
    let fungible_asset_2: Asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?, 456)?.into();

    let mut builder = MockChain::builder();

    // Create accounts
    let sender_account = builder.create_new_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let target_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let malicious_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Create the note
    let note = builder.add_p2id_note(
        sender_account.id(),
        target_account.id(),
        &[fungible_asset_1, fungible_asset_2],
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;

    // CONSTRUCT AND EXECUTE TX (Success)
    // --------------------------------------------------------------------------------------------
    // Execute the transaction and get the witness
    let executed_transaction = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;

    // vault delta
    let target_account_after: Account = Account::new_existing(
        target_account.id(),
        AssetVault::new(&[fungible_asset_1, fungible_asset_2]).unwrap(),
        target_account.storage().clone(),
        target_account.code().clone(),
        Felt::new_unchecked(2),
    );

    assert_eq!(
        executed_transaction.final_account().to_commitment(),
        target_account_after.to_commitment()
    );

    // CONSTRUCT AND EXECUTE TX (Failure)
    // --------------------------------------------------------------------------------------------
    // A "malicious" account tries to consume the note, we expect an error (not the correct target)

    // Execute the transaction and get the result
    let executed_transaction_2 = mock_chain
        .build_transaction(malicious_account.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    // Check that we got the expected result - TransactionExecutorError
    assert_transaction_executor_error!(
        executed_transaction_2,
        ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_TARGET_ACCOUNT
    );
    Ok(())
}

/// Consumes an existing note with a new account
#[tokio::test]
async fn prove_consume_note_with_new_account() -> anyhow::Result<()> {
    // Create assets
    let fungible_asset: Asset = FungibleAsset::mock(123);

    let mut builder = MockChain::builder();

    // Create accounts
    let sender_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let target_account = builder.create_new_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Create the note
    let note = builder.add_p2id_note(
        sender_account.id(),
        target_account.id(),
        &[fungible_asset],
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;

    // CONSTRUCT AND EXECUTE TX (Success)
    // --------------------------------------------------------------------------------------------

    // Execute the transaction and get the witness
    let executed_transaction = mock_chain
        .build_transaction(target_account.clone())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;

    // Apply delta to the target account to verify it is no longer new
    let target_account_after: Account = Account::new_existing(
        target_account.id(),
        AssetVault::new(&[fungible_asset]).unwrap(),
        target_account.storage().clone(),
        target_account.code().clone(),
        Felt::ONE,
    );

    assert_eq!(
        executed_transaction.final_account().to_commitment(),
        target_account_after.to_commitment()
    );
    prove_and_verify_transaction_complete(executed_transaction).await?;
    Ok(())
}

/// Consumes two existing notes (with an asset from a faucet for a combined total of 123 tokens)
/// with a basic account
#[tokio::test]
async fn prove_consume_multiple_notes() -> anyhow::Result<()> {
    let fungible_asset_1: Asset = FungibleAsset::mock(100);
    let fungible_asset_2: Asset = FungibleAsset::mock(23);

    let mut builder = MockChain::builder();
    let mut account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let note_1 = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into()?,
        account.id(),
        &[fungible_asset_1],
        NoteType::Private,
    )?;
    let note_2 = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into()?,
        account.id(),
        &[fungible_asset_2],
        NoteType::Private,
    )?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let mock_tx = mock_chain
        .build_transaction(account.id())
        .authenticated_input_notes([note_1.id(), note_2.id()])
        .build()?;

    let executed_transaction = mock_tx.execute().await?;

    account.apply_patch(executed_transaction.account_patch())?;
    let resulting_asset = account.vault().assets().next().unwrap();
    assert_eq!(resulting_asset.unwrap_fungible().amount().as_u64(), 123);

    prove_and_verify_transaction_complete(executed_transaction).await?;

    Ok(())
}

/// Consumes two existing notes and creates two other notes in the same transaction
#[tokio::test]
async fn test_create_consume_multiple_notes() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let mut account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [FungibleAsset::mock(20)],
    )?;

    let input_note_faucet_id = ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?;
    let input_note_asset_1: Asset = FungibleAsset::new(input_note_faucet_id, 11)?.into();

    let input_note_asset_2: Asset = FungibleAsset::new(input_note_faucet_id, 100)?.into();

    let input_note_1 = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into()?,
        account.id(),
        &[input_note_asset_1],
        NoteType::Private,
    )?;

    let input_note_2 = builder.add_p2id_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into()?,
        account.id(),
        &[input_note_asset_2],
        NoteType::Private,
    )?;

    let mock_chain = builder.build()?;

    let asset_1 = FungibleAsset::mock(10);
    let asset_2 = FungibleAsset::mock(5);

    let output_note_1: Note = P2idNote::builder()
        .sender(account.id())
        .target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2.try_into()?)
        .asset(asset_1)
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::from([1, 2, 3, 4u32])))
        .build()?
        .into();

    let output_note_2: Note = P2idNote::builder()
        .sender(account.id())
        .target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into()?)
        .asset(asset_2)
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::from([4, 3, 2, 1u32])))
        .build()?
        .into();

    let tx_script_src = &format!(
        "
            use miden::protocol::output_note
            @transaction_script
            pub proc main
                push.{recipient_1}
                push.{note_type_1}
                push.{tag_1}
                call.::miden::standards::note::note_creator::create_note
                movdn.15 dropw dropw dropw drop drop drop

                push.{ASSET_VALUE_1}
                push.{ASSET_ID_1}
                call.::miden::standards::wallets::basic::move_asset_to_note
                dropw dropw dropw dropw

                push.{recipient_2}
                push.{note_type_2}
                push.{tag_2}
                call.::miden::standards::note::note_creator::create_note
                movdn.15 dropw dropw dropw drop drop drop

                push.{ASSET_VALUE_2}
                push.{ASSET_ID_2}
                call.::miden::standards::wallets::basic::move_asset_to_note
                dropw dropw dropw dropw
            end
            ",
        recipient_1 = output_note_1.recipient().digest(),
        note_type_1 = NoteType::Public as u8,
        tag_1 = Felt::from(output_note_1.metadata().tag()),
        ASSET_ID_1 = asset_1.to_id_word(),
        ASSET_VALUE_1 = asset_1.to_value_word(),
        recipient_2 = output_note_2.recipient().digest(),
        note_type_2 = NoteType::Public as u8,
        tag_2 = Felt::from(output_note_2.metadata().tag()),
        ASSET_ID_2 = asset_2.to_id_word(),
        ASSET_VALUE_2 = asset_2.to_value_word(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_src)?;

    let mock_tx = mock_chain
        .build_transaction(account.id())
        .authenticated_input_notes([input_note_1.id(), input_note_2.id()])
        .expected_output_notes(vec![
            RawOutputNote::Full(output_note_1),
            RawOutputNote::Full(output_note_2),
        ])
        .tx_script(tx_script)
        .build()?;

    let executed_transaction = mock_tx.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 2);

    account.apply_patch(executed_transaction.account_patch())?;

    assert_eq!(account.vault().get_balance(input_note_asset_1.id())?.as_u64(), 111);
    assert_eq!(account.vault().get_balance(asset_1.id())?.as_u64(), 5);

    Ok(())
}

/// The MASM constructors must agree with Rust on storage, recipient, and output-note metadata.
#[rstest::rstest]
#[case::create("create_output_note", None)]
#[case::create_zero_salt("create_output_note_with_salt", Some([Felt::ZERO; 2]))]
#[case::create_salted("create_output_note_with_salt", Some([Felt::ONE, Felt::from(2u32)]))]
#[case::prepare("prepare_note", None)]
#[case::prepare_zero_salt("prepare_note_with_salt", Some([Felt::ZERO; 2]))]
#[case::prepare_salted("prepare_note_with_salt", Some([Felt::ONE, Felt::from(2u32)]))]
#[tokio::test]
async fn test_p2id_note_constructors(
    #[case] constructor: &str,
    #[case] salt: Option<[Felt; 2]>,
    #[values(NoteType::Public, NoteType::Private)] note_type: NoteType,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender_account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [FungibleAsset::mock(100)],
    )?;
    let target_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mock_chain = builder.build()?;

    let serial_num = Word::from([1u32, 2, 3, 4]);
    let tag = NoteTag::with_account_target(target_account.id());
    let asset = FungibleAsset::mock(50);
    let expected_note: Note = P2idNote::builder()
        .sender(sender_account.id())
        .target(target_account.id())
        .salt(salt.unwrap_or_default())
        .asset(asset)
        .note_type(note_type)
        .serial_number(serial_num)
        .build()?
        .into();

    let push_salt = salt
        .map(|[salt_0, salt_1]| format!("push.{salt_1}.{salt_0}"))
        .unwrap_or_default();
    // The prepare procedures return creation arguments; the caller creates the note.
    let create_note = if constructor.starts_with("prepare_note") {
        r#"
            # => [tag, note_type, RECIPIENT]
            push.0 movdn.6 push.0 movdn.6 padw padw swapdw
            call.::miden::standards::wallets::basic::create_note
            movdn.15 dropw dropw dropw drop drop drop
        "#
    } else {
        ""
    };
    let tx_script_src = format!(
        r#"
        use miden::standards::notes::p2id

        @transaction_script
        pub proc main
            push.{serial_num}
            push.{note_type}
            push.{tag}
            push.{target_prefix}
            push.{target_suffix}
            {push_salt}
            exec.p2id::{constructor}
            {create_note}
            # => [note_idx]

            push.{ASSET_VALUE}
            push.{ASSET_ID}
            call.::miden::standards::wallets::basic::move_asset_to_note
            dropw dropw dropw dropw
        end
        "#,
        target_prefix = target_account.id().prefix().as_felt(),
        target_suffix = target_account.id().suffix(),
        tag = Felt::from(tag),
        note_type = note_type as u8,
        ASSET_ID = asset.to_id_word(),
        ASSET_VALUE = asset.to_value_word(),
    );
    let tx_script = CodeBuilder::default().compile_tx_script(&tx_script_src)?;
    let executed_transaction = mock_chain
        .build_transaction(sender_account.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);
    assert_eq!(output_note.recipient_digest(), expected_note.recipient().digest());
    assert_eq!(output_note.id(), expected_note.id());
    assert_eq!(output_note.metadata(), expected_note.metadata());
    assert_eq!(output_note.assets(), expected_note.assets());
    if note_type == NoteType::Public {
        assert_eq!(output_note, &RawOutputNote::Full(expected_note.clone()));
    }

    // The salt does not change who can consume the note.
    let rejected = mock_chain
        .build_transaction(sender_account.id())
        .unauthenticated_input_note(expected_note.clone())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(rejected, ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_TARGET_ACCOUNT);

    let consumed = mock_chain
        .build_transaction(target_account.id())
        .unauthenticated_input_note(expected_note)
        .build()?
        .execute()
        .await?;
    let mut target_account = target_account;
    target_account.apply_patch(consumed.account_patch())?;
    assert_eq!(target_account.vault().get_balance(asset.id())?.as_u64(), 50);

    Ok(())
}
