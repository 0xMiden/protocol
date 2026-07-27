use core::num::NonZeroU16;
use core::slice;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountCodeInterface, AccountComponentCode, AccountId};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteRecipient,
    NoteStorage, NoteTag, NoteType, PartialNote, PartialNoteMetadata,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1, ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
};
use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_SEND_NOTES_FAUCET_NOTE_REQUIRES_ONE_ASSET;
use miden_standards::note::P2idNote;
use miden_standards::tx_script::{SendNotesTransactionScript, SendNotesTransactionScriptError};
use miden_testing::utils::create_p2any_note;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// Tests the execution of the generated send_note transaction script in case the sending account
/// has the [`BasicWallet`][wallet] interface.
///
/// This tests consumes a SPAWN note first so that the note_idx in the send_note script is not zero
/// to make sure the note_idx is correctly kept on the stack.
///
/// The test also sends two assets to make sure the generated script deals correctly with multiple
/// assets.
///
/// [wallet]: miden_standards::account::interface::AccountComponentInterface::BasicWallet
#[tokio::test]
async fn test_send_note_script_basic_wallet() -> anyhow::Result<()> {
    let total_asset = FungibleAsset::mock(100);
    let sent_asset0 = NonFungibleAsset::mock(&[4, 5, 6]);

    let sent_asset1 = FungibleAsset::mock(10);
    let sent_asset2 = FungibleAsset::mock(40);

    let mut builder = MockChain::builder();

    let sender_basic_wallet_account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [sent_asset0, total_asset],
    )?;
    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let p2any_note = create_p2any_note(
        sender_basic_wallet_account.id(),
        NoteType::Private,
        [sent_asset1],
        &mut rng,
    );
    let spawn_note = builder.add_spawn_note([&p2any_note])?;
    let mock_chain = builder.build()?;

    let attachment_0 = NoteAttachment::with_words(
        NoteAttachmentScheme::new(42)?,
        vec![Word::from([9, 8, 7, 6u32]), Word::from([5, 4, 3, 2u32])],
    )?;
    let attachment_1 =
        NoteAttachment::with_word(NoteAttachmentScheme::new(43)?, Word::from([1, 2, 3, 4u32]));
    let attachment_2 = NoteAttachment::with_words(
        NoteAttachmentScheme::new(44)?,
        vec![Word::from([10, 11, 12, 13u32])],
    )?;
    let attachment_3 =
        NoteAttachment::with_word(NoteAttachmentScheme::new(45)?, Word::from([20, 21, 22, 23u32]));
    let attachments =
        NoteAttachments::new(vec![attachment_0, attachment_1, attachment_2, attachment_3])?;
    assert_eq!(
        attachments.num_attachments() as usize,
        NoteAttachments::MAX_COUNT,
        "test should use max num of attachments"
    );

    let p2id_note: Note = P2idNote::builder()
        .sender(sender_basic_wallet_account.id())
        .target(sender_basic_wallet_account.id())
        .asset(sent_asset0)
        .asset(sent_asset2)
        .attachments(attachments.iter().cloned())
        .note_type(NoteType::Public)
        .generate_serial_number(&mut rng)
        .build()?
        .into();
    let partial_note = PartialNote::from(p2id_note.clone());

    let expiration_delta = NonZeroU16::new(10).expect("10 is non-zero");
    let send_note_transaction_script = SendNotesTransactionScript::with_expiration_delta(
        &sender_basic_wallet_account.code_interface(),
        slice::from_ref(&partial_note),
        expiration_delta,
    )?;

    let executed_transaction = mock_chain
        .build_transaction(sender_basic_wallet_account.id())
        .authenticated_input_note(spawn_note.id())
        .send_notes_script(&send_note_transaction_script)
        .expected_output_note(RawOutputNote::Full(p2id_note.clone()))
        .build()?
        .execute()
        .await?;

    // Assert that the non-fungible asset was removed
    let vault_patch = executed_transaction.account_patch().vault();
    assert_eq!(
        vault_patch.removed_asset_ids().count(),
        1,
        "the non-fungible asset should have been completely removed"
    );
    assert_eq!(
        vault_patch.removed_asset_ids().next().unwrap(),
        &sent_asset0.id(),
        "the non-fungible asset should have been completely removed"
    );

    // Assert that the fungible asset's value was decremented
    assert_eq!(
        vault_patch.updated_assets().count(),
        1,
        "the fungible asset should have been updated"
    );
    // Expected value is total - (sent_asset1 + sent_asset2).
    let expected_removed = sent_asset1.unwrap_fungible().add(sent_asset2.unwrap_fungible())?;
    let expected_asset_value = total_asset.unwrap_fungible().sub(expected_removed)?.into();
    assert_eq!(
        vault_patch.updated_assets().next().unwrap(),
        expected_asset_value,
        "fungible asset should have been decremented"
    );

    assert_eq!(
        executed_transaction.output_notes().get_note(0),
        &RawOutputNote::Partial(p2any_note.into())
    );
    assert_eq!(executed_transaction.output_notes().get_note(1), &RawOutputNote::Full(p2id_note));

    assert_eq!(
        executed_transaction.expiration_block_num(),
        executed_transaction.block_header().block_num() + u32::from(expiration_delta.get()),
        "the payload-supplied expiration delta should be applied",
    );

    Ok(())
}

/// Creates a private note with the default note script and an empty asset list.
fn create_assetless_note(sender: miden_protocol::account::AccountId) -> anyhow::Result<Note> {
    let tag = NoteTag::with_account_target(sender);
    let metadata = PartialNoteMetadata::new(sender, NoteType::Private).with_tag(tag);
    let assets = NoteAssets::new(vec![])?;
    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT)?;
    let serial_num = RandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    Ok(Note::new(assets, metadata, recipient))
}

/// Tests that a basic wallet can send a note that carries no assets.
///
/// Regression test: the script must return at stack depth 16 even when the per-asset loop never
/// runs (zero-asset note), otherwise the VM rejects the transaction with
/// `InvalidStackDepthOnReturn`.
///
/// [wallet]: miden_standards::account::interface::AccountComponentInterface::BasicWallet
#[tokio::test]
async fn test_send_note_script_basic_wallet_without_assets() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender_basic_wallet_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mock_chain = builder.build()?;

    let assetless_note = create_assetless_note(sender_basic_wallet_account.id())?;
    let partial_note = PartialNote::from(assetless_note.clone());

    let send_note_transaction_script = SendNotesTransactionScript::new(
        &sender_basic_wallet_account.code_interface(),
        slice::from_ref(&partial_note),
    )?;

    let executed_transaction = mock_chain
        .build_transaction(sender_basic_wallet_account.id())
        .send_notes_script(&send_note_transaction_script)
        .expected_output_notes(vec![RawOutputNote::Full(assetless_note.clone())])
        .build()?
        .execute()
        .await?;

    assert_eq!(
        executed_transaction.output_notes().get_note(0),
        &RawOutputNote::Full(assetless_note)
    );

    Ok(())
}

/// Tests that the faucet path still rejects assetless notes at script-build time.
#[tokio::test]
async fn test_send_note_script_fungible_faucet_without_assets() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender_fungible_faucet_account = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "POL",
        200,
        None,
    )?;
    builder.build()?;

    let assetless_note = create_assetless_note(sender_fungible_faucet_account.id())?;
    let partial_note = PartialNote::from(assetless_note);

    let result = SendNotesTransactionScript::new(
        &sender_fungible_faucet_account.code_interface(),
        slice::from_ref(&partial_note),
    );

    assert!(matches!(
        result,
        Err(SendNotesTransactionScriptError::FaucetNoteUnexpectedNumAssets)
    ));

    Ok(())
}

/// Builds the code interface of an account exposing `component`'s procedures, without
/// instantiating an account. Enough for the script builder, which only inspects the interface.
fn code_interface(
    account_id: u128,
    component: &AccountComponentCode,
) -> anyhow::Result<AccountCodeInterface> {
    let account_id = AccountId::try_from(account_id)?;
    Ok(AccountCodeInterface::new(account_id, component.procedure_roots().collect())?)
}

/// Tests that the wallet path rejects notes whose sender is not the sending account at
/// script-build time.
#[test]
fn test_send_note_script_rejects_sender_mismatch() -> anyhow::Result<()> {
    let sender_interface =
        code_interface(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE, BasicWallet::code())?;
    let other_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2)?;

    let foreign_note = create_assetless_note(other_id)?;
    let partial_note = PartialNote::from(foreign_note);

    let result = SendNotesTransactionScript::new(&sender_interface, slice::from_ref(&partial_note));

    assert!(matches!(
        result,
        Err(SendNotesTransactionScriptError::InvalidSenderAccount(sender)) if sender == other_id
    ));

    Ok(())
}

/// Tests that the faucet path rejects notes carrying an asset issued by a different faucet at
/// script-build time.
#[test]
fn test_send_note_script_rejects_foreign_faucet_asset() -> anyhow::Result<()> {
    // The mock asset is issued by `ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET`, so the sending faucet must
    // be a different one for the asset to count as foreign.
    let faucet_interface =
        code_interface(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1, FungibleFaucet::code())?;
    let foreign_asset = FungibleAsset::mock(10);
    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let note =
        create_p2any_note(faucet_interface.id(), NoteType::Private, [foreign_asset], &mut rng);
    let partial_note = PartialNote::from(note);

    let result = SendNotesTransactionScript::new(&faucet_interface, slice::from_ref(&partial_note));

    assert!(matches!(
        result,
        Err(SendNotesTransactionScriptError::IssuanceFaucetMismatch(faucet_id))
            if faucet_id == foreign_asset.faucet_id()
    ));

    Ok(())
}

/// Tests the execution of the generated send_note transaction script in case the sending account
/// has the [`FungibleFaucet`][faucet] interface.
///
/// [faucet]: miden_standards::account::interface::AccountComponentInterface::FungibleFaucet
#[tokio::test]
async fn test_send_note_script_fungible_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender_fungible_faucet_account = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "POL",
        200,
        None,
    )?;
    let mock_chain = builder.build()?;

    let tag = NoteTag::with_account_target(sender_fungible_faucet_account.id());
    let attachment = NoteAttachment::with_word(NoteAttachmentScheme::new(100)?, Word::empty());
    let metadata = PartialNoteMetadata::new(sender_fungible_faucet_account.id(), NoteType::Public)
        .with_tag(tag);
    let assets = NoteAssets::new(vec![Asset::Fungible(
        FungibleAsset::new(sender_fungible_faucet_account.id(), 10).unwrap(),
    )])?;
    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT).unwrap();
    let serial_num = RandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let attachments = NoteAttachments::from(attachment);

    let note = Note::with_attachments(assets.clone(), metadata, recipient, attachments);
    let partial_note: PartialNote = note.clone().into();

    let expiration_delta = NonZeroU16::new(10).expect("10 is non-zero");
    let send_note_transaction_script = SendNotesTransactionScript::with_expiration_delta(
        &sender_fungible_faucet_account.code_interface(),
        slice::from_ref(&partial_note),
        expiration_delta,
    )?;

    let executed_transaction = mock_chain
        .build_transaction(sender_fungible_faucet_account.id())
        .send_notes_script(&send_note_transaction_script)
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute()
        .await?;

    assert_eq!(executed_transaction.output_notes().get_note(0), &RawOutputNote::Full(note));

    assert_eq!(
        executed_transaction.expiration_block_num(),
        executed_transaction.block_header().block_num() + u32::from(expiration_delta.get()),
        "the payload-supplied expiration delta should be applied",
    );

    Ok(())
}

#[tokio::test]
async fn test_send_note_script_multiple_notes_basic_wallet() -> anyhow::Result<()> {
    let total_asset = FungibleAsset::mock(100);
    let non_fungible_asset = NonFungibleAsset::mock(&[7, 8, 9]);

    let mut builder = MockChain::builder();
    let sender_account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [total_asset, non_fungible_asset],
    )?;
    let mock_chain = builder.build()?;

    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));

    // Note A: two assets and two attachments.
    let attachment_0 =
        NoteAttachment::with_word(NoteAttachmentScheme::new(7)?, Word::from([1, 2, 3, 4u32]));
    let attachment_1 = NoteAttachment::with_words(
        NoteAttachmentScheme::new(8)?,
        vec![Word::from([5, 6, 7, 8u32]), Word::from([9, 10, 11, 12u32])],
    )?;
    let note_a: Note = P2idNote::builder()
        .sender(sender_account.id())
        .target(sender_account.id())
        .asset(FungibleAsset::mock(10))
        .asset(non_fungible_asset)
        .attachments([attachment_0, attachment_1])
        .note_type(NoteType::Public)
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    // Note B: one asset, no attachments.
    let note_b: Note = P2idNote::builder()
        .sender(sender_account.id())
        .target(sender_account.id())
        .asset(FungibleAsset::mock(40))
        .note_type(NoteType::Public)
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    // Note C: no assets and no attachments (smallest possible record).
    let metadata = PartialNoteMetadata::new(sender_account.id(), NoteType::Public)
        .with_tag(NoteTag::with_account_target(sender_account.id()));
    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT).unwrap();
    let recipient = NoteRecipient::new(rng.draw_word(), note_script, NoteStorage::default());
    let note_c = Note::new(NoteAssets::default(), metadata, recipient);

    let notes: Vec<PartialNote> =
        vec![note_a.clone().into(), note_b.clone().into(), note_c.clone().into()];
    let script = SendNotesTransactionScript::new(&sender_account.code_interface(), &notes)?;

    let executed_transaction = mock_chain
        .build_transaction(sender_account.id())
        .send_notes_script(&script)
        .expected_output_notes(vec![
            RawOutputNote::Full(note_a.clone()),
            RawOutputNote::Full(note_b.clone()),
            RawOutputNote::Full(note_c.clone()),
        ])
        .build()?
        .execute()
        .await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 3);
    assert_eq!(executed_transaction.output_notes().get_note(0), &RawOutputNote::Full(note_a));
    assert_eq!(executed_transaction.output_notes().get_note(1), &RawOutputNote::Full(note_b));
    assert_eq!(executed_transaction.output_notes().get_note(2), &RawOutputNote::Full(note_c));

    // Both of note A's assets must have left the vault: the non-fungible one entirely, and the
    // fungible one decremented by note A's and note B's amounts.
    let vault_patch = executed_transaction.account_patch().vault();
    assert_eq!(
        vault_patch.removed_asset_ids().collect::<Vec<_>>(),
        vec![&non_fungible_asset.id()],
        "the non-fungible asset should have been completely removed"
    );

    let expected_removed = FungibleAsset::mock(10)
        .unwrap_fungible()
        .add(FungibleAsset::mock(40).unwrap_fungible())?;
    let expected_asset_value = total_asset.unwrap_fungible().sub(expected_removed)?.into();
    assert_eq!(
        vault_patch.updated_assets().collect::<Vec<_>>(),
        vec![expected_asset_value],
        "the fungible asset should have been decremented by both notes' amounts"
    );

    Ok(())
}

/// Tests that the faucet script rejects a payload whose note record claims more than one asset.
#[tokio::test]
async fn test_send_note_script_faucet_rejects_multi_asset_payload() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet_account = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "POL",
        200,
        None,
    )?;
    let mock_chain = builder.build()?;

    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let own_asset = Asset::Fungible(FungibleAsset::new(faucet_account.id(), 10)?);
    let note = create_p2any_note(faucet_account.id(), NoteType::Public, [own_asset], &mut rng);

    let script = SendNotesTransactionScript::new(&faucet_account.code_interface(), &[note.into()])?;

    // Handcraft a payload whose first note record claims two assets and recompute the
    // commitment so the payload passes the advice validation and reaches the script's own
    // assertion.
    let (_, mut payload) = script.advice_entries()[0].clone();
    payload[SendNotesTransactionScript::PAYLOAD_HEADER_NUM_ELEMENTS
        + SendNotesTransactionScript::NOTE_RECORD_NUM_ASSETS_OFFSET] = Felt::from(2u32);
    let tampered_args = Hasher::hash_elements(&payload);

    let result = mock_chain
        .build_transaction(faucet_account.id())
        .tx_script(script.tx_script().clone())
        .tx_script_args(tampered_args)
        .extend_advice_map(tampered_args, payload)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SEND_NOTES_FAUCET_NOTE_REQUIRES_ONE_ASSET);

    Ok(())
}
