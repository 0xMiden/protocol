use core::slice;
use std::collections::BTreeMap;

use miden_protocol::Word;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentScheme,
    NoteAttachments,
    NoteMetadata,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNote,
};
use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::interface::{AccountInterface, AccountInterfaceExt};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_testing::utils::create_p2any_note;
use miden_testing::{Auth, MockChain};

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

    let sender_account_interface = AccountInterface::from_account(&sender_basic_wallet_account);

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

    let p2id_note = P2idNote::create(
        sender_basic_wallet_account.id(),
        sender_basic_wallet_account.id(),
        vec![sent_asset0, sent_asset2],
        NoteType::Public,
        attachments,
        &mut rng,
    )?;
    let partial_note = PartialNote::from(p2id_note.clone());

    let expiration_delta = 10u16;
    let send_note_transaction_script = sender_account_interface
        .build_send_notes_script(slice::from_ref(&partial_note), Some(expiration_delta))?;

    let executed_transaction = mock_chain
        .build_tx_context(sender_basic_wallet_account.id(), &[spawn_note.id()], &[])
        .expect("failed to build tx context")
        .tx_script(send_note_transaction_script)
        .extend_expected_output_notes(vec![RawOutputNote::Full(p2id_note.clone())])
        .build()?
        .execute()
        .await?;

    // assert that the removed asset is in the delta
    let mut removed_assets: BTreeMap<_, _> = executed_transaction
        .account_delta()
        .vault()
        .removed_assets()
        .map(|asset| (asset.vault_key(), asset))
        .collect();
    assert_eq!(removed_assets.len(), 2, "two assets should have been removed");
    assert_eq!(
        removed_assets.remove(&sent_asset0.vault_key()).unwrap(),
        sent_asset0,
        "sent asset0 should be in removed assets"
    );
    assert_eq!(
        removed_assets.remove(&sent_asset1.vault_key()).unwrap(),
        sent_asset1.unwrap_fungible().add(sent_asset2.unwrap_fungible())?.into(),
        "sent asset1 + sent_asset2 should be in removed assets"
    );
    assert_eq!(
        executed_transaction.output_notes().get_note(0),
        &RawOutputNote::Partial(p2any_note.into())
    );
    assert_eq!(executed_transaction.output_notes().get_note(1), &RawOutputNote::Full(p2id_note));

    Ok(())
}

/// Tests the execution of the generated send_note transaction script in case the sending account
/// has the [`BasicFungibleFaucet`][faucet] interface.
///
/// [faucet]: miden_standards::account::interface::AccountComponentInterface::BasicFungibleFaucet
#[tokio::test]
async fn test_send_note_script_basic_fungible_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender_basic_fungible_faucet_account = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "POL",
        200,
        None,
    )?;
    let mock_chain = builder.build()?;

    let sender_account_interface =
        AccountInterface::from_account(&sender_basic_fungible_faucet_account);

    let tag = NoteTag::with_account_target(sender_basic_fungible_faucet_account.id());
    let attachment = NoteAttachment::with_word(NoteAttachmentScheme::new(100)?, Word::empty());
    let metadata = NoteMetadata::new(sender_basic_fungible_faucet_account.id(), NoteType::Public)
        .with_tag(tag);
    let assets = NoteAssets::new(vec![Asset::Fungible(
        FungibleAsset::new(sender_basic_fungible_faucet_account.id(), 10).unwrap(),
    )])?;
    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT).unwrap();
    let serial_num = RandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let attachments = NoteAttachments::from(attachment);

    let note = Note::with_attachments(assets.clone(), metadata, recipient, attachments);
    let partial_note: PartialNote = note.clone().into();

    let expiration_delta = 10u16;
    let send_note_transaction_script = sender_account_interface
        .build_send_notes_script(slice::from_ref(&partial_note), Some(expiration_delta))?;

    let executed_transaction = mock_chain
        .build_tx_context(sender_basic_fungible_faucet_account.id(), &[], &[])
        .expect("failed to build tx context")
        .tx_script(send_note_transaction_script)
        .extend_expected_output_notes(vec![RawOutputNote::Full(note.clone())])
        .build()?
        .execute()
        .await?;

    assert_eq!(executed_transaction.output_notes().get_note(0), &RawOutputNote::Full(note));

    Ok(())
}
