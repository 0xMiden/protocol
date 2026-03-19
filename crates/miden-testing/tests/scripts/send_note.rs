use core::slice;
use std::collections::BTreeMap;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentScheme,
    NoteMetadata,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNote,
};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::interface::{AccountInterface, AccountInterfaceExt};
use miden_standards::code_builder::CodeBuilder;
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
    let p2any_note = create_p2any_note(
        sender_basic_wallet_account.id(),
        NoteType::Private,
        [sent_asset2],
        &mut RandomCoin::new(Word::from([1, 2, 3, 4u32])),
    );
    let spawn_note = builder.add_spawn_note([&p2any_note])?;
    let mock_chain = builder.build()?;

    let sender_account_interface = AccountInterface::from_account(&sender_basic_wallet_account);

    let tag = NoteTag::with_account_target(sender_basic_wallet_account.id());
    let elements = [9, 8, 7, 6, 5u32].map(Felt::from).to_vec();
    let attachment = NoteAttachment::new_array(NoteAttachmentScheme::new(42), elements.clone())?;
    let metadata = NoteMetadata::new(sender_basic_wallet_account.id(), NoteType::Public)
        .with_tag(tag)
        .with_attachment(attachment.clone());
    let assets = NoteAssets::new(vec![sent_asset0, sent_asset1]).unwrap();
    let note_script = CodeBuilder::default().compile_note_script("begin nop end").unwrap();
    let serial_num = RandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());

    let note = Note::new(assets.clone(), metadata, recipient);
    let partial_note: PartialNote = note.clone().into();

    let expiration_delta = 10u16;
    let send_note_transaction_script = sender_account_interface
        .build_send_notes_script(slice::from_ref(&partial_note), Some(expiration_delta))?;

    let executed_transaction = mock_chain
        .build_tx_context(sender_basic_wallet_account.id(), &[spawn_note.id()], &[])
        .expect("failed to build tx context")
        .tx_script(send_note_transaction_script)
        .extend_expected_output_notes(vec![RawOutputNote::Full(note.clone())])
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
    assert_eq!(executed_transaction.output_notes().get_note(1), &RawOutputNote::Full(note));

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
    let attachment = NoteAttachment::new_word(NoteAttachmentScheme::new(100), Word::empty());
    let metadata = NoteMetadata::new(sender_basic_fungible_faucet_account.id(), NoteType::Public)
        .with_tag(tag)
        .with_attachment(attachment);
    let assets = NoteAssets::new(vec![Asset::Fungible(
        FungibleAsset::new(sender_basic_fungible_faucet_account.id(), 10).unwrap(),
    )])?;
    let note_script = CodeBuilder::default().compile_note_script("begin nop end").unwrap();
    let serial_num = RandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());

    let note = Note::new(assets.clone(), metadata, recipient);
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
