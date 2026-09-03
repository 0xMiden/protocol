use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteRecipient,
    NoteStorage,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// `assert_no_output_notes` reads the live output-note count itself, so a caller that understates
/// its own share tightens the check rather than weakening it.
///
/// This pins the direction that regressed when the count was supplied rather than read: the
/// procedure asserted on the caller's number and never touched the kernel, so a caller passing
/// zero — the value a naive caller passes — disabled the check entirely. The dangerous value is
/// now the large one, which a caller has to state deliberately.
///
/// The procedure still cannot detect a caller that overstates, since only the caller knows what it
/// created. What changed is what the caller is trusted about: a fact about its own code rather
/// than a fact about transaction state it had to sample at the right moment.
#[tokio::test]
async fn assert_no_output_notes_rejects_an_understated_own_count() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT)?;
    let output_note = Note::new(
        NoteAssets::new(vec![])?,
        PartialNoteMetadata::new(account.id(), NoteType::Public),
        NoteRecipient::new(Word::from([1u32, 2, 3, 4]), note_script, NoteStorage::default()),
    );

    let script = CodeBuilder::new().compile_tx_script(format!(
        "
        use miden::standards::auth::tx_policy

        @transaction_script
        pub proc main
            push.{recipient}
            push.{note_type}
            push.{tag}
            call.::miden::standards::note::note_creator::create_note
            movdn.15 dropw dropw dropw drop drop drop
            swapdw
            dropw
            dropw

            # this caller created none of the transaction's output notes
            push.0
            exec.tx_policy::assert_no_output_notes
        end
        ",
        recipient = output_note.recipient().digest(),
        note_type = NoteType::Public as u8,
        tag = Felt::from(output_note.metadata().tag()),
    ))?;

    let mock_chain = builder.build()?;
    let result = mock_chain
        .build_transaction(account.id())
        .tx_script(script)
        .expected_output_note(RawOutputNote::Full(output_note))
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES);

    Ok(())
}
