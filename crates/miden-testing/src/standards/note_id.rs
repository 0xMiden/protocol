//! Tests for the `miden::standards::note::note_id` module.
//!
//! The kernel derives note IDs internally but exposes no accessor for them, so the standards module
//! recomputes them from the four commitments that *are* exposed. These tests pin that recomputation
//! against the Rust [`NoteId`](miden_protocol::note::NoteId) so the two cannot drift.

use miden_protocol::Word;
use miden_protocol::account::Account;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{NoteAttachment, NoteAttachmentScheme, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::testing::note::NoteBuilder;
use rstest::rstest;

use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::{Auth, TestTransactionBuilder, TransactionContext};

/// A transaction consuming a bare note (note 0: no assets, no attachments) and a rich note
/// (note 1: an asset and two attachments), covering the empty and non-empty commitment branches.
fn two_note_tx() -> anyhow::Result<TransactionContext> {
    let account = Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));

    let bare_note = NoteBuilder::new(account.id(), &mut rng).build()?;
    let rich_note = NoteBuilder::new(account.id(), &mut rng)
        .note_type(NoteType::Public)
        .add_assets(vec![FungibleAsset::mock(150)])
        .attachment(NoteAttachment::with_word(
            NoteAttachmentScheme::new(10)?,
            Word::from([3, 4, 5, 6u32]),
        ))
        .attachment(NoteAttachment::with_word(
            NoteAttachmentScheme::new(20)?,
            Word::from([7, 8, 9, 10u32]),
        ))
        .build()?;

    TestTransactionBuilder::new(account)
        .extend_input_notes(vec![bare_note, rich_note])
        .build()
}

/// Recomputing a note's ID in MASM must match `Note::id()` in Rust, for both notes of the fixture
/// (note 0 is bare, note 1 carries an asset and attachments) through both the indexed and the
/// active-note procedure.
#[rstest]
#[tokio::test]
async fn compute_active_and_input_note_id_matches_rust(
    #[values(0, 1)] note_index: u8,
    #[values("compute_active_note_id", "compute_input_note_id")] procedure: &str,
) -> anyhow::Result<()> {
    let tx_context = two_note_tx()?;

    // The input variant takes the note index from the stack; the active variant reads the active
    // note, so the test points the active-note pointer at the note under test instead.
    let setup_code = if procedure == "compute_active_note_id" {
        format!(
            "push.{note_index} exec.memory::get_input_note_ptr exec.memory::set_active_input_note_ptr"
        )
    } else {
        format!("push.{note_index}")
    };

    let code = format!(
        r#"
        use miden::tx_kernel_core::memory
        use miden::tx_kernel_core::prologue
        use miden::standards::note::note_id

        begin
            exec.prologue::prepare_transaction

            {setup_code}
            exec.note_id::{procedure}
            # => [NOTE_ID]

            # truncate the stack
            swapw dropw
        end
        "#
    );

    let exec_output = tx_context.execute_code(&code).await?;

    let expected = tx_context.input_notes().get_note(note_index as usize).note().id();
    assert_eq!(exec_output.get_stack_word(0), expected.as_word());

    Ok(())
}

/// Recomputing an output note's ID in MASM must match `Note::id()` in Rust.
///
/// This is the direction the double-hop fee flow depends on: an account that has just created a
/// note needs its ID in order to bind a sponsorship note to it. The note is built in Rust and then
/// reconstructed in MASM via `create` + `add_asset` + `add_word_attachment`, so the assets and
/// attachments commitments are both non-empty.
#[tokio::test]
async fn compute_output_note_id_matches_rust() -> anyhow::Result<()> {
    let account = Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
    let rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));

    let asset: Asset = FungibleAsset::mock(150);
    let attachment_scheme = NoteAttachmentScheme::new(10)?;
    let attachment_word = Word::from([3, 4, 5, 6u32]);

    let expected_note = NoteBuilder::new(account.id(), rng)
        .note_type(NoteType::Public)
        .add_assets(vec![asset])
        .attachment(NoteAttachment::with_word(attachment_scheme, attachment_word))
        .build()?;
    let tag = expected_note.metadata().tag();

    let tx_context = TestTransactionBuilder::new(account).build()?;

    let code = format!(
        r#"
        use miden::core::sys
        use miden::protocol::output_note
        use miden::tx_kernel_core::prologue
        use miden::standards::note::note_id

        begin
            exec.prologue::prepare_transaction

            push.{recipient}
            push.{note_type}
            push.{tag}
            call.::mock::account::create_note
            # => [note_idx]

            dup push.{asset_value} push.{asset_id}
            # => [ASSET_ID, ASSET_VALUE, note_idx, note_idx]
            exec.output_note::add_asset
            # => [note_idx]

            dup push.{attachment_word} push.{attachment_scheme}
            # => [attachment_scheme, ATTACHMENT, note_idx, note_idx]
            exec.output_note::add_word_attachment
            # => [note_idx]

            exec.note_id::compute_output_note_id
            # => [NOTE_ID]

            # truncate the stack
            exec.sys::truncate_stack
        end
        "#,
        recipient = expected_note.recipient().digest(),
        note_type = NoteType::Public as u8,
        tag = tag,
        asset_value = asset.to_value_word(),
        asset_id = asset.to_id_word(),
        attachment_word = attachment_word,
        attachment_scheme = attachment_scheme.as_u16(),
    );

    let exec_output = tx_context.execute_code(&code).await?;

    assert_eq!(exec_output.get_stack_word(0), expected_note.id().as_word());

    Ok(())
}
