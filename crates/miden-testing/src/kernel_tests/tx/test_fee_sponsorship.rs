//! Tests for the `miden::standards::attachments::fee_sponsorship` module.
//!
//! A sponsorship note binds itself to the feature note it pays for by carrying that note's ID in a
//! `FeeSponsorship` attachment. The checks exercised here are the ones the sponsorship note script
//! and the network account's auth procedure both perform: read the bound ID off an attachment, then
//! confirm it names a note that is actually present in the transaction.

use miden_protocol::Word;
use miden_protocol::account::Account;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
use miden_standards::note::FeeSponsorship;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::testing::note::NoteBuilder;

use crate::{Auth, TestTransactionBuilder, TransactionContext};

/// Builds a transaction consuming `[sponsorship_note, feature_note]`, in that order, where the
/// sponsorship note is bound to `bound_note_id`.
///
/// Passing the feature note's own ID produces a correctly bound pair; passing anything else
/// produces a sponsorship note bound to a note that is not in the transaction.
fn setup(bind_to: impl Fn(&Note) -> Word) -> anyhow::Result<TransactionContext> {
    let account = Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));

    let feature_note =
        NoteBuilder::new(account.id(), &mut rng).note_type(NoteType::Public).build()?;

    let bound_id = miden_protocol::note::NoteId::from_raw(bind_to(&feature_note));
    let sponsorship_note = NoteBuilder::new(account.id(), &mut rng)
        .note_type(NoteType::Public)
        .attachment(FeeSponsorship::new(bound_id))
        .build()?;

    TestTransactionBuilder::new(account)
        .extend_input_notes(vec![sponsorship_note, feature_note])
        .build()
}

/// The MASM to run: read the bound ID off input note 0, recompute the ID of input note 1, and
/// assert they match. This is the sponsorship note's own presence check, and the auth procedure's
/// coverage check, expressed once.
const BOUND_ID_MATCHES_FEATURE_NOTE: &str = r#"
    use miden::tx_kernel_core::prologue
    use miden::standards::attachments::fee_sponsorship
    use miden::standards::note::note_id

    begin
        exec.prologue::prepare_transaction

        push.0
        exec.fee_sponsorship::input_note_bound_note_id
        # => [BOUND_NOTE_ID]

        push.1
        exec.note_id::compute_input_note_id
        # => [FEATURE_NOTE_ID, BOUND_NOTE_ID]

        assert_eqw.err="bound note id must match the feature note id"
        # => []
    end
"#;

/// Reading the binding by note index, as the auth procedure does, yields the feature note's ID.
#[tokio::test]
async fn input_note_bound_note_id_matches_feature_note() -> anyhow::Result<()> {
    let tx_context = setup(|feature_note| feature_note.id().as_word())?;

    tx_context.execute_code(BOUND_ID_MATCHES_FEATURE_NOTE).await?;

    Ok(())
}

/// A sponsorship note bound to a note that is not in the transaction must not match any of them.
///
/// This is the failure the sponsorship note script relies on to prevent being consumed without its
/// feature note: nothing in the transaction carries the bound ID, so the check cannot pass.
#[tokio::test]
async fn bound_note_id_does_not_match_an_absent_feature_note() -> anyhow::Result<()> {
    let tx_context = setup(|_| Word::from([9, 9, 9, 9u32]))?;

    let err = tx_context
        .execute_code(BOUND_ID_MATCHES_FEATURE_NOTE)
        .await
        .expect_err("a sponsorship bound to an absent note must not verify");

    // Pin the failure to the binding check rather than accepting any error.
    assert!(
        format!("{err:?}").contains("bound note id must match the feature note id"),
        "expected the binding assertion to fail, got: {err:?}",
    );

    Ok(())
}

/// Reading the binding off the *active* note, as the sponsorship note's own script does, yields the
/// same ID as reading it by index.
#[tokio::test]
async fn active_note_bound_note_id_matches_feature_note() -> anyhow::Result<()> {
    let tx_context = setup(|feature_note| feature_note.id().as_word())?;

    // The prologue leaves the active-note pointer on input note 0, the sponsorship note.
    let code = r#"
        use miden::tx_kernel_core::prologue
        use miden::standards::attachments::fee_sponsorship
        use miden::standards::note::note_id

        begin
            exec.prologue::prepare_transaction

            exec.fee_sponsorship::active_note_bound_note_id
            # => [BOUND_NOTE_ID]

            push.1
            exec.note_id::compute_input_note_id
            # => [FEATURE_NOTE_ID, BOUND_NOTE_ID]

            assert_eqw.err="active note binding must match the feature note id"
            # => []
        end
    "#;

    tx_context.execute_code(code).await?;

    Ok(())
}
