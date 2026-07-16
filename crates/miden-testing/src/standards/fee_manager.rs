//! Tests for the `miden::standards::fees::fee_manager` note-side helpers used by
//! `create_sponsorship_notes`: recovering a note's script root and storage commitment from its
//! recipient, and the FEE_SPONSORSHIP `prepare_note` recipient computation.

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountType};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    AccountIdBuilder,
};
use miden_standards::note::FeeSponsorshipNote;
use miden_standards::testing::mock_account::MockAccountExt;

use crate::executor::CodeExecutor;
use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::{Auth, TestTransactionBuilder};

/// `output_note_get_recipient_preimage` must recover an output note's script root
/// and storage commitment from the recipient it exposes via the advice map entries that
/// compute_and_store_recipient inserts.
#[tokio::test]
async fn output_note_get_recipient_preimage_recovers_preimage() -> anyhow::Result<()> {
    let account = Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
    let tx_context = TestTransactionBuilder::new(account).build()?;

    let script_root = Word::from([11u32, 12, 13, 14]);
    let serial_num = Word::from([21u32, 22, 23, 24]);

    let code = format!(
        r#"
        use miden::core::sys
        use miden::protocol::note
        use miden::standards::fees::fee_manager
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction

            # build a recipient for a note with the given script root and empty storage, seeding the
            # advice map with the preimages the helper reads back
            push.{script_root}
            push.{serial_num}
            push.0.0
            # => [storage_ptr, num_storage_items, SERIAL_NUM, SCRIPT_ROOT]
            exec.note::compute_and_store_recipient
            # => [RECIPIENT]

            # create an output note carrying that recipient
            push.{note_type}
            push.{tag}
            # => [tag, note_type, RECIPIENT]
            call.::mock::account::create_note
            # => [output_note_idx]

            exec.fee_manager::output_note_get_recipient_preimage
            # => [NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT]

            exec.sys::truncate_stack
        end
        "#,
        script_root = script_root,
        serial_num = serial_num,
        note_type = NoteType::Public as u8,
        tag = 0,
    );

    let exec_output = tx_context.execute_code(&code).await?;

    assert_eq!(exec_output.get_stack_word(0), script_root, "recovered script root should match");
    // With zero storage items the storage commitment is the empty word.
    assert_eq!(
        exec_output.get_stack_word(4),
        Word::empty(),
        "recovered storage commitment should match"
    );

    Ok(())
}

/// `fee_sponsorship::prepare_note` must compute the same recipient the Rust
/// [`FeeSponsorshipNote`] does, pinning the 7-item storage layout across the two implementations.
#[tokio::test]
async fn prepare_note_recipient_matches_rust() -> anyhow::Result<()> {
    let mut rng = rand::rng();
    let sender = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_rng(&mut rng);
    let target = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_rng(&mut rng);
    let reclaimer = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_rng(&mut rng);

    let feature_note_id = NoteId::from_raw(Word::from([31u32, 32, 33, 34]));
    let serial_number = Word::from([41u32, 42, 43, 44]);
    let reclaim_height = 123u32;

    let note = Note::from(
        FeeSponsorshipNote::builder()
            .sender(sender)
            .target_account(target)
            .feature_note_id(feature_note_id)
            .reclaimer(reclaimer)
            .reclaim_height(BlockNumber::from(reclaim_height))
            .serial_number(serial_number)
            .asset(FungibleAsset::mock(10))
            .build()?,
    );
    let expected_recipient = note.recipient().digest();

    // `tag` and `note_type` are pass-through inputs of `prepare_note` and do not affect the
    // recipient, so arbitrary values are fine here.
    let source = format!(
        r#"
        use miden::core::sys
        use miden::standards::notes::fee_sponsorship

        begin
            push.{serial_num}
            push.{note_type}
            push.{tag}
            push.{reclaim_height}
            push.{reclaimer_prefix}
            push.{reclaimer_suffix}
            push.{feature_note_id}
            # => [feature_note_id, reclaimer_suffix, reclaimer_prefix, reclaim_height, tag,
            #     note_type, SERIAL_NUM]

            exec.fee_sponsorship::prepare_note
            # => [tag, note_type, RECIPIENT]

            drop drop
            # => [RECIPIENT]

            exec.sys::truncate_stack
        end
        "#,
        serial_num = serial_number,
        note_type = NoteType::Public as u8,
        tag = 0,
        reclaim_height = reclaim_height,
        reclaimer_prefix = reclaimer.prefix().as_felt(),
        reclaimer_suffix = reclaimer.suffix(),
        feature_note_id = feature_note_id.as_word(),
    );

    let exec_output = CodeExecutor::with_default_host().run(&source).await?;

    assert_eq!(exec_output.get_stack_word(0), expected_recipient);

    Ok(())
}
