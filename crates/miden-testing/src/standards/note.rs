//! Tests for `get_recipient_parts` of the `miden::standards::note` module.

use alloc::string::String;
use alloc::vec::Vec;

use miden_processor::advice::AdviceInputs;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{NoteRecipient, NoteStorage};
use miden_protocol::{Felt, Word};
use miden_standards::errors::standards::{
    ERR_NOTE_RECIPIENT_PREIMAGE_MISMATCH,
    ERR_NOTE_RECIPIENT_PREIMAGE_MISSING,
};
use miden_standards::note::P2idNote;

use crate::assert_execution_error;
use crate::executor::CodeExecutor;
use crate::kernel_tests::tx::ExecutionOutputExt;

/// Tests that `get_recipient_parts` returns the serial number, script root and storage commitment
/// of a recipient whose preimage is in the advice map.
#[tokio::test]
async fn get_recipient_parts_returns_the_recipient_preimage() -> anyhow::Result<()> {
    let recipient = recipient(Word::from([1, 2, 3, 4u32]))?;

    let exec_output = CodeExecutor::with_default_host()
        .extend_advice_inputs(AdviceInputs::default().with_map(recipient.to_advice_map_entries()))
        .run(&get_recipient_parts_code(recipient.digest()))
        .await?;

    assert_eq!(exec_output.get_stack_word(0), recipient.serial_num());
    assert_eq!(exec_output.get_stack_word(4), recipient.script().root().as_word());
    assert_eq!(exec_output.get_stack_word(8), recipient.storage().commitment());

    Ok(())
}

/// Tests that `get_recipient_parts` fails if the advice map has no preimage for the recipient, or
/// one that opens the recipient to the parts of another recipient.
#[rstest::rstest]
#[case::missing_preimage(false, ERR_NOTE_RECIPIENT_PREIMAGE_MISSING)]
#[case::forged_preimage(true, ERR_NOTE_RECIPIENT_PREIMAGE_MISMATCH)]
#[tokio::test]
async fn get_recipient_parts_rejects_missing_or_forged_preimage(
    #[case] forges_preimage: bool,
    #[case] expected_error: MasmError,
) -> anyhow::Result<()> {
    let recipient = recipient(Word::from([1, 2, 3, 4u32]))?;

    // map the recipient to the first entry of the preimage of a recipient with another serial
    // number, so that every lookup succeeds but the parts do not hash to the recipient
    let mut advice_map = Vec::new();
    if forges_preimage {
        let other_recipient = self::recipient(Word::from([5, 6, 7, 8u32]))?;
        advice_map.extend(other_recipient.to_advice_map_entries().into_iter().map(
            |(key, value)| {
                let key = if key == other_recipient.digest() {
                    recipient.digest()
                } else {
                    key
                };
                (key, value)
            },
        ));
    }

    let result = CodeExecutor::with_default_host()
        .extend_advice_inputs(AdviceInputs::default().with_map(advice_map))
        .run(&get_recipient_parts_code(recipient.digest()))
        .await;

    assert_execution_error!(result, expected_error);

    Ok(())
}

/// Returns a P2ID-script recipient with the provided serial number and two storage items.
fn recipient(serial_num: Word) -> anyhow::Result<NoteRecipient> {
    let storage = NoteStorage::new(vec![Felt::from(9u32), Felt::from(10u32)])?;

    Ok(NoteRecipient::new(serial_num, P2idNote::script(), storage))
}

/// Returns the code of a program that calls `get_recipient_parts` on the provided recipient.
fn get_recipient_parts_code(recipient: Word) -> String {
    format!(
        "
        use miden::core::sys
        use miden::standards::note as std_note

        begin
            push.{recipient}
            exec.std_note::get_recipient_parts
            # => [SERIAL_NUM, SCRIPT_ROOT, STORAGE_COMMITMENT, pad(16)]

            exec.sys::truncate_stack
        end
        "
    )
}
