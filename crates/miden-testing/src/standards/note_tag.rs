use miden_protocol::note::NoteTag;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_standards::errors::standards::ERR_NOTE_TAG_MAX_ACCOUNT_TARGET_LENGTH_EXCEEDED;

use crate::assert_execution_error;
use crate::executor::CodeExecutor;

#[rstest::rstest]
#[case::tag_len_0(0)]
#[case::tag_len_20(20)]
#[case::tag_len_32(32)]
#[tokio::test]
async fn test_note_tag_account_target(#[case] tag_len: u8) -> anyhow::Result<()> {
    let account_id = AccountIdBuilder::new().build_with_seed([20; 32]);
    let id_prefix = account_id.prefix().as_felt();

    let expected_tag = NoteTag::with_custom_account_target(account_id, tag_len)?;

    let code = format!(
        "
        use miden::core::sys
        use miden::standards::note_tag

        begin
            push.{id_prefix}
            push.{tag_len}

            exec.note_tag::create_custom_account_target
            # => [note_tag]

            exec.sys::truncate_stack
        end
        "
    );

    let exec_output = CodeExecutor::with_default_host().run(&code).await?;
    let actual_tag = exec_output.stack[0].as_int();

    assert_eq!(
        actual_tag,
        expected_tag.as_u32() as u64,
        "Expected tag {:#010x}, got {:#010x}",
        expected_tag.as_u32(),
        actual_tag
    );

    Ok(())
}

#[tokio::test]
async fn test_note_tag_account_target_fails_for_large_tag_len() -> anyhow::Result<()> {
    let tag_len = NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH + 1;
    let code = format!(
        "
        use miden::core::sys
        use miden::standards::note_tag

        begin
            # account ID prefix doesn't matter for this test
            push.0
            push.{tag_len}

            exec.note_tag::create_custom_account_target
            # => [note_tag]

            exec.sys::truncate_stack
        end
        "
    );

    let exec_output = CodeExecutor::with_default_host().run(&code).await;

    assert_execution_error!(exec_output, ERR_NOTE_TAG_MAX_ACCOUNT_TARGET_LENGTH_EXCEEDED);

    Ok(())
}
