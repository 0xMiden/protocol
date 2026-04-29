//! Tests for the `miden::standards::attachments::network_account_target` module.

use miden_protocol::Felt;
use miden_protocol::account::AccountStorageMode;
use miden_protocol::note::{NoteAttachment, NoteAttachmentContent};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};

use crate::executor::CodeExecutor;

#[tokio::test]
async fn network_account_target_into_target_id() -> anyhow::Result<()> {
    let target_id = AccountIdBuilder::new()
        .storage_mode(AccountStorageMode::Network)
        .build_with_rng(&mut rand::rng());
    let exec_hint = NoteExecutionHint::Always;

    let attachment = NoteAttachment::from(NetworkAccountTarget::new(target_id, exec_hint)?);

    let source = format!(
        r#"
        use miden::standards::attachments::network_account_target
        use miden::protocol::note

        begin
            push.{attachment_scheme}
            # => [attachment_scheme]
            exec.network_account_target::is_network_account_target
            # => [is_valid]
            assert.err="expected scheme to be a valid network account target"

            push.{attachment_word}
            # => [NOTE_ATTACHMENT]
            exec.network_account_target::into_target_id
            # => [account_id_suffix, account_id_prefix]
            # cleanup stack
            movup.2 drop movup.2 drop
        end
        "#,
        attachment_scheme = attachment.attachment_scheme().as_u16(),
        attachment_word = match attachment.content() {
            NoteAttachmentContent::Word(word) => *word,
            _ => unreachable!("expected word attachment"),
        },
    );

    let exec_output = CodeExecutor::with_default_host().run(&source).await?;

    assert_eq!(exec_output.stack[0], target_id.suffix());
    assert_eq!(exec_output.stack[1], target_id.prefix().as_felt());

    Ok(())
}

#[tokio::test]
async fn network_account_target_new_attachment() -> anyhow::Result<()> {
    let target_id = AccountIdBuilder::new()
        .storage_mode(AccountStorageMode::Network)
        .build_with_rng(&mut rand::rng());
    let exec_hint = NoteExecutionHint::Always;

    let attachment = NoteAttachment::from(NetworkAccountTarget::new(target_id, exec_hint)?);
    let raw_attachment_word = match attachment.content() {
        NoteAttachmentContent::Word(word) => *word,
        _ => unreachable!("expected word attachment"),
    };

    let source = format!(
        r#"
        use miden::standards::attachments::network_account_target

        begin
            push.{exec_hint}
            push.{target_id_prefix}
            push.{target_id_suffix}
            # => [target_id_suffix, target_id_prefix, exec_hint]
            exec.network_account_target::new
            # => [attachment_scheme, NOTE_ATTACHMENT, pad(16)]

            # cleanup stack
            swapdw dropw dropw
        end
        "#,
        target_id_prefix = target_id.prefix().as_felt(),
        target_id_suffix = target_id.suffix(),
        exec_hint = Felt::from(exec_hint),
    );

    let exec_output = CodeExecutor::with_default_host().run(&source).await?;

    assert_eq!(
        exec_output.stack[0],
        Felt::from(NetworkAccountTarget::ATTACHMENT_SCHEME.as_u16())
    );

    let word = exec_output.stack.get_word(1).unwrap();
    assert_eq!(word, raw_attachment_word);

    Ok(())
}

#[tokio::test]
async fn network_account_target_attachment_round_trip() -> anyhow::Result<()> {
    let target_id = AccountIdBuilder::new()
        .storage_mode(AccountStorageMode::Network)
        .build_with_rng(&mut rand::rng());
    let exec_hint = NoteExecutionHint::Always;

    let source = format!(
        r#"
        use miden::standards::attachments::network_account_target

        const ERR_NOT_NETWORK_ACCOUNT_TARGET = "attachment is not a valid network account target"

        begin
            push.{exec_hint}
            push.{target_id_prefix}
            push.{target_id_suffix}
            # => [target_id_suffix, target_id_prefix, exec_hint]
            exec.network_account_target::new
            # => [attachment_scheme, NOTE_ATTACHMENT]
            exec.network_account_target::is_network_account_target
            # => [is_valid, NOTE_ATTACHMENT]
            assert.err=ERR_NOT_NETWORK_ACCOUNT_TARGET
            # => [NOTE_ATTACHMENT]
            exec.network_account_target::into_target_id
            # => [target_id_suffix, target_id_prefix]
            # cleanup stack
            movup.2 drop movup.2 drop
        end
        "#,
        target_id_prefix = target_id.prefix().as_felt(),
        target_id_suffix = target_id.suffix(),
        exec_hint = Felt::from(exec_hint),
    );

    let exec_output = CodeExecutor::with_default_host().run(&source).await?;

    assert_eq!(exec_output.stack[0], target_id.suffix());
    assert_eq!(exec_output.stack[1], target_id.prefix().as_felt());

    Ok(())
}
