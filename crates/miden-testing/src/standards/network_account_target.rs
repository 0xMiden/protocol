//! Tests for the `miden::standards::attachments::network_account_target` module.

use miden_protocol::Felt;
use miden_protocol::account::AccountStorageMode;
use miden_protocol::note::{NoteAttachment, NoteMetadata, NoteTag, NoteType};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};

use crate::executor::CodeExecutor;

#[tokio::test]
async fn network_account_target_get_id() -> anyhow::Result<()> {
    let target_id = AccountIdBuilder::new()
        .storage_mode(AccountStorageMode::Network)
        .build_with_rng(&mut rand::rng());
    let exec_hint = NoteExecutionHint::Always;

    let attachment = NoteAttachment::from(NetworkAccountTarget::new(target_id, exec_hint)?);
    let metadata = NoteMetadata::new(target_id, NoteType::Public)
        .with_tag(NoteTag::with_account_target(target_id))
        .with_attachment(attachment.clone());
    let metadata_header = metadata.to_header_word();

    let source = format!(
        r#"
        use miden::standards::attachments::network_account_target
        use miden::protocol::note

        const ERR_NOT_NETWORK_ACCOUNT_TARGET = "attachment is not a valid network account target"

        begin
            push.{attachment_word}
            push.{metadata_header}
            exec.note::metadata_into_attachment_info
            # => [attachment_kind, attachment_scheme, NOTE_ATTACHMENT]
            swap
            # => [attachment_scheme, attachment_kind, NOTE_ATTACHMENT]
            exec.network_account_target::is_network_account_target
            # => [is_valid, NOTE_ATTACHMENT]
            assert.err=ERR_NOT_NETWORK_ACCOUNT_TARGET
            # => [NOTE_ATTACHMENT]
            exec.network_account_target::get_id
            # => [account_id_suffix, account_id_prefix]
            # cleanup stack
            movup.2 drop movup.2 drop
        end
        "#,
        metadata_header = metadata_header,
        attachment_word = attachment.content().to_word(),
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
    let attachment_word = attachment.content().to_word();
    let expected_attachment_kind = Felt::from(attachment.attachment_kind().as_u8());

    let source = format!(
        r#"
        use miden::standards::attachments::network_account_target

        begin
            push.{exec_hint}
            push.{target_id_prefix}
            push.{target_id_suffix}
            # => [target_id_suffix, target_id_prefix, exec_hint]
            exec.network_account_target::new
            # => [attachment_scheme, attachment_kind, ATTACHMENT, pad(16)]

            # cleanup stack
            swapdw dropw dropw
        end
        "#,
        target_id_prefix = target_id.prefix().as_felt(),
        target_id_suffix = target_id.suffix(),
        exec_hint = Felt::from(exec_hint),
    );

    let exec_output = CodeExecutor::with_default_host().run(&source).await?;

    assert_eq!(exec_output.stack[0], expected_attachment_kind);
    assert_eq!(
        exec_output.stack[1],
        Felt::from(NetworkAccountTarget::ATTACHMENT_SCHEME.as_u32())
    );

    let word = exec_output.stack.get_word(2).unwrap();
    assert_eq!(word, attachment_word);

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
            # => [attachment_scheme, attachment_kind, ATTACHMENT]
            exec.network_account_target::is_network_account_target
            # => [is_valid, ATTACHMENT]
            assert.err=ERR_NOT_NETWORK_ACCOUNT_TARGET
            # => [ATTACHMENT]
            exec.network_account_target::get_id
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
