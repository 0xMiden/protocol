use alloc::vec;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_protocol::Felt;
use miden_protocol::account::{
    AccountCodePatch,
    AccountHeader,
    AccountPatch,
    AccountStoragePatch,
    AccountVaultPatch,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::block::code_tree::CodePatch;
use miden_protocol::errors::ExecutedTransactionError;
use miden_protocol::note::{Note, PartialNote};
use miden_protocol::transaction::{
    ExecutedTransaction,
    LogTopic,
    RawOutputNote,
    RawOutputNotes,
    TransactionLog,
    TransactionLogs,
    TransactionMeasurements,
    TransactionOutputs,
};
use prost::Message;

use crate::decoded::account::test_utils::dummy_account_id;
use crate::decoded::transaction::inputs::tests::common::dummy_transaction_inputs;
use crate::test_utils::{dummy_word, error_source};
use crate::{BuildUnchecked, DecodeMessage, proto};

fn executed_transaction() -> anyhow::Result<ExecutedTransaction> {
    let tx_inputs = dummy_transaction_inputs();
    let final_account = AccountHeader::from(tx_inputs.account());
    let account_id = final_account.id();
    let account_patch = AccountPatch::new(
        account_id,
        AccountStoragePatch::default(),
        AccountVaultPatch::default(),
        AccountCodePatch::default(),
        Some(final_account.nonce() + Felt::ONE),
    )?;
    let output_notes = RawOutputNotes::new(vec![
        RawOutputNote::Full(Note::mock_noop(dummy_word(1))),
        RawOutputNote::Partial(PartialNote::from(Note::mock_noop(dummy_word(2)))),
    ])?;
    let logs = TransactionLogs::new(vec![TransactionLog::new(
        account_id,
        LogTopic::from_name("test::updated"),
        vec![dummy_word(3)],
    )?])?;
    let measurements = TransactionMeasurements::builder()
        .prologue(1)
        .notes_processing(2)
        .note_execution(tx_inputs.input_notes().iter().map(|note| (note.id(), 3)).collect())
        .tx_script_processing(4)
        .epilogue(5)
        .auth_procedure(6)
        .build()?;
    let tx_outputs = TransactionOutputs::new(
        final_account,
        account_patch.to_commitment(),
        output_notes,
        BlockNumber::from(42_u32),
        logs,
        CodePatch::mock(),
    );

    Ok(ExecutedTransaction::new(tx_inputs, tx_outputs, account_patch, measurements)?)
}

#[test]
fn executed_transaction_roundtrips() -> anyhow::Result<()> {
    let transaction = executed_transaction()?;

    let encoded = proto::transaction::ExecutedTransaction::from(&transaction).encode_to_vec();
    let message = proto::transaction::ExecutedTransaction::decode(encoded.as_slice())?;

    assert_eq!(message.decode_fields()?.build_unchecked()?, transaction);

    Ok(())
}

#[test]
fn executed_transaction_rejects_different_final_account() -> anyhow::Result<()> {
    let mut message = proto::transaction::ExecutedTransactionV1::from(&executed_transaction()?);
    message.final_account.as_mut().context("final account is missing")?.account_id =
        Some(dummy_account_id(8).into());

    let error = message.decode_fields()?.build_unchecked().unwrap_err();
    assert_matches!(
        error_source::<ExecutedTransactionError>(&error),
        Some(ExecutedTransactionError::InconsistentAccountId { .. })
    );

    Ok(())
}
