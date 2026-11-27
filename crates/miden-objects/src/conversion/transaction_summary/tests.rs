use alloc::vec;
use core::num::TryFromIntError;

use assert_matches::assert_matches;
use miden_protocol::Felt;
use miden_protocol::account::{
    AccountCodePatch,
    AccountDelta,
    AccountStoragePatch,
    AccountVaultDelta,
};
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::TransactionSummaryError;
use miden_protocol::note::{Note, PartialNote};
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    LogTopic,
    RawOutputNote,
    RawOutputNotes,
    TransactionLog,
    TransactionLogs,
    TransactionSummary,
    TransactionSummaryUserParams,
};
use prost::Message;

use crate::decoded::account::test_utils::private_account_id;
use crate::test_utils::{dummy_word, error_source};
use crate::{DecodeMessage, Verify, proto};

fn transaction_summary() -> anyhow::Result<TransactionSummary> {
    let account_id = private_account_id();
    let account_delta = AccountDelta::new(
        account_id,
        AccountStoragePatch::default(),
        AccountVaultDelta::default(),
        AccountCodePatch::default(),
        Felt::ONE,
    )?;
    let input_notes =
        InputNotes::new(vec![InputNote::unauthenticated(Note::mock_noop(dummy_word(1)))])?;
    let output_notes = RawOutputNotes::new(vec![
        RawOutputNote::Full(Note::mock_noop(dummy_word(2))),
        RawOutputNote::Partial(PartialNote::from(Note::mock_noop(dummy_word(3)))),
    ])?;
    let logs = TransactionLogs::new(vec![TransactionLog::new(
        account_id,
        LogTopic::from_name("test::updated"),
        vec![dummy_word(4)],
    )?])?;

    Ok(TransactionSummary::new(
        account_delta,
        input_notes,
        output_notes,
        BlockNumber::from(17_u32),
        dummy_word(5),
        u16::MAX,
        TransactionSummaryUserParams::new([1_u32, 2, 3, 4, 5, 6].map(Felt::from)),
        logs,
    ))
}

#[test]
fn transaction_summary_roundtrips() -> anyhow::Result<()> {
    let summary = transaction_summary()?;

    let encoded = proto::transaction::TransactionSummary::from(&summary).encode_to_vec();
    let message = proto::transaction::TransactionSummary::decode(encoded.as_slice())?;
    let decoded = message.decode_fields()?.verify()?;

    assert_eq!(decoded.to_commitment(), summary.to_commitment());
    assert_eq!(decoded, summary);

    Ok(())
}

#[test]
fn transaction_summary_rejects_expiration_delta_above_u16() -> anyhow::Result<()> {
    let mut message = proto::transaction::TransactionSummaryV1::from(&transaction_summary()?);
    message.expiration_delta = u32::from(u16::MAX) + 1;

    let error = message.decode_fields()?.verify().unwrap_err();
    assert_matches!(error_source::<TryFromIntError>(&error), Some(_));

    Ok(())
}

#[test]
fn transaction_summary_rejects_missing_user_param() -> anyhow::Result<()> {
    let mut message = proto::transaction::TransactionSummaryV1::from(&transaction_summary()?);
    message.user_params.pop();

    let error = message.decode_fields()?.verify().unwrap_err();
    assert_matches!(
        error_source::<TransactionSummaryError>(&error),
        Some(TransactionSummaryError::InvalidUserParamsLength { .. })
    );

    Ok(())
}
