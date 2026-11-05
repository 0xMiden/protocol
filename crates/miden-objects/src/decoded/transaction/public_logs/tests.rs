use alloc::vec;

use miden_protocol::transaction::TransactionLogError;
use rstest::rstest;

use super::*;
use crate::test_utils::error_source;

fn logged_owners() -> (miden_protocol::batch::ProvenBatch, miden_protocol::block::BlockBody) {
    use miden_protocol::Word;
    use miden_protocol::account::{AccountId, AccountPatch, AccountUpdateDetails};
    use miden_protocol::batch::{BatchAccountUpdate, ProvenBatch};
    use miden_protocol::block::BlockBody;
    use miden_protocol::block::code_tree::CodePatch;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    };
    use miden_protocol::testing::dummy_execution_proof;
    use miden_protocol::transaction::{
        InputNotes,
        OrderedTransactionHeaders,
        PublicTransactionLogs,
        TransactionHeader,
        TransactionLog,
        TransactionLogs,
    };
    let public: AccountId = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap();
    let private: AccountId = ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap();
    let log = TransactionLog::mock(1);
    let logs = TransactionLogs::new(vec![log.clone(), log]).unwrap();
    let headers = OrderedTransactionHeaders::new_unchecked(vec![
        TransactionHeader::new(
            public,
            Word::from([1u32; 4]),
            Word::from([2u32; 4]),
            InputNotes::default(),
            vec![],
            logs.commitment(),
            CodePatch::default().commitment(),
        )
        .unwrap(),
        TransactionHeader::new(
            private,
            Word::from([4u32; 4]),
            Word::from([5u32; 4]),
            InputNotes::default(),
            vec![],
            Word::from([99u32; 4]),
            CodePatch::default().commitment(),
        )
        .unwrap(),
        TransactionHeader::new(
            public,
            Word::from([2u32; 4]),
            Word::from([3u32; 4]),
            InputNotes::default(),
            vec![],
            Word::empty(),
            CodePatch::default().commitment(),
        )
        .unwrap(),
    ]);
    let public_logs = PublicTransactionLogs::new(
        vec![
            (headers.as_slice()[0].id(), logs),
            (headers.as_slice()[2].id(), TransactionLogs::default()),
        ],
        headers.as_slice().iter(),
    )
    .unwrap();
    let updates = vec![
        BatchAccountUpdate::new(
            public,
            Word::from([1u32; 4]),
            Word::from([3u32; 4]),
            AccountUpdateDetails::Public(AccountPatch::empty(public)),
        )
        .unwrap(),
        BatchAccountUpdate::new(
            private,
            Word::from([4u32; 4]),
            Word::from([5u32; 4]),
            AccountUpdateDetails::Private,
        )
        .unwrap(),
    ];
    let batch = ProvenBatch::new(
        Word::empty(),
        0.into(),
        updates,
        InputNotes::default(),
        vec![],
        1.into(),
        headers.clone(),
        public_logs.clone(),
        dummy_execution_proof(),
    )
    .unwrap();
    let grouped_headers = vec![
        OrderedTransactionHeaders::new_unchecked(headers.as_slice()[..2].to_vec()),
        OrderedTransactionHeaders::new_unchecked(headers.as_slice()[2..].to_vec()),
    ];
    let body = BlockBody::new(vec![], vec![], vec![], grouped_headers, public_logs).unwrap();
    (batch, body)
}

#[test]
fn embedded_logs_roundtrip_preserves_mixed_owners() {
    use prost::Message;

    use crate::DecodeMessageExt;
    let (batch, body) = logged_owners();
    let wire = proto::transaction::ProvenBatch::from(&batch);
    let decoded = proto::transaction::ProvenBatch::decode(wire.encode_to_vec().as_slice())
        .unwrap()
        .decode_and_build_unchecked()
        .unwrap();
    assert_eq!(batch, decoded);
    let wire = proto::blockchain::BlockBody::from(&body);
    let decoded = proto::blockchain::BlockBody::decode(wire.encode_to_vec().as_slice())
        .unwrap()
        .decode_and_build_unchecked()
        .unwrap();
    assert_eq!(body, decoded);
    let entries = &wire.public_logs.unwrap().entries;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].logs.as_ref().unwrap().logs.len(), 2);
    assert!(entries[1].logs.as_ref().unwrap().logs.is_empty());
    // A private transaction's commitment stays in its header and has no payload entry.
    assert!(entries.iter().all(
        |entry| entry.transaction_id != Some(body.transactions()[0].as_slice()[1].id().into())
    ));
}

#[rstest]
#[case::missing(0)]
#[case::missing_empty(1)]
#[case::reordered(2)]
#[case::duplicated(3)]
#[case::private_entry(4)]
#[case::content_changed(5)]
fn tampered_embedded_logs_are_rejected(#[case] mutation: u8) {
    use prost::Message;

    use crate::DecodeMessageExt;
    let (batch, body) = logged_owners();
    let mut wire_batch = proto::transaction::ProvenBatch::from(&batch);
    let entries = &mut wire_batch.public_logs.as_mut().unwrap().entries;
    match mutation {
        0 => entries.clear(),
        1 => {
            entries.pop();
        },
        2 => entries.swap(0, 1),
        3 => entries[1] = entries[0].clone(),
        4 => {
            let mut entry = entries[0].clone();
            entry.transaction_id = Some(batch.transactions().as_slice()[1].id().into());
            entries.insert(1, entry);
        },
        5 => entries[0].logs.as_mut().unwrap().logs[0].content.clear(),
        _ => unreachable!(),
    }
    let mut wire_body = proto::blockchain::BlockBody::from(&body);
    wire_body.public_logs = wire_batch.public_logs.clone();
    let errors = [
        proto::transaction::ProvenBatch::decode(wire_batch.encode_to_vec().as_slice())
            .unwrap()
            .decode_and_build_unchecked()
            .unwrap_err(),
        proto::blockchain::BlockBody::decode(wire_body.encode_to_vec().as_slice())
            .unwrap()
            .decode_and_build_unchecked()
            .unwrap_err(),
    ];
    for error in errors {
        let source = error_source::<TransactionLogError>(&error).unwrap();
        if mutation == 5 {
            assert!(matches!(source, TransactionLogError::PublicLogsCommitmentMismatch));
        } else {
            assert!(matches!(source, TransactionLogError::PublicLogsAssociationMismatch));
        }
    }
}

#[test]
fn checked_owners_revalidate_public_log_associations() {
    use miden_protocol::batch::ProvenBatch;
    use miden_protocol::block::BlockBody;
    use miden_protocol::errors::{BlockBodyError, ProvenBatchError};
    use miden_protocol::transaction::PublicTransactionLogs;
    let (batch, body) = logged_owners();
    // An empty collection is valid in isolation but not for these public headers.
    let result = BlockBody::new(
        vec![],
        vec![],
        vec![],
        body.transactions().to_vec(),
        PublicTransactionLogs::default(),
    );
    assert!(matches!(
        result,
        Err(BlockBodyError::TransactionLogs(
            TransactionLogError::PublicLogsAssociationMismatch
        ))
    ));
    let result = ProvenBatch::new(
        batch.reference_block_commitment(),
        batch.reference_block_num(),
        batch.account_updates().values().cloned(),
        batch.input_notes().clone(),
        batch.output_notes().to_vec(),
        batch.batch_expiration_block_num(),
        batch.transactions().clone(),
        PublicTransactionLogs::default(),
        batch.proof().clone(),
    );
    assert!(matches!(
        result,
        Err(ProvenBatchError::TransactionLogs(
            TransactionLogError::PublicLogsAssociationMismatch
        ))
    ));
}
