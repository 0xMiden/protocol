use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::AccountUpdateDetails;
use miden_protocol::batch::BatchAccountUpdate;
use miden_protocol::note::{Note, NoteType, PartialNoteMetadata};
use miden_protocol::transaction::{PublicOutputNote, TransactionArgs};
use miden_protocol::vm::AdviceInputs;
use miden_protocol::{Felt, Word};
use prost::Message;

use crate::decoded::account::test_utils::private_account_id;
use crate::decoded::transaction::test_utils::note_id;
use crate::test_utils::dummy_word;
use crate::{DecodeMessage, Verify, proto};

fn public_note() -> Note {
    let (assets, metadata, recipient, attachments) = Note::mock_noop(Word::empty()).into_parts();
    let metadata =
        PartialNoteMetadata::new(metadata.sender(), NoteType::Public).with_tag(metadata.tag());

    Note::with_attachments(assets, metadata, recipient, attachments)
}

#[test]
fn public_output_note_roundtrips_through_protobuf() {
    let note = PublicOutputNote::new(public_note()).unwrap();

    let encoded = proto::transaction::PublicOutputNote::from(note.clone()).encode_to_vec();
    let message = proto::transaction::PublicOutputNote::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), note);
}

#[test]
fn account_update_roundtrips_through_protobuf_bytes() {
    let update = BatchAccountUpdate::new(
        private_account_id(),
        Word::from([1_u32, 2, 3, 4]),
        Word::from([5_u32, 6, 7, 8]),
        AccountUpdateDetails::Private,
    )
    .unwrap();

    let encoded = proto::transaction::BatchAccountUpdate::from(&update).encode_to_vec();
    let message = proto::transaction::BatchAccountUpdate::decode(encoded.as_slice()).unwrap();
    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), update);
}

#[test]
fn transaction_args_roundtrip_normalizes_note_args_order() {
    let first = note_id(1);
    let second = note_id(2);
    let args = TransactionArgs::from_parts(
        None,
        dummy_word(3),
        BTreeMap::from([(second, dummy_word(4)), (first, dummy_word(5))]),
        AdviceInputs::default().with_map([(dummy_word(6), vec![Felt::from(7_u32)])]),
        dummy_word(8),
    );

    let message = proto::transaction::TransactionArgs::from(&args);

    assert_eq!(
        message
            .note_args
            .iter()
            .map(|entry| entry.note_id.clone().unwrap().decode_fields().unwrap().verify().unwrap())
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), args);
}

#[test]
fn submitted_logs_and_headers_roundtrip_without_private_records() {
    use miden_protocol::account::{
        AccountId,
        AccountIdVersion,
        AccountPatch,
        AccountType,
        AssetCallbackFlag,
    };
    use miden_protocol::transaction::{
        InputNoteCommitment,
        LogTopic,
        OutputNote,
        ProvenTransaction,
        TransactionHeader,
        TransactionLog,
        TransactionLogData,
        TransactionLogs,
        TxAccountUpdate,
    };

    use crate::BuildUnchecked;

    for account_type in [AccountType::Public, AccountType::Private] {
        let account = AccountId::dummy(
            [73; 15],
            AccountIdVersion::Version1,
            account_type,
            AssetCallbackFlag::Disabled,
        );
        let patch = AccountPatch::empty(account);
        let patch_commitment = patch.to_commitment();
        let details = if account_type.is_public() {
            AccountUpdateDetails::Public(patch)
        } else {
            AccountUpdateDetails::Private
        };
        let logs = TransactionLogs::new(vec![
            TransactionLog::new(
                account,
                LogTopic::from_name("example::updated"),
                vec![dummy_word(731)],
            )
            .unwrap(),
        ])
        .unwrap();
        let salt = dummy_word(913);
        let data = if account_type.is_public() {
            TransactionLogData::Public(logs.clone())
        } else {
            TransactionLogData::Private(logs.commitment_for_account(account, salt).unwrap())
        };
        let update =
            TxAccountUpdate::new(account, dummy_word(1), dummy_word(2), patch_commitment, details)
                .unwrap();
        let tx = ProvenTransaction::new(
            update,
            Vec::<InputNoteCommitment>::new(),
            Vec::<OutputNote>::new(),
            2u32.into(),
            dummy_word(3),
            3u32.into(),
            miden_protocol::testing::dummy_execution_proof(),
        )
        .unwrap()
        .with_log_data(data)
        .unwrap();
        let message = proto::transaction::ProvenTransaction::from(&tx);
        assert_eq!(message.decode_fields().unwrap().build_unchecked().unwrap(), tx);
        let header = TransactionHeader::from(&tx);
        let message = proto::transaction::TransactionHeader::from(&header);
        assert_eq!(message.decode_fields().unwrap().build_unchecked().unwrap(), header);
        if account_type.is_private() {
            use miden_protocol::utils::serde::Serializable;
            let bytes = proto::transaction::ProvenTransaction::from(&tx).encode_to_vec();
            for secret in [logs.to_bytes(), salt.to_bytes()] {
                assert!(!bytes.windows(secret.len()).any(|window| window == secret));
            }
        }
    }
}

#[test]
fn raw_output_notes_roundtrip_through_protobuf() {
    use miden_protocol::note::PartialNote;
    use miden_protocol::transaction::{RawOutputNote, RawOutputNotes};

    let full = RawOutputNote::Full(public_note());
    let partial = RawOutputNote::Partial(PartialNote::from(Note::mock_noop(dummy_word(7))));
    let notes = RawOutputNotes::new(vec![full, partial]).unwrap();

    let encoded = proto::transaction::RawOutputNotes::from(&notes).encode_to_vec();
    let message = proto::transaction::RawOutputNotes::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), notes);
}
