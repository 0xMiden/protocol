use alloc::string::ToString;
use alloc::vec;

use miden_protocol::Word;
use miden_protocol::note::Note;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use prost::Message;

use super::NoteMetadataError;
use crate::test_utils::error_source;
use crate::{ConversionError, DecodeMessage, Verify, proto};

#[test]
fn account_id_verification_is_deferred_in_parents() {
    use miden_protocol::errors::AccountIdError;

    let metadata = *miden_protocol::note::Note::mock_noop(Word::empty()).metadata();
    let mut wire = proto::note::NoteMetadata::from(metadata);
    let sender = wire.sender.as_mut().unwrap();
    let proto::account::account_id::Version::V1(v1) = sender.version.as_mut().unwrap();
    v1.prefix.as_mut().unwrap().value &= !0xf;

    let decoded = (*sender).decode_fields().unwrap();
    assert!(matches!(decoded.verify(), Err(AccountIdError::UnknownAccountIdVersion(0))));
    let decoded = wire.decode_fields().unwrap();
    assert!(matches!(
        error_source::<AccountIdError>(&decoded.verify().unwrap_err()),
        Some(AccountIdError::UnknownAccountIdVersion(0))
    ));
}

#[test]
fn note_id_verifies() {
    let decoded = proto::note::NoteId { id: Some(Word::empty().into()) }.decode_fields().unwrap();
    assert_eq!(decoded.verify().unwrap(), miden_protocol::note::NoteId::from_raw(Word::empty()));
}

#[test]
fn note_storage_defers_length_validation() {
    let decoded = proto::note::NoteStorage {
        items: vec![miden_protocol::Felt::ZERO.into(); miden_protocol::MAX_NOTE_STORAGE_ITEMS + 1],
    }
    .decode_fields()
    .unwrap();
    assert!(decoded.verify().is_err());
}

#[test]
fn attachment_defers_scheme_validation() {
    let decoded = proto::note::NoteAttachment { scheme: u32::MAX, words: vec![] }
        .decode_fields()
        .unwrap();
    assert!(decoded.verify().is_err());
}

#[test]
fn attachments_defer_nested_verification() {
    let decoded = proto::note::NoteAttachments {
        attachments: vec![proto::note::NoteAttachment { scheme: u32::MAX, words: vec![] }],
    }
    .decode_fields()
    .unwrap();
    let error = decoded.verify().unwrap_err();
    assert!(error.to_string().starts_with("attachments[0]:"), "{error}");
    assert!(error_source::<core::num::TryFromIntError>(&error).is_some());
}

#[test]
fn note_script_defers_entrypoint_validation() {
    let decoded = proto::note::NoteScript {
        entrypoint: 1,
        mast: Some(miden_protocol::MastForest::new().into()),
    }
    .decode_fields()
    .unwrap();
    assert!(decoded.verify().is_err());
}

#[test]
fn note_recipient_defers_nested_script_verification() {
    let decoded = proto::note::NoteRecipient {
        serial_num: Some(Word::empty().into()),
        script: Some(proto::note::NoteScript {
            entrypoint: 1,
            mast: Some(miden_protocol::MastForest::new().into()),
        }),
        storage: Some(proto::note::NoteStorage { items: vec![] }),
    }
    .decode_fields()
    .unwrap();
    assert!(decoded.verify().is_err());
}

#[test]
fn note_inclusion_proof_defers_index_and_path_checks() {
    let id = miden_protocol::note::NoteId::from_raw(Word::empty());
    let wire = proto::note::NoteInclusionProof {
        note_id: Some((&id).into()),
        block_num: Some(miden_protocol::block::BlockNumber::from(0_u32).into()),
        note_index_in_block: u32::MAX,
        inclusion_path: Some(proto::primitives::SparseMerklePath {
            empty_nodes_mask: 0,
            siblings: vec![],
        }),
    };
    let decoded = wire.decode_fields().unwrap();
    assert_eq!(decoded.note_index_in_block, u32::MAX);
    assert!(decoded.verify().is_err());
}

#[test]
fn note_metadata_decodes_named_enums_and_defers_attachment_checks() {
    let metadata = *miden_protocol::note::Note::mock_noop(Word::empty()).metadata();
    let wire = proto::note::NoteMetadata::from(metadata);
    let decoded = wire.clone().decode_fields().unwrap();
    assert_eq!(decoded.version, proto::note::NoteVersion::V1);
    assert_eq!(decoded.note_type, proto::note::NoteType::Private);
    assert_eq!(decoded.verify().unwrap(), metadata);
    for attachment_schemes in
        [vec![u32::MAX], vec![0; miden_protocol::note::NoteAttachments::MAX_COUNT + 1]]
    {
        let decoded = proto::note::NoteMetadata { attachment_schemes, ..wire.clone() }
            .decode_fields()
            .unwrap();
        assert!(decoded.verify().is_err());
    }
    let decoded = proto::note::NoteMetadata { note_type: 0, ..wire }.decode_fields().unwrap();
    assert_eq!(decoded.note_type, proto::note::NoteType::Unspecified);
    assert!(decoded.verify().is_err());
}

#[test]
fn note_header_rejects_sparse_attachment_schemes_before_changing_its_id() {
    // A zero before a present scheme changes positions when native serialization
    // compacts the headers, changing the committed metadata word and note ID.
    let header = *Note::mock_noop(Word::empty()).header();
    for schemes in [vec![0, 1], vec![1, 0, 2], vec![0, 0, 1]] {
        let mut wire = proto::note::NoteHeader::from(header);
        wire.metadata.as_mut().unwrap().attachment_schemes = schemes;
        let bytes = wire.encode_to_vec();
        let decoded_wire = proto::note::NoteHeader::decode(bytes.as_slice()).unwrap();
        let error = decoded_wire.decode_fields().unwrap().verify().unwrap_err();
        assert!(
            matches!(
                error_source::<NoteMetadataError>(&error),
                Some(NoteMetadataError::SparseAttachmentSchemes)
            ),
            "sparse attachment schemes must be rejected: {error}"
        );
    }
}

#[test]
fn note_header_accepts_dense_attachment_schemes_with_trailing_zeros() {
    // Canonical protobuf encoders emit all four positions, including absent
    // trailing headers. Those must remain valid and stable across native I/O.
    let header = *Note::mock_noop(Word::empty()).header();
    for schemes in [
        vec![],
        vec![0],
        vec![0, 0, 0, 0],
        vec![1],
        vec![1, 0],
        vec![1, 0, 0, 0],
        vec![1, 2, 0, 0],
    ] {
        let mut wire = proto::note::NoteHeader::from(header);
        wire.metadata.as_mut().unwrap().attachment_schemes = schemes;
        let verified = wire.decode_fields().unwrap().verify().unwrap();
        let roundtripped =
            miden_protocol::note::NoteHeader::read_from_bytes(&verified.to_bytes()).unwrap();
        assert_eq!(roundtripped, verified);
        assert_eq!(roundtripped.id(), verified.id());
    }
}

#[test]
fn note_header_defers_metadata_verification() {
    let header = *miden_protocol::note::Note::mock_noop(Word::empty()).header();
    let mut wire = proto::note::NoteHeader::from(header);
    assert_eq!(wire.clone().decode_fields().unwrap().verify().unwrap(), header);
    wire.metadata.as_mut().unwrap().note_type = 0;
    assert!(wire.decode_fields().unwrap().verify().is_err());
}

#[test]
fn note_metadata_protobuf_rejects_unspecified_version_after_decoding() {
    let error = proto::note::NoteMetadata {
        version: proto::note::NoteVersion::Unspecified as i32,
        ..proto::note::NoteMetadata::from(*Note::mock_noop(Word::empty()).metadata())
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new)
    .unwrap_err();

    assert_eq!(error.to_string(), "note metadata version is unspecified");
}

#[test]
fn note_protobuf_rejects_unspecified_metadata_version_after_decoding() {
    let mut message = proto::note::Note::from(Note::mock_noop(Word::empty()));
    message.metadata.as_mut().unwrap().version = proto::note::NoteVersion::Unspecified as i32;
    let error = message
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();
    assert_eq!(error.to_string(), "note metadata version is unspecified");
}
