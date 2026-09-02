use core::error::Error;

use miden_objects::conversion::decode_standalone_proven_batch;
use miden_objects::{ConversionError, proto};
use miden_protocol::account::{
    AccountHeader,
    AccountId,
    AccountIdVersion,
    AccountPatch,
    AccountStorageHeader,
    AccountStoragePatch,
    AccountType,
    AccountUpdateDetails,
    AccountVaultPatch,
    AssetCallbackFlag,
    StorageMapPatch,
    StorageSlotHeader,
    StorageSlotName,
    StorageSlotPatch,
    StorageSlotType,
    StorageValuePatch,
};
use miden_protocol::asset::{
    Asset,
    AssetClass,
    AssetComposition as ProtocolAssetComposition,
    AssetId,
    FungibleAsset,
    NonFungibleAsset,
};
use miden_protocol::batch::BatchAccountUpdate;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{
    BlockAccountUpdate,
    BlockBody,
    BlockHeader,
    BlockNumber,
    ValidatorConfig,
};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::errors::{
    AccountIdError,
    AssetError,
    OutputNoteError,
    ProtocolConfigError,
    TransactionHeaderError,
    ValidatorConfigError,
};
use miden_protocol::note::{
    Note,
    NoteId,
    NoteInclusionProof,
    NoteMetadata,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::protocol_config::NextProtocolConfig;
use miden_protocol::transaction::{
    InputNotes,
    OrderedTransactionHeaders,
    ProvenTransaction,
    PublicOutputNote,
    TransactionHeader,
    TxAccountUpdate,
};
use miden_protocol::vm::ExecutionProof;
use miden_protocol::{Felt, Word};
use prost::Message;

#[test]
fn protobuf_descriptor_includes_structured_asset_schema() {
    assert!(
        miden_objects::FILE_DESCRIPTOR_SET
            .windows(b"asset.proto".len())
            .any(|window| window == b"asset.proto")
    );
}

#[test]
fn fungible_asset_roundtrips_through_structured_protobuf() {
    let asset = FungibleAsset::mock(42);

    let encoded = proto::asset::Asset::from(asset);

    assert_eq!(
        encoded.asset_id.as_ref().unwrap().composition,
        proto::asset::AssetComposition::Fungible as i32
    );
    assert_eq!(Asset::try_from(encoded).unwrap(), asset);
}

#[test]
fn non_fungible_asset_roundtrips_through_structured_protobuf() {
    let asset = NonFungibleAsset::mock(&[1, 2, 3]);

    let encoded = proto::asset::Asset::from(asset);

    assert_eq!(
        encoded.asset_id.as_ref().unwrap().composition,
        proto::asset::AssetComposition::None as i32
    );
    assert_eq!(Asset::try_from(encoded).unwrap(), asset);
}

#[test]
fn structured_asset_conversion_requires_message_fields() {
    let suffix_error = AssetClass::try_from(proto::asset::AssetClass {
        suffix: None,
        prefix: Some(Felt::ZERO.into()),
    })
    .unwrap_err();
    assert_eq!(
        suffix_error.to_string(),
        "field miden_objects::proto::asset::AssetClass::suffix is missing"
    );

    let prefix_error = AssetClass::try_from(proto::asset::AssetClass {
        suffix: Some(Felt::ZERO.into()),
        prefix: None,
    })
    .unwrap_err();
    assert_eq!(
        prefix_error.to_string(),
        "field miden_objects::proto::asset::AssetClass::prefix is missing"
    );

    let asset_id_error = AssetId::try_from(proto::asset::AssetId::default()).unwrap_err();
    assert!(asset_id_error.to_string().ends_with("::asset_class is missing"));

    let faucet_id_error = AssetId::try_from(proto::asset::AssetId {
        asset_class: Some(proto::asset::AssetClass {
            suffix: Some(Felt::ZERO.into()),
            prefix: Some(Felt::ZERO.into()),
        }),
        composition: proto::asset::AssetComposition::Fungible as i32,
        faucet_id: None,
    })
    .unwrap_err();
    assert!(faucet_id_error.to_string().ends_with("::faucet_id is missing"));

    let asset_error = Asset::try_from(proto::asset::Asset::default()).unwrap_err();
    assert!(asset_error.to_string().ends_with("::asset_id is missing"));

    let value_error = Asset::try_from(proto::asset::Asset {
        asset_id: Some(proto::asset::AssetId {
            asset_class: Some(proto::asset::AssetClass {
                suffix: Some(Felt::ZERO.into()),
                prefix: Some(Felt::ZERO.into()),
            }),
            composition: proto::asset::AssetComposition::Fungible as i32,
            faucet_id: Some(FungibleAsset::mock_issuer().into()),
        }),
        value: None,
    })
    .unwrap_err();
    assert!(value_error.to_string().ends_with("::value is missing"));
}

#[test]
fn structured_asset_conversion_rejects_unspecified_unknown_and_custom_compositions() {
    let asset_class = proto::asset::AssetClass {
        suffix: Some(Felt::ZERO.into()),
        prefix: Some(Felt::ZERO.into()),
    };
    let faucet_id = Some(FungibleAsset::mock_issuer().into());

    let unspecified = AssetId::try_from(proto::asset::AssetId {
        asset_class: Some(asset_class),
        composition: proto::asset::AssetComposition::Unspecified as i32,
        faucet_id: faucet_id.clone(),
    })
    .unwrap_err();
    assert_eq!(unspecified.to_string(), "composition: asset composition is unspecified");

    let unknown = AssetId::try_from(proto::asset::AssetId {
        asset_class: Some(asset_class),
        composition: 4,
        faucet_id: faucet_id.clone(),
    })
    .unwrap_err();
    assert_eq!(unknown.to_string(), "composition: unknown asset composition 4");

    let custom = AssetId::try_from(proto::asset::AssetId {
        asset_class: Some(asset_class),
        composition: proto::asset::AssetComposition::Custom as i32,
        faucet_id,
    })
    .unwrap_err();
    assert!(matches!(
        custom.source().and_then(|source| source.downcast_ref::<AssetError>()),
        Some(AssetError::UnsupportedAssetComposition(ProtocolAssetComposition::Custom))
    ));
}

#[test]
fn structured_asset_conversion_rejects_nonzero_fungible_class() {
    let error = AssetId::try_from(proto::asset::AssetId {
        asset_class: Some(proto::asset::AssetClass {
            suffix: Some(Felt::ONE.into()),
            prefix: Some(Felt::ZERO.into()),
        }),
        composition: proto::asset::AssetComposition::Fungible as i32,
        faucet_id: Some(FungibleAsset::mock_issuer().into()),
    })
    .unwrap_err();

    assert!(matches!(
        error.source().and_then(|source| source.downcast_ref::<AssetError>()),
        Some(AssetError::FungibleAssetClassMustBeZero(_))
    ));
}

#[test]
fn structured_asset_conversion_rejects_invalid_fungible_values() {
    let error = Asset::try_from(proto::asset::Asset {
        asset_id: Some(proto::asset::AssetId {
            asset_class: Some(proto::asset::AssetClass {
                suffix: Some(Felt::ZERO.into()),
                prefix: Some(Felt::ZERO.into()),
            }),
            composition: proto::asset::AssetComposition::Fungible as i32,
            faucet_id: Some(FungibleAsset::mock_issuer().into()),
        }),
        value: Some(Word::from([1_u32, 1, 0, 0]).into()),
    })
    .unwrap_err();

    assert!(matches!(
        error.source().and_then(|source| source.downcast_ref::<AssetError>()),
        Some(AssetError::FungibleAssetValueMostSignificantElementsMustBeZero(_))
    ));
}

#[test]
fn conversion_error_preserves_deserialization_error_source() {
    use miden_protocol::utils::serde::DeserializationError;

    let error = ConversionError::deserialization(
        "AccountId",
        DeserializationError::InvalidValue("invalid account id".into()),
    );

    assert_eq!(
        error.to_string(),
        "failed to deserialize AccountId: invalid value: invalid account id"
    );
    assert!(matches!(
        error
            .source()
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<DeserializationError>()),
        Some(DeserializationError::InvalidValue(message)) if message == "invalid account id"
    ));
}

fn private_account_id() -> AccountId {
    AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

fn account_witness(account_id: AccountId) -> AccountWitness {
    let path = SparseMerklePath::from_parts(u64::MAX, vec![]).unwrap();
    AccountWitness::new(account_id, Word::empty(), path).unwrap()
}

fn account_header() -> AccountHeader {
    AccountHeader::new(
        private_account_id(),
        Felt::ONE,
        Word::from([1_u32, 2, 3, 4]),
        Word::from([5_u32, 6, 7, 8]),
        Word::from([9_u32, 10, 11, 12]),
    )
}

fn account_patch() -> AccountPatch {
    AccountPatch::new(
        private_account_id(),
        AccountStoragePatch::from_entries([]).unwrap(),
        AccountVaultPatch::new([].into()).unwrap(),
        None,
        None,
    )
    .unwrap()
}

#[test]
fn account_witness_protobuf_round_trip() {
    let witness = account_witness(private_account_id());

    let message: proto::account::AccountWitness = (&witness).into();
    let decoded = AccountWitness::try_from(message).unwrap();

    assert_eq!(decoded, witness);
}

#[test]
fn account_witness_protobuf_requires_witness_id() {
    let error = AccountWitness::try_from(proto::account::AccountWitness {
        commitment: Some(Word::empty().into()),
        path: Some(proto::primitives::SparseMerklePath {
            empty_nodes_mask: u64::MAX,
            siblings: vec![],
        }),
        ..Default::default()
    })
    .unwrap_err();

    assert!(error.to_string().ends_with("::witness_id is missing"));
}

#[test]
fn account_witness_conversion_preserves_account_tree_error_source() {
    let account_id = private_account_id();
    let error = AccountWitness::try_from(proto::account::AccountWitness {
        witness_id: Some(account_id.into()),
        commitment: Some(Word::empty().into()),
        path: Some(proto::primitives::SparseMerklePath::default()),
    })
    .unwrap_err();

    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<miden_protocol::errors::AccountTreeError>()),
        Some(
            miden_protocol::errors::AccountTreeError::WitnessMerklePathDepthDoesNotMatchAccountTreeDepth(0)
        )
    ));
}

#[test]
fn account_id_protobuf_requires_exactly_15_bytes() {
    for id in [vec![0; AccountId::SERIALIZED_SIZE - 1], vec![0; AccountId::SERIALIZED_SIZE + 1]] {
        let error = AccountId::try_from(proto::account::AccountId { id }).unwrap_err();

        assert!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<core::array::TryFromSliceError>())
                .is_some()
        );
    }
}

#[test]
fn account_id_protobuf_rejects_invalid_metadata() {
    let mut id = <[u8; AccountId::SERIALIZED_SIZE]>::from(private_account_id());
    id[7] &= 0b1111_0000;

    let error = AccountId::try_from(proto::account::AccountId { id: id.into() }).unwrap_err();

    assert!(matches!(
        error.source().and_then(|source| source.downcast_ref::<AccountIdError>()),
        Some(AccountIdError::UnknownAccountIdVersion(0))
    ));
}

#[test]
fn account_header_roundtrips_through_explicit_versioned_protobuf_bytes() {
    let header = account_header();

    let encoded = proto::account::AccountHeader::from(&header).encode_to_vec();
    let message = proto::account::AccountHeader::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.version, proto::account::AccountVersion::V1 as i32);
    assert_eq!(AccountHeader::try_from(message).unwrap(), header);
}

#[test]
fn account_header_protobuf_rejects_unspecified_version_before_payload_fields() {
    let error = AccountHeader::try_from(proto::account::AccountHeader {
        version: proto::account::AccountVersion::Unspecified as i32,
        ..Default::default()
    })
    .unwrap_err();

    assert_eq!(error.to_string(), "version: account header version is unspecified");
}

#[test]
fn account_header_protobuf_preserves_unknown_version_error_sources() {
    for version in [i32::MAX, i32::MIN] {
        let error = AccountHeader::try_from(proto::account::AccountHeader {
            version,
            ..Default::default()
        })
        .unwrap_err();

        assert_eq!(error.to_string(), format!("version: unknown account header version {version}"));
        assert!(matches!(
            error
                .source()
                .and_then(Error::source)
                .and_then(|source| source.downcast_ref::<prost::UnknownEnumValue>()),
            Some(prost::UnknownEnumValue(value)) if *value == version
        ));
    }
}

#[test]
fn account_header_protobuf_preserves_invalid_nonce_source() {
    let error = AccountHeader::try_from(proto::account::AccountHeader {
        version: proto::account::AccountVersion::V1 as i32,
        account_id: Some(private_account_id().into()),
        vault_root: Some(Word::empty().into()),
        storage_commitment: Some(Word::empty().into()),
        code_commitment: Some(Word::empty().into()),
        nonce: Felt::ORDER,
    })
    .unwrap_err();

    assert!(error.to_string().starts_with("nonce: "));
    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<<Felt as TryFrom<u64>>::Error>()),
        Some(source) if source.as_u64() == Felt::ORDER
    ));
}

#[test]
fn account_patch_roundtrips_through_explicit_versioned_protobuf_bytes() {
    let patch = account_patch();

    let encoded = proto::account::AccountPatch::from(&patch).encode_to_vec();
    let message = proto::account::AccountPatch::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.version, proto::account::AccountPatchVersion::V1 as i32);
    assert_eq!(AccountPatch::try_from(message).unwrap(), patch);
}

#[test]
fn account_patch_protobuf_rejects_unspecified_version_before_payload_fields() {
    let error = AccountPatch::try_from(proto::account::AccountPatch {
        version: proto::account::AccountPatchVersion::Unspecified as i32,
        ..Default::default()
    })
    .unwrap_err();

    assert_eq!(error.to_string(), "version: account patch version is unspecified");
}

#[test]
fn account_patch_protobuf_preserves_unknown_version_error_sources() {
    for version in [i32::MAX, i32::MIN] {
        let error =
            AccountPatch::try_from(proto::account::AccountPatch { version, ..Default::default() })
                .unwrap_err();

        assert_eq!(error.to_string(), format!("version: unknown account patch version {version}"));
        assert!(matches!(
            error
                .source()
                .and_then(Error::source)
                .and_then(|source| source.downcast_ref::<prost::UnknownEnumValue>()),
            Some(prost::UnknownEnumValue(value)) if *value == version
        ));
    }
}

#[test]
fn note_metadata_roundtrips_through_v1_protobuf_bytes() {
    let metadata = *Note::mock_noop(Word::empty()).metadata();

    let encoded = proto::note::NoteMetadata::from(metadata).encode_to_vec();
    let message = proto::note::NoteMetadata::decode(encoded.as_slice()).unwrap();

    assert!(matches!(message.version, Some(proto::note::note_metadata::Version::V1(_))));
    assert_eq!(NoteMetadata::try_from(message).unwrap(), metadata);
}

#[test]
fn note_protobuf_roundtrips_through_versioned_note_metadata() {
    let note = Note::mock_noop(Word::empty());

    let encoded = proto::note::Note::from(note.clone()).encode_to_vec();
    let message = proto::note::Note::decode(encoded.as_slice()).unwrap();

    assert_eq!(Note::try_from(message).unwrap(), note);
}

#[test]
fn note_protobuf_requires_note_attachments() {
    let mut message = proto::note::Note::from(Note::mock_noop(Word::empty()));
    message.note_attachments = None;

    let error = Note::try_from(message).unwrap_err();

    assert_eq!(
        error.to_string(),
        "field miden_objects::proto::note::Note::note_attachments is missing"
    );
}

#[test]
fn note_protobuf_requires_note_details() {
    let mut message = proto::note::Note::from(Note::mock_noop(Word::empty()));
    message.note_details = None;

    let error = Note::try_from(message).unwrap_err();

    assert_eq!(
        error.to_string(),
        "field miden_objects::proto::note::Note::note_details is missing"
    );
}

#[test]
fn note_metadata_protobuf_requires_version() {
    let error = NoteMetadata::try_from(proto::note::NoteMetadata::default()).unwrap_err();

    assert!(error.to_string().ends_with("::version is missing"));
}

#[test]
fn note_metadata_v1_protobuf_reports_invalid_sender() {
    let metadata = *Note::mock_noop(Word::empty()).metadata();
    let mut message = proto::note::NoteMetadata::from(metadata);
    let Some(proto::note::note_metadata::Version::V1(v1)) = message.version.as_mut() else {
        panic!("note metadata should encode as v1");
    };
    v1.sender.as_mut().unwrap().id.clear();

    let error = NoteMetadata::try_from(message).unwrap_err();

    assert!(error.to_string().starts_with("v1.sender: "));
    assert!(
        error
            .source()
            .unwrap()
            .downcast_ref::<core::array::TryFromSliceError>()
            .is_some()
    );
}

fn assert_missing_block_number(error: ConversionError, field: &str) {
    let error = error.to_string();
    assert!(error.starts_with(&format!("{field}: field ")));
    assert!(error.ends_with(&format!("::{field} is missing")));
}

fn proven_transaction_data() -> proto::transaction::ProvenTransaction {
    let account_update = TxAccountUpdate::new(
        private_account_id(),
        Word::empty(),
        Word::from([1_u32, 0, 0, 0]),
        Word::empty(),
        AccountUpdateDetails::Private,
    )
    .unwrap();

    proto::transaction::ProvenTransaction {
        account_update: Some((&account_update).into()),
        input_notes: vec![],
        output_notes: vec![],
        reference_block_num: Some(proto::blockchain::BlockNumber { block_num: 1 }),
        reference_block_commitment: Some(Word::empty().into()),
        expiration_block_num: Some(proto::blockchain::BlockNumber { block_num: 2 }),
        proof: Some(ExecutionProof::new_dummy().into()),
    }
}

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

    assert_eq!(PublicOutputNote::try_from(message).unwrap(), note);
}

#[test]
fn public_output_note_protobuf_requires_nested_note() {
    let error =
        PublicOutputNote::try_from(proto::transaction::PublicOutputNote::default()).unwrap_err();

    assert_eq!(
        error.to_string(),
        "field miden_objects::proto::transaction::PublicOutputNote::note is missing"
    );
}

#[test]
fn public_output_note_protobuf_rejects_private_note() {
    let note = Note::mock_noop(Word::empty());
    let error = PublicOutputNote::try_from(proto::transaction::PublicOutputNote {
        note: Some(note.clone().into()),
    })
    .unwrap_err();

    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<OutputNoteError>()),
        Some(OutputNoteError::NoteIsPrivate(note_id)) if *note_id == note.id()
    ));
}

fn proven_batch_data() -> proto::transaction::ProvenBatch {
    proto::transaction::ProvenBatch {
        reference_block_commitment: Some(Word::empty().into()),
        reference_block_num: Some(proto::blockchain::BlockNumber { block_num: 1 }),
        account_updates: vec![],
        input_notes: vec![],
        output_notes: vec![],
        expiration_block_num: Some(proto::blockchain::BlockNumber { block_num: 2 }),
        transactions: vec![],
        proof: Some(ExecutionProof::new_dummy().into()),
    }
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
    assert_eq!(BatchAccountUpdate::try_from(message).unwrap(), update);
}

#[test]
fn block_body_and_transaction_header_roundtrip() {
    let account_id = private_account_id();
    let transaction = TransactionHeader::new(
        account_id,
        Word::from([1_u32, 2, 3, 4]),
        Word::from([5_u32, 6, 7, 8]),
        InputNotes::default(),
        vec![],
    )
    .unwrap();
    let account_update = BlockAccountUpdate::new(
        account_id,
        transaction.final_state_commitment(),
        AccountUpdateDetails::Private,
    )
    .unwrap();
    let body = BlockBody::new(
        vec![account_update],
        vec![],
        vec![],
        OrderedTransactionHeaders::new_unchecked(vec![transaction]),
    )
    .unwrap();

    let encoded = proto::blockchain::BlockBody::from(&body).encode_to_vec();
    let message = proto::blockchain::BlockBody::decode(encoded.as_slice()).unwrap();
    assert_eq!(BlockBody::try_from(message).unwrap(), body);
}

#[test]
fn account_storage_header_rejects_invalid_slot_types() {
    for (slot_type, expected_message) in [
        (Default::default(), "storage slot type is unspecified"),
        (i32::MAX, "unknown storage slot type 2147483647"),
    ] {
        let message = proto::account::AccountStorageHeader {
            slots: vec![proto::account::account_storage_header::StorageSlot {
                slot_name: "miden::test::storage".into(),
                slot_type,
                commitment: Some(Word::empty().into()),
            }],
        };

        let error = AccountStorageHeader::try_from(message).unwrap_err();
        assert_eq!(error.to_string(), format!("slots.slot_type: {expected_message}"));
    }
}

#[test]
fn account_storage_header_preserves_unknown_enum_value_source() {
    let error = AccountStorageHeader::try_from(proto::account::AccountStorageHeader {
        slots: vec![proto::account::account_storage_header::StorageSlot {
            slot_name: "miden::test::storage".into(),
            slot_type: i32::MAX,
            commitment: Some(Word::empty().into()),
        }],
    })
    .unwrap_err();

    assert!(matches!(
        error
            .source()
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<prost::UnknownEnumValue>()),
        Some(prost::UnknownEnumValue(value)) if *value == i32::MAX
    ));
}

#[test]
fn account_storage_header_uses_generated_slot_type_values() {
    for (slot_type, expected_slot_type) in [
        (StorageSlotType::Value, proto::account::StorageSlotType::Value),
        (StorageSlotType::Map, proto::account::StorageSlotType::Map),
    ] {
        let header = AccountStorageHeader::new(vec![StorageSlotHeader::new(
            StorageSlotName::new("miden::test::storage").unwrap(),
            slot_type,
            Word::empty(),
        )])
        .unwrap();

        let message = proto::account::AccountStorageHeader::from(&header);
        assert_eq!(message.slots[0].slot_type, expected_slot_type as i32);
        assert_eq!(AccountStorageHeader::try_from(message).unwrap(), header);
    }
}

#[test]
fn account_storage_patch_protobuf_slots_follow_canonical_storage_order() {
    let storage_patch = AccountStoragePatch::from_entries([
        (StorageSlotName::mock(3), StorageSlotPatch::Value(StorageValuePatch::Remove)),
        (StorageSlotName::mock(1), StorageSlotPatch::Map(StorageMapPatch::Remove)),
        (StorageSlotName::mock(4), StorageSlotPatch::Value(StorageValuePatch::Remove)),
        (StorageSlotName::mock(2), StorageSlotPatch::Map(StorageMapPatch::Remove)),
    ])
    .unwrap();

    let expected_slots = [
        ("miden::test::slot::3", true),
        ("miden::test::slot::1", false),
        ("miden::test::slot::4", true),
        ("miden::test::slot::2", false),
    ];
    let message = proto::account::AccountStoragePatch::from(&storage_patch);

    assert_eq!(
        message
            .slots
            .iter()
            .map(|slot| {
                (
                    slot.slot_name.as_str(),
                    matches!(
                        slot.patch.as_ref(),
                        Some(proto::account::storage_slot_patch::Patch::Value(_))
                    ),
                )
            })
            .collect::<Vec<_>>(),
        expected_slots
    );
}

#[test]
fn empty_protobuf_block_body_decodes_to_an_empty_domain_body() {
    let expected =
        BlockBody::new(vec![], vec![], vec![], OrderedTransactionHeaders::new_unchecked(vec![]))
            .unwrap();

    assert_eq!(BlockBody::try_from(proto::blockchain::BlockBody::default()).unwrap(), expected);
}

#[test]
fn block_header_rejects_missing_block_number() {
    let header = BlockHeader::mock(1, None, None, &[]);
    let mut message = proto::blockchain::BlockHeader::from(header);
    message.block_num = Default::default();

    let error = BlockHeader::try_from(message).unwrap_err();
    assert_eq!(
        error.to_string(),
        "block_num: field miden_objects::proto::blockchain::BlockHeader::block_num is missing"
    );
}

#[test]
fn block_header_protobuf_rejects_unspecified_version_before_payload_fields() {
    let error = BlockHeader::try_from(proto::blockchain::BlockHeader {
        version: proto::blockchain::BlockVersion::Unspecified as i32,
        ..Default::default()
    })
    .unwrap_err();

    assert_eq!(error.to_string(), "version: block header version is unspecified");
}

#[test]
fn block_header_protobuf_preserves_unknown_version_error_sources() {
    for version in [i32::MAX, i32::MIN] {
        let error =
            BlockHeader::try_from(proto::blockchain::BlockHeader { version, ..Default::default() })
                .unwrap_err();

        assert_eq!(error.to_string(), format!("version: unknown block header version {version}"));
        assert!(matches!(
            error
                .source()
                .and_then(Error::source)
                .and_then(|source| source.downcast_ref::<prost::UnknownEnumValue>()),
            Some(prost::UnknownEnumValue(value)) if *value == version
        ));
    }
}

fn block_header_with_scheduled_upgrade() -> BlockHeader {
    let header = BlockHeader::mock(1, None, None, &[]);
    let (_, validator_config) = ValidatorConfig::random_with_signers(3);
    let next_protocol_config =
        NextProtocolConfig::new(BlockNumber::from(42u32), Word::from([9u32, 8, 7, 6])).unwrap();

    BlockHeader::new(
        header.prev_block_commitment(),
        header.block_num(),
        header.chain_commitment(),
        header.account_root(),
        header.nullifier_root(),
        header.note_root(),
        header.tx_commitment(),
        validator_config,
        header.fee_parameters().clone(),
        header.protocol_config_commitment(),
        Some(next_protocol_config),
        header.timestamp(),
    )
}

#[test]
fn block_header_protobuf_round_trip_preserves_current_fields() {
    let header = block_header_with_scheduled_upgrade();

    let encoded = proto::blockchain::BlockHeader::from(&header).encode_to_vec();
    let message = proto::blockchain::BlockHeader::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.version, proto::blockchain::BlockVersion::V1 as i32);
    assert_eq!(BlockHeader::try_from(message).unwrap(), header);
}

#[test]
fn block_header_protobuf_rejects_invalid_validator_quorum() {
    let header = block_header_with_scheduled_upgrade();
    let mut message = proto::blockchain::BlockHeader::from(header);
    message.validator_config.as_mut().unwrap().quorum = 0;

    let error = BlockHeader::try_from(message).unwrap_err();
    let source = error.source().unwrap().downcast_ref::<ValidatorConfigError>().unwrap();

    assert!(error.to_string().starts_with("validator_config: "));
    assert!(matches!(
        source,
        ValidatorConfigError::QuorumMustEqualValidatorCount { quorum: 0, count: 3 }
    ));
}

#[test]
fn block_header_protobuf_reports_invalid_validator_key_index() {
    let header = block_header_with_scheduled_upgrade();
    let mut message = proto::blockchain::BlockHeader::from(header);
    message.validator_config.as_mut().unwrap().keys[1].encoded.clear();

    let error = BlockHeader::try_from(message).unwrap_err();

    assert!(error.to_string().starts_with("validator_config.keys[1].encoded: "));
}

#[test]
fn block_header_protobuf_rejects_upgrade_effective_at_genesis() {
    let header = block_header_with_scheduled_upgrade();
    let mut message = proto::blockchain::BlockHeader::from(header);
    message.next_protocol_config.as_mut().unwrap().effective_from =
        Some(BlockNumber::GENESIS.into());

    let error = BlockHeader::try_from(message).unwrap_err();
    let source = error.source().unwrap().downcast_ref::<ProtocolConfigError>().unwrap();

    assert!(error.to_string().starts_with("next_protocol_config: "));
    assert!(matches!(source, ProtocolConfigError::NextConfigEffectiveAtGenesis));
}

#[test]
fn note_inclusion_proof_rejects_missing_block_number() {
    let message = proto::note::NoteInclusionProof {
        note_id: Some(Word::empty().into()),
        block_num: None,
        note_index_in_block: 0,
        inclusion_path: Some(proto::primitives::SparseMerklePath {
            empty_nodes_mask: 0,
            siblings: vec![],
        }),
    };

    let error = <(NoteId, NoteInclusionProof)>::try_from(&message).unwrap_err();
    assert_missing_block_number(error, "block_num");
}

#[test]
fn proven_transaction_rejects_missing_block_numbers() {
    let mut message = proven_transaction_data();
    message.reference_block_num = None;
    let error = ProvenTransaction::try_from(message).unwrap_err();
    assert_missing_block_number(error, "reference_block_num");

    let mut message = proven_transaction_data();
    message.expiration_block_num = None;
    let error = ProvenTransaction::try_from(message).unwrap_err();
    assert_missing_block_number(error, "expiration_block_num");
}

#[test]
fn proven_batch_rejects_missing_block_numbers() {
    let mut message = proven_batch_data();
    message.reference_block_num = None;
    let error = decode_standalone_proven_batch(message).unwrap_err();
    assert_missing_block_number(error, "reference_block_num");

    let mut message = proven_batch_data();
    message.expiration_block_num = None;
    let error = decode_standalone_proven_batch(message).unwrap_err();
    assert_missing_block_number(error, "expiration_block_num");
}

#[test]
fn transaction_header_conversion_preserves_validation_error_source() {
    let note = Note::mock_noop(Word::empty());
    let transaction = TransactionHeader::new(
        private_account_id(),
        Word::from([1_u32, 2, 3, 4]),
        Word::from([5_u32, 6, 7, 8]),
        InputNotes::default(),
        vec![*note.header()],
    )
    .unwrap();
    let mut message = proto::transaction::TransactionHeader::from(transaction);
    message.output_notes.push(message.output_notes[0].clone());

    let error = TransactionHeader::try_from(message).unwrap_err();
    let source = error.source().unwrap().downcast_ref::<TransactionHeaderError>().unwrap();

    assert!(matches!(
        source,
        TransactionHeaderError::DuplicateOutputNote(note_id) if *note_id == note.id()
    ));
}
