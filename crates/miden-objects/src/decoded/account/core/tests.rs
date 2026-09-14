use alloc::string::ToString;
use alloc::vec;
use core::error::Error;

use assert_matches::assert_matches;
use miden_protocol::assembly::mast::MastForestError;
use miden_protocol::errors::AccountIdError;
use miden_protocol::{Felt, Word};
use prost::Message;

use crate::decoded::account::test_utils::{account_header, private_account_id};
use crate::decoded::primitives::test_utils::corrupt_node_hash;
use crate::test_utils::error_source;
use crate::{ConversionError, DecodeMessage, Verify, proto};

#[test]
fn account_id_v1_verification_is_deferred() {
    use miden_protocol::errors::AccountIdError;

    for (suffix, prefix, expected) in [
        (0, 0, AccountIdError::UnknownAccountIdVersion(0)),
        (1, 1, AccountIdError::AccountIdSuffixLeastSignificantByteMustBeZero),
        (1 << 63, 1, AccountIdError::AccountIdSuffixMostSignificantBitMustBeZero),
    ] {
        let decoded = proto::account::AccountIdV1 {
            suffix: Some(proto::primitives::Felt { value: suffix }),
            prefix: Some(proto::primitives::Felt { value: prefix }),
        }
        .decode_fields()
        .unwrap();
        assert_eq!(decoded.verify().unwrap_err().to_string(), expected.to_string());
    }
}

#[test]
fn account_code_defers_procedure_validation() {
    let decoded = proto::account::AccountCode {
        mast: Some(miden_protocol::MastForest::new().into()),
        procedure_roots: vec![],
    }
    .decode_fields()
    .unwrap();
    assert!(decoded.verify().is_err());
}

#[test]
fn account_witness_defers_path_depth_verification() {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
    let id = AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    );
    for (mask, valid) in [(0, false), (u64::MAX, true)] {
        let decoded = proto::account::AccountWitness {
            witness_id: Some(id.into()),
            commitment: Some(Word::empty().into()),
            path: Some(proto::primitives::SparseMerklePath {
                empty_nodes_mask: mask,
                siblings: vec![],
            }),
        }
        .decode_fields()
        .unwrap();
        assert_eq!(decoded.verify().is_ok(), valid);
    }
}

#[test]
fn account_header_decodes_named_version_before_verifying() {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
    let id = AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    );
    let header = miden_protocol::account::AccountHeader::new(
        id,
        miden_protocol::Felt::ZERO,
        Word::empty(),
        Word::empty(),
        Word::empty(),
    );
    let wire = proto::account::AccountHeader::from(&header);
    let decoded = wire.clone().decode_fields().unwrap();
    assert_eq!(decoded.version, proto::account::AccountVersion::V1);
    assert_eq!(decoded.verify().unwrap(), header);
    let decoded = proto::account::AccountHeader { version: 0, ..wire.clone() }
        .decode_fields()
        .unwrap();
    assert_eq!(decoded.version, proto::account::AccountVersion::Unspecified);
    assert!(decoded.verify().is_err());
    let decoded = proto::account::AccountHeader {
        nonce: miden_protocol::Felt::ORDER,
        ..wire
    }
    .decode_fields()
    .unwrap();
    assert!(decoded.verify().is_err());
}

#[test]
fn account_witness_conversion_preserves_account_tree_error_source() {
    let account_id = private_account_id();
    let error = proto::account::AccountWitness {
        witness_id: Some(account_id.into()),
        commitment: Some(Word::empty().into()),
        path: Some(proto::primitives::SparseMerklePath::default()),
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new)
    .unwrap_err();

    assert_matches!(
        error
            .source()
            .and_then(core::error::Error::source)
            .and_then(|source| source.downcast_ref::<miden_protocol::errors::AccountTreeError>()),
        Some(
            miden_protocol::errors::AccountTreeError::WitnessMerklePathDepthDoesNotMatchAccountTreeDepth(0)
        )
    );
}

#[test]
fn account_id_protobuf_requires_a_known_version() {
    // Field 2 represents an unknown future version. It must not default to V1.
    for bytes in [&[][..], &[0x12, 0][..]] {
        let wire = proto::account::AccountId::decode(bytes).unwrap();
        let error = wire.decode_fields().unwrap_err();
        assert_eq!(
            error.to_string(),
            "version: field miden_objects::proto::account::AccountId::version is missing"
        );
    }
}

#[test]
fn account_id_protobuf_rejects_invalid_metadata() {
    let mut wire = proto::account::AccountId::from(private_account_id());
    let proto::account::account_id::Version::V1(v1) = wire.version.as_mut().unwrap();
    v1.prefix.as_mut().unwrap().value &= !0xf;

    let error = wire
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error.source().and_then(|source| source.downcast_ref::<AccountIdError>()),
        Some(AccountIdError::UnknownAccountIdVersion(0))
    );
}

#[test]
fn account_header_protobuf_rejects_unspecified_version_after_decoding() {
    let error = proto::account::AccountHeader {
        version: proto::account::AccountVersion::Unspecified as i32,
        ..proto::account::AccountHeader::from(&account_header())
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new)
    .unwrap_err();

    assert_eq!(error.to_string(), "account header version is unspecified");
}

#[test]
fn account_header_protobuf_preserves_invalid_nonce_source() {
    let error = proto::account::AccountHeader {
        version: proto::account::AccountVersion::V1 as i32,
        account_id: Some(private_account_id().into()),
        vault_root: Some(Word::empty().into()),
        storage_commitment: Some(Word::empty().into()),
        code_commitment: Some(Word::empty().into()),
        nonce: Felt::ORDER,
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new)
    .unwrap_err();

    assert!(error.to_string().starts_with("invalid account nonce: "));
    assert_matches!(
        error_source::<<Felt as TryFrom<u64>>::Error>(&error),
        Some(source) if source.as_u64() == Felt::ORDER
    );
}

#[test]
fn account_code_validates_its_forest() {
    let code = miden_protocol::account::AccountCode::mock();
    let mast = corrupt_node_hash(&code.mast(), code.procedure_roots().next().unwrap());
    let mut wire = proto::account::AccountCode::from(&code);
    wire.mast = Some(mast);
    assert!(matches!(
        error_source::<MastForestError>(&wire.decode_fields().unwrap().verify().unwrap_err()),
        Some(MastForestError::HashMismatch { .. })
    ));
}
