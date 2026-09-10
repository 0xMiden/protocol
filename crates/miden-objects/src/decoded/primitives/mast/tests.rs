use alloc::string::ToString;
use alloc::vec;

use miden_protocol::assembly::mast::MastForestError;

use crate::decoded::primitives::test_utils::corrupt_node_hash;
use crate::{DecodeMessage, Verify, proto};

#[test]
fn mast_forest_decode_and_verify() {
    let mast = miden_protocol::MastForest::new();
    assert_eq!(
        proto::primitives::MastForest::from(&mast)
            .decode_fields()
            .unwrap()
            .verify()
            .unwrap(),
        mast
    );
}

#[test]
fn corrupted_node_hash_is_rejected_during_verification() {
    let script = miden_protocol::note::NoteScript::mock();
    let wire = corrupt_node_hash(&script.mast(), script.root().into());
    assert!(matches!(
        wire.decode_fields().unwrap().verify(),
        Err(MastForestError::HashMismatch { .. })
    ));
}

#[test]
fn malformed_mast_bytes_have_generated_paths() {
    let script = miden_protocol::note::NoteScript::mock();
    let mut trailing = proto::primitives::MastForest::from(script.mast().as_ref());
    trailing.encoded.push(0);
    for mast in [proto::primitives::MastForest { encoded: vec![] }, trailing] {
        let error = mast.clone().decode_fields().unwrap_err();
        assert!(error.to_string().starts_with("encoded: "), "{error}");
        let wire = proto::note::NoteScript {
            mast: Some(mast),
            entrypoint: script.entrypoint().into(),
        };
        let error = wire.decode_fields().unwrap_err();
        assert!(error.to_string().starts_with("mast.encoded: "), "{error}");
    }
}
