use alloc::string::ToString;
use alloc::vec;
use core::error::Error;

use assert_matches::assert_matches;
use miden_protocol::utils::serde::DeserializationError;

use crate::{DecodeMessage, Verify, proto};

#[test]
fn public_key_oneof_rejects_missing_and_noncanonical_payloads() {
    use miden_protocol::testing::random_secret_key::random_secret_key;
    use prost::Message;
    let key = random_secret_key().public_key();
    let wire: proto::primitives::PublicKey = (&key).into();
    assert_eq!(
        proto::primitives::PublicKey::decode(wire.encode_to_vec().as_slice())
            .unwrap()
            .decode_fields()
            .unwrap()
            .verify()
            .unwrap(),
        key
    );
    assert!(proto::primitives::PublicKey::default().decode_fields().is_err());
    let mut wire: proto::primitives::PublicKey = key.into();
    let proto::primitives::public_key::Key::EcdsaK256Keccak(bytes) = wire.key.as_mut().unwrap();
    bytes.push(0);
    assert!(
        wire.decode_fields()
            .unwrap_err()
            .to_string()
            .starts_with("key.ecdsa_k256_keccak:")
    );
    // An unknown algorithm does not become the default supported algorithm.
    let wire = proto::primitives::PublicKey::decode(&[0x12, 0][..]).unwrap();
    assert!(wire.decode_fields().is_err());
}

#[test]
fn signature_oneof_rejects_missing_unknown_and_noncanonical_payloads() {
    use miden_protocol::testing::random_secret_key::random_secret_key;
    use prost::Message;
    let signature = random_secret_key().sign(miden_protocol::Word::empty());
    let wire: proto::primitives::Signature = (&signature).into();
    assert_eq!(
        proto::primitives::Signature::decode(wire.encode_to_vec().as_slice())
            .unwrap()
            .decode_fields()
            .unwrap()
            .verify()
            .unwrap(),
        signature
    );
    assert!(proto::primitives::Signature::default().decode_fields().is_err());
    let mut wire: proto::primitives::Signature = signature.into();
    let proto::primitives::signature::Signature::EcdsaK256Keccak(bytes) =
        wire.signature.as_mut().unwrap();
    bytes.push(0);
    assert!(
        wire.decode_fields()
            .unwrap_err()
            .to_string()
            .starts_with("signature.ecdsa_k256_keccak:")
    );
    assert!(
        proto::primitives::Signature::decode(&[0x12, 0][..])
            .unwrap()
            .decode_fields()
            .is_err()
    );
}

#[test]
fn public_key_and_signature_reject_malformed_encodings() {
    let public_key_error = proto::primitives::PublicKey {
        key: Some(proto::primitives::public_key::Key::EcdsaK256Keccak(vec![])),
    }
    .decode_fields()
    .unwrap_err();
    assert_matches!(
        public_key_error
            .source()
            .and_then(|source| source.downcast_ref::<DeserializationError>()),
        Some(DeserializationError::UnexpectedEOF)
    );

    let signature_error = proto::primitives::Signature {
        signature: Some(proto::primitives::signature::Signature::EcdsaK256Keccak(vec![])),
    }
    .decode_fields()
    .unwrap_err();
    assert_matches!(
        signature_error
            .source()
            .and_then(|source| source.downcast_ref::<DeserializationError>()),
        Some(DeserializationError::UnexpectedEOF)
    );
}
