use alloc::string::ToString;
use alloc::vec;

use assert_matches::assert_matches;
use prost::Message;
use rstest::rstest;

use crate::account_file::AccountFile;
use crate::decoded::account::test_utils::{auth_secret_keys, mock_account};
use crate::{DecodeMessage, Verify, proto};

#[rstest]
#[case::no_version(&[])]
// Field 2 represents an unknown future version. It must not default to V1.
#[case::unknown_future_version(&[0x12, 0])]
fn account_file_protobuf_requires_a_known_version(#[case] bytes: &[u8]) {
    let wire = proto::account_file::AccountFile::decode(bytes).unwrap();

    let error = wire.decode_fields().unwrap_err();

    assert_eq!(
        error.to_string(),
        "version: field miden_objects::proto::account_file::AccountFile::version is missing"
    );
}

#[rstest]
#[case::no_scheme(&[])]
// Field 3 represents an unknown future scheme. It must not default to a known one.
#[case::unknown_future_scheme(&[0x1a, 0])]
fn auth_secret_key_protobuf_requires_a_known_scheme(#[case] bytes: &[u8]) {
    let wire = proto::account_file::AuthSecretKey::decode(bytes).unwrap();

    let error = wire.decode_fields().unwrap_err();

    assert_eq!(
        error.to_string(),
        "key: field miden_objects::proto::account_file::AuthSecretKey::key is missing"
    );
}

#[test]
fn auth_secret_key_protobuf_rejects_non_canonical_key_bytes() {
    use proto::account_file::auth_secret_key::Key;

    for key in auth_secret_keys() {
        let Some(encoded) = proto::account_file::AuthSecretKey::from(&key).key else {
            panic!("the encoder always sets the key");
        };
        let (mut trailing, empty) = match encoded {
            Key::Falcon512Poseidon2(bytes) => {
                (bytes, Key::Falcon512Poseidon2(alloc::vec::Vec::new()))
            },
            Key::EcdsaK256Keccak(bytes) => (bytes, Key::EcdsaK256Keccak(alloc::vec::Vec::new())),
        };
        trailing.push(0);
        let trailing = match &empty {
            Key::Falcon512Poseidon2(_) => Key::Falcon512Poseidon2(trailing),
            Key::EcdsaK256Keccak(_) => Key::EcdsaK256Keccak(trailing),
        };

        for invalid in [trailing, empty] {
            let wire = proto::account_file::AuthSecretKey { key: Some(invalid) };

            assert!(wire.decode_fields().is_err());
        }
    }
}

#[test]
fn account_file_verification_reports_the_invalid_account() {
    let file = AccountFile::new(mock_account(), auth_secret_keys());
    let mut wire = proto::account_file::AccountFile::from(&file);
    let Some(proto::account_file::account_file::Version::V1(v1)) = wire.version.as_mut() else {
        panic!("the encoder always sets the V1 version");
    };
    // A seed is only valid for an account that is not yet created on chain.
    v1.account.as_mut().unwrap().seed = Some(miden_protocol::Word::empty().into());

    let error = wire.decode_fields().unwrap().verify().unwrap_err();

    assert_matches!(
        crate::test_utils::error_source::<miden_protocol::errors::AccountError>(&error),
        Some(miden_protocol::errors::AccountError::ExistingAccountWithSeed)
    );
}

#[test]
fn account_file_accepts_no_secret_keys() {
    let file = AccountFile::new(mock_account(), vec![]);

    let wire = proto::account_file::AccountFile::from(&file);

    assert_eq!(wire.decode_fields().unwrap().verify().unwrap(), file);
}
