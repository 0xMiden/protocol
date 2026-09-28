use assert_matches::assert_matches;
use prost::Message;

use crate::account_file::AccountFile;
use crate::decoded::account::test_utils::{auth_secret_keys, mock_account};
use crate::{DecodeMessage, Verify, proto};

#[test]
fn account_file_roundtrips_through_protobuf() {
    let file = AccountFile::new(mock_account(), auth_secret_keys());

    let encoded = proto::account_file::AccountFile::from(&file);
    assert_matches!(encoded.version, Some(proto::account_file::account_file::Version::V1(_)));

    let wire =
        proto::account_file::AccountFile::decode(encoded.encode_to_vec().as_slice()).unwrap();
    assert_eq!(wire.decode_fields().unwrap().verify().unwrap(), file);
}

#[test]
fn auth_secret_key_roundtrips_through_protobuf() {
    for key in auth_secret_keys() {
        let wire = proto::account_file::AuthSecretKey::from(&key);
        let wire =
            proto::account_file::AuthSecretKey::decode(wire.encode_to_vec().as_slice()).unwrap();
        assert_eq!(wire.decode_fields().unwrap().verify().unwrap(), key);
    }
}
