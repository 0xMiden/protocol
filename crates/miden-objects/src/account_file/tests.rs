use assert_matches::assert_matches;

use super::{AccountFile, AccountFileError, MAGIC};
use crate::decoded::account::test_utils::{auth_secret_keys, mock_account};

fn account_file() -> AccountFile {
    AccountFile::new(mock_account(), auth_secret_keys())
}

#[test]
fn account_file_roundtrips_through_protobuf_bytes() {
    let file = account_file();

    assert_eq!(AccountFile::try_from_bytes(&file.to_bytes()).unwrap(), file);
}

#[test]
fn serialized_account_file_starts_with_the_magic() {
    assert_eq!(&account_file().to_bytes()[..MAGIC.len()], b"acct");
}

#[test]
fn account_file_rejects_a_wrong_or_truncated_magic() {
    let bytes = account_file().to_bytes();

    let mut wrong_magic = bytes.clone();
    wrong_magic[0] = b'x';

    for invalid in [&wrong_magic[..], &bytes[..MAGIC.len() - 1], &[]] {
        assert_matches!(AccountFile::try_from_bytes(invalid), Err(AccountFileError::InvalidMagic));
    }
}

#[cfg(feature = "std")]
#[test]
fn account_file_roundtrips_through_a_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("account_file.mac");
    let file = account_file();

    file.write(&path).unwrap();

    assert_eq!(AccountFile::read(&path).unwrap(), file);
}

#[cfg(feature = "std")]
#[test]
fn reading_a_missing_account_file_reports_the_io_error() {
    let directory = tempfile::tempdir().unwrap();

    let error = AccountFile::read(directory.path().join("absent.mac")).unwrap_err();

    assert_matches!(error, AccountFileError::Io(_));
}
