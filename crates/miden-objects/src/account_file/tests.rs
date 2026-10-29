#[cfg(all(feature = "std", unix))]
use std::fs;
#[cfg(all(feature = "std", unix))]
use std::os::unix::fs::PermissionsExt;

#[cfg(feature = "std")]
use assert_matches::assert_matches;

use super::AccountFile;
#[cfg(feature = "std")]
use super::AccountFileError;
use crate::decoded::account::test_utils::{auth_secret_keys, mock_account};

fn account_file() -> AccountFile {
    AccountFile::new(mock_account(), auth_secret_keys())
}

#[test]
fn account_file_roundtrips_through_protobuf_bytes() {
    let file = account_file();

    assert_eq!(AccountFile::try_from_bytes(&file.to_bytes()).unwrap(), file);
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

#[cfg(all(feature = "std", unix))]
#[test]
fn account_file_write_restricts_new_file_permissions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("account_file.mac");

    account_file().write(&path).unwrap();

    assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
}

#[cfg(all(feature = "std", unix))]
#[test]
fn account_file_write_restricts_existing_file_permissions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("account_file.mac");
    fs::write(&path, []).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    let file = account_file();
    file.write(&path).unwrap();

    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(AccountFile::read(path).unwrap(), file);
}

#[cfg(feature = "std")]
#[test]
fn reading_a_missing_account_file_reports_the_io_error() {
    let directory = tempfile::tempdir().unwrap();

    let error = AccountFile::read(directory.path().join("absent.mac")).unwrap_err();

    assert_matches!(error, AccountFileError::Io(_));
}
