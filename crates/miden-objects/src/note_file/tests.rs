use assert_matches::assert_matches;

use super::{MAGIC, NoteFile, NoteFileError};
use crate::decoded::note_file::test_utils::note_files;

#[test]
fn note_file_roundtrips_through_protobuf_bytes() {
    for file in note_files() {
        assert_eq!(NoteFile::try_from_bytes(&file.to_bytes()).unwrap(), file);
    }
}

#[test]
fn serialized_note_file_starts_with_the_magic() {
    for file in note_files() {
        assert_eq!(&file.to_bytes()[..MAGIC.len()], b"note");
    }
}

#[test]
fn note_file_rejects_a_wrong_or_truncated_magic() {
    let bytes = note_files().swap_remove(0).to_bytes();

    let mut wrong_magic = bytes.clone();
    wrong_magic[0] = b'x';

    for invalid in [&wrong_magic[..], &bytes[..MAGIC.len() - 1], &[]] {
        assert_matches!(NoteFile::try_from_bytes(invalid), Err(NoteFileError::InvalidMagic));
    }
}

#[cfg(feature = "std")]
#[test]
fn note_file_roundtrips_through_a_file() {
    let directory = tempfile::tempdir().unwrap();

    for (index, file) in note_files().into_iter().enumerate() {
        let path = directory.path().join(alloc::format!("note_file_{index}.mno"));
        file.write(&path).unwrap();

        assert_eq!(NoteFile::read(&path).unwrap(), file);
    }
}

#[cfg(feature = "std")]
#[test]
fn reading_a_missing_note_file_reports_the_io_error() {
    let directory = tempfile::tempdir().unwrap();

    let error = NoteFile::read(directory.path().join("absent.mno")).unwrap_err();

    assert_matches!(error, NoteFileError::Io(_));
}

/// The note file schema must stay out of the exported descriptor set, which carries only the
/// transport objects.
#[test]
fn note_file_schema_is_not_exported() {
    assert!(
        !crate::FILE_DESCRIPTOR_SET
            .windows(b"note_file".len())
            .any(|window| window == b"note_file"),
    );
}
