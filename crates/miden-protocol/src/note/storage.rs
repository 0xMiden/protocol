use alloc::vec::Vec;

use crate::errors::NoteError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, MAX_NOTE_STORAGE_ITEMS, Word};

// NOTE STORAGE
// ================================================================================================

/// A container for note storage items.
///
/// A note can be associated with up to 1024 storage items. Each item is represented by a single
/// field element. Thus, note storage can contain up to ~8 KB of data.
///
/// All storage items associated with a note can be reduced to a single commitment which is
/// computed as an RPO256 hash over the storage elements.
#[derive(Clone, Debug)]
pub struct NoteStorage {
    items: Vec<Felt>,
    commitment: Word,
}

impl NoteStorage {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns [NoteStorage] instantiated from the provided items.
    ///
    /// # Errors
    /// Returns an error if the number of provided storage items is greater than 1024.
    pub fn new(items: Vec<Felt>) -> Result<Self, NoteError> {
        if items.len() > MAX_NOTE_STORAGE_ITEMS {
            return Err(NoteError::TooManyStorageItems(items.len()));
        }

        let commitment = Hasher::hash_elements(&items);

        Ok(Self { items, commitment })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a commitment to this storage.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// Returns the number of storage items.
    ///
    /// The returned value is guaranteed to be smaller than or equal to [`MAX_NOTE_STORAGE_ITEMS`].
    pub fn num_items(&self) -> u16 {
        const _: () = assert!(MAX_NOTE_STORAGE_ITEMS <= u16::MAX as usize);
        debug_assert!(
            self.items.len() <= MAX_NOTE_STORAGE_ITEMS,
            "The constructor should have checked the number of storage items"
        );
        self.items.len() as u16
    }

    /// Returns `true` if the storage has no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns a reference to the storage items.
    pub fn items(&self) -> &[Felt] {
        &self.items
    }

    /// Returns the note's storage as a vector of field elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        self.items.to_vec()
    }
}

impl Default for NoteStorage {
    fn default() -> Self {
        Self::new(vec![]).expect("empty storage should be valid")
    }
}

impl PartialEq for NoteStorage {
    fn eq(&self, other: &Self) -> bool {
        let NoteStorage { items, commitment: _ } = self;
        items == &other.items
    }
}

impl Eq for NoteStorage {}

// CONVERSION
// ================================================================================================

impl From<NoteStorage> for Vec<Felt> {
    fn from(value: NoteStorage) -> Self {
        value.items
    }
}

impl TryFrom<Vec<Felt>> for NoteStorage {
    type Error = NoteError;

    fn try_from(value: Vec<Felt>) -> Result<Self, Self::Error> {
        NoteStorage::new(value)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteStorage {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let NoteStorage { items, commitment: _commitment } = self;
        target.write_u16(items.len().try_into().expect("storage items len is not a u16 value"));
        target.write_many(items);
    }
}

impl Deserializable for NoteStorage {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_u16()? as usize;
        let items = source.read_many::<Felt>(len)?;
        Self::new(items).map_err(|v| DeserializationError::InvalidValue(format!("{v}")))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_crypto::utils::Deserializable;

    use super::{Felt, NoteStorage, Serializable};

    #[test]
    fn test_storage_item_ordering() {
        // storage items are provided in reverse stack order
        let storage_items = vec![Felt::new(1), Felt::new(2), Felt::new(3)];
        // we expect the storage items to remain in reverse stack order.
        let expected_ordering = vec![Felt::new(1), Felt::new(2), Felt::new(3)];

        let note_storage = NoteStorage::new(storage_items).expect("note created should succeed");
        assert_eq!(&expected_ordering, note_storage.items());
    }

    #[test]
    fn test_storage_serialization() {
        let storage_items = vec![Felt::new(1), Felt::new(2), Felt::new(3)];
        let note_storage = NoteStorage::new(storage_items).unwrap();

        let bytes = note_storage.to_bytes();
        let parsed_note_storage = NoteStorage::read_from_bytes(&bytes).unwrap();
        assert_eq!(note_storage, parsed_note_storage);
    }
}
