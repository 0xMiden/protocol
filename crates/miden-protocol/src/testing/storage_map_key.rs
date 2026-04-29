use crate::Word;
use crate::account::StorageMapKey;

impl StorageMapKey {
    /// Creates a [`StorageMapKey`] from an array of u32s for testing purposes.
    pub fn from_array(array: [u32; 4]) -> Self {
        Self::from_raw(Word::from(array))
    }
}
