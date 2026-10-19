use alloc::string::ToString;
use alloc::vec::Vec;

use crate::crypto::SequentialCommit;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word};

mod errors;
pub use errors::StorageArrayError;

/// An immutable array of words with a cached commitment.
///
/// The commitment hashes every word in order, including zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageArray {
    values: Vec<Word>,
    commitment: Word,
}

impl StorageArray {
    /// The maximum number of words in an array.
    pub const MAX_NUM_WORDS: usize = 256;

    /// Creates an array of 1 to [`Self::MAX_NUM_WORDS`] words.
    pub fn new(values: Vec<Word>) -> Result<Self, StorageArrayError> {
        StorageArrayLength::try_from(values.len())?;
        let commitment = Hasher::hash_elements(Word::words_as_elements(&values));
        Ok(Self { values, commitment })
    }

    /// Creates an array filled with zero words.
    pub fn empty(length: StorageArrayLength) -> Self {
        Self::new(vec![Word::empty(); length.as_usize()]).expect("validated array length")
    }

    /// Returns the words in index order.
    pub fn values(&self) -> &[Word] {
        &self.values
    }

    /// Returns the length in words.
    pub fn length(&self) -> StorageArrayLength {
        StorageArrayLength(self.values.len() as u16)
    }

    /// Returns the cached array commitment.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// Returns the array as field elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }
}

impl SequentialCommit for StorageArray {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        Word::words_as_elements(&self.values).to_vec()
    }

    fn to_commitment(&self) -> Word {
        self.commitment
    }
}

impl Serializable for StorageArray {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.length());
        target.write_many(&self.values);
    }

    fn get_size_hint(&self) -> usize {
        2 + self.values.len() * Word::SERIALIZED_SIZE
    }
}

impl Deserializable for StorageArray {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let length: StorageArrayLength = source.read()?;
        let values = source.read_many_iter(length.as_usize())?.collect::<Result<_, _>>()?;
        Self::new(values).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

/// A validated storage array length, in words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageArrayLength(u16);

impl StorageArrayLength {
    pub fn as_u16(self) -> u16 {
        self.0
    }

    pub fn as_usize(self) -> usize {
        usize::from(self.0)
    }
}

impl TryFrom<usize> for StorageArrayLength {
    type Error = StorageArrayError;

    fn try_from(length: usize) -> Result<Self, Self::Error> {
        if !(1..=StorageArray::MAX_NUM_WORDS).contains(&length) {
            return Err(StorageArrayError::InvalidLength(length));
        }
        Ok(Self(length as u16))
    }
}

impl Serializable for StorageArrayLength {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(self.0);
    }

    fn get_size_hint(&self) -> usize {
        2
    }
}

impl Deserializable for StorageArrayLength {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::try_from(usize::from(source.read_u16()?))
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

#[cfg(test)]
mod tests;
