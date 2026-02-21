use alloc::string::String;
use core::fmt::{Debug, Display, Formatter};

use miden_crypto::WordError;
use miden_protocol_macros::WordWrapper;

use super::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Felt,
    Hasher,
    NoteDetails,
    Serializable,
    WORD_SIZE,
    Word,
    ZERO,
};

// CONSTANTS
// ================================================================================================

const NULLIFIER_PREFIX_SHIFT: u8 = 48;

// NULLIFIER
// ================================================================================================

/// A note's nullifier.
///
/// A note's nullifier is computed as:
///
/// > hash(serial_num, script_root, storage_commitment, asset_commitment).
///
/// This achieves the following properties:
/// - Every note can be reduced to a single unique nullifier.
/// - We cannot derive a note's commitment from its nullifier, or a note's nullifier from its hash.
/// - To compute the nullifier we must know all components of the note: serial_num, script_root,
///   storage_commitment and asset_commitment.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, WordWrapper)]
pub struct Nullifier(Word);

impl Nullifier {
    /// Returns a new note [Nullifier] instantiated from the provided digest.
    pub fn new(
        script_root: Word,
        storage_commitment: Word,
        asset_commitment: Word,
        serial_num: Word,
    ) -> Self {
        let mut elements = [ZERO; 4 * WORD_SIZE];
        elements[..4].copy_from_slice(serial_num.as_elements());
        elements[4..8].copy_from_slice(script_root.as_elements());
        elements[8..12].copy_from_slice(storage_commitment.as_elements());
        elements[12..].copy_from_slice(asset_commitment.as_elements());
        Self(Hasher::hash_elements(&elements))
    }

    /// Returns the most significant felt (the last element in array)
    pub fn most_significant_felt(&self) -> Felt {
        self.as_elements()[3]
    }

    /// Returns the prefix of this nullifier.
    ///
    /// Nullifier prefix is defined as the 16 most significant bits of the nullifier value.
    pub fn prefix(&self) -> u16 {
        (self.as_word()[3].as_int() >> NULLIFIER_PREFIX_SHIFT) as u16
    }

    /// Creates a Nullifier from a hex string. Assumes that the string starts with "0x" and
    /// that the hexadecimal characters are big-endian encoded.
    ///
    /// Callers must ensure the provided value is an actual [`Nullifier`].
    pub fn from_hex(hex_value: &str) -> Result<Self, WordError> {
        Word::try_from(hex_value).map(Self::from_raw)
    }

    #[cfg(any(feature = "testing", test))]
    pub fn dummy(n: u64) -> Self {
        use miden_core::FieldElement;

        Self(Word::new([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::new(n)]))
    }
}

impl Display for Nullifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Debug for Nullifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Display::fmt(self, f)
    }
}

// CONVERSIONS INTO NULLIFIER
// ================================================================================================

impl From<&NoteDetails> for Nullifier {
    fn from(note: &NoteDetails) -> Self {
        Self::new(
            note.script().root(),
            note.storage().commitment(),
            note.assets().commitment(),
            note.serial_num(),
        )
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Nullifier {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0.to_bytes());
    }
}

impl Deserializable for Nullifier {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let nullifier = Word::read_from(source)?;
        Ok(Self(nullifier))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use crate::note::Nullifier;

    #[test]
    fn test_from_hex_and_back() {
        let nullifier_hex = "0x41e7dbbc8ce63ec25cf2d76d76162f16ef8fd1195288171f5e5a3e178222f6d2";
        let nullifier = Nullifier::from_hex(nullifier_hex).unwrap();

        assert_eq!(nullifier_hex, nullifier.to_hex());
    }
}
