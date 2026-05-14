use alloc::string::String;

use miden_crypto_derive::WordWrapper;

use super::{Felt, Hasher, Word};
use crate::note::{NoteAssets, NoteRecipient};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// NOTE DETAILS COMMITMENT
// ================================================================================================

/// A commitment to a note's details, without note metadata.
///
/// This commitment is computed as:
/// > hash(NOTE_RECIPIENT_DIGEST || NOTE_ASSETS_COMMITMENT)
///
/// Together with the note metadata commitment it is used to derive the note's
/// [`NoteId`](super::NoteId).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, WordWrapper)]
pub struct NoteDetailsCommitment(Word);

impl NoteDetailsCommitment {
    /// Returns a new [`NoteDetailsCommitment`] instantiated from the provided note components.
    pub fn new(recipient: &NoteRecipient, assets: &NoteAssets) -> Self {
        Self::merge(recipient.digest(), assets.commitment())
    }

    /// Returns a new [`NoteDetailsCommitment`] by merging the provided recipient and asset
    /// commitments.
    pub fn merge(recipient: Word, asset_commitment: Word) -> Self {
        Self(Hasher::merge(&[recipient, asset_commitment]))
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteDetailsCommitment {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0.to_bytes());
    }

    fn get_size_hint(&self) -> usize {
        Word::SERIALIZED_SIZE
    }
}

impl Deserializable for NoteDetailsCommitment {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let commitment = Word::read_from(source)?;
        Ok(Self(commitment))
    }
}
