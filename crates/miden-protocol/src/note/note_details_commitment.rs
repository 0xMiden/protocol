use miden_crypto_derive::WordWrapper;

use super::{Hasher, Word};
use crate::note::{NoteAssets, NoteRecipient};

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
        Self::from_raw_commitments(recipient.digest(), assets.commitment())
    }

    /// Returns a new [`NoteDetailsCommitment`] by hashing the recipient and asset commitments
    /// in that order.
    pub fn from_raw_commitments(recipient: Word, asset_commitment: Word) -> Self {
        Self(Hasher::hash_double_word(&[recipient, asset_commitment]))
    }
}
