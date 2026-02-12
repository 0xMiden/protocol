use alloc::vec::Vec;

use crate::crypto::merkle::MerkleError;
use crate::crypto::merkle::smt::{LeafIndex, SimpleSmt};
use crate::note::{NoteId, NoteMetadata, compute_note_commitment};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use crate::{BATCH_NOTE_TREE_DEPTH, EMPTY_WORD, Word};

/// Wrapper over [SimpleSmt<BATCH_NOTE_TREE_DEPTH>] for batch note tree.
///
/// Value of each leaf is computed as: `hash(note_id || note_metadata_commitment)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchNoteTree(SimpleSmt<BATCH_NOTE_TREE_DEPTH>);

impl BatchNoteTree {
    /// Wrapper around [`SimpleSmt::with_contiguous_leaves`] which populates notes at contiguous
    /// indices starting at index 0.
    ///
    /// # Errors
    /// Returns an error if the number of entries exceeds the maximum tree capacity, that is
    /// 2^{depth}.
    pub fn with_contiguous_leaves<'a>(
        entries: impl IntoIterator<Item = (NoteId, &'a NoteMetadata)>,
    ) -> Result<Self, MerkleError> {
        let leaves = entries
            .into_iter()
            .map(|(note_id, metadata)| compute_note_commitment(note_id, metadata));

        SimpleSmt::with_contiguous_leaves(leaves).map(Self)
    }

    /// Returns the root of the tree
    pub fn root(&self) -> Word {
        self.0.root()
    }

    /// Returns the number of non-empty leaves in this tree.
    pub fn num_leaves(&self) -> usize {
        self.0.num_leaves()
    }

    /// Removes the note at the given `index` form the tree by inserting [`EMPTY_WORD`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the `index` is equal to or exceeds
    ///   [`MAX_OUTPUT_NOTES_PER_BATCH`](crate::constants::MAX_OUTPUT_NOTES_PER_BATCH).
    pub fn remove(&mut self, index: u64) -> Result<(), MerkleError> {
        let key = LeafIndex::new(index)?;
        self.0.insert(key, EMPTY_WORD);

        Ok(())
    }

    /// Consumes the batch note tree and returns the underlying [`SimpleSmt`].
    pub fn into_smt(self) -> SimpleSmt<BATCH_NOTE_TREE_DEPTH> {
        self.0
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for BatchNoteTree {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.leaves().collect::<Vec<_>>().write_into(target);
    }
}

impl Deserializable for BatchNoteTree {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let leaves = Vec::read_from(source)?;
        let smt = SimpleSmt::with_leaves(leaves.into_iter()).map_err(|err| {
            DeserializationError::UnknownError(format!(
                "failed to deserialize BatchNoteTree: {err}"
            ))
        })?;
        Ok(Self(smt))
    }
}
