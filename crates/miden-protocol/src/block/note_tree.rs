use alloc::string::ToString;

use miden_crypto::merkle::SparseMerklePath;

use crate::batch::BatchNoteTree;
use crate::crypto::merkle::MerkleError;
use crate::crypto::merkle::smt::{LeafIndex, SimpleSmt};
use crate::note::{NoteId, NoteMetadata, compute_note_commitment};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use crate::{
    BLOCK_NOTE_TREE_DEPTH,
    MAX_BATCHES_PER_BLOCK,
    MAX_OUTPUT_NOTES_PER_BATCH,
    MAX_OUTPUT_NOTES_PER_BLOCK,
    Word,
};

/// Wrapper over [SimpleSmt<BLOCK_NOTE_TREE_DEPTH>] for notes tree.
///
/// Each note is stored as two adjacent leaves: odd leaf for id, even leaf for metadata hash.
/// ID's leaf index is calculated as [(batch_idx * MAX_NOTES_PER_BATCH + note_idx_in_batch) * 2].
/// Metadata hash leaf is stored the next after id leaf: [id_index + 1].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockNoteTree(SimpleSmt<BLOCK_NOTE_TREE_DEPTH>);

impl BlockNoteTree {
    /// Returns a new [`BlockNoteTree`] instantiated with entries set as specified by the provided
    /// entries.
    ///
    /// Entry format: (note_index, note_id, note_metadata).
    ///
    /// Value of each leaf is computed as: `hash(note_id || note_metadata_commitment)`.
    /// All leaves omitted from the entries list are set to [crate::EMPTY_WORD].
    ///
    /// # Errors
    /// Returns an error if:
    /// - The number of entries exceeds the maximum notes tree capacity, that is 2^16.
    /// - The provided entries contain multiple values for the same key.
    pub fn with_entries<'metadata>(
        entries: impl IntoIterator<Item = (BlockNoteIndex, NoteId, &'metadata NoteMetadata)>,
    ) -> Result<Self, MerkleError> {
        let leaves = entries.into_iter().map(|(index, note_id, metadata)| {
            (index.leaf_index_value() as u64, compute_note_commitment(note_id, metadata))
        });

        SimpleSmt::with_leaves(leaves).map(Self)
    }

    /// Returns a new, empty [`BlockNoteTree`].
    pub fn empty() -> Self {
        Self(SimpleSmt::new().expect("depth should be 16 and thus > 0 and <= 64"))
    }

    /// Inserts the given [`BatchNoteTree`] as a subtree into the block note tree at the specified
    /// index.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the given batch index is greater or equal to [`MAX_BATCHES_PER_BLOCK`]
    pub fn insert_batch_note_subtree(
        &mut self,
        batch_idx: u64,
        batch_note_tree: BatchNoteTree,
    ) -> Result<(), MerkleError> {
        // Note that the subtree depth > depth error cannot occur, as the batch note tree's depth is
        // smaller than the block note tree's depth.
        // This is guaranteed through the definition of MAX_BATCHES_PER_BLOCK.
        self.0.set_subtree(batch_idx, batch_note_tree.into_smt()).map(|_| ())
    }

    /// Returns the root of the tree
    pub fn root(&self) -> Word {
        self.0.root()
    }

    /// Returns merkle path for the note with specified batch/note indexes.
    pub fn open(&self, index: BlockNoteIndex) -> SparseMerklePath {
        // get the path to the leaf containing the note (path len = 16)
        self.0.open(&index.leaf_index()).path
    }

    /// Returns the number of notes in this block note tree.
    pub fn num_notes(&self) -> usize {
        self.0.num_leaves()
    }

    /// Returns a boolean value indicating whether the block note tree is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for BlockNoteTree {
    fn default() -> Self {
        Self(SimpleSmt::new().expect("Unreachable"))
    }
}

// BLOCK NOTE INDEX
// ================================================================================================

/// Index of a block note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockNoteIndex {
    batch_idx: usize,
    note_idx_in_batch: usize,
}

impl BlockNoteIndex {
    /// Creates a new [BlockNoteIndex].
    ///
    /// # Errors
    ///
    /// Returns `None` if the batch index is equal to or greater than [`MAX_BATCHES_PER_BLOCK`] or
    /// if the note index is equal to or greater than [`MAX_OUTPUT_NOTES_PER_BATCH`].
    pub fn new(batch_idx: usize, note_idx_in_batch: usize) -> Option<Self> {
        if batch_idx >= MAX_BATCHES_PER_BLOCK || note_idx_in_batch >= MAX_OUTPUT_NOTES_PER_BATCH {
            return None;
        }

        Some(Self { batch_idx, note_idx_in_batch })
    }

    /// Returns the batch index.
    pub fn batch_idx(&self) -> usize {
        self.batch_idx
    }

    /// Returns the note index in the batch.
    pub fn note_idx_in_batch(&self) -> usize {
        self.note_idx_in_batch
    }

    /// Returns the leaf index of the note in the note tree.
    pub fn leaf_index(&self) -> LeafIndex<BLOCK_NOTE_TREE_DEPTH> {
        LeafIndex::new(
            (self.batch_idx() * MAX_OUTPUT_NOTES_PER_BATCH + self.note_idx_in_batch()) as u64,
        )
        .expect("Unreachable: Input values must be valid at this point")
    }

    /// Returns the leaf index value of the note in the note tree.
    pub fn leaf_index_value(&self) -> u16 {
        const _: () = assert!(
            MAX_OUTPUT_NOTES_PER_BLOCK <= u16::MAX as usize + 1,
            "Any note index is expected to fit in `u16`"
        );

        self.leaf_index()
            .value()
            .try_into()
            .expect("Unreachable: Input values must be valid at this point")
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for BlockNoteTree {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.0.num_leaves() as u32);
        target.write_many(self.0.leaves());
    }
}

impl Deserializable for BlockNoteTree {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = source.read_u32()?;
        let leaves = source.read_many(count as usize)?;

        SimpleSmt::with_leaves(leaves)
            .map(Self)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use miden_crypto::merkle::smt::SimpleSmt;
    use miden_crypto::utils::{Deserializable, Serializable};

    use super::BlockNoteTree;
    use crate::Word;

    #[test]
    fn test_serialization() {
        let data = core::iter::repeat(())
            .enumerate()
            .map(|(idx, ())| (idx as u64, Word::from([1, 0, 1, idx as u32])))
            .take(100);
        let initial_tree = BlockNoteTree(SimpleSmt::with_leaves(data).unwrap());

        let serialized = initial_tree.to_bytes();
        let deserialized_tree = BlockNoteTree::read_from_bytes(&serialized).unwrap();

        assert_eq!(deserialized_tree, initial_tree);
    }
}
