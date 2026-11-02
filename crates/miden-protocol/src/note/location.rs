use miden_crypto::merkle::SparseMerklePath;

use super::NoteError;
use crate::block::BlockNumber;
use crate::crypto::merkle::InnerNodeInfo;
use crate::note::NoteId;
use crate::{MAX_BATCHES_PER_BLOCK, MAX_OUTPUT_NOTES_PER_BATCH};

/// Contains information about the location of a note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteLocation {
    /// The block number the note was created in.
    block_num: BlockNumber,

    /// The index of the note in the [`BlockNoteTree`](crate::block::BlockNoteTree) of the block
    /// the note was created in.
    block_note_tree_index: u16,
}

impl NoteLocation {
    /// Returns the block number the note was created in.
    pub fn block_num(&self) -> BlockNumber {
        self.block_num
    }

    /// Returns the index of the note in the [`BlockNoteTree`](crate::block::BlockNoteTree) of the
    /// block the note was created in.
    ///
    /// # Note
    ///
    /// The height of the Merkle tree is [crate::constants::BLOCK_NOTE_TREE_DEPTH].
    /// Thus, the maximum index is `2 ^ BLOCK_NOTE_TREE_DEPTH - 1`.
    pub fn block_note_tree_index(&self) -> u16 {
        self.block_note_tree_index
    }
}

/// Contains the data required to prove inclusion of a note in the canonical chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteInclusionProof {
    /// Details about the note's location.
    location: NoteLocation,

    /// The note's authentication Merkle path its block's the note root.
    note_path: SparseMerklePath,
}

impl NoteInclusionProof {
    /// Returns a new [NoteInclusionProof].
    pub fn new(
        block_num: BlockNumber,
        block_note_tree_index: u16,
        note_path: SparseMerklePath,
    ) -> Result<Self, NoteError> {
        const HIGHEST_INDEX: usize = MAX_BATCHES_PER_BLOCK * MAX_OUTPUT_NOTES_PER_BATCH - 1;
        if block_note_tree_index as usize > HIGHEST_INDEX {
            return Err(NoteError::BlockNoteTreeIndexOutOfBounds {
                block_note_tree_index,
                highest_index: HIGHEST_INDEX,
            });
        }

        let location = NoteLocation { block_num, block_note_tree_index };

        Ok(Self { location, note_path })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the location of the note.
    pub fn location(&self) -> &NoteLocation {
        &self.location
    }

    /// Returns the Sparse Merkle path to the note in the note Merkle tree of the block the note was
    /// created in.
    pub fn note_path(&self) -> &SparseMerklePath {
        &self.note_path
    }

    /// Returns an iterator over inner nodes of this proof assuming that `note_id` is the value of
    /// the node to which this proof opens.
    pub fn authenticated_nodes(&self, note_id: NoteId) -> impl Iterator<Item = InnerNodeInfo> {
        // SAFETY: expect() is fine here because we check index consistency in the constructor
        self.note_path
            .authenticated_nodes(self.location.block_note_tree_index().into(), note_id.as_word())
            .expect("note index is not out of bounds")
    }
}

// SERIALIZATION
// ================================================================================================
