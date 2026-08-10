use alloc::string::ToString;

use miden_crypto::merkle::{NodeIndex, SparseMerklePath};

use super::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    NoteError,
    Serializable,
};
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
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `block_note_tree_index` is out of bounds of the block note tree.
    /// - `block_note_tree_index` does not address a leaf of `note_path` at its depth.
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

        // `authenticated_nodes` uses `block_note_tree_index` as a leaf position within
        // `note_path`, so the index must be addressable at that path's depth.
        if NodeIndex::new(note_path.depth(), block_note_tree_index.into()).is_err() {
            return Err(NoteError::NoteInclusionProofIndexNotInPath {
                block_note_tree_index,
                path_depth: note_path.depth(),
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
        // SAFETY: every construction path verifies that `block_note_tree_index` addresses a leaf
        // of `note_path`, which is exactly the bound checked here.
        self.note_path
            .authenticated_nodes(self.location.block_note_tree_index().into(), note_id.as_word())
            .expect("note index is not out of bounds")
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteLocation {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.block_num);
        target.write_u16(self.block_note_tree_index);
    }
}

impl Deserializable for NoteLocation {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let block_num = source.read()?;
        let block_note_tree_index = source.read_u16()?;

        Ok(Self { block_num, block_note_tree_index })
    }
}

impl Serializable for NoteInclusionProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.location.write_into(target);
        self.note_path.write_into(target);
    }
}

impl Deserializable for NoteInclusionProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let location = NoteLocation::read_from(source)?;
        let note_path = SparseMerklePath::read_from(source)?;

        Self::new(location.block_num, location.block_note_tree_index, note_path)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use assert_matches::assert_matches;

    use super::*;
    use crate::{BLOCK_NOTE_TREE_DEPTH, Word};

    /// Builds a path of the given depth. A zero mask means every node along the path is non-empty,
    /// so the depth equals the number of nodes.
    fn path_of_depth(depth: u8) -> SparseMerklePath {
        SparseMerklePath::from_parts(0, vec![Word::default(); depth as usize])
            .expect("a zero mask with `depth` nodes describes a valid path")
    }

    #[test]
    fn new_accepts_index_addressable_at_path_depth() {
        // 1000 < 2^10, so the index addresses a leaf of a depth-10 path.
        assert!(NoteInclusionProof::new(BlockNumber::GENESIS, 1000, path_of_depth(10)).is_ok());
    }

    #[test]
    fn new_accepts_zero_index_with_empty_path() {
        // A depth-0 path opens to the root, whose only leaf position is 0.
        assert!(NoteInclusionProof::new(BlockNumber::GENESIS, 0, path_of_depth(0)).is_ok());
    }

    #[test]
    fn new_rejects_index_beyond_path_depth() {
        // 1000 is a valid block note tree index, but no leaf of a depth-5 path carries it.
        let err = NoteInclusionProof::new(BlockNumber::GENESIS, 1000, path_of_depth(5))
            .expect_err("index 1000 is not addressable at depth 5");

        assert_matches!(
            err,
            NoteError::NoteInclusionProofIndexNotInPath { block_note_tree_index, path_depth }
                if block_note_tree_index == 1000 && path_depth == 5
        );
    }

    #[test]
    fn read_from_rejects_index_beyond_path_depth() {
        // `new` rejects this combination, so the bytes are encoded field by field.
        let mut bytes = Vec::new();
        NoteLocation {
            block_num: BlockNumber::GENESIS,
            block_note_tree_index: 1000,
        }
        .write_into(&mut bytes);
        path_of_depth(5).write_into(&mut bytes);

        assert!(NoteInclusionProof::read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn valid_proof_round_trips() {
        let path = path_of_depth(BLOCK_NOTE_TREE_DEPTH);
        let proof = NoteInclusionProof::new(BlockNumber::GENESIS, 7, path).unwrap();

        let decoded = NoteInclusionProof::read_from_bytes(&proof.to_bytes()).unwrap();

        assert_eq!(proof, decoded);
    }
}
