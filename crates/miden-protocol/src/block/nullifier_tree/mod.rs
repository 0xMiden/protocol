use alloc::string::ToString;
use alloc::vec::Vec;

use crate::block::BlockNumber;
use crate::crypto::merkle::MerkleError;
use crate::crypto::merkle::smt::{MutationSet, SMT_DEPTH, Smt};
use crate::errors::NullifierTreeError;
use crate::note::Nullifier;
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use crate::{Felt, FieldElement, Word};

mod backend;
pub use backend::NullifierTreeBackend;

mod witness;
pub use witness::NullifierWitness;

mod partial;
pub use partial::PartialNullifierTree;

// NULLIFIER TREE
// ================================================================================================

/// The sparse merkle tree of all nullifiers in the blockchain.
///
/// A nullifier can only ever be spent once and its value in the tree is the block number at which
/// it was spent.
///
/// The tree guarantees that once a nullifier has been inserted into the tree, its block number does
/// not change. Note that inserting the nullifier multiple times with the same block number is
/// valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullifierTree<Backend = Smt> {
    smt: Backend,
}

impl<Backend> Default for NullifierTree<Backend>
where
    Backend: Default,
{
    fn default() -> Self {
        Self { smt: Default::default() }
    }
}

impl<Backend> NullifierTree<Backend>
where
    Backend: NullifierTreeBackend<Error = MerkleError>,
{
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The depth of the nullifier tree.
    pub const DEPTH: u8 = SMT_DEPTH;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new `NullifierTree` from its inner representation.
    ///
    /// # Invariants
    ///
    /// See the documentation on [`NullifierTreeBackend`] trait documentation.
    pub fn new_unchecked(backend: Backend) -> Self {
        NullifierTree { smt: backend }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the nullifier SMT.
    pub fn root(&self) -> Word {
        self.smt.root()
    }

    /// Returns the number of spent nullifiers in this tree.
    pub fn num_nullifiers(&self) -> usize {
        self.smt.num_entries()
    }

    /// Returns an iterator over the nullifiers and their block numbers in the tree.
    pub fn entries(&self) -> impl Iterator<Item = (Nullifier, BlockNumber)> {
        self.smt.entries().map(|(nullifier, value)| {
            (
                Nullifier::from_raw(nullifier),
                NullifierBlock::new(value)
                    .expect("SMT should only store valid NullifierBlocks")
                    .into(),
            )
        })
    }

    /// Returns a [`NullifierWitness`] of the leaf associated with the `nullifier`.
    ///
    /// Conceptually, such a witness is a Merkle path to the leaf, as well as the leaf itself.
    ///
    /// This witness is a proof of the current block number of the given nullifier. If that block
    /// number is zero, it proves that the nullifier is unspent.
    pub fn open(&self, nullifier: &Nullifier) -> NullifierWitness {
        NullifierWitness::new(self.smt.open(&nullifier.as_word()))
    }

    /// Returns the block number for the given nullifier or `None` if the nullifier wasn't spent
    /// yet.
    pub fn get_block_num(&self, nullifier: &Nullifier) -> Option<BlockNumber> {
        let nullifier_block = self.smt.get_value(&nullifier.as_word());
        if nullifier_block.is_unspent() {
            return None;
        }

        Some(nullifier_block.into())
    }

    /// Computes a mutation set resulting from inserting the provided nullifiers into this nullifier
    /// tree.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a nullifier in the provided iterator was already spent.
    pub fn compute_mutations<I>(
        &self,
        nullifiers: impl IntoIterator<Item = (Nullifier, BlockNumber), IntoIter = I>,
    ) -> Result<NullifierMutationSet, NullifierTreeError>
    where
        I: Iterator<Item = (Nullifier, BlockNumber)> + Clone,
    {
        let nullifiers = nullifiers.into_iter();
        for (nullifier, _) in nullifiers.clone() {
            if self.get_block_num(&nullifier).is_some() {
                return Err(NullifierTreeError::NullifierAlreadySpent(nullifier));
            }
        }

        let mutation_set = self
            .smt
            .compute_mutations(
                nullifiers
                    .into_iter()
                    .map(|(nullifier, block_num)| {
                        (nullifier.as_word(), NullifierBlock::from(block_num).into())
                    })
                    .collect::<Vec<_>>(),
            )
            .map_err(NullifierTreeError::ComputeMutations)?;

        Ok(NullifierMutationSet::new(mutation_set))
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Marks the given nullifier as spent at the given block number.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the nullifier was already spent.
    pub fn mark_spent(
        &mut self,
        nullifier: Nullifier,
        block_num: BlockNumber,
    ) -> Result<(), NullifierTreeError> {
        let prev_nullifier_value = self
            .smt
            .insert(nullifier.as_word(), NullifierBlock::from(block_num))
            .map_err(NullifierTreeError::MaxLeafEntriesExceeded)?;

        if prev_nullifier_value.is_spent() {
            Err(NullifierTreeError::NullifierAlreadySpent(nullifier))
        } else {
            Ok(())
        }
    }

    /// Applies mutations to the nullifier tree.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `mutations` was computed on a tree with a different root than this one.
    pub fn apply_mutations(
        &mut self,
        mutations: NullifierMutationSet,
    ) -> Result<(), NullifierTreeError> {
        self.smt
            .apply_mutations(mutations.into_mutation_set())
            .map_err(NullifierTreeError::TreeRootConflict)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NullifierTree {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.entries().collect::<Vec<_>>().write_into(target);
    }
}

impl Deserializable for NullifierTree {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let entries = Vec::<(Nullifier, BlockNumber)>::read_from(source)?;
        Self::with_entries(entries)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// NULLIFIER MUTATION SET
// ================================================================================================

/// A newtype wrapper around a [`MutationSet`] for use in the [`NullifierTree`].
///
/// It guarantees that applying the contained mutations will result in a nullifier tree where
/// nullifier's block numbers are not updated (except if they were unspent before), ensuring that
/// nullifiers are only spent once.
///
/// It is returned by and used in methods on the [`NullifierTree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullifierMutationSet {
    mutation_set: MutationSet<SMT_DEPTH, Word, Word>,
}

impl NullifierMutationSet {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NullifierMutationSet`] from the provided raw mutation set.
    fn new(mutation_set: MutationSet<SMT_DEPTH, Word, Word>) -> Self {
        Self { mutation_set }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the underlying [`MutationSet`].
    pub fn as_mutation_set(&self) -> &MutationSet<SMT_DEPTH, Word, Word> {
        &self.mutation_set
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Consumes self and returns the underlying [`MutationSet`].
    pub fn into_mutation_set(self) -> MutationSet<SMT_DEPTH, Word, Word> {
        self.mutation_set
    }
}

// NULLIFIER BLOCK
// ================================================================================================

/// The [`BlockNumber`] at which a [`Nullifier`] was consumed.
///
/// Since there are no nullifiers in the genesis block the [`BlockNumber::GENESIS`] is used to
/// signal an unconsumed nullifier.
///
/// This type can be converted to a [`Word`] which is laid out like this:
///
/// ```text
/// [block_num, 0, 0, 0]
/// ```
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct NullifierBlock(BlockNumber);

impl NullifierBlock {
    pub const UNSPENT: NullifierBlock = NullifierBlock(BlockNumber::GENESIS);

    /// Returns a new [NullifierBlock] constructed from the provided word.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The 0th element in the word is not a valid [BlockNumber].
    /// - Any of the remaining elements is non-zero.
    pub fn new(word: Word) -> Result<Self, NullifierTreeError> {
        let block_num = u32::try_from(word[0].as_int())
            .map(BlockNumber::from)
            .map_err(|_| NullifierTreeError::InvalidNullifierBlockNumber(word))?;

        if word[1..4].iter().any(|felt| *felt != Felt::ZERO) {
            return Err(NullifierTreeError::InvalidNullifierBlockNumber(word));
        }

        Ok(NullifierBlock(block_num))
    }

    /// Returns true if the nullifier has already been spent.
    pub fn is_spent(&self) -> bool {
        !self.is_unspent()
    }

    /// Returns true if the nullifier has not yet been spent.
    pub fn is_unspent(&self) -> bool {
        self == &Self::UNSPENT
    }
}

impl From<BlockNumber> for NullifierBlock {
    fn from(block_num: BlockNumber) -> Self {
        Self(block_num)
    }
}

impl From<NullifierBlock> for BlockNumber {
    fn from(value: NullifierBlock) -> BlockNumber {
        value.0
    }
}

impl From<NullifierBlock> for Word {
    fn from(value: NullifierBlock) -> Word {
        Word::from([Felt::from(value.0), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }
}

impl TryFrom<Word> for NullifierBlock {
    type Error = NullifierTreeError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::NullifierTree;
    use crate::Word;
    use crate::block::BlockNumber;
    use crate::block::nullifier_tree::NullifierBlock;
    use crate::errors::NullifierTreeError;
    use crate::note::Nullifier;

    #[test]
    fn leaf_value_encode_decode() {
        let block_num = BlockNumber::from(0xffff_ffff_u32);
        let nullifier_block = NullifierBlock::from(block_num);
        let block_num_recovered = nullifier_block.into();
        assert_eq!(block_num, block_num_recovered);
    }

    #[test]
    fn leaf_value_encoding() {
        let block_num = BlockNumber::from(123);
        let nullifier_value = NullifierBlock::from(block_num);
        assert_eq!(
            nullifier_value,
            NullifierBlock::new(Word::from([block_num.as_u32(), 0, 0, 0u32])).unwrap()
        );
    }

    #[test]
    fn leaf_value_decoding() {
        let block_num = 123;
        let nullifier_value = NullifierBlock::new(Word::from([block_num, 0, 0, 0u32])).unwrap();
        let decoded_block_num: BlockNumber = nullifier_value.into();

        assert_eq!(decoded_block_num, block_num.into());
    }

    #[test]
    fn apply_mutations() {
        let nullifier1 = Nullifier::dummy(1);
        let nullifier2 = Nullifier::dummy(2);
        let nullifier3 = Nullifier::dummy(3);

        let block1 = BlockNumber::from(1);
        let block2 = BlockNumber::from(2);
        let block3 = BlockNumber::from(3);

        let mut tree = NullifierTree::with_entries([(nullifier1, block1)]).unwrap();

        // Check that passing nullifier2 twice with different values will use the last value.
        let mutations = tree
            .compute_mutations([(nullifier2, block1), (nullifier3, block3), (nullifier2, block2)])
            .unwrap();

        tree.apply_mutations(mutations).unwrap();

        assert_eq!(tree.num_nullifiers(), 3);
        assert_eq!(tree.get_block_num(&nullifier1).unwrap(), block1);
        assert_eq!(tree.get_block_num(&nullifier2).unwrap(), block2);
        assert_eq!(tree.get_block_num(&nullifier3).unwrap(), block3);
    }

    #[test]
    fn nullifier_already_spent() {
        let nullifier1 = Nullifier::dummy(1);

        let block1 = BlockNumber::from(1);
        let block2 = BlockNumber::from(2);

        let mut tree = NullifierTree::with_entries([(nullifier1, block1)]).unwrap();

        // Attempt to insert nullifier 1 again at _the same_ block number.
        let err = tree.clone().compute_mutations([(nullifier1, block1)]).unwrap_err();
        assert_matches!(err, NullifierTreeError::NullifierAlreadySpent(nullifier) if nullifier == nullifier1);

        let err = tree.clone().mark_spent(nullifier1, block1).unwrap_err();
        assert_matches!(err, NullifierTreeError::NullifierAlreadySpent(nullifier) if nullifier == nullifier1);

        // Attempt to insert nullifier 1 again at a different block number.
        let err = tree.clone().compute_mutations([(nullifier1, block2)]).unwrap_err();
        assert_matches!(err, NullifierTreeError::NullifierAlreadySpent(nullifier) if nullifier == nullifier1);

        let err = tree.mark_spent(nullifier1, block2).unwrap_err();
        assert_matches!(err, NullifierTreeError::NullifierAlreadySpent(nullifier) if nullifier == nullifier1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn large_smt_backend_basic_operations() {
        use miden_crypto::merkle::smt::{LargeSmt, MemoryStorage};

        // Create test data
        let nullifier1 = Nullifier::dummy(1);
        let nullifier2 = Nullifier::dummy(2);
        let nullifier3 = Nullifier::dummy(3);

        let block1 = BlockNumber::from(1);
        let block2 = BlockNumber::from(2);
        let block3 = BlockNumber::from(3);

        // Create NullifierTree with LargeSmt backend
        let mut tree = NullifierTree::new_unchecked(
            LargeSmt::with_entries(
                MemoryStorage::default(),
                [
                    (nullifier1.as_word(), NullifierBlock::from(block1).into()),
                    (nullifier2.as_word(), NullifierBlock::from(block2).into()),
                ],
            )
            .unwrap(),
        );

        // Test basic operations
        assert_eq!(tree.num_nullifiers(), 2);
        assert_eq!(tree.get_block_num(&nullifier1).unwrap(), block1);
        assert_eq!(tree.get_block_num(&nullifier2).unwrap(), block2);

        // Test opening
        let _witness1 = tree.open(&nullifier1);

        // Test mutations
        tree.mark_spent(nullifier3, block3).unwrap();
        assert_eq!(tree.num_nullifiers(), 3);
        assert_eq!(tree.get_block_num(&nullifier3).unwrap(), block3);
    }

    #[cfg(feature = "std")]
    #[test]
    fn large_smt_backend_nullifier_already_spent() {
        use miden_crypto::merkle::smt::{LargeSmt, MemoryStorage};

        let nullifier1 = Nullifier::dummy(1);

        let block1 = BlockNumber::from(1);
        let block2 = BlockNumber::from(2);

        let mut tree = NullifierTree::new_unchecked(
            LargeSmt::with_entries(
                MemoryStorage::default(),
                [(nullifier1.as_word(), NullifierBlock::from(block1).into())],
            )
            .unwrap(),
        );

        assert_eq!(tree.get_block_num(&nullifier1).unwrap(), block1);

        let err = tree.mark_spent(nullifier1, block2).unwrap_err();
        assert_matches!(err, NullifierTreeError::NullifierAlreadySpent(nullifier) if nullifier == nullifier1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn large_smt_backend_apply_mutations() {
        use miden_crypto::merkle::smt::{LargeSmt, MemoryStorage};

        let nullifier1 = Nullifier::dummy(1);
        let nullifier2 = Nullifier::dummy(2);
        let nullifier3 = Nullifier::dummy(3);

        let block1 = BlockNumber::from(1);
        let block2 = BlockNumber::from(2);
        let block3 = BlockNumber::from(3);

        let mut tree = LargeSmt::with_entries(
            MemoryStorage::default(),
            [(nullifier1.as_word(), NullifierBlock::from(block1).into())],
        )
        .map(NullifierTree::new_unchecked)
        .unwrap();

        let mutations =
            tree.compute_mutations([(nullifier2, block2), (nullifier3, block3)]).unwrap();

        tree.apply_mutations(mutations).unwrap();

        assert_eq!(tree.num_nullifiers(), 3);
        assert_eq!(tree.get_block_num(&nullifier1).unwrap(), block1);
        assert_eq!(tree.get_block_num(&nullifier2).unwrap(), block2);
        assert_eq!(tree.get_block_num(&nullifier3).unwrap(), block3);
    }

    #[cfg(feature = "std")]
    #[test]
    fn large_smt_backend_same_root_as_regular_smt() {
        use miden_crypto::merkle::smt::{LargeSmt, MemoryStorage};

        let nullifier1 = Nullifier::dummy(1);
        let nullifier2 = Nullifier::dummy(2);

        let block1 = BlockNumber::from(1);
        let block2 = BlockNumber::from(2);

        // Create tree with LargeSmt backend
        let large_tree = LargeSmt::with_entries(
            MemoryStorage::default(),
            [
                (nullifier1.as_word(), NullifierBlock::from(block1).into()),
                (nullifier2.as_word(), NullifierBlock::from(block2).into()),
            ],
        )
        .map(NullifierTree::new_unchecked)
        .unwrap();

        // Create tree with regular Smt backend
        let regular_tree =
            NullifierTree::with_entries([(nullifier1, block1), (nullifier2, block2)]).unwrap();

        // Both should have the same root
        assert_eq!(large_tree.root(), regular_tree.root());

        // Both should have the same nullifier entries
        let large_entries: std::collections::BTreeMap<_, _> = large_tree.entries().collect();
        let regular_entries: std::collections::BTreeMap<_, _> = regular_tree.entries().collect();

        assert_eq!(large_entries, regular_entries);
    }
}
