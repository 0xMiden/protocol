use super::{NullifierBlock, NullifierWitness};
use crate::Word;
use crate::block::BlockNumber;
use crate::crypto::merkle::smt::PartialSmt;
use crate::errors::NullifierTreeError;
use crate::note::Nullifier;

// PARTIAL NULLIFIER TREE
// ================================================================================================

/// The partial sparse merkle tree containing the nullifiers of consumed notes.
///
/// A nullifier can only ever be spent once and its value in the tree is the block number at which
/// it was spent.
///
/// The tree guarantees that once a nullifier has been inserted into the tree, its block number does
/// not change. Note that inserting the nullifier multiple times with the same block number is
/// valid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartialNullifierTree(PartialSmt);

impl PartialNullifierTree {
    /// Creates a new partial nullifier tree with the provided root that does not track any
    /// nullifiers.
    pub fn new(root: Word) -> Self {
        PartialNullifierTree(PartialSmt::new(root))
    }

    /// Returns a new [`PartialNullifierTree`] instantiated with the provided entries.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the merkle paths of the witnesses do not result in the same tree root.
    pub fn with_witnesses(
        witnesses: impl IntoIterator<Item = NullifierWitness>,
    ) -> Result<Self, NullifierTreeError> {
        PartialSmt::from_proofs(witnesses.into_iter().map(NullifierWitness::into_proof))
            .map_err(NullifierTreeError::TreeRootConflict)
            .map(Self)
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> Word {
        self.0.root()
    }

    /// Adds the given nullifier witness to the partial tree and tracks it.
    ///
    /// Once a nullifier has been added to the tree, it can be marked as spent using
    /// [`Self::mark_spent`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - after the witness' merkle path was added, the partial nullifier tree has a different root
    ///   than before it was added.
    pub fn track_nullifier(&mut self, witness: NullifierWitness) -> Result<(), NullifierTreeError> {
        let (path, leaf) = witness.into_proof().into_parts();
        self.0.add_path(leaf, path).map_err(NullifierTreeError::TreeRootConflict)
    }

    /// Marks the given nullifier as spent at the given block number.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a nullifier was already spent.
    /// - a nullifier is not tracked by this partial nullifier tree, that is, its
    ///   [`NullifierWitness`] was not added to the tree previously.
    pub fn mark_spent(
        &mut self,
        nullifier: Nullifier,
        block_num: BlockNumber,
    ) -> Result<(), NullifierTreeError> {
        let prev_nullifier_value: NullifierBlock = self
            .0
            .insert(nullifier.as_word(), NullifierBlock::from(block_num).into())
            .map_err(|source| NullifierTreeError::UntrackedNullifier { nullifier, source })?
            .try_into()?;

        if prev_nullifier_value.is_spent() {
            Err(NullifierTreeError::NullifierAlreadySpent(nullifier))
        } else {
            Ok(())
        }
    }

    /// Marks the given nullifiers as spent at the given block number.
    ///
    /// # Errors
    ///
    /// See [`Self::mark_spent`] for the possible error conditions.
    pub fn mark_spent_all(
        &mut self,
        nullifiers: impl IntoIterator<Item = Nullifier>,
        block_num: BlockNumber,
    ) -> Result<(), NullifierTreeError> {
        for nullifier in nullifiers {
            self.mark_spent(nullifier, block_num)?;
        }

        Ok(())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_crypto::merkle::smt::Smt;
    use winter_rand_utils::rand_value;

    use super::*;
    use crate::block::nullifier_tree::NullifierTree;
    use crate::{EMPTY_WORD, Word};

    /// Test that using a stale nullifier witness together with a current one results in a different
    /// tree root and thus an error.
    #[test]
    fn partial_nullifier_tree_root_mismatch() {
        let key0 = rand_value::<Word>();
        let key1 = rand_value::<Word>();
        let key2 = rand_value::<Word>();

        let value0 = EMPTY_WORD;
        let value1 = rand_value::<Word>();
        let value2 = EMPTY_WORD;

        let kv_pairs = vec![(key0, value0)];

        let mut full = Smt::with_entries(kv_pairs).unwrap();
        let stale_proof0 = full.open(&key0);
        // Insert a non-empty value so the nullifier tree's root changes.
        full.insert(key1, value1).unwrap();
        full.insert(key2, value2).unwrap();
        let proof2 = full.open(&key2);

        assert_ne!(stale_proof0.compute_root(), proof2.compute_root());

        let mut partial =
            PartialNullifierTree::with_witnesses([NullifierWitness::new(stale_proof0)]).unwrap();

        let error = partial.track_nullifier(NullifierWitness::new(proof2)).unwrap_err();

        assert_matches!(error, NullifierTreeError::TreeRootConflict(_));
    }

    #[test]
    fn nullifier_already_spent() {
        let nullifier1 = Nullifier::dummy(1);

        let block1 = BlockNumber::from(1);
        let block2 = BlockNumber::from(2);

        let tree = NullifierTree::with_entries([(nullifier1, block1)]).unwrap();

        let witness = tree.open(&nullifier1);

        let mut partial_tree = PartialNullifierTree::with_witnesses([witness]).unwrap();

        // Attempt to insert nullifier 1 again at a different block number.
        let err = partial_tree.mark_spent_all([nullifier1], block2).unwrap_err();

        assert_matches!(err, NullifierTreeError::NullifierAlreadySpent(nullifier) if nullifier == nullifier1);
    }

    #[test]
    fn full_and_partial_nullifier_tree_consistency() {
        let nullifier1 = Nullifier::dummy(1);
        let nullifier2 = Nullifier::dummy(2);
        let nullifier3 = Nullifier::dummy(3);

        let block1 = BlockNumber::from(1);
        let block2 = BlockNumber::from(2);
        let block3 = BlockNumber::from(3);

        let mut tree =
            NullifierTree::with_entries([(nullifier1, block1), (nullifier2, block2)]).unwrap();

        let mut partial_tree = PartialNullifierTree::new(tree.root());

        for nullifier in [nullifier1, nullifier2, nullifier3] {
            let witness = tree.open(&nullifier);
            partial_tree.track_nullifier(witness).unwrap();
        }

        assert_eq!(tree.root(), partial_tree.root());

        // Insert a new value into partial and full tree and assert the root is the same.
        tree.mark_spent(nullifier3, block3).unwrap();
        partial_tree.mark_spent(nullifier3, block3).unwrap();

        assert_eq!(tree.root(), partial_tree.root());
    }
}
