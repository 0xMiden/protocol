use miden_crypto::merkle::smt::{PartialSmt, SmtLeaf};

use super::{AccountWitness, account_id_to_smt_key};
use crate::Word;
use crate::account::AccountId;
use crate::errors::AccountTreeError;

/// The partial sparse merkle tree containing the state commitments of accounts in the chain.
///
/// This is the partial version of [`AccountTree`](crate::block::account_tree::AccountTree).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartialAccountTree {
    smt: PartialSmt,
}

impl PartialAccountTree {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new partial account tree with the provided root that does not track any account
    /// IDs.
    pub fn new(root: Word) -> Self {
        PartialAccountTree { smt: PartialSmt::new(root) }
    }

    /// Returns a new [`PartialAccountTree`] instantiated with the provided entries.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the merkle paths of the witnesses do not result in the same tree root.
    /// - there are multiple witnesses for the same ID _prefix_.
    pub fn with_witnesses(
        witnesses: impl IntoIterator<Item = AccountWitness>,
    ) -> Result<Self, AccountTreeError> {
        let mut witnesses = witnesses.into_iter();

        let Some(first_witness) = witnesses.next() else {
            return Ok(Self::default());
        };

        // Construct a partial account tree with the root of the first witness.
        // SAFETY: This is guaranteed to _not_ result in a tree with more than one entry because
        // the account witness type guarantees that it tracks zero or one entries.
        let partial_smt = PartialSmt::from_proofs([first_witness.into_proof()])
            .map_err(AccountTreeError::TreeRootConflict)?;
        let mut tree = PartialAccountTree { smt: partial_smt };

        // Add all remaining witnesses to the tree, which validates the invariants of the account
        // tree.
        for witness in witnesses {
            tree.track_account(witness)?;
        }

        Ok(tree)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns an opening of the leaf associated with the `account_id`. This is a proof of the
    /// current state commitment of the given account ID.
    ///
    /// Conceptually, an opening is a Merkle path to the leaf, as well as the leaf itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the account ID is not tracked by this account tree.
    pub fn open(&self, account_id: AccountId) -> Result<AccountWitness, AccountTreeError> {
        let key = account_id_to_smt_key(account_id);

        self.smt
            .open(&key)
            .map(|proof| AccountWitness::from_smt_proof(account_id, proof))
            .map_err(|source| AccountTreeError::UntrackedAccountId { id: account_id, source })
    }

    /// Returns the current state commitment of the given account ID.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the account ID is not tracked by this account tree.
    pub fn get(&self, account_id: AccountId) -> Result<Word, AccountTreeError> {
        let key = account_id_to_smt_key(account_id);
        self.smt
            .get_value(&key)
            .map_err(|source| AccountTreeError::UntrackedAccountId { id: account_id, source })
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> Word {
        self.smt.root()
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the given account witness to the partial tree and tracks it. Once an account has
    /// been added to the tree, it can be updated using [`Self::upsert_state_commitments`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - after the witness' merkle path was added, the partial account tree has a different root
    ///   than before it was added (except when the first witness is added).
    /// - there exists a leaf in the tree whose account ID prefix matches the one in the provided
    ///   witness.
    pub fn track_account(&mut self, witness: AccountWitness) -> Result<(), AccountTreeError> {
        let id_prefix = witness.id().prefix();
        let id_key = account_id_to_smt_key(witness.id());

        // If a leaf with the same prefix is already tracked by this partial tree, consider it an
        // error.
        //
        // We return an error even for empty leaves, because tracking the same ID prefix twice
        // indicates that different IDs are attempted to be tracked. It would technically not
        // violate the invariant of the tree that it only tracks zero or one entries per leaf, but
        // since tracking the same ID twice should practically never happen, we return an error, out
        // of an abundance of caution.
        if self.smt.get_leaf(&id_key).is_ok() {
            return Err(AccountTreeError::DuplicateIdPrefix { duplicate_prefix: id_prefix });
        }

        self.smt
            .add_proof(witness.into_proof())
            .map_err(AccountTreeError::TreeRootConflict)?;

        Ok(())
    }

    /// Inserts or updates the provided account ID -> state commitment updates into the partial tree
    /// which results in a new tree root.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the prefix of the account ID already exists in the tree.
    /// - the account_id is not tracked by this partial account tree.
    pub fn upsert_state_commitments(
        &mut self,
        updates: impl IntoIterator<Item = (AccountId, Word)>,
    ) -> Result<(), AccountTreeError> {
        for (account_id, state_commitment) in updates {
            self.insert(account_id, state_commitment)?;
        }

        Ok(())
    }

    /// Inserts the state commitment for the given account ID, returning the previous state
    /// commitment associated with that ID.
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the prefix of the account ID already exists in the tree.
    /// - the account_id is not tracked by this partial account tree.
    fn insert(
        &mut self,
        account_id: AccountId,
        state_commitment: Word,
    ) -> Result<Word, AccountTreeError> {
        let key = account_id_to_smt_key(account_id);

        // If there exists a tracked leaf whose key is _not_ the one we're about to overwrite, then
        // we would insert the new commitment next to an existing account ID with the same prefix,
        // which is an error.
        // Note that if the leaf is empty, that's fine. It means it is tracked by the partial SMT,
        // but no account ID is inserted yet.
        // Also note that the multiple variant cannot occur by construction of the tree.
        if let Ok(SmtLeaf::Single((existing_key, _))) = self.smt.get_leaf(&key)
            && key != existing_key
        {
            return Err(AccountTreeError::DuplicateIdPrefix {
                duplicate_prefix: account_id.prefix(),
            });
        }

        self.smt
            .insert(key, state_commitment)
            .map_err(|source| AccountTreeError::UntrackedAccountId { id: account_id, source })
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_crypto::merkle::smt::Smt;

    use super::*;
    use crate::block::account_tree::AccountTree;
    use crate::block::account_tree::tests::setup_duplicate_prefix_ids;

    #[test]
    fn insert_fails_on_duplicate_prefix() -> anyhow::Result<()> {
        let mut full_tree = AccountTree::<Smt>::default();

        let [(id0, commitment0), (id1, commitment1)] = setup_duplicate_prefix_ids();

        full_tree.insert(id0, commitment0).unwrap();
        let witness = full_tree.open(id0);

        let mut partial_tree = PartialAccountTree::with_witnesses([witness])?;

        partial_tree.insert(id0, commitment0).unwrap();
        assert_eq!(partial_tree.get(id0).unwrap(), commitment0);

        let err = partial_tree.insert(id1, commitment1).unwrap_err();

        assert_matches!(err, AccountTreeError::DuplicateIdPrefix {
          duplicate_prefix
        } if duplicate_prefix == id0.prefix());

        partial_tree.upsert_state_commitments([(id1, commitment1)]).unwrap_err();

        assert_matches!(err, AccountTreeError::DuplicateIdPrefix {
          duplicate_prefix
        } if duplicate_prefix == id0.prefix());

        Ok(())
    }

    #[test]
    fn insert_succeeds_on_multiple_updates() {
        let mut full_tree = AccountTree::<Smt>::default();
        let [(id0, commitment0), (_, commitment1)] = setup_duplicate_prefix_ids();

        full_tree.insert(id0, commitment0).unwrap();
        let witness = full_tree.open(id0);

        let mut partial_tree = PartialAccountTree::new(full_tree.root());

        partial_tree.track_account(witness.clone()).unwrap();
        assert_eq!(
            partial_tree.open(id0).unwrap(),
            witness,
            "full tree witness and partial tree witness should be the same"
        );
        assert_eq!(
            partial_tree.root(),
            full_tree.root(),
            "full tree root and partial tree root should be the same"
        );

        partial_tree.insert(id0, commitment0).unwrap();
        partial_tree.insert(id0, commitment1).unwrap();
        assert_eq!(partial_tree.get(id0).unwrap(), commitment1);
    }

    #[test]
    fn upsert_state_commitments_fails_on_untracked_key() {
        let mut partial_tree = PartialAccountTree::default();
        let [update, _] = setup_duplicate_prefix_ids();

        let err = partial_tree.upsert_state_commitments([update]).unwrap_err();
        assert_matches!(err, AccountTreeError::UntrackedAccountId { id, .. }
          if id == update.0
        )
    }

    #[test]
    fn track_fails_on_duplicate_prefix() {
        // Use a raw Smt since an account tree would not allow us to get the witnesses for two
        // account IDs with the same prefix.
        let full_tree = Smt::with_entries(
            setup_duplicate_prefix_ids()
                .map(|(id, commitment)| (account_id_to_smt_key(id), commitment)),
        )
        .unwrap();

        let [(id0, _), (id1, _)] = setup_duplicate_prefix_ids();

        let key0 = account_id_to_smt_key(id0);
        let key1 = account_id_to_smt_key(id1);
        let proof0 = full_tree.open(&key0);
        let proof1 = full_tree.open(&key1);
        assert_eq!(proof0.leaf(), proof1.leaf());

        let witness0 =
            AccountWitness::new(id0, proof0.get(&key0).unwrap(), proof0.into_parts().0).unwrap();
        let witness1 =
            AccountWitness::new(id1, proof1.get(&key1).unwrap(), proof1.into_parts().0).unwrap();

        let mut partial_tree = PartialAccountTree::with_witnesses([witness0]).unwrap();
        let err = partial_tree.track_account(witness1).unwrap_err();

        assert_matches!(err, AccountTreeError::DuplicateIdPrefix { duplicate_prefix, .. }
          if duplicate_prefix == id1.prefix()
        )
    }
}
