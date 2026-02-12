use alloc::string::ToString;
use alloc::vec::Vec;

use miden_crypto::merkle::smt::LeafIndex;

use crate::Word;
use crate::account::{AccountId, AccountIdPrefix};
use crate::crypto::merkle::MerkleError;
use crate::crypto::merkle::smt::{MutationSet, SMT_DEPTH, Smt, SmtLeaf};
use crate::errors::AccountTreeError;
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

mod partial;
pub use partial::PartialAccountTree;

mod witness;
pub use witness::AccountWitness;

mod backend;
pub use backend::AccountTreeBackend;

// FREE HELPER FUNCTIONS
// ================================================================================================
// These module-level functions provide conversions between AccountIds and SMT keys.
// They avoid the need for awkward syntax like account_id_to_smt_key().

const KEY_PREFIX_IDX: usize = 3;
const KEY_SUFFIX_IDX: usize = 2;

/// Converts an [`AccountId`] to an SMT key for use in account trees.
///
/// The key is constructed with the account ID suffix at index 2 and prefix at index 3.
pub fn account_id_to_smt_key(account_id: AccountId) -> Word {
    let mut key = Word::empty();
    key[KEY_SUFFIX_IDX] = account_id.suffix();
    key[KEY_PREFIX_IDX] = account_id.prefix().as_felt();
    key
}

/// Recovers an [`AccountId`] from an SMT key.
///
/// # Panics
///
/// Panics if the key does not represent a valid account ID. This should never happen when used
/// with keys from account trees, as the tree only stores valid IDs.
pub fn smt_key_to_account_id(key: Word) -> AccountId {
    AccountId::try_from([key[KEY_PREFIX_IDX], key[KEY_SUFFIX_IDX]])
        .expect("account tree should only contain valid IDs")
}

/// Converts an AccountId to an SMT leaf index for use with MerkleStore operations.
pub fn account_id_to_smt_index(account_id: AccountId) -> LeafIndex<SMT_DEPTH> {
    account_id_to_smt_key(account_id).into()
}

// ACCOUNT TREE
// ================================================================================================

/// The sparse merkle tree of all accounts in the blockchain.
///
/// The key is the [`AccountId`] while the value is the current state commitment of the account,
/// i.e. [`Account::commitment`](crate::account::Account::commitment). If the account is new, then
/// the commitment is the [`EMPTY_WORD`](crate::EMPTY_WORD).
///
/// Each account ID occupies exactly one leaf in the tree, which is identified by its
/// [`AccountId::prefix`]. In other words, account ID prefixes are unique in the blockchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountTree<S = Smt> {
    smt: S,
}

impl<S> Default for AccountTree<S>
where
    S: Default,
{
    fn default() -> Self {
        Self { smt: Default::default() }
    }
}

impl<S> AccountTree<S>
where
    S: AccountTreeBackend<Error = MerkleError>,
{
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The depth of the account tree.
    pub const DEPTH: u8 = SMT_DEPTH;

    /// The index of the account ID suffix in the SMT key.
    pub(super) const KEY_SUFFIX_IDX: usize = 2;
    /// The index of the account ID prefix in the SMT key.
    pub(super) const KEY_PREFIX_IDX: usize = 3;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new `AccountTree` from its inner representation with validation.
    ///
    /// This constructor validates that the provided SMT upholds the guarantees of the
    /// [`AccountTree`]. The constructor ensures only the uniqueness of the account ID prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The SMT contains duplicate account ID prefixes
    pub fn new(smt: S) -> Result<Self, AccountTreeError> {
        for (_leaf_idx, leaf) in smt.leaves() {
            match leaf {
                SmtLeaf::Empty(_) => {
                    // Empty leaves are fine (shouldn't be returned by leaves() but handle anyway)
                    continue;
                },
                SmtLeaf::Single((key, _)) => {
                    // Single entry is good - verify it's a valid account ID
                    smt_key_to_account_id(key);
                },
                SmtLeaf::Multiple(entries) => {
                    // Multiple entries means duplicate prefixes
                    // Extract one of the keys to identify the duplicate prefix
                    if let Some((key, _)) = entries.first() {
                        let account_id = smt_key_to_account_id(*key);
                        return Err(AccountTreeError::DuplicateIdPrefix {
                            duplicate_prefix: account_id.prefix(),
                        });
                    }
                },
            }
        }

        Ok(Self::new_unchecked(smt))
    }

    /// Creates a new `AccountTree` from its inner representation without validation.
    ///
    /// # Warning
    ///
    /// Assumes the provided SMT upholds the guarantees of the [`AccountTree`]. Specifically:
    /// - Each account ID prefix must be unique (no duplicate prefixes allowed)
    /// - The SMT should only contain valid account IDs and their state commitments
    ///
    /// See type-level documentation for more details on these invariants. Using this constructor
    /// with an SMT that violates these guarantees may lead to undefined behavior.
    pub fn new_unchecked(smt: S) -> Self {
        AccountTree { smt }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns an opening of the leaf associated with the `account_id`. This is a proof of the
    /// current state commitment of the given account ID.
    ///
    /// Conceptually, an opening is a Merkle path to the leaf, as well as the leaf itself.
    ///
    /// # Panics
    ///
    /// Panics if the SMT backend fails to open the leaf (only possible with `LargeSmt` backend).
    pub fn open(&self, account_id: AccountId) -> AccountWitness {
        let key = account_id_to_smt_key(account_id);
        let proof = self.smt.open(&key);

        AccountWitness::from_smt_proof(account_id, proof)
    }

    /// Returns the current state commitment of the given account ID.
    pub fn get(&self, account_id: AccountId) -> Word {
        let key = account_id_to_smt_key(account_id);
        self.smt.get_value(&key)
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> Word {
        self.smt.root()
    }

    /// Returns true if the tree contains a leaf for the given account ID prefix.
    pub fn contains_account_id_prefix(&self, account_id_prefix: AccountIdPrefix) -> bool {
        let key = Self::id_prefix_to_smt_key(account_id_prefix);
        let is_empty = matches!(self.smt.get_leaf(&key), SmtLeaf::Empty(_));
        !is_empty
    }

    /// Returns the number of account IDs in this tree.
    pub fn num_accounts(&self) -> usize {
        // Because each ID's prefix is unique in the tree and occupies a single leaf, the number of
        // IDs in the tree is equivalent to the number of leaves in the tree.
        self.smt.num_leaves()
    }

    /// Returns an iterator over the account ID state commitment pairs in the tree.
    pub fn account_commitments(&self) -> impl Iterator<Item = (AccountId, Word)> {
        self.smt.leaves().map(|(_leaf_idx, leaf)| {
            // SAFETY: By construction no Multiple variant is ever present in the tree.
            // The Empty variant is not returned by Smt::leaves, because it only returns leaves that
            // are actually present.
            let SmtLeaf::Single((key, commitment)) = leaf else {
                unreachable!("empty and multiple variant should never be encountered")
            };

            (
                // SAFETY: By construction, the tree only contains valid IDs.
                AccountId::try_from([key[Self::KEY_PREFIX_IDX], key[Self::KEY_SUFFIX_IDX]])
                    .expect("account tree should only contain valid IDs"),
                commitment,
            )
        })
    }

    /// Computes the necessary changes to insert the specified (account ID, state commitment) pairs
    /// into this tree, allowing for validation before applying those changes.
    ///
    /// [`Self::apply_mutations`] can be used in order to commit these changes to the tree.
    ///
    /// If the `concurrent` feature of `miden-crypto` is enabled, this function uses a parallel
    /// implementation to compute the mutations, otherwise it defaults to the sequential
    /// implementation.
    ///
    /// This is a thin wrapper around [`Smt::compute_mutations`]. See its documentation for more
    /// details.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - an insertion of an account ID would violate the uniqueness of account ID prefixes in the
    ///   tree.
    pub fn compute_mutations(
        &self,
        account_commitments: impl IntoIterator<Item = (AccountId, Word)>,
    ) -> Result<AccountMutationSet, AccountTreeError> {
        let mutation_set = self
            .smt
            .compute_mutations(Vec::from_iter(
                account_commitments
                    .into_iter()
                    .map(|(id, commitment)| (account_id_to_smt_key(id), commitment)),
            ))
            .map_err(AccountTreeError::ComputeMutations)?;

        for id_key in mutation_set.new_pairs().keys() {
            // Check if the insertion would be valid.
            match self.smt.get_leaf(id_key) {
                // Inserting into an empty leaf is valid.
                SmtLeaf::Empty(_) => (),
                SmtLeaf::Single((existing_key, _)) => {
                    // If the key matches the existing one, then we're updating the leaf, which is
                    // valid. If it does not match, then we would insert a duplicate.
                    if existing_key != *id_key {
                        return Err(AccountTreeError::DuplicateIdPrefix {
                            duplicate_prefix: smt_key_to_account_id(*id_key).prefix(),
                        });
                    }
                },
                SmtLeaf::Multiple(_) => {
                    unreachable!(
                        "account tree should never contain duplicate ID prefixes and therefore never a multiple leaf"
                    )
                },
            }
        }

        Ok(AccountMutationSet::new(mutation_set))
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

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
    pub fn insert(
        &mut self,
        account_id: AccountId,
        state_commitment: Word,
    ) -> Result<Word, AccountTreeError> {
        let key = account_id_to_smt_key(account_id);
        // SAFETY: account tree should not contain multi-entry leaves and so the maximum number
        // of entries per leaf should never be exceeded.
        let prev_value = self.smt.insert(key, state_commitment)
            .expect("account tree should always have a single value per key, and hence cannot exceed the maximum leaf number");

        // If the leaf of the account ID now has two or more entries, we've inserted a duplicate
        // prefix.
        if self.smt.get_leaf(&key).num_entries() >= 2 {
            return Err(AccountTreeError::DuplicateIdPrefix {
                duplicate_prefix: account_id.prefix(),
            });
        }

        Ok(prev_value)
    }

    /// Applies the prospective mutations computed with [`Self::compute_mutations`] to this tree.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `mutations` was computed on a tree with a different root than this one.
    pub fn apply_mutations(
        &mut self,
        mutations: AccountMutationSet,
    ) -> Result<(), AccountTreeError> {
        self.smt
            .apply_mutations(mutations.into_mutation_set())
            .map_err(AccountTreeError::ApplyMutations)
    }

    /// Applies the prospective mutations computed with [`Self::compute_mutations`] to this tree
    /// and returns the reverse mutation set.
    ///
    /// Applying the reverse mutation sets to the updated tree will revert the changes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `mutations` was computed on a tree with a different root than this one.
    pub fn apply_mutations_with_reversion(
        &mut self,
        mutations: AccountMutationSet,
    ) -> Result<AccountMutationSet, AccountTreeError> {
        let reversion = self
            .smt
            .apply_mutations_with_reversion(mutations.into_mutation_set())
            .map_err(AccountTreeError::ApplyMutations)?;
        Ok(AccountMutationSet::new(reversion))
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the SMT key of the given account ID prefix.
    fn id_prefix_to_smt_key(account_id: AccountIdPrefix) -> Word {
        // We construct this in such a way that we're forced to use the constants, so that when
        // they're updated, the other usages of the constants are also updated.
        let mut key = Word::empty();
        key[Self::KEY_PREFIX_IDX] = account_id.as_felt();

        key
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountTree {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account_commitments().collect::<Vec<_>>().write_into(target);
    }
}

impl Deserializable for AccountTree {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let entries = Vec::<(AccountId, Word)>::read_from(source)?;

        // Validate uniqueness of account ID prefixes before creating the tree
        let mut seen_prefixes = alloc::collections::BTreeSet::new();
        for (id, _) in &entries {
            if !seen_prefixes.insert(id.prefix()) {
                return Err(DeserializationError::InvalidValue(format!(
                    "Duplicate account ID prefix: {}",
                    id.prefix()
                )));
            }
        }

        // Create the SMT with validated entries
        let smt =
            Smt::with_entries(entries.into_iter().map(|(k, v)| (account_id_to_smt_key(k), v)))
                .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
        Ok(Self::new_unchecked(smt))
    }
}

// ACCOUNT MUTATION SET
// ================================================================================================

/// A newtype wrapper around a [`MutationSet`] for use in the [`AccountTree`].
///
/// It guarantees that applying the contained mutations will result in an account tree with unique
/// account ID prefixes.
///
/// It is returned by and used in methods on the [`AccountTree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMutationSet {
    mutation_set: MutationSet<SMT_DEPTH, Word, Word>,
}

impl AccountMutationSet {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AccountMutationSet`] from the provided raw mutation set.
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

// TESTS
// ================================================================================================

#[cfg(test)]
pub(super) mod tests {
    use std::vec::Vec;

    use assert_matches::assert_matches;

    use super::*;
    use crate::account::{AccountStorageMode, AccountType};
    use crate::testing::account_id::{AccountIdBuilder, account_id};

    pub(crate) fn setup_duplicate_prefix_ids() -> [(AccountId, Word); 2] {
        let id0 = AccountId::try_from(account_id(
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
            0xaabb_ccdd,
        ))
        .unwrap();
        let id1 = AccountId::try_from(account_id(
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
            0xaabb_ccff,
        ))
        .unwrap();
        assert_eq!(id0.prefix(), id1.prefix(), "test requires that these ids have the same prefix");

        let commitment0 = Word::from([0, 0, 0, 42u32]);
        let commitment1 = Word::from([0, 0, 0, 24u32]);

        assert_eq!(id0.prefix(), id1.prefix(), "test requires that these ids have the same prefix");
        [(id0, commitment0), (id1, commitment1)]
    }

    #[test]
    fn insert_fails_on_duplicate_prefix() {
        let mut tree = AccountTree::<Smt>::default();
        let [(id0, commitment0), (id1, commitment1)] = setup_duplicate_prefix_ids();

        tree.insert(id0, commitment0).unwrap();
        assert_eq!(tree.get(id0), commitment0);

        let err = tree.insert(id1, commitment1).unwrap_err();

        assert_matches!(err, AccountTreeError::DuplicateIdPrefix {
          duplicate_prefix
        } if duplicate_prefix == id0.prefix());
    }

    #[test]
    fn insert_succeeds_on_multiple_updates() {
        let mut tree = AccountTree::<Smt>::default();
        let [(id0, commitment0), (_, commitment1)] = setup_duplicate_prefix_ids();

        tree.insert(id0, commitment0).unwrap();
        tree.insert(id0, commitment1).unwrap();
        assert_eq!(tree.get(id0), commitment1);
    }

    #[test]
    fn apply_mutations() {
        let id0 = AccountIdBuilder::new().build_with_seed([5; 32]);
        let id1 = AccountIdBuilder::new().build_with_seed([6; 32]);
        let id2 = AccountIdBuilder::new().build_with_seed([7; 32]);

        let digest0 = Word::from([0, 0, 0, 1u32]);
        let digest1 = Word::from([0, 0, 0, 2u32]);
        let digest2 = Word::from([0, 0, 0, 3u32]);
        let digest3 = Word::from([0, 0, 0, 4u32]);

        let mut tree = AccountTree::with_entries([(id0, digest0), (id1, digest1)]).unwrap();

        let mutations = tree
            .compute_mutations([(id0, digest1), (id1, digest2), (id2, digest3)])
            .unwrap();

        tree.apply_mutations(mutations).unwrap();

        assert_eq!(tree.num_accounts(), 3);
        assert_eq!(tree.get(id0), digest1);
        assert_eq!(tree.get(id1), digest2);
        assert_eq!(tree.get(id2), digest3);
    }

    #[test]
    fn duplicates_in_compute_mutations() {
        let [pair0, pair1] = setup_duplicate_prefix_ids();
        let id2 = AccountIdBuilder::new().build_with_seed([5; 32]);
        let commitment2 = Word::from([0, 0, 0, 99u32]);

        let tree = AccountTree::with_entries([pair0, (id2, commitment2)]).unwrap();
        let err = tree.compute_mutations([pair1]).unwrap_err();

        assert_matches!(err, AccountTreeError::DuplicateIdPrefix {
          duplicate_prefix
        } if duplicate_prefix == pair1.0.prefix());
    }

    #[test]
    fn account_commitments() {
        let id0 = AccountIdBuilder::new().build_with_seed([5; 32]);
        let id1 = AccountIdBuilder::new().build_with_seed([6; 32]);
        let id2 = AccountIdBuilder::new().build_with_seed([7; 32]);

        let digest0 = Word::from([0, 0, 0, 1u32]);
        let digest1 = Word::from([0, 0, 0, 2u32]);
        let digest2 = Word::from([0, 0, 0, 3u32]);
        let empty_digest = Word::empty();

        let mut tree =
            AccountTree::with_entries([(id0, digest0), (id1, digest1), (id2, digest2)]).unwrap();

        // remove id2
        tree.insert(id2, empty_digest).unwrap();

        assert_eq!(tree.num_accounts(), 2);

        let accounts: Vec<_> = tree.account_commitments().collect();
        assert_eq!(accounts.len(), 2);
        assert!(accounts.contains(&(id0, digest0)));
        assert!(accounts.contains(&(id1, digest1)));
    }

    #[test]
    fn account_witness() {
        let id0 = AccountIdBuilder::new().build_with_seed([5; 32]);
        let id1 = AccountIdBuilder::new().build_with_seed([6; 32]);

        let digest0 = Word::from([0, 0, 0, 1u32]);
        let digest1 = Word::from([0, 0, 0, 2u32]);

        let tree = AccountTree::with_entries([(id0, digest0), (id1, digest1)]).unwrap();

        assert_eq!(tree.num_accounts(), 2);

        for id in [id0, id1] {
            let proof = tree.smt.open(&account_id_to_smt_key(id));
            let (control_path, control_leaf) = proof.into_parts();
            let witness = tree.open(id);

            assert_eq!(witness.leaf(), control_leaf);
            assert_eq!(witness.path(), &control_path);
        }
    }

    #[test]
    fn contains_account_prefix() {
        // Create a tree with a single account.
        let [pair0, pair1] = setup_duplicate_prefix_ids();
        let tree = AccountTree::with_entries([pair0]).unwrap();
        assert_eq!(tree.num_accounts(), 1);

        // Validate the leaf for the inserted account exists.
        assert!(tree.contains_account_id_prefix(pair0.0.prefix()));

        // Validate the leaf for the uninserted account with same prefix exists.
        assert!(tree.contains_account_id_prefix(pair1.0.prefix()));

        // Validate the unrelated, uninserted account leaf does not exist.
        let id1 = AccountIdBuilder::new().build_with_seed([7; 32]);
        assert!(!tree.contains_account_id_prefix(id1.prefix()));
    }

    #[cfg(feature = "std")]
    #[test]
    fn large_smt_backend_basic_operations() {
        use miden_crypto::merkle::smt::{LargeSmt, MemoryStorage};

        // Create test data
        let id0 = AccountIdBuilder::new().build_with_seed([5; 32]);
        let id1 = AccountIdBuilder::new().build_with_seed([6; 32]);
        let id2 = AccountIdBuilder::new().build_with_seed([7; 32]);

        let digest0 = Word::from([0, 0, 0, 1u32]);
        let digest1 = Word::from([0, 0, 0, 2u32]);
        let digest2 = Word::from([0, 0, 0, 3u32]);

        // Create AccountTree with LargeSmt backend
        let tree = LargeSmt::<MemoryStorage>::with_entries(
            MemoryStorage::default(),
            [(account_id_to_smt_key(id0), digest0), (account_id_to_smt_key(id1), digest1)],
        )
        .map(AccountTree::new_unchecked)
        .unwrap();

        // Test basic operations
        assert_eq!(tree.num_accounts(), 2);
        assert_eq!(tree.get(id0), digest0);
        assert_eq!(tree.get(id1), digest1);

        // Test opening
        let witness0 = tree.open(id0);
        assert_eq!(witness0.id(), id0);

        // Test mutations
        let mut tree_mut = LargeSmt::<MemoryStorage>::with_entries(
            MemoryStorage::default(),
            [(account_id_to_smt_key(id0), digest0), (account_id_to_smt_key(id1), digest1)],
        )
        .map(AccountTree::new_unchecked)
        .unwrap();
        tree_mut.insert(id2, digest2).unwrap();
        assert_eq!(tree_mut.num_accounts(), 3);
        assert_eq!(tree_mut.get(id2), digest2);

        // Verify original tree unchanged
        assert_eq!(tree.num_accounts(), 2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn large_smt_backend_duplicate_prefix_check() {
        use miden_crypto::merkle::smt::{LargeSmt, MemoryStorage};

        let [(id0, commitment0), (id1, commitment1)] = setup_duplicate_prefix_ids();

        let mut tree = AccountTree::new_unchecked(LargeSmt::new(MemoryStorage::default()).unwrap());

        tree.insert(id0, commitment0).unwrap();
        assert_eq!(tree.get(id0), commitment0);

        let err = tree.insert(id1, commitment1).unwrap_err();

        assert_matches!(
            err,
            AccountTreeError::DuplicateIdPrefix { duplicate_prefix }
            if duplicate_prefix == id0.prefix()
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn large_smt_backend_apply_mutations() {
        use miden_crypto::merkle::smt::{LargeSmt, MemoryStorage};

        let id0 = AccountIdBuilder::new().build_with_seed([5; 32]);
        let id1 = AccountIdBuilder::new().build_with_seed([6; 32]);
        let id2 = AccountIdBuilder::new().build_with_seed([7; 32]);

        let digest0 = Word::from([0, 0, 0, 1u32]);
        let digest1 = Word::from([0, 0, 0, 2u32]);
        let digest2 = Word::from([0, 0, 0, 3u32]);
        let digest3 = Word::from([0, 0, 0, 4u32]);

        let mut tree = LargeSmt::with_entries(
            MemoryStorage::default(),
            [(account_id_to_smt_key(id0), digest0), (account_id_to_smt_key(id1), digest1)],
        )
        .map(AccountTree::new_unchecked)
        .unwrap();

        let mutations = tree
            .compute_mutations([(id0, digest1), (id1, digest2), (id2, digest3)])
            .unwrap();

        tree.apply_mutations(mutations).unwrap();

        assert_eq!(tree.num_accounts(), 3);
        assert_eq!(tree.get(id0), digest1);
        assert_eq!(tree.get(id1), digest2);
        assert_eq!(tree.get(id2), digest3);
    }

    #[cfg(feature = "std")]
    #[test]
    fn large_smt_backend_same_root_as_regular_smt() {
        use miden_crypto::merkle::smt::{LargeSmt, MemoryStorage};

        let id0 = AccountIdBuilder::new().build_with_seed([5; 32]);
        let id1 = AccountIdBuilder::new().build_with_seed([6; 32]);

        let digest0 = Word::from([0, 0, 0, 1u32]);
        let digest1 = Word::from([0, 0, 0, 2u32]);

        // Create tree with LargeSmt backend
        let large_tree = LargeSmt::with_entries(
            MemoryStorage::default(),
            [(account_id_to_smt_key(id0), digest0), (account_id_to_smt_key(id1), digest1)],
        )
        .map(AccountTree::new_unchecked)
        .unwrap();

        // Create tree with regular Smt backend
        let regular_tree = AccountTree::with_entries([(id0, digest0), (id1, digest1)]).unwrap();

        // Both should have the same root
        assert_eq!(large_tree.root(), regular_tree.root());

        // Both should have the same account commitments
        let large_commitments: std::collections::BTreeMap<_, _> =
            large_tree.account_commitments().collect();
        let regular_commitments: std::collections::BTreeMap<_, _> =
            regular_tree.account_commitments().collect();

        assert_eq!(large_commitments, regular_commitments);
    }
}
