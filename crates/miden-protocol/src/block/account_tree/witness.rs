use alloc::string::ToString;

use miden_crypto::merkle::smt::{LeafIndex, SMT_DEPTH, SmtLeaf, SmtProof, SmtProofError};
use miden_crypto::merkle::{InnerNodeInfo, SparseMerklePath};

use crate::Word;
use crate::account::AccountId;
use crate::block::account_tree::{account_id_to_smt_key, smt_key_to_account_id};
use crate::errors::AccountTreeError;
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// ACCOUNT WITNESS
// ================================================================================================

/// A specialized version of an [`SmtProof`] for use in [`AccountTree`](super::AccountTree) and
/// [`PartialAccountTree`](super::PartialAccountTree). It proves the inclusion of an account
/// ID at a certain state (i.e. [`Account::commitment`](crate::account::Account::commitment)) in the
/// [`AccountTree`](super::AccountTree).
///
/// By construction the witness can only represent the equivalent of an [`SmtLeaf`] with zero or one
/// entries, which guarantees that the account ID prefix it represents is unique in the tree.
///
/// # Guarantees
///
/// This type guarantees that:
/// - its MerklePath is of depth [`SMT_DEPTH`].
/// - converting this type into an [`SmtProof`] results in a leaf with zero or one entries, i.e. the
///   account ID prefix is unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountWitness {
    /// The account ID that this witness proves inclusion for.
    id: AccountId,
    /// The state commitment of the account ID.
    commitment: Word,
    /// The merkle path of the account witness.
    path: SparseMerklePath,
}

impl AccountWitness {
    /// Constructs a new [`AccountWitness`] from the provided parts.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the merkle path's depth is not [`SMT_DEPTH`].
    pub fn new(
        account_id: AccountId,
        commitment: Word,
        path: SparseMerklePath,
    ) -> Result<Self, AccountTreeError> {
        if path.depth() != SMT_DEPTH {
            return Err(AccountTreeError::WitnessMerklePathDepthDoesNotMatchAccountTreeDepth(
                path.depth() as usize,
            ));
        }

        Ok(Self::new_unchecked(account_id, commitment, path))
    }

    /// Creates an [`AccountWitness`] from the provided proof and the account ID for which the proof
    /// was requested.
    ///
    /// # Warning
    ///
    /// This should only be called on SMT proofs retrieved from (partial) account tree, because it
    /// relies on the guarantees of those types.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - the merkle path in the proof does not have depth equal to [`SMT_DEPTH`].
    /// - the proof contains an SmtLeaf::Multiple.
    pub(super) fn from_smt_proof(requested_account_id: AccountId, proof: SmtProof) -> Self {
        // Check which account ID this proof actually contains. We rely on the fact that the
        // trees only contain zero or one entry per account ID prefix.
        //
        // If the requested account ID matches an existing ID's prefix but their suffixes do
        // not match, then this witness is for the _existing ID_.
        //
        // Otherwise, if the ID matches the one in the leaf or if it's empty, the witness is
        // for the requested ID.
        let witness_id = match proof.leaf() {
            SmtLeaf::Empty(_) => requested_account_id,
            SmtLeaf::Single((key_in_leaf, _)) => {
                // SAFETY: By construction, the tree only contains valid IDs.
                smt_key_to_account_id(*key_in_leaf)
            },
            SmtLeaf::Multiple(_) => {
                unreachable!("account tree should only contain zero or one entry per ID prefix")
            },
        };

        let commitment = proof
            .get(&account_id_to_smt_key(witness_id))
            .expect("we should have received a proof for the witness key");

        // SAFETY: The proof is guaranteed to have depth SMT_DEPTH if it comes from one of
        // the account trees.
        debug_assert_eq!(proof.path().depth(), SMT_DEPTH);

        AccountWitness::new_unchecked(witness_id, commitment, proof.into_parts().0)
    }

    /// Constructs a new [`AccountWitness`] from the provided parts.
    ///
    /// # Warning
    ///
    /// This does not validate any of the guarantees of this type.
    pub(super) fn new_unchecked(
        account_id: AccountId,
        commitment: Word,
        path: SparseMerklePath,
    ) -> Self {
        Self { id: account_id, commitment, path }
    }

    /// Returns the underlying [`AccountId`] that this witness proves inclusion for.
    pub fn id(&self) -> AccountId {
        self.id
    }

    /// Returns the state commitment of the account witness.
    pub fn state_commitment(&self) -> Word {
        self.commitment
    }

    /// Returns the [`SparseMerklePath`] of the account witness.
    pub fn path(&self) -> &SparseMerklePath {
        &self.path
    }

    /// Returns the [`SmtLeaf`] of the account witness.
    pub fn leaf(&self) -> SmtLeaf {
        if self.commitment == Word::empty() {
            let leaf_idx = LeafIndex::from(account_id_to_smt_key(self.id));
            SmtLeaf::new_empty(leaf_idx)
        } else {
            let key = account_id_to_smt_key(self.id);
            SmtLeaf::new_single(key, self.commitment)
        }
    }

    /// Consumes self and returns the inner proof.
    pub fn into_proof(self) -> SmtProof {
        let leaf = self.leaf();
        debug_assert_eq!(self.path.depth(), SMT_DEPTH);
        SmtProof::new(self.path, leaf)
            .expect("merkle path depth should be the SMT depth by construction")
    }

    /// Returns an iterator over every inner node of this witness' merkle path.
    pub fn authenticated_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        let leaf = self.leaf();
        self.path()
            .authenticated_nodes(leaf.index().value(), leaf.hash())
            .expect("leaf index is u64 and should be less than 2^SMT_DEPTH")
    }
}

impl From<AccountWitness> for SmtProof {
    fn from(witness: AccountWitness) -> Self {
        witness.into_proof()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountWitness {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.id.write_into(target);
        self.commitment.write_into(target);
        self.path.write_into(target);
    }
}

impl Deserializable for AccountWitness {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let id = AccountId::read_from(source)?;
        let commitment = Word::read_from(source)?;
        let path = SparseMerklePath::read_from(source)?;

        if path.depth() != SMT_DEPTH {
            return Err(DeserializationError::InvalidValue(
                SmtProofError::InvalidMerklePathLength(path.depth() as usize).to_string(),
            ));
        }

        Ok(Self { id, commitment, path })
    }
}
