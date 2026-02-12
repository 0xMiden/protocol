use alloc::collections::BTreeMap;

use crate::account::AccountId;
use crate::block::BlockHeader;
use crate::block::account_tree::AccountWitness;
use crate::block::nullifier_tree::NullifierWitness;
use crate::note::{NoteId, NoteInclusionProof, Nullifier};
use crate::transaction::PartialBlockchain;
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// BLOCK INPUTS
// ================================================================================================

/// The required inputs for building a [`ProposedBlock`](crate::block::ProposedBlock).
#[derive(Clone, Debug)]
pub struct BlockInputs {
    /// The previous block header that the block should reference.
    prev_block_header: BlockHeader,

    /// The chain state at the previous block with authentication paths for:
    /// - each block referenced by a batch in the block,
    /// - each block referenced by a note inclusion proof for an unauthenticated note.
    partial_blockchain: PartialBlockchain,

    /// The state commitments of the accounts in the block and their authentication paths.
    account_witnesses: BTreeMap<AccountId, AccountWitness>,

    /// The nullifiers of the notes consumed in the block and their authentication paths.
    nullifier_witnesses: BTreeMap<Nullifier, NullifierWitness>,

    /// Note inclusion proofs for all unauthenticated notes in the block that are not erased (i.e.
    /// created and consumed within the block).
    unauthenticated_note_proofs: BTreeMap<NoteId, NoteInclusionProof>,
}

impl BlockInputs {
    /// Creates new [`BlockInputs`] from the provided parts.
    pub fn new(
        prev_block_header: BlockHeader,
        partial_blockchain: PartialBlockchain,
        account_witnesses: BTreeMap<AccountId, AccountWitness>,
        nullifier_witnesses: BTreeMap<Nullifier, NullifierWitness>,
        unauthenticated_note_proofs: BTreeMap<NoteId, NoteInclusionProof>,
    ) -> Self {
        Self {
            prev_block_header,
            partial_blockchain,
            account_witnesses,
            nullifier_witnesses,
            unauthenticated_note_proofs,
        }
    }

    /// Returns a reference to the previous block header.
    pub fn prev_block_header(&self) -> &BlockHeader {
        &self.prev_block_header
    }

    /// Returns a reference to the [`PartialBlockchain`].
    pub fn partial_blockchain(&self) -> &PartialBlockchain {
        &self.partial_blockchain
    }

    /// Returns a reference to the account witnesses.
    pub fn account_witnesses(&self) -> &BTreeMap<AccountId, AccountWitness> {
        &self.account_witnesses
    }

    /// Returns a reference to the nullifier witnesses.
    pub fn nullifier_witnesses(&self) -> &BTreeMap<Nullifier, NullifierWitness> {
        &self.nullifier_witnesses
    }

    /// Returns a reference to the note inclusion proofs.
    pub fn unauthenticated_note_proofs(&self) -> &BTreeMap<NoteId, NoteInclusionProof> {
        &self.unauthenticated_note_proofs
    }

    /// Consumes self and returns the underlying parts.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        BlockHeader,
        PartialBlockchain,
        BTreeMap<AccountId, AccountWitness>,
        BTreeMap<Nullifier, NullifierWitness>,
        BTreeMap<NoteId, NoteInclusionProof>,
    ) {
        (
            self.prev_block_header,
            self.partial_blockchain,
            self.account_witnesses,
            self.nullifier_witnesses,
            self.unauthenticated_note_proofs,
        )
    }

    // TESTING
    // --------------------------------------------------------------------------------------------

    /// Returns a mutable reference to the [`PartialBlockchain`].
    ///
    /// Allows mutating the inner partial blockchain for testing purposes.
    #[cfg(any(feature = "testing", test))]
    pub fn partial_blockchain_mut(&mut self) -> &mut PartialBlockchain {
        &mut self.partial_blockchain
    }

    /// Returns a mutable reference to the note inclusion proofs.
    ///
    /// Allows mutating the inner note proofs map for testing purposes.
    #[cfg(any(feature = "testing", test))]
    pub fn unauthenticated_note_proofs_mut(&mut self) -> &mut BTreeMap<NoteId, NoteInclusionProof> {
        &mut self.unauthenticated_note_proofs
    }

    /// Returns a mutable reference to the nullifier witnesses.
    ///
    /// Allows mutating the inner nullifier witnesses map for testing purposes.
    #[cfg(any(feature = "testing", test))]
    pub fn nullifier_witnesses_mut(&mut self) -> &mut BTreeMap<Nullifier, NullifierWitness> {
        &mut self.nullifier_witnesses
    }

    /// Returns a mutable reference to the account witnesses.
    ///
    /// Allows mutating the inner account witnesses map for testing purposes.
    #[cfg(any(feature = "testing", test))]
    pub fn account_witnesses_mut(&mut self) -> &mut BTreeMap<AccountId, AccountWitness> {
        &mut self.account_witnesses
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for BlockInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.prev_block_header.write_into(target);
        self.partial_blockchain.write_into(target);
        self.account_witnesses.write_into(target);
        self.nullifier_witnesses.write_into(target);
        self.unauthenticated_note_proofs.write_into(target);
    }
}

impl Deserializable for BlockInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let prev_block_header = BlockHeader::read_from(source)?;
        let partial_blockchain = PartialBlockchain::read_from(source)?;
        let account_witnesses = BTreeMap::<AccountId, AccountWitness>::read_from(source)?;
        let nullifier_witnesses = BTreeMap::<Nullifier, NullifierWitness>::read_from(source)?;
        let unauthenticated_note_proofs =
            BTreeMap::<NoteId, NoteInclusionProof>::read_from(source)?;

        Ok(Self::new(
            prev_block_header,
            partial_blockchain,
            account_witnesses,
            nullifier_witnesses,
            unauthenticated_note_proofs,
        ))
    }
}
