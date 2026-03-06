use alloc::vec::Vec;

use anyhow::Context;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{Note, NoteInclusionProof, Nullifier};
use miden_protocol::transaction::{
    InputNote,
    ProvenOutputNote,
    ProvenTransaction,
    ProvenTransactionBuilder,
};
use miden_protocol::vm::ExecutionProof;

/// A builder to build mocked [`ProvenTransaction`]s.
pub struct MockProvenTxBuilder {
    account_id: AccountId,
    initial_account_commitment: Word,
    final_account_commitment: Word,
    ref_block_commitment: Option<Word>,
    fee: FungibleAsset,
    expiration_block_num: BlockNumber,
    output_notes: Option<Vec<ProvenOutputNote>>,
    input_notes: Option<Vec<InputNote>>,
    nullifiers: Option<Vec<Nullifier>>,
}

impl MockProvenTxBuilder {
    /// Creates a new builder for a transaction executed against the given account with its initial
    /// and final state commitment.
    pub fn with_account(
        account_id: AccountId,
        initial_account_commitment: Word,
        final_account_commitment: Word,
    ) -> Self {
        Self {
            account_id,
            initial_account_commitment,
            final_account_commitment,
            ref_block_commitment: None,
            fee: FungibleAsset::mock(50).unwrap_fungible(),
            expiration_block_num: BlockNumber::from(u32::MAX),
            output_notes: None,
            input_notes: None,
            nullifiers: None,
        }
    }

    /// Adds unauthenticated notes to the transaction.
    #[must_use]
    pub fn authenticated_notes(mut self, notes: Vec<Note>) -> Self {
        let mock_proof = NoteInclusionProof::new(
            BlockNumber::from(0),
            0,
            SparseMerklePath::from_sized_iter(vec![]).unwrap(),
        )
        .unwrap();
        self.input_notes = Some(
            notes
                .into_iter()
                .map(|note| InputNote::authenticated(note, mock_proof.clone()))
                .collect(),
        );

        self
    }

    /// Adds unauthenticated notes to the transaction.
    #[must_use]
    pub fn unauthenticated_notes(mut self, notes: Vec<Note>) -> Self {
        self.input_notes = Some(notes.into_iter().map(InputNote::unauthenticated).collect());

        self
    }

    /// Sets the transaction's expiration block number.
    #[must_use]
    pub fn expiration_block_num(mut self, expiration_block_num: BlockNumber) -> Self {
        self.expiration_block_num = expiration_block_num;

        self
    }

    /// Adds notes to the transaction's output notes.
    #[must_use]
    pub fn output_notes(mut self, notes: Vec<ProvenOutputNote>) -> Self {
        self.output_notes = Some(notes);

        self
    }

    /// Sets the transaction's block reference.
    #[must_use]
    pub fn ref_block_commitment(mut self, ref_block_commitment: Word) -> Self {
        self.ref_block_commitment = Some(ref_block_commitment);

        self
    }

    /// Builds the [`ProvenTransaction`] and returns potential errors.
    pub fn build(self) -> anyhow::Result<ProvenTransaction> {
        ProvenTransactionBuilder::new(
            self.account_id,
            self.initial_account_commitment,
            self.final_account_commitment,
            Word::empty(),
            BlockNumber::from(0),
            self.ref_block_commitment.unwrap_or_default(),
            self.fee,
            self.expiration_block_num,
            ExecutionProof::new_dummy(),
        )
        .add_input_notes(self.input_notes.unwrap_or_default())
        .add_input_notes(self.nullifiers.unwrap_or_default())
        .add_output_notes(self.output_notes.unwrap_or_default())
        .build()
        .context("failed to build proven transaction")
    }
}
