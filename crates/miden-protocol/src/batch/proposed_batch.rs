use alloc::collections::btree_map::Entry;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::account::AccountId;
use crate::batch::{BatchAccountUpdate, BatchId, InputOutputNoteTracker};
use crate::block::{BlockHeader, BlockNumber};
use crate::errors::ProposedBatchError;
use crate::note::{NoteId, NoteInclusionProof};
use crate::transaction::{
    InputNoteCommitment,
    InputNotes,
    OrderedTransactionHeaders,
    OutputNote,
    PartialBlockchain,
    ProvenTransaction,
    TransactionHeader,
};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use crate::{MAX_ACCOUNTS_PER_BATCH, MAX_INPUT_NOTES_PER_BATCH, MAX_OUTPUT_NOTES_PER_BATCH};

/// A proposed batch of transactions with all necessary data to validate it.
///
/// See [`ProposedBatch::new`] for what a proposed batch expects and guarantees.
///
/// This type is fairly large, so consider boxing it.
#[derive(Debug, Clone)]
pub struct ProposedBatch {
    /// The transactions of this batch.
    transactions: Vec<Arc<ProvenTransaction>>,
    /// The header of the reference block that this batch is proposed for.
    reference_block_header: BlockHeader,
    /// The partial blockchain used to authenticate:
    /// - all unauthenticated notes that can be authenticated,
    /// - all block commitments referenced by the transactions in the batch.
    partial_blockchain: PartialBlockchain,
    /// The note inclusion proofs for unauthenticated notes that were consumed in the batch which
    /// can be authenticated.
    unauthenticated_note_proofs: BTreeMap<NoteId, NoteInclusionProof>,
    /// The ID of the batch, which is a cryptographic commitment to the transactions in the batch.
    id: BatchId,
    /// A map from account ID's updated in this batch to the aggregated update from all
    /// transaction's that touched the account.
    account_updates: BTreeMap<AccountId, BatchAccountUpdate>,
    /// The block number at which the batch will expire. This is the minimum of all transaction's
    /// expiration block number.
    batch_expiration_block_num: BlockNumber,
    /// The input note commitment of the transaction batch. This consists of all authenticated
    /// notes that transactions in the batch consume as well as unauthenticated notes whose
    /// authentication is delayed to the block kernel. These are sorted by
    /// [`InputNoteCommitment::nullifier`].
    input_notes: InputNotes<InputNoteCommitment>,
    /// The output notes of this batch. This consists of all notes created by transactions in the
    /// batch that are not consumed within the same batch. These are sorted by [`OutputNote::id`].
    output_notes: Vec<OutputNote>,
}

impl ProposedBatch {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`ProposedBatch`] from the provided parts.
    ///
    /// # Inputs
    ///
    /// - The given transactions must be correctly ordered. That is, if two transactions A and B
    ///   update the same account in this order, meaning A's initial account state commitment
    ///   matches the account state before any transactions are executed and B's initial account
    ///   state commitment matches the final account state commitment of A, then A must come before
    ///   B.
    /// - The partial blockchain's hashed peaks must match the reference block's `chain_commitment`
    ///   and it must contain all block headers:
    ///   - that are referenced by note inclusion proofs in `unauthenticated_note_proofs`.
    ///   - that are referenced by a transaction in the batch.
    /// - The `unauthenticated_note_proofs` should contain [`NoteInclusionProof`]s for any
    ///   unauthenticated note consumed by the transaction's in the batch which can be
    ///   authenticated. This means it is not required that every unauthenticated note has an entry
    ///   in this map for two reasons.
    ///     - Unauthenticated note authentication can be delayed to the block kernel.
    ///     - Another transaction in the batch creates an output note matching an unauthenticated
    ///       input note, in which case inclusion in the chain does not need to be proven.
    /// - The reference block of a batch must satisfy the following requirement: Its block number
    ///   must be greater or equal to the highest block number referenced by any transaction. This
    ///   is not verified explicitly, but will implicitly cause an error during the validation that
    ///   each reference block of a transaction is in the partial blockchain.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The number of input notes exceeds [`MAX_INPUT_NOTES_PER_BATCH`].
    ///   - Note that unauthenticated notes that are created in the same batch do not count. Any
    ///     other input notes, unauthenticated or not, do count.
    /// - The number of output notes exceeds [`MAX_OUTPUT_NOTES_PER_BATCH`].
    ///   - Note that output notes that are consumed in the same batch as unauthenticated input
    ///     notes do not count.
    /// - Any note is consumed more than once.
    /// - Any note is created more than once.
    /// - The number of account updates exceeds [`MAX_ACCOUNTS_PER_BATCH`].
    ///   - Note that any number of transactions against the same account count as one update.
    /// - The partial blockchains chain length does not match the block header's block number. This
    ///   means the partial blockchain should not contain the block header itself as it is added to
    ///   the MMR in the batch kernel.
    /// - The partial blockchains hashed peaks do not match the block header's chain commitment.
    /// - The reference block of any transaction is not in the partial blockchain.
    /// - The note inclusion proof for an unauthenticated note fails to verify.
    /// - The block referenced by a note inclusion proof for an unauthenticated note is missing from
    ///   the partial blockchain.
    /// - The transactions in the proposed batch which update the same account are not correctly
    ///   ordered.
    /// - The provided list of transactions is empty. An empty batch is pointless and would
    ///   potentially result in the same [`BatchId`] for two empty batches which would mean batch
    ///   IDs are no longer unique.
    /// - There are duplicate transactions.
    /// - If any transaction's expiration block number is less than or equal to the batch's
    ///   reference block.
    pub fn new(
        transactions: Vec<Arc<ProvenTransaction>>,
        reference_block_header: BlockHeader,
        partial_blockchain: PartialBlockchain,
        unauthenticated_note_proofs: BTreeMap<NoteId, NoteInclusionProof>,
    ) -> Result<Self, ProposedBatchError> {
        // Check for empty or duplicate transactions.
        // --------------------------------------------------------------------------------------------

        if transactions.is_empty() {
            return Err(ProposedBatchError::EmptyTransactionBatch);
        }

        let mut transaction_set = BTreeSet::new();
        for tx in transactions.iter() {
            if !transaction_set.insert(tx.id()) {
                return Err(ProposedBatchError::DuplicateTransaction { transaction_id: tx.id() });
            }
        }

        // Verify block header and partial blockchain match.
        // --------------------------------------------------------------------------------------------

        if partial_blockchain.chain_length() != reference_block_header.block_num() {
            return Err(ProposedBatchError::InconsistentChainLength {
                expected: reference_block_header.block_num(),
                actual: partial_blockchain.chain_length(),
            });
        }

        let hashed_peaks = partial_blockchain.peaks().hash_peaks();
        if hashed_peaks != reference_block_header.chain_commitment() {
            return Err(ProposedBatchError::InconsistentChainRoot {
                expected: reference_block_header.chain_commitment(),
                actual: hashed_peaks,
            });
        }

        // Verify all block references from the transactions are in the partial blockchain, except
        // for the batch's reference block.
        //
        // Note that some block X is only added to the blockchain by block X + 1. This
        // is because block X cannot compute its own block commitment and thus cannot add
        // itself to the chain. So, more generally, a previous block is added to the
        // blockchain by its child block.
        //
        // The reference block of a batch may be the latest block in the chain and, as mentioned,
        // block is not yet part of the blockchain, so its inclusion cannot be proven.
        // Since the inclusion cannot be proven in all cases, the batch kernel instead
        // commits to this reference block's commitment as a public input, which means the
        // block kernel will prove this block's inclusion when including this batch and
        // verifying its ZK proof.
        //
        // Finally, note that we don't verify anything cryptographically here. We have previously
        // verified that the batch reference block's chain commitment matches the hashed peaks of
        // the `PartialBlockchain`, and so we only have to check if the partial blockchain contains
        // the block here.
        // --------------------------------------------------------------------------------------------

        for tx in transactions.iter() {
            if reference_block_header.block_num() != tx.ref_block_num()
                && !partial_blockchain.contains_block(tx.ref_block_num())
            {
                return Err(ProposedBatchError::MissingTransactionBlockReference {
                    block_reference: tx.ref_block_commitment(),
                    transaction_id: tx.id(),
                });
            }
        }

        // Aggregate individual tx-level account updates into a batch-level account update - one per
        // account.
        // --------------------------------------------------------------------------------------------

        // Populate batch output notes and updated accounts.
        let mut account_updates = BTreeMap::<AccountId, BatchAccountUpdate>::new();
        for tx in transactions.iter() {
            // Merge account updates so that state transitions A->B->C become A->C.
            match account_updates.entry(tx.account_id()) {
                Entry::Vacant(vacant) => {
                    let batch_account_update = BatchAccountUpdate::from_transaction(tx);
                    vacant.insert(batch_account_update);
                },
                Entry::Occupied(occupied) => {
                    // This returns an error if the transactions are not correctly ordered, e.g. if
                    // B comes before A.
                    occupied.into_mut().merge_proven_tx(tx).map_err(|source| {
                        ProposedBatchError::AccountUpdateError {
                            account_id: tx.account_id(),
                            source,
                        }
                    })?;
                },
            };
        }

        if account_updates.len() > MAX_ACCOUNTS_PER_BATCH {
            return Err(ProposedBatchError::TooManyAccountUpdates(account_updates.len()));
        }

        // Check that all transaction's expiration block numbers are greater than the reference
        // block.
        // --------------------------------------------------------------------------------------------

        let mut batch_expiration_block_num = BlockNumber::from(u32::MAX);
        for tx in transactions.iter() {
            if tx.expiration_block_num() <= reference_block_header.block_num() {
                return Err(ProposedBatchError::ExpiredTransaction {
                    transaction_id: tx.id(),
                    transaction_expiration_num: tx.expiration_block_num(),
                    reference_block_num: reference_block_header.block_num(),
                });
            }

            // The expiration block of the batch is the minimum of all transaction's expiration
            // block.
            batch_expiration_block_num = batch_expiration_block_num.min(tx.expiration_block_num());
        }

        // Check for duplicates in input notes.
        // --------------------------------------------------------------------------------------------

        // Check for duplicate input notes both within a transaction and across transactions.
        // This also includes authenticated notes, as the transaction kernel doesn't check for
        // duplicates.
        let mut input_note_map = BTreeMap::new();

        for tx in transactions.iter() {
            for note in tx.input_notes() {
                let nullifier = note.nullifier();
                if let Some(first_transaction_id) = input_note_map.insert(nullifier, tx.id()) {
                    return Err(ProposedBatchError::DuplicateInputNote {
                        note_nullifier: nullifier,
                        first_transaction_id,
                        second_transaction_id: tx.id(),
                    });
                }
            }
        }

        // Create input and output note set of the batch.
        // --------------------------------------------------------------------------------------------

        // Check for duplicate output notes and remove all output notes from the batch output note
        // set that are consumed by transactions.
        let (input_notes, output_notes) = InputOutputNoteTracker::from_transactions(
            transactions.iter().map(AsRef::as_ref),
            &unauthenticated_note_proofs,
            &partial_blockchain,
            &reference_block_header,
        )?;

        if input_notes.len() > MAX_INPUT_NOTES_PER_BATCH {
            return Err(ProposedBatchError::TooManyInputNotes(input_notes.len()));
        }
        // SAFETY: This is safe as we have checked for duplicates and the max number of input notes
        // in a batch.
        let input_notes = InputNotes::new_unchecked(input_notes);

        if output_notes.len() > MAX_OUTPUT_NOTES_PER_BATCH {
            return Err(ProposedBatchError::TooManyOutputNotes(output_notes.len()));
        }

        // Compute batch ID.
        // --------------------------------------------------------------------------------------------

        let id = BatchId::from_transactions(transactions.iter().map(AsRef::as_ref));

        Ok(Self {
            id,
            transactions,
            reference_block_header,
            partial_blockchain,
            unauthenticated_note_proofs,
            account_updates,
            batch_expiration_block_num,
            input_notes,
            output_notes,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a slice of the [`ProvenTransaction`]s in the batch.
    pub fn transactions(&self) -> &[Arc<ProvenTransaction>] {
        &self.transactions
    }

    /// Returns the ordered set of transactions in the batch.
    pub fn transaction_headers(&self) -> OrderedTransactionHeaders {
        // SAFETY: This constructs an ordered set in the order of the transactions in the batch.
        OrderedTransactionHeaders::new_unchecked(
            self.transactions
                .iter()
                .map(AsRef::as_ref)
                .map(TransactionHeader::from)
                .collect(),
        )
    }

    /// Returns the map of account IDs mapped to their [`BatchAccountUpdate`]s.
    ///
    /// If an account was updated by multiple transactions, the [`BatchAccountUpdate`] is the result
    /// of merging the individual updates.
    ///
    /// For example, suppose an account's state before this batch is `A` and the batch contains two
    /// transactions that updated it. Applying the first transaction results in intermediate state
    /// `B`, and applying the second one results in state `C`. Then the returned update represents
    /// the state transition from `A` to `C`.
    pub fn account_updates(&self) -> &BTreeMap<AccountId, BatchAccountUpdate> {
        &self.account_updates
    }

    /// The ID of this batch. See [`BatchId`] for details on how it is computed.
    pub fn id(&self) -> BatchId {
        self.id
    }

    /// Returns the block number at which the batch will expire.
    pub fn batch_expiration_block_num(&self) -> BlockNumber {
        self.batch_expiration_block_num
    }

    /// Returns the [`InputNotes`] of this batch.
    pub fn input_notes(&self) -> &InputNotes<InputNoteCommitment> {
        &self.input_notes
    }

    /// Returns the output notes of the batch.
    ///
    /// This is the aggregation of all output notes by the transactions in the batch, except the
    /// ones that were consumed within the batch itself.
    pub fn output_notes(&self) -> &[OutputNote] {
        &self.output_notes
    }

    /// Consumes the proposed batch and returns its underlying parts.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        Vec<Arc<ProvenTransaction>>,
        BlockHeader,
        PartialBlockchain,
        BTreeMap<NoteId, NoteInclusionProof>,
        BatchId,
        BTreeMap<AccountId, BatchAccountUpdate>,
        InputNotes<InputNoteCommitment>,
        Vec<OutputNote>,
        BlockNumber,
    ) {
        (
            self.transactions,
            self.reference_block_header,
            self.partial_blockchain,
            self.unauthenticated_note_proofs,
            self.id,
            self.account_updates,
            self.input_notes,
            self.output_notes,
            self.batch_expiration_block_num,
        )
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for ProposedBatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.transactions
            .iter()
            .map(|tx| tx.as_ref().clone())
            .collect::<Vec<ProvenTransaction>>()
            .write_into(target);

        self.reference_block_header.write_into(target);
        self.partial_blockchain.write_into(target);
        self.unauthenticated_note_proofs.write_into(target);
    }
}

impl Deserializable for ProposedBatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let transactions = Vec::<ProvenTransaction>::read_from(source)?
            .into_iter()
            .map(Arc::new)
            .collect::<Vec<Arc<ProvenTransaction>>>();

        let block_header = BlockHeader::read_from(source)?;
        let partial_blockchain = PartialBlockchain::read_from(source)?;
        let unauthenticated_note_proofs =
            BTreeMap::<NoteId, NoteInclusionProof>::read_from(source)?;

        ProposedBatch::new(
            transactions,
            block_header,
            partial_blockchain,
            unauthenticated_note_proofs,
        )
        .map_err(|source| {
            DeserializationError::UnknownError(format!("failed to create proposed batch: {source}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use miden_crypto::merkle::mmr::{Mmr, PartialMmr};
    use miden_verifier::ExecutionProof;
    use winter_rand_utils::rand_value;

    use super::*;
    use crate::Word;
    use crate::account::{AccountIdVersion, AccountStorageMode, AccountType};
    use crate::asset::FungibleAsset;
    use crate::transaction::ProvenTransactionBuilder;

    #[test]
    fn proposed_batch_serialization() -> anyhow::Result<()> {
        // create partial blockchain with 3 blocks - i.e., 2 peaks
        let mut mmr = Mmr::default();
        for i in 0..3 {
            let block_header = BlockHeader::mock(i, None, None, &[], Word::empty());
            mmr.add(block_header.commitment());
        }
        let partial_mmr: PartialMmr = mmr.peaks().into();
        let partial_blockchain = PartialBlockchain::new(partial_mmr, Vec::new()).unwrap();

        let chain_commitment = partial_blockchain.peaks().hash_peaks();
        let note_root = rand_value::<Word>();
        let tx_kernel_commitment = rand_value::<Word>();
        let reference_block_header = BlockHeader::mock(
            3,
            Some(chain_commitment),
            Some(note_root),
            &[],
            tx_kernel_commitment,
        );

        let account_id = AccountId::dummy(
            [1; 15],
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Private,
        );
        let initial_account_commitment =
            [2; 32].try_into().expect("failed to create initial account commitment");
        let final_account_commitment =
            [3; 32].try_into().expect("failed to create final account commitment");
        let account_delta_commitment =
            [4; 32].try_into().expect("failed to create account delta commitment");
        let block_num = reference_block_header.block_num();
        let block_ref = reference_block_header.commitment();
        let expiration_block_num = reference_block_header.block_num() + 1;
        let proof = ExecutionProof::new_dummy();

        let tx = ProvenTransactionBuilder::new(
            account_id,
            initial_account_commitment,
            final_account_commitment,
            account_delta_commitment,
            block_num,
            block_ref,
            FungibleAsset::mock(100).unwrap_fungible(),
            expiration_block_num,
            proof,
        )
        .build()
        .context("failed to build proven transaction")?;

        let batch = ProposedBatch::new(
            vec![Arc::new(tx)],
            reference_block_header,
            partial_blockchain,
            BTreeMap::new(),
        )
        .context("failed to propose batch")?;

        let encoded_batch = batch.to_bytes();

        let batch2 = ProposedBatch::read_from_bytes(&encoded_batch)
            .context("failed to deserialize proposed batch")?;

        assert_eq!(batch.transactions(), batch2.transactions());
        assert_eq!(batch.reference_block_header, batch2.reference_block_header);
        assert_eq!(batch.partial_blockchain, batch2.partial_blockchain);
        assert_eq!(batch.unauthenticated_note_proofs, batch2.unauthenticated_note_proofs);
        assert_eq!(batch.id, batch2.id);
        assert_eq!(batch.account_updates, batch2.account_updates);
        assert_eq!(batch.batch_expiration_block_num, batch2.batch_expiration_block_num);
        assert_eq!(batch.input_notes, batch2.input_notes);
        assert_eq!(batch.output_notes, batch2.output_notes);

        Ok(())
    }
}
