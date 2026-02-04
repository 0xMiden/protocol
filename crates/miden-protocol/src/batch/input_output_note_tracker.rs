use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::Word;
use crate::batch::{BatchId, ProvenBatch};
use crate::block::{BlockHeader, BlockNumber};
use crate::crypto::merkle::MerkleError;
use crate::errors::{ProposedBatchError, ProposedBlockError};
use crate::note::{NoteHeader, NoteId, NoteInclusionProof, Nullifier};
use crate::transaction::{
    InputNoteCommitment,
    OutputNote,
    PartialBlockchain,
    ProvenTransaction,
    TransactionId,
};

type BatchInputNotes = Vec<InputNoteCommitment>;
type BlockInputNotes = Vec<InputNoteCommitment>;
type ErasedNotes = Vec<Nullifier>;
type BlockOutputNotes = BTreeMap<NoteId, (BatchId, OutputNote)>;
type BatchOutputNotes = Vec<OutputNote>;

// INPUT OUTPUT NOTE TRACKER
// ================================================================================================

/// A helper struct to track input and output notes and erase those that are created and consumed
/// within the same batch or block.
///
/// Its main purpose is to check for duplicates and allow for removal of output notes that are
/// consumed in the same batch/block, and so are not output notes of the batch/block.
///
/// The approach for this is that:
/// - for batches, the input/output note set is initialized to the union of all input/output notes
///   of the transactions in the batch.
/// - for blocks, the input/output note set is initialized to the union of all input/output of the
///   batches in the block.
///
/// All input notes for which a note inclusion proof is provided are authenticated and converted
/// into authenticated notes.
///
/// All input notes which are also output notes are removed, as they are considered consumed within
/// the same batch/block and will not be visible as created or consumed notes for the batch/block.
#[derive(Debug)]
pub(crate) struct InputOutputNoteTracker<ContainerId> {
    /// An index from Nullifier to the identifier that consumes it (either a [`TransactionId`] or
    /// [`BatchId`](crate::batch::BatchId)).
    input_notes: BTreeMap<Nullifier, (ContainerId, InputNoteCommitment)>,
    /// An index from [`NoteId`]s to the transaction that creates the note and the note itself.
    /// The transaction ID is tracked to produce better errors when a duplicate note is
    /// encountered.
    output_notes: BTreeMap<NoteId, (ContainerId, OutputNote)>,
}

impl InputOutputNoteTracker<TransactionId> {
    /// Computes the input and output notes for a transaction batch from the provided iterator over
    /// transactions. Implements batch-specific logic.
    pub fn from_transactions<'a>(
        txs: impl Iterator<Item = &'a ProvenTransaction> + Clone,
        unauthenticated_note_proofs: &BTreeMap<NoteId, NoteInclusionProof>,
        partial_blockchain: &PartialBlockchain,
        batch_reference_block: &BlockHeader,
    ) -> Result<(BatchInputNotes, BatchOutputNotes), ProposedBatchError> {
        let input_notes_iter = txs.clone().flat_map(|tx| {
            tx.input_notes()
                .iter()
                .map(|input_note_commitment| (input_note_commitment.clone(), tx.id()))
        });
        let output_notes_iter = txs.flat_map(|tx| {
            tx.output_notes().iter().map(|output_note| (output_note.clone(), tx.id()))
        });

        let tracker = Self::from_iter(
            input_notes_iter,
            output_notes_iter,
            unauthenticated_note_proofs,
            partial_blockchain,
            batch_reference_block,
        )
        .map_err(ProposedBatchError::from)?;

        let (batch_input_notes, _erased_notes, batch_output_notes) =
            tracker.erase_notes().map_err(ProposedBatchError::from)?;

        // Collect the remaining (non-erased) output notes into the final set of output notes.
        let final_output_notes = batch_output_notes
            .into_iter()
            .map(|(_, (_, output_note))| output_note)
            .collect();

        Ok((batch_input_notes, final_output_notes))
    }
}

impl InputOutputNoteTracker<BatchId> {
    /// Computes the input and output notes for a block from the provided iterator over batches.
    /// Implements block-specific logic.
    pub fn from_batches<'a>(
        batches: impl Iterator<Item = &'a ProvenBatch> + Clone,
        unauthenticated_note_proofs: &BTreeMap<NoteId, NoteInclusionProof>,
        partial_blockchain: &PartialBlockchain,
        prev_block: &BlockHeader,
    ) -> Result<(BlockInputNotes, ErasedNotes, BlockOutputNotes), ProposedBlockError> {
        let input_notes_iter = batches.clone().flat_map(|batch| {
            batch
                .input_notes()
                .iter()
                .map(|input_note_commitment| (input_note_commitment.clone(), batch.id()))
        });

        let output_notes_iter = batches.flat_map(|batch| {
            batch.output_notes().iter().map(|output_note| (output_note.clone(), batch.id()))
        });

        let tracker = Self::from_iter(
            input_notes_iter,
            output_notes_iter,
            unauthenticated_note_proofs,
            partial_blockchain,
            prev_block,
        )
        .map_err(ProposedBlockError::from)?;

        let (block_input_notes, erased_notes, block_output_notes) =
            tracker.erase_notes().map_err(ProposedBlockError::from)?;

        Ok((block_input_notes, erased_notes, block_output_notes))
    }
}

// GENERIC CODE FOR BATCHES AND BLOCKS
// ================================================================================================

impl<ContainerId: Copy> InputOutputNoteTracker<ContainerId> {
    /// Creates the input and output note set while checking for duplicates and, in the process,
    /// authenticating any unauthenticated notes for which proofs are provided.
    fn from_iter(
        input_notes_iter: impl Iterator<Item = (InputNoteCommitment, ContainerId)>,
        output_notes_iter: impl Iterator<Item = (OutputNote, ContainerId)>,
        unauthenticated_note_proofs: &BTreeMap<NoteId, NoteInclusionProof>,
        partial_blockchain: &PartialBlockchain,
        reference_block: &BlockHeader,
    ) -> Result<Self, InputOutputNoteTrackerError<ContainerId>> {
        let mut input_notes = BTreeMap::new();
        let mut output_notes = BTreeMap::new();

        for (mut input_note_commitment, container_id) in input_notes_iter {
            // Transform unauthenticated notes into authenticated ones if the provided proof is
            // valid.
            if let Some(note_header) = input_note_commitment.header()
                && let Some(proof) = unauthenticated_note_proofs.get(&note_header.id())
            {
                input_note_commitment = Self::authenticate_unauthenticated_note(
                    input_note_commitment.nullifier(),
                    note_header,
                    proof,
                    partial_blockchain,
                    reference_block,
                )?;
            }

            let nullifier = input_note_commitment.nullifier();
            if let Some((first_container_id, _)) =
                input_notes.insert(nullifier, (container_id, input_note_commitment))
            {
                return Err(InputOutputNoteTrackerError::DuplicateInputNote {
                    note_nullifier: nullifier,
                    first_container_id,
                    second_container_id: container_id,
                });
            }
        }

        for (note, container_id) in output_notes_iter {
            if let Some((first_container_id, _)) =
                output_notes.insert(note.id(), (container_id, note.clone()))
            {
                return Err(InputOutputNoteTrackerError::DuplicateOutputNote {
                    note_id: note.id(),
                    first_container_id,
                    second_container_id: container_id,
                });
            }
        }

        Ok(Self { input_notes, output_notes })
    }

    /// Iterates the input notes and if an unauthenticated note is encountered, attempts to remove
    /// it from the output notes if it is present in that set.
    /// If it is, the note is considered erased and added to the list of erased notes, otherwise it
    /// is added to the final input notes.
    ///
    /// Returns the sets of input notes, erased notes and output notes.
    #[allow(clippy::type_complexity)]
    fn erase_notes(
        mut self,
    ) -> Result<
        (
            Vec<InputNoteCommitment>,
            ErasedNotes,
            BTreeMap<NoteId, (ContainerId, OutputNote)>,
        ),
        InputOutputNoteTrackerError<ContainerId>,
    > {
        let mut erased_notes = Vec::new();
        let mut final_input_notes = Vec::new();

        for (_, input_note_commitment) in self.input_notes.values() {
            match input_note_commitment.header() {
                Some(input_note_header) => {
                    let is_output_note =
                        Self::remove_output_note(input_note_header, &mut self.output_notes)?;

                    // If the unauthenticated note is also created as an output note we erase it by
                    // adding it to the erased notes and, crucially, not adding it to the
                    // final_input_notes.
                    if is_output_note {
                        erased_notes.push(input_note_commitment.nullifier());
                    } else {
                        final_input_notes.push(input_note_commitment.clone());
                    }
                },
                None => {
                    final_input_notes.push(input_note_commitment.clone());
                },
            }
        }

        Ok((final_input_notes, erased_notes, self.output_notes))
    }

    /// Attempts to remove the given input note from the output note set.
    ///
    /// Returns `true` if the given note existed in the output note set and was removed from it,
    /// `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the given note has a corresponding note in the output note set with the same [`NoteId`]
    ///   but their hashes differ (i.e. their metadata is different).
    fn remove_output_note(
        input_note_header: &NoteHeader,
        output_notes: &mut BTreeMap<NoteId, (ContainerId, OutputNote)>,
    ) -> Result<bool, InputOutputNoteTrackerError<ContainerId>> {
        let id = input_note_header.id();
        if let Some((_, output_note)) = output_notes.remove(&id) {
            // Check if the notes with the same ID have differing hashes.
            // This could happen if the metadata of the notes is different, which we consider an
            // error.
            let input_commitment = input_note_header.commitment();
            let output_commitment = output_note.commitment();
            if output_commitment != input_commitment {
                return Err(InputOutputNoteTrackerError::NoteCommitmentMismatch {
                    id,
                    input_commitment,
                    output_commitment,
                });
            }

            return Ok(true);
        }

        Ok(false)
    }

    /// Verifies the note inclusion proof for the given input note commitment parts (nullifier and
    /// note header). Uses the block header referenced by the inclusion proof from the partial
    /// blockchain.
    ///
    /// If the proof is valid, it means the note is part of the chain and it is "marked" as
    /// authenticated by returning an [`InputNoteCommitment`] without the note header.
    fn authenticate_unauthenticated_note(
        nullifier: Nullifier,
        note_header: &NoteHeader,
        proof: &NoteInclusionProof,
        partial_blockchain: &PartialBlockchain,
        reference_block: &BlockHeader,
    ) -> Result<InputNoteCommitment, InputOutputNoteTrackerError<ContainerId>> {
        let proof_reference_block = proof.location().block_num();
        let note_block_header = if reference_block.block_num() == proof_reference_block {
            reference_block
        } else {
            partial_blockchain.get_block(proof.location().block_num()).ok_or_else(|| {
                InputOutputNoteTrackerError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
                    block_number: proof.location().block_num(),
                    note_id: note_header.id(),
                }
            })?
        };

        let note_index = proof.location().node_index_in_block().into();
        let note_commitment = note_header.commitment();
        proof
            .note_path()
            .verify(note_index, note_commitment, &note_block_header.note_root())
            .map_err(|source| {
                InputOutputNoteTrackerError::UnauthenticatedNoteAuthenticationFailed {
                    note_id: note_header.id(),
                    block_num: proof.location().block_num(),
                    source,
                }
            })?;

        // Erase the note header from the input note.
        Ok(InputNoteCommitment::from(nullifier))
    }
}

// INPUT OUTPUT NOTE TRACKER ERROR
// ================================================================================================

// An error generic over the ContainerId. It is only used to abstract over the concrete errors, so
// it does not implement any traits, Error or otherwise.
enum InputOutputNoteTrackerError<ContainerId: Copy> {
    DuplicateInputNote {
        note_nullifier: Nullifier,
        first_container_id: ContainerId,
        second_container_id: ContainerId,
    },
    DuplicateOutputNote {
        note_id: NoteId,
        first_container_id: ContainerId,
        second_container_id: ContainerId,
    },
    NoteCommitmentMismatch {
        id: NoteId,
        input_commitment: Word,
        output_commitment: Word,
    },
    UnauthenticatedInputNoteBlockNotInPartialBlockchain {
        block_number: BlockNumber,
        note_id: NoteId,
    },
    UnauthenticatedNoteAuthenticationFailed {
        note_id: NoteId,
        block_num: BlockNumber,
        source: MerkleError,
    },
}

impl From<InputOutputNoteTrackerError<BatchId>> for ProposedBlockError {
    fn from(error: InputOutputNoteTrackerError<BatchId>) -> Self {
        match error {
            InputOutputNoteTrackerError::DuplicateInputNote {
                note_nullifier,
                first_container_id,
                second_container_id,
            } => ProposedBlockError::DuplicateInputNote {
                note_nullifier,
                first_batch_id: first_container_id,
                second_batch_id: second_container_id,
            },
            InputOutputNoteTrackerError::DuplicateOutputNote {
                note_id,
                first_container_id,
                second_container_id,
            } => ProposedBlockError::DuplicateOutputNote {
                note_id,
                first_batch_id: first_container_id,
                second_batch_id: second_container_id,
            },
            InputOutputNoteTrackerError::NoteCommitmentMismatch {
                id,
                input_commitment,
                output_commitment,
            } => ProposedBlockError::NoteCommitmentMismatch {
                id,
                input_commitment,
                output_commitment,
            },
            InputOutputNoteTrackerError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
                block_number,
                note_id,
            } => ProposedBlockError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
                block_number,
                note_id,
            },
            InputOutputNoteTrackerError::UnauthenticatedNoteAuthenticationFailed {
                note_id,
                block_num,
                source,
            } => ProposedBlockError::UnauthenticatedNoteAuthenticationFailed {
                note_id,
                block_num,
                source,
            },
        }
    }
}

impl From<InputOutputNoteTrackerError<TransactionId>> for ProposedBatchError {
    fn from(error: InputOutputNoteTrackerError<TransactionId>) -> Self {
        match error {
            InputOutputNoteTrackerError::DuplicateInputNote {
                note_nullifier,
                first_container_id,
                second_container_id,
            } => ProposedBatchError::DuplicateInputNote {
                note_nullifier,
                first_transaction_id: first_container_id,
                second_transaction_id: second_container_id,
            },
            InputOutputNoteTrackerError::DuplicateOutputNote {
                note_id,
                first_container_id,
                second_container_id,
            } => ProposedBatchError::DuplicateOutputNote {
                note_id,
                first_transaction_id: first_container_id,
                second_transaction_id: second_container_id,
            },
            InputOutputNoteTrackerError::NoteCommitmentMismatch {
                id,
                input_commitment,
                output_commitment,
            } => ProposedBatchError::NoteCommitmentMismatch {
                id,
                input_commitment,
                output_commitment,
            },
            InputOutputNoteTrackerError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
                block_number,
                note_id,
            } => ProposedBatchError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
                block_number,
                note_id,
            },
            InputOutputNoteTrackerError::UnauthenticatedNoteAuthenticationFailed {
                note_id,
                block_num,
                source,
            } => ProposedBatchError::UnauthenticatedNoteAuthenticationFailed {
                note_id,
                block_num,
                source,
            },
        }
    }
}
