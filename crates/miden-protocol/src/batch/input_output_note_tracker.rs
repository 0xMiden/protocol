use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt::Debug;

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

/// Computes the input and output notes for a transaction batch from the provided iterator over
/// transactions. Implements batch-specific logic.
///
/// Tracks the input and output notes and erases those that are created and consumed within the same
/// batch or block. The exception is that notes must be created by a transaction before a
/// transaction is allowed to consume and erase it, to prevent circular note dependencies.
///
/// All input notes for which a note inclusion proof is provided are authenticated and converted
/// into authenticated notes, unless they were erased first.
///
/// # Errors
///
/// Returns an error if:
/// - The set of all transaction's input notes contain duplicates.
/// - The set of all transaction's output notes contain duplicates.
/// - An unauthenticated note is consumed before it is created (as determined by the order in which
///   transactions are given).
/// - The block is missing in which an unauthenticated note was created and for which a proof is
///   provided.
/// - Authentication of an unauthenticated note fails due to an invalid proof.
pub fn erase_transaction_notes<'a>(
    txs: impl Iterator<Item = &'a ProvenTransaction>,
    unauthenticated_note_proofs: &BTreeMap<NoteId, NoteInclusionProof>,
    partial_blockchain: &PartialBlockchain,
    batch_reference_block: &BlockHeader,
) -> Result<(BatchInputNotes, BatchOutputNotes), ProposedBatchError> {
    let tx_notes_iter = txs
        .map(|tx| (tx.id(), tx.input_notes().iter().cloned(), tx.output_notes().iter().cloned()));

    let (batch_input_notes, _erased_notes, batch_output_notes) = erase_notes_inner(
        tx_notes_iter,
        unauthenticated_note_proofs,
        partial_blockchain,
        batch_reference_block,
    )
    .map_err(ProposedBatchError::from)?;

    // Collect the remaining (non-erased) output notes into the final set of output notes.
    let final_output_notes = batch_output_notes
        .into_iter()
        .map(|(_, (_, output_note))| output_note)
        .collect();

    Ok((batch_input_notes, final_output_notes))
}

/// Computes the input and output notes for a block from the provided iterator over batches.
/// Implements block-specific logic.
///
/// The same details as in [`erase_transaction_notes`] apply, except for batches rather than
/// transactions.
pub fn erase_batch_notes<'a>(
    batches: impl Iterator<Item = &'a ProvenBatch>,
    unauthenticated_note_proofs: &BTreeMap<NoteId, NoteInclusionProof>,
    partial_blockchain: &PartialBlockchain,
    prev_block: &BlockHeader,
) -> Result<(BlockInputNotes, ErasedNotes, BlockOutputNotes), ProposedBlockError> {
    let batch_notes_iter = batches.map(|batch| {
        (
            batch.id(),
            batch.input_notes().iter().cloned(),
            batch.output_notes().iter().cloned(),
        )
    });

    let (block_input_notes, erased_notes, block_output_notes) = erase_notes_inner(
        batch_notes_iter,
        unauthenticated_note_proofs,
        partial_blockchain,
        prev_block,
    )
    .map_err(ProposedBlockError::from)?;

    Ok((block_input_notes, erased_notes, block_output_notes))
}

// GENERIC CODE FOR BATCHES AND BLOCKS
// ================================================================================================

/// Creates the input and output note set. Checks for duplicates, erases notes and, authenticates
/// any unauthenticated notes for which proofs are provided.
#[allow(clippy::type_complexity)]
fn erase_notes_inner<ContainerId: Copy + Eq + Debug>(
    notes_iter: impl Iterator<
        Item = (
            ContainerId,
            impl Iterator<Item = InputNoteCommitment>,
            impl Iterator<Item = OutputNote>,
        ),
    >,
    unauthenticated_note_proofs: &BTreeMap<NoteId, NoteInclusionProof>,
    partial_blockchain: &PartialBlockchain,
    reference_block: &BlockHeader,
) -> Result<
    (
        Vec<InputNoteCommitment>,
        ErasedNotes,
        BTreeMap<NoteId, (ContainerId, OutputNote)>,
    ),
    InputOutputNoteTrackerError<ContainerId>,
> {
    let mut input_notes = BTreeMap::new();
    let mut output_notes = BTreeMap::new();
    let mut erased_notes = Vec::new();

    for (container_id, input_notes_iter, output_notes_iter) in notes_iter {
        // Whether we process output notes or input notes first shouldn't matter, since these sets
        // should be disjoint.
        // The advantage of processing output notes first, is that we can detect the "note created
        // and consumed within same tx/batch" case, even if it should never occur (see below).
        //
        // Note erasure happens only when iterating unauthenticated input notes, since we only have
        // access to the note ID when we have a note header and we do not store the note ID in the
        // input_notes map.
        for output_note in output_notes_iter {
            let output_note_id = output_note.id();
            if let Some((first_container_id, _)) =
                output_notes.insert(output_note_id, (container_id, output_note))
            {
                return Err(InputOutputNoteTrackerError::DuplicateOutputNote {
                    note_id: output_note_id,
                    first_container_id,
                    second_container_id: container_id,
                });
            }
        }

        'input_note_iter: for mut input_note_commitment in input_notes_iter {
            // If the note is unauthenticated (has a header), attempt to erase or authenticate
            // it.
            // Running note erasure first technically means an unauthenticated note for which a
            // proof is provided (= effectively a note that exists on-chain) could be erased if
            // a note with the same ID is also created and this is technically valid.
            if let Some(input_note_header) = input_note_commitment.header() {
                // Erase if the note is also in the output notes.
                if let Some((created_by, _output_note)) =
                    output_notes.remove(&input_note_header.id())
                {
                    // We should never encounter a note that is created and consumed by the same
                    // container. If we do anyway, it is better to panic than to proceed.
                    // - A `ProvenTransaction` guarantees that the set of input and output notes is
                    //   disjoint.
                    // - A batch guarantees this as well due to executing _this_ function's logic.
                    //
                    // Notes that are created and consumed within transactions or batches must NOT
                    // be erased as it is a form of circular note dependency and could be abused. If
                    // not erased, it would lead to an unspendable note, so there is no reason to
                    // allow it in the first place.
                    assert_ne!(
                        created_by, container_id,
                        "transactions and batches should never create and consume the same note"
                    );

                    erased_notes.push(input_note_commitment.nullifier());

                    // Skip inserting the erased note into the input notes set.
                    continue 'input_note_iter;
                } else {
                    // If the note wasn't erased and a proof is provided, transform it into an
                    // authenticated one. Otherwise the note stays unauthenticated.
                    if let Some(proof) = unauthenticated_note_proofs.get(&input_note_header.id()) {
                        input_note_commitment = authenticate_unauthenticated_note(
                            input_note_commitment.nullifier(),
                            input_note_header,
                            proof,
                            partial_blockchain,
                            reference_block,
                        )?;
                    }
                }
            }

            // Insert the note into the set of input notes and prevent duplicates.
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
    }

    // Any unauthenticated input notes that appear in the output notes, indicate an 1) incorrect
    // ordering or 2) a circular dependency between two transactions or batches. Notes that were
    // created and consumed in-order would have been erased during note erasure above.
    //
    // We need to disallow incorrectly ordered transactions at the batch (and block) level. Consider
    // transaction A that creates note 1 and transaction B that consumes note 1, but they are
    // provided in order [B, A]. Instead of returning an error, an alternative would be to promote
    // B's input note to an unauthenticated input note of the batch, and to promote A's output note
    // to an output note of the batch. However, this would result in a batch that creates and
    // consumes the same note, which must be disallowed as it has the same abuse potential as
    // https://github.com/0xMiden/protocol/issues/2796.
    for (consumed_by, unauthenticated_input_note) in
        input_notes.values().filter_map(|(consumed_by, input_note_commitment)| {
            input_note_commitment.header().map(|header| (consumed_by, header))
        })
    {
        if let Some((created_by, _)) = output_notes.get(&unauthenticated_input_note.id()) {
            return Err(InputOutputNoteTrackerError::NoteConsumedBeforeCreated {
                note_id: unauthenticated_input_note.id(),
                consumed_by: *consumed_by,
                created_by: *created_by,
            });
        }
    }

    Ok((
        input_notes
            .into_values()
            .map(|(_, input_note_commitment)| input_note_commitment)
            .collect(),
        erased_notes,
        output_notes,
    ))
}

/// Verifies the note inclusion proof for the given input note commitment parts (nullifier and
/// note header). Uses the block header referenced by the inclusion proof from the partial
/// blockchain.
///
/// If the proof is valid, it means the note is part of the chain and it is "marked" as
/// authenticated by returning an [`InputNoteCommitment`] without the note header.
fn authenticate_unauthenticated_note<ContainerId: Copy>(
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

    let note_index = proof.location().block_note_tree_index().into();
    let note_id = note_header.id().as_word();
    proof
        .note_path()
        .verify(note_index, note_id, &note_block_header.note_root())
        .map_err(|source| InputOutputNoteTrackerError::UnauthenticatedNoteAuthenticationFailed {
            note_id: note_header.id(),
            block_num: proof.location().block_num(),
            source,
        })?;

    // Erase the note header from the input note.
    Ok(InputNoteCommitment::from(nullifier))
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
    UnauthenticatedInputNoteBlockNotInPartialBlockchain {
        block_number: BlockNumber,
        note_id: NoteId,
    },
    UnauthenticatedNoteAuthenticationFailed {
        note_id: NoteId,
        block_num: BlockNumber,
        source: MerkleError,
    },
    NoteConsumedBeforeCreated {
        note_id: NoteId,
        consumed_by: ContainerId,
        created_by: ContainerId,
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
            InputOutputNoteTrackerError::NoteConsumedBeforeCreated {
                note_id,
                consumed_by,
                created_by,
            } => ProposedBlockError::NoteConsumedBeforeCreated { note_id, consumed_by, created_by },
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
            InputOutputNoteTrackerError::NoteConsumedBeforeCreated {
                note_id,
                consumed_by,
                created_by,
            } => ProposedBatchError::NoteConsumedBeforeCreated { note_id, consumed_by, created_by },
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
