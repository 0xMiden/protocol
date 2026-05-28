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

// NOTE CONTAINER
// ================================================================================================

/// Abstracts over a "container" of transactions or batches that
/// [`InputOutputNoteTracker::push`] can consume.
///
/// This lets the tracker treat both a [`ProvenTransaction`] (when building a batch) and a
/// [`ProvenBatch`] (when building a block) uniformly, while keeping the container-specific ID
/// type (e.g. [`TransactionId`] or [`BatchId`]) attached to any error we produce.
pub(crate) trait NoteContainer {
    type Id: Copy + Eq + Debug;

    fn id(&self) -> Self::Id;

    fn input_notes(&self) -> impl Iterator<Item = InputNoteCommitment>;

    fn output_notes(&self) -> impl Iterator<Item = OutputNote>;
}

impl NoteContainer for &ProvenTransaction {
    type Id = TransactionId;

    fn id(&self) -> Self::Id {
        ProvenTransaction::id(self)
    }

    fn input_notes(&self) -> impl Iterator<Item = InputNoteCommitment> {
        ProvenTransaction::input_notes(self).iter().cloned()
    }

    fn output_notes(&self) -> impl Iterator<Item = OutputNote> {
        ProvenTransaction::output_notes(self).iter().cloned()
    }
}

impl NoteContainer for &ProvenBatch {
    type Id = BatchId;

    fn id(&self) -> Self::Id {
        ProvenBatch::id(self)
    }

    fn input_notes(&self) -> impl Iterator<Item = InputNoteCommitment> {
        ProvenBatch::input_notes(self).iter().cloned()
    }

    fn output_notes(&self) -> impl Iterator<Item = OutputNote> {
        ProvenBatch::output_notes(self).iter().cloned()
    }
}

// INPUT OUTPUT NOTE TRACKER
// ================================================================================================

/// Accumulates the input and output notes of a batch or a block, with cross-container duplicate
/// detection, in-flight note erasure, unauthenticated-note authentication, and a final cycle
/// (circular dependency) check.
///
/// Containers (transactions for a batch, batches for a block) are added via
/// [`InputOutputNoteTracker::push`] in their final ordering. The tracker erases an unauthenticated
/// input note as soon as it sees a matching output note from a *previous* container, which is what
/// gives us the ordering guarantee: any unauthenticated input note still present in the input set
/// after all containers have been pushed, whose `NoteId` is also still present in the output set,
/// must have been pushed *before* its creator, and is therefore part of a circular dependency.
/// That check happens once in [`InputOutputNoteTracker::finalize`].
///
/// All input notes for which a note inclusion proof is provided are authenticated and converted
/// into authenticated notes, unless they were erased first.
pub(crate) struct NoteTracker<'container, ContainerId: Copy + Eq + Debug> {
    partial_blockchain: &'container PartialBlockchain,
    reference_block: &'container BlockHeader,
    unauthenticated_note_proofs: &'container BTreeMap<NoteId, NoteInclusionProof>,
    input_notes: BTreeMap<Nullifier, (ContainerId, InputNoteCommitment)>,
    output_notes: BTreeMap<NoteId, (ContainerId, OutputNote)>,
    erased_notes: Vec<Nullifier>,
}

/// The result of [`NoteTracker::finalize`].
pub(crate) struct TrackerOutput<ContainerId> {
    pub input_notes: Vec<InputNoteCommitment>,
    pub erased_notes: Vec<Nullifier>,
    pub output_notes: BTreeMap<NoteId, (ContainerId, OutputNote)>,
}

impl<'container, ContainerId: Copy + Eq + Debug> NoteTracker<'container, ContainerId> {
    /// Creates a new, empty tracker.
    pub(crate) fn new(
        partial_blockchain: &'container PartialBlockchain,
        reference_block: &'container BlockHeader,
        unauthenticated_note_proofs: &'container BTreeMap<NoteId, NoteInclusionProof>,
    ) -> Self {
        Self {
            partial_blockchain,
            reference_block,
            unauthenticated_note_proofs,
            input_notes: BTreeMap::new(),
            output_notes: BTreeMap::new(),
            erased_notes: Vec::new(),
        }
    }

    /// Pushes the input and output notes of `container` into the tracker.
    ///
    /// Output notes are processed before input notes. The order between the two doesn't matter for
    /// the outcome, since these sets should be disjoint within a single container. The advantage
    /// of processing output notes first is that we can detect the "note created and consumed
    /// within same tx/batch" case as a panic (see [`Self::process_input_notes`]).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - An output note from `container` was already pushed by a previous container.
    /// - An input note from `container` was already pushed by a previous container.
    /// - An unauthenticated input note has a [`NoteInclusionProof`] in
    ///   `unauthenticated_note_proofs` and authentication of that proof fails.
    /// - An unauthenticated input note has a [`NoteInclusionProof`] whose referenced block is not
    ///   in the partial blockchain.
    pub(crate) fn push<Container: NoteContainer<Id = ContainerId>>(
        &mut self,
        container: Container,
    ) -> Result<(), NoteTrackerError<ContainerId>> {
        let container_id = container.id();

        self.process_output_notes(container_id, container.output_notes())?;
        self.process_input_notes(container_id, container.input_notes())?;

        Ok(())
    }

    /// Inserts each output note into the tracker, returning an error if a note with the same
    /// [`NoteId`] was already pushed by a previous container.
    fn process_output_notes(
        &mut self,
        container_id: ContainerId,
        output_notes: impl Iterator<Item = OutputNote>,
    ) -> Result<(), NoteTrackerError<ContainerId>> {
        for output_note in output_notes {
            let output_note_id = output_note.id();
            if let Some((first_container_id, _)) =
                self.output_notes.insert(output_note_id, (container_id, output_note))
            {
                return Err(NoteTrackerError::DuplicateOutputNote {
                    note_id: output_note_id,
                    first_container_id,
                    second_container_id: container_id,
                });
            }
        }
        Ok(())
    }

    /// Processes the input notes from a single container.
    ///
    /// Note erasure happens only when iterating unauthenticated input notes, since we only have
    /// access to the note ID when we have a note header and we do not store the note ID in the
    /// input_notes map.
    ///
    /// Running note erasure first technically means an unauthenticated note for which a
    /// proof is provided (= effectively a note that exists on-chain) could be erased if
    /// a note with the same ID is also created, and this is technically valid.
    fn process_input_notes(
        &mut self,
        container_id: ContainerId,
        input_notes: impl Iterator<Item = InputNoteCommitment>,
    ) -> Result<(), NoteTrackerError<ContainerId>> {
        'input_note_iter: for mut input_note_commitment in input_notes {
            // If the note is unauthenticated (has a header), attempt to erase or authenticate it.
            if let Some(input_note_header) = input_note_commitment.header() {
                // Erase if the note is also in the output notes.
                if let Some((created_by, _output_note)) =
                    self.output_notes.remove(&input_note_header.id())
                {
                    // We should never encounter a note that is created and consumed by the same
                    // container. If we do anyway, it is better to panic than to proceed.
                    // - A `ProvenTransaction` guarantees that the set of input and output notes is
                    //   disjoint.
                    // - A batch guarantees this as well due to executing _this_ function's logic.
                    //
                    // Notes that are created and consumed within transactions or batches must NOT
                    // be erased as it is a form of circular note dependency and could be abused.
                    // If not erased, it would lead to an unspendable note, so there is no reason
                    // to allow it in the first place.
                    assert_ne!(
                        created_by, container_id,
                        "transactions and batches should never create and consume the same note"
                    );

                    self.erased_notes.push(input_note_commitment.nullifier());

                    // Skip inserting the erased note into the input notes set.
                    continue 'input_note_iter;
                } else {
                    // If the note wasn't erased and a proof is provided, transform it into an
                    // authenticated one. Otherwise the note stays unauthenticated.
                    if let Some(proof) =
                        self.unauthenticated_note_proofs.get(&input_note_header.id())
                    {
                        input_note_commitment = self.authenticate_unauthenticated_note(
                            input_note_commitment.nullifier(),
                            input_note_header,
                            proof,
                        )?;
                    }
                }
            }

            // Insert the note into the set of input notes and prevent duplicates.
            let nullifier = input_note_commitment.nullifier();
            if let Some((first_container_id, _)) =
                self.input_notes.insert(nullifier, (container_id, input_note_commitment))
            {
                return Err(NoteTrackerError::DuplicateInputNote {
                    note_nullifier: nullifier,
                    first_container_id,
                    second_container_id: container_id,
                });
            }
        }
        Ok(())
    }

    /// Performs the final circular-dependency check and consumes the tracker, returning the
    /// accumulated input notes, erased note nullifiers, and output notes.
    ///
    /// # Errors
    ///
    /// Any unauthenticated input notes that appear in the output notes indicate 1) an incorrect
    /// ordering or 2) a circular dependency between two transactions or batches. Notes that were
    /// created and consumed in-order would have been erased by [`Self::push`].
    ///
    /// We need to disallow incorrectly ordered transactions at the batch (and block) level.
    /// Consider transaction A that creates note 1 and transaction B that consumes note 1, but they
    /// are provided in order [B, A]. Instead of returning an error, an alternative would be to
    /// promote B's input note to an unauthenticated input note of the batch, and to promote A's
    /// output note to an output note of the batch. However, this would result in a batch that
    /// creates and consumes the same note, which must be disallowed as it has the same abuse
    /// potential as <https://github.com/0xMiden/protocol/issues/2796>.
    pub(crate) fn finalize(
        self,
    ) -> Result<TrackerOutput<ContainerId>, NoteTrackerError<ContainerId>> {
        for (consumed_by, unauthenticated_input_note) in
            self.input_notes.values().filter_map(|(consumed_by, input_note_commitment)| {
                input_note_commitment.header().map(|header| (consumed_by, header))
            })
        {
            if let Some((created_by, _)) = self.output_notes.get(&unauthenticated_input_note.id()) {
                return Err(NoteTrackerError::NoteConsumedBeforeCreated {
                    note_id: unauthenticated_input_note.id(),
                    consumed_by: *consumed_by,
                    created_by: *created_by,
                });
            }
        }

        Ok(TrackerOutput {
            input_notes: self
                .input_notes
                .into_values()
                .map(|(_, input_note_commitment)| input_note_commitment)
                .collect(),
            erased_notes: self.erased_notes,
            output_notes: self.output_notes,
        })
    }

    /// Verifies the note inclusion proof for the given input note commitment parts (nullifier and
    /// note header). Uses the block header referenced by the inclusion proof from the partial
    /// blockchain.
    ///
    /// If the proof is valid, it means the note is part of the chain and it is "marked" as
    /// authenticated by returning an [`InputNoteCommitment`] without the note header.
    fn authenticate_unauthenticated_note(
        &self,
        nullifier: Nullifier,
        note_header: &NoteHeader,
        proof: &NoteInclusionProof,
    ) -> Result<InputNoteCommitment, NoteTrackerError<ContainerId>> {
        let proof_reference_block = proof.location().block_num();
        let note_block_header = if self.reference_block.block_num() == proof_reference_block {
            self.reference_block
        } else {
            self.partial_blockchain.get_block(proof.location().block_num()).ok_or_else(|| {
                NoteTrackerError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
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
            .map_err(|source| NoteTrackerError::UnauthenticatedNoteAuthenticationFailed {
                note_id: note_header.id(),
                block_num: proof.location().block_num(),
                source,
            })?;

        // Erase the note header from the input note.
        Ok(InputNoteCommitment::from(nullifier))
    }
}

// INPUT OUTPUT NOTE TRACKER ERROR
// ================================================================================================

// An error generic over the ContainerId. It is only used to abstract over the concrete errors, so
// it does not implement any traits, Error or otherwise.
pub(crate) enum NoteTrackerError<ContainerId: Copy> {
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

impl From<NoteTrackerError<BatchId>> for ProposedBlockError {
    fn from(error: NoteTrackerError<BatchId>) -> Self {
        match error {
            NoteTrackerError::DuplicateInputNote {
                note_nullifier,
                first_container_id,
                second_container_id,
            } => ProposedBlockError::DuplicateInputNote {
                note_nullifier,
                first_batch_id: first_container_id,
                second_batch_id: second_container_id,
            },
            NoteTrackerError::DuplicateOutputNote {
                note_id,
                first_container_id,
                second_container_id,
            } => ProposedBlockError::DuplicateOutputNote {
                note_id,
                first_batch_id: first_container_id,
                second_batch_id: second_container_id,
            },
            NoteTrackerError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
                block_number,
                note_id,
            } => ProposedBlockError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
                block_number,
                note_id,
            },
            NoteTrackerError::UnauthenticatedNoteAuthenticationFailed {
                note_id,
                block_num,
                source,
            } => ProposedBlockError::UnauthenticatedNoteAuthenticationFailed {
                note_id,
                block_num,
                source,
            },
            NoteTrackerError::NoteConsumedBeforeCreated { note_id, consumed_by, created_by } => {
                ProposedBlockError::NoteConsumedBeforeCreated { note_id, consumed_by, created_by }
            },
        }
    }
}

impl From<NoteTrackerError<TransactionId>> for ProposedBatchError {
    fn from(error: NoteTrackerError<TransactionId>) -> Self {
        match error {
            NoteTrackerError::DuplicateInputNote {
                note_nullifier,
                first_container_id,
                second_container_id,
            } => ProposedBatchError::DuplicateInputNote {
                note_nullifier,
                first_transaction_id: first_container_id,
                second_transaction_id: second_container_id,
            },
            NoteTrackerError::DuplicateOutputNote {
                note_id,
                first_container_id,
                second_container_id,
            } => ProposedBatchError::DuplicateOutputNote {
                note_id,
                first_transaction_id: first_container_id,
                second_transaction_id: second_container_id,
            },
            NoteTrackerError::NoteConsumedBeforeCreated { note_id, consumed_by, created_by } => {
                ProposedBatchError::NoteConsumedBeforeCreated { note_id, consumed_by, created_by }
            },
            NoteTrackerError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
                block_number,
                note_id,
            } => ProposedBatchError::UnauthenticatedInputNoteBlockNotInPartialBlockchain {
                block_number,
                note_id,
            },
            NoteTrackerError::UnauthenticatedNoteAuthenticationFailed {
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
