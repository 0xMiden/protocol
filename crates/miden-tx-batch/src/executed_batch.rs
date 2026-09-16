use alloc::vec::Vec;

use miden_processor::{PrecompileWitness, VmWitness};
use miden_protocol::batch::{BatchOutputs, ProposedBatch};

// EXECUTED BATCH
// ================================================================================================

/// A [`ProposedBatch`] whose batch kernel has been executed, but not yet proven.
///
/// Produced by [`BatchExecutor::execute`](crate::BatchExecutor::execute) and consumed by
/// [`LocalBatchProver::prove`](crate::LocalBatchProver::prove). It carries the witnesses proving
/// needs: the batch kernel's VM witness and the portable precompile witnesses of the
/// batch's transactions in transaction order.
pub struct ExecutedBatch {
    proposed_batch: ProposedBatch,
    witness: VmWitness,
    precompile_witnesses: Vec<PrecompileWitness>,
    batch_outputs: BatchOutputs,
}

impl ExecutedBatch {
    /// Creates a new [`ExecutedBatch`] from the proposed batch, its VM and precompile
    /// witnesses, and the public outputs produced by executing the batch kernel over it.
    pub(crate) fn new(
        proposed_batch: ProposedBatch,
        witness: VmWitness,
        precompile_witnesses: Vec<PrecompileWitness>,
        batch_outputs: BatchOutputs,
    ) -> Self {
        Self {
            proposed_batch,
            witness,
            precompile_witnesses,
            batch_outputs,
        }
    }

    /// Returns the [`ProposedBatch`] this batch was executed from.
    pub fn proposed_batch(&self) -> &ProposedBatch {
        &self.proposed_batch
    }

    /// Returns the precompile witnesses of the batch's transactions in transaction order.
    pub fn precompile_witnesses(&self) -> &[PrecompileWitness] {
        &self.precompile_witnesses
    }

    /// Returns the public outputs produced by the batch kernel.
    pub fn batch_outputs(&self) -> &BatchOutputs {
        &self.batch_outputs
    }

    /// Consumes the executed batch, returning the proposed batch and the witnesses needed to prove
    /// it.
    pub(crate) fn into_parts(self) -> (ProposedBatch, VmWitness, Vec<PrecompileWitness>) {
        (self.proposed_batch, self.witness, self.precompile_witnesses)
    }
}
