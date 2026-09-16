use alloc::string::ToString;

use miden_processor::ExecutionError;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::errors::ProvenBatchError;
use miden_prover::HashFunction::Poseidon2;
use miden_prover::{ExecutionProof, Prover};

use crate::ExecutedBatch;

// LOCAL BATCH PROVER
// ================================================================================================

/// A local prover for transaction batches.
///
/// Proves an [`ExecutedBatch`] (produced by [`BatchExecutor`](crate::BatchExecutor)) into a
/// [`ProvenBatch`] carrying an [`ExecutionProof`] over the batch's public commitments.
#[derive(Clone)]
pub struct LocalBatchProver {
    prover: Prover,
    skip_precompile_proof_generation: bool,
}

impl Default for LocalBatchProver {
    fn default() -> Self {
        Self::new(Prover::new().with_hash_fn(Poseidon2))
    }
}

impl LocalBatchProver {
    /// Creates a new [`LocalBatchProver`] instance.
    pub fn new(prover: Prover) -> Self {
        Self {
            prover,
            skip_precompile_proof_generation: false,
        }
    }

    /// Returns the prover with generation of the batch's precompile proof turned off.
    ///
    /// The precompile claims are still checked natively when the executor collects them, so the
    /// resulting batch is unchanged; only the in-circuit evidence for those claims is missing.
    ///
    /// This option can be removed once the batch kernel proof recursively verifies the transaction
    /// precompiles.
    pub fn skip_precompile_proof_generation(
        mut self,
        skip_precompile_proof_generation: bool,
    ) -> Self {
        self.skip_precompile_proof_generation = skip_precompile_proof_generation;
        self
    }

    /// Proves the [`ExecutedBatch`] into a [`ProvenBatch`].
    ///
    /// Builds the execution trace from the executed batch and generates the proof, attaching it to
    /// the returned [`ProvenBatch`]. The kernel's public outputs are not yet cross-checked against
    /// the proposed batch's expected values.
    ///
    /// The precompile claims of the batch's transactions are settled with a single precompile proof
    /// over their ordered witnesses, unless [`Self::skip_precompile_proof_generation`] was called.
    /// That proof is discarded rather than attached to the returned batch; see [`ProvenBatch`] for
    /// what this does and does not establish.
    ///
    /// # Errors
    ///
    /// Returns an error if proof generation fails.
    pub fn prove(&self, executed_batch: ExecutedBatch) -> Result<ProvenBatch, ProvenBatchError> {
        let (proposed_batch, witness, precompile_witnesses) = executed_batch.into_parts();

        if !self.skip_precompile_proof_generation && !precompile_witnesses.is_empty() {
            // The proof is dropped: the batch kernel cannot verify it yet, and shipping it on the
            // proven batch would add a wire format field that has to be removed again once the
            // kernel does. The batch executor already checked each witness natively against its
            // transaction proof; proving them adds that the aggregate statement holds in-circuit.
            let _precompile_proof = self
                .prover
                .prove_precompiles(precompile_witnesses)
                .map_err(|error| ExecutionError::ProvingError(error.to_string()))
                .map_err(ProvenBatchError::PrecompileProvingFailed)?;
        }

        let proof = self
            .prover
            .prove_vm_witness(witness)
            .map_err(|error| ExecutionError::ProvingError(error.to_string()))
            .map_err(ProvenBatchError::BatchKernelProvingFailed)?;

        Self::build_proven_batch(proposed_batch, proof)
    }

    /// Returns a [`ProvenBatch`] built from the proposed batch with a dummy [`ExecutionProof`]
    /// attached, without running the batch kernel.
    #[cfg(any(feature = "testing", test))]
    pub fn prove_dummy(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, ProvenBatchError> {
        Self::build_proven_batch(proposed_batch, miden_protocol::testing::dummy_execution_proof())
    }

    /// Returns a batch carrying a structurally incomplete proof for verifier tests.
    #[cfg(any(feature = "testing", test))]
    pub fn prove_dummy_deferred(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, ProvenBatchError> {
        Self::build_proven_batch(
            proposed_batch,
            miden_protocol::testing::dummy_deferred_execution_proof(),
        )
    }

    /// Returns a batch carrying a structurally complete proof with precompile work.
    #[cfg(any(feature = "testing", test))]
    pub fn prove_dummy_precompile(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, ProvenBatchError> {
        Self::build_proven_batch(
            proposed_batch,
            miden_protocol::testing::dummy_precompile_execution_proof(),
        )
    }

    /// Combines the parts of a [`ProposedBatch`] with the produced [`ExecutionProof`] into a
    /// [`ProvenBatch`].
    fn build_proven_batch(
        proposed_batch: ProposedBatch,
        proof: ExecutionProof,
    ) -> Result<ProvenBatch, ProvenBatchError> {
        let tx_headers = proposed_batch.transaction_headers();
        let (
            _transactions,
            block_header,
            _block_chain,
            _authenticatable_unauthenticated_notes,
            id,
            updated_accounts,
            input_notes,
            output_notes,
            batch_expiration_block_num,
        ) = proposed_batch.into_parts();

        ProvenBatch::new_unchecked(
            id,
            block_header.commitment(),
            block_header.block_num(),
            updated_accounts,
            input_notes,
            output_notes,
            batch_expiration_block_num,
            tx_headers,
            proof,
        )
    }
}
