use miden_processor::{DefaultHost, ExecutionOptions};
use miden_protocol::batch::{BatchKernel, ProposedBatch, ProvenBatch};
use miden_protocol::errors::ProvenBatchError;
use miden_prover::{ExecutionProof, ProvingOptions, prove};

// LOCAL BATCH PROVER
// ================================================================================================

/// A local prover for transaction batches.
///
/// Runs the batch kernel program to produce an [`ExecutionProof`] over the batch's public
/// commitments.
#[derive(Clone, Default)]
pub struct LocalBatchProver {
    proving_options: ProvingOptions,
}

impl LocalBatchProver {
    /// Creates a new [`LocalBatchProver`] instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Proves the [`ProposedBatch`] into a [`ProvenBatch`].
    ///
    /// Runs the batch kernel via `miden_prover::prove` and attaches the resulting proof to the
    /// returned [`ProvenBatch`]. The kernel's public outputs are not yet cross-checked against the
    /// proposed batch's expected values.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the batch kernel program fails to execute or produce a proof;
    /// - the kernel output stack fails to parse.
    pub async fn prove(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, ProvenBatchError> {
        let (stack_inputs, advice_inputs) = BatchKernel::prepare_inputs(&proposed_batch);
        let mut host = DefaultHost::default();

        let (stack_outputs, proof) = prove(
            &BatchKernel::main(),
            stack_inputs,
            advice_inputs,
            &mut host,
            ExecutionOptions::default(),
            self.proving_options.clone(),
        )
        .await
        .map_err(ProvenBatchError::BatchKernelExecutionFailed)?;

        // Validate the output stack shape (padding cells are zero and the expiration fits in
        // u32); the actual output values themselves are not checked until the kernel verifies
        // them.
        BatchKernel::parse_output_stack(&stack_outputs)
            .map_err(ProvenBatchError::BatchKernelOutputInvalid)?;

        Self::build_proven_batch(proposed_batch, proof)
    }

    /// Returns a [`ProvenBatch`] built from the proposed batch with a dummy [`ExecutionProof`]
    /// attached, without running the batch kernel.
    #[cfg(any(feature = "testing", test))]
    pub fn prove_dummy(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, ProvenBatchError> {
        Self::build_proven_batch(proposed_batch, ExecutionProof::new_dummy())
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
