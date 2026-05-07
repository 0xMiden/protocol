use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;

use miden_processor::DefaultHost;
use miden_protocol::batch::{BatchKernel, ProposedBatch, ProvenBatch};
use miden_protocol::errors::ProvenBatchError;
use miden_prover::{ExecutionProof, ProvingOptions, prove};
use miden_tx::TransactionVerifier;

// LOCAL BATCH PROVER
// ================================================================================================

/// A local prover for transaction batches.
///
/// Verifies each transaction's `ExecutionProof` natively, then runs the batch kernel program in
/// `miden_prover::prove` to produce an [`ExecutionProof`] over the batch's public commitments.
#[derive(Clone)]
pub struct LocalBatchProver {
    proof_security_level: u32,
    proving_options: ProvingOptions,
}

impl LocalBatchProver {
    /// Creates a new [`LocalBatchProver`] instance.
    pub fn new(proof_security_level: u32) -> Self {
        Self {
            proof_security_level,
            proving_options: ProvingOptions::default(),
        }
    }

    /// Returns this prover's configured proof security level.
    pub fn proof_security_level(&self) -> u32 {
        self.proof_security_level
    }

    /// Attempts to prove the [`ProposedBatch`] into a [`ProvenBatch`].
    ///
    /// Verifies each transaction's `ExecutionProof` natively first, then runs the batch kernel via
    /// `miden_prover::prove` and attaches the resulting proof to the returned [`ProvenBatch`].
    ///
    /// After proof generation, the kernel's parsed `batch_expiration_block_num` output is
    /// checked against `proposed_batch.batch_expiration_block_num()`. The two batch note
    /// commitments produced by the kernel are *not* checked here because the kernel computes a
    /// raw sequential hash that does not match `proposed_batch.input_notes().commitment()` for
    /// batches with intra-batch unauthenticated-note erasure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - any transaction's proof in the batch fails to verify;
    /// - the batch kernel program fails to execute or produce a proof;
    /// - the kernel output stack fails to parse;
    /// - the kernel's `batch_expiration_block_num` does not match
    ///   `proposed_batch.batch_expiration_block_num()`.
    pub async fn prove(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, ProvenBatchError> {
        let verifier = TransactionVerifier::new(self.proof_security_level);

        for tx in proposed_batch.transactions() {
            verifier.verify(tx).map_err(|source| {
                ProvenBatchError::TransactionVerificationFailed {
                    transaction_id: tx.id(),
                    source: Box::new(source),
                }
            })?;
        }

        let expected_expiration = proposed_batch.batch_expiration_block_num();
        let (stack_inputs, advice_inputs) = BatchKernel::prepare_inputs(&proposed_batch);
        let mut host = DefaultHost::default();

        let (stack_outputs, proof) = prove(
            &BatchKernel::main(),
            stack_inputs,
            advice_inputs,
            &mut host,
            self.proving_options.clone(),
        )
        .await
        .map_err(|err| ProvenBatchError::BatchKernelExecutionFailed(err.to_string()))?;

        let (_input_notes_commitment, _output_notes_commitment, kernel_expiration) =
            BatchKernel::parse_output_stack(&stack_outputs)
                .map_err(|err| ProvenBatchError::BatchKernelExecutionFailed(err.to_string()))?;

        if kernel_expiration != expected_expiration {
            return Err(ProvenBatchError::BatchKernelExecutionFailed(format!(
                "kernel batch_expiration_block_num {kernel_expiration} does not match the proposed batch's {expected_expiration}",
            )));
        }

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

    /// Combines the parts of a [`ProposedBatch`] with a freshly-produced [`ExecutionProof`] into a
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
