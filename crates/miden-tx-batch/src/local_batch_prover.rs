use alloc::string::ToString;

use miden_processor::ExecutionError;
use miden_protocol::PROTOCOL_PROOF_HASH;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::errors::ProvenBatchError;
use miden_protocol::transaction::PublicTransactionLogs;
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
}

impl Default for LocalBatchProver {
    fn default() -> Self {
        Self::new(Prover::new())
    }
}

impl LocalBatchProver {
    /// Creates a new [`LocalBatchProver`] while preserving the supplied prover settings and using
    /// the protocol proof hash.
    pub fn new(prover: Prover) -> Self {
        Self {
            prover: prover.with_hash_fn(PROTOCOL_PROOF_HASH),
        }
    }

    /// Proves the [`ExecutedBatch`] into a [`ProvenBatch`].
    ///
    /// Builds the execution trace from the executed batch and generates the proof, attaching it to
    /// the returned [`ProvenBatch`]. The kernel's public outputs are not yet cross-checked against
    /// the proposed batch's expected values.
    ///
    /// Each transaction's kernel proof covers its precompile verification, so the batch prover
    /// does not generate a separate precompile proof.
    ///
    /// # Errors
    ///
    /// Returns an error if proof generation fails.
    pub fn prove(&self, executed_batch: ExecutedBatch) -> Result<ProvenBatch, ProvenBatchError> {
        let (proposed_batch, witness) = executed_batch.into_parts();

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
        let public_logs = PublicTransactionLogs::from_batch(&proposed_batch)?;
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
            public_logs,
            proof,
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    use miden_protocol::Word;
    use miden_protocol::account::{AccountId, AccountPatch, AccountUpdateDetails};
    use miden_protocol::block::BlockHeader;
    use miden_protocol::crypto::merkle::mmr::{Mmr, PartialMmr};
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    };
    use miden_protocol::testing::dummy_execution_proof;
    use miden_protocol::transaction::{
        InputNoteCommitment,
        OutputNote,
        PartialBlockchain,
        ProvenTransaction,
        TransactionLog,
        TransactionLogDetails,
        TransactionLogs,
        TxAccountUpdate,
    };

    use super::*;

    #[test]
    fn proving_preserves_public_logs() {
        let mut mmr = Mmr::default();
        for number in 0..3 {
            mmr.add(BlockHeader::mock(number, None, None, &[]).commitment()).unwrap();
        }
        let chain = PartialBlockchain::new(PartialMmr::from_peaks(mmr.peaks()), vec![]).unwrap();
        let reference = BlockHeader::mock(3, Some(chain.peaks().hash_peaks()), None, &[]);
        let log = TransactionLog::mock(1);
        let logs = TransactionLogs::new(vec![log.clone(), log]).unwrap();
        let mut txs = Vec::new();
        for (private, initial, final_state, log_details) in [
            (false, 1u32, 2u32, TransactionLogDetails::Public(logs.clone())),
            (true, 4, 5, TransactionLogDetails::Private(Word::from([99u32; 4]))),
            (false, 2, 3, TransactionLogDetails::Public(TransactionLogs::default())),
        ] {
            let id: AccountId = if private {
                ACCOUNT_ID_PRIVATE_SENDER
            } else {
                ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE
            }
            .try_into()
            .unwrap();
            let (details, commitment) = if private {
                (AccountUpdateDetails::Private, Word::empty())
            } else {
                let patch = AccountPatch::empty(id);
                let commitment = patch.to_commitment();
                (AccountUpdateDetails::Public(patch), commitment)
            };
            let update = TxAccountUpdate::new(
                id,
                Word::from([initial; 4]),
                Word::from([final_state; 4]),
                commitment,
                details,
            )
            .unwrap();
            txs.push(Arc::new(
                ProvenTransaction::new(
                    update,
                    Vec::<InputNoteCommitment>::new(),
                    Vec::<OutputNote>::new(),
                    reference.block_num(),
                    reference.commitment(),
                    reference.block_num() + 1,
                    dummy_execution_proof(),
                    log_details,
                    Default::default(),
                )
                .unwrap(),
            ));
        }
        let expected = vec![(txs[0].id(), logs), (txs[2].id(), TransactionLogs::default())];
        let proposal =
            ProposedBatch::new_unverified(txs, reference, chain, BTreeMap::new()).unwrap();
        let expected_id = proposal.id();
        // Ordinary and dummy proving share this constructor after proof generation.
        let batch = LocalBatchProver::build_proven_batch(proposal.clone(), dummy_execution_proof())
            .unwrap();
        assert_eq!(batch.id(), expected_id);
        assert_eq!(batch.public_logs().entries(), expected);
        assert_eq!(
            LocalBatchProver::default()
                .prove_dummy(proposal)
                .unwrap()
                .public_logs()
                .entries(),
            expected
        );
    }
}
