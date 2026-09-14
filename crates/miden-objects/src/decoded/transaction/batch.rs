use miden_protobuf::unwrap_infallible;
pub use proto::transaction::DecodedBatchAccountUpdate as BatchAccountUpdate;

use crate::decoded::VerificationError;
use crate::{BuildUnchecked, Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for BatchAccountUpdate {
    type Verified = miden_protocol::batch::BatchAccountUpdate;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(
            self.account_id.verify()?,
            self.initial_state_commitment,
            self.final_state_commitment,
            self.details.verify()?,
        )?)
    }
}

pub use proto::transaction::DecodedProposedBatch as ProposedBatch;

/// Verifies transaction proofs and batch consistency, not trust in the supplied reference chain.
impl crate::VerifyWith<u32> for ProposedBatch {
    type Verified = miden_protocol::batch::ProposedBatch;
    type Error = VerificationError;
    fn verify_with(self, proof_security_level: u32) -> Result<Self::Verified, Self::Error> {
        let transactions = self
            .transactions
            .into_iter()
            .map(|tx| tx.build_unchecked().map(alloc::sync::Arc::new))
            .collect::<Result<_, _>>()?;
        let header = self.reference_block_header.build_unchecked()?;
        let chain = self.partial_blockchain.build_unchecked()?;
        let mut proofs = alloc::collections::BTreeMap::new();
        let mut previous = None;
        for proof in self.unauthenticated_note_proofs {
            let (id, proof) = proof.verify()?;
            if previous.is_some_and(|previous| id <= previous) {
                return Err(ProposedBatchError::ProofOrder.into());
            }
            previous = Some(id);
            proofs.insert(id, proof);
        }
        Ok(Self::Verified::new(transactions, header, chain, proofs, proof_security_level)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProposedBatchError {
    #[error("unauthenticated note proofs must have unique, ascending note IDs")]
    ProofOrder,
}

pub use proto::transaction::DecodedProvenBatch as ProvenBatch;

/// Checks local batch invariants, but not proof validity, note aggregation, or transaction
/// ordering.
impl crate::BuildUnchecked for ProvenBatch {
    type Output = miden_protocol::batch::ProvenBatch;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        let mut previous = None;
        let mut updates = alloc::vec::Vec::new();
        for update in self.account_updates {
            let update = update.verify()?;
            if previous.is_some_and(|previous| update.account_id() <= previous) {
                return Err(ProvenBatchError::AccountOrder.into());
            }
            previous = Some(update.account_id());
            updates.push(update);
        }
        let inputs = self
            .input_notes
            .into_iter()
            .map(BuildUnchecked::build_unchecked)
            .collect::<Result<_, _>>()?;
        let outputs =
            self.output_notes.into_iter().map(Verify::verify).collect::<Result<_, _>>()?;
        let transactions = self
            .transactions
            .into_iter()
            .map(BuildUnchecked::build_unchecked)
            .collect::<Result<_, _>>()?;
        Ok(Self::Output::new(
            self.reference_block_commitment,
            unwrap_infallible(self.reference_block_num.verify()),
            updates,
            miden_protocol::transaction::InputNotes::new_unchecked(inputs),
            outputs,
            unwrap_infallible(self.expiration_block_num.verify()),
            miden_protocol::transaction::OrderedTransactionHeaders::new_unchecked(transactions),
            self.proof,
        )?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProvenBatchError {
    #[error("account updates must have unique, ascending account IDs")]
    AccountOrder,
    #[error("{0} does not match proposal")]
    ProposalMismatch(&'static str),
}

/// Checks all fields duplicated from an already-verified proposal. The batch execution proof
/// still needs verification by the consuming service; this only establishes proposal agreement.
impl crate::VerifyWith<&miden_protocol::batch::ProposedBatch> for ProvenBatch {
    type Verified = miden_protocol::batch::ProvenBatch;
    type Error = VerificationError;
    fn verify_with(
        self,
        proposed: &miden_protocol::batch::ProposedBatch,
    ) -> Result<Self::Verified, Self::Error> {
        let batch = self.build_unchecked()?;
        let header = proposed.reference_block_header();
        let mismatch = if batch.reference_block_num() != header.block_num() {
            Some("reference block number")
        } else if batch.reference_block_commitment() != header.commitment() {
            Some("reference block commitment")
        } else if batch.account_updates() != proposed.account_updates() {
            Some("account updates")
        } else if !batch.input_notes().iter().eq(proposed.input_notes().iter()) {
            Some("input notes")
        } else if batch.output_notes() != proposed.output_notes() {
            Some("output notes")
        } else if batch.batch_expiration_block_num() != proposed.batch_expiration_block_num() {
            Some("expiration block")
        } else if batch.transactions().as_slice() != proposed.transaction_headers().as_slice() {
            Some("transaction headers")
        } else {
            None
        };
        if let Some(mismatch) = mismatch {
            return Err(ProvenBatchError::ProposalMismatch(mismatch).into());
        }
        Ok(batch)
    }
}
