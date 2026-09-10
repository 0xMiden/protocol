use miden_protobuf::unwrap_infallible;
pub use proto::transaction::DecodedTransactionId as TransactionId;

use crate::decoded::VerificationError;
use crate::{BuildUnchecked, Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for TransactionId {
    type Verified = miden_protocol::transaction::TransactionId;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::from_raw(self.id))
    }
}

pub use proto::transaction::DecodedTransactionHeader as TransactionHeader;

/// Builds a header using unchecked input-note commitments. Input/output note uniqueness,
/// note-header invariants, and the transmitted transaction ID are still checked. The caller must
/// establish each input's nullifier/header consistency and authentication, the original note order,
/// and the account ID's relationship to the transaction data.
impl BuildUnchecked for TransactionHeader {
    type Output = miden_protocol::transaction::TransactionHeader;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        let transmitted = unwrap_infallible(self.transaction_id.verify());
        let input_notes = self
            .input_notes
            .into_iter()
            .map(BuildUnchecked::build_unchecked)
            .collect::<Result<_, _>>()?;
        let input_notes = miden_protocol::transaction::InputNotes::new(input_notes)?;
        let output_notes =
            self.output_notes.into_iter().map(Verify::verify).collect::<Result<_, _>>()?;
        let header = Self::Output::new(
            self.account_id.verify()?,
            self.initial_state_commitment,
            self.final_state_commitment,
            input_notes,
            output_notes,
        )?;
        if header.id() != transmitted {
            return Err(TransactionHeaderBuildError::IdMismatch {
                transmitted,
                recomputed: header.id(),
            }
            .into());
        }
        Ok(header)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionHeaderBuildError {
    #[error("transaction ID mismatch: transmitted {transmitted}, recomputed {recomputed}")]
    IdMismatch {
        transmitted: miden_protocol::transaction::TransactionId,
        recomputed: miden_protocol::transaction::TransactionId,
    },
}

pub use proto::transaction::DecodedTxAccountUpdate as TxAccountUpdate;

impl Verify for TxAccountUpdate {
    type Verified = miden_protocol::transaction::TxAccountUpdate;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(
            self.account_id.verify()?,
            self.initial_state_commitment,
            self.final_state_commitment,
            self.account_patch_commitment,
            self.details.verify()?,
        )?)
    }
}

pub use proto::transaction::DecodedProvenTransaction as ProvenTransaction;

/// Checks transaction construction invariants, but not its proof or input-note authentication.
impl crate::BuildUnchecked for ProvenTransaction {
    type Output = miden_protocol::transaction::ProvenTransaction;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        let inputs = self
            .input_notes
            .into_iter()
            .map(BuildUnchecked::build_unchecked)
            .collect::<Result<alloc::vec::Vec<_>, _>>()?;
        let outputs = self
            .output_notes
            .into_iter()
            .map(Verify::verify)
            .collect::<Result<alloc::vec::Vec<_>, _>>()?;
        Ok(Self::Output::new(
            self.account_update.verify()?,
            inputs,
            outputs,
            unwrap_infallible(self.reference_block_num.verify()),
            self.reference_block_commitment,
            unwrap_infallible(self.expiration_block_num.verify()),
            self.proof,
        )?)
    }
}
