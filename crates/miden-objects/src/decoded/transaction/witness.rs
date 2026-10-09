use miden_protobuf::unwrap_infallible;

use crate::decoded::VerificationError;
use crate::{BuildUnchecked, Verify, proto};

#[cfg(test)]
mod tests;

pub use proto::transaction::DecodedTransactionWitnessV1 as TransactionWitnessV1;

/// Builds the inputs under the same conditions as [`super::TransactionInputsV1`]. The final account
/// and expiration block number are not checked to be the result of executing the inputs, which a
/// prover checks.
impl BuildUnchecked for TransactionWitnessV1 {
    type Output = miden_protocol::transaction::TransactionWitness;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        Ok(Self::Output::new_unchecked(
            self.tx_inputs.build_unchecked()?,
            self.final_account.verify()?,
            unwrap_infallible(self.expiration_block_num.verify()),
        ))
    }
}

pub use proto::transaction::DecodedTransactionWitness as TransactionWitness;

/// Dispatches the decoded version.
impl BuildUnchecked for TransactionWitness {
    type Output = miden_protocol::transaction::TransactionWitness;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        let proto::transaction::transaction_witness::DecodedVersion::V1(witness) = self.version;
        witness.build_unchecked()
    }
}
