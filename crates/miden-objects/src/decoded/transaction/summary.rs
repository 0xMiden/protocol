use miden_protobuf::unwrap_infallible;
use miden_protocol::transaction::TransactionSummaryUserParams;
pub use proto::transaction::DecodedTransactionSummary as TransactionSummary;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

/// Dispatches the decoded version.
impl Verify for TransactionSummary {
    type Verified = miden_protocol::transaction::TransactionSummary;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let proto::transaction::transaction_summary::DecodedVersion::V1(summary) = self.version;
        summary.verify()
    }
}

pub use proto::transaction::DecodedTransactionSummaryV1 as TransactionSummaryV1;

impl Verify for TransactionSummaryV1 {
    type Verified = miden_protocol::transaction::TransactionSummary;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let user_params = self.user_params.into_inner();
        Ok(Self::Verified::new(
            self.account_delta.verify()?,
            self.input_notes.verify()?,
            self.output_notes.verify()?,
            self.code_patch.verify()?,
            unwrap_infallible(self.block_number.verify()),
            self.block_commitment,
            self.expiration_delta.try_into()?,
            TransactionSummaryUserParams::try_from(user_params.as_slice())?,
            self.logs.verify()?,
        ))
    }
}
