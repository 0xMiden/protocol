use miden_protocol::transaction::{
    OrderedTransactionHeaders,
    PublicTransactionLogs as VerifiedLogs,
    TransactionId,
    TransactionLogs,
};
pub use proto::transaction::DecodedPublicTransactionLogs as PublicTransactionLogs;

use crate::decoded::VerificationError;
use crate::{Verify, VerifyWith, proto};

/// Checks completeness, visibility and payload commitments against the owner's transaction headers.
/// This does not authenticate those headers; the enclosing owner enforces its aggregate limits.
impl VerifyWith<&OrderedTransactionHeaders> for PublicTransactionLogs {
    type Verified = VerifiedLogs;
    type Error = VerificationError;

    fn verify_with(
        self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<Self::Verified, Self::Error> {
        Ok(VerifiedLogs::new(self.verify_entries()?, headers)?)
    }
}

/// Checks a block's public logs against its transaction headers in batch order.
impl VerifyWith<&[OrderedTransactionHeaders]> for PublicTransactionLogs {
    type Verified = VerifiedLogs;
    type Error = VerificationError;

    fn verify_with(
        self,
        batches: &[OrderedTransactionHeaders],
    ) -> Result<Self::Verified, Self::Error> {
        Ok(VerifiedLogs::new_for_block(self.verify_entries()?, batches)?)
    }
}

impl PublicTransactionLogs {
    fn verify_entries(
        self,
    ) -> Result<alloc::vec::Vec<(TransactionId, TransactionLogs)>, VerificationError> {
        self.entries.try_map(|entry| -> Result<_, VerificationError> {
            Ok((
                miden_protobuf::unwrap_infallible(entry.transaction_id.verify()),
                entry.logs.verify()?,
            ))
        })
    }
}
