use alloc::vec::Vec;

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
/// This enforces the public-content-word limit but does not authenticate the headers.
impl VerifyWith<&OrderedTransactionHeaders> for PublicTransactionLogs {
    type Verified = VerifiedLogs;
    type Error = VerificationError;

    fn verify_with(
        self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<Self::Verified, Self::Error> {
        Ok(VerifiedLogs::new(self.verify_entries()?, headers.as_slice().iter())?)
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
        Ok(VerifiedLogs::new(
            self.verify_entries()?,
            batches.iter().flat_map(OrderedTransactionHeaders::as_slice),
        )?)
    }
}

impl PublicTransactionLogs {
    fn verify_entries(self) -> Result<Vec<(TransactionId, TransactionLogs)>, VerificationError> {
        Ok(self.entries.try_map(|entry| -> Result<_, VerificationError> {
            Ok((
                miden_protobuf::unwrap_infallible(entry.transaction_id.verify()),
                entry.logs.verify()?,
            ))
        })?)
    }
}

#[cfg(test)]
mod tests;
