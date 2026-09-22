use miden_protobuf::unwrap_infallible;
pub use proto::transaction::DecodedTransactionEffects as TransactionEffects;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

/// Dispatches the decoded version.
impl Verify for TransactionEffects {
    type Verified = miden_protocol::transaction::TransactionEffects;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let proto::transaction::transaction_effects::DecodedVersion::V1(effects) = self.version;
        effects.verify()
    }
}

pub use proto::transaction::DecodedTransactionEffectsV1 as TransactionEffectsV1;

/// Verifies the effects. The account patch, the input notes and the output notes are each
/// verified, and both note collections are checked for duplicates and length limits.
///
/// The reference block commitment is not checked against the reference block number, the account
/// patch is not checked to belong to the account the transaction ran against, and input notes are
/// not authenticated.
impl Verify for TransactionEffectsV1 {
    type Verified = miden_protocol::transaction::TransactionEffects;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Self::Verified::new(
            self.initial_state_commitment,
            self.final_state_commitment,
            self.account_patch.verify()?,
            self.input_notes.verify()?,
            self.output_notes.verify()?,
            unwrap_infallible(self.ref_block_number.verify()),
            self.ref_block_commitment,
            unwrap_infallible(self.expiration_block_num.verify()),
        )
        .with_logs(self.logs.into_inner(), self.log_salt)
        .map_err(VerificationError::new)
    }
}
