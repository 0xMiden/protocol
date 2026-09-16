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

/// Verifies the effects and the transaction ID they commit to. The account patch, the input notes
/// and the output notes are each verified, both note collections are checked for duplicates and
/// length limits, and the transaction ID is recomputed from the account state commitments and the
/// note commitments and compared against the transmitted one.
///
/// The reference block commitment is not checked against the reference block number, the account
/// patch is not checked to belong to the account the transaction ran against, and input notes are
/// not authenticated.
impl Verify for TransactionEffectsV1 {
    type Verified = miden_protocol::transaction::TransactionEffects;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let transmitted = unwrap_infallible(self.transaction_id.verify());
        let effects = Self::Verified::new(
            self.initial_state_commitment,
            self.final_state_commitment,
            self.account_patch.verify()?,
            self.input_notes.verify()?,
            self.output_notes.verify()?,
            unwrap_infallible(self.ref_block_number.verify()),
            self.ref_block_commitment,
            unwrap_infallible(self.expiration_block_num.verify()),
        );

        if effects.transaction_id() != transmitted {
            return Err(TransactionEffectsError::IdMismatch {
                transmitted,
                recomputed: effects.transaction_id(),
            }
            .into());
        }

        Ok(effects)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionEffectsError {
    #[error("transaction ID mismatch: transmitted {transmitted}, recomputed {recomputed}")]
    IdMismatch {
        transmitted: miden_protocol::transaction::TransactionId,
        recomputed: miden_protocol::transaction::TransactionId,
    },
}
