use alloc::vec::Vec;

use super::{TransactionLogError, TransactionLogs};
use crate::account::AccountId;
use crate::{Felt, Word};

/// Submitted transaction log data for the account against which the transaction executes.
///
/// A public native account submits complete transaction logs. A private native account submits
/// only their commitment. This applies to all transaction logs, including those emitted by
/// foreign accounts during FPI.
///
/// Validating a private transaction log commitment requires the transaction proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionLogDetails {
    /// A commitment to the private transaction logs.
    Private(Word),
    /// Complete public transaction logs, from which the commitment is derived.
    Public(TransactionLogs),
}

impl TransactionLogDetails {
    /// Returns the computed public or supplied private transaction log commitment.
    pub fn to_commitment(&self) -> Word {
        match self {
            Self::Private(commitment) => *commitment,
            Self::Public(logs) => logs.commitment(),
        }
    }

    /// Returns the public commitment's preimage, or `None` when the logs are private.
    pub fn to_elements(&self) -> Option<Vec<Felt>> {
        match self {
            Self::Private(_) => None,
            Self::Public(logs) => Some(logs.to_elements()),
        }
    }

    /// Checks that public transaction logs are submitted for a public native account and a
    /// private commitment is submitted for a private native account.
    ///
    /// `native_account` is the account against which the transaction executes. A public foreign
    /// account emitting transaction logs during FPI does not make a private transaction public.
    pub(crate) fn validate_visibility(
        &self,
        native_account: AccountId,
    ) -> Result<(), TransactionLogError> {
        let is_public = matches!(self, Self::Public(_));
        if is_public == native_account.is_public() {
            Ok(())
        } else {
            Err(TransactionLogError::VisibilityMismatch)
        }
    }
}
