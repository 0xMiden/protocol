use alloc::vec::Vec;

use miden_protocol::asset::AssetAmount;
use miden_protocol::note::{Note, NoteId};
use miden_standards::errors::standards::{
    ERR_FEE_MANAGER_INPUT_NOTE_FEE_NOT_COVERED,
    ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE,
};

use super::bundle::{NoteBundle, SponsorshipInput};
use crate::TransactionExecutorError;

// FEE ERROR
// ================================================================================================

/// The reason the account could not collect the fee of a feature note, recovered from the error of
/// the failed execution.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FeeError {
    /// The account's fee policy has no fee for the feature note, so fee estimation aborted.
    #[error("the account's fee policy has no fee for feature note {feature_note_id}")]
    FeeNotScheduled { feature_note_id: NoteId },
    /// The FEE_SPONSORSHIP notes bound to the feature note carry less than the fee the account
    /// charges for it.
    #[error(
        "the FEE_SPONSORSHIP notes bound to feature note {feature_note_id} provide a fee of {provided}, which does not cover the fee the account charges for it"
    )]
    FeeNotCovered {
        /// The feature note whose fee is not covered.
        feature_note_id: NoteId,
        /// The FEE_SPONSORSHIP notes bound to the feature note.
        sponsorship_ids: Vec<NoteId>,
        /// The fee the FEE_SPONSORSHIP notes provide between them.
        provided: AssetAmount,
        /// The fee the account charges for the feature note, if it could be determined.
        required: Option<AssetAmount>,
    },
}

impl NoteBundle {
    /// Returns the fee error the failed execution of this bundle reports, or `None` if the
    /// execution failed for another reason or the bundle collects no fee.
    pub(super) fn fee_error(&self, error: &TransactionExecutorError) -> Option<FeeError> {
        match self {
            NoteBundle::Feature { feature_note, sponsorships } => {
                fee_error(error, feature_note, sponsorships)
            },
            // A reclaim collects no fee.
            NoteBundle::Reclaim(_) => None,
        }
    }
}

/// Returns the fee error the failed execution of a transaction consuming `feature_note` and the
/// `sponsorships` bound to it reports, or `None` if the execution failed for another reason.
///
/// The error is recognized by the error code of the fee collection or fee estimation assertion
/// that failed, and its details are taken from the notes.
pub(super) fn fee_error(
    error: &TransactionExecutorError,
    feature_note: &Note,
    sponsorships: &[SponsorshipInput],
) -> Option<FeeError> {
    let TransactionExecutorError::TransactionProgramExecutionFailed(execution_error) = error else {
        return None;
    };

    if ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE.matches_execution_error(execution_error) {
        return Some(FeeError::FeeNotScheduled { feature_note_id: feature_note.id() });
    }
    if !ERR_FEE_MANAGER_INPUT_NOTE_FEE_NOT_COVERED.matches_execution_error(execution_error) {
        return None;
    }

    // A total above the maximum asset amount could not have been collected into the account vault
    // in the first place, so the execution would have failed for another reason.
    let provided = sponsorships.iter().try_fold(AssetAmount::ZERO, |total, sponsorship| {
        (total + sponsorship.sponsorship().asset().amount()).ok()
    })?;

    Some(FeeError::FeeNotCovered {
        feature_note_id: feature_note.id(),
        sponsorship_ids: sponsorships.iter().map(|sponsorship| sponsorship.note().id()).collect(),
        provided,
        required: None,
    })
}
