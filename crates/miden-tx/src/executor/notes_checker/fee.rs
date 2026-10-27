use miden_protocol::asset::AssetAmount;
use miden_protocol::note::Note;
use miden_standards::errors::standards::{
    ERR_FEE_MANAGER_INPUT_NOTE_FEE_NOT_COVERED,
    ERR_FEE_MANAGER_SPONSORSHIP_WRONG_ASSET,
    ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE,
};

use super::bundle::{NoteBundle, SponsorshipInput};
use super::error::FeeError;
use crate::TransactionExecutorError;

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

    if ERR_FEE_MANAGER_SPONSORSHIP_WRONG_ASSET.matches_execution_error(execution_error) {
        return Some(FeeError::WrongFeeAsset);
    }
    if ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE.matches_execution_error(execution_error) {
        return Some(FeeError::FeeNotScheduled { feature_note_id: feature_note.id() });
    }
    if !ERR_FEE_MANAGER_INPUT_NOTE_FEE_NOT_COVERED.matches_execution_error(execution_error) {
        return None;
    }

    // A total above the maximum asset amount could not have been collected into the account vault
    // in the first place, so the execution would have failed for another reason.
    let provided = sponsorships
        .iter()
        .try_fold(AssetAmount::ZERO, |total, sponsorship| (total + sponsorship.amount()).ok())?;

    Some(FeeError::FeeNotCovered {
        feature_note_id: feature_note.id(),
        sponsorship_ids: sponsorships.iter().map(|sponsorship| sponsorship.note().id()).collect(),
        provided,
    })
}
