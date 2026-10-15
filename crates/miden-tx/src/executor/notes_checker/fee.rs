use alloc::format;
use alloc::vec::Vec;

use miden_processor::advice::AdviceInputs;
use miden_protocol::Felt;
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::{Note, NoteId};
use miden_protocol::transaction::TransactionScript;
use miden_standards::code_builder::CodeBuilder;
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

impl FeeError {
    /// Sets the fee the account charges for the feature note of a [`FeeError::FeeNotCovered`],
    /// leaving any other error unchanged.
    pub(super) fn with_required_fee(mut self, required_fee: Option<AssetAmount>) -> Self {
        if let FeeError::FeeNotCovered { required, .. } = &mut self {
            *required = required_fee;
        }
        self
    }
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

// FEE ESTIMATION
// ================================================================================================

/// Returns the transaction script and the advice inputs that estimate the fee the account charges
/// for `note` through its fee manager, as [`fee_from_estimation_stack`] reads it from the stack the
/// script leaves.
///
/// The note is priced with a timeframe and priority of 0, which is what fee collection passes. The
/// advice inputs carry the preimage of the note's recipient, which fee policies may recover.
///
/// Returns `None` if the script cannot be compiled.
pub(super) fn fee_estimation_script(note: &Note) -> Option<(TransactionScript, AdviceInputs)> {
    let source = format!(
        r#"
        use miden::standards::assets::fungible_asset
        use miden::standards::fees::fee_manager

        @transaction_script
        pub proc main
            # place the note parameters with a timeframe and priority of 0, and the padding
            push.0.0.0.0
            push.{attachments_commitment}
            push.{assets_commitment}
            push.{recipient}
            # => [RECIPIENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe, priority, pad(2),
            #     SCRIPT_ARGS, pad(12)]

            call.fee_manager::estimate_note_fee
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8), SCRIPT_ARGS, pad(12)]

            dropw exec.fungible_asset::value_into_amount_unchecked
            # => [fee_amount, pad(8), SCRIPT_ARGS, pad(12)]

            # drop the padding, keeping the stack at 16 elements
            movdn.8 dropw dropw swap drop
            # => [fee_amount, pad(15)]
        end
        "#,
        attachments_commitment = note.attachments().to_commitment(),
        assets_commitment = note.assets().commitment(),
        recipient = note.recipient().digest(),
    );
    let script = CodeBuilder::default().compile_tx_script(source).ok()?;
    let advice_inputs = AdviceInputs::default().with_map(note.recipient().to_advice_map_entries());

    Some((script, advice_inputs))
}

/// Returns the fee the [`fee_estimation_script`] left on top of `stack`.
pub(super) fn fee_from_estimation_stack(stack: &[Felt; 16]) -> Option<AssetAmount> {
    AssetAmount::new(stack[0].as_canonical_u64()).ok()
}
