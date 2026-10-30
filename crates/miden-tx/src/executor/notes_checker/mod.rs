use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_processor::ExecutionError;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Note;
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    TransactionArgs,
    TransactionInputs,
    TransactionKernel,
};
use miden_standards::note::{NoteConsumptionStatus, StandardNote};

use super::{ProgramExecutor, TransactionExecutor};
use crate::auth::TransactionAuthenticator;
use crate::errors::TransactionCheckerError;
use crate::executor::map_execution_error;
use crate::{DataStore, NoteCheckerError, TransactionExecutorError, TransactionKernelError};

mod bundle;
mod checker_utils;
mod error;
mod fee;
mod standards_errors;

use bundle::{NoteBundler, NoteBundles};
use checker_utils::CheckerBudget;
pub use checker_utils::{
    FailedNote,
    MAX_NUM_CHECKER_NOTES,
    NoteConsumptionInfo,
    NoteFailure,
    SuccessfulNote,
};
pub use error::{FeeError, SponsorshipRejectionError};
use fee::fee_error;

// NOTE CONSUMPTION CHECKER
// ================================================================================================

/// This struct performs input notes check against provided target account.
///
/// The check is performed using the [NoteConsumptionChecker::check_notes_consumability] procedure.
/// Essentially runs the transaction to make sure that provided input notes could be consumed by the
/// account.
pub struct NoteConsumptionChecker<'a, STORE, AUTH, EXEC: ProgramExecutor> {
    tx_executor: &'a TransactionExecutor<'a, 'a, STORE, AUTH, EXEC>,
}

impl<'a, STORE, AUTH, EXEC> NoteConsumptionChecker<'a, STORE, AUTH, EXEC>
where
    STORE: DataStore + Sync,
    AUTH: TransactionAuthenticator + Sync,
    EXEC: ProgramExecutor,
{
    /// Creates a new [`NoteConsumptionChecker`] instance with the given transaction executor.
    pub fn new(tx_executor: &'a TransactionExecutor<'a, 'a, STORE, AUTH, EXEC>) -> Self {
        NoteConsumptionChecker { tx_executor }
    }

    /// Checks whether some set of the provided input notes could be consumed by the provided
    /// account by executing the transaction with varying combination of notes. Returns a list of
    /// successfully consumed notes and a list of failed notes.
    ///
    /// This function attempts to find the maximum set of notes that can be successfully executed
    /// together by the target account.
    ///
    /// Because of the runtime complexity involved in this function, a limited range of
    /// [`MAX_NUM_CHECKER_NOTES`] input notes is allowed.
    ///
    /// If some notes succeed and others fail, the failed notes are removed from the candidate set,
    /// together with the notes bound to them, and the remaining notes (successful + unattempted)
    /// are retried in the next iteration. This process continues until either all remaining notes
    /// succeed or no notes can be successfully executed.
    ///
    /// For example, given notes A, B, C, D, E, the execution flow would be as follows:
    /// - Try [A, B, C, D, E] → A, B succeed, C fails → Remove C, try again.
    /// - Try [A, B, D, E] → A, B, D succeed, E fails → Remove E, try again.
    /// - Try [A, B, D] → All succeed → Return successful=[A, B, D], failed=[C, E].
    ///
    /// If a failure occurs at the epilogue phase of the transaction execution, the relevant set of
    /// otherwise-successful notes are retried in various combinations in an attempt to find a
    /// combination that passes the epilogue phase successfully. Notes that are only consumable
    /// together, such as a feature note and the FEE_SPONSORSHIP notes bound to it, are grouped and
    /// retried as a unit.
    ///
    /// FEE_SPONSORSHIP notes the target account cannot consume at all are rejected up front, before
    /// anything is executed: one whose feature note is absent and which the account may not
    /// reclaim, and one naming another FEE_SPONSORSHIP note as its feature note.
    ///
    /// A bundle whose fee the account could not collect fails as a whole, with its feature note
    /// reported as [`NoteFailure::Fee`]: when a sponsorship carries an asset other than the one the
    /// account collects fees in, when the account has no fee for the feature note, or when the
    /// sponsorships do not cover the fee, which is reported with the fee they provide.
    ///
    /// # Errors
    ///
    /// Returns an error if [`InputNotes`] cannot be created from the provided notes vector.
    pub async fn check_notes_consumability(
        &self,
        target_account_id: AccountId,
        block_ref: BlockNumber,
        notes: Vec<Note>,
        tx_args: TransactionArgs,
    ) -> Result<NoteConsumptionInfo, NoteCheckerError> {
        let num_notes = notes.len();
        if num_notes == 0 || num_notes > MAX_NUM_CHECKER_NOTES {
            return Err(NoteCheckerError::InputNoteCountOutOfRange(num_notes));
        }

        // Group the notes into bundles, dropping the ones that can be ruled out without executing
        // anything.
        let (bundles, rejected) = NoteBundler::new(target_account_id, block_ref).bundle(&notes);
        if bundles.is_empty() {
            return Ok(NoteConsumptionInfo::new(Vec::new(), rejected));
        }

        let input_notes = InputNotes::from_unauthenticated_notes(bundles.to_notes())
            .map_err(NoteCheckerError::TransactionInputs)?;

        let tx_inputs = self
            .tx_executor
            .prepare_tx_inputs(target_account_id, block_ref, input_notes, tx_args)
            .await
            .map_err(NoteCheckerError::TransactionPreparation)?;

        // Attempt to find an executable set of notes.
        let mut budget = CheckerBudget::new(self.tx_executor.exec_options);
        let mut data_store_request_count = 0;
        self.find_executable_notes_by_elimination(
            tx_inputs,
            bundles,
            rejected,
            &mut budget,
            &mut data_store_request_count,
        )
        .await
    }

    /// Checks whether the provided input note could be consumed by the provided account by
    /// executing a transaction at the specified block height.
    ///
    /// This function takes into account the possibility that the signatures may not be loaded into
    /// the transaction context and returns the [`NoteConsumptionStatus`] result accordingly.
    ///
    /// This function first applies the static analysis of the provided note, and if it doesn't
    /// reveal any errors next it tries to execute the transaction. A FEE_SPONSORSHIP note is
    /// analysed as a note whose feature note is absent, since it is the only input note, and so
    /// against the rules of its reclaim path.
    ///
    /// Based on the execution result,
    /// it either returns a [`NoteCheckerError`] or the [`NoteConsumptionStatus`]: depending on
    /// whether the execution succeeded, failed in the prologue, during the note execution process
    /// or in the epilogue.
    pub async fn can_consume(
        &self,
        target_account_id: AccountId,
        block_ref: BlockNumber,
        note: InputNote,
        tx_args: TransactionArgs,
    ) -> Result<NoteConsumptionStatus, NoteCheckerError> {
        // Return the consumption status if we manage to determine it from the standard note
        if let Some(standard_note) = StandardNote::from_script_root(note.note().script().root())
            && let Some(consumption_status) =
                standard_note.is_consumable(note.note(), target_account_id, block_ref)
        {
            return Ok(consumption_status);
        }

        // Prepare transaction inputs.
        let mut tx_inputs = self
            .tx_executor
            .prepare_tx_inputs(
                target_account_id,
                block_ref,
                InputNotes::new_unchecked(vec![note.clone()]),
                tx_args,
            )
            .await
            .map_err(NoteCheckerError::TransactionPreparation)?;

        // try to consume the provided note
        let mut budget = CheckerBudget::single_attempt(self.tx_executor.exec_options);
        let mut data_store_request_count = 0;
        match self
            .try_execute_notes(&mut tx_inputs, &mut budget, &mut data_store_request_count)
            .await
        {
            // execution succeeded
            Ok(_cycle_counts) => Ok(NoteConsumptionStatus::Consumable),
            Err(tx_checker_error) => {
                match tx_checker_error {
                    TransactionCheckerError::ExecutionBudgetExhausted { max_cycles } => {
                        Err(NoteCheckerError::ExecutionBudgetExhausted { max_cycles })
                    },
                    TransactionCheckerError::DataStoreRequestLimitExceeded { max_requests } => {
                        Err(NoteCheckerError::DataStoreRequestLimitExceeded { max_requests })
                    },
                    // execution failed on the preparation stage, before we actually executed the tx
                    TransactionCheckerError::TransactionPreparation(e) => {
                        Err(NoteCheckerError::TransactionPreparation(e))
                    },
                    // execution failed during the prologue
                    TransactionCheckerError::PrologueExecution(e) => {
                        Err(NoteCheckerError::PrologueExecution(e))
                    },
                    // execution failed during the note processing
                    TransactionCheckerError::NoteExecution { .. } => {
                        Ok(NoteConsumptionStatus::UnconsumableConditions)
                    },
                    // execution failed during the epilogue
                    TransactionCheckerError::EpilogueExecution {
                        error: epilogue_error, ..
                    } => Ok(handle_epilogue_error(note.note(), epilogue_error)),
                    TransactionCheckerError::TransactionScriptExecution(error) => {
                        Err(NoteCheckerError::TransactionScriptExecution(error))
                    },
                }
            },
        }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Finds a set of executable notes and eliminates failed notes from the list in the process.
    ///
    /// When a note fails, the whole bundle it belongs to is eliminated: the failed note is blamed,
    /// and the rest of its bundle is reported as its collateral.
    ///
    /// The result contains some combination of the input notes partitioned by whether they
    /// succeeded or failed to execute. `failed_notes` seeds the failures reported, so that notes
    /// already ruled out before any execution are accounted for in the result.
    async fn find_executable_notes_by_elimination(
        &self,
        mut tx_inputs: TransactionInputs,
        mut bundles: NoteBundles,
        mut failed_notes: Vec<FailedNote>,
        budget: &mut CheckerBudget,
        data_store_request_count: &mut usize,
    ) -> Result<NoteConsumptionInfo, NoteCheckerError> {
        // Attempt to execute notes in a loop. Reduce the set of bundles based on failures until
        // either a set of notes executes without failure or the set of bundles cannot be further
        // reduced.
        loop {
            // Execute the notes of the candidate bundles.
            //
            // We can safely use unchecked builder for the candidate notes here since the provided
            // notes were already validated previously in the `check_notes_consumability` via the
            // `from_unauthenticated_notes` constructor.
            tx_inputs.set_input_notes(InputNotes::new_unchecked(
                bundles.to_notes().into_iter().map(InputNote::unauthenticated).collect(),
            ));
            match self.try_execute_notes(&mut tx_inputs, budget, data_store_request_count).await {
                Ok(cycle_counts) => {
                    // A full set of successful notes has been found. The bundles hold the notes in
                    // the order they were executed in, so they line up with the cycle counts.
                    let successful = bundles
                        .into_notes()
                        .into_iter()
                        .zip(cycle_counts)
                        .map(|(note, num_cycles)| SuccessfulNote::new(note, num_cycles))
                        .collect();
                    return Ok(NoteConsumptionInfo::new(successful, failed_notes));
                },
                Err(TransactionCheckerError::NoteExecution {
                    failed_note_index,
                    error,
                    failed_note_cycle_count,
                    ..
                }) => {
                    // The rest of the failed note's bundle cannot be consumed without it, so the
                    // whole bundle is eliminated.
                    let failed_note_id =
                        tx_inputs.input_notes().get_note(failed_note_index).note().id();
                    let bundle = bundles
                        .remove_containing(failed_note_id)
                        .expect("every candidate note belongs to a bundle");
                    let blamed_idx = bundle
                        .notes()
                        .position(|note| note.id() == failed_note_id)
                        .expect("the bundle holds the failed note");
                    failed_notes.extend(bundle.failed_notes(
                        blamed_idx,
                        NoteFailure::Blamed {
                            error,
                            num_cycles: failed_note_cycle_count,
                        },
                    ));

                    // All possible candidate combinations have been attempted.
                    if bundles.is_empty() {
                        return Ok(NoteConsumptionInfo::new(Vec::new(), failed_notes));
                    }
                    // Continue and process the next set of candidates.
                },
                Err(TransactionCheckerError::EpilogueExecution { .. }) => {
                    return self
                        .find_largest_executable_combination(
                            bundles,
                            failed_notes,
                            tx_inputs,
                            budget,
                            data_store_request_count,
                        )
                        .await;
                },
                Err(TransactionCheckerError::ExecutionBudgetExhausted { max_cycles }) => {
                    return Err(NoteCheckerError::ExecutionBudgetExhausted { max_cycles });
                },
                Err(TransactionCheckerError::DataStoreRequestLimitExceeded { max_requests }) => {
                    return Err(NoteCheckerError::DataStoreRequestLimitExceeded { max_requests });
                },
                Err(TransactionCheckerError::PrologueExecution(err)) => {
                    return Err(NoteCheckerError::PrologueExecution(err));
                },
                Err(TransactionCheckerError::TransactionPreparation(err)) => {
                    return Err(NoteCheckerError::TransactionPreparation(err));
                },
                Err(TransactionCheckerError::TransactionScriptExecution(err)) => {
                    return Err(NoteCheckerError::TransactionScriptExecution(err));
                },
            }
        }
    }

    /// Attempts to find the largest possible combination of notes that can execute successfully
    /// together.
    ///
    /// The search grows a known-good set one bundle at a time: each round appends every remaining
    /// bundle to the accepted set in turn and keeps the first bundle that lets the whole set pass,
    /// until a round adds nothing.
    async fn find_largest_executable_combination(
        &self,
        mut remaining_bundles: NoteBundles,
        mut failed_notes: Vec<FailedNote>,
        mut tx_inputs: TransactionInputs,
        budget: &mut CheckerBudget,
        data_store_request_count: &mut usize,
    ) -> Result<NoteConsumptionInfo, NoteCheckerError> {
        let mut successful_notes: Vec<Note> = Vec::new();
        let mut successful_cycle_counts = Vec::new();
        let mut failed_note_index = BTreeMap::new();

        // Grow the accepted set until a full pass over the remaining bundles adds nothing, at which
        // point no bundle can extend it and the set is as large as this search can make it.
        loop {
            let mut extended = false;

            for idx in 0..remaining_bundles.bundles().len() {
                let bundle = remaining_bundles.bundles()[idx].clone();
                let bundle_notes: Vec<Note> = bundle.notes().cloned().collect();
                let candidate_notes: Vec<Note> =
                    successful_notes.iter().chain(&bundle_notes).cloned().collect();

                // We can safely use unchecked builder for the candidate notes here since the
                // provided notes were already validated previously in the
                // `check_notes_consumability` via the `from_unauthenticated_notes` constructor.
                tx_inputs.set_input_notes(InputNotes::new_unchecked(
                    candidate_notes.iter().cloned().map(InputNote::unauthenticated).collect(),
                ));
                match self.try_execute_notes(&mut tx_inputs, budget, data_store_request_count).await
                {
                    Ok(cycle_counts) => {
                        // The notes just added might have failed earlier, either on their own or
                        // as part of another candidate set. Remove them from the failed list.
                        for note in bundle_notes {
                            failed_note_index.remove(&note.id());
                        }

                        // Store the cycle counts from the latest successful execution.
                        successful_cycle_counts = cycle_counts;

                        // This combination succeeded; commit it and drop the bundle from the
                        // remaining set.
                        successful_notes = candidate_notes;
                        remaining_bundles.remove(idx);
                        extended = true;

                        break;
                    },
                    Err(TransactionCheckerError::ExecutionBudgetExhausted { max_cycles }) => {
                        return Err(NoteCheckerError::ExecutionBudgetExhausted { max_cycles });
                    },
                    Err(TransactionCheckerError::DataStoreRequestLimitExceeded {
                        max_requests,
                    }) => {
                        return Err(NoteCheckerError::DataStoreRequestLimitExceeded {
                            max_requests,
                        });
                    },
                    Err(TransactionCheckerError::PrologueExecution(error)) => {
                        return Err(NoteCheckerError::PrologueExecution(error));
                    },
                    Err(TransactionCheckerError::TransactionPreparation(error)) => {
                        return Err(NoteCheckerError::TransactionPreparation(error));
                    },
                    Err(TransactionCheckerError::TransactionScriptExecution(error)) => {
                        return Err(NoteCheckerError::TransactionScriptExecution(error));
                    },
                    Err(TransactionCheckerError::NoteExecution {
                        failed_note_index: execution_failed_note_index,
                        error,
                        failed_note_cycle_count,
                        ..
                    }) => {
                        let blamed_idx = execution_failed_note_index
                            .checked_sub(successful_notes.len())
                            .filter(|idx| *idx < bundle_notes.len())
                            .unwrap_or(0);
                        let failure = NoteFailure::Blamed {
                            error,
                            num_cycles: failed_note_cycle_count,
                        };
                        for failed_note in bundle.failed_notes(blamed_idx, failure) {
                            failed_note_index.insert(failed_note.note().id(), failed_note);
                        }
                    },
                    Err(TransactionCheckerError::EpilogueExecution { error, .. }) => {
                        let failure = match bundle.fee_error(&error) {
                            Some(reason) => NoteFailure::Fee { reason, error },
                            None => NoteFailure::Blamed { error, num_cycles: None },
                        };
                        for failed_note in bundle.failed_notes(0, failure) {
                            failed_note_index.insert(failed_note.note().id(), failed_note);
                        }
                    },
                }
            }

            if !extended {
                break;
            }
        }

        // Pair successful notes with their cycle counts from the last successful execution.
        let successful = successful_notes
            .into_iter()
            .zip(successful_cycle_counts)
            .map(|(note, num_cycles)| SuccessfulNote::new(note, num_cycles))
            .collect();

        // Append failed notes to the list of failed notes provided as input.
        failed_notes.extend(failed_note_index.into_values());
        Ok(NoteConsumptionInfo::new(successful, failed_notes))
    }

    /// Attempts to execute a transaction with the provided input notes.
    ///
    /// This method executes the full transaction pipeline including prologue, note execution,
    /// and epilogue phases. It returns `Ok(cycle_counts)` if all notes are successfully consumed
    /// (where `cycle_counts` contains the number of cycles for each note), or a specific
    /// [`TransactionCheckerError`] indicating where and why the execution failed. The order of the
    /// returned `cycle_counts` is guaranteed to match the order of the input notes.
    async fn try_execute_notes(
        &self,
        tx_inputs: &mut TransactionInputs,
        budget: &mut CheckerBudget,
        data_store_request_count: &mut usize,
    ) -> Result<Vec<usize>, TransactionCheckerError> {
        if tx_inputs.input_notes().is_empty() {
            return Ok(Vec::new());
        }

        let (mut host, stack_inputs, advice_inputs) = self
            .tx_executor
            .prepare_transaction_with_data_store_request_count(tx_inputs, *data_store_request_count)
            .await
            .map_err(TransactionCheckerError::TransactionPreparation)?;

        let exec_options = budget.take_execution_options(self.tx_executor.exec_options).ok_or(
            TransactionCheckerError::ExecutionBudgetExhausted { max_cycles: budget.max_cycles() },
        )?;

        let program = TransactionKernel::main();
        let kernel_debug_info = TransactionKernel::main_debug_info();
        let executor = EXEC::new(stack_inputs, advice_inputs, exec_options)
            .map_err(ExecutionError::advice_error_no_context)
            .map_err(map_execution_error)
            .map_err(TransactionCheckerError::PrologueExecution)?;
        let result = executor
            .with_debug_info(kernel_debug_info.as_deref().cloned().unwrap_or_default())
            .with_entrypoint_source_node(TransactionKernel::main_entrypoint_source_node())
            .execute(&program, &mut host)
            .await
            .map_err(map_execution_error);

        let (tx_progress, lazy_loaded_data, updated_data_store_request_count) =
            host.into_notes_checker_parts();
        *data_store_request_count = updated_data_store_request_count;

        // Set the lazy loaded from the execution as input for reexecution. This avoids lazy-loading
        // data that was already loaded from the data store in the next potential run.
        // This data is valid regardless of whether execution was successful or not.
        lazy_loaded_data.add_to(tx_inputs).map_err(|source| {
            TransactionCheckerError::TransactionPreparation(
                TransactionExecutorError::InvalidTransactionInputs(source),
            )
        })?;

        if let Err(error) = &result
            && let Some(max_requests) = data_store_request_limit(error)
        {
            return Err(TransactionCheckerError::DataStoreRequestLimitExceeded { max_requests });
        }

        match result {
            Ok(_execution_output) => {
                let cycle_counts = tx_progress
                    .note_execution()
                    .iter()
                    .map(|(_, interval)| interval.len())
                    .collect();

                Ok(cycle_counts)
            },
            Err(error) => {
                let notes = tx_progress.note_execution();

                // Empty notes vector means that we didn't process the notes, so an error
                // occurred.
                if notes.is_empty() {
                    return Err(TransactionCheckerError::PrologueExecution(error));
                }

                let ((_, last_note_interval), success_notes) =
                    notes.split_last().expect("notes vector is not empty because of earlier check");

                // If the epilogue started, then an error occurred during the epilogue. All notes
                // executed successfully in this case.
                if tx_progress.epilogue().start().is_some() {
                    let successful_notes_cycle_counts =
                        notes.iter().map(|(_, interval)| interval.len()).collect();
                    Err(TransactionCheckerError::EpilogueExecution {
                        error,
                        successful_notes_cycle_counts,
                    })
                } else if last_note_interval.end().is_some() {
                    Err(TransactionCheckerError::TransactionScriptExecution(error))
                } else {
                    // Return the index of the failed note.
                    let failed_note_index = success_notes.len();
                    let successful_notes_cycle_counts =
                        success_notes.iter().map(|(_, interval)| interval.len()).collect();

                    // Compute the failed note's cycle count when the failure was due to
                    // exceeding the cycle limit. In this case, the note's interval has a
                    // start but no end, and the total cycles consumed equals the max allowed.
                    let failed_note_cycle_count = match &error {
                        TransactionExecutorError::TransactionProgramExecutionFailed(
                            ExecutionError::CycleLimitExceeded(max_cycles),
                        ) => last_note_interval
                            .start()
                            .map(|start| *max_cycles as usize - usize::from(start)),
                        _ => None,
                    };

                    Err(TransactionCheckerError::NoteExecution {
                        failed_note_index,
                        error,
                        successful_notes_cycle_counts,
                        failed_note_cycle_count,
                    })
                }
            },
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn data_store_request_limit(error: &TransactionExecutorError) -> Option<usize> {
    let TransactionExecutorError::TransactionProgramExecutionFailed(ExecutionError::EventError {
        error,
        ..
    }) = error
    else {
        return None;
    };

    match error.downcast_ref::<TransactionKernelError>() {
        Some(TransactionKernelError::DataStoreRequestLimitExceeded { max_requests }) => {
            Some(*max_requests)
        },
        _ => None,
    }
}

/// Handle the epilogue error during the note consumption check in the `can_consume` method.
///
/// The goal of this helper function is to handle the cases where the account couldn't consume the
/// note because of some epilogue check failure, e.g. absence of the authenticator.
fn handle_epilogue_error(
    note: &Note,
    epilogue_error: TransactionExecutorError,
) -> NoteConsumptionStatus {
    // A note checked on its own has no FEE_SPONSORSHIP notes bound to it, which a fee-collecting
    // account reports as a fee it cannot collect.
    if let Some(fee_error) = fee_error(&epilogue_error, note, &[]) {
        return NoteConsumptionStatus::NeverConsumable(Box::new(fee_error));
    }

    match epilogue_error {
        // `Unauthorized` is returned for the multisig accounts if the transaction doesn't have
        // enough signatures.
        TransactionExecutorError::Unauthorized(_)
        // `MissingAuthenticator` is returned for the account with the basic auth if the
        // authenticator was not provided to the executor (UnreachableAuth).
        | TransactionExecutorError::MissingAuthenticator => {
            // Both these cases signal that there is a probability that the provided note could be
            // consumed if the authentication is provided.
            NoteConsumptionStatus::ConsumableWithAuthorization
        },
        _ => NoteConsumptionStatus::UnconsumableConditions,
    }
}
