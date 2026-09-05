use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::ExecutionError;
use miden_processor::advice::AdviceInputs;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId};
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    TransactionArgs,
    TransactionInputs,
    TransactionKernel,
};
use miden_standards::note::{FeeSponsorshipNote, NoteConsumptionStatus, StandardNote};

use super::{ProgramExecutor, TransactionExecutor};
use crate::auth::TransactionAuthenticator;
use crate::errors::TransactionCheckerError;
use crate::executor::map_execution_error;
use crate::{DataStore, NoteCheckerError, TransactionExecutorError};

// CONSTANTS
// ================================================================================================

/// Maximum number of notes that can be checked at once.
///
/// Fixed at an amount that should keep each run of note consumption checking to a maximum of ~50ms.
pub const MAX_NUM_CHECKER_NOTES: usize = 20;

// NOTE CONSUMPTION INFO
// ================================================================================================

/// Represents a successfully consumed note along with the number of cycles it took to execute.
#[derive(Debug)]
pub struct SuccessfulNote {
    note: Note,
    num_cycles: usize,
}

impl SuccessfulNote {
    /// Constructs a new `SuccessfulNote`.
    pub fn new(note: Note, num_cycles: usize) -> Self {
        Self { note, num_cycles }
    }

    /// Returns a reference to the note.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// Returns the number of cycles consumed during execution.
    pub fn num_cycles(&self) -> usize {
        self.num_cycles
    }
}

/// Represents a failed note consumption.
#[derive(Debug)]
pub struct FailedNote {
    note: Note,
    /// The error the failing execution produced.
    ///
    /// Shared rather than owned because a whole bundle of notes is tested at once, and every note
    /// of a rejected bundle is reported with the error that rejected it.
    error: Arc<TransactionExecutorError>,
    /// The number of cycles consumed by the note before it failed.
    ///
    /// This is `Some` when the failure was due to exceeding the cycle limit, and `None`
    /// for other error types where the cycle count is not meaningful.
    num_cycles: Option<usize>,
    /// The note this one is bound to, when it failed only as collateral of that note's failure.
    ///
    /// See [`FailedNote::bundled_with`].
    bundled_with: Option<NoteId>,
}

impl FailedNote {
    /// Constructs a new `FailedNote`.
    pub fn new(note: Note, error: TransactionExecutorError, num_cycles: Option<usize>) -> Self {
        Self {
            note,
            error: Arc::new(error),
            num_cycles,
            bundled_with: None,
        }
    }

    /// Returns a reference to the note.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// Returns a reference to the error.
    pub fn error(&self) -> &TransactionExecutorError {
        &self.error
    }

    /// Returns the number of cycles consumed before failure, if available.
    ///
    /// This is `Some` when the failure was due to exceeding the cycle limit, and `None`
    /// for other error types where the cycle count is not meaningful.
    pub fn num_cycles(&self) -> Option<usize> {
        self.num_cycles
    }

    /// Returns the ID of the note this one is bound to, if it failed only because that note did.
    ///
    /// Some notes can only be consumed together, e.g. a FEE_SPONSORSHIP note and the feature note
    /// it pays for. Such notes are tested as one bundle, so rejecting the bundle rejects every note
    /// in it. This is `Some` for the notes that were not themselves blamed for the failure: they
    /// may well be consumable in a different set, and [`FailedNote::error`] reports the error that
    /// rejected the bundle rather than an error attributable to this note.
    pub fn bundled_with(&self) -> Option<NoteId> {
        self.bundled_with
    }
}

/// Contains information about the successful and failed consumption of notes.
#[derive(Default, Debug)]
pub struct NoteConsumptionInfo {
    successful: Vec<SuccessfulNote>,
    failed: Vec<FailedNote>,
}

impl NoteConsumptionInfo {
    /// Creates a new [`NoteConsumptionInfo`] instance with the given successful notes.
    pub fn new_successful(successful: Vec<SuccessfulNote>) -> Self {
        Self { successful, ..Default::default() }
    }

    /// Creates a new [`NoteConsumptionInfo`] instance with the given successful and failed notes.
    pub fn new(successful: Vec<SuccessfulNote>, failed: Vec<FailedNote>) -> Self {
        Self { successful, failed }
    }

    /// Returns a reference to the successfully consumed notes.
    pub fn successful(&self) -> &[SuccessfulNote] {
        &self.successful
    }

    /// Returns a reference to the failed notes.
    pub fn failed(&self) -> &[FailedNote] {
        &self.failed
    }

    /// Consumes the struct and returns the successful and failed notes.
    pub fn into_parts(self) -> (Vec<SuccessfulNote>, Vec<FailedNote>) {
        (self.successful, self.failed)
    }
}

// NOTE BUNDLE
// ================================================================================================

/// A group of input notes that has to be tested for consumability as a unit.
///
/// Most notes stand alone, but some are consumable only in each other's company: a FEE_SPONSORSHIP
/// note is rejected unless the feature note it pays for is an input of the same transaction, and a
/// feature note whose fee is not covered is rejected unless its sponsorships are. Probing such
/// notes individually always fails, so the search for an executable set treats a bundle as its
/// smallest unit.
#[derive(Debug)]
struct NoteBundle {
    notes: Vec<Note>,
}

impl NoteBundle {
    /// Groups `notes` into bundles that must be consumed together.
    ///
    /// A FEE_SPONSORSHIP note joins the bundle of the feature note it names, wherever that note
    /// sits in `notes`; several sponsorships may join the same bundle, matching the top-up
    /// behaviour of `collect_sponsored_fees`. A sponsorship whose feature note is absent from
    /// `notes`, or whose storage does not decode, forms a bundle of its own so that it fails alone
    /// instead of dropping the notes it would otherwise have been grouped with. Every other note
    /// forms a bundle of its own.
    ///
    /// Bundles are ordered by their lowest-indexed note, and notes keep their relative order within
    /// a bundle, so the caller's ordering of `notes` still determines the order in which candidates
    /// are probed.
    fn group(notes: Vec<Note>) -> Vec<Self> {
        let note_ids: BTreeSet<NoteId> = notes.iter().map(Note::id).collect();

        // Map every note that sponsorships can attach to onto the index of its bundle, so a
        // sponsorship can find its feature note's bundle regardless of their relative order.
        let mut bundle_of_note = BTreeMap::new();
        let mut bundles: Vec<Vec<Note>> = Vec::new();
        // Sponsorships are collected in a second pass: the feature note may come after them.
        let mut sponsorships = Vec::new();

        for note in notes {
            // A sponsorship is only bundled when the note it names is actually an input; otherwise
            // it can only be reclaimed, which is something it has to attempt on its own.
            match FeeSponsorshipNote::sponsored_feature_note_id(&note)
                .filter(|feature_note_id| note_ids.contains(feature_note_id))
            {
                Some(feature_note_id) => sponsorships.push((feature_note_id, note)),
                None => {
                    bundle_of_note.insert(note.id(), bundles.len());
                    bundles.push(vec![note]);
                },
            }
        }

        for (feature_note_id, sponsorship) in sponsorships {
            match bundle_of_note.get(&feature_note_id) {
                Some(&bundle_idx) => bundles[bundle_idx].push(sponsorship),
                // The named note is itself a bundled sponsorship, which no well-formed sponsorship
                // does. Leave such a note on its own rather than guessing where it belongs.
                None => bundles.push(vec![sponsorship]),
            }
        }

        bundles.into_iter().map(|notes| Self { notes }).collect()
    }

    /// Returns the notes forming the bundle.
    fn notes(&self) -> &[Note] {
        &self.notes
    }
}

// NOTE CONSUMPTION CHECKER
// ================================================================================================

/// This struct performs input notes check against provided target account.
///
/// The check is performed using the [NoteConsumptionChecker::check_notes_consumability] procedure.
/// Essentially runs the transaction to make sure that provided input notes could be consumed by the
/// account.
pub struct NoteConsumptionChecker<'a, STORE, AUTH, EXEC: ProgramExecutor>(
    &'a TransactionExecutor<'a, 'a, STORE, AUTH, EXEC>,
);

impl<'a, STORE, AUTH, EXEC> NoteConsumptionChecker<'a, STORE, AUTH, EXEC>
where
    STORE: DataStore + Sync,
    AUTH: TransactionAuthenticator + Sync,
    EXEC: ProgramExecutor,
{
    /// Creates a new [`NoteConsumptionChecker`] instance with the given transaction executor.
    pub fn new(tx_executor: &'a TransactionExecutor<'a, 'a, STORE, AUTH, EXEC>) -> Self {
        NoteConsumptionChecker(tx_executor)
    }

    /// Checks whether some set of the provided input notes could be consumed by the provided
    /// account by executing the transaction with varying combination of notes.
    ///
    /// This function attempts to find the maximum set of notes that can be successfully executed
    /// together by the target account.
    ///
    /// Because of the runtime complexity involved in this function, a limited range of
    /// [`MAX_NUM_CHECKER_NOTES`] input notes is allowed.
    ///
    /// If some notes succeed and others fail, the failed notes are removed from the candidate set
    /// and the remaining notes (successful + unattempted) are retried in the next iteration. This
    /// process continues until either all remaining notes succeed or no notes can be successfully
    /// executed
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
    /// retried as a unit, since neither part of such a group executes on its own.
    ///
    /// Returns a list of successfully consumed notes and a list of failed notes.
    pub async fn check_notes_consumability(
        &self,
        target_account_id: AccountId,
        block_ref: BlockNumber,
        mut notes: Vec<Note>,
        tx_args: TransactionArgs,
    ) -> Result<NoteConsumptionInfo, NoteCheckerError> {
        let num_notes = notes.len();
        if num_notes == 0 || num_notes > MAX_NUM_CHECKER_NOTES {
            return Err(NoteCheckerError::InputNoteCountOutOfRange(num_notes));
        }
        // Ensure standard notes are ordered first.
        notes.sort_unstable_by_key(|note| {
            StandardNote::from_script_root(note.script().root()).is_none()
        });

        let notes = InputNotes::from(notes);
        let tx_inputs = self
            .0
            .prepare_tx_inputs(target_account_id, block_ref, notes, tx_args)
            .await
            .map_err(NoteCheckerError::TransactionPreparation)?;

        // Attempt to find an executable set of notes.
        self.find_executable_notes_by_elimination(tx_inputs).await
    }

    /// Checks whether the provided input note could be consumed by the provided account by
    /// executing a transaction at the specified block height.
    ///
    /// This function takes into account the possibility that the signatures may not be loaded into
    /// the transaction context and returns the [`NoteConsumptionStatus`] result accordingly.
    ///
    /// This function first applies the static analysis of the provided note, and if it doesn't
    /// reveal any errors next it tries to execute the transaction. Based on the execution result,
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
            .0
            .prepare_tx_inputs(
                target_account_id,
                block_ref,
                InputNotes::new_unchecked(vec![note]),
                tx_args,
            )
            .await
            .map_err(NoteCheckerError::TransactionPreparation)?;

        // try to consume the provided note
        match self.try_execute_notes(&mut tx_inputs).await {
            // execution succeeded
            Ok(_cycle_counts) => Ok(NoteConsumptionStatus::Consumable),
            Err(tx_checker_error) => {
                match tx_checker_error {
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
                    } => Ok(handle_epilogue_error(epilogue_error)),
                }
            },
        }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Finds a set of executable notes and eliminates failed notes from the list in the process.
    ///
    /// The result contains some combination of the input notes partitioned by whether they
    /// succeeded or failed to execute.
    async fn find_executable_notes_by_elimination(
        &self,
        mut tx_inputs: TransactionInputs,
    ) -> Result<NoteConsumptionInfo, NoteCheckerError> {
        let mut candidate_notes = tx_inputs
            .input_notes()
            .iter()
            .map(|note| note.clone().into_note())
            .collect::<Vec<_>>();
        let mut failed_notes = Vec::new();

        // Attempt to execute notes in a loop. Reduce the set of notes based on failures until
        // either a set of notes executes without failure or the set of notes cannot be
        // further reduced.
        loop {
            // Execute the candidate notes.
            tx_inputs.set_input_notes(candidate_notes.clone());
            match self.try_execute_notes(&mut tx_inputs).await {
                Ok(cycle_counts) => {
                    // A full set of successful notes has been found.
                    let successful = candidate_notes
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
                    // SAFETY: Failed note index is in bounds of the candidate notes.
                    let failed_note = candidate_notes.remove(failed_note_index);
                    failed_notes.push(FailedNote::new(failed_note, error, failed_note_cycle_count));

                    // All possible candidate combinations have been attempted.
                    if candidate_notes.is_empty() {
                        return Ok(NoteConsumptionInfo::new(Vec::new(), failed_notes));
                    }
                    // Continue and process the next set of candidates.
                },
                Err(TransactionCheckerError::EpilogueExecution { .. }) => {
                    let consumption_info = self
                        .find_largest_executable_combination(
                            candidate_notes,
                            failed_notes,
                            tx_inputs,
                        )
                        .await;
                    return Ok(consumption_info);
                },
                Err(TransactionCheckerError::PrologueExecution(err)) => {
                    return Err(NoteCheckerError::PrologueExecution(err));
                },
                Err(TransactionCheckerError::TransactionPreparation(err)) => {
                    return Err(NoteCheckerError::TransactionPreparation(err));
                },
            }
        }
    }

    /// Attempts to find the largest possible combination of notes that can execute successfully
    /// together.
    ///
    /// The notes are first grouped into [`NoteBundle`]s, and the search grows a known-good set one
    /// bundle at a time: each round appends every remaining bundle to the accepted set in turn and
    /// keeps the first bundle that lets the whole set pass, until a round adds nothing.
    ///
    /// Bundles rather than individual notes are the unit of the search because some notes are only
    /// consumable together. Growing the set one note at a time can never reach such a set: it only
    /// reaches sets that contain a consumable subset with one note fewer, and a bound
    /// (feature note, FEE_SPONSORSHIP) pair has none - neither half executes on its own.
    async fn find_largest_executable_combination(
        &self,
        remaining_notes: Vec<Note>,
        mut failed_notes: Vec<FailedNote>,
        mut tx_inputs: TransactionInputs,
    ) -> NoteConsumptionInfo {
        let mut remaining_bundles = NoteBundle::group(remaining_notes);
        let mut successful_notes: Vec<Note> = Vec::new();
        let mut successful_cycle_counts = Vec::new();
        let mut failed_note_index = BTreeMap::new();

        // Grow the accepted set until a full pass over the remaining bundles adds nothing, at which
        // point no bundle can extend it and the set is as large as this search can make it.
        loop {
            let mut extended = false;

            for idx in 0..remaining_bundles.len() {
                let bundle_notes = remaining_bundles[idx].notes().to_vec();
                let candidate_notes: Vec<Note> =
                    successful_notes.iter().chain(&bundle_notes).cloned().collect();

                tx_inputs.set_input_notes(candidate_notes.clone());
                match self.try_execute_notes(&mut tx_inputs).await {
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
                    Err(error) => {
                        // This combination failed, so the whole bundle is rejected. Blame the note
                        // the executor pointed at, when it pointed at one of the bundle's notes;
                        // an epilogue failure blames no particular note, so it falls to the
                        // bundle's first note, which is the feature note of
                        // a sponsored bundle.
                        let (blamed_idx, num_cycles) = match &error {
                            TransactionCheckerError::NoteExecution {
                                failed_note_index,
                                failed_note_cycle_count,
                                ..
                            } => (
                                failed_note_index
                                    .checked_sub(successful_notes.len())
                                    .filter(|idx| *idx < bundle_notes.len())
                                    .unwrap_or(0),
                                *failed_note_cycle_count,
                            ),
                            _ => (0, None),
                        };

                        let error = Arc::new(TransactionExecutorError::from(error));
                        let blamed_id = bundle_notes[blamed_idx].id();

                        // Record every note of the bundle (overwriting previous failures for the
                        // relevant notes), so the reported notes always account for all inputs.
                        // The notes that were not blamed are marked as bound to the one that was.
                        for (note_idx, note) in bundle_notes.iter().enumerate() {
                            let is_blamed = note_idx == blamed_idx;
                            failed_note_index.insert(
                                note.id(),
                                FailedNote {
                                    note: note.clone(),
                                    error: Arc::clone(&error),
                                    num_cycles: is_blamed.then_some(num_cycles).flatten(),
                                    bundled_with: (!is_blamed).then_some(blamed_id),
                                },
                            );
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
        NoteConsumptionInfo::new(successful, failed_notes)
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
    ) -> Result<Vec<usize>, TransactionCheckerError> {
        if tx_inputs.input_notes().is_empty() {
            return Ok(Vec::new());
        }

        let (mut host, stack_inputs, advice_inputs) =
            self.0
                .prepare_transaction(tx_inputs)
                .await
                .map_err(TransactionCheckerError::TransactionPreparation)?;

        let program = TransactionKernel::main();
        let kernel_debug_info = TransactionKernel::main_debug_info();
        let executor = EXEC::new(stack_inputs, advice_inputs, self.0.exec_options)
            .map_err(ExecutionError::advice_error_no_context)
            .map_err(map_execution_error)
            .map_err(TransactionCheckerError::PrologueExecution)?;
        let result = executor
            .with_debug_info(kernel_debug_info.as_deref().cloned().unwrap_or_default())
            .with_entrypoint_source_node(TransactionKernel::main_entrypoint_source_node())
            .execute(&program, &mut host)
            .await
            .map_err(map_execution_error);

        match result {
            Ok(execution_output) => {
                let cycle_counts = host
                    .tx_progress()
                    .note_execution()
                    .iter()
                    .map(|(_, interval)| interval.len())
                    .collect();

                // Set the advice inputs from the successful execution as advice inputs for
                // reexecution. This avoids calls to the data store (to load data lazily) that have
                // already been done as part of this execution.
                let (_, advice_map, merkle_store) = execution_output.advice.into_parts();
                let advice_inputs = AdviceInputs::from(advice_map).with_merkle_store(merkle_store);
                tx_inputs.set_advice_inputs(advice_inputs);
                Ok(cycle_counts)
            },
            Err(error) => {
                let notes = host.tx_progress().note_execution();

                // Empty notes vector means that we didn't process the notes, so an error
                // occurred.
                if notes.is_empty() {
                    return Err(TransactionCheckerError::PrologueExecution(error));
                }

                let ((_, last_note_interval), success_notes) =
                    notes.split_last().expect("notes vector is not empty because of earlier check");

                // If the interval end of the last note is specified, then an error occurred after
                // notes processing. All notes executed successfully in this case.
                if last_note_interval.end().is_some() {
                    let successful_notes_cycle_counts =
                        notes.iter().map(|(_, interval)| interval.len()).collect();
                    Err(TransactionCheckerError::EpilogueExecution {
                        error,
                        successful_notes_cycle_counts,
                    })
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

/// Handle the epilogue error during the note consumption check in the `can_consume` method.
///
/// The goal of this helper function is to handle the cases where the account couldn't consume the
/// note because of some epilogue check failure, e.g. absence of the authenticator.
fn handle_epilogue_error(epilogue_error: TransactionExecutorError) -> NoteConsumptionStatus {
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
        // TODO: apply additional checks to get the verbose error reason
        _ => NoteConsumptionStatus::UnconsumableConditions,
    }
}
