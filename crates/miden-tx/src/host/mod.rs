mod account_update_tracker;
use account_update_tracker::AccountUpdateTracker;

mod storage_patch_tracker;

mod vault_update_tracker;

mod link_map;
pub use link_map::{LinkMap, MemoryViewer};

mod account_procedures;
pub use account_procedures::AccountProcedureIndexMap;

mod code_patch;
use code_patch::{CodePatchTracker, CodeRootVerification, referenced_procedures};

pub(crate) mod note_builder;
use miden_protocol::CoreLibrary;
use miden_protocol::transaction::{
    TransactionEventId,
    TransactionLog,
    TransactionLogError,
    TransactionLogs,
};
use miden_protocol::vm::{AdviceMap, EventId, EventName};
use note_builder::OutputNoteBuilder;

mod kernel_process;
use kernel_process::TransactionKernelProcess;

mod script_mast_forest_store;
pub use script_mast_forest_store::ScriptMastForestStore;

mod tx_progress;

mod tx_event;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::advice::AdviceMutation;
use miden_processor::event::{EventError, EventHandlerRegistry};
use miden_processor::mast::{MastForest, MastNodeId};
use miden_processor::trace::RowIndex;
use miden_processor::{Felt, LoadedMastForest, MastForestStore, ProcessorState};
use miden_protocol::Word;
use miden_protocol::account::{
    AccountCode,
    AccountCodeUpgrade,
    AccountDelta,
    AccountHeader,
    AccountId,
    AccountPatch,
    AccountStorageHeader,
    AssetDelta,
    PartialAccount,
    StorageMapKey,
    StorageSlotHeader,
    StorageSlotId,
    StorageSlotName,
};
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;
use miden_protocol::block::code_tree::{CodeWitness, CodeWitnessRequest, PartialCodeTree};
use miden_protocol::code::ProcedureRoot;
use miden_protocol::note::{
    NoteAttachment,
    NoteId,
    NoteRecipient,
    NoteScript,
    PartialNoteMetadata,
};
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    RawOutputNote,
    RawOutputNotes,
    TransactionMeasurements,
    TransactionSummary,
    TransactionSummaryMetadata,
    TransactionSummaryUserParams,
};
pub(crate) use tx_event::{
    RecipientData,
    TransactionEvent,
    TransactionProgressEvent,
    TxSummaryOrSignature,
};
pub use tx_progress::TransactionProgress;

use crate::errors::TransactionKernelError;
use crate::host::tx_event::AssetPatch;

// TRANSACTION BASE HOST
// ================================================================================================

/// The base transaction host that implements shared behavior of all transaction host
/// implementations.
pub struct TransactionBaseHost<'store, STORE> {
    /// MAST store which contains the code required to execute account code functions.
    mast_store: &'store STORE,

    /// MAST store which contains the forests of all scripts involved in the transaction. These
    /// include input note scripts and the transaction script, but not account code.
    scripts_mast_store: ScriptMastForestStore,

    /// The header of the account at the beginning of transaction execution.
    initial_account_header: AccountHeader,

    /// The storage header of the native account at the beginning of transaction execution.
    initial_account_storage_header: AccountStorageHeader,

    /// Account state changes accumulated during transaction execution.
    ///
    /// The tracker is updated by event handlers.
    update_tracker: AccountUpdateTracker,

    /// A map of the procedure MAST roots to the corresponding procedure indices for all the
    /// account codes involved in the transaction (for native and foreign accounts alike).
    acct_procedure_index_map: AccountProcedureIndexMap,

    /// Input notes consumed by the transaction.
    input_notes: InputNotes<InputNote>,

    /// The commitments of the blocks the transaction authenticates, keyed by block number.
    block_commitments: BTreeMap<BlockNumber, Word>,

    /// The list of notes created while executing a transaction stored as note_ptr |-> note_builder
    /// map.
    output_notes: BTreeMap<usize, OutputNoteBuilder>,
    logs: Vec<TransactionLog>,

    /// The procedure roots of the code of the native account if it is new and public. These are
    /// top-level procedure roots of the code patch.
    new_public_account_procedures: Vec<ProcedureRoot>,

    /// The recipients of the output notes that the transaction is expected to create.
    expected_output_recipients: Vec<NoteRecipient>,

    /// Answers the code witness verification requests of the kernel.
    code_patch: CodePatchTracker,

    /// Handle the VM default events _before_ passing it to user defined ones.
    core_lib_handlers: EventHandlerRegistry,
}

impl<'store, STORE> TransactionBaseHost<'store, STORE> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TransactionBaseHost`] instance from the provided inputs.
    ///
    /// # Errors
    ///
    /// Returns an error if the [`AccountUpdateTracker`] cannot be created for the account.
    pub fn new(
        account: &PartialAccount,
        input_notes: InputNotes<InputNote>,
        block_commitments: BTreeMap<BlockNumber, Word>,
        mast_store: &'store STORE,
        scripts_mast_store: ScriptMastForestStore,
        acct_procedure_index_map: AccountProcedureIndexMap,
        code_tree: PartialCodeTree,
        expected_output_recipients: &[NoteRecipient],
    ) -> Result<Self, TransactionKernelError> {
        let expected_output_recipients = expected_output_recipients.to_vec();

        let new_public_account_procedures = if account.is_new() && account.id().is_public() {
            account.code().procedure_roots().map(ProcedureRoot::from_raw).collect()
        } else {
            Vec::new()
        };

        let core_lib_handlers = {
            let mut registry = EventHandlerRegistry::new();

            let core_lib = CoreLibrary::default();
            for (event_id, handler) in core_lib.handlers() {
                registry
                    .register(event_id, handler)
                    .expect("There are no duplicates in the core library handlers");
            }
            registry
        };
        Ok(Self {
            mast_store,
            scripts_mast_store,
            initial_account_header: account.into(),
            initial_account_storage_header: account.storage().header().clone(),
            update_tracker: AccountUpdateTracker::new(account)?,
            acct_procedure_index_map,
            output_notes: BTreeMap::default(),
            logs: Vec::new(),
            input_notes,
            block_commitments,
            new_public_account_procedures,
            expected_output_recipients,
            code_patch: CodePatchTracker::new(code_tree),
            core_lib_handlers,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the ID of the native account.
    pub fn native_account_id(&self) -> AccountId {
        self.initial_account_header().id()
    }

    /// Returns a reference to the initial account header of the native account, which represents
    /// the state at the beginning of the transaction.
    pub fn initial_account_header(&self) -> &AccountHeader {
        &self.initial_account_header
    }

    /// Returns a reference to the initial storage header of the native account, which represents
    /// the state at the beginning of the transaction.
    pub fn initial_account_storage_header(&self) -> &AccountStorageHeader {
        &self.initial_account_storage_header
    }

    /// Returns the initial storage slot of the native account identified by [`StorageSlotId`],
    /// which represents the state at the beginning of the transaction.
    pub fn initial_account_storage_slot(
        &self,
        slot_id: StorageSlotId,
    ) -> Result<&StorageSlotHeader, TransactionKernelError> {
        self.initial_account_storage_header()
            .find_slot_header_by_id(slot_id)
            .ok_or_else(|| {
                TransactionKernelError::other(format!(
                    "failed to find storage map with name {slot_id} in storage header"
                ))
            })
    }

    /// Returns a reference to the account delta tracker of this transaction host.
    pub fn account_update_tracker(&self) -> &AccountUpdateTracker {
        &self.update_tracker
    }

    /// Clones the inner [`AccountUpdateTracker`] and converts it into an [`AccountDelta`].
    pub fn build_account_delta(&self) -> AccountDelta {
        self.account_update_tracker().clone().into_delta()
    }

    /// Returns the input notes consumed in this transaction.
    pub fn input_notes(&self) -> InputNotes<InputNote> {
        self.input_notes.clone()
    }

    /// Clones the inner [`OutputNoteBuilder`]s and returns the vector of created output notes that
    /// are tracked by this host.
    pub fn build_output_notes(&self) -> Vec<RawOutputNote> {
        self.output_notes.values().cloned().map(|builder| builder.build()).collect()
    }

    /// Consumes `self` and returns the account patch, input and output notes, and transaction logs.
    pub fn into_parts(
        self,
    ) -> (AccountPatch, InputNotes<InputNote>, Vec<RawOutputNote>, TransactionLogs) {
        let output_notes = self.output_notes.into_values().map(|builder| builder.build()).collect();

        (
            self.update_tracker.into_patch(),
            self.input_notes,
            output_notes,
            TransactionLogs::new(self.logs)
                .expect("host validates transaction log limits before appending"),
        )
    }

    /// Returns the complete transaction logs collected during execution.
    pub fn logs(&self) -> &[TransactionLog] {
        &self.logs
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts an output note builder at the specified index.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a note builder already exists at the given index.
    pub(super) fn insert_output_note_builder(
        &mut self,
        note_idx: usize,
        note_builder: OutputNoteBuilder,
    ) -> Result<(), TransactionKernelError> {
        if self.output_notes.contains_key(&note_idx) {
            return Err(TransactionKernelError::other(format!(
                "Attempted to create note builder for note index {} twice",
                note_idx
            )));
        }
        self.output_notes.insert(note_idx, note_builder);
        Ok(())
    }

    /// Inserts an [`OutputNoteBuilder`] into the output notes created from only the recipient
    /// digest.
    pub(super) fn output_note_from_recipient_digest(
        &mut self,
        note_idx: usize,
        metadata: PartialNoteMetadata,
        recipient_digest: Word,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        let note_builder = OutputNoteBuilder::from_recipient_digest(metadata, recipient_digest)?;
        self.insert_output_note_builder(note_idx, note_builder)?;

        Ok(Vec::new())
    }

    /// Inserts an [`OutputNoteBuilder`] into the output notes created from the full
    /// [`NoteRecipient`] object.
    pub(super) fn output_note_from_recipient(
        &mut self,
        note_idx: usize,
        metadata: PartialNoteMetadata,
        recipient: NoteRecipient,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        let note_builder = OutputNoteBuilder::from_recipient(metadata, recipient);
        self.insert_output_note_builder(note_idx, note_builder)?;

        Ok(Vec::new())
    }

    /// Loads the provided [`AccountCode`] into the host's [`AccountProcedureIndexMap`].
    pub fn load_foreign_account_code(&mut self, account_code: &AccountCode) {
        self.acct_procedure_index_map.insert_code(account_code)
    }

    // EVENT HANDLERS
    // --------------------------------------------------------------------------------------------

    /// Appends a transaction log emitted by the kernel.
    pub(crate) fn on_log_added(
        &mut self,
        log: TransactionLog,
    ) -> Result<(), TransactionKernelError> {
        let num_logs = self.logs.len() + 1;
        if num_logs > TransactionLogs::MAX_COUNT {
            return Err(TransactionKernelError::other_with_source(
                "invalid transaction logs",
                TransactionLogError::TooManyLogs(num_logs),
            ));
        }
        let num_words = self.logs().iter().map(TransactionLog::num_content_words).sum::<usize>()
            + log.num_content_words();
        if num_words > TransactionLogs::MAX_NUM_WORDS {
            return Err(TransactionKernelError::other_with_source(
                "invalid transaction logs",
                TransactionLogError::TooManyTotalContentWords(num_words),
            ));
        }
        self.logs.push(log);
        Ok(())
    }

    /// Pushes an input note's index and a presence flag onto the advice stack.
    ///
    /// When the note is absent, index zero is returned with a cleared presence flag. The index is
    /// an unauthenticated hint and must be validated by the VM before it is used.
    pub fn on_input_note_index_lookup(&self, note_id: NoteId) -> Vec<AdviceMutation> {
        let note_idx =
            self.input_notes.iter().position(|input_note| input_note.id() == note_id).map(
                |note_idx| {
                    u16::try_from(note_idx).expect("maximum number of input notes fits in u16")
                },
            );

        let is_found = Felt::from(note_idx.is_some() as u8);
        let note_idx = Felt::from(note_idx.unwrap_or(0));

        vec![AdviceMutation::extend_advice_stack_with([note_idx, is_found])]
    }

    /// Handles the event if the core lib event handler registry contains a handler with the emitted
    /// event ID.
    ///
    /// Returns `Some` if the event was handled, `None` otherwise.
    pub fn handle_core_lib_events(
        &self,
        process: &ProcessorState,
    ) -> Result<Option<Vec<AdviceMutation>>, EventError> {
        let event_id = EventId::from_felt(process.get_stack_item(0));
        if let Some(mutations) = self.core_lib_handlers.handle_event(event_id, process)? {
            Ok(Some(mutations))
        } else {
            Ok(None)
        }
    }

    /// Resolves an [`EventId`] to its corresponding [`EventName`], if known.
    ///
    /// First checks if the event is a core library event, then checks if it is a transaction
    /// kernel event.
    pub fn resolve_event(&self, event_id: EventId) -> Option<&EventName> {
        if let Some(name) = self.core_lib_handlers.resolve_event(event_id) {
            return Some(name);
        }

        TransactionEventId::try_from(event_id)
            .ok()
            .map(|event_id| event_id.event_name())
    }

    /// Converts the provided signature into an advice mutation that pushes it onto the advice stack
    /// as a response to an `AuthRequest` event.
    pub fn on_auth_requested(&self, signature: Vec<Felt>) -> Vec<AdviceMutation> {
        vec![AdviceMutation::extend_advice_stack_with(signature)]
    }

    /// Adds an asset to the output note identified by the note index.
    pub fn on_note_before_add_asset(
        &mut self,
        note_idx: usize,
        asset: Asset,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        let note_builder = self.output_notes.get_mut(&note_idx).ok_or_else(|| {
            TransactionKernelError::other(format!("failed to find output note {note_idx}"))
        })?;

        note_builder.add_asset(asset)?;

        Ok(Vec::new())
    }

    /// Appends an attachment to the output note identified by the note index.
    pub fn on_note_before_add_attachment(
        &mut self,
        note_idx: usize,
        attachment: NoteAttachment,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        let note_builder = self.output_notes.get_mut(&note_idx).ok_or_else(|| {
            TransactionKernelError::other(format!("failed to find output note {note_idx}"))
        })?;

        note_builder.add_attachment(attachment)?;

        Ok(Vec::new())
    }

    /// Pushes the index of the procedure root in the code identified by the commitment onto the
    /// advice stack.
    pub fn on_account_push_procedure_index(
        &mut self,
        code_commitment: Word,
        procedure_root: Word,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        let proc_idx =
            self.acct_procedure_index_map.get_proc_index(code_commitment, procedure_root)?;
        Ok(vec![AdviceMutation::extend_advice_stack_with([Felt::from(proc_idx)])])
    }

    /// Handles the increment nonce event by incrementing the nonce delta by one.
    pub fn on_account_after_increment_nonce(
        &mut self,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        if self.update_tracker.was_nonce_incremented() {
            return Err(TransactionKernelError::NonceCanOnlyIncrementOnce);
        }

        self.update_tracker.increment_nonce();

        Ok(Vec::new())
    }

    /// Handles the before code upgrade event by recording the new code in the update tracker and
    /// providing its procedures to the kernel through the advice map.
    ///
    /// The `code_upgrade` is taken from the advice map entry under
    /// [`AccountCodeUpgrade::advice_map_key`] when the event is extracted.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the commitment of `code_upgrade` does not match `new_code_commitment`.
    /// - the update tracker rejects the upgrade.
    pub fn on_account_before_code_upgrade(
        &mut self,
        new_code_commitment: Word,
        code_upgrade: AccountCodeUpgrade,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        if code_upgrade.commitment() != new_code_commitment {
            return Err(TransactionKernelError::AccountCodeUpgradeCommitmentMismatch {
                expected: new_code_commitment,
                actual: code_upgrade.commitment(),
            });
        }

        let procedures = code_upgrade.code().to_elements();
        self.update_tracker.record_code_upgrade(code_upgrade)?;

        Ok(vec![AdviceMutation::extend_map(AdviceMap::from_iter([(
            new_code_commitment,
            procedures,
        )]))])
    }

    // ACCOUNT STORAGE UPDATE HANDLERS
    // --------------------------------------------------------------------------------------------

    /// Tracks the insertion of an item in the account delta.
    pub fn on_account_storage_after_set_item(
        &mut self,
        slot_name: StorageSlotName,
        new_value: Word,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        self.update_tracker.storage().set_item(slot_name, new_value)?;

        Ok(Vec::new())
    }

    /// Tracks the insertion of a storage map item in the account delta.
    pub fn on_account_storage_after_set_map_item(
        &mut self,
        slot_name: StorageSlotName,
        key: StorageMapKey,
        old_map_value: Word,
        new_map_value: Word,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        self.update_tracker
            .storage()
            .set_map_item(slot_name, key, old_map_value, new_map_value)?;

        Ok(Vec::new())
    }

    // ACCOUNT VAULT UPDATE HANDLERS
    // --------------------------------------------------------------------------------------------

    /// Resets the accumulating vault delta before the kernel iterates the asset delta.
    pub fn on_account_before_asset_delta_computation(
        &mut self,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        self.update_tracker.reset_vault_delta();

        Ok(Vec::new())
    }

    /// Tracks the computation of an asset delta for the account delta.
    ///
    /// The kernel iterates its asset delta map once per computation, so this is called at most once
    /// per asset ID, and only after
    /// [`Self::on_account_before_asset_delta_computation`] has reset the accumulated delta.
    pub fn on_account_on_asset_delta_computation(
        &mut self,
        delta: AssetDelta,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        self.update_tracker.add_asset_delta(delta);

        Ok(Vec::new())
    }

    /// Tracks the update of an asset from the account vault in the account patch.
    pub fn on_account_vault_after_remove_asset(
        &mut self,
        patch: AssetPatch,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        self.update_tracker.update_asset_patch(patch)?;

        Ok(Vec::new())
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Builds a [`TransactionSummary`] from the current host's state and validates it against the
    /// provided commitments.
    pub(crate) fn build_tx_summary(
        &self,
        account_delta_commitment: Word,
        input_notes_commitment: Word,
        output_notes_commitment: Word,
        metadata: TransactionSummaryMetadata,
        block_commitment: Word,
        user_params: TransactionSummaryUserParams,
        logs: TransactionLogs,
    ) -> Result<TransactionSummary, TransactionKernelError> {
        let block_number = metadata.block_number();
        let account_delta = self.build_account_delta();
        let input_notes = self.input_notes();
        let output_notes_vec = self.build_output_notes();
        let output_notes = RawOutputNotes::new(output_notes_vec).map_err(|err| {
            TransactionKernelError::TransactionSummaryConstructionFailed(Box::new(err))
        })?;

        // Validate commitments
        let actual_account_delta_commitment = account_delta.to_commitment();
        if actual_account_delta_commitment != account_delta_commitment {
            return Err(TransactionKernelError::TransactionSummaryCommitmentMismatch(
                format!(
                    "expected account delta commitment to be {actual_account_delta_commitment} but was {account_delta_commitment}"
                )
                .into(),
            ));
        }

        let actual_input_notes_commitment = input_notes.commitment();
        if actual_input_notes_commitment != input_notes_commitment {
            return Err(TransactionKernelError::TransactionSummaryCommitmentMismatch(
                format!(
                    "expected input notes commitment to be {actual_input_notes_commitment} but was {input_notes_commitment}"
                )
                .into(),
            ));
        }

        let actual_output_notes_commitment = output_notes.commitment();
        if actual_output_notes_commitment != output_notes_commitment {
            return Err(TransactionKernelError::TransactionSummaryCommitmentMismatch(
                format!(
                    "expected output notes commitment to be {actual_output_notes_commitment} but was {output_notes_commitment}"
                )
                .into(),
            ));
        }

        let expected_block_commitment = self
            .block_commitments
            .get(&block_number)
            .ok_or(TransactionKernelError::TransactionSummaryUnknownBlockNumber(block_number))?;
        if *expected_block_commitment != block_commitment {
            return Err(TransactionKernelError::TransactionSummaryCommitmentMismatch(
                format!(
                    "expected block commitment to be {expected_block_commitment} but was {block_commitment}"
                )
                .into(),
            ));
        }

        Ok(TransactionSummary::new(
            account_delta,
            input_notes,
            output_notes,
            block_number,
            block_commitment,
            metadata.expiration_delta(),
            user_params,
            logs,
        ))
    }

    /// Returns the underlying store of the base host.
    pub fn store(&self) -> &'store STORE {
        self.mast_store
    }
}

impl<'store, STORE> TransactionBaseHost<'store, STORE>
where
    STORE: MastForestStore,
{
    /// Returns the [`MastForest`] that contains the procedure with the given `procedure_root`.
    pub fn get_mast_forest(&self, procedure_root: &Word) -> Option<LoadedMastForest> {
        // Search in the note MAST forest store, otherwise fall back to the user-provided store
        match self.scripts_mast_store.get(procedure_root) {
            Some(forest) => Some(forest),
            None => self.mast_store.get(procedure_root),
        }
    }

    // CODE WITNESSES
    // --------------------------------------------------------------------------------------------

    /// Returns the code tree of the reference block that tracks the available code witnesses.
    pub fn code_tree(&self) -> &PartialCodeTree {
        self.code_patch.code_tree()
    }

    /// Returns `true` if the code witness of the procedure root is available.
    pub fn has_code_witness(&self, procedure_root: &ProcedureRoot) -> bool {
        self.code_patch.has_witness(procedure_root)
    }

    /// Adds the provided code witnesses to the available code witnesses.
    ///
    /// # Errors
    ///
    /// Returns an error if a witness does not fit the code tree of the reference block.
    pub fn add_code_witnesses(
        &mut self,
        witnesses: impl IntoIterator<Item = CodeWitness>,
    ) -> Result<(), TransactionKernelError> {
        self.code_patch.add_witnesses(witnesses)
    }

    /// Returns `true` if the verification of the top-level procedure root needs a code witness
    /// that is not available.
    ///
    /// This uses the same rule as [`Self::on_code_before_proc_root_verified`] to determine the
    /// needed witnesses, so that the witnesses that the kernel verified are sufficient to
    /// execute the transaction again.
    ///
    /// # Errors
    ///
    /// Returns an error if the presence of a procedure root cannot be determined.
    pub fn is_code_witness_missing(
        &self,
        procedure_root: ProcedureRoot,
    ) -> Result<bool, TransactionKernelError> {
        if self.code_patch.is_verified(&procedure_root) {
            return Ok(false);
        }
        if !self.has_code_witness(&procedure_root) {
            return Ok(true);
        }
        if self.code_patch.is_present(&procedure_root)? {
            return Ok(false);
        }

        // A referenced procedure without a witness is missing, so the walk does not descend into
        // it.
        let referenced_procedures = referenced_procedures(
            procedure_root,
            |root| self.resolve_procedure_mast(root),
            |root| Ok(self.has_code_witness(&root) && self.needs_referenced_procedures(root)?),
            false,
        )?;

        Ok(referenced_procedures.iter().any(|root| !self.has_code_witness(root)))
    }

    /// Returns the code witness requests for all top-level procedure roots that the host can see
    /// and whose witnesses are missing, starting with the provided procedure root.
    ///
    /// The top-level procedure roots are the procedures of a new public account and the script
    /// roots of the public output notes created so far and of the expected output notes that the
    /// transaction did not create yet, e.g. notes that the auth procedure creates. Requesting the
    /// witnesses in bulk avoids a request per root.
    ///
    /// The note type of an expected output note is unknown before the note is created, so the
    /// request can contain the script roots of private notes. The expected output notes that the
    /// transaction created before are left out, so that the data store does not learn the scripts
    /// of their private notes.
    ///
    /// Each request contains all procedures that the host can reach from the top-level root,
    /// because the host does not know yet which of them are present.
    ///
    /// # Errors
    ///
    /// Returns an error if the presence of a procedure root cannot be determined.
    pub fn code_witness_requests(
        &self,
        procedure_root: ProcedureRoot,
    ) -> Result<Vec<CodeWitnessRequest>, TransactionKernelError> {
        let note_scripts =
            self.public_output_note_scripts().chain(self.pending_expected_note_scripts());
        let top_level_roots = [procedure_root]
            .into_iter()
            .chain(self.new_public_account_procedures.iter().copied())
            .chain(
                note_scripts.map(|note_script| ProcedureRoot::from_raw(note_script.root().into())),
            );

        let mut requested_roots = BTreeSet::new();
        let mut requests = Vec::new();
        for top_level_root in top_level_roots {
            if !requested_roots.insert(top_level_root)
                || self.code_patch.is_verified(&top_level_root)
            {
                continue;
            }

            if !self.is_code_witness_missing(top_level_root)? {
                continue;
            }

            let referenced_procedures = referenced_procedures(
                top_level_root,
                |root| self.resolve_procedure_mast(root),
                |_| Ok(true),
                false,
            )?;
            requests.push(CodeWitnessRequest::new(
                top_level_root,
                referenced_procedures.into_iter().collect(),
            ));
        }

        Ok(requests)
    }

    /// Handles the verification of a top-level procedure root by the kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a code witness that the kernel needs is not available.
    /// - the MAST of an absent procedure is not available.
    pub fn on_code_before_proc_root_verified(
        &mut self,
        procedure_root: ProcedureRoot,
    ) -> Result<CodeRootVerification, TransactionKernelError> {
        let referenced_procedures =
            if self.code_patch.needs_referenced_procedures(&procedure_root)? {
                referenced_procedures(
                    procedure_root,
                    |root| self.resolve_procedure_mast(root),
                    |root| self.needs_referenced_procedures(root),
                    true,
                )?
            } else {
                Vec::new()
            };

        self.code_patch.verify_top_level_root(procedure_root, referenced_procedures)
    }

    /// Returns `true` if the walk over the referenced procedures descends into the code of the
    /// procedure root.
    ///
    /// The code of a present procedure is already registered, and the procedures that the code of
    /// a verified procedure references were verified with it, so the walk stops at both.
    fn needs_referenced_procedures(
        &self,
        procedure_root: ProcedureRoot,
    ) -> Result<bool, TransactionKernelError> {
        self.code_patch.needs_referenced_procedures(&procedure_root)
    }

    /// Returns the scripts of the expected output notes that the transaction did not create yet.
    fn pending_expected_note_scripts(&self) -> impl Iterator<Item = &NoteScript> {
        let created_recipients = self
            .output_notes
            .values()
            .map(OutputNoteBuilder::recipient_digest)
            .collect::<BTreeSet<_>>();

        self.expected_output_recipients
            .iter()
            .filter(move |recipient| !created_recipients.contains(&recipient.digest()))
            .map(NoteRecipient::script)
    }

    /// Returns the scripts of the public output notes created so far.
    fn public_output_note_scripts(&self) -> impl Iterator<Item = &NoteScript> {
        self.output_notes
            .values()
            .filter(|note_builder| note_builder.metadata().is_public())
            .filter_map(|note_builder| note_builder.recipient().map(NoteRecipient::script))
    }

    /// Returns the MAST forest and the node of the procedure with the provided root, if
    /// available.
    ///
    /// The MAST is searched in the MAST stores and the scripts of the output notes and the
    /// expected output notes. A node that only references the procedure is not its MAST, e.g. the
    /// entrypoint of a note script that references a library procedure.
    fn resolve_procedure_mast(
        &self,
        procedure_root: ProcedureRoot,
    ) -> Option<(Arc<MastForest>, MastNodeId)> {
        let procedure_root = procedure_root.as_word();
        let from_store = self.get_mast_forest(&procedure_root).and_then(|loaded_forest| {
            let mast_forest = loaded_forest.mast_forest().clone();
            mast_forest
                .find_procedure_root(procedure_root)
                .map(|node_id| (mast_forest, node_id))
        });
        let from_note_scripts = self
            .output_notes
            .values()
            .filter_map(|note_builder| note_builder.recipient().map(NoteRecipient::script))
            .chain(self.expected_output_recipients.iter().map(NoteRecipient::script))
            .filter(|note_script| Word::from(note_script.root()) == procedure_root)
            .map(|note_script| (note_script.mast(), note_script.entrypoint()));

        from_store
            .into_iter()
            .chain(from_note_scripts)
            .find(|(mast_forest, node_id)| !mast_forest[*node_id].is_external())
    }
}
