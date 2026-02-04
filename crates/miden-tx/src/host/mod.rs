mod account_delta_tracker;

use account_delta_tracker::AccountDeltaTracker;
mod storage_delta_tracker;

mod link_map;
pub use link_map::{LinkMap, MemoryViewer};

mod account_procedures;
pub use account_procedures::AccountProcedureIndexMap;

pub(crate) mod note_builder;
use miden_protocol::CoreLibrary;
use miden_protocol::vm::EventId;
use note_builder::OutputNoteBuilder;

mod kernel_process;
use kernel_process::TransactionKernelProcess;

mod script_mast_forest_store;
pub use script_mast_forest_store::ScriptMastForestStore;

mod tx_progress;

mod tx_event;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::{
    AdviceMutation,
    EventError,
    EventHandlerRegistry,
    Felt,
    MastForest,
    MastForestStore,
    ProcessState,
};
use miden_protocol::Word;
use miden_protocol::account::{
    AccountCode,
    AccountDelta,
    AccountHeader,
    AccountId,
    AccountStorageHeader,
    PartialAccount,
    StorageSlotHeader,
    StorageSlotId,
    StorageSlotName,
};
use miden_protocol::asset::Asset;
use miden_protocol::note::{NoteAttachment, NoteId, NoteMetadata, NoteRecipient};
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    OutputNote,
    OutputNotes,
    TransactionMeasurements,
    TransactionSummary,
};
use miden_protocol::vm::RowIndex;
pub(crate) use tx_event::{RecipientData, TransactionEvent, TransactionProgressEvent};
pub use tx_progress::TransactionProgress;

use crate::errors::TransactionKernelError;

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
    /// The delta is updated by event handlers.
    account_delta: AccountDeltaTracker,

    /// A map of the procedure MAST roots to the corresponding procedure indices for all the
    /// account codes involved in the transaction (for native and foreign accounts alike).
    acct_procedure_index_map: AccountProcedureIndexMap,

    /// Input notes consumed by the transaction.
    input_notes: InputNotes<InputNote>,

    /// The list of notes created while executing a transaction stored as note_ptr |-> note_builder
    /// map.
    output_notes: BTreeMap<usize, OutputNoteBuilder>,

    /// Handle the VM default events _before_ passing it to user defined ones.
    core_lib_handlers: EventHandlerRegistry,
}

impl<'store, STORE> TransactionBaseHost<'store, STORE> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TransactionBaseHost`] instance from the provided inputs.
    pub fn new(
        account: &PartialAccount,
        input_notes: InputNotes<InputNote>,
        mast_store: &'store STORE,
        scripts_mast_store: ScriptMastForestStore,
        acct_procedure_index_map: AccountProcedureIndexMap,
    ) -> Self {
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
        Self {
            mast_store,
            scripts_mast_store,
            initial_account_header: account.into(),
            initial_account_storage_header: account.storage().header().clone(),
            account_delta: AccountDeltaTracker::new(account),
            acct_procedure_index_map,
            output_notes: BTreeMap::default(),
            input_notes,
            core_lib_handlers,
        }
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
    pub fn account_delta_tracker(&self) -> &AccountDeltaTracker {
        &self.account_delta
    }

    /// Clones the inner [`AccountDeltaTracker`] and converts it into an [`AccountDelta`].
    pub fn build_account_delta(&self) -> AccountDelta {
        self.account_delta_tracker().clone().into_delta()
    }

    /// Returns the input notes consumed in this transaction.
    pub fn input_notes(&self) -> InputNotes<InputNote> {
        self.input_notes.clone()
    }

    /// Clones the inner [`OutputNoteBuilder`]s and returns the vector of created output notes that
    /// are tracked by this host.
    pub fn build_output_notes(&self) -> Vec<OutputNote> {
        self.output_notes.values().cloned().map(|builder| builder.build()).collect()
    }

    /// Consumes `self` and returns the account delta, input and output notes.
    pub fn into_parts(self) -> (AccountDelta, InputNotes<InputNote>, Vec<OutputNote>) {
        let output_notes = self.output_notes.into_values().map(|builder| builder.build()).collect();

        (self.account_delta.into_delta(), self.input_notes, output_notes)
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
        metadata: NoteMetadata,
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
        metadata: NoteMetadata,
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

    /// Handles the event if the core lib event handler registry contains a handler with the emitted
    /// event ID.
    ///
    /// Returns `Some` if the event was handled, `None` otherwise.
    pub fn handle_core_lib_events(
        &self,
        process: &ProcessState,
    ) -> Result<Option<Vec<AdviceMutation>>, EventError> {
        let event_id = EventId::from_felt(process.get_stack_item(0));
        if let Some(mutations) = self.core_lib_handlers.handle_event(event_id, process)? {
            Ok(Some(mutations))
        } else {
            Ok(None)
        }
    }

    /// Converts the provided signature into an advice mutation that pushes it onto the advice stack
    /// as a response to an `AuthRequest` event.
    pub fn on_auth_requested(&self, signature: Vec<Felt>) -> Vec<AdviceMutation> {
        vec![AdviceMutation::extend_stack(signature)]
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

    /// Sets the attachment on the output note identified by the note index.
    pub fn on_note_before_set_attachment(
        &mut self,
        note_idx: usize,
        attachment: NoteAttachment,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        let note_builder = self.output_notes.get_mut(&note_idx).ok_or_else(|| {
            TransactionKernelError::other(format!("failed to find output note {note_idx}"))
        })?;

        note_builder.set_attachment(attachment);

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
        Ok(vec![AdviceMutation::extend_stack([Felt::from(proc_idx)])])
    }

    /// Handles the increment nonce event by incrementing the nonce delta by one.
    pub fn on_account_after_increment_nonce(
        &mut self,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        if self.account_delta.was_nonce_incremented() {
            return Err(TransactionKernelError::NonceCanOnlyIncrementOnce);
        }

        self.account_delta.increment_nonce();

        Ok(Vec::new())
    }

    // ACCOUNT STORAGE UPDATE HANDLERS
    // --------------------------------------------------------------------------------------------

    /// Tracks the insertion of an item in the account delta.
    pub fn on_account_storage_after_set_item(
        &mut self,
        slot_name: StorageSlotName,
        new_value: Word,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        self.account_delta.storage().set_item(slot_name, new_value);

        Ok(Vec::new())
    }

    /// Tracks the insertion of a storage map item in the account delta.
    pub fn on_account_storage_after_set_map_item(
        &mut self,
        slot_name: StorageSlotName,
        key: Word,
        old_map_value: Word,
        new_map_value: Word,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        self.account_delta
            .storage()
            .set_map_item(slot_name, key, old_map_value, new_map_value);

        Ok(Vec::new())
    }

    // ACCOUNT VAULT UPDATE HANDLERS
    // --------------------------------------------------------------------------------------------

    /// Tracks the addition of an asset to the account vault in the account delta.
    pub fn on_account_vault_after_add_asset(
        &mut self,
        asset: Asset,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        self.account_delta
            .vault_delta_mut()
            .add_asset(asset)
            .map_err(TransactionKernelError::AccountDeltaAddAssetFailed)?;

        Ok(Vec::new())
    }

    /// Tracks the removal of an asset from the account vault in the account delta.
    pub fn on_account_vault_after_remove_asset(
        &mut self,
        asset: Asset,
    ) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
        self.account_delta
            .vault_delta_mut()
            .remove_asset(asset)
            .map_err(TransactionKernelError::AccountDeltaRemoveAssetFailed)?;

        Ok(Vec::new())
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Builds a [`TransactionSummary`] from the current host's state and validates it against the
    /// provided commitments.
    pub(crate) fn build_tx_summary(
        &self,
        salt: Word,
        output_notes_commitment: Word,
        input_notes_commitment: Word,
        account_delta_commitment: Word,
    ) -> Result<TransactionSummary, TransactionKernelError> {
        let account_delta = self.build_account_delta();
        let input_notes = self.input_notes();
        let output_notes_vec = self.build_output_notes();
        let output_notes = OutputNotes::new(output_notes_vec).map_err(|err| {
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

        Ok(TransactionSummary::new(account_delta, input_notes, output_notes, salt))
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
    pub fn get_mast_forest(&self, procedure_root: &Word) -> Option<Arc<MastForest>> {
        // Search in the note MAST forest store, otherwise fall back to the user-provided store
        match self.scripts_mast_store.get(procedure_root) {
            Some(forest) => Some(forest),
            None => self.mast_store.get(procedure_root),
        }
    }
}
