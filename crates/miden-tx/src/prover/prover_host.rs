use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::{
    AdviceMutation,
    BaseHost,
    EventError,
    MastForest,
    MastForestStore,
    ProcessState,
    SyncHost,
};
use miden_protocol::Word;
use miden_protocol::account::{AccountDelta, PartialAccount};
use miden_protocol::assembly::debuginfo::Location;
use miden_protocol::assembly::{SourceFile, SourceSpan};
use miden_protocol::transaction::{InputNote, InputNotes, OutputNote};

use crate::host::{RecipientData, ScriptMastForestStore, TransactionBaseHost, TransactionEvent};
use crate::{AccountProcedureIndexMap, TransactionKernelError};

/// The transaction prover host is responsible for handling [`SyncHost`] requests made by the
/// transaction kernel during proving.
pub struct TransactionProverHost<'store, STORE>
where
    STORE: MastForestStore,
{
    /// The underlying base transaction host.
    base_host: TransactionBaseHost<'store, STORE>,
}

impl<'store, STORE> TransactionProverHost<'store, STORE>
where
    STORE: MastForestStore,
{
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TransactionProverHost`] instance from the provided inputs.
    pub fn new(
        account: &PartialAccount,
        input_notes: InputNotes<InputNote>,
        mast_store: &'store STORE,
        scripts_mast_store: ScriptMastForestStore,
        acct_procedure_index_map: AccountProcedureIndexMap,
    ) -> Self {
        let base_host = TransactionBaseHost::new(
            account,
            input_notes,
            mast_store,
            scripts_mast_store,
            acct_procedure_index_map,
        );

        Self { base_host }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Consumes `self` and returns the account delta, input and output notes.
    pub fn into_parts(self) -> (AccountDelta, InputNotes<InputNote>, Vec<OutputNote>) {
        self.base_host.into_parts()
    }
}

// HOST IMPLEMENTATION
// ================================================================================================

impl<STORE> BaseHost for TransactionProverHost<'_, STORE>
where
    STORE: MastForestStore,
{
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        // For the prover, we assume that the transaction witness is a successfully executed
        // transaction and so there should be no need to provide the actual source manager, as it
        // is only used to improve error message quality which we shouldn't run into here.
        (SourceSpan::UNKNOWN, None)
    }
}

impl<STORE> SyncHost for TransactionProverHost<'_, STORE>
where
    STORE: MastForestStore,
{
    fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>> {
        self.base_host.get_mast_forest(node_digest)
    }

    fn on_event(&mut self, process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
        if let Some(advice_mutations) = self.base_host.handle_core_lib_events(process)? {
            return Ok(advice_mutations);
        }

        let tx_event =
            TransactionEvent::extract(&self.base_host, process).map_err(EventError::from)?;

        // None means the event ID does not need to be handled.
        let Some(tx_event) = tx_event else {
            return Ok(Vec::new());
        };

        let result = match tx_event {
            // Foreign account data and witnesses should be in the advice provider at
            // proving time, so there is nothing to do.
            TransactionEvent::AccountBeforeForeignLoad { .. } => Ok(Vec::new()),

            TransactionEvent::AccountVaultAfterRemoveAsset { asset } => {
                self.base_host.on_account_vault_after_remove_asset(asset)
            },
            TransactionEvent::AccountVaultAfterAddAsset { asset } => {
                self.base_host.on_account_vault_after_add_asset(asset)
            },

            TransactionEvent::AccountStorageAfterSetItem { slot_name, new_value } => {
                self.base_host.on_account_storage_after_set_item(slot_name, new_value)
            },

            TransactionEvent::AccountStorageAfterSetMapItem {
                slot_name,
                key,
                old_value,
                new_value,
            } => self
                .base_host
                .on_account_storage_after_set_map_item(slot_name, key, old_value, new_value),

            // Access witnesses should be in the advice provider at proving time.
            TransactionEvent::AccountVaultBeforeAssetAccess { .. } => Ok(Vec::new()),
            TransactionEvent::AccountStorageBeforeMapItemAccess { .. } => Ok(Vec::new()),

            TransactionEvent::AccountAfterIncrementNonce => {
                self.base_host.on_account_after_increment_nonce()
            },

            TransactionEvent::AccountPushProcedureIndex { code_commitment, procedure_root } => {
                self.base_host.on_account_push_procedure_index(code_commitment, procedure_root)
            },

            TransactionEvent::NoteBeforeCreated { note_idx, metadata, recipient_data } => {
                match recipient_data {
                    RecipientData::Digest(recipient_digest) => self
                        .base_host
                        .output_note_from_recipient_digest(note_idx, metadata, recipient_digest),
                    RecipientData::Recipient(note_recipient) => self
                        .base_host
                        .output_note_from_recipient(note_idx, metadata, note_recipient),
                    RecipientData::ScriptMissing { .. } => Err(TransactionKernelError::other(
                        "note script should be in the advice provider at proving time",
                    )),
                }
            },

            TransactionEvent::NoteBeforeAddAsset { note_idx, asset } => {
                self.base_host.on_note_before_add_asset(note_idx, asset).map(|_| Vec::new())
            },

            TransactionEvent::NoteBeforeSetAttachment { note_idx, attachment } => self
                .base_host
                .on_note_before_set_attachment(note_idx, attachment)
                .map(|_| Vec::new()),

            TransactionEvent::AuthRequest { signature, .. } => {
                if let Some(signature) = signature {
                    Ok(self.base_host.on_auth_requested(signature))
                } else {
                    Err(TransactionKernelError::other(
                        "signatures should be in the advice provider at proving time",
                    ))
                }
            },

            TransactionEvent::Unauthorized { tx_summary } => {
                Err(TransactionKernelError::other(format!(
                    "unexpected unauthorized event during proving with tx summary commitment {}",
                    tx_summary.to_commitment()
                )))
            },

            // We don't track enough information to handle this event. Since this just improves
            // error messages for users and the error should not be relevant during proving, we
            // ignore it.
            TransactionEvent::EpilogueBeforeTxFeeRemovedFromAccount { .. } => Ok(Vec::new()),

            TransactionEvent::LinkMapSet { advice_mutation } => Ok(advice_mutation),
            TransactionEvent::LinkMapGet { advice_mutation } => Ok(advice_mutation),

            // We do not track tx progress during proving.
            TransactionEvent::Progress(_) => Ok(Vec::new()),
        };

        result.map_err(EventError::from)
    }
}
