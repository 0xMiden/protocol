use core::fmt;

use miden_core::EventId;

use crate::errors::TransactionEventError;

// CONSTANTS
// ================================================================================================
// Include the generated event constants
include!(concat!(env!("OUT_DIR"), "/assets/transaction_events.rs"));

// TRANSACTION EVENT
// ================================================================================================

/// Events which may be emitted by a transaction kernel.
///
/// The events are emitted via the `emit.<event_id>` instruction. The event ID is a Felt
/// derived from the `EventId` string which is used to identify the event type. Events emitted
/// by the transaction kernel are in the `miden` namespace.
#[repr(u64)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TransactionEventId {
    AccountBeforeForeignLoad = ACCOUNT_BEFORE_FOREIGN_LOAD,

    AccountVaultBeforeAddAsset = ACCOUNT_VAULT_BEFORE_ADD_ASSET,
    AccountVaultAfterAddAsset = ACCOUNT_VAULT_AFTER_ADD_ASSET,

    AccountVaultBeforeRemoveAsset = ACCOUNT_VAULT_BEFORE_REMOVE_ASSET,
    AccountVaultAfterRemoveAsset = ACCOUNT_VAULT_AFTER_REMOVE_ASSET,

    AccountVaultBeforeGetAsset = ACCOUNT_VAULT_BEFORE_GET_ASSET,

    AccountStorageBeforeSetItem = ACCOUNT_STORAGE_BEFORE_SET_ITEM,
    AccountStorageAfterSetItem = ACCOUNT_STORAGE_AFTER_SET_ITEM,

    AccountStorageBeforeGetMapItem = ACCOUNT_STORAGE_BEFORE_GET_MAP_ITEM,

    AccountStorageBeforeSetMapItem = ACCOUNT_STORAGE_BEFORE_SET_MAP_ITEM,
    AccountStorageAfterSetMapItem = ACCOUNT_STORAGE_AFTER_SET_MAP_ITEM,

    AccountBeforeIncrementNonce = ACCOUNT_BEFORE_INCREMENT_NONCE,
    AccountAfterIncrementNonce = ACCOUNT_AFTER_INCREMENT_NONCE,

    AccountPushProcedureIndex = ACCOUNT_PUSH_PROCEDURE_INDEX,

    NoteBeforeCreated = NOTE_BEFORE_CREATED,
    NoteAfterCreated = NOTE_AFTER_CREATED,

    NoteBeforeAddAsset = NOTE_BEFORE_ADD_ASSET,
    NoteAfterAddAsset = NOTE_AFTER_ADD_ASSET,

    NoteBeforeSetAttachment = NOTE_BEFORE_SET_ATTACHMENT,

    AuthRequest = AUTH_REQUEST,

    PrologueStart = PROLOGUE_START,
    PrologueEnd = PROLOGUE_END,

    NotesProcessingStart = NOTES_PROCESSING_START,
    NotesProcessingEnd = NOTES_PROCESSING_END,

    NoteExecutionStart = NOTE_EXECUTION_START,
    NoteExecutionEnd = NOTE_EXECUTION_END,

    TxScriptProcessingStart = TX_SCRIPT_PROCESSING_START,
    TxScriptProcessingEnd = TX_SCRIPT_PROCESSING_END,

    EpilogueStart = EPILOGUE_START,
    EpilogueEnd = EPILOGUE_END,

    EpilogueAuthProcStart = EPILOGUE_AUTH_PROC_START,
    EpilogueAuthProcEnd = EPILOGUE_AUTH_PROC_END,

    EpilogueAfterTxCyclesObtained = EPILOGUE_AFTER_TX_CYCLES_OBTAINED,
    EpilogueBeforeTxFeeRemovedFromAccount = EPILOGUE_BEFORE_TX_FEE_REMOVED_FROM_ACCOUNT,

    LinkMapSet = LINK_MAP_SET,
    LinkMapGet = LINK_MAP_GET,

    Unauthorized = AUTH_UNAUTHORIZED,
}

impl TransactionEventId {
    /// Returns `true` if the event is privileged, i.e. it is only allowed to be emitted from the
    /// root context of the VM, which is where the transaction kernel executes.
    pub fn is_privileged(&self) -> bool {
        let is_unprivileged = matches!(self, Self::AuthRequest | Self::Unauthorized);
        !is_unprivileged
    }

    /// Returns the [`EventId`] of the transaction event.
    pub fn event_id(&self) -> EventId {
        EventId::from_u64(self.clone() as u64)
    }
}

impl fmt::Display for TransactionEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl TryFrom<EventId> for TransactionEventId {
    type Error = TransactionEventError;

    fn try_from(event_id: EventId) -> Result<Self, Self::Error> {
        let raw = event_id.as_felt().as_int();

        let name = EVENT_NAME_LUT.get(&raw).copied();

        match raw {
            ACCOUNT_BEFORE_FOREIGN_LOAD => Ok(TransactionEventId::AccountBeforeForeignLoad),

            ACCOUNT_VAULT_BEFORE_ADD_ASSET => Ok(TransactionEventId::AccountVaultBeforeAddAsset),
            ACCOUNT_VAULT_AFTER_ADD_ASSET => Ok(TransactionEventId::AccountVaultAfterAddAsset),

            ACCOUNT_VAULT_BEFORE_REMOVE_ASSET => {
                Ok(TransactionEventId::AccountVaultBeforeRemoveAsset)
            },
            ACCOUNT_VAULT_AFTER_REMOVE_ASSET => {
                Ok(TransactionEventId::AccountVaultAfterRemoveAsset)
            },

            ACCOUNT_VAULT_BEFORE_GET_ASSET => Ok(TransactionEventId::AccountVaultBeforeGetAsset),

            ACCOUNT_STORAGE_BEFORE_SET_ITEM => Ok(TransactionEventId::AccountStorageBeforeSetItem),
            ACCOUNT_STORAGE_AFTER_SET_ITEM => Ok(TransactionEventId::AccountStorageAfterSetItem),

            ACCOUNT_STORAGE_BEFORE_GET_MAP_ITEM => {
                Ok(TransactionEventId::AccountStorageBeforeGetMapItem)
            },

            ACCOUNT_STORAGE_BEFORE_SET_MAP_ITEM => {
                Ok(TransactionEventId::AccountStorageBeforeSetMapItem)
            },
            ACCOUNT_STORAGE_AFTER_SET_MAP_ITEM => {
                Ok(TransactionEventId::AccountStorageAfterSetMapItem)
            },

            ACCOUNT_BEFORE_INCREMENT_NONCE => Ok(TransactionEventId::AccountBeforeIncrementNonce),
            ACCOUNT_AFTER_INCREMENT_NONCE => Ok(TransactionEventId::AccountAfterIncrementNonce),

            ACCOUNT_PUSH_PROCEDURE_INDEX => Ok(TransactionEventId::AccountPushProcedureIndex),

            NOTE_BEFORE_CREATED => Ok(TransactionEventId::NoteBeforeCreated),
            NOTE_AFTER_CREATED => Ok(TransactionEventId::NoteAfterCreated),

            NOTE_BEFORE_ADD_ASSET => Ok(TransactionEventId::NoteBeforeAddAsset),
            NOTE_AFTER_ADD_ASSET => Ok(TransactionEventId::NoteAfterAddAsset),

            NOTE_BEFORE_SET_ATTACHMENT => Ok(TransactionEventId::NoteBeforeSetAttachment),

            AUTH_REQUEST => Ok(TransactionEventId::AuthRequest),

            PROLOGUE_START => Ok(TransactionEventId::PrologueStart),
            PROLOGUE_END => Ok(TransactionEventId::PrologueEnd),

            NOTES_PROCESSING_START => Ok(TransactionEventId::NotesProcessingStart),
            NOTES_PROCESSING_END => Ok(TransactionEventId::NotesProcessingEnd),

            NOTE_EXECUTION_START => Ok(TransactionEventId::NoteExecutionStart),
            NOTE_EXECUTION_END => Ok(TransactionEventId::NoteExecutionEnd),

            TX_SCRIPT_PROCESSING_START => Ok(TransactionEventId::TxScriptProcessingStart),
            TX_SCRIPT_PROCESSING_END => Ok(TransactionEventId::TxScriptProcessingEnd),

            EPILOGUE_START => Ok(TransactionEventId::EpilogueStart),
            EPILOGUE_AUTH_PROC_START => Ok(TransactionEventId::EpilogueAuthProcStart),
            EPILOGUE_AUTH_PROC_END => Ok(TransactionEventId::EpilogueAuthProcEnd),
            EPILOGUE_AFTER_TX_CYCLES_OBTAINED => {
                Ok(TransactionEventId::EpilogueAfterTxCyclesObtained)
            },
            EPILOGUE_BEFORE_TX_FEE_REMOVED_FROM_ACCOUNT => {
                Ok(TransactionEventId::EpilogueBeforeTxFeeRemovedFromAccount)
            },
            EPILOGUE_END => Ok(TransactionEventId::EpilogueEnd),

            LINK_MAP_SET => Ok(TransactionEventId::LinkMapSet),
            LINK_MAP_GET => Ok(TransactionEventId::LinkMapGet),

            AUTH_UNAUTHORIZED => Ok(TransactionEventId::Unauthorized),

            _ => Err(TransactionEventError::InvalidTransactionEvent(event_id, name)),
        }
    }
}
