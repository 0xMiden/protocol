use core::fmt;

use crate::errors::TransactionEventError;
use crate::vm::{EventId, EventName};

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
    AccountBeforeForeignLoad = ACCOUNT_BEFORE_FOREIGN_LOAD_ID,

    AccountVaultBeforeAddAsset = ACCOUNT_VAULT_BEFORE_ADD_ASSET_ID,
    AccountVaultAfterAddAsset = ACCOUNT_VAULT_AFTER_ADD_ASSET_ID,

    AccountVaultBeforeRemoveAsset = ACCOUNT_VAULT_BEFORE_REMOVE_ASSET_ID,
    AccountVaultAfterRemoveAsset = ACCOUNT_VAULT_AFTER_REMOVE_ASSET_ID,

    AccountVaultBeforeGetAsset = ACCOUNT_VAULT_BEFORE_GET_ASSET_ID,

    AccountStorageBeforeSetItem = ACCOUNT_STORAGE_BEFORE_SET_ITEM_ID,
    AccountStorageAfterSetItem = ACCOUNT_STORAGE_AFTER_SET_ITEM_ID,

    AccountStorageBeforeGetMapItem = ACCOUNT_STORAGE_BEFORE_GET_MAP_ITEM_ID,

    AccountStorageBeforeSetMapItem = ACCOUNT_STORAGE_BEFORE_SET_MAP_ITEM_ID,
    AccountStorageAfterSetMapItem = ACCOUNT_STORAGE_AFTER_SET_MAP_ITEM_ID,

    AccountBeforeIncrementNonce = ACCOUNT_BEFORE_INCREMENT_NONCE_ID,
    AccountAfterIncrementNonce = ACCOUNT_AFTER_INCREMENT_NONCE_ID,

    AccountPushProcedureIndex = ACCOUNT_PUSH_PROCEDURE_INDEX_ID,

    NoteBeforeCreated = NOTE_BEFORE_CREATED_ID,
    NoteAfterCreated = NOTE_AFTER_CREATED_ID,

    NoteBeforeAddAsset = NOTE_BEFORE_ADD_ASSET_ID,
    NoteAfterAddAsset = NOTE_AFTER_ADD_ASSET_ID,

    NoteBeforeSetAttachment = NOTE_BEFORE_SET_ATTACHMENT_ID,

    AuthRequest = AUTH_REQUEST_ID,

    PrologueStart = PROLOGUE_START_ID,
    PrologueEnd = PROLOGUE_END_ID,

    NotesProcessingStart = NOTES_PROCESSING_START_ID,
    NotesProcessingEnd = NOTES_PROCESSING_END_ID,

    NoteExecutionStart = NOTE_EXECUTION_START_ID,
    NoteExecutionEnd = NOTE_EXECUTION_END_ID,

    TxScriptProcessingStart = TX_SCRIPT_PROCESSING_START_ID,
    TxScriptProcessingEnd = TX_SCRIPT_PROCESSING_END_ID,

    EpilogueStart = EPILOGUE_START_ID,
    EpilogueEnd = EPILOGUE_END_ID,

    EpilogueAuthProcStart = EPILOGUE_AUTH_PROC_START_ID,
    EpilogueAuthProcEnd = EPILOGUE_AUTH_PROC_END_ID,

    EpilogueAfterTxCyclesObtained = EPILOGUE_AFTER_TX_CYCLES_OBTAINED_ID,
    EpilogueBeforeTxFeeRemovedFromAccount = EPILOGUE_BEFORE_TX_FEE_REMOVED_FROM_ACCOUNT_ID,

    LinkMapSet = LINK_MAP_SET_ID,
    LinkMapGet = LINK_MAP_GET_ID,

    Unauthorized = AUTH_UNAUTHORIZED_ID,
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

    /// Returns the [`EventName`] of the transaction event.
    pub fn event_name(&self) -> &'static EventName {
        match self {
            Self::AccountBeforeForeignLoad => &ACCOUNT_BEFORE_FOREIGN_LOAD_NAME,
            Self::AccountVaultBeforeAddAsset => &ACCOUNT_VAULT_BEFORE_ADD_ASSET_NAME,
            Self::AccountVaultAfterAddAsset => &ACCOUNT_VAULT_AFTER_ADD_ASSET_NAME,
            Self::AccountVaultBeforeRemoveAsset => &ACCOUNT_VAULT_BEFORE_REMOVE_ASSET_NAME,
            Self::AccountVaultAfterRemoveAsset => &ACCOUNT_VAULT_AFTER_REMOVE_ASSET_NAME,
            Self::AccountVaultBeforeGetAsset => &ACCOUNT_VAULT_BEFORE_GET_ASSET_NAME,
            Self::AccountStorageBeforeSetItem => &ACCOUNT_STORAGE_BEFORE_SET_ITEM_NAME,
            Self::AccountStorageAfterSetItem => &ACCOUNT_STORAGE_AFTER_SET_ITEM_NAME,
            Self::AccountStorageBeforeGetMapItem => &ACCOUNT_STORAGE_BEFORE_GET_MAP_ITEM_NAME,
            Self::AccountStorageBeforeSetMapItem => &ACCOUNT_STORAGE_BEFORE_SET_MAP_ITEM_NAME,
            Self::AccountStorageAfterSetMapItem => &ACCOUNT_STORAGE_AFTER_SET_MAP_ITEM_NAME,
            Self::AccountBeforeIncrementNonce => &ACCOUNT_BEFORE_INCREMENT_NONCE_NAME,
            Self::AccountAfterIncrementNonce => &ACCOUNT_AFTER_INCREMENT_NONCE_NAME,
            Self::AccountPushProcedureIndex => &ACCOUNT_PUSH_PROCEDURE_INDEX_NAME,
            Self::NoteBeforeCreated => &NOTE_BEFORE_CREATED_NAME,
            Self::NoteAfterCreated => &NOTE_AFTER_CREATED_NAME,
            Self::NoteBeforeAddAsset => &NOTE_BEFORE_ADD_ASSET_NAME,
            Self::NoteAfterAddAsset => &NOTE_AFTER_ADD_ASSET_NAME,
            Self::NoteBeforeSetAttachment => &NOTE_BEFORE_SET_ATTACHMENT_NAME,
            Self::AuthRequest => &AUTH_REQUEST_NAME,
            Self::PrologueStart => &PROLOGUE_START_NAME,
            Self::PrologueEnd => &PROLOGUE_END_NAME,
            Self::NotesProcessingStart => &NOTES_PROCESSING_START_NAME,
            Self::NotesProcessingEnd => &NOTES_PROCESSING_END_NAME,
            Self::NoteExecutionStart => &NOTE_EXECUTION_START_NAME,
            Self::NoteExecutionEnd => &NOTE_EXECUTION_END_NAME,
            Self::TxScriptProcessingStart => &TX_SCRIPT_PROCESSING_START_NAME,
            Self::TxScriptProcessingEnd => &TX_SCRIPT_PROCESSING_END_NAME,
            Self::EpilogueStart => &EPILOGUE_START_NAME,
            Self::EpilogueEnd => &EPILOGUE_END_NAME,
            Self::EpilogueAuthProcStart => &EPILOGUE_AUTH_PROC_START_NAME,
            Self::EpilogueAuthProcEnd => &EPILOGUE_AUTH_PROC_END_NAME,
            Self::EpilogueAfterTxCyclesObtained => &EPILOGUE_AFTER_TX_CYCLES_OBTAINED_NAME,
            Self::EpilogueBeforeTxFeeRemovedFromAccount => {
                &EPILOGUE_BEFORE_TX_FEE_REMOVED_FROM_ACCOUNT_NAME
            },
            Self::LinkMapSet => &LINK_MAP_SET_NAME,
            Self::LinkMapGet => &LINK_MAP_GET_NAME,
            Self::Unauthorized => &AUTH_UNAUTHORIZED_NAME,
        }
    }
}

impl fmt::Display for TransactionEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.event_name())
    }
}

impl TryFrom<EventId> for TransactionEventId {
    type Error = TransactionEventError;

    fn try_from(event_id: EventId) -> Result<Self, Self::Error> {
        let raw = event_id.as_felt().as_canonical_u64();

        match raw {
            ACCOUNT_BEFORE_FOREIGN_LOAD_ID => Ok(TransactionEventId::AccountBeforeForeignLoad),

            ACCOUNT_VAULT_BEFORE_ADD_ASSET_ID => Ok(TransactionEventId::AccountVaultBeforeAddAsset),
            ACCOUNT_VAULT_AFTER_ADD_ASSET_ID => Ok(TransactionEventId::AccountVaultAfterAddAsset),

            ACCOUNT_VAULT_BEFORE_REMOVE_ASSET_ID => {
                Ok(TransactionEventId::AccountVaultBeforeRemoveAsset)
            },
            ACCOUNT_VAULT_AFTER_REMOVE_ASSET_ID => {
                Ok(TransactionEventId::AccountVaultAfterRemoveAsset)
            },

            ACCOUNT_VAULT_BEFORE_GET_ASSET_ID => Ok(TransactionEventId::AccountVaultBeforeGetAsset),

            ACCOUNT_STORAGE_BEFORE_SET_ITEM_ID => {
                Ok(TransactionEventId::AccountStorageBeforeSetItem)
            },
            ACCOUNT_STORAGE_AFTER_SET_ITEM_ID => Ok(TransactionEventId::AccountStorageAfterSetItem),

            ACCOUNT_STORAGE_BEFORE_GET_MAP_ITEM_ID => {
                Ok(TransactionEventId::AccountStorageBeforeGetMapItem)
            },

            ACCOUNT_STORAGE_BEFORE_SET_MAP_ITEM_ID => {
                Ok(TransactionEventId::AccountStorageBeforeSetMapItem)
            },
            ACCOUNT_STORAGE_AFTER_SET_MAP_ITEM_ID => {
                Ok(TransactionEventId::AccountStorageAfterSetMapItem)
            },

            ACCOUNT_BEFORE_INCREMENT_NONCE_ID => {
                Ok(TransactionEventId::AccountBeforeIncrementNonce)
            },
            ACCOUNT_AFTER_INCREMENT_NONCE_ID => Ok(TransactionEventId::AccountAfterIncrementNonce),

            ACCOUNT_PUSH_PROCEDURE_INDEX_ID => Ok(TransactionEventId::AccountPushProcedureIndex),

            NOTE_BEFORE_CREATED_ID => Ok(TransactionEventId::NoteBeforeCreated),
            NOTE_AFTER_CREATED_ID => Ok(TransactionEventId::NoteAfterCreated),

            NOTE_BEFORE_ADD_ASSET_ID => Ok(TransactionEventId::NoteBeforeAddAsset),
            NOTE_AFTER_ADD_ASSET_ID => Ok(TransactionEventId::NoteAfterAddAsset),

            NOTE_BEFORE_SET_ATTACHMENT_ID => Ok(TransactionEventId::NoteBeforeSetAttachment),

            AUTH_REQUEST_ID => Ok(TransactionEventId::AuthRequest),

            PROLOGUE_START_ID => Ok(TransactionEventId::PrologueStart),
            PROLOGUE_END_ID => Ok(TransactionEventId::PrologueEnd),

            NOTES_PROCESSING_START_ID => Ok(TransactionEventId::NotesProcessingStart),
            NOTES_PROCESSING_END_ID => Ok(TransactionEventId::NotesProcessingEnd),

            NOTE_EXECUTION_START_ID => Ok(TransactionEventId::NoteExecutionStart),
            NOTE_EXECUTION_END_ID => Ok(TransactionEventId::NoteExecutionEnd),

            TX_SCRIPT_PROCESSING_START_ID => Ok(TransactionEventId::TxScriptProcessingStart),
            TX_SCRIPT_PROCESSING_END_ID => Ok(TransactionEventId::TxScriptProcessingEnd),

            EPILOGUE_START_ID => Ok(TransactionEventId::EpilogueStart),
            EPILOGUE_AUTH_PROC_START_ID => Ok(TransactionEventId::EpilogueAuthProcStart),
            EPILOGUE_AUTH_PROC_END_ID => Ok(TransactionEventId::EpilogueAuthProcEnd),
            EPILOGUE_AFTER_TX_CYCLES_OBTAINED_ID => {
                Ok(TransactionEventId::EpilogueAfterTxCyclesObtained)
            },
            EPILOGUE_BEFORE_TX_FEE_REMOVED_FROM_ACCOUNT_ID => {
                Ok(TransactionEventId::EpilogueBeforeTxFeeRemovedFromAccount)
            },
            EPILOGUE_END_ID => Ok(TransactionEventId::EpilogueEnd),

            LINK_MAP_SET_ID => Ok(TransactionEventId::LinkMapSet),
            LINK_MAP_GET_ID => Ok(TransactionEventId::LinkMapGet),

            AUTH_UNAUTHORIZED_ID => Ok(TransactionEventId::Unauthorized),

            _ => Err(TransactionEventError::InvalidTransactionEvent(event_id)),
        }
    }
}
