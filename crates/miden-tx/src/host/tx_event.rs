use alloc::vec::Vec;

use miden_processor::{AdviceMutation, AdviceProvider, ProcessState, RowIndex};
use miden_protocol::account::{AccountId, StorageMap, StorageSlotName, StorageSlotType};
use miden_protocol::asset::{Asset, AssetVault, AssetVaultKey, FungibleAsset};
use miden_protocol::note::{
    NoteAttachment,
    NoteAttachmentArray,
    NoteAttachmentContent,
    NoteAttachmentKind,
    NoteAttachmentScheme,
    NoteId,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_protocol::transaction::memory::{NOTE_MEM_SIZE, OUTPUT_NOTE_SECTION_OFFSET};
use miden_protocol::transaction::{TransactionEventId, TransactionSummary};
use miden_protocol::vm::EventId;
use miden_protocol::{Felt, Hasher, Word};

use crate::host::{TransactionBaseHost, TransactionKernelProcess};
use crate::{LinkMap, TransactionKernelError};

// TRANSACTION PROGRESS EVENT
// ================================================================================================
#[derive(Debug)]
pub(crate) enum TransactionProgressEvent {
    PrologueStart(RowIndex),
    PrologueEnd(RowIndex),

    NotesProcessingStart(RowIndex),
    NotesProcessingEnd(RowIndex),

    NoteExecutionStart { note_id: NoteId, clk: RowIndex },
    NoteExecutionEnd(RowIndex),

    TxScriptProcessingStart(RowIndex),
    TxScriptProcessingEnd(RowIndex),

    EpilogueStart(RowIndex),
    EpilogueEnd(RowIndex),

    EpilogueAuthProcStart(RowIndex),
    EpilogueAuthProcEnd(RowIndex),

    EpilogueAfterTxCyclesObtained(RowIndex),
}

// TRANSACTION EVENT
// ================================================================================================

/// The data necessary to handle a [`TransactionEventId`].
#[derive(Debug)]
pub(crate) enum TransactionEvent {
    /// The data necessary to request a foreign account's data from the data store.
    AccountBeforeForeignLoad {
        /// The foreign account's ID.
        foreign_account_id: AccountId,
    },

    AccountVaultAfterRemoveAsset {
        asset: Asset,
    },

    AccountVaultAfterAddAsset {
        asset: Asset,
    },

    AccountStorageAfterSetItem {
        slot_name: StorageSlotName,
        new_value: Word,
    },

    AccountStorageAfterSetMapItem {
        slot_name: StorageSlotName,
        key: Word,
        old_value: Word,
        new_value: Word,
    },

    /// The data necessary to request a storage map witness from the data store.
    AccountStorageBeforeMapItemAccess {
        /// The account ID for whose storage a witness is requested.
        active_account_id: AccountId,
        /// The root of the storage map for which a witness is requested.
        map_root: Word,
        /// The raw map key for which a witness is requested.
        map_key: Word,
    },

    /// The data necessary to request an asset witness from the data store.
    AccountVaultBeforeAssetAccess {
        /// The account ID for whose vault a witness is requested.
        active_account_id: AccountId,
        /// The vault root identifying the asset vault from which a witness is requested.
        vault_root: Word,
        /// The asset for which a witness is requested.
        asset_key: AssetVaultKey,
    },

    AccountAfterIncrementNonce,

    AccountPushProcedureIndex {
        /// The code commitment of the active account.
        code_commitment: Word,
        /// The procedure root whose index is requested.
        procedure_root: Word,
    },

    NoteBeforeCreated {
        /// The note index extracted from the stack.
        note_idx: usize,
        /// The note metadata extracted from the stack.
        metadata: NoteMetadata,
        /// The recipient data extracted from the advice inputs.
        recipient_data: RecipientData,
    },

    NoteBeforeAddAsset {
        /// The note index to which the asset is added.
        note_idx: usize,
        /// The asset that is added to the output note.
        asset: Asset,
    },

    NoteBeforeSetAttachment {
        /// The note index on which the attachment is set.
        note_idx: usize,
        /// The attachment that is set.
        attachment: NoteAttachment,
    },

    /// The data necessary to handle an auth request.
    AuthRequest {
        pub_key_hash: Word,
        tx_summary: TransactionSummary,
        signature: Option<Vec<Felt>>,
    },

    Unauthorized {
        tx_summary: TransactionSummary,
    },

    EpilogueBeforeTxFeeRemovedFromAccount {
        fee_asset: FungibleAsset,
    },

    LinkMapSet {
        advice_mutation: Vec<AdviceMutation>,
    },
    LinkMapGet {
        advice_mutation: Vec<AdviceMutation>,
    },

    Progress(TransactionProgressEvent),
}

impl TransactionEvent {
    /// Extracts the [`TransactionEventId`] from the stack as well as the data necessary to handle
    /// it.
    ///
    /// Returns `Some` if the extracted [`TransactionEventId`] resulted in an event that needs to be
    /// handled, `None` otherwise.
    pub fn extract<'store, STORE>(
        base_host: &TransactionBaseHost<'store, STORE>,
        process: &ProcessState,
    ) -> Result<Option<TransactionEvent>, TransactionKernelError> {
        let event_id = EventId::from_felt(process.get_stack_item(0));
        let tx_event_id = TransactionEventId::try_from(event_id).map_err(|err| {
            TransactionKernelError::other_with_source(
                "failed to convert event ID into transaction event ID",
                err,
            )
        })?;

        let tx_event = match tx_event_id {
            TransactionEventId::AccountBeforeForeignLoad => {
                // Expected stack state: [event, account_id_prefix, account_id_suffix]
                let account_id_word = process.get_stack_word_be(1);
                let account_id = AccountId::try_from([account_id_word[3], account_id_word[2]])
                    .map_err(|err| {
                        TransactionKernelError::other_with_source(
                            "failed to convert account ID word into account ID",
                            err,
                        )
                    })?;

                Some(TransactionEvent::AccountBeforeForeignLoad { foreign_account_id: account_id })
            },
            TransactionEventId::AccountVaultBeforeAddAsset
            | TransactionEventId::AccountVaultBeforeRemoveAsset => {
                // Expected stack state: [event, ASSET, account_vault_root_ptr]
                let asset_word = process.get_stack_word_be(1);
                let asset = Asset::try_from(asset_word).map_err(|source| {
                    TransactionKernelError::MalformedAssetInEventHandler {
                        handler: "on_account_vault_before_add_or_remove_asset",
                        source,
                    }
                })?;

                let vault_root_ptr = process.get_stack_item(5);
                let current_vault_root = process.get_vault_root(vault_root_ptr)?;

                on_account_vault_asset_accessed(
                    base_host,
                    process,
                    asset.vault_key(),
                    current_vault_root,
                )?
            },
            TransactionEventId::AccountVaultAfterRemoveAsset => {
                // Expected stack state: [event, ASSET]
                let asset: Asset = process.get_stack_word_be(1).try_into().map_err(|source| {
                    TransactionKernelError::MalformedAssetInEventHandler {
                        handler: "on_account_vault_after_remove_asset",
                        source,
                    }
                })?;

                Some(TransactionEvent::AccountVaultAfterRemoveAsset { asset })
            },
            TransactionEventId::AccountVaultAfterAddAsset => {
                // Expected stack state: [event, ASSET]
                let asset: Asset = process.get_stack_word_be(1).try_into().map_err(|source| {
                    TransactionKernelError::MalformedAssetInEventHandler {
                        handler: "on_account_vault_after_add_asset",
                        source,
                    }
                })?;

                Some(TransactionEvent::AccountVaultAfterAddAsset { asset })
            },
            TransactionEventId::AccountVaultBeforeGetBalance => {
                // Expected stack state:
                // [event, faucet_id_prefix, faucet_id_suffix, vault_root_ptr]
                let stack_top = process.get_stack_word_be(1);
                let faucet_id =
                    AccountId::try_from([stack_top[3], stack_top[2]]).map_err(|err| {
                        TransactionKernelError::other_with_source(
                            "failed to convert faucet ID word into faucet ID",
                            err,
                        )
                    })?;
                let vault_root_ptr = stack_top[1];
                let vault_root = process.get_vault_root(vault_root_ptr)?;

                let vault_key = AssetVaultKey::from_account_id(faucet_id).ok_or_else(|| {
                    TransactionKernelError::other(format!(
                        "provided faucet ID {faucet_id} is not valid for fungible assets"
                    ))
                })?;

                on_account_vault_asset_accessed(base_host, process, vault_key, vault_root)?
            },
            TransactionEventId::AccountVaultBeforeHasNonFungibleAsset => {
                // Expected stack state: [event, ASSET, vault_root_ptr]
                let asset_word = process.get_stack_word_be(1);
                let asset = Asset::try_from(asset_word).map_err(|err| {
                    TransactionKernelError::other_with_source(
                        "provided asset is not a valid asset",
                        err,
                    )
                })?;

                let vault_root_ptr = process.get_stack_item(5);
                let vault_root = process.get_vault_root(vault_root_ptr)?;

                on_account_vault_asset_accessed(base_host, process, asset.vault_key(), vault_root)?
            },

            TransactionEventId::AccountStorageBeforeSetItem => None,

            TransactionEventId::AccountStorageAfterSetItem => {
                // Expected stack state: [event, slot_ptr, VALUE]
                let slot_ptr = process.get_stack_item(1);
                let new_value = process.get_stack_word_be(2);

                let (slot_id, slot_type, _old_value) = process.get_storage_slot(slot_ptr)?;

                let slot_header = base_host.initial_account_storage_slot(slot_id)?;
                let slot_name = slot_header.name().clone();

                if !slot_type.is_value() {
                    return Err(TransactionKernelError::other(format!(
                        "expected slot to be of type value, found {slot_type}"
                    )));
                }

                Some(TransactionEvent::AccountStorageAfterSetItem { slot_name, new_value })
            },

            TransactionEventId::AccountStorageBeforeGetMapItem => {
                // Expected stack state: [event, slot_ptr, KEY]
                let slot_ptr = process.get_stack_item(1);
                let map_key = process.get_stack_word_be(2);

                on_account_storage_map_item_accessed(base_host, process, slot_ptr, map_key)?
            },

            TransactionEventId::AccountStorageBeforeSetMapItem => {
                // Expected stack state: [event, slot_ptr, KEY]
                let slot_ptr = process.get_stack_item(1);
                let map_key = process.get_stack_word_be(2);

                on_account_storage_map_item_accessed(base_host, process, slot_ptr, map_key)?
            },

            TransactionEventId::AccountStorageAfterSetMapItem => {
                // Expected stack state: [event, slot_ptr, KEY, OLD_VALUE, NEW_VALUE]
                let slot_ptr = process.get_stack_item(1);
                let key = process.get_stack_word_be(2);
                let old_value = process.get_stack_word_be(6);
                let new_value = process.get_stack_word_be(10);

                // Resolve slot ID to slot name.
                let (slot_id, ..) = process.get_storage_slot(slot_ptr)?;
                let slot_header = base_host.initial_account_storage_slot(slot_id)?;
                let slot_name = slot_header.name().clone();

                Some(TransactionEvent::AccountStorageAfterSetMapItem {
                    slot_name,
                    key,
                    old_value,
                    new_value,
                })
            },

            TransactionEventId::AccountBeforeIncrementNonce => None,

            TransactionEventId::AccountAfterIncrementNonce => {
                Some(TransactionEvent::AccountAfterIncrementNonce)
            },

            TransactionEventId::AccountPushProcedureIndex => {
                // Expected stack state: [event, PROC_ROOT]
                let procedure_root = process.get_stack_word_be(1);
                let code_commitment = process.get_active_account_code_commitment()?;

                Some(TransactionEvent::AccountPushProcedureIndex {
                    code_commitment,
                    procedure_root,
                })
            },

            TransactionEventId::NoteBeforeCreated => {
                // Expected stack state:  [event, tag, note_type, RECIPIENT]
                let tag = process.get_stack_item(1);
                let note_type = process.get_stack_item(2);
                let recipient_digest = process.get_stack_word_be(3);

                let sender = base_host.native_account_id();
                let metadata = build_note_metadata(sender, note_type, tag)?;

                let note_idx = process.get_num_output_notes() as usize;

                // try to read the full recipient from the advice provider
                let recipient_data = if process.has_advice_map_entry(recipient_digest) {
                    let (note_storage, script_root, serial_num) =
                        process.read_note_recipient_info_from_adv_map(recipient_digest)?;

                    let note_script = process
                        .advice_provider()
                        .get_mapped_values(&script_root)
                        .map(|script_data| {
                            NoteScript::try_from(script_data).map_err(|source| {
                                TransactionKernelError::MalformedNoteScript {
                                    data: script_data.to_vec(),
                                    source,
                                }
                            })
                        })
                        .transpose()?;

                    match note_script {
                        Some(note_script) => {
                            let recipient =
                                NoteRecipient::new(serial_num, note_script, note_storage);

                            if recipient.digest() != recipient_digest {
                                return Err(TransactionKernelError::other(format!(
                                    "recipient digest is {recipient_digest}, but recipient constructed from raw inputs has digest {}",
                                    recipient.digest()
                                )));
                            }

                            RecipientData::Recipient(recipient)
                        },
                        None => RecipientData::ScriptMissing {
                            recipient_digest,
                            serial_num,
                            script_root,
                            note_storage,
                        },
                    }
                } else {
                    RecipientData::Digest(recipient_digest)
                };

                Some(TransactionEvent::NoteBeforeCreated { note_idx, metadata, recipient_data })
            },

            TransactionEventId::NoteAfterCreated => None,

            TransactionEventId::NoteBeforeAddAsset => {
                // Expected stack state: [event, ASSET, note_ptr, num_of_assets, note_idx]
                let note_idx = process.get_stack_item(7).as_int() as usize;

                let asset_word = process.get_stack_word_be(1);
                let asset = Asset::try_from(asset_word).map_err(|source| {
                    TransactionKernelError::MalformedAssetInEventHandler {
                        handler: "on_note_before_add_asset",
                        source,
                    }
                })?;

                Some(TransactionEvent::NoteBeforeAddAsset { note_idx, asset })
            },

            TransactionEventId::NoteAfterAddAsset => None,

            TransactionEventId::NoteBeforeSetAttachment => {
                // Expected stack state: [
                //     event, attachment_scheme, attachment_kind,
                //     note_ptr, note_ptr, ATTACHMENT
                // ]

                let attachment_scheme = process.get_stack_item(1);
                let attachment_kind = process.get_stack_item(2);
                let note_ptr = process.get_stack_item(3);
                let attachment = process.get_stack_word_be(5);

                let (note_idx, attachment) = extract_note_attachment(
                    attachment_scheme,
                    attachment_kind,
                    attachment,
                    note_ptr,
                    process.advice_provider(),
                )?;

                Some(TransactionEvent::NoteBeforeSetAttachment { note_idx, attachment })
            },

            TransactionEventId::AuthRequest => {
                // Expected stack state: [event, MESSAGE, PUB_KEY]
                let message = process.get_stack_word_be(1);
                let pub_key_hash = process.get_stack_word_be(5);
                let signature_key = Hasher::merge(&[pub_key_hash, message]);

                let signature = process
                    .advice_provider()
                    .get_mapped_values(&signature_key)
                    .map(|slice| slice.to_vec());

                let tx_summary = extract_tx_summary(base_host, process, message)?;

                Some(TransactionEvent::AuthRequest { pub_key_hash, tx_summary, signature })
            },

            TransactionEventId::Unauthorized => {
                // Expected stack state: [event, MESSAGE]
                let message = process.get_stack_word_be(1);
                let tx_summary = extract_tx_summary(base_host, process, message)?;

                Some(TransactionEvent::Unauthorized { tx_summary })
            },

            TransactionEventId::EpilogueBeforeTxFeeRemovedFromAccount => {
                // Expected stack state: [event, FEE_ASSET]
                let fee_asset = process.get_stack_word_be(1);
                let fee_asset = FungibleAsset::try_from(fee_asset)
                    .map_err(TransactionKernelError::FailedToConvertFeeAsset)?;

                Some(TransactionEvent::EpilogueBeforeTxFeeRemovedFromAccount { fee_asset })
            },

            TransactionEventId::LinkMapSet => Some(TransactionEvent::LinkMapSet {
                advice_mutation: LinkMap::handle_set_event(process),
            }),
            TransactionEventId::LinkMapGet => Some(TransactionEvent::LinkMapGet {
                advice_mutation: LinkMap::handle_get_event(process),
            }),

            TransactionEventId::PrologueStart => Some(TransactionEvent::Progress(
                TransactionProgressEvent::PrologueStart(process.clk()),
            )),
            TransactionEventId::PrologueEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::PrologueEnd(process.clk()),
            )),

            TransactionEventId::NotesProcessingStart => Some(TransactionEvent::Progress(
                TransactionProgressEvent::NotesProcessingStart(process.clk()),
            )),
            TransactionEventId::NotesProcessingEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::NotesProcessingEnd(process.clk()),
            )),

            TransactionEventId::NoteExecutionStart => {
                let note_id = process.get_active_note_id()?.ok_or_else(|| TransactionKernelError::other(
                    "note execution interval measurement is incorrect: check the placement of the start and the end of the interval",
                ))?;

                Some(TransactionEvent::Progress(TransactionProgressEvent::NoteExecutionStart {
                    note_id,
                    clk: process.clk(),
                }))
            },
            TransactionEventId::NoteExecutionEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::NoteExecutionEnd(process.clk()),
            )),

            TransactionEventId::TxScriptProcessingStart => Some(TransactionEvent::Progress(
                TransactionProgressEvent::TxScriptProcessingStart(process.clk()),
            )),
            TransactionEventId::TxScriptProcessingEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::TxScriptProcessingEnd(process.clk()),
            )),

            TransactionEventId::EpilogueStart => Some(TransactionEvent::Progress(
                TransactionProgressEvent::EpilogueStart(process.clk()),
            )),
            TransactionEventId::EpilogueEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::EpilogueEnd(process.clk()),
            )),

            TransactionEventId::EpilogueAuthProcStart => Some(TransactionEvent::Progress(
                TransactionProgressEvent::EpilogueAuthProcStart(process.clk()),
            )),
            TransactionEventId::EpilogueAuthProcEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::EpilogueAuthProcEnd(process.clk()),
            )),

            TransactionEventId::EpilogueAfterTxCyclesObtained => Some(TransactionEvent::Progress(
                TransactionProgressEvent::EpilogueAfterTxCyclesObtained(process.clk()),
            )),
        };

        Ok(tx_event)
    }
}

// RECIPIENT DATA
// ================================================================================================

/// The partial data to construct a note recipient.
#[derive(Debug)]
pub(crate) enum RecipientData {
    /// Only the recipient digest is available.
    Digest(Word),
    /// The full [`NoteRecipient`] is available.
    Recipient(NoteRecipient),
    /// Everything but the note script is available.
    ScriptMissing {
        recipient_digest: Word,
        serial_num: Word,
        script_root: Word,
        note_storage: NoteStorage,
    },
}

/// Checks if the necessary witness for accessing the asset identified by the vault key is already
/// in the merkle store, and:
/// - If so, returns `None`.
/// - If not, returns `Some` with all necessary data for requesting it.
fn on_account_vault_asset_accessed<'store, STORE>(
    base_host: &TransactionBaseHost<'store, STORE>,
    process: &ProcessState,
    vault_key: AssetVaultKey,
    vault_root: Word,
) -> Result<Option<TransactionEvent>, TransactionKernelError> {
    let leaf_index = Felt::new(vault_key.to_leaf_index().value());
    let active_account_id = process.get_active_account_id()?;

    // For the native account we need to explicitly request the initial vault root, while for
    // foreign accounts the current vault root is always the initial one.
    let vault_root = if active_account_id == base_host.native_account_id() {
        base_host.initial_account_header().vault_root()
    } else {
        vault_root
    };

    // Note that we check whether a merkle path for the current vault root is present, not
    // necessarily for the root we are going to request. This is because the end goal is to
    // enable access to an asset against the current vault root, and so if this
    // condition is already satisfied, there is nothing to request.
    if process.has_merkle_path::<{ AssetVault::DEPTH }>(vault_root, leaf_index)? {
        // If the witness already exists, the event does not need to be handled.
        Ok(None)
    } else {
        Ok(Some(TransactionEvent::AccountVaultBeforeAssetAccess {
            active_account_id,
            vault_root,
            asset_key: vault_key,
        }))
    }
}

/// Checks if the necessary witness for accessing the map item identified by the map key is already
/// in the merkle store, and:
/// - If so, returns `None`.
/// - If not, returns `Some` with all necessary data for requesting it.
fn on_account_storage_map_item_accessed<'store, STORE>(
    base_host: &TransactionBaseHost<'store, STORE>,
    process: &ProcessState,
    slot_ptr: Felt,
    map_key: Word,
) -> Result<Option<TransactionEvent>, TransactionKernelError> {
    let (slot_id, slot_type, current_map_root) = process.get_storage_slot(slot_ptr)?;

    if !slot_type.is_map() {
        return Err(TransactionKernelError::other(format!(
            "expected slot to be of type map, found {slot_type}"
        )));
    }

    let active_account_id = process.get_active_account_id()?;
    let leaf_index: Felt = StorageMap::map_key_to_leaf_index(map_key)
        .value()
        .try_into()
        .expect("expected key index to be a felt");

    // For the native account we need to explicitly request the initial map root,
    // while for foreign accounts the current map root is always the initial one.
    let map_root = if active_account_id == base_host.native_account_id() {
        // For native accounts, we have to request witnesses against the initial
        // root instead of the _current_ one, since the data
        // store only has witnesses for initial one.
        let slot_header = base_host.initial_account_storage_slot(slot_id)?;

        if slot_header.slot_type() != StorageSlotType::Map {
            return Err(TransactionKernelError::other(format!(
                "expected slot {slot_id} to be of type map"
            )));
        }
        slot_header.value()
    } else {
        current_map_root
    };

    if process.has_merkle_path::<{ StorageMap::DEPTH }>(current_map_root, leaf_index)? {
        // If the witness already exists, the event does not need to be handled.
        Ok(None)
    } else {
        Ok(Some(TransactionEvent::AccountStorageBeforeMapItemAccess {
            active_account_id,
            map_root,
            map_key,
        }))
    }
}

/// Extracts the transaction summary from the advice map using the provided `message` as the
/// key.
///
/// ```text
/// Expected advice map state: {
///     MESSAGE: [
///         SALT, OUTPUT_NOTES_COMMITMENT, INPUT_NOTES_COMMITMENT, ACCOUNT_DELTA_COMMITMENT
///     ]
/// }
/// ```
fn extract_tx_summary<'store, STORE>(
    base_host: &TransactionBaseHost<'store, STORE>,
    process: &ProcessState,
    message: Word,
) -> Result<TransactionSummary, TransactionKernelError> {
    let Some(commitments) = process.advice_provider().get_mapped_values(&message) else {
        return Err(TransactionKernelError::TransactionSummaryConstructionFailed(
            "expected message to exist in advice provider".into(),
        ));
    };

    if commitments.len() != 16 {
        return Err(TransactionKernelError::TransactionSummaryConstructionFailed(
            "expected 4 words for transaction summary commitments".into(),
        ));
    }

    let salt = extract_word(commitments, 0);
    let output_notes_commitment = extract_word(commitments, 4);
    let input_notes_commitment = extract_word(commitments, 8);
    let account_delta_commitment = extract_word(commitments, 12);

    let tx_summary = base_host.build_tx_summary(
        salt,
        output_notes_commitment,
        input_notes_commitment,
        account_delta_commitment,
    )?;

    if tx_summary.to_commitment() != message {
        return Err(TransactionKernelError::TransactionSummaryConstructionFailed(
            "transaction summary doesn't commit to the expected message".into(),
        ));
    }

    Ok(tx_summary)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds the note metadata from sender, note type and tag if all inputs are valid.
fn build_note_metadata(
    sender: AccountId,
    note_type: Felt,
    tag: Felt,
) -> Result<NoteMetadata, TransactionKernelError> {
    let note_type = u8::try_from(note_type)
        .map_err(|_| TransactionKernelError::other("failed to decode note_type into u8"))
        .and_then(|note_type_byte| {
            NoteType::try_from(note_type_byte).map_err(|source| {
                TransactionKernelError::other_with_source(
                    "failed to decode note_type from u8",
                    source,
                )
            })
        })?;

    let tag = u32::try_from(tag)
        .map_err(|_| TransactionKernelError::other("failed to decode note tag into u32"))
        .map(NoteTag::new)?;

    Ok(NoteMetadata::new(sender, note_type, tag))
}

fn extract_note_attachment(
    attachment_scheme: Felt,
    attachment_kind: Felt,
    attachment: Word,
    note_ptr: Felt,
    advice_provider: &AdviceProvider,
) -> Result<(usize, NoteAttachment), TransactionKernelError> {
    let note_idx = note_ptr_to_idx(note_ptr)?;

    let attachment_kind = u8::try_from(attachment_kind)
        .map_err(|_| TransactionKernelError::other("failed to convert attachment kind to u8"))
        .and_then(|attachment_kind| {
            NoteAttachmentKind::try_from(attachment_kind).map_err(|source| {
                TransactionKernelError::other_with_source(
                    "failed to convert u8 to attachment kind",
                    source,
                )
            })
        })?;

    let attachment_scheme = u32::try_from(attachment_scheme)
        .map_err(|_| TransactionKernelError::other("failed to convert attachment scheme to u32"))
        .map(NoteAttachmentScheme::new)?;

    let attachment_content = match attachment_kind {
        NoteAttachmentKind::None => {
            if !attachment.is_empty() {
                return Err(TransactionKernelError::NoteAttachmentNoneIsNotEmpty);
            }
            NoteAttachmentContent::None
        },
        NoteAttachmentKind::Word => NoteAttachmentContent::Word(attachment),
        NoteAttachmentKind::Array => {
            let elements = advice_provider.get_mapped_values(&attachment).ok_or_else(|| {
              TransactionKernelError::other(
                  "elements of a note attachment commitment must be present in the advice provider",
              )
            })?;

            let commitment_attachment =
                NoteAttachmentArray::new(elements.to_vec()).map_err(|source| {
                    TransactionKernelError::other_with_source(
                        "failed to construct note attachment commitment",
                        source,
                    )
                })?;

            if commitment_attachment.commitment() != attachment {
                return Err(TransactionKernelError::NoteAttachmentArrayMismatch {
                    actual: commitment_attachment.commitment(),
                    provided: attachment,
                });
            }

            NoteAttachmentContent::Array(commitment_attachment)
        },
    };

    let attachment =
        NoteAttachment::new(attachment_scheme, attachment_content).map_err(|source| {
            TransactionKernelError::other_with_source("failed to extract note attachment", source)
        })?;

    Ok((note_idx as usize, attachment))
}

/// Extracts a word from a slice of field elements.
#[inline(always)]
fn extract_word(commitments: &[Felt], start: usize) -> Word {
    Word::from([
        commitments[start],
        commitments[start + 1],
        commitments[start + 2],
        commitments[start + 3],
    ])
}

/// Converts the provided note ptr into the corresponding note index.
fn note_ptr_to_idx(note_ptr: Felt) -> Result<u32, TransactionKernelError> {
    u32::try_from(note_ptr)
        .map_err(|_| TransactionKernelError::other("failed to convert note_ptr to u32"))
        .and_then(|note_ptr| {
            note_ptr
                .checked_sub(OUTPUT_NOTE_SECTION_OFFSET)
                .ok_or_else(|| {
                    TransactionKernelError::other("failed to calculate note_idx from note_ptr")
                })
                .map(|note_ptr| note_ptr / NOTE_MEM_SIZE)
        })
}
