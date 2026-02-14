use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::println;

use miden_core::field::PrimeField64;
use miden_processor::ProcessorState;
use miden_processor::advice::AdviceMutation;
use miden_protocol::account::{AccountId, StorageMap, StorageSlotName, StorageSlotType};
use miden_protocol::asset::{Asset, AssetVault, AssetVaultKey, FungibleAsset};
use miden_protocol::note::{NoteId, NoteInputs, NoteMetadata, NoteRecipient, NoteScript};
use miden_protocol::transaction::{TransactionEventId, TransactionSummary};
use miden_protocol::vm::{EventId, RowIndex};
use miden_protocol::{Felt, Hasher, Word};

use crate::host::{TransactionBaseHost, TransactionKernelProcess, get_stack_word_le};
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

    NoteAfterCreated {
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
        process: &ProcessorState,
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
                #[cfg(feature = "std")]
                if std::env::var("MIDEN_DEBUG_FOREIGN_LOAD").is_ok() {
                    let stack_items: Vec<Felt> =
                        (0..16).map(|idx| process.get_stack_item(idx)).collect();
                    let account_id_word = get_stack_word_le(process, 1);
                    let suffix = account_id_word[1];
                    let suffix_u64 = suffix.as_canonical_u64();
                    std::eprintln!(
                        "debug: before_foreign_load stack0..15={stack_items:?} account_id_word={account_id_word} suffix_lsb=0x{suffix_lsb:02x}",
                        suffix_lsb = (suffix_u64 & 0xff)
                    );
                }
                let account_id_word = get_stack_word_le(process, 1);
                let account_id = AccountId::try_from([account_id_word[0], account_id_word[1]])
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
                let asset_word = get_stack_word_le(process, 1);
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
                let asset: Asset = get_stack_word_le(process, 1).try_into().map_err(|source| {
                    TransactionKernelError::MalformedAssetInEventHandler {
                        handler: "on_account_vault_after_remove_asset",
                        source,
                    }
                })?;

                Some(TransactionEvent::AccountVaultAfterRemoveAsset { asset })
            },
            TransactionEventId::AccountVaultAfterAddAsset => {
                // Expected stack state: [event, ASSET]
                let asset: Asset = get_stack_word_le(process, 1).try_into().map_err(|source| {
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
                let stack_top = get_stack_word_le(process, 1);
                let faucet_id =
                    AccountId::try_from([stack_top[0], stack_top[1]]).map_err(|err| {
                        TransactionKernelError::other_with_source(
                            "failed to convert faucet ID word into faucet ID",
                            err,
                        )
                    })?;
                let vault_root_ptr = stack_top[2];
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
                let asset_word = get_stack_word_le(process, 1);
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
                #[cfg(feature = "std")]
                if std::env::var("MIDEN_DEBUG_SLOT_PTR").is_ok() {
                    println!("debug: AccountStorageAfterSetItem slot_ptr={slot_ptr}");
                }
                let new_value = get_stack_word_le(process, 2);

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
                #[cfg(feature = "std")]
                if std::env::var("MIDEN_DEBUG_SLOT_PTR").is_ok() {
                    println!("debug: AccountStorageBeforeGetMapItem slot_ptr={slot_ptr}");
                }
                let map_key = get_stack_word_le(process, 2);

                on_account_storage_map_item_accessed(base_host, process, slot_ptr, map_key)?
            },

            TransactionEventId::AccountStorageBeforeSetMapItem => {
                // Expected stack state: [event, slot_ptr, KEY]
                let slot_ptr = process.get_stack_item(1);
                #[cfg(feature = "std")]
                if std::env::var("MIDEN_DEBUG_SLOT_PTR").is_ok() {
                    println!("debug: AccountStorageBeforeSetMapItem slot_ptr={slot_ptr}");
                }
                let map_key = get_stack_word_le(process, 2);

                on_account_storage_map_item_accessed(base_host, process, slot_ptr, map_key)?
            },

            TransactionEventId::AccountStorageAfterSetMapItem => {
                // Expected stack state: [event, slot_ptr, KEY, OLD_VALUE, NEW_VALUE]
                let slot_ptr = process.get_stack_item(1);
                #[cfg(feature = "std")]
                if std::env::var("MIDEN_DEBUG_SLOT_PTR").is_ok() {
                    println!("debug: AccountStorageAfterSetMapItem slot_ptr={slot_ptr}");
                }
                let key = get_stack_word_le(process, 2);
                let old_value = get_stack_word_le(process, 6);
                let new_value = get_stack_word_le(process, 10);

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
                let procedure_root = get_stack_word_le(process, 1);
                let code_commitment = process.get_active_account_code_commitment()?;

                Some(TransactionEvent::AccountPushProcedureIndex {
                    code_commitment,
                    procedure_root,
                })
            },

            TransactionEventId::NoteBeforeCreated => {
                #[cfg(feature = "std")]
                if std::env::var("MIDEN_DEBUG_NOTE_BEFORE_CREATED").is_ok() {
                    let tag = process.get_stack_item(1).as_canonical_u64();
                    let aux = process.get_stack_item(2).as_canonical_u64();
                    let note_type = process.get_stack_item(3).as_canonical_u64();
                    let execution_hint = process.get_stack_item(4).as_canonical_u64();
                    let recipient = get_stack_word_le(process, 5);
                    let active_account = process
                        .get_active_account_id()
                        .map(|id| (id.prefix().as_felt().as_canonical_u64(), id.suffix()))
                        .ok();
                    std::eprintln!(
                        "debug note before created: tag={tag} aux={aux} note_type={note_type} execution_hint={execution_hint} recipient={:?} active_account={active_account:?}",
                        recipient
                            .iter()
                            .map(|v| v.as_canonical_u64())
                            .collect::<Vec<_>>()
                    );
                }
                None
            },

            TransactionEventId::NoteAfterCreated => {
                // Expected stack state: [event, NOTE_METADATA, note_ptr, RECIPIENT, note_idx]
                let metadata_word = get_stack_word_le(process, 1);
                #[cfg(feature = "std")]
                if std::env::var("MIDEN_DEBUG_NOTE_METADATA").is_ok() {
                    std::eprintln!(
                        "debug note metadata word={:?}",
                        metadata_word
                            .iter()
                            .map(|v| v.as_canonical_u64())
                            .collect::<Vec<_>>()
                    );
                }
                let metadata = NoteMetadata::try_from(metadata_word)
                    .map_err(TransactionKernelError::MalformedNoteMetadata)?;

                let recipient_digest = get_stack_word_le(process, 6);
                let note_idx = process.get_stack_item(10).as_canonical_u64() as usize;

                // try to read the full recipient from the advice provider
                let recipient_data = if process.has_advice_map_entry(recipient_digest) {
                    let (note_inputs, script_root, serial_num) =
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
                                NoteRecipient::new(serial_num, note_script, note_inputs);

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
                            note_inputs,
                        },
                    }
                } else {
                    RecipientData::Digest(recipient_digest)
                };

                Some(TransactionEvent::NoteAfterCreated { note_idx, metadata, recipient_data })
            },

            TransactionEventId::NoteBeforeAddAsset => {
                // Expected stack state: [event, ASSET, note_ptr, num_of_assets, note_idx]
                let note_idx = process.get_stack_item(7).as_canonical_u64() as usize;

                let asset_word = get_stack_word_le(process, 1);
                let asset = Asset::try_from(asset_word).map_err(|source| {
                    TransactionKernelError::MalformedAssetInEventHandler {
                        handler: "on_note_before_add_asset",
                        source,
                    }
                })?;

                Some(TransactionEvent::NoteBeforeAddAsset { note_idx, asset })
            },

            TransactionEventId::NoteAfterAddAsset => None,

            TransactionEventId::AuthRequest => {
                // Expected stack state: [event, MESSAGE, PUB_KEY]
                let message = get_stack_word_le(process, 1);
                let pub_key_hash = get_stack_word_le(process, 5);
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
                let message = get_stack_word_le(process, 1);
                let tx_summary = extract_tx_summary(base_host, process, message)?;

                Some(TransactionEvent::Unauthorized { tx_summary })
            },

            TransactionEventId::EpilogueBeforeTxFeeRemovedFromAccount => {
                // Expected stack state: [event, FEE_ASSET]
                let fee_asset = get_stack_word_le(process, 1);
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
                TransactionProgressEvent::PrologueStart(process.clock()),
            )),
            TransactionEventId::PrologueEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::PrologueEnd(process.clock()),
            )),

            TransactionEventId::NotesProcessingStart => Some(TransactionEvent::Progress(
                TransactionProgressEvent::NotesProcessingStart(process.clock()),
            )),
            TransactionEventId::NotesProcessingEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::NotesProcessingEnd(process.clock()),
            )),

            TransactionEventId::NoteExecutionStart => {
                let note_id = process.get_active_note_id()?.ok_or_else(|| TransactionKernelError::other(
                    "note execution interval measurement is incorrect: check the placement of the start and the end of the interval",
                ))?;


                Some(TransactionEvent::Progress(TransactionProgressEvent::NoteExecutionStart {
                    note_id,
                    clk: process.clock(),
                }))
            },
            TransactionEventId::NoteExecutionEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::NoteExecutionEnd(process.clock()),
            )),

            TransactionEventId::TxScriptProcessingStart => Some(TransactionEvent::Progress(
                TransactionProgressEvent::TxScriptProcessingStart(process.clock()),
            )),
            TransactionEventId::TxScriptProcessingEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::TxScriptProcessingEnd(process.clock()),
            )),
            TransactionEventId::EpilogueStart => Some(TransactionEvent::Progress(
                TransactionProgressEvent::EpilogueStart(process.clock()),
            )),
            TransactionEventId::EpilogueEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::EpilogueEnd(process.clock()),
            )),

            TransactionEventId::EpilogueAuthProcStart => Some(TransactionEvent::Progress(
                TransactionProgressEvent::EpilogueAuthProcStart(process.clock()),
            )),
            TransactionEventId::EpilogueAuthProcEnd => Some(TransactionEvent::Progress(
                TransactionProgressEvent::EpilogueAuthProcEnd(process.clock()),
            )),

            TransactionEventId::EpilogueAfterTxCyclesObtained => Some(TransactionEvent::Progress(
                TransactionProgressEvent::EpilogueAfterTxCyclesObtained(process.clock()),
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
        note_inputs: NoteInputs,
    },
}

/// Checks if the necessary witness for accessing the asset identified by the vault key is already
/// in the merkle store, and:
/// - If so, returns `None`.
/// - If not, returns `Some` with all necessary data for requesting it.
fn on_account_vault_asset_accessed<'store, STORE>(
    base_host: &TransactionBaseHost<'store, STORE>,
    process: &ProcessorState,
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
    let has_path = process.has_merkle_path::<{ AssetVault::DEPTH }>(vault_root, leaf_index)?;
    if has_path {
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
    process: &ProcessorState,
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
    let hashed_map_key = StorageMap::hash_key(map_key);
    let leaf_index = StorageMap::hashed_map_key_to_leaf_index(hashed_map_key);

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

    let has_path = process.has_merkle_path::<{ StorageMap::DEPTH }>(current_map_root, leaf_index)?;
    #[cfg(feature = "std")]
    if std::env::var("MIDEN_DEBUG_STORAGE_MAP_ACCESS").is_ok() {
        let stack_items: Vec<Felt> = (0..64).map(|idx| process.get_stack_item(idx)).collect();
        std::eprintln!(
            "debug: storage_map_access account_id={active_account_id} slot_ptr={slot_ptr} map_root={current_map_root} map_key={map_key} hashed_key={hashed_map_key} leaf_index={leaf_index} has_path={has_path} stack0..63={stack_items:?}"
        );
    }

    if has_path {
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
    process: &ProcessorState,
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
