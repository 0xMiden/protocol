//! Shared construction for the GER note builders (UPDATE_GER and REMOVE_GER).
//!
//! Both notes carry the same payload (8 felts of GER data), target the bridge account, are
//! always public, and carry no assets; they differ only in the note script they reference.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachments,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteType,
    PartialNoteMetadata,
};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};

use crate::ExitRoot;

/// Creates a GER note (UPDATE_GER or REMOVE_GER) carrying the given GER data and running the
/// provided note `script`.
///
/// The two GER notes are structurally identical - 8 felts of GER storage, a network-account
/// target on the bridge, public metadata, and no assets - so this helper holds their shared
/// construction and each note type only supplies its own script.
///
/// The note storage contains 8 felts: GER[0..7].
///
/// # Parameters
/// - `ger`: the Global Exit Root data the note carries
/// - `sender_account_id`: the account ID of the note creator (the GER manager or remover)
/// - `target_account_id`: the account ID that will consume this note (the bridge account)
/// - `script`: the note script to run (UPDATE_GER or REMOVE_GER)
/// - `rng`: random number generator for the note serial number
///
/// # Errors
/// Returns an error if note creation fails.
pub(crate) fn create_ger_note<R: FeltRng>(
    ger: ExitRoot,
    sender_account_id: AccountId,
    target_account_id: AccountId,
    script: NoteScript,
    rng: &mut R,
) -> Result<Note, NoteError> {
    // Create note storage with 8 felts: GER[0..7]
    let storage_values = ger.to_elements().to_vec();
    let note_storage = NoteStorage::new(storage_values)?;

    // Generate a serial number for the note
    let serial_num = rng.draw_word();

    let recipient = NoteRecipient::new(serial_num, script, note_storage);

    let attachment = NetworkAccountTarget::new(target_account_id, NoteExecutionHint::Always)
        .map_err(|e| NoteError::other(e.to_string()))?;
    let attachments = NoteAttachments::from(NoteAttachment::from(attachment));
    let metadata = PartialNoteMetadata::new(sender_account_id, NoteType::Public);

    // GER notes don't carry assets
    let assets = NoteAssets::new(vec![])?;

    Ok(Note::with_attachments(assets, metadata, recipient, attachments))
}
