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
    NoteExecutionHint,
    NoteMetadata,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_standards::note::NetworkAccountTarget;

use crate::{ExitRoot, update_ger_script};

/// Creates an UPDATE_GER note with the given GER (Global Exit Root) data.
///
/// The note storage contains 8 felts: GER[0..7]
pub fn create_update_ger_note<R: FeltRng>(
    ger: ExitRoot,
    sender_account_id: AccountId,
    target_account_id: AccountId,
    rng: &mut R,
) -> Result<Note, NoteError> {
    let update_ger_script = update_ger_script();

    // Create note storage with 8 felts: GER[0..7]
    let storage_values = ger.to_elements().to_vec();

    let note_storage = NoteStorage::new(storage_values)?;

    // Generate a serial number for the note
    let serial_num = rng.draw_word();

    let recipient = NoteRecipient::new(serial_num, update_ger_script, note_storage);

    let attachment = NoteAttachment::from(
        NetworkAccountTarget::new(target_account_id, NoteExecutionHint::Always)
            .map_err(|e| NoteError::other(e.to_string()))?,
    );
    let note_tag = NoteTag::new(0);
    let metadata = NoteMetadata::new(sender_account_id, NoteType::Public, note_tag)
        .with_attachment(attachment);

    // UPDATE_GER notes don't carry assets
    let assets = NoteAssets::new(vec![])?;

    Ok(Note::new(assets, metadata, recipient))
}
