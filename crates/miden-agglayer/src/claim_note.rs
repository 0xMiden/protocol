use alloc::vec;
use alloc::vec::Vec;

use miden_assembly::Library;
use miden_assembly::serde::Deserializable;
use miden_core::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::crypto::SequentialCommit;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachments,
    NoteRecipient,
    NoteScript,
    NoteScriptRoot,
    NoteStorage,
    NoteType,
    PartialNoteMetadata,
};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_utils_sync::LazyLock;

use crate::types::{LeafData, ProofData};

// NOTE SCRIPT
// ================================================================================================

// Initialize the CLAIM note script only once
static CLAIM_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/claim.masl"));
    let library =
        Library::read_from_bytes(bytes).expect("shipped CLAIM script library is well-formed");
    NoteScript::from_library(&library).expect("shipped CLAIM script is well-formed")
});

// CLAIM NOTE
// ================================================================================================

/// CLAIM (Bridge from AggLayer) note.
///
/// This note instructs the AggLayer bridge to validate a claim against its registered GERs and
/// emit a corresponding MINT note for the AggLayer faucet. CLAIM notes are always public.
pub struct ClaimNote;

impl ClaimNote {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the CLAIM (Bridge from AggLayer) note script.
    pub fn script() -> NoteScript {
        CLAIM_SCRIPT.clone()
    }

    /// Returns the CLAIM note script root.
    pub fn script_root() -> NoteScriptRoot {
        CLAIM_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates a CLAIM note — a note that instructs the bridge to validate a claim and create
    /// a MINT note for the AggLayer Faucet. CLAIM notes are always public.
    ///
    /// # Parameters
    /// - `storage`: The core storage for creating the CLAIM note
    /// - `target_bridge_id`: The account ID of the bridge that should consume this note. Encoded as
    ///   a `NetworkAccountTarget` attachment on the note metadata.
    /// - `sender_account_id`: The account ID of the CLAIM note creator
    /// - `rng`: Random number generator for creating the CLAIM note serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        storage: ClaimNoteStorage,
        target_bridge_id: AccountId,
        sender_account_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let note_storage = NoteStorage::try_from(storage)?;

        let attachment = NetworkAccountTarget::new(target_bridge_id, NoteExecutionHint::Always)
            .map_err(|error| {
                NoteError::other_with_source("failed to create claim network account target", error)
            })?;
        let attachments = NoteAttachments::from(NoteAttachment::from(attachment));

        let metadata = PartialNoteMetadata::new(sender_account_id, NoteType::Public);

        let recipient = NoteRecipient::new(rng.draw_word(), Self::script(), note_storage);
        let assets = NoteAssets::new(vec![])?;

        Ok(Note::with_attachments(assets, metadata, recipient, attachments))
    }
}

/// Data for creating a CLAIM note.
///
/// This struct groups the core data needed to create a CLAIM note that exactly
/// matches the agglayer claimAsset function signature.
#[derive(Clone)]
pub struct ClaimNoteStorage {
    /// Proof data containing SMT proofs and root hashes
    pub proof_data: ProofData,
    /// Leaf data containing network, address, amount, and metadata
    pub leaf_data: LeafData,
    /// Miden claim amount (scaled-down token amount as Felt)
    pub miden_claim_amount: Felt,
}

impl TryFrom<ClaimNoteStorage> for NoteStorage {
    type Error = NoteError;

    fn try_from(storage: ClaimNoteStorage) -> Result<Self, Self::Error> {
        // proof_data + leaf_data + miden_claim_amount
        // 536 + 32 + 1
        let mut claim_storage = Vec::with_capacity(569);

        claim_storage.extend(storage.proof_data.to_elements());
        claim_storage.extend(storage.leaf_data.to_elements());
        claim_storage.push(storage.miden_claim_amount);

        NoteStorage::new(claim_storage)
    }
}
