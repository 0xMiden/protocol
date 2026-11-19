//! Verifiable encryption for private P2ID notes.
//!
//! The sender encrypts each note's details to its recipient and produces one proof for a batch
//! of up to [`MAX_NOTES_PER_BATCH`] notes. The note transport service uses
//! [`verify_note_encryption_batch`] to check that each received envelope encrypts the details
//! committed to by the corresponding note header under the expected recipient key. The recipient
//! uses [`decrypt_note`] to recover those details.
//!
//! The program takes the number of notes as public input. Its public output is a hash of the
//! ordered list of (note ID, key commitment, envelope commitment) triples. The verifier derives
//! each note ID from the [`NoteHeader`], which contains public metadata and a commitment to the
//! note details. It computes the other commitments from the expected key and received envelope.
//! The transport service also checks note inclusion and authenticates the keys.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_crypto::ecdh::ecgfp5::{PublicKey, SecretKey};
use miden_crypto::hash::eidos::Eidos;
use miden_crypto::ies::SealedMessage;
use miden_crypto::ies::ecgfp5_eidos::{self, Envelope};
use miden_protocol::asset::Asset;
use miden_protocol::errors::ProofVerificationError;
use miden_protocol::note::{Note, NoteAssets, NoteDetails, NoteHeader, NoteId, NoteType};
use miden_protocol::utils::serde::{ByteWriter, Deserializable, Serializable};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::vm::{ExecutionProof, Package, Program, StackInputs, StackOutputs};
use miden_protocol::{
    DoubleWord,
    Felt,
    MIN_PROOF_SECURITY_LEVEL,
    Word,
    verify_execution_proof,
    word,
};
use miden_verifier::{ExecutionClaim, KernelDescriptor, VerificationError};
use thiserror::Error;

use super::P2idNoteStorage;

// CONSTANTS
// ================================================================================================

/// Maximum batch size accepted by the P2ID encryption sender and verifier.
///
/// The pinned proof program accepts up to eight notes.
pub const MAX_NOTES_PER_BATCH: usize = 2;

/// Wire identifier (format version, profile ID) for the v1 P2ID encryption format.
/// After release, assign a new pair if the encoding, note script root, proof program root,
/// or proof program's kernel descriptor changes.
const P2ID_V1_HEADER: [u8; 2] = [1, 1];

const FIXED_PLAINTEXT_LEN: usize = 2 * Word::NUM_ELEMENTS + P2idNoteStorage::NUM_ITEMS;
const MAX_PLAINTEXT_LEN: usize =
    FIXED_PLAINTEXT_LEN + DoubleWord::NUM_ELEMENTS * NoteAssets::MAX_NUM_ASSETS;
// Two format bytes, IES scheme, length-prefixed point (40 bytes), two-byte payload length,
// payload type, tag (16 bytes), and two u32 limbs per plaintext Felt.
const MAX_WIRE_LEN: usize = 2 + 1 + 1 + 40 + 2 + 1 + 16 + 8 * MAX_PLAINTEXT_LEN;

// ENCRYPTED NOTE
// ================================================================================================

/// Encrypted note details in the v1 P2ID transport format.
///
/// Construction and decoding check the envelope's format and length. Call
/// [`verify_note_encryption`] to verify that it encrypts the expected note under the expected key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedNote {
    envelope: Envelope,
}

impl EncryptedNote {
    /// Returns the underlying EcGFp5/Eidos envelope.
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// Reads exactly one v1 P2ID encrypted note, rejecting oversized or noncanonical encodings.
    pub fn read_from_bytes(bytes: &[u8]) -> Result<Self, NoteEncryptionError> {
        let payload = bytes
            .strip_prefix(&P2ID_V1_HEADER)
            .ok_or(NoteEncryptionError::InvalidEncoding)?;
        if bytes.len() > MAX_WIRE_LEN {
            return Err(NoteEncryptionError::InvalidLength);
        }
        let message = SealedMessage::read_from_bytes_with_budget(payload, payload.len())
            .map_err(|_| NoteEncryptionError::InvalidEncoding)?;
        // The common IES decoder accepts trailing bytes and alternate length encodings.
        if message.to_bytes() != payload {
            return Err(NoteEncryptionError::InvalidEncoding);
        }
        let envelope =
            Envelope::try_from(message).map_err(|_| NoteEncryptionError::InvalidEncoding)?;
        Self::try_from(envelope)
    }
}

impl TryFrom<Envelope> for EncryptedNote {
    type Error = NoteEncryptionError;

    fn try_from(envelope: Envelope) -> Result<Self, Self::Error> {
        // Each asset occupies a double word between the header, serial number, and P2ID storage.
        let len = envelope.ciphertext().len() / 2;
        let Some(asset_felts) = len.checked_sub(FIXED_PLAINTEXT_LEN) else {
            return Err(NoteEncryptionError::InvalidLength);
        };
        if !asset_felts.is_multiple_of(DoubleWord::NUM_ELEMENTS)
            || !(1..=NoteAssets::MAX_NUM_ASSETS).contains(&(asset_felts / DoubleWord::NUM_ELEMENTS))
        {
            return Err(NoteEncryptionError::InvalidLength);
        }
        Ok(Self { envelope })
    }
}

impl Serializable for EncryptedNote {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&P2ID_V1_HEADER);
        SealedMessage::from(self.envelope.clone()).write_into(target);
    }
}

// VERIFICATION
// ================================================================================================

/// Verifies that the received envelope encrypts the details committed to by the header under
/// the supplied recipient key. The caller checks header inclusion and supplies the expected key.
/// See [`verify_note_encryption_batch`] for the proof requirements.
pub fn verify_note_encryption(
    header: &NoteHeader,
    key: PublicKey,
    encrypted_note: &EncryptedNote,
    proof: &ExecutionProof,
) -> Result<(), NoteEncryptionError> {
    verify_note_encryption_batch(&[(header, key, encrypted_note)], proof)
}

/// Verifies one proof for an ordered batch of headers, expected recipient keys, and received
/// envelopes. The caller checks each header's inclusion and authenticates each recipient key.
///
/// The proof must use the protocol's transcript hash, contain no precompile work, and meet the
/// protocol's minimum conjectured security level.
pub fn verify_note_encryption_batch(
    entries: &[(&NoteHeader, PublicKey, &EncryptedNote)],
    proof: &ExecutionProof,
) -> Result<(), NoteEncryptionError> {
    if proof.has_precompiles() {
        return Err(NoteEncryptionError::UnsupportedProof);
    }
    let claim = p2id_batch_claim(entries)?;
    let outcome = verify_execution_proof(&claim, proof, MIN_PROOF_SECURITY_LEVEL)?;
    if !outcome.is_complete() {
        return Err(NoteEncryptionError::UnsupportedProof);
    }
    Ok(())
}

// DECRYPTION
// ================================================================================================

/// Authenticates the envelope and returns the decoded details after checking the header commitment.
pub fn decrypt_note(
    header: &NoteHeader,
    key: &SecretKey,
    encrypted_note: &EncryptedNote,
) -> Result<NoteDetails, NoteEncryptionError> {
    check_header(header)?;
    let [version, profile] = P2ID_V1_HEADER.map(Felt::from);
    let [n0, n1, n2, n3] = header.id().as_word().into_elements();
    let plaintext =
        ecgfp5_eidos::open(key, &[n0, n1, n2, n3, version, profile], &encrypted_note.envelope)
            .map_err(|_| NoteEncryptionError::Authentication)?;
    // The checked length fixes the split. The encrypted header must agree with that layout.
    let (fields, body) = plaintext.split_at(Word::NUM_ELEMENTS);
    let (serial, body) = body.split_first_chunk::<4>().expect("checked plaintext length");
    let (assets, storage) = body.split_at(body.len() - P2idNoteStorage::NUM_ITEMS);
    let (assets, _) = assets.as_chunks::<{ DoubleWord::NUM_ELEMENTS }>();
    if fields
        != [
            version,
            profile,
            Felt::from_u32(assets.len() as u32),
            Felt::from_u32(storage.len() as u32),
        ]
    {
        return Err(NoteEncryptionError::InvalidDetails);
    }
    let assets = assets
        .iter()
        .map(|asset| {
            let words = DoubleWord::try_from(asset.as_slice()).expect("one asset double word");
            Asset::from_id_and_value_words(words.lo(), words.hi())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NoteEncryptionError::InvalidDetails)?;
    let details = NoteDetails::new(
        NoteAssets::new(assets).map_err(|_| NoteEncryptionError::InvalidDetails)?,
        P2idNoteStorage::try_from(storage)
            .map_err(|_| NoteEncryptionError::InvalidDetails)?
            .into_recipient(Word::new(*serial)),
    );
    if details.commitment() != header.details_commitment() {
        return Err(NoteEncryptionError::HeaderMismatch);
    }
    Ok(details)
}

// PROOF CLAIM AND PROGRAM INTERFACE
// ================================================================================================

include!("encryption/p2id_v1_program_identity.rs");

/// Builds the claim for the v1 P2ID program from the expected headers and keys and the envelopes.
/// The output commits to the note ID, key commitment, and envelope commitment for each note
/// in submission order.
pub fn p2id_batch_claim(
    entries: &[(&NoteHeader, PublicKey, &EncryptedNote)],
) -> Result<ExecutionClaim, NoteEncryptionError> {
    let inputs = public_inputs(entries.iter().map(|(header, ..)| header.id()))?;
    let mut batch_elements = Vec::with_capacity(entries.len() * 3 * Word::NUM_ELEMENTS);
    for &(header, key, encrypted_note) in entries {
        check_header(header)?;
        batch_elements.extend(header.id().as_word());
        batch_elements.extend(key.to_commitment());
        batch_elements.extend(encrypted_note.envelope.to_commitment());
    }
    let batch_commitment =
        Eidos::hash_elements_in_domain(&batch_elements, crate::P2ID_ENCRYPTION_BATCH);
    let outputs = StackOutputs::new(batch_commitment.as_elements())
        .expect("one word fits on the output stack");
    let kernel = KernelDescriptor::new(&P2ID_V1_KERNEL_PROCEDURES)
        .expect("one kernel procedure is a valid kernel descriptor");
    Ok(ExecutionClaim::new(P2ID_V1_PROGRAM_ROOT, kernel, inputs, outputs))
}

/// Checks that the batch contains between one and [`MAX_NOTES_PER_BATCH`] distinct note IDs
/// and builds its public count input.
pub fn public_inputs(
    mut note_ids: impl ExactSizeIterator<Item = NoteId>,
) -> Result<StackInputs, NoteEncryptionError> {
    let note_count = note_ids.len();
    if !(1..=MAX_NOTES_PER_BATCH).contains(&note_count) {
        return Err(NoteEncryptionError::InvalidBatchSize);
    }
    let mut seen = BTreeSet::new();
    if note_ids.any(|id| !seen.insert(id)) {
        return Err(NoteEncryptionError::DuplicateNote);
    }
    Ok(StackInputs::new(&[Felt::from_u32(note_count as u32)])
        .expect("one count fits on the input stack"))
}

static P2ID_V1_PROGRAM: LazyLock<Program> = LazyLock::new(|| {
    // The Standards build script produces these package bytes.
    Package::read_from_bytes_trusted(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/p2id-envelope:p2id-envelope.masp"
    )))
    .expect("failed to deserialize the embedded P2ID encryption package")
    .try_into_program()
    .expect("P2ID encryption package should contain a program")
});

/// Returns the executable for the v1 P2ID profile.
pub fn program() -> &'static Program {
    &P2ID_V1_PROGRAM
}

/// Encodes one P2ID note for the advice stack of [`program`].
///
/// The caller supplies a note with the P2ID storage layout (target account ID suffix and prefix).
/// This function serializes the note ID, key commitment, asset count, serial number, assets,
/// storage, and metadata commitment in the order the program reads them.
pub fn p2id_note_advice(note: &Note, key: PublicKey) -> Vec<Felt> {
    let mut advice = Vec::new();
    advice.extend(note.id().as_word());
    advice.extend(key.to_commitment());
    advice.push(Felt::from_u32(note.assets().num_assets() as u32));
    advice.extend(note.recipient().serial_num());
    advice.extend(note.assets().to_elements());
    advice.extend(note.recipient().storage().items());
    advice.extend(note.metadata().to_commitment());
    advice
}

// HELPER FUNCTIONS
// ================================================================================================

fn check_header(header: &NoteHeader) -> Result<(), NoteEncryptionError> {
    if header.metadata().note_type() != NoteType::Private {
        return Err(NoteEncryptionError::PublicNote);
    }
    Ok(())
}

// NOTE ENCRYPTION ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum NoteEncryptionError {
    #[error("encryption batch contains a repeated note ID")]
    DuplicateNote,
    #[error("encryption batch must contain between 1 and {MAX_NOTES_PER_BATCH} notes")]
    InvalidBatchSize,
    #[error("expected a private note header")]
    PublicNote,
    #[error("unsupported or noncanonical encrypted note encoding")]
    InvalidEncoding,
    #[error("invalid P2ID envelope length")]
    InvalidLength,
    #[error("expected a complete VM proof using the protocol transcript hash")]
    UnsupportedProof,
    #[error("proof security of {actual} bits is below the required {required} bits")]
    InsufficientSecurity { actual: u32, required: u32 },
    #[error("invalid note encryption proof")]
    Proof(#[from] VerificationError),
    #[error("envelope authentication failed")]
    Authentication,
    #[error("invalid P2ID plaintext")]
    InvalidDetails,
    #[error("decrypted details do not match the note header")]
    HeaderMismatch,
}

impl From<ProofVerificationError> for NoteEncryptionError {
    fn from(error: ProofVerificationError) -> Self {
        match error {
            ProofVerificationError::UnsupportedVmProofHash { .. } => Self::UnsupportedProof,
            ProofVerificationError::InsufficientSecurityLevel { actual, required } => {
                Self::InsufficientSecurity { actual, required }
            },
            ProofVerificationError::VerificationFailed(error) => Self::Proof(error),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests;
