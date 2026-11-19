//! Sender-side proving for private P2ID note transport.
//!
//! The production VM prover uses non-hiding trace commitments. Sharing an execution proof
//! therefore carries no zero-knowledge guarantee for the note details or sealing secrets in
//! its witness. Deployments that require those values to stay private need a zero-knowledge
//! proving backend.

use alloc::vec::Vec;

use miden_core_lib::CoreLibrary;
use miden_core_lib::handlers::ecgfp5_eidos::Ecgfp5SealHandler;
use miden_processor::advice::AdviceError;
use miden_processor::{DefaultHost, ExecutionError, FastProcessor};
use miden_protocol::address::{Address, AddressId};
use miden_protocol::crypto::ecdh::ecgfp5::PublicKey;
use miden_protocol::crypto::ies::SealingKey;
use miden_protocol::crypto::ies::ecgfp5_eidos::Envelope;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::vm::{AdviceInputs, ExecutionProof};
use miden_protocol::{PROTOCOL_PROOF_HASH, ProtocolLib, Word};
use miden_prover::{Prover, ProverError};
use miden_standards::note::encryption::EncryptedNote;
use miden_standards::note::{P2idNote, P2idNoteStorage, encryption};
use rand::CryptoRng;
use thiserror::Error;

// NOTE ENCRYPTION PROVER
// ================================================================================================

/// Encrypts a private P2ID note to the address's sealing key and proves that the envelope contains
/// the details committed to by the note header.
///
/// Supply the recipient's address with its EcGFp5 sealing key and a cryptographic RNG for fresh
/// encryption randomness. The address's account ID must match the note's target.
pub fn encrypt_and_prove(
    note: &Note,
    address: &Address,
    rng: impl CryptoRng + Send + Sync + 'static,
) -> Result<(EncryptedNote, ExecutionProof), NoteEncryptionProverError> {
    let (mut encrypted_notes, proof) = encrypt_and_prove_batch(&[(note, address)], rng)?;
    Ok((encrypted_notes.pop().expect("one encrypted note"), proof))
}

/// Proves encryption for one to [`encryption::MAX_NOTES_PER_BATCH`] distinct private P2ID notes.
/// Each entry pairs a note with its recipient's address. The function returns the encrypted
/// notes in submission order and one proof covering the entire batch.
///
/// The proof must meet the protocol's minimum conjectured security level; otherwise this returns
/// an error reporting the observed and required security levels.
pub fn encrypt_and_prove_batch(
    entries: &[(&Note, &Address)],
    rng: impl CryptoRng + Send + Sync + 'static,
) -> Result<(Vec<EncryptedNote>, ExecutionProof), NoteEncryptionProverError> {
    let inputs = encryption::public_inputs(entries.iter().map(|(note, _)| note.id()))?;
    let mut keys = Vec::with_capacity(entries.len());
    let mut note_advice = Vec::new();
    let mut seal_handler = Ecgfp5SealHandler::new(rng);
    for &(note, address) in entries {
        let key = sealing_key(note, address)?;
        keys.push(key);
        seal_handler = seal_handler.with_public_key(key);
        note_advice.extend(encryption::p2id_note_advice(note, key));
    }
    let mut host = DefaultHost::default().with_library(&CoreLibrary::default())?;
    host.load_library(ProtocolLib::default().mast_forest())?;
    for (event, handler) in seal_handler.handlers() {
        host.register_handler(event, handler)?;
    }
    let (witness, output_advice) = FastProcessor::new(inputs)
        .with_advice(AdviceInputs::default().with_stack(note_advice.into()))?
        .execute_for_proving_with_advice_sync(encryption::program(), &mut host)?;
    let claim = witness.claim();

    // The public batch commitment locates the ordered entries in the advice map. Each entry
    // contains the note ID, key commitment, then the commitment used to look up its envelope.
    let batch_commitment = claim.stack_outputs().get_word(0).expect("one public output word");
    let batch_elements = output_advice
        .get_mapped_values(&batch_commitment)
        .ok_or(NoteEncryptionProverError::InvalidEnvelope)?;
    let (batch_entries, remainder) = batch_elements.as_chunks::<{ 3 * Word::NUM_ELEMENTS }>();
    if batch_entries.len() != entries.len() || !remainder.is_empty() {
        return Err(NoteEncryptionProverError::InvalidEnvelope);
    }
    let mut encrypted_notes = Vec::with_capacity(entries.len());
    for entry in batch_entries {
        let envelope_commitment = Word::new(
            entry[2 * Word::NUM_ELEMENTS..].try_into().expect("last word of a batch entry"),
        );
        let envelope_elements = output_advice
            .get_mapped_values(&envelope_commitment)
            .ok_or(NoteEncryptionProverError::InvalidEnvelope)?;
        let envelope = Envelope::from_elements(envelope_elements)
            .map_err(|_| NoteEncryptionProverError::InvalidEnvelope)?;
        encrypted_notes.push(
            EncryptedNote::try_from(envelope)
                .map_err(|_| NoteEncryptionProverError::InvalidEnvelope)?,
        );
    }

    // Check the claim using the requested headers and keys and the encrypted notes we will return.
    let records: Vec<_> = entries
        .iter()
        .zip(&keys)
        .zip(&encrypted_notes)
        .map(|(((note, _), &key), encrypted_note)| (note.header(), key, encrypted_note))
        .collect();
    if encryption::p2id_batch_claim(&records)? != claim {
        return Err(NoteEncryptionProverError::ClaimMismatch);
    }
    let proof = Prover::new().with_hash_fn(PROTOCOL_PROOF_HASH).prove_full(witness)?;
    // The verifier checks the security level at the actual trace height.
    encryption::verify_note_encryption_batch(&records, &proof)?;
    Ok((encrypted_notes, proof))
}

// HELPER FUNCTIONS
// ================================================================================================

fn sealing_key(note: &Note, address: &Address) -> Result<PublicKey, NoteEncryptionProverError> {
    if note.header().metadata().note_type() != NoteType::Private
        || note.recipient().script().root() != P2idNote::script_root()
        || note.assets().is_empty()
    {
        return Err(NoteEncryptionProverError::UnsupportedNote);
    }
    let target = P2idNoteStorage::try_from(note.recipient().storage().items())
        .map_err(|_| NoteEncryptionProverError::UnsupportedNote)?
        .target();
    let Some(SealingKey::Ecgfp5Eidos(key)) = address.encryption_key() else {
        return Err(NoteEncryptionProverError::InvalidAddress);
    };
    if address.id() != AddressId::AccountId(target) {
        return Err(NoteEncryptionProverError::InvalidAddress);
    }
    Ok(*key)
}

// NOTE ENCRYPTION PROVER ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum NoteEncryptionProverError {
    #[error(transparent)]
    Verification(#[from] encryption::NoteEncryptionError),
    #[error("expected a private P2ID note")]
    UnsupportedNote,
    #[error("the address must identify the note target and carry an EcGFp5 sealing key")]
    InvalidAddress,
    #[error("invalid sealing advice")]
    Advice(#[from] AdviceError),
    #[error("note encryption execution failed")]
    Execution(#[from] ExecutionError),
    #[error("invalid envelope exported by the encryption program")]
    InvalidEnvelope,
    #[error("the execution claim does not match the requested notes, keys, and exported envelopes")]
    ClaimMismatch,
    #[error("note encryption proof generation failed")]
    Proving(#[from] ProverError),
}
