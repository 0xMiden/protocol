use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::testing::{dummy_deferred_execution_proof, dummy_execution_proof};
use miden_protocol::vm::HashFunction;
use miden_verifier::StarkProof;

use super::*;
use crate::note::P2idNote;

fn note(note_type: NoteType) -> Note {
    P2idNote::builder()
        .sender(ACCOUNT_ID_SENDER.try_into().unwrap())
        .target(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into().unwrap())
        .serial_number(Word::new([1, 2, 3, 4].map(Felt::from_u32)))
        .note_type(note_type)
        .assets([FungibleAsset::mock(100)])
        .build()
        .unwrap()
        .into()
}

fn secret_key() -> SecretKey {
    let mut bytes = [0; 40];
    bytes[0] = 7;
    SecretKey::from_bytes(&bytes).unwrap()
}

// Native sealing lets these tests authenticate malformed plaintext that the proof program rejects.
fn seal_plaintext(header: &NoteHeader, plaintext: &[Felt]) -> Envelope {
    let mut context = header.id().as_word().as_elements().to_vec();
    context.extend(P2ID_V1_HEADER.map(Felt::from));
    let secret = secret_key();
    ecgfp5_eidos::seal_with_scalar(&secret.public_key(), plaintext, &context, &secret).unwrap()
}

fn encode_details(note: &Note) -> Vec<Felt> {
    let [version, profile] = P2ID_V1_HEADER.map(Felt::from);
    let mut plaintext = vec![
        version,
        profile,
        Felt::from_u32(note.assets().num_assets() as u32),
        Felt::from_u32(P2idNoteStorage::NUM_ITEMS as u32),
    ];
    plaintext.extend(note.recipient().serial_num());
    plaintext.extend(note.assets().to_elements());
    plaintext.extend(note.recipient().storage().items());
    plaintext
}

/// Seals `plaintext` under the note's header and returns what the recipient decrypts.
fn decrypt_sealed(note: &Note, plaintext: &[Felt]) -> Result<NoteDetails, NoteEncryptionError> {
    let encrypted = EncryptedNote::try_from(seal_plaintext(note.header(), plaintext)).unwrap();
    decrypt_note(note.header(), &secret_key(), &encrypted)
}

#[test]
fn recipient_rejects_authenticated_details_for_another_note() {
    let note = note(NoteType::Private);
    let mut plaintext = encode_details(&note);
    plaintext[Word::NUM_ELEMENTS] += Felt::ONE; // Different serial number, same sealing context.
    assert!(matches!(
        decrypt_sealed(&note, &plaintext),
        Err(NoteEncryptionError::HeaderMismatch)
    ));
}

#[test]
fn recipient_rejects_authenticated_invalid_plaintext() {
    let note = note(NoteType::Private);
    let plaintext = encode_details(&note);
    let assert_invalid = |changed: &[Felt]| {
        assert!(matches!(
            decrypt_sealed(&note, changed),
            Err(NoteEncryptionError::InvalidDetails)
        ));
    };

    // Version, profile, asset count, and storage count must agree with the supported layout.
    for field in 0..Word::NUM_ELEMENTS {
        let mut changed = plaintext.clone();
        changed[field] += Felt::ONE;
        assert_invalid(&changed);
    }
    let mut invalid_asset = plaintext.clone();
    invalid_asset[2 * Word::NUM_ELEMENTS..2 * Word::NUM_ELEMENTS + DoubleWord::NUM_ELEMENTS]
        .fill(Felt::ZERO);
    assert_invalid(&invalid_asset);

    let mut invalid_target = plaintext;
    let storage_start = invalid_target.len() - P2idNoteStorage::NUM_ITEMS;
    invalid_target[storage_start] += Felt::ONE;
    assert_invalid(&invalid_target);
}

#[test]
fn claim_depends_on_each_envelope_field() {
    let note = note(NoteType::Private);
    let key = secret_key().public_key();
    let envelope = seal_plaintext(note.header(), &encode_details(&note));
    let claim = |elements: &[Felt]| {
        let encrypted =
            EncryptedNote::try_from(Envelope::from_elements(elements).unwrap()).unwrap();
        p2id_batch_claim(&[(note.header(), key, &encrypted)]).unwrap()
    };
    let elements = envelope.to_elements();
    let expected = claim(&elements);

    // The encoding is the ephemeral key, two tag limbs, the plaintext length, then the
    // ciphertext limbs. Replace the ephemeral key with another valid point.
    let mut other_scalar = [0; 40];
    other_scalar[0] = 11;
    let other_key = SecretKey::from_bytes(&other_scalar).unwrap().public_key().to_elements();
    let mut changed = elements.clone();
    changed[..other_key.len()].copy_from_slice(&other_key);
    assert!(claim(&changed) != expected, "changed the ephemeral key");

    // Change each tag limb and ciphertext limb. The ciphertext fixes the plaintext length.
    let plaintext_len = other_key.len() + 2;
    for index in (other_key.len()..elements.len()).filter(|&index| index != plaintext_len) {
        let mut changed = elements.clone();
        changed[index] = Felt::try_from(changed[index].as_canonical_u64() ^ 1).unwrap();
        assert!(claim(&changed) != expected, "changed element {index}");
    }
}

#[test]
fn verifier_rejects_precompile_work_and_other_transcript_hashes() {
    let note = note(NoteType::Private);
    let encrypted =
        EncryptedNote::try_from(seal_plaintext(note.header(), &encode_details(&note))).unwrap();
    let entries = [(note.header(), secret_key().public_key(), &encrypted)];

    let (compatibility, mut vm, precompile) = dummy_execution_proof().into_parts();
    vm.proof = StarkProof::new(Vec::new(), HashFunction::Blake3_256);
    let other_hash = ExecutionProof::from_parts(compatibility, vm, precompile);
    for proof in [dummy_deferred_execution_proof(), other_hash] {
        assert!(matches!(
            verify_note_encryption_batch(&entries, &proof),
            Err(NoteEncryptionError::UnsupportedProof)
        ));
    }
}

#[test]
fn public_headers_are_rejected_by_claim_construction_and_decryption() {
    let note = note(NoteType::Public);
    let encrypted =
        EncryptedNote::try_from(seal_plaintext(note.header(), &encode_details(&note))).unwrap();
    assert!(matches!(
        p2id_batch_claim(&[(note.header(), secret_key().public_key(), &encrypted)]),
        Err(NoteEncryptionError::PublicNote)
    ));
    assert!(matches!(
        decrypt_note(note.header(), &secret_key(), &encrypted),
        Err(NoteEncryptionError::PublicNote)
    ));
}

#[test]
fn encrypted_note_encoding_is_canonical_and_bounded() {
    let note = note(NoteType::Private);
    let envelope = seal_plaintext(note.header(), &vec![Felt::ZERO; MAX_PLAINTEXT_LEN]);
    let encrypted = EncryptedNote::try_from(envelope).unwrap();
    let valid = encrypted.to_bytes();
    assert_eq!(valid.len(), MAX_WIRE_LEN);
    assert_eq!(&valid[..2], &P2ID_V1_HEADER);
    assert_eq!(EncryptedNote::read_from_bytes(&valid).unwrap(), encrypted);

    assert!(matches!(
        EncryptedNote::read_from_bytes(&[valid.as_slice(), &[0]].concat()),
        Err(NoteEncryptionError::InvalidLength)
    ));
    // Use a shorter envelope so trailing data reaches the canonical-encoding check.
    let encrypted =
        EncryptedNote::try_from(seal_plaintext(note.header(), &encode_details(&note))).unwrap();
    let valid = encrypted.to_bytes();
    // The 40-byte point has length prefix [81]; [162, 0] encodes 40 in two bytes.
    for bad in [
        [&valid[..3], &[162, 0], &valid[4..]].concat(),
        [&valid[..3], usize::MAX.to_bytes().as_slice(), &valid[4..]].concat(),
        vec![],
        [valid.as_slice(), &[0]].concat(),
        valid[..valid.len() - 1].to_vec(),
        [&[2], &valid[1..]].concat(),
        [&valid[..1], &[2], &valid[2..]].concat(),
    ] {
        assert!(matches!(
            EncryptedNote::read_from_bytes(&bad),
            Err(NoteEncryptionError::InvalidEncoding)
        ));
    }

    // Empty plaintext, no assets, a partial asset, and one asset beyond the limit.
    for len in [
        0,
        FIXED_PLAINTEXT_LEN,
        FIXED_PLAINTEXT_LEN + 1,
        MAX_PLAINTEXT_LEN + DoubleWord::NUM_ELEMENTS,
    ] {
        let envelope = seal_plaintext(note.header(), &vec![Felt::ZERO; len]);
        let bytes = [
            P2ID_V1_HEADER.as_slice(),
            SealedMessage::from(envelope.clone()).to_bytes().as_slice(),
        ]
        .concat();
        assert!(matches!(
            EncryptedNote::try_from(envelope),
            Err(NoteEncryptionError::InvalidLength)
        ));
        assert!(matches!(
            EncryptedNote::read_from_bytes(&bytes),
            Err(NoteEncryptionError::InvalidLength)
        ));
    }
}
