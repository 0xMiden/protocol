//! Exercises private P2ID note encryption from proof generation through recipient recovery.

use miden_core::mast::error_code_from_msg;
use miden_core_lib::CoreLibrary;
use miden_core_lib::handlers::ecgfp5_eidos::Ecgfp5SealHandler;
use miden_crypto::ecdh::ecgfp5::{PublicKey, SecretKey};
use miden_crypto::ies::SealingKey;
use miden_crypto::ies::ecgfp5_eidos::Envelope;
use miden_processor::advice::AdviceInputs;
use miden_processor::operation::OperationError;
use miden_processor::{DefaultHost, ExecutionError, ExecutionOutput, FastProcessor};
use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
use miden_protocol::address::{Address, AddressInterface, RoutingParameters};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::note::{Note, NoteAssets, NoteId, NoteRecipient, NoteStorage, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::utils::serde::Serializable;
use miden_protocol::vm::{StackInputs, StackOutputs};
use miden_protocol::{DoubleWord, Felt, Hasher, PROTOCOL_PROOF_HASH, ProtocolLib, Word};
use miden_standards::P2ID_ENCRYPTION_BATCH;
use miden_standards::note::encryption::{
    EncryptedNote,
    MAX_NOTES_PER_BATCH,
    NoteEncryptionError,
    decrypt_note,
    p2id_batch_claim,
    p2id_note_advice,
    program,
    public_inputs,
    verify_note_encryption,
    verify_note_encryption_batch,
};
use miden_standards::note::{P2idNote, P2idNoteStorage};
use miden_tx::Prover;
use miden_tx::note_encryption::{
    NoteEncryptionProverError,
    encrypt_and_prove,
    encrypt_and_prove_batch,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const PROGRAM_MAX_NOTES: usize = 8; // MAX_NOTES in the P2ID encryption program.

#[test]
fn prove_private_p2id_note_round_trip() {
    // The recipient publishes the sealing key in their address and keeps the secret key.
    let recipient_secret = secret_key(7);
    let recipient_key = recipient_secret.public_key();
    let p2id = p2id_note(fungible_assets([1]));
    let recipient_address = address_with_sealing_key(p2id.target(), recipient_key);
    let note = Note::from(p2id);

    // The sender submits the public header, encoded envelope, and proof.
    let rng = ChaCha20Rng::from_seed([42; 32]); // Fixed seed for the test.
    let (encrypted_note, proof) = encrypt_and_prove(&note, &recipient_address, rng).unwrap();
    let bytes = encrypted_note.to_bytes();
    let header = note.header();

    // The note transport service verifies the encryption proof before storing the encrypted note.
    let received_note = EncryptedNote::read_from_bytes(&bytes).unwrap();
    verify_note_encryption(header, recipient_key, &received_note, &proof).unwrap();

    // The recipient uses the secret key to recover the original note details.
    let details = decrypt_note(header, &recipient_secret, &received_note).unwrap();
    assert_eq!(&details, note.details());
}

fn secret_key(scalar: u8) -> SecretKey {
    let mut bytes = [0; 40];
    bytes[0] = scalar;
    SecretKey::from_bytes(&bytes).unwrap()
}

fn fungible_assets(faucets: impl IntoIterator<Item = u8>) -> Vec<Asset> {
    faucets
        .into_iter()
        .map(|seed| {
            let faucet = AccountId::dummy(
                [seed; 15],
                AccountIdVersion::Version1,
                AccountType::Public,
                AssetCallbackFlag::Disabled,
            );
            FungibleAsset::new(faucet, 1000 + u64::from(seed)).unwrap().into()
        })
        .collect()
}

fn p2id_note(assets: Vec<Asset>) -> P2idNote {
    P2idNote::builder()
        .sender(ACCOUNT_ID_SENDER.try_into().unwrap())
        .target(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into().unwrap())
        .serial_number(Word::new([1, 2, 3, 4].map(Felt::from_u32)))
        .note_type(NoteType::Private)
        .assets(assets)
        .build()
        .unwrap()
}

fn address_with_sealing_key(target: AccountId, key: PublicKey) -> Address {
    Address::new(target).with_routing_parameters(
        RoutingParameters::new(AddressInterface::BasicWallet)
            .with_encryption_key(SealingKey::Ecgfp5Eidos(key)),
    )
}

fn sealing_host(key: PublicKey) -> DefaultHost {
    let mut host = DefaultHost::default().with_library(&CoreLibrary::default()).unwrap();
    host.load_library(ProtocolLib::default().mast_forest()).unwrap();
    let sealing = Ecgfp5SealHandler::new(ChaCha20Rng::from_seed([42; 32])).with_public_key(key);
    for (event, handler) in sealing.handlers() {
        host.register_handler(event, handler).unwrap();
    }
    host
}

fn execute_program(
    note_count: u32,
    key: PublicKey,
    advice: Vec<Felt>,
) -> Result<ExecutionOutput, ExecutionError> {
    let inputs = StackInputs::new(&[Felt::from_u32(note_count)]).unwrap();
    FastProcessor::new(inputs)
        .with_advice(AdviceInputs::default().with_stack(advice.into()))
        .unwrap()
        .execute_sync(program(), &mut sealing_host(key))
}

fn assert_rejected(result: Result<ExecutionOutput, ExecutionError>, message: &str) {
    let Err(error) = result else {
        panic!("expected assertion `{message}`");
    };
    assert!(
        matches!(
            error,
            ExecutionError::OperationError {
                err: OperationError::FailedAssertion { err_code, .. }
                    | OperationError::U32AssertionFailed { err_code, .. },
                ..
            } if err_code == error_code_from_msg(message)
        ),
        "expected `{message}`, got {error:?}"
    );
}

#[test]
fn sender_rejects_unsupported_scripts_and_invalid_addresses() {
    let key = secret_key(7).public_key();
    let p2id = p2id_note(fungible_assets([1]));
    let target = p2id.target();
    let address = address_with_sealing_key(target, key);
    let note = Note::from(p2id);
    let rng = || ChaCha20Rng::from_seed([42; 32]);
    let other_script = NoteRecipient::new(
        note.recipient().serial_num(),
        miden_standards::note::StandardNote::P2IDE.script(),
        note.recipient().storage().clone(),
    );
    let unsupported =
        Note::new(note.assets().clone(), *note.metadata().partial_metadata(), other_script);
    assert!(matches!(
        encrypt_and_prove(&unsupported, &address, rng()),
        Err(NoteEncryptionProverError::UnsupportedNote)
    ));

    let other_target: AccountId = ACCOUNT_ID_SENDER.try_into().unwrap();
    for invalid_address in [Address::new(target), address_with_sealing_key(other_target, key)] {
        assert!(matches!(
            encrypt_and_prove(&note, &invalid_address, rng()),
            Err(NoteEncryptionProverError::InvalidAddress)
        ));
    }
}

#[test]
fn rejects_incorrect_openings_and_asset_counts() {
    let key = secret_key(7).public_key();
    let note = Note::from(p2id_note(fungible_assets(1..=2)));
    let advice = p2id_note_advice(&note, key);
    // The note ID and key commitment precede the asset count and serial number.
    let num_assets = 2 * Word::NUM_ELEMENTS;
    let serial_num = num_assets + 1;
    let first_asset_value = serial_num + DoubleWord::NUM_ELEMENTS;
    let target_suffix = advice.len() - Word::NUM_ELEMENTS - P2idNote::NUM_STORAGE_ITEMS;

    // Change the serial number, an asset value, the target, and the metadata commitment.
    // Adding 256 to the suffix preserves the account ID's structure.
    for (index, delta) in [
        (serial_num, 1),
        (first_asset_value, 1),
        (target_suffix, 256),
        (advice.len() - 1, 1),
    ] {
        let mut changed = advice.clone();
        changed[index] += Felt::from_u32(delta);
        assert_rejected(execute_program(1, key, changed), "plaintext does not open the note ID");
    }

    for (count, message) in [
        (Felt::ZERO, "a P2ID note must contain at least one asset"),
        (
            Felt::from_u32(NoteAssets::MAX_NUM_ASSETS as u32 + 1),
            "number of assets exceeds the note limit",
        ),
        (Felt::try_from(1u64 << 32).unwrap(), "number of assets must fit in a u32"),
    ] {
        let mut changed = advice.clone();
        changed[num_assets] = count;
        assert_rejected(execute_program(1, key, changed), message);
    }
}

#[test]
fn validates_the_p2id_target_like_the_rust_decoder() {
    let key = secret_key(7);
    let base = p2id_note(fungible_assets([1]));
    let target = base.target();
    let base = Note::from(base);
    let suffix = target.suffix().as_canonical_u64();
    let prefix = target.prefix().as_felt().as_canonical_u64();

    for (suffix, prefix, error) in [
        (suffix, prefix ^ 0x10, None), // account type
        (suffix, prefix ^ 0x20, None), // asset callback flag
        (
            suffix | 1,
            prefix,
            Some("least significant byte of the account ID suffix must be zero"),
        ),
        (
            suffix | 1 << 63,
            prefix,
            Some("most significant bit of the account ID suffix must be zero"),
        ),
        (suffix, prefix & !0xf, Some("unknown version in account ID")),
        (suffix, (prefix & !0xf) | 2, Some("unknown version in account ID")),
    ] {
        let storage = [suffix, prefix].map(|value| Felt::try_from(value).unwrap());
        assert_eq!(P2idNoteStorage::try_from(storage.as_slice()).is_err(), error.is_some());

        // Commit to the supplied storage even if it fails the P2ID decoder.
        let recipient = NoteRecipient::new(
            base.recipient().serial_num(),
            P2idNote::script(),
            NoteStorage::new(storage.to_vec()).unwrap(),
        );
        let note = Note::new(base.assets().clone(), *base.metadata().partial_metadata(), recipient);
        let advice = p2id_note_advice(&note, key.public_key());
        if let Some(message) = error {
            assert_rejected(execute_program(1, key.public_key(), advice), message);
        } else {
            execute_program(1, key.public_key(), advice).unwrap();
        }
    }
}

#[test]
fn prove_batch_binds_order_keys_and_received_envelopes() {
    let a = p2id_note(fungible_assets(1..=NoteAssets::MAX_NUM_ASSETS as u8));
    let b = P2idNote::builder()
        .sender(a.sender())
        .target(ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap())
        .serial_number(a.serial_number())
        .note_type(NoteType::Private)
        .assets(fungible_assets([1]))
        .build()
        .unwrap();
    let [sk_a, sk_b] = [7, 11].map(secret_key);
    let keys = [sk_a.public_key(), sk_b.public_key()];
    let addresses = [
        address_with_sealing_key(a.target(), keys[0]),
        address_with_sealing_key(b.target(), keys[1]),
    ];
    let [a, b] = [a, b].map(Note::from);
    let rng = ChaCha20Rng::from_seed([23; 32]);
    let (encrypted_notes, proof) =
        encrypt_and_prove_batch(&[(&a, &addresses[0]), (&b, &addresses[1])], rng).unwrap();
    let [ea, eb]: [EncryptedNote; 2] = encrypted_notes.try_into().unwrap();
    let entries = [(a.header(), keys[0], &ea), (b.header(), keys[1], &eb)];
    verify_note_encryption_batch(&entries, &proof).unwrap();
    for (note, secret, encrypted_note) in [(&a, &sk_a, &ea), (&b, &sk_b, &eb)] {
        assert_eq!(&decrypt_note(note.header(), secret, encrypted_note).unwrap(), note.details());
    }
    assert!(matches!(
        decrypt_note(a.header(), &sk_b, &ea),
        Err(NoteEncryptionError::Authentication)
    ));
    assert!(matches!(
        decrypt_note(b.header(), &sk_a, &ea),
        Err(NoteEncryptionError::Authentication)
    ));
    assert!(matches!(
        verify_note_encryption_batch(&entries[..1], &proof),
        Err(NoteEncryptionError::Proof(_))
    ));
    assert!(matches!(
        verify_note_encryption_batch(&[entries[0], entries[0]], &proof),
        Err(NoteEncryptionError::DuplicateNote)
    ));
    let other_note = Note::from(p2id_note(fungible_assets([2])));
    // Change one ciphertext limb while holding the header, key, and rest of the envelope fixed.
    let mut elements = ea.envelope().to_elements();
    let first_ciphertext_limb = elements.len() - ea.envelope().ciphertext().len();
    elements[first_ciphertext_limb] =
        Felt::try_from(elements[first_ciphertext_limb].as_canonical_u64() ^ 1).unwrap();
    let changed_ciphertext =
        EncryptedNote::try_from(Envelope::from_elements(&elements).unwrap()).unwrap();
    assert!(matches!(
        decrypt_note(a.header(), &sk_a, &changed_ciphertext),
        Err(NoteEncryptionError::Authentication)
    ));
    for changed in [
        [entries[1], entries[0]],
        [(a.header(), keys[1], &ea), (b.header(), keys[0], &eb)],
        [(a.header(), keys[0], &eb), (b.header(), keys[1], &ea)],
        [(other_note.header(), keys[0], &ea), entries[1]],
        [(a.header(), keys[0], &changed_ciphertext), entries[1]],
    ] {
        assert!(matches!(
            verify_note_encryption_batch(&changed, &proof),
            Err(NoteEncryptionError::Proof(_))
        ));
    }
}

#[test]
fn prove_and_reject_wrong_program() {
    let note = Note::from(p2id_note(fungible_assets([1])));
    let secret = secret_key(7);
    let key = secret.public_key();
    let envelope =
        miden_crypto::ies::ecgfp5_eidos::seal_with_scalar(&key, &[Felt::ZERO; 18], &[], &secret)
            .unwrap();
    let encrypted = EncryptedNote::try_from(envelope).unwrap();
    let entries = [(note.header(), key, &encrypted)];

    // Give the other program the same kernel and public stacks to isolate its program root.
    let expected = p2id_batch_claim(&entries).unwrap();
    let other = TransactionKernel::assembler()
        .assemble_program("echo", "begin adv_loadw end")
        .unwrap()
        .try_into_program()
        .unwrap();
    let advice = expected.stack_outputs().get_word(0).unwrap().as_elements().to_vec();
    let witness = FastProcessor::new(*expected.stack_inputs())
        .with_advice(AdviceInputs::default().with_stack(advice.into()))
        .unwrap()
        .execute_for_proving_sync(&other, &mut DefaultHost::default())
        .unwrap();
    let claim = witness.claim();
    assert_eq!(claim.stack_outputs(), expected.stack_outputs());
    assert_eq!(claim.kernel(), expected.kernel());
    let proof = Prover::new().with_hash_fn(PROTOCOL_PROOF_HASH).prove_full(witness).unwrap();
    assert!(matches!(
        verify_note_encryption_batch(&entries, &proof),
        Err(NoteEncryptionError::Proof(_))
    ));
}

#[test]
fn prove_maximum_batch_with_one_recipient_key() {
    let max_assets = NoteAssets::MAX_NUM_ASSETS as u8;
    let mut assets = fungible_assets(1..max_assets);
    assets.push(NonFungibleAsset::mock(b"collectible"));
    let first = p2id_note(assets.clone());
    assets.reverse();
    let target = first.target();
    let notes = [first, p2id_note(assets)].map(Note::from);
    assert_eq!(notes.len(), MAX_NOTES_PER_BATCH);
    let secret = secret_key(7);
    let key = secret.public_key();
    let address = address_with_sealing_key(target, key);
    let entries = notes.each_ref().map(|note| (note, &address));
    let rng = ChaCha20Rng::from_seed([23; 32]);
    // The sender verifies the proof against the protocol's security floor before returning it.
    let (encrypted_notes, _) = encrypt_and_prove_batch(&entries, rng).unwrap();
    assert_eq!(encrypted_notes.len(), notes.len());
    for (note, encrypted_note) in notes.iter().zip(&encrypted_notes) {
        assert_eq!(&decrypt_note(note.header(), &secret, encrypted_note).unwrap(), note.details());
    }
}

#[test]
fn program_seals_a_full_batch() {
    // Mix short and long notes to exercise buffer reuse.
    let max_assets = NoteAssets::MAX_NUM_ASSETS as u8;
    let asset_counts: [u8; PROGRAM_MAX_NOTES] =
        [1, max_assets, 2, max_assets - 1, 3, max_assets - 2, 4, max_assets - 3];
    let notes = asset_counts.map(|count| Note::from(p2id_note(fungible_assets(1..=count))));
    let secret = secret_key(7);
    let key = secret.public_key();
    let advice = notes.iter().flat_map(|note| p2id_note_advice(note, key)).collect();
    let output = execute_program(notes.len() as u32, key, advice).unwrap();

    let batch_commitment = output.stack.get_word(0).unwrap();
    assert_eq!(output.stack, StackOutputs::new(batch_commitment.as_elements()).unwrap());
    let entries = output.advice.get_mapped_values(&batch_commitment).unwrap();
    assert_eq!(
        Hasher::hash_elements_in_domain(entries, P2ID_ENCRYPTION_BATCH),
        batch_commitment
    );
    let (entries, remainder) = entries.as_chunks::<{ 3 * Word::NUM_ELEMENTS }>();
    assert!(remainder.is_empty());
    assert_eq!(entries.len(), notes.len());

    for (entry, note) in entries.iter().zip(&notes) {
        let (words, _) = entry.as_chunks::<{ Word::NUM_ELEMENTS }>();
        let [note_id, key_commitment, envelope_commitment] = [0, 1, 2].map(|i| Word::new(words[i]));
        assert_eq!(note_id, note.id().as_word());
        assert_eq!(key_commitment, key.to_commitment());
        let envelope = output.advice.get_mapped_values(&envelope_commitment).unwrap();
        let envelope = Envelope::from_elements(envelope).unwrap();
        assert_eq!(envelope.to_commitment(), envelope_commitment);
        let encrypted_note = EncryptedNote::try_from(envelope).unwrap();
        assert_eq!(&decrypt_note(note.header(), &secret, &encrypted_note).unwrap(), note.details());
    }
}

#[test]
fn rust_and_program_enforce_their_batch_limits() {
    let note_ids = |count| {
        (0..count).map(|i| NoteId::from_raw(Word::new([i as u32, 0, 0, 0].map(Felt::from_u32))))
    };
    for count in [0, MAX_NOTES_PER_BATCH + 1] {
        assert!(matches!(
            public_inputs(note_ids(count)),
            Err(NoteEncryptionError::InvalidBatchSize)
        ));
    }
    // Supply no advice to check that the program rejects invalid counts before reading it.
    for (count, error) in [
        (0, "empty encryption batch"),
        (PROGRAM_MAX_NOTES + 1, "too many notes in encryption batch"),
    ] {
        let inputs = StackInputs::new(&[Felt::from_u32(count as u32)]).unwrap();
        let result =
            FastProcessor::new(inputs).execute_sync(program(), &mut DefaultHost::default());
        assert_rejected(result, error);
    }
}
