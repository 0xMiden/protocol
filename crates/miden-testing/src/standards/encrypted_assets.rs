//! Tests for the `miden::standards::attachments::encrypted_assets` module.

use alloc::vec::Vec;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_processor::ExecutionError;
use miden_processor::advice::AdviceError;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountType,
    StorageSlot,
};
use miden_protocol::asset::{Asset, AssetAmount, AssetCallbacks, FungibleAsset, NonFungibleAsset};
use miden_protocol::crypto::ecdh::ecgfp5::SecretKey;
use miden_protocol::crypto::ies::ecgfp5_eidos;
use miden_protocol::errors::MasmError;
use miden_protocol::errors::protocol::ERR_NOTE_RECIPIENT_PREIMAGE_MISMATCH;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachments,
    NoteMetadata,
    NoteType,
    PartialNote,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
};
use miden_protocol::transaction::{ExecutedTransaction, OutputNote, RawOutputNote};
use miden_protocol::utils::FeltSliceExt;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Pausable};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_ENCRYPTED_ASSETS_ISSUER_KEY_MISSING;
use miden_standards::note::{
    EncryptedAssetsAttachment,
    EncryptedAssetsAttachmentError,
    EncryptedAssetsIssuerKey,
    P2idNote,
};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_tx::{LocalTransactionProver, TransactionExecutorError};

use crate::executor::CodeExecutor;
use crate::utils::DEFAULT_EXPIRATION_BLOCK_DELTA;
use crate::{AccountState, Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};

// CONSTANTS
// ================================================================================================

/// The name of the component that registers the issuing faucet's note callback.
const ISSUER_COMPONENT_NAME: &str = "miden::testing::encrypted_assets::issuer";

/// An `on_before_note_sealed` callback that returns the note's encrypted asset attachment as an
/// attachment list with one entry, or the empty list for a public note.
const ISSUER_CALLBACK_CODE: &str = "
    use miden::core::crypto::hashes::eidos
    use miden::core::sys
    use miden::standards::attachments::encrypted_assets

    #! Inputs:  [note_idx, pad(15)]
    #! Outputs: [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(11)]
    @locals(8)
    @account_procedure
    pub proc on_before_note_sealed
        exec.encrypted_assets::build_attachment
        # => [attachment_scheme, ATTACHMENT_COMMITMENT, pad(15)]

        # a public note gets attachment scheme 0 and the empty word, which already are the number
        # of attachments and the commitment of the empty list
        dup neq.0
        # => [has_attachment, attachment_scheme, ATTACHMENT_COMMITMENT, pad(15)]

        if.true
            # write the list entry [attachment_scheme, 0, 0, 0, ATTACHMENT_COMMITMENT] to memory
            push.0.0.0 movup.3 loc_storew_le.0 dropw
            # => [ATTACHMENT_COMMITMENT, pad(15)]

            loc_storew_le.4 dropw
            # => [pad(15)]

            locaddr.0 dup add.8 swap
            # => [list_ptr, list_end_ptr, pad(15)]

            dup.1 dup.1 exec.eidos::hash_words
            # => [ATTACHMENT_LIST_COMMITMENT, list_ptr, list_end_ptr, pad(15)]

            adv.insert_mem
            # => [ATTACHMENT_LIST_COMMITMENT, list_ptr, list_end_ptr, pad(15)]

            movup.4 drop movup.4 drop push.1
            # => [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(15)]
        end
        # => [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(15)]

        exec.sys::truncate_stack
        # => [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(11)]
    end
";

// TYPES
// ================================================================================================

/// The recipient preimage of the sent note in the transaction's advice map.
#[derive(Debug, Clone, Copy)]
enum RecipientPreimage {
    /// The transaction expects the note, which puts its recipient preimage into the advice map.
    Expected,
    /// The advice map holds no preimage of the note's recipient.
    Missing,
    /// The advice map maps the note's recipient to a chain of entries that does not hash to it.
    Forged,
}

// TESTS
// ================================================================================================

/// Tests that the issuer decrypts the encrypted asset attachment of a private note and recomputes
/// the note's ID and nullifier from it and the note's metadata, and that building the attachment
/// applies the default expiration delta.
///
/// The note holds the issuer's asset and, depending on the case, other faucets' assets, up to the
/// maximum number of assets per note.
#[rstest::rstest]
#[case::single_asset(Vec::new())]
#[case::several_assets(several_other_assets())]
#[case::max_assets(
    (0..NoteAssets::MAX_NUM_ASSETS - 1).map(|i| NonFungibleAsset::mock(&[i as u8])).collect()
)]
#[tokio::test]
async fn issuer_recomputes_note_id_and_nullifier_from_attachment(
    #[case] other_assets: Vec<Asset>,
) -> anyhow::Result<()> {
    let (note, result) =
        send_note(NoteType::Private, other_assets, issuer_key_slots(), RecipientPreimage::Expected)
            .await?;
    let executed_tx = result?;
    assert_eq!(
        executed_tx.expiration_block_num(),
        executed_tx.block_header().block_num() + DEFAULT_EXPIRATION_BLOCK_DELTA
    );

    let RawOutputNote::Full(full_note) = executed_tx.output_notes().get_note(0) else {
        anyhow::bail!("output note should be a full note");
    };
    let nullifier = full_note.nullifier();

    let proven_tx = LocalTransactionProver::default().prove(executed_tx)?;
    let OutputNote::Private(output_note) = proven_tx.output_notes().get_note(0) else {
        anyhow::bail!("output note should be private");
    };

    let attachment = output_note
        .attachments()
        .find(EncryptedAssetsAttachment::ATTACHMENT_SCHEME)
        .context("output note should carry the encrypted asset attachment")?;
    assert_eq!(usize::from(attachment.num_words()), 8 + 4 * note.assets().num_assets());

    let plaintext = EncryptedAssetsAttachment::decrypt_and_verify_note(
        output_note.header(),
        output_note.attachments(),
        &issuer_secret_key(),
    )
    .context("the encrypted asset attachment should describe the note")?;
    assert_eq!(plaintext.assets(), note.assets());
    assert_eq!(plaintext.nullifier(output_note.metadata()), nullifier);

    Ok(())
}

/// Tests that a public note gets no encrypted asset attachment.
#[tokio::test]
async fn public_note_gets_no_encrypted_assets_attachment() -> anyhow::Result<()> {
    let (note, result) =
        send_note(NoteType::Public, Vec::new(), issuer_key_slots(), RecipientPreimage::Expected)
            .await?;
    let executed_tx = result?;

    let output_note = executed_tx.output_notes().get_note(0);
    assert!(output_note.attachments().is_empty());
    assert_eq!(output_note.id(), note.id());

    Ok(())
}

/// Tests that a private note whose attachment cannot be built cannot be sealed, so that its
/// creator cannot skip the attachment.
#[rstest::rstest]
#[case::forged_recipient_preimage(
    issuer_key_slots(),
    RecipientPreimage::Forged,
    ERR_NOTE_RECIPIENT_PREIMAGE_MISMATCH
)]
#[case::missing_issuer_key(
    EncryptedAssetsIssuerKey::slot_names().clone().map(StorageSlot::with_empty_value),
    RecipientPreimage::Expected,
    ERR_ENCRYPTED_ASSETS_ISSUER_KEY_MISSING
)]
#[tokio::test]
async fn private_note_without_attachment_cannot_be_sealed(
    #[case] issuer_key_slots: [StorageSlot; 2],
    #[case] recipient_preimage: RecipientPreimage,
    #[case] expected_error: MasmError,
) -> anyhow::Result<()> {
    let (_, result) =
        send_note(NoteType::Private, Vec::new(), issuer_key_slots, recipient_preimage).await?;

    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// Tests that a private note whose recipient preimage is not in the advice map cannot be sealed.
#[tokio::test]
async fn private_note_without_recipient_preimage_cannot_be_sealed() -> anyhow::Result<()> {
    let (note, result) =
        send_note(NoteType::Private, Vec::new(), issuer_key_slots(), RecipientPreimage::Missing)
            .await?;

    assert_transaction_executor_error!(
        result,
        matches ExecutionError::AdviceError { err: AdviceError::MapKeyNotFound { key }, .. }
            if key == note.recipient().digest()
    );

    Ok(())
}

/// Tests that the issuer keeps only the attachment that describes the note, although the note's
/// creator added a decoy attachment of the same scheme first, that the attachment does not decrypt
/// with another secret key or after tampering, and that the plaintext with other metadata yields
/// another note ID.
#[tokio::test]
async fn issuer_keeps_only_the_attachment_that_describes_the_note() -> anyhow::Result<()> {
    // the decoy encrypts the details of another note to the issuer key
    let decoy_plaintext = EncryptedAssetsAttachment::new(
        Word::from([9u32; 4]),
        P2idNote::script_root(),
        Word::empty(),
        NoteAssets::default(),
    );
    let decoy_envelope = ecgfp5_eidos::seal_with_rng(
        &issuer_secret_key().public_key(),
        &decoy_plaintext.to_elements(),
        &EncryptedAssetsAttachment::IES_CONTEXT,
        &mut rand::rng(),
    )?;
    let decoy = NoteAttachment::with_words(
        EncryptedAssetsAttachment::ATTACHMENT_SCHEME,
        decoy_envelope
            .to_elements()
            .to_words()
            .context("the envelope elements should form whole words")?,
    )?;

    let (note, result) = send_note_with_attachments(
        NoteType::Private,
        Vec::new(),
        vec![decoy.clone()],
        issuer_key_slots(),
        RecipientPreimage::Expected,
    )
    .await?;
    let executed_tx = result?;
    let output_note = executed_tx.output_notes().get_note(0);
    assert_eq!(output_note.attachments().get(0), Some(&decoy));

    let plaintext = EncryptedAssetsAttachment::decrypt_and_verify_note(
        output_note.header(),
        output_note.attachments(),
        &issuer_secret_key(),
    )
    .context("the encrypted asset attachment should describe the note")?;
    assert_eq!(plaintext.serial_num(), note.recipient().serial_num());
    assert_eq!(
        EncryptedAssetsAttachment::decrypt(&decoy, &issuer_secret_key())?,
        decoy_plaintext
    );

    let attachment = output_note
        .attachments()
        .get(1)
        .context("output note should carry the encrypted asset attachment after the decoy")?;

    let other_secret_key = SecretKey::from_bytes(&[8; 40])?;
    assert_matches!(
        EncryptedAssetsAttachment::decrypt(attachment, &other_secret_key),
        Err(EncryptedAssetsAttachmentError::DecryptionFailed(_))
    );
    assert_eq!(
        EncryptedAssetsAttachment::decrypt_and_verify_note(
            output_note.header(),
            output_note.attachments(),
            &other_secret_key
        ),
        None
    );

    // flip the lowest bit of the first ciphertext limb, which keeps it a valid u32 limb
    let mut elements = attachment.to_elements();
    elements[8] = Felt::new(elements[8].as_canonical_u64() ^ 1)?;
    let tampered = NoteAttachment::with_words(
        EncryptedAssetsAttachment::ATTACHMENT_SCHEME,
        elements.to_words().context("the attachment elements should form whole words")?,
    )?;
    assert_matches!(
        EncryptedAssetsAttachment::decrypt(&tampered, &issuer_secret_key()),
        Err(EncryptedAssetsAttachmentError::DecryptionFailed(_))
    );

    let other_metadata =
        NoteMetadata::new(*output_note.metadata().partial_metadata(), &NoteAttachments::empty());
    assert_ne!(plaintext.note_id(&other_metadata), output_note.id());

    Ok(())
}

/// Tests that the MASM constants of the attachment format match their Rust counterparts.
#[tokio::test]
async fn encrypted_assets_masm_constants_match_rust() -> anyhow::Result<()> {
    let source = "
        use {
            ENCRYPTED_ASSETS_ATTACHMENT_SCHEME,
            ISSUER_KEY_0_SLOT,
            ISSUER_KEY_1_SLOT,
        } from miden::standards::attachments::encrypted_assets

        begin
            push.ISSUER_KEY_1_SLOT[0..2]
            push.ISSUER_KEY_0_SLOT[0..2]
            push.ENCRYPTED_ASSETS_ATTACHMENT_SCHEME
            # => [attachment_scheme, slot_0_id_suffix, slot_0_id_prefix, slot_1_id_suffix,
            #     slot_1_id_prefix, pad(16)]

            # truncate the stack to 16 elements
            repeat.5 movup.5 drop end
        end
    ";

    let exec_output = CodeExecutor::with_default_host().run(source).await?;

    let [slot_0_id, slot_1_id] =
        EncryptedAssetsIssuerKey::slot_names().each_ref().map(|name| name.id());
    assert_eq!(exec_output.stack[..1], EncryptedAssetsAttachment::IES_CONTEXT);
    assert_eq!(
        exec_output.stack[1..5],
        [slot_0_id.suffix(), slot_0_id.prefix(), slot_1_id.suffix(), slot_1_id.prefix()]
    );

    Ok(())
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a fungible asset of another faucet and a non-fungible asset.
fn several_other_assets() -> Vec<Asset> {
    let other_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
        .expect("account ID constant should be valid");
    let other_asset =
        FungibleAsset::new(other_faucet_id, 50).expect("fungible asset should be valid");

    vec![other_asset.into(), NonFungibleAsset::mock(&[1, 2, 3])]
}

/// Returns the issuer's secret key.
fn issuer_secret_key() -> SecretKey {
    SecretKey::from_bytes(&[7; 40]).expect("bytes should encode a valid secret key")
}

/// Returns the storage slots that hold the public key of [`issuer_secret_key`].
fn issuer_key_slots() -> [StorageSlot; 2] {
    EncryptedAssetsIssuerKey::new(issuer_secret_key().public_key()).into_storage_slots()
}

/// Executes a transaction in which a wallet sends a P2ID note of the provided type that holds an
/// asset of a faucet whose `on_before_note_sealed` callback returns the note's encrypted asset
/// attachment, followed by `other_assets`.
///
/// The faucet stores `issuer_key_slots`, and `recipient_preimage` determines the preimage of the
/// note's recipient in the advice map.
///
/// Returns the note as the wallet creates it, i.e. without the attachment, and the execution
/// result.
async fn send_note(
    note_type: NoteType,
    other_assets: Vec<Asset>,
    issuer_key_slots: [StorageSlot; 2],
    recipient_preimage: RecipientPreimage,
) -> anyhow::Result<(Note, Result<ExecutedTransaction, TransactionExecutorError>)> {
    send_note_with_attachments(
        note_type,
        other_assets,
        Vec::new(),
        issuer_key_slots,
        recipient_preimage,
    )
    .await
}

/// Executes the transaction of [`send_note`] for a note to which its creator adds
/// `creator_attachments`.
async fn send_note_with_attachments(
    note_type: NoteType,
    other_assets: Vec<Asset>,
    creator_attachments: Vec<NoteAttachment>,
    issuer_key_slots: [StorageSlot; 2],
    recipient_preimage: RecipientPreimage,
) -> anyhow::Result<(Note, Result<ExecutedTransaction, TransactionExecutorError>)> {
    let mut builder = MockChain::builder();
    let faucet = add_issuing_faucet(&mut builder, issuer_key_slots)?;
    let assets = core::iter::once(FungibleAsset::new(faucet.id(), 100)?.into())
        .chain(other_assets)
        .collect::<Vec<Asset>>();
    let wallet = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        assets.clone(),
    )?;
    let mock_chain = builder.build()?;

    let note: Note = P2idNote::builder()
        .sender(wallet.id())
        .target(AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)?)
        .assets(assets)
        .attachments(creator_attachments)
        .note_type(note_type)
        .serial_number(Word::from([1, 2, 3, 4u32]))
        .build()?
        .into();
    let send_script = SendNotesTransactionScript::new(
        &wallet.code_interface(),
        &[PartialNote::from(note.clone())],
    )?;

    let mut tx_builder = mock_chain
        .build_transaction(wallet.id())
        .send_notes_script(&send_script)
        .foreign_accounts([mock_chain.get_foreign_account_inputs(faucet.id())?]);
    match recipient_preimage {
        RecipientPreimage::Expected => {
            tx_builder = tx_builder.expected_output_note(RawOutputNote::Full(note.clone()));
        },
        RecipientPreimage::Missing => {},
        RecipientPreimage::Forged => {
            // the entries open the recipient to a serial number, script root and storage
            // commitment of no known note, so the host keeps the note private
            let [serial_script_commitment, serial_commitment, script_root, storage_commitment] =
                [11, 12, 13, 14u32].map(|value| Word::from([value; 4]));
            let forged_serial_num = Word::from([15u32; 4]);
            tx_builder = tx_builder
                .add_advice_map_entry(
                    note.recipient().digest(),
                    double_word_elements(serial_script_commitment, storage_commitment),
                )
                .add_advice_map_entry(
                    serial_script_commitment,
                    double_word_elements(serial_commitment, script_root),
                )
                .add_advice_map_entry(
                    serial_commitment,
                    double_word_elements(forged_serial_num, Word::empty()),
                );
        },
    }
    let result = tx_builder.build()?.execute().await;

    Ok((note, result))
}

/// Returns the elements of the two provided words.
fn double_word_elements(first: Word, second: Word) -> Vec<Felt> {
    first.into_iter().chain(second).collect()
}

/// Adds a faucet whose `on_before_note_sealed` callback returns the note's encrypted asset
/// attachment, and which stores `issuer_key_slots`.
fn add_issuing_faucet(
    builder: &mut MockChainBuilder,
    issuer_key_slots: [StorageSlot; 2],
) -> anyhow::Result<Account> {
    let callback_code = CodeBuilder::default()
        .compile_component_code(ISSUER_COMPONENT_NAME, ISSUER_CALLBACK_CODE)?;
    let callback_root = callback_code
        .as_package()
        .get_procedure_root_by_path(
            format!("{ISSUER_COMPONENT_NAME}::on_before_note_sealed").as_str(),
        )
        .context("note callback procedure should exist")?;

    let mut storage_slots =
        AssetCallbacks::new().on_before_note_sealed(callback_root).into_storage_slots();
    storage_slots.extend(issuer_key_slots);
    let issuer_component = AccountComponent::new(
        callback_code,
        storage_slots,
        AccountComponentMetadata::new(ISSUER_COMPONENT_NAME)
            .with_description("encrypted asset attachment callback for testing"),
    )?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::from(1_000_000u32))
        .build()?;

    let account_builder = AccountBuilder::new([42; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Authority::AuthControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .build(),
        )
        .with_component(Pausable::unpaused())
        .with_component(issuer_component);

    builder.add_account_from_builder(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        account_builder,
        AccountState::Exists,
    )
}
