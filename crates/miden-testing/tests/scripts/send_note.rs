use core::num::NonZeroU16;
use core::slice;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountCodeInterface, AccountComponentCode, AccountId};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentScheme,
    NoteAttachments,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNote,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
};
use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::faucets::{FungibleFaucet, NonFungibleFaucet};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_SEND_NOTES_FAUCET_NOTE_REQUIRES_ONE_ASSET,
    ERR_SEND_NOTES_RECORDS_LENGTH_MISMATCH,
};
use miden_standards::note::P2idNote;
use miden_standards::tx_script::{
    SendFungibleFaucetNotesTransactionScript,
    SendNonFungibleFaucetNotesTransactionScript,
    SendNotesTransactionScript,
    SendNotesTransactionScriptError,
    SendWalletNotesTransactionScript,
};
use miden_testing::utils::create_p2any_note;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;

/// Tests the execution of the generated send_note transaction script in case the sending account
/// has the [`BasicWallet`][wallet] interface.
///
/// This tests consumes a SPAWN note first so that the note_idx in the send_note script is not zero
/// to make sure the note_idx is correctly kept on the stack.
///
/// The test also sends two assets to make sure the generated script deals correctly with multiple
/// assets.
///
/// [wallet]: miden_standards::account::interface::AccountComponentInterface::BasicWallet
#[tokio::test]
async fn test_send_note_script_basic_wallet() -> anyhow::Result<()> {
    let total_asset = FungibleAsset::mock(100);
    let sent_asset0 = NonFungibleAsset::mock(&[4, 5, 6]);

    let sent_asset1 = FungibleAsset::mock(10);
    let sent_asset2 = FungibleAsset::mock(40);

    let mut builder = MockChain::builder();

    let sender_basic_wallet_account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [sent_asset0, total_asset],
    )?;
    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let p2any_note = create_p2any_note(
        sender_basic_wallet_account.id(),
        NoteType::Private,
        [sent_asset1],
        &mut rng,
    );
    let spawn_note = builder.add_spawn_note([&p2any_note])?;
    let mock_chain = builder.build()?;

    let attachment_0 = NoteAttachment::with_words(
        NoteAttachmentScheme::new(42)?,
        vec![Word::from([9, 8, 7, 6u32]), Word::from([5, 4, 3, 2u32])],
    )?;
    let attachment_1 =
        NoteAttachment::with_word(NoteAttachmentScheme::new(43)?, Word::from([1, 2, 3, 4u32]));
    let attachment_2 = NoteAttachment::with_words(
        NoteAttachmentScheme::new(44)?,
        vec![Word::from([10, 11, 12, 13u32])],
    )?;
    let attachment_3 =
        NoteAttachment::with_word(NoteAttachmentScheme::new(45)?, Word::from([20, 21, 22, 23u32]));
    let attachments =
        NoteAttachments::new(vec![attachment_0, attachment_1, attachment_2, attachment_3])?;
    assert_eq!(
        attachments.num_attachments() as usize,
        NoteAttachments::MAX_COUNT,
        "test should use max num of attachments"
    );

    let p2id_note: Note = P2idNote::builder()
        .sender(sender_basic_wallet_account.id())
        .target(sender_basic_wallet_account.id())
        .asset(sent_asset0)
        .asset(sent_asset2)
        .attachments(attachments.iter().cloned())
        .note_type(NoteType::Public)
        .generate_serial_number(&mut rng)
        .build()?
        .into();
    let partial_note = PartialNote::from(p2id_note.clone());

    let expiration_delta = NonZeroU16::new(10).expect("10 is non-zero");
    let send_note_transaction_script = SendNotesTransactionScript::with_expiration_delta(
        &sender_basic_wallet_account.code_interface(),
        slice::from_ref(&partial_note),
        expiration_delta,
    )?;

    let executed_transaction = mock_chain
        .build_transaction(sender_basic_wallet_account.id())
        .authenticated_input_note(spawn_note.id())
        .send_notes_script(&send_note_transaction_script)
        .expected_output_note(RawOutputNote::Full(p2id_note.clone()))
        .build()?
        .execute()
        .await?;

    // Assert that the non-fungible asset was removed
    let vault_patch = executed_transaction.account_patch().vault();
    assert_eq!(
        vault_patch.removed_asset_ids().count(),
        1,
        "the non-fungible asset should have been completely removed"
    );
    assert_eq!(
        vault_patch.removed_asset_ids().next().unwrap(),
        &sent_asset0.id(),
        "the non-fungible asset should have been completely removed"
    );

    // Assert that the fungible asset's value was decremented
    assert_eq!(
        vault_patch.updated_assets().count(),
        1,
        "the fungible asset should have been updated"
    );
    // Expected value is total - (sent_asset1 + sent_asset2).
    let expected_removed = sent_asset1.unwrap_fungible().add(sent_asset2.unwrap_fungible())?;
    let expected_asset_value = total_asset.unwrap_fungible().sub(expected_removed)?.into();
    assert_eq!(
        vault_patch.updated_assets().next().unwrap(),
        expected_asset_value,
        "fungible asset should have been decremented"
    );

    assert_eq!(
        executed_transaction.output_notes().get_note(0),
        &RawOutputNote::Partial(p2any_note.into())
    );
    assert_eq!(executed_transaction.output_notes().get_note(1), &RawOutputNote::Full(p2id_note));

    assert_eq!(
        executed_transaction.expiration_block_num(),
        executed_transaction.block_header().block_num() + u32::from(expiration_delta.get()),
        "the payload-supplied expiration delta should be applied",
    );

    Ok(())
}

/// Creates a private note with the default note script and an empty asset list.
fn create_assetless_note(sender: miden_protocol::account::AccountId) -> anyhow::Result<Note> {
    let tag = NoteTag::with_account_target(sender);
    let metadata = PartialNoteMetadata::new(sender, NoteType::Private).with_tag(tag);
    let assets = NoteAssets::new(vec![])?;
    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT)?;
    let serial_num = RandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    Ok(Note::new(assets, metadata, recipient))
}

/// Tests that a basic wallet can send a note that carries no assets.
///
/// Regression test: the script must return at stack depth 16 even when the per-asset loop never
/// runs (zero-asset note), otherwise the VM rejects the transaction with
/// `InvalidStackDepthOnReturn`.
///
/// [wallet]: miden_standards::account::interface::AccountComponentInterface::BasicWallet
#[tokio::test]
async fn test_send_note_script_basic_wallet_without_assets() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender_basic_wallet_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mock_chain = builder.build()?;

    let assetless_note = create_assetless_note(sender_basic_wallet_account.id())?;
    let partial_note = PartialNote::from(assetless_note.clone());

    let send_note_transaction_script = SendNotesTransactionScript::new(
        &sender_basic_wallet_account.code_interface(),
        slice::from_ref(&partial_note),
    )?;

    let executed_transaction = mock_chain
        .build_transaction(sender_basic_wallet_account.id())
        .send_notes_script(&send_note_transaction_script)
        .expected_output_notes(vec![RawOutputNote::Full(assetless_note.clone())])
        .build()?
        .execute()
        .await?;

    assert_eq!(
        executed_transaction.output_notes().get_note(0),
        &RawOutputNote::Full(assetless_note)
    );

    Ok(())
}

/// Tests that the faucet path still rejects assetless notes at script-build time.
#[tokio::test]
async fn test_send_note_script_fungible_faucet_without_assets() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender_fungible_faucet_account = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "POL",
        200,
        None,
    )?;
    builder.build()?;

    let assetless_note = create_assetless_note(sender_fungible_faucet_account.id())?;
    let partial_note = PartialNote::from(assetless_note);

    let result = SendNotesTransactionScript::new(
        &sender_fungible_faucet_account.code_interface(),
        slice::from_ref(&partial_note),
    );

    assert!(matches!(
        result,
        Err(SendNotesTransactionScriptError::FaucetNoteUnexpectedNumAssets)
    ));

    Ok(())
}

/// Builds the code interface of an account exposing `component`'s procedures, without
/// instantiating an account. Enough for the script builder, which only inspects the interface.
fn code_interface(
    account_id: u128,
    component: &AccountComponentCode,
) -> anyhow::Result<AccountCodeInterface> {
    let account_id = AccountId::try_from(account_id)?;
    Ok(AccountCodeInterface::new(account_id, component.procedure_roots().collect())?)
}

/// Tests that the wallet path rejects notes whose sender is not the sending account at
/// script-build time.
#[test]
fn test_send_note_script_rejects_sender_mismatch() -> anyhow::Result<()> {
    let sender_interface =
        code_interface(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE, BasicWallet::code())?;
    let other_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2)?;

    let foreign_note = create_assetless_note(other_id)?;
    let partial_note = PartialNote::from(foreign_note);

    let result = SendNotesTransactionScript::new(&sender_interface, slice::from_ref(&partial_note));

    assert!(matches!(
        result,
        Err(SendNotesTransactionScriptError::InvalidSenderAccount(sender)) if sender == other_id
    ));

    Ok(())
}

/// Tests that embedding the payload in the script's MAST forest leaves the script root untouched,
/// so a single canonical root covers every set of output notes and stays allowlistable.
#[test]
fn test_send_note_script_root_is_independent_of_payload() -> anyhow::Result<()> {
    let wallet_interface =
        code_interface(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE, BasicWallet::code())?;
    let note = create_assetless_note(wallet_interface.id())?;

    let script = SendNotesTransactionScript::new(&wallet_interface, &[note.clone().into()])?;
    assert!(
        matches!(script, SendNotesTransactionScript::Wallet(_)),
        "a wallet interface should select the wallet script"
    );
    assert_eq!(
        script.tx_script().root(),
        SendWalletNotesTransactionScript::script_root(),
        "the embedded payload must not change the script root"
    );
    assert!(
        SendNotesTransactionScript::script_roots()
            .contains(&SendWalletNotesTransactionScript::script_root()),
        "the canonical roots should include the wallet script"
    );

    // A different payload must still produce the same root.
    let other = SendNotesTransactionScript::with_expiration_delta(
        &wallet_interface,
        &[note.into()],
        NonZeroU16::new(10).expect("10 is non-zero"),
    )?;
    assert_eq!(script.tx_script().root(), other.tx_script().root());
    assert_ne!(
        script.tx_script_args(),
        other.tx_script_args(),
        "a different payload should still change the script arguments"
    );

    Ok(())
}

/// Tests the execution of the `send_notes` script in case the sending account has the
/// [`NonFungibleFaucet`] interface, which mints the note's asset from its commitment alone.
#[tokio::test]
async fn test_send_note_script_non_fungible_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet_account = builder.add_existing_non_fungible_faucet(Auth::IncrNonce, "NFT")?;
    let mock_chain = builder.build()?;

    let commitment =
        NonFungibleFaucet::compute_asset_commitment(b"token #1", Word::from([7, 8, 9, 10u32]));
    let asset = Asset::NonFungible(NonFungibleAsset::from_parts(faucet_account.id(), commitment));

    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let note = create_p2any_note(faucet_account.id(), NoteType::Public, [asset], &mut rng);

    let script =
        SendNotesTransactionScript::new(&faucet_account.code_interface(), &[note.clone().into()])?;
    assert!(
        matches!(script, SendNotesTransactionScript::NonFungible(_)),
        "a non-fungible faucet interface should select the non-fungible script"
    );
    assert_eq!(
        script.tx_script().root(),
        SendNonFungibleFaucetNotesTransactionScript::script_root()
    );

    let executed_transaction = mock_chain
        .build_transaction(faucet_account.id())
        .send_notes_script(&script)
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute()
        .await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    assert_eq!(executed_transaction.output_notes().get_note(0), &RawOutputNote::Full(note));

    Ok(())
}

/// Tests that each dedicated script type rejects an interface it does not apply to, so building
/// one directly is as safe as letting [`SendNotesTransactionScript`] dispatch, and that the
/// dispatch picks the variant matching the interface.
#[test]
fn test_dedicated_send_notes_scripts_validate_their_interface() -> anyhow::Result<()> {
    let wallet_interface =
        code_interface(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE, BasicWallet::code())?;
    let faucet_interface =
        code_interface(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1, FungibleFaucet::code())?;

    // The faucet script needs a faucet interface.
    let wallet_note = create_assetless_note(wallet_interface.id())?;
    assert!(matches!(
        SendFungibleFaucetNotesTransactionScript::new(&wallet_interface, &[wallet_note.into()]),
        Err(SendNotesTransactionScriptError::UnsupportedAccountInterface)
    ));

    // The wallet script needs the wallet procedures.
    let own_asset = Asset::Fungible(FungibleAsset::new(faucet_interface.id(), 10)?);
    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let faucet_note =
        create_p2any_note(faucet_interface.id(), NoteType::Private, [own_asset], &mut rng);
    assert!(matches!(
        SendWalletNotesTransactionScript::new(&faucet_interface, &[faucet_note.clone().into()]),
        Err(SendNotesTransactionScriptError::UnsupportedAccountInterface)
    ));

    // A faucet interface dispatches to the fungible faucet script.
    let dispatched = SendNotesTransactionScript::new(&faucet_interface, &[faucet_note.into()])?;
    assert!(matches!(dispatched, SendNotesTransactionScript::Fungible(_)));
    assert_eq!(
        dispatched.tx_script().root(),
        SendFungibleFaucetNotesTransactionScript::script_root()
    );

    Ok(())
}

/// Tests that the faucet path rejects notes carrying an asset issued by a different faucet at
/// script-build time.
#[test]
fn test_send_note_script_rejects_foreign_faucet_asset() -> anyhow::Result<()> {
    // The mock asset is issued by `ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET`, so the sending faucet must
    // be a different one for the asset to count as foreign.
    let faucet_interface =
        code_interface(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1, FungibleFaucet::code())?;
    let foreign_asset = FungibleAsset::mock(10);
    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let note =
        create_p2any_note(faucet_interface.id(), NoteType::Private, [foreign_asset], &mut rng);
    let partial_note = PartialNote::from(note);

    let result = SendNotesTransactionScript::new(&faucet_interface, slice::from_ref(&partial_note));

    assert!(matches!(
        result,
        Err(SendNotesTransactionScriptError::IssuanceFaucetMismatch(faucet_id))
            if faucet_id == foreign_asset.faucet_id()
    ));

    Ok(())
}

/// Tests the execution of the generated send_note transaction script in case the sending account
/// has the [`FungibleFaucet`][faucet] interface.
///
/// [faucet]: miden_standards::account::interface::AccountComponentInterface::FungibleFaucet
#[tokio::test]
async fn test_send_note_script_fungible_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender_fungible_faucet_account = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "POL",
        200,
        None,
    )?;
    let mock_chain = builder.build()?;

    let tag = NoteTag::with_account_target(sender_fungible_faucet_account.id());
    let attachment = NoteAttachment::with_word(NoteAttachmentScheme::new(100)?, Word::empty());
    let metadata = PartialNoteMetadata::new(sender_fungible_faucet_account.id(), NoteType::Public)
        .with_tag(tag);
    let assets = NoteAssets::new(vec![Asset::Fungible(
        FungibleAsset::new(sender_fungible_faucet_account.id(), 10).unwrap(),
    )])?;
    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT).unwrap();
    let serial_num = RandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let attachments = NoteAttachments::from(attachment);

    let note = Note::with_attachments(assets.clone(), metadata, recipient, attachments);
    let partial_note: PartialNote = note.clone().into();

    let expiration_delta = NonZeroU16::new(10).expect("10 is non-zero");
    let send_note_transaction_script = SendNotesTransactionScript::with_expiration_delta(
        &sender_fungible_faucet_account.code_interface(),
        slice::from_ref(&partial_note),
        expiration_delta,
    )?;

    let executed_transaction = mock_chain
        .build_transaction(sender_fungible_faucet_account.id())
        .send_notes_script(&send_note_transaction_script)
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute()
        .await?;

    assert_eq!(executed_transaction.output_notes().get_note(0), &RawOutputNote::Full(note));

    assert_eq!(
        executed_transaction.expiration_block_num(),
        executed_transaction.block_header().block_num() + u32::from(expiration_delta.get()),
        "the payload-supplied expiration delta should be applied",
    );

    Ok(())
}

#[tokio::test]
async fn test_send_note_script_multiple_notes_basic_wallet() -> anyhow::Result<()> {
    let total_asset = FungibleAsset::mock(100);
    let non_fungible_asset = NonFungibleAsset::mock(&[7, 8, 9]);

    let mut builder = MockChain::builder();
    let sender_account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [total_asset, non_fungible_asset],
    )?;
    let mock_chain = builder.build()?;

    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));

    // Note A: two assets and two attachments.
    let attachment_0 =
        NoteAttachment::with_word(NoteAttachmentScheme::new(7)?, Word::from([1, 2, 3, 4u32]));
    let attachment_1 = NoteAttachment::with_words(
        NoteAttachmentScheme::new(8)?,
        vec![Word::from([5, 6, 7, 8u32]), Word::from([9, 10, 11, 12u32])],
    )?;
    let note_a: Note = P2idNote::builder()
        .sender(sender_account.id())
        .target(sender_account.id())
        .asset(FungibleAsset::mock(10))
        .asset(non_fungible_asset)
        .attachments([attachment_0, attachment_1])
        .note_type(NoteType::Public)
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    // Note B: one asset, no attachments.
    let note_b: Note = P2idNote::builder()
        .sender(sender_account.id())
        .target(sender_account.id())
        .asset(FungibleAsset::mock(40))
        .note_type(NoteType::Public)
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    // Note C: no assets and no attachments (smallest possible record).
    let metadata = PartialNoteMetadata::new(sender_account.id(), NoteType::Public)
        .with_tag(NoteTag::with_account_target(sender_account.id()));
    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT).unwrap();
    let recipient = NoteRecipient::new(rng.draw_word(), note_script, NoteStorage::default());
    let note_c = Note::new(NoteAssets::default(), metadata, recipient);

    let notes: Vec<PartialNote> =
        vec![note_a.clone().into(), note_b.clone().into(), note_c.clone().into()];
    let script = SendNotesTransactionScript::new(&sender_account.code_interface(), &notes)?;

    let executed_transaction = mock_chain
        .build_transaction(sender_account.id())
        .send_notes_script(&script)
        .expected_output_notes(vec![
            RawOutputNote::Full(note_a.clone()),
            RawOutputNote::Full(note_b.clone()),
            RawOutputNote::Full(note_c.clone()),
        ])
        .build()?
        .execute()
        .await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 3);
    assert_eq!(executed_transaction.output_notes().get_note(0), &RawOutputNote::Full(note_a));
    assert_eq!(executed_transaction.output_notes().get_note(1), &RawOutputNote::Full(note_b));
    assert_eq!(executed_transaction.output_notes().get_note(2), &RawOutputNote::Full(note_c));

    // Both of note A's assets must have left the vault: the non-fungible one entirely, and the
    // fungible one decremented by note A's and note B's amounts.
    let vault_patch = executed_transaction.account_patch().vault();
    assert_eq!(
        vault_patch.removed_asset_ids().collect::<Vec<_>>(),
        vec![&non_fungible_asset.id()],
        "the non-fungible asset should have been completely removed"
    );

    let expected_removed = FungibleAsset::mock(10)
        .unwrap_fungible()
        .add(FungibleAsset::mock(40).unwrap_fungible())?;
    let expected_asset_value = total_asset.unwrap_fungible().sub(expected_removed)?.into();
    assert_eq!(
        vault_patch.updated_assets().collect::<Vec<_>>(),
        vec![expected_asset_value],
        "the fungible asset should have been decremented by both notes' amounts"
    );

    Ok(())
}

/// Builds a faucet account and the genuine `send_notes` payload for a single one-asset note,
/// returning the chain, the account, the script, and the payload elements.
async fn faucet_with_single_asset_payload()
-> anyhow::Result<(MockChain, Account, SendNotesTransactionScript, Vec<Felt>)> {
    let mut builder = MockChain::builder();
    let faucet_account = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "POL",
        200,
        None,
    )?;
    let mock_chain = builder.build()?;

    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let own_asset = Asset::Fungible(FungibleAsset::new(faucet_account.id(), 10)?);
    let note = create_p2any_note(faucet_account.id(), NoteType::Public, [own_asset], &mut rng);

    let script = SendNotesTransactionScript::new(&faucet_account.code_interface(), &[note.into()])?;

    // The genuine payload is read back out of the script's embedded advice map.
    let payload = script
        .tx_script()
        .mast()
        .advice_map()
        .get(&script.tx_script_args())
        .expect("the script should embed its payload")
        .to_vec();

    Ok((mock_chain, faucet_account, script, payload))
}

/// Executes `payload` against `faucet_account` as a handcrafted `send_notes` payload, recomputing
/// the commitment so it passes the advice validation and reaches the script's own assertions.
async fn execute_with_payload(
    mock_chain: &MockChain,
    faucet_account: &Account,
    script: &SendNotesTransactionScript,
    payload: Vec<Felt>,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let tampered_args = Hasher::hash_elements(&payload);
    Ok(mock_chain
        .build_transaction(faucet_account.id())
        .tx_script(script.tx_script().clone())
        .tx_script_args(tampered_args)
        .add_advice_map_entry(tampered_args, payload)
        .build()?
        .execute()
        .await)
}

/// Tests that a payload whose note record claims more assets than it carries data for is rejected
/// before any loop walks the record, rather than reading past the piped-in payload.
#[tokio::test]
async fn test_send_note_script_rejects_record_length_mismatch() -> anyhow::Result<()> {
    let (mock_chain, faucet_account, script, mut payload) =
        faucet_with_single_asset_payload().await?;

    // Claim two assets without appending the second asset's elements.
    payload[SendNotesTransactionScript::PAYLOAD_HEADER_NUM_ELEMENTS
        + SendNotesTransactionScript::NOTE_RECORD_NUM_ASSETS_OFFSET] = Felt::from(2u32);

    let result = execute_with_payload(&mock_chain, &faucet_account, &script, payload).await?;

    assert_transaction_executor_error!(result, ERR_SEND_NOTES_RECORDS_LENGTH_MISMATCH);

    Ok(())
}

/// Tests that the faucet script rejects a well-formed payload whose note record carries more than
/// one asset, since the faucet mints exactly one asset per note.
#[tokio::test]
async fn test_send_note_script_faucet_rejects_multi_asset_payload() -> anyhow::Result<()> {
    let (mock_chain, faucet_account, script, mut payload) =
        faucet_with_single_asset_payload().await?;

    // Claim two assets and append a second asset's elements, so the record stays well formed and
    // the failure comes from the faucet's own one-asset assertion rather than the bounds check.
    payload[SendNotesTransactionScript::PAYLOAD_HEADER_NUM_ELEMENTS
        + SendNotesTransactionScript::NOTE_RECORD_NUM_ASSETS_OFFSET] = Felt::from(2u32);
    let first_asset_start = SendNotesTransactionScript::PAYLOAD_HEADER_NUM_ELEMENTS
        + SendNotesTransactionScript::NOTE_RECORD_ITEMS_OFFSET;
    let first_asset: Vec<Felt> = payload
        [first_asset_start..first_asset_start + SendNotesTransactionScript::ITEM_NUM_ELEMENTS]
        .to_vec();
    let insert_at = first_asset_start + SendNotesTransactionScript::ITEM_NUM_ELEMENTS;
    payload.splice(insert_at..insert_at, first_asset);

    let result = execute_with_payload(&mock_chain, &faucet_account, &script, payload).await?;

    assert_transaction_executor_error!(result, ERR_SEND_NOTES_FAUCET_NOTE_REQUIRES_ONE_ASSET);

    Ok(())
}
