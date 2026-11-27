//! Tests for the encrypted assets send policy ([`SendPolicy::with_encrypted_assets`]) and the
//! [`EncryptedAssetsIssuerKey`] component that installs the issuer key on the faucet.

use anyhow::Context;
use miden_processor::ExecutionError;
use miden_processor::advice::AdviceError;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
use miden_protocol::crypto::ecdh::ecgfp5::SecretKey;
use miden_protocol::crypto::rand::EidosRandomCoin;
use miden_protocol::note::{Note, NoteType, PartialNote};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::{ExecutedTransaction, OutputNote, RawOutputNote};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::faucets::{NonFungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BlocklistStorage,
    BurnPolicy,
    MintPolicy,
    SendPolicy,
    TokenPolicyManager,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_ACCOUNT_IS_BLOCKED,
    ERR_ENCRYPTED_ASSETS_NOTE_HAS_MULTIPLE_ASSETS,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::note::config::EncryptedAssetsIssuerKeyConfigNote;
use miden_standards::note::{EncryptedAssetsAttachment, EncryptedAssetsIssuerKey, P2idNote};
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};
use miden_tx::{LocalTransactionProver, TransactionExecutorError};

use super::transfer_policy::{SEALED_NOTE_IDX, build_mint_note_for};
use super::{
    assert_default_expiration_limit,
    fungible_faucet,
    fungible_faucet_account,
    policy_component,
};
use crate::consume_note;

// CONSTANTS
// ================================================================================================

/// The amount of the faucet's asset that a note holds.
const NOTE_AMOUNT: u64 = 100;

// FIXTURES
// ================================================================================================

/// Returns the issuer's secret key.
fn issuer_secret_key() -> SecretKey {
    SecretKey::from_bytes(&[7; 40]).expect("bytes should encode a valid secret key")
}

/// Returns the elements of the public key of [`issuer_secret_key`].
fn issuer_key_elements() -> [Felt; 5] {
    issuer_secret_key().public_key().to_elements()
}

/// Returns the issuer key holding the public key of [`issuer_secret_key`].
fn issuer_key() -> EncryptedAssetsIssuerKey {
    EncryptedAssetsIssuerKey::new(issuer_secret_key().public_key())
}

/// Returns a token policy manager whose active send policy is `send_policy`.
fn policy_manager(send_policy: SendPolicy) -> TokenPolicyManager {
    TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(send_policy)
        .build()
}

/// Adds an existing auth-controlled fungible faucet with the provided token policy manager.
fn add_faucet(
    builder: &mut MockChainBuilder,
    token_policy_manager: TokenPolicyManager,
) -> anyhow::Result<Account> {
    let account_builder = fungible_faucet_account(48)?
        .with_component(Authority::AuthControlled)
        .with_components(token_policy_manager);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Returns a P2ID note of the provided type, created by `sender`, that holds [`NOTE_AMOUNT`] units
/// of the asset of `faucet_id` and whose serial number repeats `serial_num_element`.
fn p2id_note(
    sender: AccountId,
    faucet_id: AccountId,
    note_type: NoteType,
    serial_num_element: u32,
) -> anyhow::Result<Note> {
    Ok(P2idNote::builder()
        .sender(sender)
        .target(AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)?)
        .assets([FungibleAsset::new(faucet_id, NOTE_AMOUNT)?])
        .note_type(note_type)
        .serial_number(Word::from([serial_num_element; 4]))
        .build()?
        .into())
}

/// Executes a transaction in which `wallet` sends an empty private note and then `note`, which
/// holds the asset of `faucet_id`, at [`SEALED_NOTE_IDX`].
///
/// The transaction expects `note`, which puts its recipient preimage into the advice map.
async fn execute_send(
    mock_chain: &MockChain,
    wallet: &Account,
    faucet_id: AccountId,
    note: &Note,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let empty_note = NoteBuilder::new(wallet.id(), EidosRandomCoin::new(Word::empty()))
        .note_type(NoteType::Private)
        .build()?;
    let send_script = SendNotesTransactionScript::new(
        &wallet.code_interface(),
        &[PartialNote::from(empty_note), PartialNote::from(note.clone())],
    )?;

    Ok(mock_chain
        .build_transaction(wallet.id())
        .send_notes_script(&send_script)
        .foreign_accounts([mock_chain.get_foreign_account_inputs(faucet_id)?])
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute()
        .await)
}

/// Executes a transaction in which a wallet sends a private note that holds the asset of a faucet
/// whose active send policy is the one `send_policy` returns for the wallet's ID.
///
/// Returns the note as the wallet creates it, i.e. without the policy's attachment, and the
/// execution result.
async fn send_note(
    send_policy: impl FnOnce(AccountId) -> anyhow::Result<SendPolicy>,
) -> anyhow::Result<(Note, Result<ExecutedTransaction, TransactionExecutorError>)> {
    let mut builder = MockChain::builder();
    // the wallet is created before the faucet so that the send policy can name it
    let mut wallet = builder
        .add_existing_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak })?;
    let faucet = add_faucet(&mut builder, policy_manager(send_policy(wallet.id())?))?;

    let note = p2id_note(wallet.id(), faucet.id(), NoteType::Private, 1)?;
    wallet
        .vault_mut()
        .add_asset(FungibleAsset::new(faucet.id(), NOTE_AMOUNT)?.into())?;
    builder.add_account(wallet.clone())?;
    let mock_chain = builder.build()?;

    let result = execute_send(&mock_chain, &wallet, faucet.id(), &note).await?;

    Ok((note, result))
}

/// Returns a send policy that rejects notes created by a blocked account and returns the encrypted
/// asset attachment of the other notes, starting with `blocked_accounts` blocked.
///
/// The policy combines the native account check of the basic blocklist policy with the encrypted
/// assets policy, and installs the issuer key like [`SendPolicy::with_encrypted_assets`].
fn blocklist_with_encrypted_assets_policy(
    blocked_accounts: impl IntoIterator<Item = AccountId>,
) -> anyhow::Result<SendPolicy> {
    let (root, component) = policy_component(
        "tests::blocklist_with_encrypted_assets",
        "check_send_policy",
        vec![BlocklistStorage::with_blocked_accounts(blocked_accounts).into_slot()],
        "
        use miden::standards::faucets::policies::transfer::basic_blocklist
        use miden::standards::faucets::policies::transfer::encrypted_assets

        #! Inputs:  [note_idx, pad(15)]
        #! Outputs: [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(11)]
        @account_procedure
        pub proc check_send_policy
            exec.basic_blocklist::check_native_account
            exec.encrypted_assets::check_send_policy
        end
        ",
    )?;

    Ok(SendPolicy::custom(root, [component, issuer_key().into()])?)
}

/// Asserts that the output note of `executed` at [`SEALED_NOTE_IDX`] is a private note with a
/// single attachment, from which the issuer recomputes the note's ID and nullifier with
/// `issuer_secret_key`.
fn assert_issuer_decrypts_note(
    executed: &ExecutedTransaction,
    issuer_secret_key: &SecretKey,
) -> anyhow::Result<()> {
    assert_eq!(executed.output_notes().num_notes(), SEALED_NOTE_IDX + 1);
    let RawOutputNote::Full(note) = executed.output_notes().get_note(SEALED_NOTE_IDX) else {
        anyhow::bail!("output note should be a full note");
    };
    assert_eq!(note.metadata().note_type(), NoteType::Private);
    assert_eq!(note.attachments().num_attachments(), 1);

    let plaintext = EncryptedAssetsAttachment::decrypt_and_verify_note(
        note.header(),
        note.attachments(),
        issuer_secret_key,
    )
    .context("attachment should decrypt to the note's details")?;
    assert_eq!(plaintext.assets(), note.assets());
    assert_eq!(plaintext.nullifier(note.metadata()), note.nullifier());

    Ok(())
}

/// Returns an [`EncryptedAssetsIssuerKeyConfigNote`], created by `sender`, that sets `issuer_key`
/// on `faucet_id`.
fn issuer_key_config_note(
    sender: AccountId,
    faucet_id: AccountId,
    issuer_key: EncryptedAssetsIssuerKey,
) -> anyhow::Result<Note> {
    let mut rng = EidosRandomCoin::new([Felt::from(6u32); 4].into());
    Ok(EncryptedAssetsIssuerKeyConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .issuer_key(issuer_key)
        .generate_serial_number(&mut rng)
        .build()?
        .into())
}

/// Adds an existing faucet owned by `owner`, whose authority gates its setters, with
/// [`SendPolicy::with_encrypted_assets`] active.
fn add_owned_faucet(builder: &mut MockChainBuilder, owner: AccountId) -> anyhow::Result<Account> {
    let account_builder = fungible_faucet_account(50)?
        .with_component(Ownable2Step::new(owner))
        .with_component(Authority::OwnerControlled)
        .with_components(policy_manager(SendPolicy::with_encrypted_assets(issuer_key())));

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// SEND TESTS
// ================================================================================================

/// A wallet sends a private note holding the faucet's asset. The send policy attaches the
/// encrypted asset attachment, the transaction is proven, and the issuer decrypts the attachment
/// of the proven note and recomputes the note's ID and nullifier.
#[tokio::test]
async fn issuer_decrypts_attachment_of_proven_private_note() -> anyhow::Result<()> {
    let (note, result) = send_note(|_| Ok(SendPolicy::with_encrypted_assets(issuer_key()))).await?;
    let executed = result?;
    let RawOutputNote::Full(full_note) = executed.output_notes().get_note(SEALED_NOTE_IDX) else {
        anyhow::bail!("output note should be a full note");
    };
    let nullifier = full_note.nullifier();

    let proven = LocalTransactionProver::default().prove(executed)?;
    let OutputNote::Private(output_note) = proven.output_notes().get_note(SEALED_NOTE_IDX) else {
        anyhow::bail!("output note should be private");
    };
    assert_eq!(output_note.attachments().num_attachments(), 1);

    let plaintext = EncryptedAssetsAttachment::decrypt_and_verify_note(
        output_note.header(),
        output_note.attachments(),
        &issuer_secret_key(),
    )
    .context("attachment should decrypt to the note's details")?;
    assert_eq!(plaintext.serial_num(), note.recipient().serial_num());
    assert_eq!(plaintext.assets(), note.assets());
    assert_eq!(plaintext.nullifier(output_note.metadata()), nullifier);

    Ok(())
}

/// A wallet sends a private note holding the faucet's asset and an asset of another faucet. The
/// send policy rejects the note, since its attachment would show the other asset to the issuer.
#[tokio::test]
async fn send_policy_rejects_private_note_with_other_assets() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet =
        add_faucet(&mut builder, policy_manager(SendPolicy::with_encrypted_assets(issuer_key())))?;
    let assets = [
        Asset::from(FungibleAsset::new(faucet.id(), NOTE_AMOUNT)?),
        Asset::from(FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?, 10)?),
    ];
    let wallet = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak },
        assets,
    )?;
    let mock_chain = builder.build()?;

    let note: Note = P2idNote::builder()
        .sender(wallet.id())
        .target(AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)?)
        .assets(assets)
        .note_type(NoteType::Private)
        .serial_number(Word::from([1u32; 4]))
        .build()?
        .into();
    let result = execute_send(&mock_chain, &wallet, faucet.id(), &note).await?;

    assert_transaction_executor_error!(result, ERR_ENCRYPTED_ASSETS_NOTE_HAS_MULTIPLE_ASSETS);

    Ok(())
}

/// The send policy counts all assets of a private note, so it also rejects a private note that
/// holds two assets of a non-fungible faucet with the policy.
#[tokio::test]
async fn send_policy_rejects_private_note_with_two_assets_of_the_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account_builder = AccountBuilder::new([51; 32])
        .account_type(AccountType::Public)
        .with_component(
            NonFungibleFaucet::builder()
                .name(TokenName::new("NFT")?)
                .symbol("NFT".try_into()?)
                .build()?,
        )
        .with_component(Authority::AuthControlled)
        .with_components(policy_manager(SendPolicy::with_encrypted_assets(issuer_key())));
    let faucet =
        builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)?;
    let assets = [1u8, 2].map(|data| {
        Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(faucet.id(), vec![data])))
    });
    let wallet = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak },
        assets,
    )?;
    let mock_chain = builder.build()?;

    let note: Note = P2idNote::builder()
        .sender(wallet.id())
        .target(AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)?)
        .assets(assets)
        .note_type(NoteType::Private)
        .serial_number(Word::from([1u32; 4]))
        .build()?
        .into();
    let result = execute_send(&mock_chain, &wallet, faucet.id(), &note).await?;

    assert_transaction_executor_error!(result, ERR_ENCRYPTED_ASSETS_NOTE_HAS_MULTIPLE_ASSETS);

    Ok(())
}

/// A send policy that combines the basic blocklist check with the encrypted assets policy rejects
/// a note created by a blocked account and attaches the encrypted asset attachment to a note
/// created by another account.
#[rstest::rstest]
#[case::blocked_sender(true)]
#[case::allowed_sender(false)]
#[tokio::test]
async fn combined_blocklist_policy_checks_sender_and_returns_attachment(
    #[case] sender_blocked: bool,
) -> anyhow::Result<()> {
    let (_, result) = send_note(|wallet_id| {
        blocklist_with_encrypted_assets_policy(sender_blocked.then_some(wallet_id))
    })
    .await?;

    if sender_blocked {
        assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_BLOCKED);
    } else {
        assert_issuer_decrypts_note(&result?, &issuer_secret_key())?;
    }

    Ok(())
}

/// The token policy manager switches the active send policy between `allow_all` and the encrypted
/// assets policy, registered as an allowed alternative, and the next private note sent with the
/// faucet's asset carries an attachment exactly when the encrypted assets policy is active.
#[rstest::rstest]
#[case::to_encrypted_assets(
    SendPolicy::allow_all(),
    SendPolicy::with_encrypted_assets(issuer_key()),
    true
)]
#[case::to_allow_all(
    SendPolicy::with_encrypted_assets(issuer_key()),
    SendPolicy::allow_all(),
    false
)]
#[tokio::test]
async fn set_send_policy_switches_the_attachment(
    #[case] active_policy: SendPolicy,
    #[case] new_policy: SendPolicy,
    #[case] expects_attachment: bool,
) -> anyhow::Result<()> {
    let new_policy_root = new_policy.root();
    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(active_policy)
        .allowed_send_policy(new_policy)
        .build();

    let mut builder = MockChain::builder();
    let faucet = add_faucet(&mut builder, token_policy_manager)?;
    let wallet = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak },
        [FungibleAsset::new(faucet.id(), NOTE_AMOUNT)?.into()],
    )?;
    let mut mock_chain = builder.build()?;

    let set_policy_script = CodeBuilder::default()
        .with_dynamically_linked_package(TokenPolicyManager::code())?
        .compile_tx_script(format!(
            "
            @transaction_script
            pub proc main
                push.{new_policy_root}
                call.::miden::standards::components::faucets::policies::policy_manager::set_send_policy
                dropw
            end
            "
        ))?;
    let set_policy_tx = mock_chain
        .build_transaction(faucet.id())
        .tx_script(set_policy_script)
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&set_policy_tx)?;
    mock_chain.prove_next_block()?;

    let faucet = mock_chain.committed_account(faucet.id())?;
    assert_eq!(
        faucet.storage().get_item(TokenPolicyManager::active_send_policy_slot())?,
        new_policy_root.as_word()
    );

    let note = p2id_note(wallet.id(), faucet.id(), NoteType::Private, 1)?;
    let executed = execute_send(&mock_chain, &wallet, faucet.id(), &note).await??;

    if expects_attachment {
        assert_issuer_decrypts_note(&executed, &issuer_secret_key())?;
    } else {
        let output_note = executed.output_notes().get_note(SEALED_NOTE_IDX);
        assert!(output_note.attachments().is_empty());
        assert_eq!(output_note.id(), note.id());
    }

    Ok(())
}

/// The issuer key component exposes the issuer's public key and limits the transaction's
/// expiration.
#[tokio::test]
async fn issuer_key_component_returns_public_key() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet =
        add_faucet(&mut builder, policy_manager(SendPolicy::with_encrypted_assets(issuer_key())))?;
    let mock_chain = builder.build()?;

    let assert_public_key_code = issuer_key_elements()
        .iter()
        .map(|element| {
            format!(
                r#"push.{element} assert_eq.err="issuer public key should match the installed key""#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(EncryptedAssetsIssuerKey::code())?
        .compile_tx_script(format!(
            "
            @transaction_script
            pub proc main
                call.::miden::standards::components::attachments::encrypted_assets::get_issuer_key
                # => [public_key(5), pad(11)]

                {assert_public_key_code}
                # => [pad(16)]
            end
            "
        ))?;

    let executed = mock_chain
        .build_transaction(faucet.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    assert_default_expiration_limit(&executed);

    Ok(())
}

/// The faucet's authority rotates the issuer key with `set_issuer_key`. A private note sent
/// afterwards decrypts with the new secret key and not with the previous one.
#[tokio::test]
async fn authority_rotates_issuer_key() -> anyhow::Result<()> {
    let owner = AccountId::try_from(ACCOUNT_ID_SENDER)?;
    let new_secret_key = SecretKey::from_bytes(&[8; 40])?;

    let mut builder = MockChain::builder();
    let faucet = add_owned_faucet(&mut builder, owner)?;
    let wallet = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak },
        [FungibleAsset::new(faucet.id(), NOTE_AMOUNT)?.into()],
    )?;
    let rotation_note = issuer_key_config_note(
        owner,
        faucet.id(),
        EncryptedAssetsIssuerKey::new(new_secret_key.public_key()),
    )?;
    builder.add_output_note(RawOutputNote::Full(rotation_note.clone()));
    let mut mock_chain = builder.build()?;

    consume_note(&mut mock_chain, faucet.id(), &rotation_note).await?;

    let note = p2id_note(wallet.id(), faucet.id(), NoteType::Private, 1)?;
    let executed = execute_send(&mock_chain, &wallet, faucet.id(), &note).await??;

    assert_issuer_decrypts_note(&executed, &new_secret_key)?;
    let sent_note = executed.output_notes().get_note(SEALED_NOTE_IDX);
    assert!(
        EncryptedAssetsAttachment::decrypt_and_verify_note(
            sent_note.header(),
            sent_note.attachments(),
            &issuer_secret_key()
        )
        .is_none()
    );

    Ok(())
}

/// `set_issuer_key` rejects a caller that the faucet's authority does not authorize.
#[tokio::test]
async fn set_issuer_key_rejects_unauthorized_sender() -> anyhow::Result<()> {
    let owner = AccountId::try_from(ACCOUNT_ID_SENDER)?;
    let sender = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)?;

    let mut builder = MockChain::builder();
    let faucet = add_owned_faucet(&mut builder, owner)?;
    let rotation_note = issuer_key_config_note(sender, faucet.id(), issuer_key())?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(faucet.id())
        .unauthenticated_input_note(rotation_note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

// MINT TESTS
// ================================================================================================

/// A network faucet consumes a MINT note with a public or a private output note. The send policy
/// runs with the faucet as the native account, so the minted note gets no attachment, and the
/// faucet mints the private note although the MINT note holds only its recipient digest.
///
/// The faucet consumes a public MINT note first, so the output note under test is at
/// [`SEALED_NOTE_IDX`].
#[rstest::rstest]
#[case::public_output_note(NoteType::Public)]
#[case::private_output_note(NoteType::Private)]
#[tokio::test]
async fn network_faucet_mints_notes_without_attachment(
    #[case] output_note_type: NoteType,
) -> anyhow::Result<()> {
    let owner = AccountId::try_from(ACCOUNT_ID_SENDER)?;
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_network_faucet_with_policies(
        owner,
        fungible_faucet()?,
        [],
        policy_manager(SendPolicy::with_encrypted_assets(issuer_key())),
    )?;

    let first_mint_note =
        build_mint_note_for(owner, &p2id_note(faucet.id(), faucet.id(), NoteType::Public, 2)?, 5)?;
    let output_note = p2id_note(faucet.id(), faucet.id(), output_note_type, 1)?;
    let mint_note_under_test = build_mint_note_for(owner, &output_note, 6)?;
    builder.add_output_note(RawOutputNote::Full(first_mint_note.clone()));
    builder.add_output_note(RawOutputNote::Full(mint_note_under_test.clone()));
    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_transaction(faucet.id())
        .authenticated_input_note(first_mint_note.id())
        .authenticated_input_note(mint_note_under_test.id())
        .build()?
        .execute()
        .await?;

    let minted_note = executed.output_notes().get_note(SEALED_NOTE_IDX);
    assert_eq!(minted_note.metadata().note_type(), output_note_type);
    assert_eq!(minted_note.recipient_digest(), output_note.recipient().digest());
    assert!(minted_note.attachments().is_empty());

    Ok(())
}

// SWAP TESTS
// ================================================================================================

/// The account that fills a SWAP note requesting the faucet's asset with a private payback note
/// knows only the payback note's recipient digest, so it cannot seal the payback note.
#[tokio::test]
async fn swap_with_private_payback_cannot_be_filled() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet =
        add_faucet(&mut builder, policy_manager(SendPolicy::with_encrypted_assets(issuer_key())))?;
    let requested_asset = Asset::from(FungibleAsset::new(faucet.id(), NOTE_AMOUNT)?);
    let filler = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak },
        [requested_asset],
    )?;
    let offered_asset =
        Asset::from(FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?, 10)?);
    let (swap_note, payback_note) = builder.add_swap_note(
        ACCOUNT_ID_SENDER.try_into()?,
        offered_asset,
        requested_asset,
        NoteType::Private,
    )?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(filler.id())
        .authenticated_input_note(swap_note.id())
        .foreign_accounts([mock_chain.get_foreign_account_inputs(faucet.id())?])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        matches ExecutionError::AdviceError { err: AdviceError::MapKeyNotFound { key }, .. }
            if key == payback_note.recipient().digest()
    );

    Ok(())
}
