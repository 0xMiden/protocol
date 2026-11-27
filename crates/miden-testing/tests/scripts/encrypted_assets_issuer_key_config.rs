//! Tests for the `EncryptedAssetsIssuerKeyConfig` note, which rotates the issuer key of a faucet's
//! encrypted assets send policy.
//!
//! The rotation itself and the rejection of an unauthorized sender are covered by the
//! `encrypted_assets_policy` suite; this suite covers what the note adds on top: the guards that
//! reject a malformed or wrongly targeted note.

extern crate alloc;

use alloc::vec::Vec;

use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::AssetAmount;
use miden_protocol::crypto::ecdh::ecgfp5::{PreparedPublicKey, SecretKey};
use miden_protocol::crypto::rand::EidosRandomCoin;
use miden_protocol::errors::MasmError;
use miden_protocol::errors::protocol::ERR_NOTE_TOO_MANY_STORAGE_ITEMS;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS};
use miden_standards::account::access::AccessControl;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    ReceivePolicy,
    SendPolicy,
    TokenPolicyManager,
};
use miden_standards::errors::standards::{
    ERR_ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG_NOTE_IS_NOT_PUBLIC,
    ERR_ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_ENCRYPTED_ASSETS_ISSUER_KEY_ZERO,
    ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT,
};
use miden_standards::note::config::EncryptedAssetsIssuerKeyConfigNote;
use miden_standards::note::{EncryptedAssetsIssuerKey, NetworkAccountTarget, NoteExecutionHint};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use crate::into_private_note;

// HELPERS
// ================================================================================================

/// Returns an issuer key derived from a secret key with all bytes set to `seed`.
fn issuer_key(seed: u8) -> anyhow::Result<EncryptedAssetsIssuerKey> {
    Ok(EncryptedAssetsIssuerKey::new(&PreparedPublicKey::new(
        SecretKey::from_bytes(&[seed; 40])?.public_key(),
    )))
}

/// Builds a fungible faucet whose active send policy is the encrypted assets policy, gated by
/// `owner` via `Authority::OwnerControlled` (installed by `AccessControl::Ownable2Step`).
fn create_faucet_with_issuer_key(owner: AccountId) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("ENC")?)
        .symbol("ENC".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(SendPolicy::with_encrypted_assets(issuer_key(7)?))
        .active_receive_policy(ReceivePolicy::allow_all())
        .build();

    let account = AccountBuilder::new([44; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(faucet)
        .with_components(token_policy_manager)
        .build_existing()?;

    Ok(account)
}

/// Builds an [`EncryptedAssetsIssuerKeyConfigNote`] rotating the issuer key of `account`, sent by
/// `sender`.
fn issuer_key_config_note(
    sender: AccountId,
    account: AccountId,
    rng: &mut EidosRandomCoin,
) -> anyhow::Result<Note> {
    let note = EncryptedAssetsIssuerKeyConfigNote::builder()
        .sender(sender)
        .target(account)
        .issuer_key(issuer_key(8)?)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the EncryptedAssetsIssuerKeyConfig script with hand-crafted storage,
/// bypassing the builder so malformed inputs can be exercised.
///
/// It carries a `NetworkAccountTarget` for the consuming account, like a real config note, so the
/// note passes the script's target check and reaches the guard under test.
fn malformed_issuer_key_config_note(
    sender: AccountId,
    target: AccountId,
    storage: Vec<Felt>,
    rng: &mut EidosRandomCoin,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rng)
        .script(EncryptedAssetsIssuerKeyConfigNote::script())
        .note_storage(storage)?
        .attachment(NetworkAccountTarget::new(target, NoteExecutionHint::Always)?)
        .build()?;
    Ok(note)
}

// TESTS
// ================================================================================================

/// A note with malformed storage is rejected before the issuer key changes:
/// - storage without the expected key elements fails the count guard.
/// - storage with more items than the script accepts is rejected before it is loaded, so the work
///   an oversized note can impose is bounded by the accepted layout rather than by
///   `MAX_NOTE_STORAGE_ITEMS`.
/// - the zero key, which the builder cannot express, is rejected by `set_issuer_key`.
#[rstest::rstest]
#[case::wrong_storage_item_count(
    Vec::new(),
    ERR_ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
)]
#[case::oversized_storage(
    vec![Felt::from(0u32); MAX_NOTE_STORAGE_ITEMS],
    ERR_NOTE_TOO_MANY_STORAGE_ITEMS
)]
#[case::zero_key(
    vec![Felt::from(0u32); EncryptedAssetsIssuerKeyConfigNote::NUM_STORAGE_ITEMS],
    ERR_ENCRYPTED_ASSETS_ISSUER_KEY_ZERO
)]
#[tokio::test]
async fn malformed_storage_is_rejected(
    #[case] storage: Vec<Felt>,
    #[case] expected_error: MasmError,
) -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let faucet = create_faucet_with_issuer_key(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = EidosRandomCoin::new([Felt::from(100u32); 4].into());

    let note = malformed_issuer_key_config_note(owner, faucet.id(), storage, &mut rng)?;
    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, expected_error);
    Ok(())
}

/// The note is bound to its target account, so a decoy account cannot consume a note meant for
/// another account. The decoy carries the same issuer key setup with the same owner, so the
/// sender-based authorization would pass; consuming a note targeted at a different account aborts
/// at the target check before the issuer key changes.
#[tokio::test]
async fn decoy_account_cannot_consume_note_of_another_account() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let decoy = create_faucet_with_issuer_key(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(decoy.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = EidosRandomCoin::new([Felt::from(100u32); 4].into());

    // The note's intended target. It need not be built: the note only references its ID.
    let target = AccountId::builder().account_type(AccountType::Public).build_with_seed([9; 32]);

    let note = issuer_key_config_note(owner, target, &mut rng)?;
    let result = mock_chain
        .build_transaction(decoy.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT
    );
    Ok(())
}

/// A private note carrying the same script and storage as a legitimate config note is rejected
/// before the issuer key changes.
#[tokio::test]
async fn private_note_cannot_dispatch_the_action() -> anyhow::Result<()> {
    let owner = AccountIdBuilder::new().build_with_seed([1; 32]);

    let faucet = create_faucet_with_issuer_key(owner)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;
    let mut rng = EidosRandomCoin::new([Felt::from(100u32); 4].into());

    let note = issuer_key_config_note(owner, faucet.id(), &mut rng)?;
    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(into_private_note(note))
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_ENCRYPTED_ASSETS_ISSUER_KEY_CONFIG_NOTE_IS_NOT_PUBLIC
    );
    Ok(())
}
