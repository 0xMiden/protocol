use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::account::AccountBuilder;
use miden_protocol::account::auth::{self, PublicKeyCommitment};
use miden_protocol::asset::NonFungibleAsset;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{NoteAttachments, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;

use crate::account::auth::{AuthMultisig, AuthMultisigConfig, AuthSingleSig, NoAuth};
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::account::wallets::BasicWallet;
use crate::note::SwapNote;
use crate::testing::account_interface::get_public_keys_from_account;

/// Checks the function `create_swap_note` should fail if the requested asset is the same as the
/// offered asset.
#[test]
fn test_required_asset_same_as_offered() {
    let offered_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);
    let requested_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let result = SwapNote::create(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        offered_asset,
        requested_asset,
        NoteType::Public,
        NoteAttachments::default(),
        NoteType::Public,
        &mut RandomCoin::new(Word::from([1, 2, 3, 4u32])),
    );

    assert_matches!(result, Err(NoteError::Other { error_msg, .. }) if error_msg == "requested asset same as offered asset".into());
}

// HELPERS
// ================================================================================================

fn get_mock_falcon_auth_component() -> AuthSingleSig {
    let mock_word = Word::from([0, 1, 2, 3u32]);
    let mock_public_key = PublicKeyCommitment::from(mock_word);
    AuthSingleSig::new(mock_public_key, auth::AuthScheme::Falcon512Poseidon2)
}

// AUTH COMPONENT IDENTIFICATION TESTS
// ================================================================================================

#[test]
fn test_account_interface_identifies_single_sig_auth() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_falcon_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from_account(&wallet_account);

    let auth_components: alloc::vec::Vec<_> = wallet_account_interface.auth_components().collect();
    assert_eq!(auth_components.len(), 1);
    assert!(matches!(auth_components[0], AccountComponentInterface::AuthSingleSig));
}

#[test]
fn test_account_interface_identifies_no_auth() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    let no_auth_account_interface = AccountInterface::from_account(&no_auth_account);

    let auth_components: alloc::vec::Vec<_> = no_auth_account_interface.auth_components().collect();
    assert_eq!(auth_components.len(), 1);
    assert!(matches!(auth_components[0], AccountComponentInterface::AuthNoAuth));
}

#[test]
fn test_basic_wallet_is_not_an_auth_component() {
    assert!(!AccountComponentInterface::BasicWallet.is_auth_component());
    assert!(AccountComponentInterface::AuthSingleSig.is_auth_component());
    assert!(AccountComponentInterface::AuthNoAuth.is_auth_component());
}

#[test]
fn test_public_key_extraction_regular_account() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_falcon_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    // Test public key extraction like miden-client would do
    let pub_keys = get_public_keys_from_account(&wallet_account);

    assert_eq!(pub_keys.len(), 1);
    assert_eq!(pub_keys[0], Word::from([0, 1, 2, 3u32]));
}

#[test]
fn test_public_key_extraction_multisig_account() {
    // Create test public keys
    let pub_key_1 = PublicKeyCommitment::from(Word::from([1u32, 0, 0, 0]));
    let pub_key_2 = PublicKeyCommitment::from(Word::from([2u32, 0, 0, 0]));
    let pub_key_3 = PublicKeyCommitment::from(Word::from([3u32, 0, 0, 0]));

    let approvers = vec![
        (pub_key_1, auth::AuthScheme::Falcon512Poseidon2),
        (pub_key_2, auth::AuthScheme::Falcon512Poseidon2),
        (pub_key_3, auth::AuthScheme::EcdsaK256Keccak),
    ];

    let threshold = 2u32;

    // Create multisig component
    let multisig_component =
        AuthMultisig::new(AuthMultisigConfig::new(approvers.clone(), threshold).unwrap())
            .expect("multisig component creation failed");

    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let multisig_account = AccountBuilder::new(mock_seed)
        .with_auth_component(multisig_component)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create multisig account");

    let pub_keys = get_public_keys_from_account(&multisig_account);

    assert_eq!(pub_keys.len(), 3);
    assert_eq!(pub_keys[0], Word::from([1u32, 0, 0, 0]));
    assert_eq!(pub_keys[1], Word::from([2u32, 0, 0, 0]));
    assert_eq!(pub_keys[2], Word::from([3u32, 0, 0, 0]));
}

#[test]
fn test_public_key_extraction_no_auth_account() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    // Test public key extraction
    let pub_keys = get_public_keys_from_account(&no_auth_account);

    // NoAuth should not contribute any public keys
    assert_eq!(pub_keys.len(), 0);
}
