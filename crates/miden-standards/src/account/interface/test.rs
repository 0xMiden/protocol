use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::account::AccountBuilder;
use miden_protocol::account::auth::{self, PublicKeyCommitment};
use miden_protocol::asset::NonFungibleAsset;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{NoteAttachments, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;

use crate::account::auth::{
    AccountAuthScheme,
    AuthMultisig,
    AuthMultisigConfig,
    AuthSingleSig,
    NoAuth,
};
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

/// Helper function to create a mock auth component for testing
fn get_mock_falcon_auth_component() -> AuthSingleSig {
    let mock_word = Word::from([0, 1, 2, 3u32]);
    let mock_public_key = PublicKeyCommitment::from(mock_word);
    AuthSingleSig::new(mock_public_key, auth::AuthScheme::Falcon512Poseidon2)
}

/// Helper function to create a mock Ecdsa auth component for testing
fn get_mock_ecdsa_auth_component() -> AuthSingleSig {
    let mock_word = Word::from([0, 1, 2, 3u32]);
    let mock_public_key = PublicKeyCommitment::from(mock_word);
    AuthSingleSig::new(mock_public_key, auth::AuthScheme::EcdsaK256Keccak)
}

// GET AUTH SCHEME TESTS
// ================================================================================================

#[test]
fn test_get_auth_scheme_ecdsa_k256_keccak() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_ecdsa_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from_account(&wallet_account);

    // Find the EcdsaK256Keccak component interface
    let ecdsa_k256_keccak_component = wallet_account_interface
        .components()
        .iter()
        .find(|component| matches!(component, AccountComponentInterface::AuthSingleSig))
        .expect("should have EcdsaK256Keccak component");

    // Test auth_scheme classifier
    assert_eq!(ecdsa_k256_keccak_component.auth_scheme(), Some(AccountAuthScheme::SingleSig));
}

#[test]
fn test_get_auth_scheme_falcon512_poseidon2() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_falcon_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from_account(&wallet_account);

    // Find the single sig component interface
    let rpo_falcon_component = wallet_account_interface
        .components()
        .iter()
        .find(|component| matches!(component, AccountComponentInterface::AuthSingleSig))
        .expect("should have single sig component");

    // Test auth_scheme classifier
    assert_eq!(rpo_falcon_component.auth_scheme(), Some(AccountAuthScheme::SingleSig));
}

#[test]
fn test_get_auth_scheme_no_auth() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    let no_auth_account_interface = AccountInterface::from_account(&no_auth_account);

    // Find the NoAuth component interface
    let no_auth_component = no_auth_account_interface
        .components()
        .iter()
        .find(|component| matches!(component, AccountComponentInterface::AuthNoAuth))
        .expect("should have NoAuth component");

    // Test auth_scheme classifier
    assert_eq!(no_auth_component.auth_scheme(), Some(AccountAuthScheme::NoAuth));
}

/// Test that non-auth components return None
#[test]
fn test_get_auth_scheme_non_auth_component() {
    let basic_wallet_component = AccountComponentInterface::BasicWallet;
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_falcon_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    assert!(basic_wallet_component.auth_scheme().is_none());
    let _ = wallet_account.storage();
}

/// Test that the From<&Account> implementation correctly uses get_auth_scheme
#[test]
fn test_account_interface_from_account_uses_get_auth_scheme() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_falcon_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from_account(&wallet_account);

    // Should have exactly one auth scheme
    assert_eq!(wallet_account_interface.auth().len(), 1);
    assert_eq!(wallet_account_interface.auth()[0], AccountAuthScheme::SingleSig);

    // Test with NoAuth
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    let no_auth_account_interface = AccountInterface::from_account(&no_auth_account);

    assert_eq!(no_auth_account_interface.auth().len(), 1);
    assert_eq!(no_auth_account_interface.auth()[0], AccountAuthScheme::NoAuth);
}

/// Test AccountInterface.get_auth_scheme() method with Falcon512Poseidon2 and NoAuth
#[test]
fn test_account_interface_get_auth_scheme() {
    let mock_seed = Word::from([0, 1, 2, 3u32]).as_bytes();
    let wallet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(get_mock_falcon_auth_component())
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let wallet_account_interface = AccountInterface::from_account(&wallet_account);

    // Test that auth() method provides the authentication scheme tags
    assert_eq!(wallet_account_interface.auth().len(), 1);
    assert_eq!(wallet_account_interface.auth()[0], AccountAuthScheme::SingleSig);

    // Test AccountInterface auth() with NoAuth
    let no_auth_account = AccountBuilder::new(mock_seed)
        .with_auth_component(NoAuth)
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create no-auth account");

    let no_auth_account_interface = AccountInterface::from_account(&no_auth_account);

    assert_eq!(no_auth_account_interface.auth().len(), 1);
    assert_eq!(no_auth_account_interface.auth()[0], AccountAuthScheme::NoAuth);
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
