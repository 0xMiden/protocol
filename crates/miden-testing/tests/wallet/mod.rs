use miden_protocol::Word;
use miden_protocol::account::auth::AuthSecretKey;
use miden_standards::AuthMethod;
use miden_standards::account::wallets::create_basic_wallet;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wallet_creation() {
    use miden_protocol::account::{AccountCode, AccountStorageMode, AccountType, auth};
    use miden_standards::account::auth::AuthSingleSig;
    use miden_standards::account::wallets::BasicWallet;

    // we need a Falcon Public Key to create the wallet account
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let sec_key = AuthSecretKey::new_falcon512_rpo_with_rng(&mut rng);
    let auth_scheme = auth::AuthScheme::Falcon512Rpo;
    let pub_key = sec_key.public_key().to_commitment();
    let auth_method: AuthMethod = AuthMethod::SingleSig { approver: (pub_key, auth_scheme) };

    // we need to use an initial seed to create the wallet account
    let init_seed: [u8; 32] = [
        95, 113, 209, 94, 84, 105, 250, 242, 223, 203, 216, 124, 22, 159, 14, 132, 215, 85, 183,
        204, 149, 90, 166, 68, 100, 73, 106, 168, 125, 237, 138, 16,
    ];

    let account_type = AccountType::RegularAccountImmutableCode;
    let storage_mode = AccountStorageMode::Private;

    let wallet = create_basic_wallet(init_seed, auth_method, account_type, storage_mode).unwrap();

    let expected_code = AccountCode::from_components(
        &[AuthSingleSig::new(pub_key, auth_scheme).into(), BasicWallet.into()],
        AccountType::RegularAccountUpdatableCode,
    )
    .unwrap();
    let expected_code_commitment = expected_code.commitment();

    assert!(wallet.is_regular_account());
    assert_eq!(wallet.code().commitment(), expected_code_commitment);
    assert_eq!(
        wallet.storage().get_item(AuthSingleSig::public_key_slot()).unwrap(),
        Word::from(pub_key)
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wallet_creation_2() {
    use miden_protocol::account::{AccountCode, AccountStorageMode, AccountType, auth};
    use miden_standards::account::auth::AuthSingleSig;
    use miden_standards::account::wallets::BasicWallet;

    // we need a ECDSA Public Key to create the wallet account
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let sec_key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);
    let auth_scheme = auth::AuthScheme::EcdsaK256Keccak;
    let pub_key = sec_key.public_key().to_commitment();
    let auth_method: AuthMethod = AuthMethod::SingleSig { approver: (pub_key, auth_scheme) };

    // we need to use an initial seed to create the wallet account
    let init_seed: [u8; 32] = [
        95, 113, 209, 94, 84, 105, 250, 242, 223, 203, 216, 124, 22, 159, 14, 132, 215, 85, 183,
        204, 149, 90, 166, 68, 100, 73, 106, 168, 125, 237, 138, 16,
    ];

    let account_type = AccountType::RegularAccountImmutableCode;
    let storage_mode = AccountStorageMode::Private;

    let wallet = create_basic_wallet(init_seed, auth_method, account_type, storage_mode).unwrap();

    let expected_code = AccountCode::from_components(
        &[AuthSingleSig::new(pub_key, auth_scheme).into(), BasicWallet.into()],
        AccountType::RegularAccountUpdatableCode,
    )
    .unwrap();
    let expected_code_commitment = expected_code.commitment();

    assert!(wallet.is_regular_account());
    assert_eq!(wallet.code().commitment(), expected_code_commitment);
    assert_eq!(
        wallet.storage().get_item(AuthSingleSig::public_key_slot()).unwrap(),
        Word::from(pub_key)
    );
}
