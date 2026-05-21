use alloc::collections::BTreeSet;

use assert_matches::assert_matches;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::{AccountBuilder, AccountType};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::{Felt, Word};

use super::{FungibleFaucet, create_fungible_faucet};
use crate::AuthMethod;
use crate::account::access::AccessControl;
use crate::account::auth::{AuthSingleSig, AuthSingleSigAcl};
use crate::account::faucets::{Description, FungibleFaucetError, TokenMetadata, TokenName};
use crate::account::policies::{
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyRegistration,
    TokenPolicyManager,
    TransferPolicy,
};
use crate::account::wallets::BasicWallet;

/// Builds a minimal policy manager with AllowAll on every kind, used by the construction tests.
fn allow_all_policy_manager() -> TokenPolicyManager {
    TokenPolicyManager::new()
        .with_mint_policy(MintPolicyConfig::AllowAll, PolicyRegistration::Active)
        .unwrap()
        .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)
        .unwrap()
        .with_send_policy(TransferPolicy::AllowAll, PolicyRegistration::Active)
        .unwrap()
        .with_receive_policy(TransferPolicy::AllowAll, PolicyRegistration::Active)
        .unwrap()
}

/// Builds a sample `FungibleFaucet` shared by construction tests.
fn sample_faucet() -> FungibleFaucet {
    FungibleFaucet::builder()
        .name(TokenName::new("polygon").unwrap())
        .symbol(TokenSymbol::try_from("POL").unwrap())
        .decimals(2)
        .max_supply(AssetAmount::from(123u32))
        .description(Description::new("A polygon token").unwrap())
        .build()
        .unwrap()
}

/// Reads every trigger-procedure-root map entry from `0..num` and returns the set.
fn read_trigger_procedure_roots(
    account: &miden_protocol::account::Account,
    num: u32,
) -> BTreeSet<Word> {
    (0..num)
        .map(|i| {
            account
                .storage()
                .get_map_item(
                    AuthSingleSigAcl::trigger_procedure_roots_slot(),
                    [Felt::from(i), Felt::ZERO, Felt::ZERO, Felt::ZERO].into(),
                )
                .unwrap()
        })
        .collect()
}

#[test]
fn faucet_contract_creation() {
    let pub_key_word = Word::new([Felt::ONE; 4]);
    let auth_method = AuthMethod::SingleSig {
        approver: (pub_key_word.into(), AuthScheme::Falcon512Poseidon2),
    };

    // we need to use an initial seed to create the wallet account
    let init_seed: [u8; 32] = [
        90, 110, 209, 94, 84, 105, 250, 242, 223, 203, 216, 124, 22, 159, 14, 132, 215, 85, 183,
        204, 149, 90, 166, 68, 100, 73, 106, 168, 125, 237, 138, 16,
    ];

    let token_symbol_string = "POL";
    let token_symbol = TokenSymbol::try_from(token_symbol_string).unwrap();
    let token_name_string = "polygon";
    let description_string = "A polygon token";

    let faucet = sample_faucet();
    let faucet_account = create_fungible_faucet(
        init_seed,
        faucet,
        AccountType::Private,
        auth_method,
        AccessControl::AuthControlled,
        allow_all_policy_manager(),
    )
    .unwrap();

    // The falcon auth component's public key should be present.
    assert_eq!(
        faucet_account.storage().get_item(AuthSingleSigAcl::public_key_slot()).unwrap(),
        pub_key_word
    );

    // The config slot of the auth component stores:
    // [num_trigger_procs, allow_unauthorized_output_notes, allow_unauthorized_input_notes, 0].
    //
    // With 9 authority-gated trigger procedures (mint_and_send + 4 token metadata setters +
    // 4 policy setters), allow_unauthorized_output_notes=false, and
    // allow_unauthorized_input_notes=true, this should be [9, 0, 1, 0].
    assert_eq!(
        faucet_account.storage().get_item(AuthSingleSigAcl::config_slot()).unwrap(),
        [Felt::from(9_u32), Felt::ZERO, Felt::ONE, Felt::ZERO].into()
    );

    // The trigger procedure root map should contain every authority-gated setter root.
    let stored_roots = read_trigger_procedure_roots(&faucet_account, 9);
    let expected_roots: BTreeSet<Word> = [
        FungibleFaucet::mint_and_send_root(),
        FungibleFaucet::set_max_supply_root(),
        FungibleFaucet::set_description_root(),
        FungibleFaucet::set_logo_uri_root(),
        FungibleFaucet::set_external_link_root(),
        TokenPolicyManager::set_mint_policy_root(),
        TokenPolicyManager::set_burn_policy_root(),
        TokenPolicyManager::set_send_policy_root(),
        TokenPolicyManager::set_receive_policy_root(),
    ]
    .into_iter()
    .map(|root| root.as_word())
    .collect();
    assert_eq!(stored_roots, expected_roots);

    // Check that faucet metadata was initialized to the given values.
    // Storage layout: [token_supply, max_supply, decimals, symbol]
    assert_eq!(
        faucet_account.storage().get_item(FungibleFaucet::token_config_slot()).unwrap(),
        [Felt::ZERO, Felt::from(123_u32), Felt::from(2_u32), token_symbol.into()].into()
    );

    // Check that name was stored
    let name_0 = faucet_account.storage().get_item(TokenMetadata::name_chunk_0_slot()).unwrap();
    let name_1 = faucet_account.storage().get_item(TokenMetadata::name_chunk_1_slot()).unwrap();
    let decoded_name = TokenName::try_from_words(&[name_0, name_1]).unwrap();
    assert_eq!(decoded_name.as_str(), token_name_string);
    let expected_desc_words = Description::new(description_string).unwrap().to_words();
    for (i, expected) in expected_desc_words.iter().enumerate() {
        let chunk = faucet_account.storage().get_item(TokenMetadata::description_slot(i)).unwrap();
        assert_eq!(chunk, *expected);
    }

    // Verify the faucet component can be extracted
    let _faucet_component = FungibleFaucet::try_from(faucet_account.clone()).unwrap();
}

#[test]
fn auth_controlled_rejects_no_auth() {
    let err = create_fungible_faucet(
        [7u8; 32],
        sample_faucet(),
        AccountType::Private,
        AuthMethod::NoAuth,
        AccessControl::AuthControlled,
        allow_all_policy_manager(),
    )
    .expect_err("AuthControlled+NoAuth should be rejected");
    assert_matches!(err, FungibleFaucetError::IncompatibleAuthControlledAuth(_));
}

/// `(Ownable2Step / Rbac, SingleSig)` must be rejected: SingleSig is intended for
/// user-account faucets gated by `AuthControlled`; under owner/role-gated faucets it
/// duplicates the setter check with a per-tx signature that doesn't add security.
#[test]
fn ownable2step_rejects_single_sig() {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;

    let owner = miden_protocol::account::AccountId::try_from(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    )
    .unwrap();
    let auth_method = AuthMethod::SingleSig {
        approver: (Word::new([Felt::ONE; 4]).into(), AuthScheme::Falcon512Poseidon2),
    };

    let err = create_fungible_faucet(
        [7u8; 32],
        sample_faucet(),
        AccountType::Public,
        auth_method,
        AccessControl::Ownable2Step { owner },
        allow_all_policy_manager(),
    )
    .expect_err("Ownable2Step+SingleSig should be rejected");
    assert_matches!(err, FungibleFaucetError::UnsupportedAccessControlAuthCombination(_));
}

#[test]
fn ownable2step_with_no_auth_is_accepted() {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;

    let owner = miden_protocol::account::AccountId::try_from(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    )
    .unwrap();

    let _account = create_fungible_faucet(
        [7u8; 32],
        sample_faucet(),
        AccountType::Public,
        AuthMethod::NoAuth,
        AccessControl::Ownable2Step { owner },
        allow_all_policy_manager(),
    )
    .expect("Ownable2Step+NoAuth should be accepted");
}

#[test]
fn faucet_create_from_account() {
    // prepare the test data
    let mock_word = Word::from([0, 1, 2, 3u32]);
    let mock_public_key = PublicKeyCommitment::from(mock_word);
    let mock_seed = mock_word.as_bytes();

    // valid account
    let token_symbol = TokenSymbol::new("POL").expect("invalid token symbol");
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("POL").unwrap())
        .symbol(token_symbol)
        .decimals(10)
        .max_supply(AssetAmount::from(100u32))
        .build()
        .expect("failed to create faucet");

    let faucet_account = AccountBuilder::new(mock_seed)
        .with_component(faucet)
        .with_auth_component(AuthSingleSig::new(mock_public_key, AuthScheme::Falcon512Poseidon2))
        .build_existing()
        .expect("failed to create wallet account");

    let _fungible_faucet =
        FungibleFaucet::try_from(faucet_account).expect("fungible faucet creation failed");

    // invalid account: fungible faucet component is missing
    let invalid_faucet_account = AccountBuilder::new(mock_seed)
        .with_auth_component(AuthSingleSig::new(mock_public_key, AuthScheme::Falcon512Poseidon2))
        // we need to add some other component so the builder doesn't fail
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let err = FungibleFaucet::try_from(invalid_faucet_account)
        .expect_err("fungible faucet creation should fail");
    assert_matches!(err, FungibleFaucetError::MissingFungibleFaucetInterface);
}

/// Check that the obtaining of the fungible faucet procedure roots does not panic.
#[test]
fn get_faucet_procedures() {
    let _mint_and_send_root = FungibleFaucet::mint_and_send_root();
    let _receive_and_burn_root = FungibleFaucet::receive_and_burn_root();
    let _set_max_supply_root = FungibleFaucet::set_max_supply_root();
    let _set_description_root = FungibleFaucet::set_description_root();
    let _set_logo_uri_root = FungibleFaucet::set_logo_uri_root();
    let _set_external_link_root = FungibleFaucet::set_external_link_root();
    let _set_mint_policy_root = TokenPolicyManager::set_mint_policy_root();
    let _set_burn_policy_root = TokenPolicyManager::set_burn_policy_root();
    let _set_send_policy_root = TokenPolicyManager::set_send_policy_root();
    let _set_receive_policy_root = TokenPolicyManager::set_receive_policy_root();
}
