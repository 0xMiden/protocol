use alloc::collections::BTreeSet;

use assert_matches::assert_matches;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::{AccountBuilder, AccountType};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::{Felt, Word};

use super::{
    FungibleFaucet,
    create_network_fungible_faucet,
    create_user_fungible_faucet,
    user_faucet_single_sig_acl,
};
use crate::account::access::{AccessControl, PausableManager};
use crate::account::auth::{AccountAuthComponent, AuthSingleSig, AuthSingleSigAcl};
use crate::account::faucets::{Description, FungibleFaucetError, TokenMetadata, TokenName};
use crate::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager, TransferPolicy};
use crate::account::wallets::BasicWallet;

/// Builds a minimal policy manager with AllowAll on every kind, used by the construction tests.
fn allow_all_policy_manager() -> TokenPolicyManager {
    TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build()
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
fn user_fungible_faucet_with_single_sig_acl() {
    let pub_key_word = Word::new([Felt::ONE; 4]);
    let init_seed: [u8; 32] = [
        90, 110, 209, 94, 84, 105, 250, 242, 223, 203, 216, 124, 22, 159, 14, 132, 215, 85, 183,
        204, 149, 90, 166, 68, 100, 73, 106, 168, 125, 237, 138, 16,
    ];

    let token_symbol_string = "POL";
    let token_symbol = TokenSymbol::try_from(token_symbol_string).unwrap();
    let token_name_string = "polygon";
    let description_string = "A polygon token";

    let auth_component =
        user_faucet_single_sig_acl(pub_key_word.into(), AuthScheme::Falcon512Poseidon2).unwrap();

    let faucet_account = create_user_fungible_faucet(
        init_seed,
        sample_faucet(),
        auth_component,
        allow_all_policy_manager(),
        AccountType::Private,
    )
    .unwrap();

    // The auth component's public key should be present.
    assert_eq!(
        faucet_account.storage().get_item(AuthSingleSigAcl::public_key_slot()).unwrap(),
        pub_key_word
    );

    // Config slot: 11 trigger procedures (mint_and_send + 4 token metadata setters + 4 policy
    // setters + pause + unpause), allow_unauthorized_input_notes=true → [11, 0, 1, 0].
    assert_eq!(
        faucet_account.storage().get_item(AuthSingleSigAcl::config_slot()).unwrap(),
        [Felt::from(11_u32), Felt::ZERO, Felt::ONE, Felt::ZERO].into()
    );

    let stored_roots = read_trigger_procedure_roots(&faucet_account, 11);
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
        PausableManager::pause_root(),
        PausableManager::unpause_root(),
    ]
    .into_iter()
    .map(|root| root.as_word())
    .collect();
    assert_eq!(stored_roots, expected_roots);

    // Token config slot layout: [token_supply, max_supply, decimals, symbol]
    assert_eq!(
        faucet_account.storage().get_item(FungibleFaucet::token_config_slot()).unwrap(),
        [Felt::ZERO, Felt::from(123_u32), Felt::from(2_u32), token_symbol.into()].into()
    );

    let name_0 = faucet_account.storage().get_item(TokenMetadata::name_chunk_0_slot()).unwrap();
    let name_1 = faucet_account.storage().get_item(TokenMetadata::name_chunk_1_slot()).unwrap();
    let decoded_name = TokenName::try_from_words(&[name_0, name_1]).unwrap();
    assert_eq!(decoded_name.as_str(), token_name_string);
    let expected_desc_words = Description::new(description_string).unwrap().to_words();
    for (i, expected) in expected_desc_words.iter().enumerate() {
        let chunk = faucet_account.storage().get_item(TokenMetadata::description_slot(i)).unwrap();
        assert_eq!(chunk, *expected);
    }

    let _faucet_component = FungibleFaucet::try_from(faucet_account.clone()).unwrap();
}

/// `create_user_fungible_faucet` with `NoAuth` must be rejected: the auth component is the
/// sole gate for authority-protected setters.
#[test]
fn user_fungible_faucet_rejects_no_auth() {
    let err = create_user_fungible_faucet(
        [7u8; 32],
        sample_faucet(),
        AccountAuthComponent::no_auth(),
        allow_all_policy_manager(),
        AccountType::Private,
    )
    .expect_err("user faucet with NoAuth should be rejected");
    assert_matches!(err, FungibleFaucetError::IncompatibleAuthControlledAuth(_));
}

/// `create_user_fungible_faucet` with a plain `SingleSig` (no ACL) must be rejected: the
/// trigger list would be empty, leaving authority-gated setters permissionless. Callers must
/// use `user_faucet_single_sig_acl`.
#[test]
fn user_fungible_faucet_rejects_plain_single_sig() {
    let pub_key_word = Word::new([Felt::ONE; 4]);
    let err = create_user_fungible_faucet(
        [7u8; 32],
        sample_faucet(),
        AccountAuthComponent::single_sig(pub_key_word.into(), AuthScheme::Falcon512Poseidon2),
        allow_all_policy_manager(),
        AccountType::Private,
    )
    .expect_err("user faucet with plain SingleSig should be rejected");
    assert_matches!(err, FungibleFaucetError::UnsupportedAccessControlAuthCombination(_));
}

/// `create_user_fungible_faucet` with NetworkAccount must be rejected: network-style auth
/// belongs with `create_network_fungible_faucet`.
#[test]
fn user_fungible_faucet_rejects_network_account() {
    let allowlist: BTreeSet<miden_protocol::note::NoteScriptRoot> =
        [miden_protocol::note::NoteScriptRoot::from_raw(Word::new([Felt::ONE; 4]))]
            .into_iter()
            .collect();
    let err = create_user_fungible_faucet(
        [7u8; 32],
        sample_faucet(),
        AccountAuthComponent::network_account(allowlist).unwrap(),
        allow_all_policy_manager(),
        AccountType::Private,
    )
    .expect_err("user faucet with NetworkAccount should be rejected");
    assert_matches!(err, FungibleFaucetError::UnsupportedAccessControlAuthCombination(_));
}

/// `create_network_fungible_faucet` with `Ownable2Step + NoAuth` is a valid configuration: the
/// setter gate is enforced in-procedure (`assert_sender_is_owner`).
#[test]
fn network_fungible_faucet_ownable2step_with_no_auth_is_accepted() {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;

    let owner = miden_protocol::account::AccountId::try_from(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    )
    .unwrap();

    let _account = create_network_fungible_faucet(
        [7u8; 32],
        sample_faucet(),
        AccessControl::Ownable2Step { owner },
        AccountAuthComponent::no_auth(),
        allow_all_policy_manager(),
        AccountType::Public,
    )
    .expect("Ownable2Step+NoAuth should be accepted");
}

/// `create_network_fungible_faucet` with SingleSig must be rejected: SingleSig belongs with
/// the user-account faucet factory.
#[test]
fn network_fungible_faucet_rejects_single_sig() {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;

    let owner = miden_protocol::account::AccountId::try_from(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    )
    .unwrap();

    let err = create_network_fungible_faucet(
        [7u8; 32],
        sample_faucet(),
        AccessControl::Ownable2Step { owner },
        AccountAuthComponent::single_sig(
            Word::new([Felt::ONE; 4]).into(),
            AuthScheme::Falcon512Poseidon2,
        ),
        allow_all_policy_manager(),
        AccountType::Public,
    )
    .expect_err("network faucet with SingleSig should be rejected");
    assert_matches!(err, FungibleFaucetError::UnsupportedAccessControlAuthCombination(_));
}

#[test]
fn faucet_create_from_account() {
    let mock_word = Word::from([0, 1, 2, 3u32]);
    let mock_public_key = PublicKeyCommitment::from(mock_word);
    let mock_seed = mock_word.as_bytes();

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
