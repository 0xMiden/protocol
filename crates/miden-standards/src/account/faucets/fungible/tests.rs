use assert_matches::assert_matches;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::{AccountBuilder, AccountId, AccountType, StorageMapKey};
use miden_protocol::asset::{AssetAmount, AssetId, FungibleAsset, TokenSymbol};
use miden_protocol::{Felt, Word};

use super::{
    FungibleFaucet,
    create_guarded_user_fungible_faucet,
    create_multisig_user_fungible_faucet,
    create_native_fungible_faucet_for_genesis,
    create_network_fungible_faucet,
    create_singlesig_user_fungible_faucet,
};
use crate::account::access::{AccessControl, Authority};
use crate::account::auth::{
    Approver,
    AuthGuardedMultisig,
    AuthMultisig,
    AuthNetworkAccount,
    AuthSingleSig,
    GuardianConfig,
    NetworkAccount,
};
use crate::account::faucets::{Description, FungibleFaucetError, TokenMetadata, TokenName};
use crate::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use crate::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager, TransferPolicy};
use crate::account::wallets::BasicWallet;
use crate::testing::faucet::{user_faucet_guarded, user_faucet_multisig};
use crate::tx_script::ExpirationTransactionScript;

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

#[test]
fn user_fungible_faucet_with_single_sig() {
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
        AuthSingleSig::new(Approver::new(pub_key_word.into(), AuthScheme::Falcon512Poseidon2));

    let faucet_account = create_singlesig_user_fungible_faucet(
        init_seed,
        sample_faucet(),
        auth_component,
        allow_all_policy_manager(),
        AccountType::Private,
    )
    .unwrap();

    // The auth component's public key should be present.
    assert_eq!(
        faucet_account.storage().get_item(AuthSingleSig::public_key_slot()).unwrap(),
        pub_key_word
    );

    // Authority-gated setters are gated by the auth component itself, not by a separate owner /
    // role check.
    assert_eq!(
        Authority::try_from_storage(faucet_account.storage()).unwrap(),
        Authority::AuthControlled
    );

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

/// Builds `n` distinct approver `(PublicKeyCommitment, AuthScheme)` pairs for multisig tests.
fn sample_approvers(n: u32) -> alloc::vec::Vec<(PublicKeyCommitment, AuthScheme)> {
    (0..n)
        .map(|i| {
            (
                PublicKeyCommitment::from(Word::new([Felt::from(i + 1); 4])),
                AuthScheme::Falcon512Poseidon2,
            )
        })
        .collect()
}

#[test]
fn user_fungible_faucet_with_multisig() {
    let threshold = 2;
    let num_approvers = 3;
    let auth_component = user_faucet_multisig(sample_approvers(num_approvers), threshold).unwrap();

    let faucet_account = create_multisig_user_fungible_faucet(
        [3u8; 32],
        sample_faucet(),
        auth_component,
        allow_all_policy_manager(),
        AccountType::Private,
    )
    .unwrap();

    // Threshold config slot layout: [threshold, num_approvers, 0, 0].
    assert_eq!(
        faucet_account
            .storage()
            .get_item(AuthMultisig::threshold_config_slot())
            .unwrap(),
        [Felt::from(threshold), Felt::from(num_approvers), Felt::ZERO, Felt::ZERO].into()
    );

    // No per-procedure overrides are configured, so every authority-gated setter is governed by
    // the default threshold asserted above (`AuthMultisig` is fail-closed).

    // The faucet component round-trips from the built account.
    let _faucet_component = FungibleFaucet::try_from(faucet_account).unwrap();
}

#[test]
fn user_fungible_faucet_with_guarded_multisig() {
    let threshold = 2;
    let num_approvers = 3;
    let approver = Approver::new(
        PublicKeyCommitment::from(Word::new([Felt::from(99_u32); 4])),
        AuthScheme::Falcon512Poseidon2,
    );
    let guardian = GuardianConfig::new(approver);
    let auth_component =
        user_faucet_guarded(sample_approvers(num_approvers), threshold, guardian).unwrap();

    let faucet_account = create_guarded_user_fungible_faucet(
        [4u8; 32],
        sample_faucet(),
        auth_component,
        allow_all_policy_manager(),
        AccountType::Private,
    )
    .unwrap();

    // Threshold config slot layout: [threshold, num_approvers, 0, 0].
    assert_eq!(
        faucet_account
            .storage()
            .get_item(AuthGuardedMultisig::threshold_config_slot())
            .unwrap(),
        [Felt::from(threshold), Felt::from(num_approvers), Felt::ZERO, Felt::ZERO].into()
    );

    // No per-procedure overrides are configured, so every authority-gated setter is governed by
    // the default threshold asserted above (`AuthGuardedMultisig` is fail-closed).

    // The faucet component round-trips from the built account.
    let _faucet_component = FungibleFaucet::try_from(faucet_account).unwrap();
}

/// `create_network_fungible_faucet` with `Ownable2Step` builds a valid account. The factory
/// constructs `AuthNetworkAccount` internally; the setter gate is enforced in-procedure by
/// `assert_sender_is_owner`.
#[test]
fn network_fungible_faucet_with_ownable2step() {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;

    let owner = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE).unwrap();

    let _account = create_network_fungible_faucet(
        [7u8; 32],
        sample_faucet(),
        AccessControl::Ownable2Step { owner },
        allow_all_policy_manager(),
        FeePolicyManager::mock(FungibleAsset::mock_issuer()),
    )
    .expect("Ownable2Step network faucet should be accepted");
}

/// `create_network_fungible_faucet` allowlists the canonical `ExpirationTransactionScript` in the
/// tx-script allowlist so submitters can shorten their transaction's expiration.
#[test]
fn network_fungible_faucet_allowlists_expiration_tx_script() {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;

    let owner = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE).unwrap();

    let account = create_network_fungible_faucet(
        [8u8; 32],
        sample_faucet(),
        AccessControl::Ownable2Step { owner },
        allow_all_policy_manager(),
        FeePolicyManager::mock(FungibleAsset::mock_issuer()),
    )
    .unwrap();

    // The expiration tx-script root is flagged as allowed ([1, 0, 0, 0]) in the allowlist map.
    let stored = account
        .storage()
        .get_map_item(
            AuthNetworkAccount::allowed_tx_scripts_slot(),
            StorageMapKey::new(ExpirationTransactionScript::script_root().as_word()),
        )
        .unwrap();
    assert_eq!(stored, [Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO].into());
}

/// The genesis native faucet uses its own asset for fees.
#[test]
fn native_fungible_faucet_for_genesis_uses_its_own_fee_asset() {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;

    const INIT_SEED: [u8; 32] = [9; 32];

    let operator = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE).unwrap();
    let account = create_native_fungible_faucet_for_genesis(
        INIT_SEED,
        sample_faucet(),
        operator,
        allow_all_policy_manager(),
        BasicConstantFeePolicy::new(),
    )
    .unwrap();

    assert_eq!(account.nonce(), Felt::ONE);
    assert_eq!(account.seed(), None);
    assert!(NetworkAccount::new(account.clone()).is_ok());
    assert_eq!(
        account.storage().get_item(FeePolicyManager::fee_asset_id_slot()).unwrap(),
        AssetId::new_fungible(account.id()).to_word()
    );
    assert_eq!(
        account.storage().get_item(FeePolicyManager::active_fee_policy_slot()).unwrap(),
        BasicConstantFeePolicy::root().as_word()
    );
    assert_eq!(
        account
            .storage()
            .get_map_item(
                FeePolicyManager::allowed_fee_policies_slot(),
                StorageMapKey::new(BasicConstantFeePolicy::root().as_word()),
            )
            .unwrap(),
        Word::from([1u32, 0, 0, 0])
    );

    // Recreate the storage commitment used to derive the account ID.
    let id = account.id();
    let (_id, _vault, mut initial_storage, code, _nonce, _seed) = account.into_parts();
    initial_storage
        .set_item(FeePolicyManager::fee_asset_id_slot(), Word::empty())
        .unwrap();
    let code_commitment = code.commitment();
    let storage_commitment = initial_storage.to_commitment();
    let account_seed = AccountId::compute_account_seed(
        INIT_SEED,
        AccountType::Public,
        id.asset_callback_flag(),
        id.version(),
        code_commitment,
        storage_commitment,
    )
    .unwrap();
    let derived_id =
        AccountId::new(account_seed, id.version(), code_commitment, storage_commitment).unwrap();

    assert_eq!(derived_id, id);
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
        .with_component(AuthSingleSig::new(Approver::new(
            mock_public_key,
            AuthScheme::Falcon512Poseidon2,
        )))
        .build_existing()
        .expect("failed to create wallet account");

    let _fungible_faucet =
        FungibleFaucet::try_from(faucet_account).expect("fungible faucet creation failed");

    // invalid account: fungible faucet component is missing
    let invalid_faucet_account = AccountBuilder::new(mock_seed)
        .with_component(AuthSingleSig::new(Approver::new(
            mock_public_key,
            AuthScheme::Falcon512Poseidon2,
        )))
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
