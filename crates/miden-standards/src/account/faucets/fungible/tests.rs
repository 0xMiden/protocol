use assert_matches::assert_matches;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::{AccountBuilder, AccountId, AccountType, StorageMapKey};
use miden_protocol::asset::{AssetAmount, FungibleAsset, TokenSymbol};
use miden_protocol::{Felt, Word};

use super::{
    FungibleFaucet,
    create_guarded_user_fungible_faucet,
    create_multisig_user_fungible_faucet,
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
};
use crate::account::faucets::{Description, FungibleFaucetError, TokenMetadata, TokenName};
use crate::account::fees::FeePolicyManager;
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

/// Every user faucet factory bundles the [`BasicWallet`] interface. See
/// [`create_singlesig_user_fungible_faucet`] for why a faucet is unusable on a fee-charging chain
/// without it.
///
/// This pins only that the interface is present; that a fee is actually payable end to end is
/// covered by `auth::fee_payment::faucet` in `miden-testing`.
#[test]
fn user_faucets_bundle_the_wallet_interface() {
    let init_seed: [u8; 32] = [
        90, 110, 209, 94, 84, 105, 250, 242, 223, 203, 216, 124, 22, 159, 14, 132, 215, 85, 183,
        204, 149, 90, 166, 68, 100, 73, 106, 168, 125, 237, 138, 16,
    ];
    let pub_key_word = Word::new([Felt::ONE; 4]);
    let approvers = vec![(pub_key_word.into(), AuthScheme::Falcon512Poseidon2)];
    // The guardian key has to differ from the approver set.
    let guardian_key = Word::new([Felt::ZERO, Felt::ONE, Felt::ONE, Felt::ONE]);
    let guardian =
        GuardianConfig::new(Approver::new(guardian_key.into(), AuthScheme::Falcon512Poseidon2));

    let singlesig = create_singlesig_user_fungible_faucet(
        init_seed,
        sample_faucet(),
        AuthSingleSig::new(Approver::new(pub_key_word.into(), AuthScheme::Falcon512Poseidon2)),
        allow_all_policy_manager(),
        AccountType::Private,
    )
    .unwrap();

    let multisig = create_multisig_user_fungible_faucet(
        init_seed,
        sample_faucet(),
        user_faucet_multisig(approvers.clone(), 1).unwrap(),
        allow_all_policy_manager(),
        AccountType::Private,
    )
    .unwrap();

    let guarded = create_guarded_user_fungible_faucet(
        init_seed,
        sample_faucet(),
        user_faucet_guarded(approvers, 1, guardian).unwrap(),
        allow_all_policy_manager(),
        AccountType::Private,
    )
    .unwrap();

    // Checked one root at a time so the failure names the procedure that went missing.
    for (label, account) in [("singlesig", singlesig), ("multisig", multisig), ("guarded", guarded)]
    {
        for (procedure, root) in [
            ("receive_asset", BasicWallet::receive_asset_root()),
            ("move_asset_to_note", BasicWallet::move_asset_to_note_root()),
            ("create_note", BasicWallet::create_note_root()),
        ] {
            assert!(
                account.code_interface().contains([root]),
                "{label} user faucet does not export `{procedure}`, so its wallet interface is \
                 incomplete; without `receive_asset` in particular it cannot be funded with the \
                 fee asset and can never transact on a fee-charging chain",
            );
        }
    }
}

/// The network faucet must *not* bundle [`BasicWallet`]: it is credited directly by
/// `fees::collect_sponsored_fees` rather than through `receive_asset`, so the wallet interface
/// would widen its surface for nothing.
#[test]
fn network_fungible_faucet_omits_the_wallet_interface() {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;

    let owner = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE).unwrap();

    let account = create_network_fungible_faucet(
        [9u8; 32],
        sample_faucet(),
        AccessControl::Ownable2Step { owner },
        allow_all_policy_manager(),
        FeePolicyManager::mock(FungibleAsset::mock_issuer()),
    )
    .unwrap();

    // Checked one root at a time: `!contains([a, b, c])` is satisfied as soon as a single root is
    // absent, so it would not catch a partially installed wallet.
    for (label, root) in [
        ("receive_asset", BasicWallet::receive_asset_root()),
        ("move_asset_to_note", BasicWallet::move_asset_to_note_root()),
        ("create_note", BasicWallet::create_note_root()),
    ] {
        assert!(
            !account.code_interface().contains([root]),
            "network faucet should fund itself through `collect_sponsored_fees`, but it exports \
             `{label}`",
        );
    }
}
