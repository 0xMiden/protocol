use assert_matches::assert_matches;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::{AccountBuilder, AccountStorageMode, AccountType};
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
    PolicyAuthority,
    PolicyRegistration,
    TokenPolicyManager,
    TransferPolicy,
};
use crate::account::wallets::BasicWallet;

#[test]
fn faucet_contract_creation() {
    let pub_key_word = Word::new([Felt::ONE; 4]);
    let auth_method: AuthMethod = AuthMethod::SingleSig {
        approver: (pub_key_word.into(), AuthScheme::Falcon512Poseidon2),
    };

    // we need to use an initial seed to create the wallet account
    let init_seed: [u8; 32] = [
        90, 110, 209, 94, 84, 105, 250, 242, 223, 203, 216, 124, 22, 159, 14, 132, 215, 85, 183,
        204, 149, 90, 166, 68, 100, 73, 106, 168, 125, 237, 138, 16,
    ];

    let max_supply = AssetAmount::new(123).unwrap();
    let token_symbol_string = "POL";
    let token_symbol = TokenSymbol::try_from(token_symbol_string).unwrap();
    let token_name_string = "polygon";
    let description_string = "A polygon token";
    let decimals = 2u8;
    let storage_mode = AccountStorageMode::Private;

    let token_name = TokenName::new(token_name_string).unwrap();
    let description = Description::new(description_string).unwrap();
    let faucet = FungibleFaucet::builder(token_name, token_symbol.clone(), decimals, max_supply)
        .description(description)
        .build()
        .unwrap();
    let faucet_account = create_fungible_faucet(
        init_seed,
        faucet,
        storage_mode,
        auth_method,
        AccessControl::AuthControlled,
        TokenPolicyManager::new(PolicyAuthority::AuthControlled)
            .with_mint_policy(MintPolicyConfig::AllowAll, PolicyRegistration::Active)
            .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)
            .with_send_policy(TransferPolicy::AllowAll, PolicyRegistration::Active)
            .with_receive_policy(TransferPolicy::AllowAll, PolicyRegistration::Active),
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
    // With 1 trigger procedure (mint_and_send), allow_unauthorized_output_notes=false, and
    // allow_unauthorized_input_notes=true, this should be [1, 0, 1, 0].
    assert_eq!(
        faucet_account.storage().get_item(AuthSingleSigAcl::config_slot()).unwrap(),
        [Felt::ONE, Felt::ZERO, Felt::ONE, Felt::ZERO].into()
    );

    // The procedure root map should contain the mint_and_send procedure root.
    let mint_root = FungibleFaucet::mint_and_send_digest();
    assert_eq!(
        faucet_account
            .storage()
            .get_map_item(
                AuthSingleSigAcl::trigger_procedure_roots_slot(),
                [Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO].into()
            )
            .unwrap(),
        mint_root
    );

    // Check that faucet metadata was initialized to the given values.
    // Storage layout: [token_supply, max_supply, decimals, symbol]
    assert_eq!(
        faucet_account.storage().get_item(FungibleFaucet::token_config_slot()).unwrap(),
        [Felt::ZERO, Felt::new(123), Felt::new(2), token_symbol.into()].into()
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

    assert!(faucet_account.is_faucet());

    assert_eq!(faucet_account.account_type(), AccountType::FungibleFaucet);

    // Verify the faucet component can be extracted
    let _faucet_component = FungibleFaucet::try_from(faucet_account.clone()).unwrap();
}

#[test]
fn faucet_create_from_account() {
    // prepare the test data
    let mock_word = Word::from([0, 1, 2, 3u32]);
    let mock_public_key = PublicKeyCommitment::from(mock_word);
    let mock_seed = mock_word.as_bytes();

    // valid account
    let token_symbol = TokenSymbol::new("POL").expect("invalid token symbol");
    let faucet = FungibleFaucet::builder(
        TokenName::new("POL").unwrap(),
        token_symbol,
        10,
        AssetAmount::new(100).unwrap(),
    )
    .build()
    .expect("failed to create faucet");

    let faucet_account = AccountBuilder::new(mock_seed)
        .account_type(AccountType::FungibleFaucet)
        .with_component(faucet)
        .with_auth_component(AuthSingleSig::new(mock_public_key, AuthScheme::Falcon512Poseidon2))
        .build_existing()
        .expect("failed to create wallet account");

    let _fungible_faucet =
        FungibleFaucet::try_from(faucet_account).expect("fungible faucet creation failed");

    // invalid account: fungible faucet component is missing
    let invalid_faucet_account = AccountBuilder::new(mock_seed)
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(AuthSingleSig::new(mock_public_key, AuthScheme::Falcon512Poseidon2))
        // we need to add some other component so the builder doesn't fail
        .with_component(BasicWallet)
        .build_existing()
        .expect("failed to create wallet account");

    let err = FungibleFaucet::try_from(invalid_faucet_account)
        .expect_err("fungible faucet creation should fail");
    assert_matches!(err, FungibleFaucetError::MissingFungibleFaucetInterface);
}

/// Check that the obtaining of the fungible faucet procedure digests does not panic.
#[test]
fn get_faucet_procedures() {
    let _mint_and_send_digest = FungibleFaucet::mint_and_send_digest();
    let _receive_and_burn_digest = FungibleFaucet::receive_and_burn_digest();
}
