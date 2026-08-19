use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::{AccountId, AccountType, AssetCallbackFlag};
use miden_protocol::asset::{FungibleAsset, TokenSymbol};
use miden_protocol::{Felt, Word};

use super::{
    NonFungibleFaucet,
    create_network_non_fungible_faucet,
    create_user_non_fungible_faucet,
};
use crate::account::access::AccessControl;
use crate::account::auth::{Approver, AuthSingleSig};
use crate::account::faucets::TokenName;
use crate::account::faucets::test_utils::{
    allow_all_policy_manager,
    mint_burn_only_policy_manager,
};
use crate::account::fees::FeePolicyManager;
use crate::account::policies::TokenPolicyManager;

/// Building a faucet exposes the configured fields.
#[test]
fn non_fungible_faucet_fields() -> anyhow::Result<()> {
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new("Example Collection")?)
        .symbol(TokenSymbol::new("EC")?)
        .build();

    assert_eq!(faucet.symbol(), &TokenSymbol::new("EC")?);
    assert_eq!(faucet.token_name(), &TokenName::new("Example Collection")?);

    Ok(())
}

/// Builds a sample [`NonFungibleFaucet`] shared by the factory tests.
fn sample_faucet() -> NonFungibleFaucet {
    NonFungibleFaucet::builder()
        .name(TokenName::new("Example Collection").unwrap())
        .symbol(TokenSymbol::new("EC").unwrap())
        .build()
}

/// Every non-fungible faucet factory must grind `AssetCallbackFlag::Enabled` into the account ID
/// when the policy manager registers a transfer policy, and `Disabled` when it does not.
#[rstest::rstest]
#[case::with_transfer_policy(allow_all_policy_manager(), AssetCallbackFlag::Enabled)]
#[case::without_transfer_policy(mint_burn_only_policy_manager(), AssetCallbackFlag::Disabled)]
fn non_fungible_faucet_factories_encode_transfer_policy_callback_flag(
    #[case] token_policy_manager: TokenPolicyManager,
    #[case] expected_flag: AssetCallbackFlag,
) {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;

    let approver = Approver::new(
        PublicKeyCommitment::from(Word::new([Felt::from(11_u32); 4])),
        AuthScheme::Falcon512Poseidon2,
    );

    let user = create_user_non_fungible_faucet(
        [31u8; 32],
        sample_faucet(),
        AuthSingleSig::new(approver),
        token_policy_manager.clone(),
        AccountType::Private,
    )
    .unwrap();
    assert_eq!(user.id().asset_callback_flag(), expected_flag);

    let owner = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE).unwrap();
    let network = create_network_non_fungible_faucet(
        [32u8; 32],
        sample_faucet(),
        AccessControl::Ownable2Step { owner },
        token_policy_manager,
        FeePolicyManager::mock(FungibleAsset::mock_issuer()),
    )
    .unwrap();
    assert_eq!(network.id().asset_callback_flag(), expected_flag);
}

/// `compute_asset_commitment` is deterministic and salt-sensitive.
#[test]
fn compute_asset_commitment_is_salt_sensitive() {
    use miden_protocol::Word;

    let data = b"token #1 metadata";
    let salt_a = Word::from([1u32, 2, 3, 4]);
    let salt_b = Word::from([5u32, 6, 7, 8]);

    let c_a = NonFungibleFaucet::compute_asset_commitment(data, salt_a);
    let c_b = NonFungibleFaucet::compute_asset_commitment(data, salt_b);

    assert_eq!(c_a, NonFungibleFaucet::compute_asset_commitment(data, salt_a));
    assert_ne!(c_a, c_b);
}
