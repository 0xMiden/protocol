use alloc::vec::Vec;

use assert_matches::assert_matches;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::{
    Account,
    AccountId,
    AccountStorage,
    AccountType,
    AssetCallbackFlag,
    StorageSlot,
};
use miden_protocol::asset::{FungibleAsset, NonFungibleAsset, TokenSymbol};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::{Felt, Word};

use super::{
    NonFungibleFaucet,
    TokenBaseUri,
    create_guarded_user_non_fungible_faucet,
    create_multisig_user_non_fungible_faucet,
    create_network_non_fungible_faucet,
    create_singlesig_user_non_fungible_faucet,
};
use crate::account::access::AccessControl;
use crate::account::auth::{Approver, AuthSingleSig, GuardianConfig};
use crate::account::faucets::test_utils::{
    allow_all_policy_manager,
    mint_burn_only_policy_manager,
    owner_only_mint_policy_manager,
};
use crate::account::faucets::{NonFungibleFaucetError, TokenName};
use crate::account::fees::FeePolicyManager;
use crate::account::policies::TokenPolicyManager;
use crate::testing::faucet::{user_faucet_guarded, user_faucet_multisig};
use crate::utils::FixedWidthStringError;

/// Building a faucet exposes the configured fields.
#[test]
fn non_fungible_faucet_fields() -> anyhow::Result<()> {
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new("Example Collection")?)
        .symbol(TokenSymbol::new("EC")?)
        .build()?;

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
        .unwrap()
}

/// Reads a faucet back from the given storage slots.
fn decode_storage(slots: Vec<StorageSlot>) -> Result<NonFungibleFaucet, NonFungibleFaucetError> {
    NonFungibleFaucet::try_from(&AccountStorage::new(slots).unwrap())
}

/// The token base URI cannot be empty: an empty one marks private token metadata, which is
/// represented by its absence.
#[test]
fn token_base_uri_rejects_empty_string() {
    assert_matches!(TokenBaseUri::new(""), Err(FixedWidthStringError::Empty));
}

/// A mutable token base URI that is not set could never be set, since the setter cannot switch
/// it from empty to non-empty, so the builder rejects it.
#[test]
fn builder_rejects_mutable_empty_token_base_uri() -> anyhow::Result<()> {
    let result = NonFungibleFaucet::builder()
        .name(TokenName::new("Example Collection")?)
        .symbol(TokenSymbol::new("EC")?)
        .is_token_base_uri_mutable(true)
        .build();

    assert_matches!(result, Err(NonFungibleFaucetError::MutableEmptyTokenBaseUri));

    Ok(())
}

/// The token base URI and its mutability flag survive a round trip through account storage.
#[rstest::rstest]
#[case::private(None, false)]
#[case::public_immutable(Some("ipfs://bafybeigdyrzt/"), false)]
#[case::public_mutable(Some("https://example.com/tokens/"), true)]
fn token_base_uri_roundtrips_through_storage(
    #[case] token_base_uri: Option<&str>,
    #[case] is_token_base_uri_mutable: bool,
) -> anyhow::Result<()> {
    let token_base_uri = token_base_uri.map(TokenBaseUri::new).transpose()?;
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new("Example Collection")?)
        .symbol(TokenSymbol::new("EC")?)
        .maybe_token_base_uri(token_base_uri.clone())
        .is_token_base_uri_mutable(is_token_base_uri_mutable)
        .build()?;

    let decoded = decode_storage(faucet.into_storage_slots())?;

    assert_eq!(decoded.token_base_uri(), token_base_uri.as_ref());
    assert_eq!(decoded.is_token_base_uri_mutable(), is_token_base_uri_mutable);

    Ok(())
}

/// Decoding rejects a non-fungible mutability config the builder cannot produce.
#[test]
fn decoding_rejects_invalid_token_base_uri_mutability() {
    let with_mutability_config = |mutability_config: Word| {
        sample_faucet()
            .into_storage_slots()
            .into_iter()
            .map(|slot| {
                if slot.name() == NonFungibleFaucet::mutability_config_slot() {
                    StorageSlot::with_value(slot.name().clone(), mutability_config)
                } else {
                    slot
                }
            })
            .collect()
    };

    assert_matches!(
        decode_storage(with_mutability_config(Word::from([1u32, 0, 0, 0]))),
        Err(NonFungibleFaucetError::MutableEmptyTokenBaseUri)
    );
    assert_matches!(
        decode_storage(with_mutability_config(Word::from([2u32, 0, 0, 0]))),
        Err(NonFungibleFaucetError::InvalidTokenBaseUriMutabilityFlag { value: 2 })
    );
}

/// A token's URI is the token base URI followed by the token ID in its `AssetClass` form: `0x`,
/// then the prefix (value element 1) and the suffix (value element 0) as 16-digit hex each.
#[test]
fn token_uri_is_token_base_uri_followed_by_token_id() -> anyhow::Result<()> {
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET)?;
    let asset = NonFungibleAsset::from_parts(faucet_id, Word::from([0xab_u32, 0xcd, 3, 4]));

    let public_faucet = NonFungibleFaucet::builder()
        .name(TokenName::new("Example Collection")?)
        .symbol(TokenSymbol::new("EC")?)
        .token_base_uri(TokenBaseUri::new("ipfs://bafybeigdyrzt/")?)
        .build()?;

    assert_eq!(
        public_faucet.token_uri(&asset).as_deref(),
        Some("ipfs://bafybeigdyrzt/0x00000000000000cd00000000000000ab")
    );
    assert_eq!(sample_faucet().token_uri(&asset), None);

    Ok(())
}

/// Builds one faucet with each user-account factory: single-sig, multisig and guarded.
fn user_faucets(token_policy_manager: TokenPolicyManager) -> [Account; 3] {
    let approver = Approver::new(
        PublicKeyCommitment::from(Word::new([Felt::from(11_u32); 4])),
        AuthScheme::Falcon512Eidos,
    );
    let approvers: Vec<_> = (1..=3_u32)
        .map(|i| {
            (
                PublicKeyCommitment::from(Word::new([Felt::from(i); 4])),
                AuthScheme::Falcon512Eidos,
            )
        })
        .collect();

    let singlesig = create_singlesig_user_non_fungible_faucet(
        [31u8; 32],
        sample_faucet(),
        AuthSingleSig::new(approver),
        token_policy_manager.clone(),
        AccountType::Private,
    )
    .unwrap();

    let multisig = create_multisig_user_non_fungible_faucet(
        [33u8; 32],
        sample_faucet(),
        user_faucet_multisig(approvers.clone(), 2).unwrap(),
        token_policy_manager.clone(),
        AccountType::Private,
    )
    .unwrap();

    let guarded = create_guarded_user_non_fungible_faucet(
        [34u8; 32],
        sample_faucet(),
        user_faucet_guarded(approvers, 2, GuardianConfig::new(approver)).unwrap(),
        token_policy_manager,
        AccountType::Private,
    )
    .unwrap();

    [singlesig, multisig, guarded]
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
    for user in user_faucets(token_policy_manager.clone()) {
        assert_eq!(user.id().asset_callback_flag(), expected_flag);
    }

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
    let data = b"token #1 metadata";
    let salt_a = Word::from([1u32, 2, 3, 4]);
    let salt_b = Word::from([5u32, 6, 7, 8]);

    let c_a = NonFungibleFaucet::compute_asset_commitment(data, salt_a);
    let c_b = NonFungibleFaucet::compute_asset_commitment(data, salt_b);

    assert_eq!(c_a, NonFungibleFaucet::compute_asset_commitment(data, salt_a));
    assert_ne!(c_a, c_b);
}

/// A user faucet installs no `Ownable2Step` component, so an owner-gated mint policy would have no
/// owner slot to read and every mint would abort. The factory must reject that configuration.
#[test]
fn user_non_fungible_faucet_rejects_owner_only_mint_policy() {
    let auth_component = AuthSingleSig::new(Approver::new(
        Word::new([Felt::ONE; 4]).into(),
        AuthScheme::Falcon512Eidos,
    ));

    let err = create_singlesig_user_non_fungible_faucet(
        [21u8; 32],
        sample_faucet(),
        auth_component,
        owner_only_mint_policy_manager(),
        AccountType::Private,
    )
    .expect_err("owner-only mint policy without Ownable2Step should be rejected");

    assert_matches!(err, NonFungibleFaucetError::OwnerOnlyPolicyWithoutOwnable2Step);
}
