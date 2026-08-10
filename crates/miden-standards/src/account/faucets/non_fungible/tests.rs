use assert_matches::assert_matches;
use miden_protocol::account::AccountType;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::TokenSymbol;
use miden_protocol::errors::AccountError;
use miden_protocol::{Felt, Word};

use super::{NonFungibleFaucet, create_user_non_fungible_faucet};
use crate::account::access::Ownable2Step;
use crate::account::auth::{Approver, AuthSingleSig};
use crate::account::faucets::{NonFungibleFaucetError, TokenName};
use crate::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager};

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

/// A user faucet installs no `Ownable2Step` component, so an owner-only mint policy has no owner
/// slot to read and every mint would abort. The factory must reject that configuration.
#[test]
fn user_non_fungible_faucet_rejects_owner_only_mint_policy() {
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new("Example Collection").unwrap())
        .symbol(TokenSymbol::new("EC").unwrap())
        .build();

    let auth_component = AuthSingleSig::new(Approver::new(
        Word::new([Felt::ONE; 4]).into(),
        AuthScheme::Falcon512Poseidon2,
    ));

    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::allow_all())
        .build();

    let err = create_user_non_fungible_faucet(
        [21u8; 32],
        faucet,
        auth_component,
        token_policy_manager,
        AccountType::Private,
    )
    .expect_err("owner-only mint policy without Ownable2Step should be rejected");

    assert_matches!(err, NonFungibleFaucetError::AccountCreationFailed(AccountError::BuildError(_, Some(source))) => {
        assert_matches!(*source, AccountError::UnsatisfiedComponentDependency { slot_name, .. } => {
            assert_eq!(&slot_name, Ownable2Step::slot_name());
        });
    });
}
