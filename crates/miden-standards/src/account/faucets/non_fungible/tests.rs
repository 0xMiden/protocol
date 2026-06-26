use miden_protocol::asset::TokenSymbol;

use super::NonFungibleFaucet;
use crate::account::faucets::TokenName;

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
