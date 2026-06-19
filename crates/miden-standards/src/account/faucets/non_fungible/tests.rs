use miden_protocol::asset::TokenSymbol;

use super::NonFungibleFaucet;
use crate::account::faucets::{NonFungibleFaucetError, TokenName};

/// Building a faucet and round-tripping its storage slots reconstructs the same config.
#[test]
fn non_fungible_faucet_storage_round_trip() -> anyhow::Result<()> {
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new("Example Collection")?)
        .symbol(TokenSymbol::new("EC")?)
        .max_supply(10_000)
        .build()?;

    assert_eq!(faucet.max_supply(), 10_000);
    assert_eq!(faucet.current_supply(), 0);
    assert_eq!(faucet.symbol(), &TokenSymbol::new("EC")?);

    // building the component must not panic
    let _component: miden_protocol::account::AccountComponent = faucet.into();

    Ok(())
}

/// A `max_supply` of 0 is stored as the unlimited sentinel (the maximum field element).
#[test]
fn non_fungible_faucet_unlimited_supply() -> anyhow::Result<()> {
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new("Unlimited")?)
        .symbol(TokenSymbol::new("UNL")?)
        .build()?;

    assert_eq!(faucet.max_supply(), NonFungibleFaucet::UNLIMITED_MAX_SUPPLY);

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

#[allow(unused)]
fn _error_is_constructible(e: NonFungibleFaucetError) -> NonFungibleFaucetError {
    e
}
