extern crate alloc;

use miden_agglayer::testing::create_existing_agglayer_faucet;
use miden_protocol::Felt;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_standards::account::access::Ownable2Step;
use miden_standards::account::faucets::FungibleFaucet;
use miden_testing::{Auth, MockChain};

use super::test_utils::{
    MIDEN_NETWORK_ID,
    bridge_admin_account_id,
    create_existing_bridge_account_with_roles,
};

/// An agglayer faucet is a standard [`FungibleFaucet`] owned by the bridge.
///
/// This pins the two properties the bridge depends on: the faucet exposes the standard fungible
/// faucet interface with its token metadata intact - including the real token *name*, which the
/// AggLayer metadata hash is computed over - and its `Ownable2Step` owner is the bridge account.
#[test]
fn agglayer_faucet_is_a_bridge_owned_fungible_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let faucet_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account_with_roles(
        builder.rng_mut().draw_word(),
        bridge_admin_account_id(),
        faucet_manager.id(),
        ger_injector.id(),
        ger_remover.id(),
        bridge_admin_account_id(),
        bridge_admin_account_id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge_account.clone())?;

    let token_name = "AggLayer Token";
    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply: Felt = FungibleAsset::MAX_AMOUNT.into();
    let token_supply = Felt::new_unchecked(123_456);

    let faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        token_name,
        token_symbol,
        decimals,
        max_supply,
        token_supply,
        bridge_admin_account_id(),
        bridge_account.id(),
    );

    // The account carries the standard fungible faucet interface, so `try_from` (which checks the
    // procedure roots before decoding storage) succeeds.
    let metadata = FungibleFaucet::try_from(&faucet)?;

    // Every field round-trips, most importantly the token name: it makes the metadata hash
    // preimage `abi.encode(name, symbol, decimals)` recoverable from faucet storage, which is what
    // will let the bridge verify the registered hash on-chain (issue #2586).
    assert_eq!(metadata.token_name().as_str(), token_name);
    assert_eq!(metadata.symbol().to_string(), token_symbol);
    assert_eq!(metadata.decimals(), decimals);
    assert_eq!(metadata.max_supply(), AssetAmount::try_from(max_supply)?);
    assert_eq!(metadata.token_supply(), AssetAmount::try_from(token_supply)?);

    // Mint and burn authorization is bound to the bridge through `Ownable2Step`.
    let ownership = Ownable2Step::try_from_storage(faucet.storage())?;
    assert_eq!(ownership.owner(), Some(bridge_account.id()));

    Ok(())
}
