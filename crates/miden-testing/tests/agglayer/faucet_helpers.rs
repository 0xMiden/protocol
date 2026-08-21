extern crate alloc;

use miden_agglayer::AggLayerFaucet;
use miden_agglayer::testing::create_existing_agglayer_faucet;
use miden_protocol::Felt;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
use miden_testing::{Auth, MockChain};

use super::test_utils::{
    MIDEN_NETWORK_ID,
    bridge_admin_account_id,
    create_existing_bridge_account_with_roles,
};

#[test]
fn test_faucet_helper_methods() -> anyhow::Result<()> {
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

    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply: Felt = FungibleAsset::MAX_AMOUNT.into();
    let token_supply = Felt::new_unchecked(123_456);

    let faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        token_symbol,
        decimals,
        max_supply,
        token_supply,
        bridge_admin_account_id(),
        bridge_account.id(),
    );

    assert_eq!(AggLayerFaucet::owner_account_id(&faucet)?, bridge_account.id());

    Ok(())
}
