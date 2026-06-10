extern crate alloc;

use miden_agglayer::{
    AggLayerFaucet,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_protocol::Felt;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
use miden_testing::{Auth, MockChain};

use super::test_utils::MIDEN_NETWORK_ID;

#[test]
fn test_faucet_helper_methods() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
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
        bridge_account.id(),
    );

    assert_eq!(AggLayerFaucet::owner_account_id(&faucet)?, bridge_account.id());

    Ok(())
}
