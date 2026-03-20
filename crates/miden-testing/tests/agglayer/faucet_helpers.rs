extern crate alloc;

use miden_agglayer::{
    AggLayerFaucet,
    EthAddress,
    MetadataHash,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_protocol::Felt;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
use miden_testing::{Auth, MockChain};

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
    );
    builder.add_account(bridge_account.clone())?;

    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT);
    let token_supply = Felt::new(123_456);

    let origin_token_address = EthAddress::from_hex("0x0102030405060708090a0b0c0d0e0f1011121314")
        .expect("invalid token address");
    let origin_network = 42u32;
    let scale = 6u8;

    let metadata_hash = MetadataHash::from_token_info(token_symbol, token_symbol, decimals);

    let faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        token_symbol,
        decimals,
        max_supply,
        token_supply,
        bridge_account.id(),
        &origin_token_address,
        origin_network,
        scale,
        metadata_hash,
    );

    assert_eq!(AggLayerFaucet::owner_account_id(&faucet)?, bridge_account.id());
    assert_eq!(AggLayerFaucet::origin_token_address(&faucet)?, origin_token_address);
    assert_eq!(AggLayerFaucet::origin_network(&faucet)?, origin_network);
    assert_eq!(AggLayerFaucet::scale(&faucet)?, scale);

    Ok(())
}
