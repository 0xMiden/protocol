//! Invariant tests for `XReserveStablecoinBuilder::build_genesis_account` and
//! `record_used_nonces` — the genesis-only native-fee-faucet build beside the byte-identity suite.
//!
//! The genesis build must reuse the plain `build_account` identity (the id is derived while the
//! fee parameters still carry the operator placeholder), then rebind the fee-asset slot to the
//! faucet's OWN asset and promote the account to nonce one with no seed. Recording the consumed
//! nonces afterwards must keep all of that. A forgotten rebinding or a drifted id fails here.

mod support;

use miden_protocol::asset::AssetId;
use miden_protocol::Felt;
use miden_standards::account::fees::FeePolicyManager;
use support::mint_transport::{marker, read_map_word};
use support::{production_builder, test_fee_faucet_id, TEST_DOMAIN};
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;
use xusdc_encoding::record_used_nonces;
use xusdc_encoding::xreserve::encoding::DepositNonce;

/// The fixed account seed, matching the byte-identity suite's anchor seed.
const SEED: [u8; 32] = [7u8; 32];
const TOKEN_SUPPLY: u64 = 0;

/// The genesis build keeps the plain build's id, carries nonce one and no seed, and its
/// fee-asset slot is rebound from the operator placeholder to the faucet's own asset.
#[test]
fn genesis_build_rebinds_the_fee_asset_and_promotes_to_nonce_one() {
    let builder = production_builder(TOKEN_SUPPLY, TEST_DOMAIN)
        .expect("the production builder must construct");
    let genesis = builder
        .build_genesis_account(SEED)
        .expect("the genesis build must succeed");
    let plain = builder
        .build_account(SEED)
        .expect("the plain build must succeed");

    assert_eq!(
        genesis.id(),
        plain.id(),
        "the genesis build must not change the seed-derived account id",
    );
    assert_eq!(
        genesis.nonce(),
        Felt::ONE,
        "a genesis account must carry nonce one (it exists at genesis, it is not deployed)",
    );
    assert!(
        genesis.seed().is_none(),
        "a genesis account must carry no seed (it cannot be deployed in a transaction)",
    );

    let fee_slot = FeePolicyManager::fee_asset_id_slot();
    assert_eq!(
        genesis
            .storage()
            .get_item(fee_slot)
            .expect("the genesis account installs the fee-asset slot"),
        AssetId::new_fungible(genesis.id()).to_word(),
        "the genesis fee-asset slot must hold the faucet's OWN asset (the native fee faucet)",
    );
    // The plain build still holds the operator placeholder, proving the genesis path performed
    // an actual rebinding rather than the grind already using the final value.
    assert_eq!(
        plain
            .storage()
            .get_item(fee_slot)
            .expect("the plain account installs the fee-asset slot"),
        AssetId::new_fungible(test_fee_faucet_id()).to_word(),
        "the plain build must keep the placeholder fee asset the id was ground with",
    );
}

/// Recording a consumed nonce on the genesis account marks it and keeps the id, the genesis form
/// and the fee-asset rebinding.
#[test]
fn record_used_nonces_marks_the_nonce_and_keeps_the_genesis_form() {
    let builder = production_builder(TOKEN_SUPPLY, TEST_DOMAIN)
        .expect("the production builder must construct");
    let consumed = DepositNonce::new([0x55; 32]);
    let genesis = builder
        .build_genesis_account(SEED)
        .expect("the genesis build must succeed");
    let recorded =
        record_used_nonces(genesis.clone(), &[consumed]).expect("recording a nonce must succeed");

    assert_eq!(
        recorded.id(),
        genesis.id(),
        "recording a consumed nonce must not change the account id",
    );
    assert_eq!(
        recorded.nonce(),
        Felt::ONE,
        "the account must stay at nonce one"
    );
    assert!(recorded.seed().is_none(), "the account must stay seedless");
    let slot = XReserveFaucetExtension::used_nonces_slot();
    assert_eq!(
        read_map_word(&recorded, slot, consumed.to_word()).expect("the registry slot exists"),
        marker(),
        "a listed nonce must carry the consumed marker",
    );
    assert_eq!(
        recorded
            .storage()
            .get_item(FeePolicyManager::fee_asset_id_slot())
            .expect("the account installs the fee-asset slot"),
        AssetId::new_fungible(recorded.id()).to_word(),
        "recording a nonce must keep the fee-asset rebinding",
    );
}
