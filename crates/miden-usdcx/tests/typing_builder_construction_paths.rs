//! Builder tests for the fee-enabled production composition.
//!
//! The tests check that the crate-root `build_faucet_account` constructor and the component path
//! (`build_components` + the auth component) compose the identical account at a fixed seed, and
//! that the crate-root constructor sets the expected account flags.

mod support;

use miden_protocol::Felt;
use miden_protocol::account::{Account, AccountType, AssetCallbackFlag, StorageSlotName};
use miden_protocol::asset::AssetAmount;
use miden_usdcx::account::xreserve::{XReserveStablecoinBuilder, build_faucet_account};
use support::*;

/// A fixed account seed, so that both construction paths derive the same account ID.
const SEED: [u8; 32] = [7u8; 32];
const TOKEN_SUPPLY: u64 = 0;

/// Composes the account from `build_components` and the production auth component at the
/// fixed seed, with the asset-callback flag derived from the composition (as the deploy path does).
fn account_via_component_path() -> Account {
    let components =
        production_component_set(TOKEN_SUPPLY).expect("the production composition must build");
    let mut builder = Account::builder(SEED).account_type(AccountType::Public);
    for component in components {
        builder = builder.with_component(component);
    }
    builder = builder.with_components(
        XReserveStablecoinBuilder::auth_component(test_fee_parameters(), test_fee_asset_id())
            .expect("the auth component must build"),
    );
    builder.build().expect("the component-path composition must build the account")
}

/// Composes the account through the crate-root `build_faucet_account` constructor, at the
/// same fixed seed and the same domain-config / role inputs the component path uses.
fn account_via_crate_root_constructor() -> Account {
    build_faucet_account(
        SEED,
        AssetAmount::new(TOKEN_SUPPLY).expect("token supply is a valid asset amount"),
        test_account_id(1),
        vec![test_account_id(1)],
        vec![test_account_id(2)],
        vec![test_account_id(3)],
        vec![test_account_id(4)],
        test_fee_parameters(),
        test_fee_asset_id(),
        TEST_DOMAIN,
    )
    .expect("the crate-root faucet-account constructor must build the account")
}

/// The two construction paths agree with each other — the crate-root constructor is a faithful
/// wrapper over the component composition + auth, not a second, subtly-different assembly.
#[test]
fn the_two_construction_paths_agree() {
    let via_ctor = account_via_crate_root_constructor();
    let via_components = account_via_component_path();
    assert_eq!(
        via_ctor.to_commitment(),
        via_components.to_commitment(),
        "the crate-root constructor and the component path must compose the identical account",
    );
    assert_eq!(
        via_ctor.storage().to_commitment(),
        via_components.storage().to_commitment(),
        "the two paths must produce identical storage",
    );
}

/// xUSDC is a policed asset: the composition installs the transfer-policy callback slots, so the
/// crate-root constructor must build the account with the Enabled asset-callback flag (a Disabled
/// flag would silently never fire the blocklist callbacks). Locks the constructor's flag
/// derivation.
#[test]
fn crate_root_account_carries_the_policed_asset_callback_flag() {
    let account = account_via_crate_root_constructor();
    assert_eq!(
        account.id().asset_callback_flag(),
        AssetCallbackFlag::Enabled,
        "the crate-root constructor must build a policed-asset faucet (Enabled callback flag)",
    );
}

/// Enforce-by-construction (16b): the crate-root constructor builds the faucet with a MUTABLE
/// `max_supply`, so the deployed `set_max_supply` admin function stays operable. This is the
/// POSITIVE lock that replaces the removed `ImmutableMaxSupply` runtime reject — a constructor that
/// built the faucet immutable would flip the flag felt and fail here. The `mutability_config` word
/// layout is `[is_desc, is_logo, is_external_uri, is_max_supply]`, so the max-supply flag is
/// element 3.
#[test]
fn crate_root_faucet_max_supply_is_mutable_by_construction() {
    const MUTABILITY_CONFIG_SLOT: &str = "miden::standards::faucets::mutability_config";
    const MAX_SUPPLY_MUTABLE_INDEX: usize = 3;
    let account = account_via_crate_root_constructor();
    let name = StorageSlotName::new(MUTABILITY_CONFIG_SLOT)
        .expect("the mutability_config slot name is valid");
    let slot = account
        .storage()
        .slots()
        .iter()
        .find(|slot| slot.name() == &name)
        .expect("the composed faucet installs its mutability_config slot");
    assert_eq!(
        slot.value()[MAX_SUPPLY_MUTABLE_INDEX],
        Felt::from(1u32),
        "the crate-root faucet must be built is_max_supply_mutable(true) (16b enforce-by-construction)",
    );
}
