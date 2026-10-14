//! Builder byte-identity tests for the fee-enabled production composition.
//!
//! The tests record the account state, code, storage, and seed-derived ID commitments at a fixed
//! seed for both construction paths.
//!
//! 1. the crate-root `build_faucet_account` constructor reproduces them EXACTLY (the faucet it
//!    builds is `is_max_supply_mutable(true)`, so `set_max_supply` stays operable),
//! 2. the component path (`build_components` + the auth component, now with the builder assembling
//!    its own xreserve component) still reproduces them, and
//! 3. the two paths agree with each other.
//!
//! Any change to a recorded commitment fails a string-exact assertion.

mod support;

use miden_protocol::account::{Account, AccountType, AssetCallbackFlag, StorageSlotName};
use miden_protocol::asset::AssetAmount;
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Felt, Hasher, Word};
use miden_usdcx::account::xreserve::{XReserveStablecoinBuilder, build_faucet_account};
use support::*;

/// The fixed account seed the anchors were captured at (production uses a random seed; a fixed one
/// makes the seed-derived id and the whole account commitment deterministic).
const SEED: [u8; 32] = [7u8; 32];
const TOKEN_SUPPLY: u64 = 0;

// Account commitments for the production composition at SEED. The fixed seed makes both
// construction paths deterministic. Updated for the P2ID salt removal and shared recipient
// helper, which change policy code and the fee schedule keyed by note script roots.
const GOLDEN_STATE_COMMITMENT: &str =
    "Word([13941042732103063686, 1920524542879185054, 16741312678771479031, 2805114000869456952])";
const GOLDEN_CODE_COMMITMENT: &str =
    "Word([13367653733810499934, 1357978482566711275, 1912364501073063008, 9132337455480230832])";
const GOLDEN_STORAGE_DIGEST: &str =
    "Word([17065993506684399558, 3464002229815106283, 7831546067101858474, 3900052850041222078])";
const GOLDEN_ACCOUNT_ID: &str = "0xc81b493e09018db1412720eb61bac2";

/// A deterministic digest over the account's storage slots (name + serialized slot), so a
/// storage-only drift is caught independently of the code commitment.
fn storage_digest(account: &Account) -> Word {
    let mut bytes = Vec::new();
    for slot in account.storage().slots() {
        bytes.extend_from_slice(&slot.to_bytes());
    }
    Hasher::hash(&bytes)
}

/// Asserts an account matches every frozen anchor.
fn assert_matches_golden(account: &Account, path: &str) {
    assert_eq!(
        format!("{}", account.id()),
        GOLDEN_ACCOUNT_ID,
        "{path}: seed-derived account id drifted",
    );
    assert_eq!(
        format!("{:?}", account.to_commitment()),
        GOLDEN_STATE_COMMITMENT,
        "{path}: account state commitment drifted (code, storage, id or type changed)",
    );
    assert_eq!(
        format!("{:?}", account.code().commitment()),
        GOLDEN_CODE_COMMITMENT,
        "{path}: account code commitment drifted (a procedure root moved)",
    );
    assert_eq!(
        format!("{:?}", storage_digest(account)),
        GOLDEN_STORAGE_DIGEST,
        "{path}: account storage drifted (a slot value or layout changed)",
    );
}

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

/// The crate-root faucet-account constructor matches the recorded commitments.
#[test]
fn crate_root_constructor_matches_the_golden() {
    assert_matches_golden(&account_via_crate_root_constructor(), "build_faucet_account");
}

/// The component path matches the recorded commitments.
#[test]
fn component_path_matches_the_golden() {
    assert_matches_golden(&account_via_component_path(), "component-path");
}

/// The two construction paths agree with each other — the crate-root constructor is a faithful
/// wrapper over the component composition + auth, not a second, subtly-different assembly.
#[test]
fn the_two_construction_paths_agree() {
    let via_ctor = account_via_crate_root_constructor();
    let via_components = account_via_component_path();
    assert_eq!(
        format!("{:?}", via_ctor.to_commitment()),
        format!("{:?}", via_components.to_commitment()),
        "the crate-root constructor and the component path must compose the identical account",
    );
    assert_eq!(
        format!("{:?}", storage_digest(&via_ctor)),
        format!("{:?}", storage_digest(&via_components)),
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
/// layout is `[is_desc, is_logo, is_extlink, is_max_supply]`, so the max-supply flag is element 3.
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
