//! Policed-asset tripwire (F4 REVERSAL, human-ratified 2026-07-23) — locks in the decision that
//! xUSDC ships as a POLICED fungible asset carrying the stock `BasicBlocklist` as the ACTIVE send AND
//! receive transfer policy (one root, both kinds, empty initial blocklist). This SUPERSEDES the former
//! basic-asset tripwire (which asserted the opposite: no transfer policy and
//! `AssetCallbackFlag::Disabled`).
//!
//! This test is GREEN on the shipped (policed) build and flips RED the moment anyone un-wires the
//! transfer blocklist (drops `active_send_policy`/`active_receive_policy` from `build_components`).
//! Un-wiring would (a) empty the `allowed_{send,receive}_policy_proc_roots` maps and (b) drop the
//! protocol asset-callback slots — this test asserts BOTH are present (with exactly the one blocklist
//! root, and holding the wrapper roots), so either facet of an un-wire trips it. It is the executable
//! half of the reversal; the prose half is the `build_components` comment in `builder.rs`. The
//! Enabled-flag half of the invariant is proven on the BUILT account by
//! `account_callable_surface::invoke_wrappers_are_live_and_the_asset_is_policed`.
//!
//! Why callback-slots-present proves callback-ENABLED minting: `faucet::has_callbacks` (protocol
//! `faucet.masm`) returns 1 only when a callback storage slot is present AND non-empty; with the
//! transfer policy wired the manager installs those slots holding the `invoke_*_policy` wrapper
//! roots, so `create_fungible_asset` stamps `AssetCallbackFlag::Enabled` on every minted asset (given
//! the account id is Enabled) and the kernel dispatches the policy on transfer/consume (FPI).

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::{
    AccountComponent, StorageMap, StorageSlot, StorageSlotContent, StorageSlotName,
};
use miden_protocol::asset::AssetCallbacks;
use miden_protocol::Word;
use miden_standards::account::policies::{BasicBlocklist, TokenPolicyManager};
use support::{production_component_set, tripwire_serial_guard_blocking};

/// First storage slot named `name` across the whole composed component set, if any.
fn find_slot<'a>(
    components: &'a [AccountComponent],
    name: &StorageSlotName,
) -> Option<&'a StorageSlot> {
    components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|s| s.name() == name)
}

/// The `StorageMap` backing a map slot the manager always registers (the allowed-policy maps exist
/// on every build, empty until a policy is registered).
fn map_slot<'a>(
    components: &'a [AccountComponent],
    name: &StorageSlotName,
) -> Result<&'a StorageMap> {
    let slot = find_slot(components, name)
        .with_context(|| format!("the policy manager must register the '{name}' slot"))?;
    match slot.content() {
        StorageSlotContent::Map(map) => Ok(map),
        StorageSlotContent::Value(_) => anyhow::bail!("'{name}' must be a MAP slot"),
    }
}

/// The value of a value slot named `name`, if present.
fn value_slot(components: &[AccountComponent], name: &StorageSlotName) -> Result<Word> {
    let slot = find_slot(components, name)
        .with_context(|| format!("the policy manager must register the '{name}' slot"))?;
    match slot.content() {
        StorageSlotContent::Value(v) => Ok(*v),
        StorageSlotContent::Map(_) => anyhow::bail!("'{name}' must be a VALUE slot"),
    }
}

/// TRIPWIRE: the production faucet composition wires the stock `BasicBlocklist` as the ACTIVE send AND
/// receive transfer policy — the `allowed_{send,receive}_policy_proc_roots` maps carry EXACTLY the
/// one blocklist root, the active send/receive policy slots hold that same root, and BOTH protocol
/// asset-callback slots are installed holding the `invoke_*_policy` wrapper roots. Un-wiring the
/// blocklist flips this RED. Do not "fix" it by dropping the policy — read the module docs and the
/// decision record.
#[test]
fn production_build_wires_the_transfer_blocklist() -> Result<()> {
    let _serial = tripwire_serial_guard_blocking();
    let components = production_component_set(0)?;
    let blocklist_root = BasicBlocklist::root().as_word();

    // (1) the send + receive transfer policy is registered: each allowed-roots map carries EXACTLY
    // the one blocklist root. Un-wiring the policy empties these.
    for (name, kind) in [
        (TokenPolicyManager::allowed_send_policies_slot(), "SEND"),
        (
            TokenPolicyManager::allowed_receive_policies_slot(),
            "RECEIVE",
        ),
    ] {
        let map = map_slot(&components, name)?;
        assert_eq!(
            map.num_entries(),
            1,
            "the {kind} allowed-policy map must carry EXACTLY the one BasicBlocklist root — the \
             transfer blocklist must be wired."
        );
    }

    // (2) the active send + receive policy slots hold the BasicBlocklist root (both kinds share the
    // one descriptor root, so the companion installs once).
    for (name, kind) in [
        (TokenPolicyManager::active_send_policy_slot(), "SEND"),
        (TokenPolicyManager::active_receive_policy_slot(), "RECEIVE"),
    ] {
        assert_eq!(
            value_slot(&components, name)?,
            blocklist_root,
            "the active {kind} policy slot must resolve to the BasicBlocklist root"
        );
    }

    // (3) both protocol asset-callback slots are installed, holding the fixed invoke_*_policy wrapper
    // roots → `faucet::has_callbacks` returns 1 → minted xUSDC is a POLICED asset (FPI dispatch on
    // transfer/consume). Un-wiring the policy drops these slots.
    for (slot, wrapper_root) in [
        (
            AssetCallbacks::on_before_asset_added_to_note_slot(),
            TokenPolicyManager::invoke_send_policy_root().as_word(),
        ),
        (
            AssetCallbacks::on_before_asset_added_to_account_slot(),
            TokenPolicyManager::invoke_receive_policy_root().as_word(),
        ),
    ] {
        let installed = find_slot(&components, slot).with_context(|| {
            format!(
                "the {slot} asset-callback slot must be installed — the transfer blocklist is wired \
                 (F4-reversal), so minted xUSDC is a POLICED asset"
            )
        })?;
        assert_eq!(
            installed.value(),
            wrapper_root,
            "the {slot} callback slot must hold the fixed invoke_*_policy wrapper root"
        );
    }
    Ok(())
}
