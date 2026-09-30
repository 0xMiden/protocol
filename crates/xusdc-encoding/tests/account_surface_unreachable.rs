//! The UNREACHABLE and READ-ONLY halves of the FULL-ACCOUNT CALLABLE-SURFACE proofs,
//! split out of `account_callable_surface.rs` to respect the file-size
//! ceiling. `account_callable_surface.rs` holds the
//! freeze/unfreeze disposition + the asset-callback (transfer-blocklist-live) proof; THIS file
//! holds:
//!   * `authority::get_authority` is READ-ONLY in execution (executed bounding, not
//!     documentation);
//!   * 13 mutator, upgrade and fee procedures in three reachability tiers. Tier A contains five
//!     unreachable procedures: the four allowlist mutators and the upgrade hook. Tier B contains
//!     six fee procedures and the `compute_note_fee` callback;
//!     these have no direct external entry point but are used by the internal fee-estimation path.
//!     Tier C contains `set_note_fee`, which is reached through the fee configuration note and
//!     authorized by `ADMIN`.
//!
//! The small conformance helpers (`production_components`/`component_surface`) are duplicated
//! here so this module is self-contained; both copies are single-sourced from
//! `XReserveStablecoinBuilder`, so neither can drift from what ships.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::account::{AccountComponent, StorageSlotContent};
use miden_protocol::assembly::mast::MastNodeExt;
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::Word;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::note::config::ConstantFeePolicyConfigNote;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

/// The production composition, component by component: the SHIPPED component set
/// (`support::production_component_set` → `XReserveStablecoinBuilder::build_components()`) PLUS the
/// `AuthNetworkAccount` auth component the MockChain fixture installs — both single-sourced from
/// `XReserveStablecoinBuilder`, so this cannot drift from what ships.
fn production_components() -> Result<Vec<AccountComponent>> {
    let mut components =
        production_component_set(0).context("the production composition must build")?;
    components.extend(
        XReserveStablecoinBuilder::auth_component(test_fee_parameters(), test_fee_asset_id())
            .context("the production auth component must build")?,
    );
    Ok(components)
}

/// Every callable procedure of the composed account, as `(path, root)` — read from each component's
/// FILTERED interface (the `@account_procedure` / `@auth_script` exports).
fn component_surface(components: &[AccountComponent]) -> Vec<(String, Word)> {
    let mut surface = Vec::new();
    for component in components {
        let code = component.component_code();
        for export in code.exports() {
            let path = export.path.to_string();
            let root = code
                .get_procedure_root_by_path(export.path.as_ref())
                .unwrap_or_else(|| panic!("the exported path {path} must resolve to a root"));
            surface.push((path, Word::from(root)));
        }
    }
    surface
}

// FEE AND MUTATOR PROCEDURES
// ================================================================================================
//
// The 13 procedures fall into three reachability tiers.
//
// Tier A contains five unreachable procedures: the four allowlist mutators and the
// `UpgradeManager::upgrade` hook. No accepted note or transaction script references them.
//
// Tier B contains six fee procedures and the `compute_note_fee` callback. Accepted notes and
// transaction scripts do not reference them directly. The auth component invokes the fee
// estimation path for input notes.
//
// Tier C contains `ConstantFeeManager::set_note_fee`, which is called by
// `ConstantFeePolicyConfigNote` and authorized through the `ADMIN` fallback.

/// Tier A contains the five unreachable procedures: the four allowlist mutators and the upgrade
/// hook.
const TIER_A_MUTATOR_ROWS: [&str; 5] = [
    "::miden::standards::components::auth::network_account::add_allowed_note_script",
    "::miden::standards::components::auth::network_account::remove_allowed_note_script",
    "::miden::standards::components::auth::network_account::add_allowed_tx_script",
    "::miden::standards::components::auth::network_account::remove_allowed_tx_script",
    "::miden::standards::components::upgrade::manager::upgrade",
];

/// Tier B contains six fee procedures and the fee-policy callback. These procedures have no direct
/// external entry point, while the auth component invokes the fee-estimation path internally.
const TIER_B_FEE_ROWS: [&str; 7] = [
    "::miden::standards::components::auth::network_account::estimate_note_fee",
    "::miden::standards::components::auth::network_account::get_fee_asset_id",
    "::miden::standards::components::auth::network_account::get_fee_policy",
    "::miden::standards::components::auth::network_account::set_fee_policy",
    "::miden::standards::components::auth::network_account::add_allowed_fee_policy",
    "::miden::standards::components::auth::network_account::remove_allowed_fee_policy",
    "::miden::standards::components::fees::policies::basic_constant_fee::compute_note_fee",
];

const TIER_C_FEE_ADMIN_ROWS: [&str; 1] =
    ["::miden::standards::components::fees::policies::constant_fee_manager::set_note_fee"];

/// Resolves account-procedure roots from the production composition by path.
fn procedure_roots(paths: &[&'static str]) -> Result<Vec<(&'static str, Word)>> {
    let components = production_components()?;
    let surface = component_surface(&components);
    paths
        .iter()
        .map(|path| {
            surface
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, root)| (*path, *root))
                .with_context(|| format!("the composed account must expose {path}"))
        })
        .collect()
}

/// Returns the roots of all 13 fee, mutator and upgrade procedures.
fn fee_and_mutator_procedure_roots() -> Result<Vec<(&'static str, Word)>> {
    let mut rows = procedure_roots(&TIER_A_MUTATOR_ROWS)?;
    rows.extend(procedure_roots(&TIER_B_FEE_ROWS)?);
    rows.extend(procedure_roots(&TIER_C_FEE_ADMIN_ROWS)?);
    Ok(rows)
}

/// Tier A, UNREACHABLE, leg 1 (static, exhaustive over the allowlist): NOT ONE of the 10
/// allowlisted note scripts references ANY of the 5 Tier-A roots ANYWHERE in its MAST — so no
/// admissible note can mutate the allowlists or record an upgrade. The swept set is asserted
/// equal to the allowlist first, so a new note cannot dodge the sweep.
#[test]
fn tier_a_mutators_are_unreachable_from_every_allowlisted_note() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let scripts = allowlisted_note_scripts();
    let swept: BTreeSet<_> = scripts.iter().map(|(_, s)| s.root()).collect();
    assert_eq!(
        swept, allowlist,
        "the swept note scripts must be EXACTLY the 10-root note-script allowlist"
    );

    let rows = procedure_roots(&TIER_A_MUTATOR_ROWS)?;
    for (label, script) in &scripts {
        let forest = script.mast();
        for node in forest.nodes() {
            for (path, root) in &rows {
                assert_ne!(
                    node.digest(),
                    *root,
                    "allowlisted note script `{label}` references the Tier-A root `{path}` — \
                     the unreachability guarantee is BROKEN (an admissible note could reach a \
                     procedure that has no admitted entry path)"
                );
            }
        }
    }
    Ok(())
}

/// Tier B, NO DIRECT REFERENCE (static, exhaustive over the allowlist): NOT ONE of the 10
/// allowlisted note scripts references ANY of the 7 fee-tier roots ANYWHERE in its MAST — no
/// admissible note calls the fee machinery ITSELF. This is deliberately NOT an unreachability
/// claim: the fee-estimation path runs INTERNALLY on every input note (the auth procedure's
/// `collect_sponsored_fees` -> `estimate_note_fee_internal` -> dyncall `compute_note_fee`),
/// computing the scheduled zero fee — internally active but inert. What this sweep proves is
/// that the only executor is that internal dispatch, never an admissible script.
#[test]
fn tier_b_fee_rows_are_not_referenced_by_any_allowlisted_note() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let scripts = allowlisted_note_scripts();
    let swept: BTreeSet<_> = scripts.iter().map(|(_, s)| s.root()).collect();
    assert_eq!(
        swept, allowlist,
        "the swept note scripts must be EXACTLY the 10-root note-script allowlist"
    );

    let rows = procedure_roots(&TIER_B_FEE_ROWS)?;
    for (label, script) in &scripts {
        let forest = script.mast();
        for node in forest.nodes() {
            for (path, root) in &rows {
                assert_ne!(
                    node.digest(),
                    *root,
                    "allowlisted note script `{label}` references the Tier-B fee root `{path}` \
                     directly — the fee machinery must only ever run via the auth procedure's \
                     internal dispatch, never from an admissible script"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn set_note_fee_is_present_for_the_allowlisted_fee_config_route() -> Result<()> {
    let rows = procedure_roots(&TIER_C_FEE_ADMIN_ROWS)?;
    assert_eq!(rows.len(), 1, "the account must expose set_note_fee");
    assert!(
        XReserveStablecoinBuilder::allowed_note_scripts()
            .contains(&ConstantFeePolicyConfigNote::script_root()),
        "the constant-fee configuration note must be allowlisted",
    );
    Ok(())
}

/// Account procedures are not themselves admissible scripts. None of these procedure roots is a
/// member of the ten-root note-script allowlist or the transaction-script allowlist. The production
/// auth component contains only the canonical expiration root in its transaction-script allowlist.
/// Tier C is reached through its allowlisted note rather than through a procedure root.
#[test]
fn fee_and_mutator_procedures_are_not_admissible_via_either_allowlist() -> Result<()> {
    let note_allowlist = XReserveStablecoinBuilder::allowed_note_scripts();

    // the production auth component's materialized tx-script allowlist keys (non-empty values
    // mark membership, matching the MASM `word::eqz` check — the s12 view).
    let auth_component: AccountComponent =
        XReserveStablecoinBuilder::auth_component(test_fee_parameters(), test_fee_asset_id())
            .map_err(|e| anyhow::anyhow!("auth_component() must build: {e}"))?
            .into_iter()
            .next()
            .expect("the auth component is yielded first");
    let tx_slot = auth_component
        .storage_slots()
        .iter()
        .find(|s| s.name() == AuthNetworkAccount::allowed_tx_scripts_slot())
        .expect("the auth component must carry the tx-script allowlist slot");
    let StorageSlotContent::Map(tx_map) = tx_slot.content() else {
        panic!("the tx-script allowlist slot must be a MAP slot");
    };
    let tx_allowlist: BTreeSet<Word> = tx_map
        .entries()
        .filter(|(_key, value)| **value != Word::empty())
        .map(|(key, _value)| key.as_word())
        .collect();

    for (path, root) in fee_and_mutator_procedure_roots()? {
        let as_note_root = NoteScriptRoot::from_raw(root);
        assert!(
            !note_allowlist.contains(&as_note_root),
            "the `{path}` root must NOT be a member of the 10-root note-script allowlist"
        );
        assert!(
            !tx_allowlist.contains(&root),
            "the `{path}` root must NOT be a member of the tx-script allowlist"
        );
    }
    Ok(())
}
