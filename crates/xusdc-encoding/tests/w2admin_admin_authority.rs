//! The shape of the faucet's admin authority: which procedures carry a role, which role each
//! carries, and what the account materializes when that map is written into storage.
//!
//! Nothing here executes a transaction. These are the structural claims the executing suites rest
//! on — that the four standard manager procedures are four distinct roots, that the map covers
//! them plus the attester setter, that the two retired-wrapper role identities are preserved, and
//! that writing the map into an account and reading it back is lossless. A lossy round trip or a
//! stray extra entry would silently regate a procedure, which no effects test would necessarily
//! catch: the wrong role can still be a role someone holds.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::account::AccountStorage;
use miden_protocol::account::{AccountComponent, RoleSymbol, StorageSlotName};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, PausableManager};
use miden_standards::account::policies::BlocklistManager;
use miden_standards::account::upgrade::UpgradeManager;
use miden_standards::note::config::{AllowlistConfigNote, BlocklistConfigNote, PauseConfigNote};
use support::w2admin::*;
use support::*;
use xusdc_encoding::account::xreserve::{XReserveAdminAuthority, XReserveStablecoinBuilder};

/// The two config notes the plan adopts are distinct scripts with the storage layouts it assumes.
/// A selector-plus-account-id layout for the blocklist note and a bare selector for the pause note
/// is what makes one note cover two actions each, which is the whole reason four custom notes
/// collapse into two stock ones.
#[test]
fn the_stock_config_notes_have_the_shapes_the_plan_assumes() {
    assert_eq!(
        PauseConfigNote::NUM_STORAGE_ITEMS,
        1,
        "a pause action note carries just its selector"
    );
    assert_eq!(
        BlocklistConfigNote::NUM_STORAGE_ITEMS,
        3,
        "a blocklist config note carries a selector plus the account id it acts on"
    );
    assert_ne!(
        PauseConfigNote::script_root(),
        BlocklistConfigNote::script_root(),
        "the pause and blocklist notes must be separate scripts, each allowlisted on its own"
    );
    assert_ne!(
        PauseConfigNote::script_root().as_word(),
        Word::empty(),
        "the pause action note script root must be a real root"
    );
    assert_ne!(
        BlocklistConfigNote::script_root().as_word(),
        Word::empty(),
        "the blocklist config note script root must be a real root"
    );
}

/// The allowlist config note is the sibling that drives the opposite policy — an allowlist, where
/// the faucet has a blocklist. It is a different script, and it must stay out of the faucet's
/// note-script allowlist both now and after the integration.
#[test]
fn the_allowlist_config_note_is_a_different_script_and_stays_out_of_the_allowlist() {
    assert_ne!(
        AllowlistConfigNote::script_root(),
        BlocklistConfigNote::script_root(),
        "the allowlist and blocklist config notes are separate scripts and must not be conflated"
    );
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    assert!(
        !allowlist.contains(&AllowlistConfigNote::script_root()),
        "the allowlist config note drives a transfer allowlist the faucet does not have; it must \
         never be an allowlisted note script"
    );
}

/// The four manager procedures the plan maps are four distinct roots. If any pair collided, one
/// map entry would silently gate two operations and the role separation would be a fiction.
#[test]
fn the_four_manager_procedure_roots_are_distinct() {
    let roots = BTreeSet::from([
        PausableManager::pause_root(),
        PausableManager::unpause_root(),
        BlocklistManager::block_account_root(),
        BlocklistManager::unblock_account_root(),
    ]);
    assert_eq!(
        roots.len(),
        4,
        "pause, unpause, block and unblock must be four distinct procedure roots so each can \
         carry its own role"
    );
}

/// The map covers the four manager procedures and the attester setter, with separate pause and
/// unpause roles, block and unblock on the blocklist role, and the setter on the attester role.
#[test]
fn the_admin_authority_maps_exactly_the_five_gated_procedures() -> Result<()> {
    let library = assemble_xreserve_lib()?;
    let component = AccountComponent::new(
        library,
        Vec::new(),
        miden_protocol::account::component::AccountComponentMetadata::new(
            "xusdc-attester-root-probe",
        ),
    )
    .context("binding the assembled xreserve library to read a procedure root")?;
    let set_attester = component
        .get_procedure_root_by_path("xreserve::attester_admin::set_attester")
        .context("the assembled xreserve library must expose the attester setter")?;
    let roles = XReserveAdminAuthority::new().procedure_roles().clone();

    assert_eq!(
        roles.len(),
        5,
        "the map must cover exactly the five gated procedures; any extra entry moves a \
         capability off its current holder"
    );
    assert_eq!(
        roles.get(&PausableManager::pause_root()),
        Some(&pauser_symbol()),
        "pause must be gated on the pause role"
    );
    assert_eq!(
        roles.get(&PausableManager::unpause_root()),
        Some(&RoleSymbol::new("DOM_UNPAUSER").expect("the Domain unpauser role symbol is valid")),
        "unpause must be gated on the unpause role"
    );
    assert_eq!(
        roles.get(&BlocklistManager::block_account_root()),
        Some(&blocklist_symbol()),
        "block must be gated on the blocklist role, as blocklist_admin.masm gates it today"
    );
    assert_eq!(
        roles.get(&BlocklistManager::unblock_account_root()),
        Some(&blocklist_symbol()),
        "unblock must be gated on the blocklist role"
    );
    assert_eq!(
        roles.get(&set_attester),
        Some(&RoleSymbol::new("ATTEST_ADMIN").expect("the attester administrator role is valid")),
        "the attester setter must be gated on the attester administrator role"
    );
    Ok(())
}

/// The role identities carried by the map are the same two roles the current MASM wrappers
/// hard-code. The mechanism moves from a MASM literal into account storage; the authority does
/// not move with it.
#[test]
fn the_mapped_roles_are_the_roles_the_current_wrappers_hard_code() {
    assert_eq!(
        Felt::from(&pauser_symbol()).as_canonical_u64(),
        DOM_PAUSER_ROLE_FELT,
        "the pause role symbol must encode to the felt pause_admin.masm hard-codes"
    );
    assert_eq!(
        Felt::from(&blocklist_symbol()).as_canonical_u64(),
        BLK_MANAGER_ROLE_FELT,
        "the blocklist role symbol must encode to the felt blocklist_admin.masm hard-codes"
    );
}

/// Writing the map into an account and reading it back yields exactly what was written. This is
/// the claim the whole plan rests on: the authority component is the only thing standing between
/// the map in Rust and the role the account enforces at runtime, and a lossy round trip would
/// silently regate a procedure.
#[test]
fn the_map_round_trips_through_real_account_storage() -> Result<()> {
    let expected = XReserveAdminAuthority::new().procedure_roles().clone();
    let component: AccountComponent = XReserveAdminAuthority::new().into();
    let storage = AccountStorage::new(component.storage_slots().to_vec())
        .context("building storage from the authority component's slots")?;

    let authority = Authority::try_from_storage(&storage)
        .map_err(|e| anyhow::anyhow!("reading the authority back from storage: {e}"))?;
    let Authority::RbacControlled { procedure_roles } = authority else {
        panic!(
            "the admin authority must be the RBAC-controlled mode, not owner or auth controlled"
        );
    };

    assert_eq!(
        procedure_roles, expected,
        "the procedure-role map read back from account storage must equal the map that was written"
    );
    assert!(
        !Authority::try_read_frozen(&storage)
            .map_err(|e| anyhow::anyhow!("reading the frozen flag: {e}"))?,
        "a freshly composed account must not ship frozen"
    );
    Ok(())
}

/// The emergency switch also stays unmapped, so it resolves to the administrator role — matching
/// today's behaviour, where it is gated on the administrator.
#[test]
fn the_emergency_switch_is_not_mapped_to_a_dedicated_role() {
    let roles = XReserveAdminAuthority::new().procedure_roles().clone();
    assert!(
        !roles.contains_key(&Authority::freeze_root()),
        "freeze must stay unmapped so it resolves to the administrator role"
    );
    assert!(
        !roles.contains_key(&Authority::unfreeze_root()),
        "unfreeze must stay unmapped so it resolves to the administrator role"
    );
}

/// The upgrade hook stays unmapped as well, so it resolves to the administrator role.
#[test]
fn the_upgrade_hook_is_not_mapped_to_a_dedicated_role() {
    let roles = XReserveAdminAuthority::new().procedure_roles().clone();
    assert!(
        !roles.contains_key(&UpgradeManager::upgrade_root()),
        "upgrade must stay unmapped so it resolves to the administrator role"
    );
}

/// The managers install no storage of their own — they write the pause flag and the blocklist map
/// that other components already own. That is what makes adopting them free of any storage-layout
/// change, so the new account id comes only from the authority flip.
#[test]
fn the_managers_install_no_storage_of_their_own() {
    let pause_manager: AccountComponent = PausableManager.into();
    let blocklist_manager: AccountComponent = BlocklistManager.into();
    assert!(
        pause_manager.storage_slots().is_empty(),
        "the pause manager must install no storage slots"
    );
    assert!(
        blocklist_manager.storage_slots().is_empty(),
        "the blocklist manager must install no storage slots"
    );
}

/// The authority component under the RBAC mode installs the configuration word plus the
/// procedure-role map, and the pause flag it gates is owned by a different component. Naming both
/// slots pins the storage delta the plan attributes the new account id to.
#[test]
fn the_admin_authority_installs_the_config_word_and_the_role_map() {
    let component: AccountComponent = XReserveAdminAuthority::new().into();
    let names: BTreeSet<&StorageSlotName> = component
        .storage_slots()
        .iter()
        .map(|slot| slot.name())
        .collect();

    assert!(
        names.contains(Authority::authority_slot()),
        "the authority component must install its configuration word"
    );
    assert!(
        names.contains(Authority::procedure_roles_slot()),
        "the RBAC mode must install the procedure-role map slot — without it every gated \
         procedure would fall back to the administrator role"
    );
    assert_eq!(
        names.len(),
        2,
        "the authority component installs exactly the configuration word and the role map"
    );
}
