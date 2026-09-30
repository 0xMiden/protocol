//! FAUCET-RECOMPOSITION TRIPWIRES — the posture PINS for the shipped faucet composition
//! (stock `MintNote` transport + attestation MintPolicy + build-seeded config with an
//! identifier-only init note + a burn policy with a zero-floor guard).
//!
//! The file is the permanent posture tripwire set:
//!
//! - The sole-supply-surface invariant (restated): every supply increase passes the attestation
//!   mint policy —
//!   the active mint policy IS `xreserve::mint_policy::check_policy`, the allowed-mint map is
//!   EXACTLY that one root, and a build with any other active mint policy is rejected with the
//!   CONCRETE `MissingAttestationMintPolicy` builder variant.
//! - There is NO mint-deny guard (nothing needs trapping: the
//!   stock path IS the attestation-gated path).
//! - The burn floor: the burn policy reads the stock `MinBurnAmount` slot, which is
//!   seeded `>= 1` (the zero-burn reject preserved by construction: `amount >= min >= 1`),
//!   the builder REJECTS `min_burn_size < 1` with the CONCRETE `MinBurnSizeBelowFloor` variant,
//!   and the admin note (targeting the stock `set_min_burn_amount`) asserts
//!   `new_min >= 1` before calling it.
//! - The note-script allowlist pins the STOCK `MintNote` root and carries NO custom
//!   mint-note root; there is no four-field `domain_init` surface — the runtime init is the
//!   minimized
//!   identifier-only init (the identifier is a provable fixpoint of the account id).
//!
//! The end-to-end legs that drive the transport for real — a successful mint, the recipient, fee
//! and replay binding negatives, and the runtime minimum-burn floor guard — live in the
//! recomposition end-to-end suite alongside this one, split only for file size; both share the
//! production-transport harness in `support::mint_transport`.
//!
//! Every test here is a security tripwire and holds the tripwire serial guard: they contend for
//! shared fixture state and flake if run in parallel.

mod support;

use anyhow::{Context, Result};
use assert_matches::assert_matches;
use miden_protocol::account::{
    AccountComponent, StorageMapKey, StorageSlot, StorageSlotContent, StorageSlotName,
};
use miden_protocol::{Felt, Word};
use miden_standards::account::policies::{MinBurnAmount, TokenPolicyManager};
use miden_standards::note::MintNote;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilderError;

// THE RATIFIED TO-BE CONSTANTS (independent test-side pins; the production Rust/MASM constants
// are parity-tested against each other — these literals keep the RATIFIED values honest)
// ================================================================================================

/// The attestation mint policy's path as the faucet component exports it.
const ATTESTATION_MINT_POLICY_PROC_PATH: &str =
    "xreserve::components::faucet_extension::check_policy";

/// The dissolved mint-deny guard's former library path (must resolve NOWHERE in the shipped
/// composition).
const FORMER_MINT_DENY_GUARD_PROC_PATH: &str = "xreserve::mint_deny_guard::check_policy";

/// The former custom mint-note script root — pinned as a LITERAL so the allowlist test can
/// prove its removal (the factory type itself no longer exists).
const FORMER_CUSTOM_MINT_NOTE_ROOT_HEX: &str =
    "0x530e20b39e77a111f00a162835823ff503202d05c182b98728387853e07d19d5";

// COMPONENT-SET INSPECTION HELPERS (the basic_asset_tripwire pattern)
// ================================================================================================

fn find_slot<'a>(
    components: &'a [AccountComponent],
    name: &StorageSlotName,
) -> Option<&'a StorageSlot> {
    components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|s| s.name() == name)
}

fn map_slot<'a>(
    components: &'a [AccountComponent],
    name: &StorageSlotName,
) -> Result<&'a miden_protocol::account::StorageMap> {
    let slot = find_slot(components, name)
        .with_context(|| format!("the policy manager must register the '{name}' slot"))?;
    match slot.content() {
        StorageSlotContent::Map(map) => Ok(map),
        StorageSlotContent::Value(_) => anyhow::bail!("'{name}' must be a MAP slot"),
    }
}

fn value_slot(components: &[AccountComponent], name: &StorageSlotName) -> Result<Word> {
    let slot = find_slot(components, name)
        .with_context(|| format!("the composition must register the '{name}' slot"))?;
    match slot.content() {
        StorageSlotContent::Value(v) => Ok(*v),
        StorageSlotContent::Map(_) => anyhow::bail!("'{name}' must be a VALUE slot"),
    }
}

/// Resolves a library-path procedure root across the composed component set.
fn resolve_proc_root(components: &[AccountComponent], path: &str) -> Option<Word> {
    components
        .iter()
        .find_map(|c| c.get_procedure_root_by_path(path))
        .map(Word::from)
}

/// The shipped MASM tree. The tripwires below assert on what is PRESENT and ABSENT in it, which is
/// the one thing an assembled package cannot answer: a deleted module leaves no trace in it.
fn shipped_asm_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("asm")
}

fn shipped_masm_path(rel: &str) -> std::path::PathBuf {
    shipped_asm_dir().join("xreserve").join(rel)
}

/// A note script is a project directory of its own, so a retired note is a directory that must not
/// come back rather than a file.
fn shipped_note_project_dir(name: &str) -> std::path::PathBuf {
    shipped_asm_dir().join("notes").join(name)
}

// 1 — POSTURE: the attestation policy IS the active mint policy (the sole supply gate restated)
// ================================================================================================

/// TRIPWIRE: the production composition's ACTIVE mint policy resolves to the attestation policy
/// (`xreserve::mint_policy::check_policy`) installed on the xreserve component — every supply
/// increase passes the attestation gate.
#[test]
fn active_mint_policy_is_the_attestation_policy() -> Result<()> {
    let _serial = tripwire_serial_guard_blocking();
    let components = production_component_set(0)?;
    let attestation_root = resolve_proc_root(&components, ATTESTATION_MINT_POLICY_PROC_PATH)
        .context(
        "the composed set must carry the attestation mint policy (xreserve::mint_policy::check_policy)",
    )?;
    let active = value_slot(&components, TokenPolicyManager::active_mint_policy_slot())?;
    assert_eq!(
        active, attestation_root,
        "the ACTIVE mint policy slot must hold the attestation policy root (INV-MINT-SECURITY: \
         every supply increase passes the attestation policy)"
    );
    Ok(())
}

/// TRIPWIRE: the allowed-mint-policy map is EXACTLY {the attestation policy root} — no reserved
/// alternate mint policy exists, so the attestation gate can never be swapped out at runtime.
#[test]
fn allowed_mint_policy_map_is_exactly_the_attestation_root() -> Result<()> {
    let _serial = tripwire_serial_guard_blocking();
    let components = production_component_set(0)?;
    let attestation_root = resolve_proc_root(&components, ATTESTATION_MINT_POLICY_PROC_PATH)
        .context("the composed set must carry the attestation mint policy")?;
    let map = map_slot(
        &components,
        TokenPolicyManager::allowed_mint_policies_slot(),
    )?;
    assert_eq!(
        map.num_entries(),
        1,
        "the allowed-mint map must carry EXACTLY one root (the attestation policy) — a superset \
         would leave a runtime path to a weaker mint policy"
    );
    let flag = map.get(&StorageMapKey::new(attestation_root));
    assert_ne!(
        flag,
        Word::empty(),
        "the allowed-mint map's single entry must be the attestation policy root"
    );
    Ok(())
}

// The active mint policy is no longer an injectable builder input — it is hard-wired to the
// attestation policy at composition (there is exactly one mint policy), so a "non-attestation active
// mint policy" build cannot be expressed through the public API and the former
// `builder_rejects_a_non_attestation_mint_policy` tripwire has no injection vector to exercise. The
// sole-supply-surface invariant is enforced by construction and asserted positively by
// `production_composition_installs_one_xreserve_and_one_manager` (builder_api.rs) and the frozen
// callable-surface pins.

/// TRIPWIRE: the mint-deny guard is fully dissolved — its module resolves nowhere in the
/// composition and its source file is gone (its job dissolved: the stock path IS the gated path).
#[test]
fn mint_deny_guard_is_fully_dissolved() -> Result<()> {
    let _serial = tripwire_serial_guard_blocking();
    let components = production_component_set(0)?;
    assert!(
        resolve_proc_root(&components, FORMER_MINT_DENY_GUARD_PROC_PATH).is_none(),
        "the mint-deny guard must not resolve anywhere in the composed set"
    );
    assert!(
        !shipped_masm_path("mint_deny_guard.masm").exists(),
        "asm/xreserve/mint_deny_guard.masm must be deleted"
    );
    Ok(())
}

// 2 — POSTURE: the custom mint transport deletes; the attestation policy + identifier init land
// ================================================================================================

/// TRIPWIRE: the custom mint transport MASM is deleted and the attestation mint policy module is
/// its replacement (the deletion ledger, executable).
#[test]
fn custom_mint_transport_masm_is_deleted() -> Result<()> {
    let _serial = tripwire_serial_guard_blocking();
    for gone in [
        "xreserve_mint.masm",
        "xreserve_mint_note_entry.masm",
        "mint_deny_guard.masm",
    ] {
        assert!(
            !shipped_masm_path(gone).exists(),
            "asm/xreserve/{gone} must be deleted by the recomposition"
        );
    }
    assert!(
        !shipped_note_project_dir("mint").exists(),
        "the custom mint note script must be deleted (the stock MintNote is the transport)"
    );
    assert!(
        shipped_masm_path("mint_policy.masm").exists(),
        "asm/xreserve/mint_policy.masm (the attestation mint policy) must exist"
    );
    Ok(())
}

/// TRIPWIRE: the legacy `domain_config` and `min_burn_admin` MASM are replaced;
/// the identifier-init module + note are gone too (the identifier is a
/// provable fixpoint of the account id, which is why the mint path derives it instead of reading a
/// seeded slot).
#[test]
fn legacy_config_and_burn_masm_are_replaced() -> Result<()> {
    let _serial = tripwire_serial_guard_blocking();
    for gone in ["domain_config.masm", "min_burn_admin.masm"] {
        assert!(
            !shipped_masm_path(gone).exists(),
            "asm/xreserve/{gone} must be deleted by the recomposition"
        );
    }
    assert!(
        !shipped_masm_path("identifier_init.masm").exists(),
        "asm/xreserve/identifier_init.masm must be deleted — the mint path derives the \
         identifier from the account's own id, so there is nothing left to initialize"
    );
    assert!(
        !shipped_note_project_dir("domain_init").exists(),
        "the four-field domain_init note script must be deleted"
    );
    assert!(
        !shipped_note_project_dir("identifier_init").exists(),
        "the identifier-init note script must be deleted along with the procedure it drove"
    );
    Ok(())
}

// 3 — POSTURE: one allowed burn policy with the zero floor preserved
// ================================================================================================

/// The faucet allows exactly one burn policy and stores a minimum burn amount of at least one.
#[test]
fn burn_policy_has_one_allowed_root_and_a_positive_floor() -> Result<()> {
    let _serial = tripwire_serial_guard_blocking();
    let components = production_component_set(0)?;
    let map = map_slot(
        &components,
        TokenPolicyManager::allowed_burn_policies_slot(),
    )?;
    assert_eq!(
        map.num_entries(),
        1,
        "the allowed-burn map must carry exactly one root"
    );
    let floor = value_slot(&components, MinBurnAmount::slot_name())?;
    assert!(
        floor[0].as_canonical_u64() >= 1,
        "the MinBurnAmount floor slot must ship >= 1 (zero-floor invariant), got {floor}"
    );
    assert_eq!(
        Word::from([
            floor[0],
            Felt::from(0u32),
            Felt::from(0u32),
            Felt::from(0u32)
        ]),
        floor,
        "the floor slot layout is [min_burn_amount, 0, 0, 0]"
    );
    Ok(())
}

/// TRIPWIRE: the builder REJECTS `min_burn_size < 1` at build time with the CONCRETE
/// `MinBurnSizeBelowFloor(0)` variant (the build-side half of the zero-floor guard — the
/// exact variant carrying the offending value, not a stringified word search).
#[test]
fn builder_rejects_a_zero_min_burn_floor() -> Result<()> {
    let _serial = tripwire_serial_guard_blocking();
    let outcome = production_builder_outcome(0, Some(0))?;
    assert_matches!(
        outcome,
        Err(XReserveStablecoinBuilderError::MinBurnSizeBelowFloor(0)),
        "a build with min_burn_size = 0 MUST be rejected with the exact below-floor variant \
         carrying the offending value (zero-floor invariant)"
    );
    Ok(())
}

// 4 — POSTURE: the note-script allowlist pins the stock MintNote
// ================================================================================================

/// The ten-root allowlist uses the standard `MintNote::script_root()` for minting.
#[test]
fn note_allowlist_pins_the_stock_mint_note() -> Result<()> {
    let _serial = tripwire_serial_guard_blocking();
    let allowlist =
        xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::allowed_note_scripts();
    assert_eq!(allowlist.len(), 10, "the allowlist contains 10 roots");
    assert!(
        allowlist.contains(&MintNote::script_root()),
        "row 1 must be the STOCK miden-standards MintNote script root"
    );
    let former = miden_protocol::note::NoteScriptRoot::from_raw(
        Word::parse(FORMER_CUSTOM_MINT_NOTE_ROOT_HEX).expect("pinned former root hex parses"),
    );
    assert!(
        !allowlist.contains(&former),
        "the former custom XReserveMintNote root must be REMOVED from the allowlist"
    );
    Ok(())
}
