//! `XReserveStablecoinBuilder` API suite: the production
//! builder must compose an ATTESTATION-gated PUBLIC faucet and reject the packaging mistakes that
//! would weaken the mint/burn posture — a non-`Public` account type, an active mint policy that is
//! not the attestation policy (the sole-supply-surface invariant restated: every supply increase
//! passes
//! `xreserve::mint_policy::check_policy`) and a sub-floor `min_burn_amount`.
//! The build-validation tests assert the exact rejection variants (pure builder logic); the
//! composed-set tests pin the posture the builder ships (active-policy slot, component seam,
//! domain-config seeding).

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::{
    AccountComponent, AccountProcedureRoot, RoleSymbol, StorageSlotName,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{PausableManager, PausableStorage};
use miden_standards::account::policies::{BlocklistManager, MinBurnAmount, TokenPolicyManager};
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveAdminAuthority, XReserveFaucetExtension, XReserveStablecoinBuilder,
    XReserveStablecoinBuilderError, ATTESTATION_MINT_POLICY_PROC_PATH, ATTEST_ADMIN_ROLE,
    BLK_MANAGER_ROLE, DOM_PAUSER_ROLE, DOM_UNPAUSER_ROLE,
};

/// The standard production builder: the fixed test supplies through the ONE production-shape
/// definition in `support` (ADMIN = ATTEST_ADMIN = id(1), DOM_PAUSER = id(2), DOM_UNPAUSER = id(3),
/// BLK_MANAGER = id(4), plus the build-seeded domain config).
fn production_builder() -> XReserveStablecoinBuilder {
    support::production_builder(0, TEST_DOMAIN).expect("the fixed-identity USDCx faucet builds")
}

/// Looks up a procedure's root by its library path across every component in the composed set.
///
/// The set is a flat list of components and a given procedure lives in exactly one of them, so the
/// first hit is the answer; `None` means no component exposes that path at all.
fn resolve_proc_root(components: &[AccountComponent], path: &str) -> Option<Word> {
    components
        .iter()
        .find_map(|c| c.get_procedure_root_by_path(path))
        .map(Word::from)
}

/// Finds a named VALUE slot's word across the composed component set.
fn find_value_slot(components: &[AccountComponent], name: &StorageSlotName) -> Option<Word> {
    components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|slot| slot.name() == name)
        .map(|slot| slot.value())
}

// BUILD + POSTURE — the production attestation-gated faucet
// ================================================================================================

/// The production composition builds, and the account it produces is gated on the attestation
/// policy.
///
/// Two things are asserted. The build succeeds and yields a public faucet, and the active
/// mint-policy storage slot holds the root of the attestation policy actually installed in the
/// composed component — not merely some non-empty value. Together they are the build-time half of
/// the claim that a mint can only happen against a valid Circle attestation; the runtime halves,
/// where real notes are minted and rejected, live in the recomposition and mint-policy end-to-end
/// suites.
#[test]
fn build_produces_attestation_gated_public_faucet() -> Result<()> {
    let components = production_builder().build_components().context(
        "the default production builder must compose an attestation-gated Public faucet",
    )?;

    let attestation_root = resolve_proc_root(&components, ATTESTATION_MINT_POLICY_PROC_PATH)
        .context("the composed set must carry the attestation mint policy proc")?;
    let active = find_value_slot(&components, TokenPolicyManager::active_mint_policy_slot())
        .context("the composed set must carry the active-mint-policy slot")?;
    assert_eq!(
        active, attestation_root,
        "the ACTIVE mint policy slot must hold the attestation policy root (INV-MINT-SECURITY)"
    );
    Ok(())
}

// BUILD VALIDATION REJECTS (GREEN)
// ================================================================================================

// The max-supply mutability invariant is now enforced BY CONSTRUCTION: the crate-root
// `build_faucet_account` builds the faucet `is_max_supply_mutable(true)`, so there is no
// runtime `ImmutableMaxSupply` reject to exercise, and the former `build_rejects_immutable_max_supply`
// tripwire has no immutable faucet to inject through the public constructor. The invariant is
// asserted positively by the crate-root byte-identity suite, which builds through
// `build_faucet_account` and composes a valid faucet whose `set_max_supply` stays operable.

// PRODUCTION minBurnSize SEEDING (the stock MinBurnAmount floor slot)
// ================================================================================================

/// Production `build_components` SEEDS the STOCK `MinBurnAmount` floor slot
/// (`MinBurnAmount::slot_name()` = `[min_burn_amount, 0, 0, 0]`, carried by the policy companion
/// component the manager emits) so the stock burn policy's floor read resolves on a real production
/// faucet — the builder owns a `min_burn_amount` default/override, and the
/// standard min-burn-amount config note mutates the SAME slot at runtime. The expected value uses the
/// canonical full-u64 `AssetAmount -> Felt`, so an `as u32` truncation in the seed would fail this
/// test (see the MIN_BURN choice below).
#[test]
fn production_seeds_min_burn_size() -> Result<()> {
    // Anti-truncation: minBurnSize is a FULL `u64` `AssetAmount` (`AssetAmount::MAX` =
    // 2^63 - 2^31), encoded as `[min_burn_size, 0, 0, 0]`. MIN_BURN is chosen > `u32::MAX` so any
    // `... as u32` truncation — in the seed (green) OR in this expectation — yields a DIFFERENT `Felt`
    // and fails the test, rather than two sides silently agreeing on a truncated low-32-bit value.
    const MIN_BURN: u64 = 5_000_000_000; // > u32::MAX (4_294_967_295), well within AssetAmount::MAX
    const _: () = assert!(
        MIN_BURN > u32::MAX as u64,
        "MIN_BURN must exceed u32::MAX so the encoding test catches u32 truncation",
    );
    let components = production_builder_verdict(
        0,
        TEST_DOMAIN,
        Some(AssetAmount::new(MIN_BURN).context("MIN_BURN must be within AssetAmount::MAX")?),
    )?
    .context("the fixed-identity USDCx faucet builds")?
    .build_components()
    .context("production build_components must compose")?;

    let floor = find_value_slot(&components, MinBurnAmount::slot_name()).with_context(|| {
        format!(
            "production build_components must install the stock MinBurnAmount floor slot \
             '{}' (the policy companion); none of the {} composed components carries it",
            MinBurnAmount::slot_name(),
            components.len()
        )
    })?;
    // Canonical FULL-u64 encoding via the protocol's own `AssetAmount -> Felt`, NOT `MIN_BURN as
    // u32` — so a seed that truncated the high bits would mismatch and fail here.
    let expected_min_burn =
        Felt::from(AssetAmount::new(MIN_BURN).context("MIN_BURN must be within AssetAmount::MAX")?);
    assert_eq!(
        floor,
        Word::from([expected_min_burn, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        "the seeded MinBurnAmount floor slot must carry the FULL-u64 [min_burn_amount, 0, 0, 0] \
         (no u32 truncation)"
    );
    Ok(())
}

/// A `min_burn_amount` below the floor (= 1) is rejected with the EXACT `MinBurnSizeBelowFloor(0)`:
/// the stock `MinBurnAmount` asserts only `min <= amount` (its stock setter even accepts 0), so a
/// zero seed would silently drop the zero-burn invariant — the builder half of the
/// zero-floor guard (the other half is the `XReserveMinBurnAmountNote` factory's refusal). The faucet
/// is otherwise valid, so the sub-floor seed is the SOLE reason for rejection. (An over-max seed
/// is unrepresentable by construction: the input is a typed `AssetAmount`.)
#[test]
fn build_rejects_zero_min_burn_amount() -> Result<()> {
    let zero = AssetAmount::new(0).expect("a zero asset amount is representable");
    let err = production_builder_verdict(0, TEST_DOMAIN, Some(zero))?.expect_err(
        "a min_burn_amount of 0 must be rejected at construction (zero-floor invariant)",
    );
    assert!(
        matches!(
            err,
            XReserveStablecoinBuilderError::MinBurnSizeBelowFloor(0)
        ),
        "expected MinBurnSizeBelowFloor(0), got {err:?}"
    );
    Ok(())
}

// DOMAIN-CONFIG SEEDING — required input + build-time slot writes
// ================================================================================================

/// The build seeds the domain slot as `[domain, 0, 0, 0]`.
#[test]
fn build_seeds_the_domain_slot() -> Result<()> {
    let components = production_builder()
        .build_components()
        .context("production build_components must compose")?;

    let slot = |name: &StorageSlotName| -> Result<Word> {
        find_value_slot(&components, name)
            .with_context(|| format!("the composed set must carry the '{name}' slot"))
    };
    assert_eq!(
        slot(XReserveFaucetExtension::domain_config_slot())?,
        Word::from([TEST_DOMAIN.as_u32(), 0, 0, 0]),
        "the domain slot must hold the build-seeded [domain, 0, 0, 0]"
    );
    Ok(())
}

// PAUSE COMPOSITION — Domain-Pauser-ONLY pause surface
// ================================================================================================

/// Domain-Pauser-only pause (Circle requires that only the Domain Pauser role may pause), now
/// expressed in the stock components: the production composition installs the stock
/// `PausableManager` and `BlocklistManager`, and the authority's role map is what keeps each of
/// their procedures with its own role rather than with the administrator.
///
/// The structural half is here — the four manager roots and the attester setter are installed,
/// and each carries the role the faucet intends. The executing half is
/// `administrator_has_no_pause_path` / `administrator_has_no_unpause_path` (pause_admin.rs) and the effects suite.
#[test]
fn builder_installs_the_stock_managers_with_their_roles_assigned() -> Result<()> {
    let components = production_builder()
        .build_components()
        .context("production build_components must compose")?;

    let installed: std::collections::BTreeSet<_> = components
        .iter()
        .flat_map(|component| component.procedures().map(|(root, _is_auth)| root))
        .collect();
    let roles = XReserveAdminAuthority::new().procedure_roles().clone();
    let pauser = RoleSymbol::new(DOM_PAUSER_ROLE).expect("the Domain pauser role symbol is valid");
    let unpauser =
        RoleSymbol::new(DOM_UNPAUSER_ROLE).expect("the Domain unpauser role symbol is valid");
    let attest_admin =
        RoleSymbol::new(ATTEST_ADMIN_ROLE).expect("the attester administrator role is valid");
    let blocklist_manager = RoleSymbol::new(BLK_MANAGER_ROLE)
        .expect("the blocklist administrator role symbol is valid");

    for (what, root, role) in [
        ("pause", PausableManager::pause_root(), &pauser),
        ("unpause", PausableManager::unpause_root(), &unpauser),
        (
            "block_account",
            BlocklistManager::block_account_root(),
            &blocklist_manager,
        ),
        (
            "unblock_account",
            BlocklistManager::unblock_account_root(),
            &blocklist_manager,
        ),
        (
            "set_attester",
            AccountProcedureRoot::from_raw(
                resolve_proc_root(
                    &components,
                    "xreserve::components::faucet_extension::set_attester",
                )
                .context("the composed set must carry the attester setter")?,
            ),
            &attest_admin,
        ),
    ] {
        assert!(
            installed.contains(&root),
            "the production composition must install the gated procedure {what} — the \
             config note calls that exact root"
        );
        assert_eq!(
            roles.get(&root),
            Some(role),
            "the procedure {what} must be gated on its intended role, or the \
             capability lands on the administrator instead"
        );
    }
    Ok(())
}

/// The `is_paused` slot's provenance: the production composition carries the value slot
/// `miden::standards::access::pausable::is_paused`, installed at v0.16 by the base `Pausable`
/// component the builder adds (`Pausable::unpaused()`) — NOT by `FungibleFaucet` (v0.16 moved the
/// slot OUT of the faucet) and NOT by the stock `PausableManager`, which writes the slot but
/// installs zero storage of its own. Without this slot the mint/burn
/// `assert_not_paused` halt-gates break, reopening the pause halt-gap (Circle requires a paused
/// faucet halt mint and burn) — and at v0.16 that failure is SILENT rather than loud: #3047 made
/// `pausable::assert_not_paused` a no-op on accounts lacking the slot instead of trapping. This
/// test is therefore the load-bearing structural tripwire for the composition: it goes RED the
/// moment `Pausable` leaves the component list.
#[test]
fn production_components_carry_is_paused_slot() -> Result<()> {
    let components = production_builder()
        .build_components()
        .context("production build_components must compose")?;

    let is_paused = PausableStorage::is_paused_slot();
    assert!(
        components
            .iter()
            .flat_map(|c| c.storage_slots().iter())
            .any(|slot| slot.name() == is_paused),
        "the production composition must carry the Pausable-installed is_paused slot (v0.16 #2944 \
         moved it out of FungibleFaucet); its absence SILENTLY disables the mint/burn pause \
         halt-gates at v0.16 (#3047 no-ops assert_not_paused when the slot is missing) — \
         CIR-ADMIN-4"
    );
    Ok(())
}

/// The production metadata mutability config permits maximum-supply updates while keeping the
/// description, logo URI, and external link immutable. This matters because the standard faucet
/// metadata configuration note dispatches all four actions from one allowlisted script root.
#[test]
fn production_components_carry_mutability_config_slot() -> Result<()> {
    let components = production_builder()
        .build_components()
        .context("production build_components must compose")?;

    let mutability = StorageSlotName::new("miden::standards::faucets::mutability_config")
        .context("the pinned mutability_config slot name")?;
    let slot_value = components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|slot| slot.name() == &mutability)
        .map(|slot| slot.value())
        .expect("the production composition must carry the faucet mutability configuration");
    assert_eq!(
        slot_value,
        Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ONE]),
        "only maximum supply is mutable",
    );
    Ok(())
}
