//! Setting the minimum burn size: who may change the floor, and what changing it writes.
//!
//! The floor is not stored by the faucet. It lives in the standard minimum-burn policy's own value
//! slot as `[min, 0, 0, 0]`, which is exactly the slot the standard `check_policy` reads when it
//! decides whether a burn is large enough. The setter is the standard
//! `min_burn_amount::set_min_burn_amount`; the faucet contributes no setter of its own.
//!
//! Authority follows Circle's admin model: this setter carries no role of its own, so the
//! account-wide role-based authority resolves it to the built-in `ADMIN` role, seeded on the
//! administrator's account. The account also seeds separate Domain Pauser and Unpauser roles, but neither may
//! set the floor, and their own powers are tested in the pause and role suites. `ADMIN` membership
//! is account-bound: it is the faucet's only authority handle.
//!
//! The authorization gate itself is the standard setter's, and it is driven through the production
//! note in `f5_admin_notes.rs`. What is left here is what belongs to this repository: that the
//! composition installs the very setter root the production note targets, that the setter is
//! deliberately NOT blocked while the faucet is paused, and that the role seeding the support
//! replica hands to every suite running against it matches what the builder seeds. The end-to-end
//! consequence — set the floor, then watch a below-floor burn trap — lives with the burn-note
//! machinery in `xreserve_receive_and_burn.rs`.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::{Account, AccountId, RoleSymbol, StorageMapKey};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Ownable2Step, RoleBasedAccessControl};
use miden_standards::account::policies::MinBurnAmount;
use support::*;

// The production fixture seeds ADMIN and ATTEST_ADMIN on id(1), DOM_PAUSER on id(2),
// DOM_UNPAUSER on id(3), and BLK_MANAGER on id(4).
fn administrator() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn plain_non_administrator() -> AccountId {
    test_account_id(99)
}

// The role read by the non-member seed check.
const DOM_PAUSER_SYMBOL: &str = "DOM_PAUSER";

const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
/// The initial (fixture-seeded) burn floor for the setter tests (always `>= 1` — the zero-floor
/// invariant the production surface enforces at build and note level).
const SEED_MIN: u64 = 1_000;

// Stock RBAC map-key encodings (miden-testing/tests/scripts/rbac.rs:57-63).
fn role_membership_key(role: &RoleSymbol, id: AccountId) -> Word {
    Word::from([
        Felt::ZERO,
        Felt::from(role),
        id.suffix(),
        id.prefix().as_felt(),
    ])
}

/// The STOCK `MinBurnAmount` floor-slot value word for a floor `v` (`[v,0,0,0]`) — the read-back
/// the write-integrity and no-state-change tests compare against (via [`read_min_burn_size`]).
/// Test floors are small, so `as u32` is exact.
fn min_word(v: u64) -> Word {
    Word::from([Felt::from(v as u32), Felt::ZERO, Felt::ZERO, Felt::ZERO])
}

/// A burn-oracle faucet (stock `MinBurnAmount` active) with the STOCK floor slot seeded
/// `SEED_MIN`. The burn_amount arg only feeds the (unconsumed here) canonical burn note.
fn faucet_harness() -> Result<BurnPolicyHarness> {
    setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        SEED_MIN,
        SEED_MIN,
    )
}

/// The faucet's CURRENT committed account (the setter tx's starting point).
fn faucet(h: &BurnPolicyHarness) -> Result<Account> {
    Ok(h.chain.committed_account(h.faucet_id)?.clone())
}

// SETTER-INSTALLED PROBE (the stock setter is part of the composed production surface)
// ================================================================================================

/// The production component set actually installs the setter the production note targets.
///
/// The note script calls the standard `min_burn_amount::set_min_burn_amount` by root, so if the
/// composition ever stopped including that procedure the note would fail at runtime with an
/// unhelpful "procedure not found". Checking the installed procedure roots here turns that into a
/// build-time-shaped failure with an obvious cause.
#[test]
fn probe_stock_min_burn_setter_installed() -> Result<()> {
    let components = production_component_set(0)?;
    assert!(
        components
            .iter()
            .any(|c| c.has_procedure(MinBurnAmount::set_min_burn_amount_root())),
        "the production component set must expose the stock MinBurnAmount::set_min_burn_amount \
         root (the setter the production admin note targets)"
    );
    Ok(())
}

// THE SETTER IS NOT PAUSE-GATED: the administrator may update the minimum while the faucet is paused
// ================================================================================================

/// After the Domain Pauser pauses the faucet (the stock `PausableManager`, role-gated), an
/// An administrator-sent minimum-burn configuration note succeeds while paused: the setter is not
/// pause-gated, so the burn floor can be adjusted during a pause. The full word `[new_min,0,0,0]`
/// lands despite is_paused == true; the administrator gate still governs it (the rejection tests
/// above prove that half).
#[tokio::test]
async fn set_min_burn_administrator_succeeds_while_paused() -> Result<()> {
    let h = faucet_harness()?;
    let account = faucet(&h)?;
    const NEW_MIN: u64 = 5_000;

    // tx1: the DOM_PAUSER pauses the faucet (is_paused := true).
    let paused = run_dom_pauser_pause(&h.chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;

    // tx2: the administrator's minimum-burn update succeeds while paused.
    let executed = run_set_min_burn_amount_against(&h.chain, &evolved, administrator(), NEW_MIN, 7)
        .await
        .expect("the administrator's minimum-burn update must succeed while the faucet is paused");
    evolved.apply_patch(executed.account_patch())?;

    assert_eq!(
        read_min_burn_size(&evolved)?,
        min_word(NEW_MIN),
        "the stock set_min_burn_amount writes [new_min,0,0,0] to the stock MinBurnAmount floor \
         slot while paused"
    );
    Ok(())
}

// ROLE SEEDING — the replica matches production
// ================================================================================================

/// The burn-oracle replica carries exactly the production RBAC config and membership maps.
#[tokio::test]
async fn support_replica_matches_the_production_role_seed() -> Result<()> {
    let h = faucet_harness()?;
    let account = faucet(&h)?;
    let components = production_component_set(TOKEN_SUPPLY)?;
    for name in [
        RoleBasedAccessControl::role_config_slot(),
        RoleBasedAccessControl::role_membership_slot(),
    ] {
        let expected = components
            .iter()
            .flat_map(|component| component.storage_slots())
            .find(|slot| slot.name() == name)
            .context("the production composition carries the RBAC slot")?;
        assert_eq!(
            account
                .storage()
                .get(name)
                .context("the replica carries the RBAC slot")?,
            expected,
            "the replica must match the production {name} seed"
        );
    }

    // And the replica must not carry an authority handle the shipped account has retired: the
    // ownership component is gone from production, so a replica that still installs it would give
    // the suites running against it an administrator slot and five callable procedures the real faucet does
    // not have — the divergence that makes a replica stop being evidence.
    assert!(
        Ownable2Step::try_from_storage(account.storage()).is_err(),
        "the replica must carry no owner-config slot — the shipped composition installs no          ownership component, and the built-in ADMIN role is its only authority handle"
    );
    Ok(())
}

/// A wrong-key membership read stays EMPTY: a non-member id is not a `DOM_PAUSER` member (proves the
/// seed is keyed on the intended holder, not blanket-true).
#[tokio::test]
async fn dom_non_member_reads_empty() -> Result<()> {
    let pauser = RoleSymbol::new(DOM_PAUSER_SYMBOL).expect("DOM_PAUSER is a valid role symbol");
    let h = faucet_harness()?;
    let account = faucet(&h)?;

    let non = account.storage().get_map_item(
        RoleBasedAccessControl::role_membership_slot(),
        StorageMapKey::new(role_membership_key(&pauser, plain_non_administrator())),
    )?;
    assert_eq!(
        non[0],
        Felt::ZERO,
        "a non-member id is not a DOM_PAUSER member"
    );
    Ok(())
}
