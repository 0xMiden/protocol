//! FULL-ACCOUNT CALLABLE-SURFACE REACHABILITY PROOFS (S12, human-ratified 2026-07-13).
//!
//! The composed account carries every callable procedure the STOCK components contribute
//! (`Authority` incl. the v0.16 `freeze`/`unfreeze`, `RoleBasedAccessControl`, `FungibleFaucet`,
//! `TokenPolicyManager`, `MinBurnAmount`, `Pausable`, and the `AuthNetworkAccount` auth procedure)
//! alongside the two xreserve roots. A stock dependency bump can hand this faucet a NEW callable
//! capability: at the v0.16 migration the stock `Authority` component began bundling
//! authority-gated `freeze`/`unfreeze` procedures (upstream #3102/#3209) that no v0.15 composition
//! had, and the #3047 `policy_manager::invoke_send_policy`/`invoke_receive_policy` transfer-policy
//! dispatch wrappers plus `authority::get_authority` came with it (human-ratified in their OWN map
//! row S24, NOT under S12). SINCE THE F4 REVERSAL (2026-07-23) the wrappers are LIVE, not inert:
//! the stock `BasicBlocklist` is wired as the active send + receive policy, so
//! `AssetCallbackFlag::Enabled` and the kernel `dyncall`s the wrappers on every policed-asset
//! transfer, which run the account-wide pause check + `basic_blocklist::check_policy`.
//! `invoke_wrappers_are_live_and_the_asset_is_policed` re-confirms the reversal at v16.
//!
//! What this file asserts about that surface is REACHABILITY, never its size or its literal
//! membership: a count or a frozen path list records a changelog, and a stock bump edits it rather
//! than being caught by it. What matters is that no admissible entry vector can reach a capability
//! the composition does not intend.
//!
//! S12 DISPOSITION — `freeze`/`unfreeze` are PRESENT but OPERATIONALLY UNREACHABLE, and this file
//! proves it rather than asserting it: the faucet is a keyless network account whose
//! `AuthNetworkAccount` admits ONLY the immutable 10-root note-script allowlist and a tx-script
//! allowlist of EXACTLY the one canonical `ExpirationTransactionScript` (S12, RATIFIED 2026-07-20 —
//! F5). `freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note`
//! scans the MAST of all 10 allowlisted note scripts and shows not one of them references the
//! freeze/unfreeze roots; `freeze_and_unfreeze_are_not_admissible_via_either_allowlist` shows the
//! roots are not among the 10 note-script roots; and `the_auth_component_rejects_a_non_allowlisted_note`
//! / `the_auth_component_rejects_non_expiration_tx_scripts_and_admits_expiration` EXECUTE the two
//! (and only two) entry vectors and watch the auth component reject every non-admitted script (the
//! sole admitted tx-script — the expiration bounder — cannot reach freeze). (The allowlist is an epilogue
//! `@auth_script`, checked AFTER note/tx-script execution, so a note that itself calls `freeze`
//! would trap on freeze's own owner-gate before the allowlist check — the allowlist's decision on
//! such a note is the root-membership one, which is why the freeze-specific proof is membership,
//! not a self-trapping execution.) So `freeze` can never be invoked, `is_frozen` is never set, and
//! `ERR_AUTHORITY_FROZEN` never fires: the mechanism is inert — the same disposition as the
//! ratified `renounce_role`.
//!
//! ROLE MANAGEMENT — REACHABLE, and deliberately so. The standard role-action note is allowlisted,
//! and its single script root carries `grant_role`, `revoke_role`, `set_role_admin` and
//! `renounce_role` alike, so all four are reachable on this account. That is a human-ratified
//! capability decision, not an oversight: the role-admin graph the build seeds
//! (`role_config[DOM_PAUSER].admin_role = DOM_MANAGER`) is runtime-mutable, each role's effective
//! admin governs the role it administers exclusively, and a holder may drop its own membership.
//! `w2admin_surface_finalization.rs` drives all four actions against the real faucet.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::account::Account;
use miden_protocol::account::AssetCallbackFlag;
use miden_protocol::assembly::mast::MastNodeExt;
use miden_protocol::asset::AssetCallbacks;
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::Word;
use miden_standards::account::access::Authority;
use miden_standards::account::policies::TokenPolicyManager;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

/// The committed production faucet ACCOUNT (the real composed, auth-carrying account the network
/// executes against).
fn production_account() -> Result<Account> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let account = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .context("the production faucet must be committed")?
        .clone();
    Ok(account)
}

// S12 — FREEZE / UNFREEZE: PRESENT, AND PROVABLY UNREACHABLE
// ================================================================================================

/// PRESENT: the v0.16 `Authority` freeze/unfreeze procedures ARE callable roots of the composed
/// account (this is the fact S12 ratifies, stated explicitly rather than left implicit in a count).
#[test]
fn authority_freeze_and_unfreeze_are_present_on_the_account() -> Result<()> {
    let account = production_account()?;
    let roots: BTreeSet<Word> = account
        .code()
        .procedures()
        .iter()
        .map(|root| Word::from(*root))
        .collect();
    for (name, root) in [
        ("freeze", Word::from(Authority::freeze_root())),
        ("unfreeze", Word::from(Authority::unfreeze_root())),
    ] {
        assert!(
            roots.contains(&root),
            "the v0.16 stock Authority component contributes `{name}` to the account's callable \
             surface (S12) — if this ever stops being true, the S12 disposition must be re-ratified"
        );
    }
    Ok(())
}

/// UNREACHABLE, leg 1 (static, exhaustive over the allowlist): NOT ONE of the 10 allowlisted note
/// scripts references the freeze or unfreeze root ANYWHERE in its MAST — so no admissible note can
/// invoke them. Scanning every MAST node digest (not just the entrypoint) catches a call by root, a
/// call by path, and any nested/external reference alike.
#[test]
fn freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let scripts = allowlisted_note_scripts();
    assert_eq!(
        scripts.len(),
        10,
        "the unreachability sweep must cover all 10 allowlisted note scripts"
    );
    // The scripts swept ARE the allowlist (no script can dodge the sweep by not being listed here).
    let swept: BTreeSet<_> = scripts.iter().map(|(_, s)| s.root()).collect();
    assert_eq!(
        swept, allowlist,
        "the swept note scripts must be EXACTLY the 10-root note-script allowlist"
    );

    let forbidden = [
        ("freeze", Word::from(Authority::freeze_root())),
        ("unfreeze", Word::from(Authority::unfreeze_root())),
    ];
    for (label, script) in &scripts {
        let forest = script.mast();
        for node in forest.nodes() {
            let digest = node.digest();
            for (name, root) in &forbidden {
                assert_ne!(
                    digest, *root,
                    "allowlisted note script `{label}` references the Authority `{name}` root — \
                     the S12 unreachability guarantee is BROKEN (a note that can invoke freeze \
                     would make the account-self-freeze operationally reachable)"
                );
            }
        }
    }
    Ok(())
}

/// UNREACHABLE, cross-reference (freeze-specific): the freeze/unfreeze roots are not ADMISSIBLE via
/// either entry vector. `AuthNetworkAccount` admits an input note only if its script root is one of
/// the 10 allowlisted roots, and admits a transaction script only if its root is in the transaction
/// script allowlist, which admits exactly the canonical `ExpirationTransactionScript` root and
/// never freeze or unfreeze.
/// There is no freeze/unfreeze NOTE FACTORY at all (the 10 are the two supply notes, six admin
/// notes, and two fee notes; none carries freeze), so no freeze-bearing note root can be among the
/// 10, and the one-root
/// tx-script allowlist admits only the expiration bounder (not freeze). Combined with the MAST sweep
/// above (no allowlisted note even references the roots) both entry vectors are provably closed.
#[test]
fn freeze_and_unfreeze_are_not_admissible_via_either_allowlist() -> Result<()> {
    let note_allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    for (name, root) in [
        ("freeze", Authority::freeze_root()),
        ("unfreeze", Authority::unfreeze_root()),
    ] {
        let as_note_root = NoteScriptRoot::from_raw(Word::from(root));
        assert!(
            !note_allowlist.contains(&as_note_root),
            "the `{name}` root must NOT be a member of the 10-root note-script allowlist \
             (there is no freeze note factory; a freeze-bearing note is inadmissible)"
        );
    }
    // The tx-script entry vector is closed to freeze by the one-root tx-script allowlist (it admits
    // ONLY the canonical expiration bounder, not freeze) — pinned + executed by
    // `the_auth_component_rejects_non_expiration_tx_scripts_and_admits_expiration` below (and the
    // canonical `f5_network_account_auth::production_faucet_tx_script_allowlist_is_exactly_the_expiration_root`).
    // Together with the note-root non-membership above, no freeze/unfreeze call is admissible via
    // either entry vector.
    Ok(())
}

// S24 (F4-REVERSAL) — the invoke_* wrappers are LIVE: the transfer blocklist is policed and the
// callback flag is Enabled
// ================================================================================================

/// F4-REVERSAL policed counterpart of the former `invoke_wrappers_are_inert_and_the_asset_stays_basic`
/// (which asserted the OPPOSITE — no callback slots, `AssetCallbackFlag::Disabled` — under the
/// basic-asset F4). The transfer blocklist is now wired as the active send + receive policy, so the
/// #3047 `invoke_send_policy`/`invoke_receive_policy` wrappers are LIVE. Asserts, directly on the
/// shipped composition + account: (1) BOTH protocol asset-callback slots ARE installed and hold the
/// fixed `invoke_*_policy` wrapper roots (the kernel dispatches them on every policed-asset
/// transfer), and (2) the committed faucet account id carries `AssetCallbackFlag::Enabled` (every
/// minted xUSDC is a POLICED asset — the silent-foot-gun tripwire: a fixture built Disabled with the
/// policy wired would make the callbacks never fire, and this assertion catches it — mutation check
/// (b)). Complements the policed `basic_asset_tripwire` (F4-reversal).
#[test]
fn invoke_wrappers_are_live_and_the_asset_is_policed() -> Result<()> {
    let components =
        production_component_set(0).context("the production composition must build")?;

    // (1) the transfer blocklist is wired → BOTH asset-callback slots are installed, holding the
    // fixed invoke_*_policy wrapper roots.
    let expected_callbacks = [
        (
            AssetCallbacks::on_before_asset_added_to_note_slot(),
            TokenPolicyManager::invoke_send_policy_root().as_word(),
        ),
        (
            AssetCallbacks::on_before_asset_added_to_account_slot(),
            TokenPolicyManager::invoke_receive_policy_root().as_word(),
        ),
    ];
    for (slot, wrapper_root) in expected_callbacks {
        let installed = components
            .iter()
            .flat_map(|c| c.storage_slots().iter())
            .find(|s| s.name() == slot)
            .unwrap_or_else(|| {
                panic!(
                    "the asset-callback slot ({slot}) must be installed — the transfer blocklist is \
                     wired as the active send/receive policy (F4-reversal), so the invoke_* wrappers \
                     are LIVE"
                )
            });
        assert_eq!(
            installed.value(),
            wrapper_root,
            "the asset-callback slot ({slot}) must hold the fixed invoke_*_policy wrapper root"
        );
    }

    // (2) the committed faucet account id carries the Enabled callback flag (policed asset). A
    // Disabled flag with the policy wired would silently never fire the callbacks — the audited
    // foot-gun. This assertion makes that impossible to miss (mutation check (b)).
    let account = production_account()?;
    assert_eq!(
        account.id().asset_callback_flag(),
        AssetCallbackFlag::Enabled,
        "the faucet account id must carry AssetCallbackFlag::Enabled (every minted xUSDC is a \
         POLICED asset — the transfer blocklist callbacks only fire when the id flag is Enabled)"
    );
    Ok(())
}
