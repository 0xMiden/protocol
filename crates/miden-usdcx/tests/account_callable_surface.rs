//! Checks the faucet's initial script allowlists and transfer-policy callbacks.
//!
//! `ADMIN` can later change the allowlists through `NetworkAccountConfigNote` or replace the
//! faucet code through `UpgradeNote`. These tests do not cover those later configurations.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::Word;
use miden_protocol::account::{Account, AssetCallbackFlag};
use miden_protocol::assembly::mast::MastNodeExt;
use miden_protocol::asset::AssetCallbacks;
use miden_protocol::note::NoteScriptRoot;
use miden_standards::account::access::Authority;
use miden_standards::account::policies::TokenPolicyManager;
use miden_usdcx::account::xreserve::XReserveStablecoinBuilder;
use support::*;

/// Builds and commits a faucet with the production components.
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

// FREEZE AND UNFREEZE
// ================================================================================================

/// The account includes the standard freeze and unfreeze procedures.
#[test]
fn authority_freeze_and_unfreeze_are_present_on_the_account() -> Result<()> {
    let account = production_account()?;
    let roots: BTreeSet<Word> =
        account.code().procedures().iter().map(|root| Word::from(*root)).collect();
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

/// The initial note scripts do not directly reference freeze or unfreeze.
/// This scans each note's own MAST, not the code of referenced packages.
#[test]
fn freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let scripts = allowlisted_note_scripts();
    assert_eq!(
        scripts.len(),
        12,
        "the unreachability sweep must cover all 12 allowlisted note scripts"
    );
    // Check every script in the builder's allowlist.
    let swept: BTreeSet<_> = scripts.iter().map(|(_, s)| s.root()).collect();
    assert_eq!(
        swept, allowlist,
        "the swept note scripts must be EXACTLY the 12-root note-script allowlist"
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

/// Neither freeze nor unfreeze is listed as an allowed note script.
#[test]
fn freeze_and_unfreeze_are_not_admissible_via_either_allowlist() -> Result<()> {
    let note_allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    for (name, root) in
        [("freeze", Authority::freeze_root()), ("unfreeze", Authority::unfreeze_root())]
    {
        let as_note_root = NoteScriptRoot::from_raw(Word::from(root));
        assert!(
            !note_allowlist.contains(&as_note_root),
            "the `{name}` root must not be in the initial note-script allowlist"
        );
    }
    Ok(())
}

// TRANSFER-POLICY CALLBACKS
// ================================================================================================

/// Both transfer-policy callbacks are installed and the account's callback flag is enabled.
#[test]
fn invoke_wrappers_are_live_and_the_asset_is_policed() -> Result<()> {
    let components =
        production_component_set(0).context("the production composition must build")?;

    // Check the send and receive callbacks in component storage.
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

    // Installed callbacks only run when the account ID has this flag enabled.
    let account = production_account()?;
    assert_eq!(
        account.id().asset_callback_flag(),
        AssetCallbackFlag::Enabled,
        "the faucet account id must carry AssetCallbackFlag::Enabled (every minted xUSDC is a \
         POLICED asset — the transfer blocklist callbacks only fire when the id flag is Enabled)"
    );
    Ok(())
}
