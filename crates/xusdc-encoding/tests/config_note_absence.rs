//! Network-account configuration is excluded while fee configuration is allowed.
//!
//! The production auth component admits ten note roots, including the constant-fee configuration
//! and fee-sponsorship notes. It excludes `NetworkAccountConfigNote`, so accepted notes cannot
//! modify the note-script or transaction-script allowlists.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::account::{AccountComponent, StorageSlotContent, StorageSlotName};
use miden_protocol::Word;
use miden_standards::account::auth::{AuthNetworkAccount, NetworkAccountNoteAllowlist};
use miden_standards::note::config::{ConstantFeePolicyConfigNote, NetworkAccountConfigNote};
use miden_standards::note::FeeSponsorshipNote;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

fn forbidden_root() -> Word {
    NetworkAccountConfigNote::script_root().as_word()
}

fn required_fee_roots() -> [(&'static str, Word); 2] {
    [
        (
            "ConstantFeePolicyConfigNote",
            ConstantFeePolicyConfigNote::script_root().as_word(),
        ),
        (
            "FeeSponsorshipNote",
            FeeSponsorshipNote::script_root().as_word(),
        ),
    ]
}

/// Reads the non-empty keys of a map storage slot from an `AccountComponent`.
fn allowlisted_keys(component: &AccountComponent, slot: &StorageSlotName) -> BTreeSet<Word> {
    let content = component
        .storage_slots()
        .iter()
        .find(|s| s.name() == slot)
        .unwrap_or_else(|| panic!("the auth component must carry the {slot} slot"))
        .content();
    let StorageSlotContent::Map(map) = content else {
        panic!("the {slot} slot must be a MAP slot");
    };
    map.entries()
        .filter(|(_key, value)| **value != Word::empty())
        .map(|(key, _value)| key.as_word())
        .collect()
}

/// The builder excludes general network-account configuration and includes both fee notes.
#[test]
fn builder_allowlist_exposes_only_the_fee_config_surface() {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    assert!(
        !allowlist
            .iter()
            .any(|root| root.as_word() == forbidden_root()),
        "NetworkAccountConfigNote must stay out of the builder allowlist",
    );
    for (name, root) in required_fee_roots() {
        assert!(
            allowlist
                .iter()
                .any(|candidate| candidate.as_word() == root),
            "the {name} script root must be present",
        );
    }
}

/// The auth component contains the two fee roots and excludes general network-account
/// configuration.
#[test]
fn auth_component_materializes_the_exact_fee_enabled_allowlist() -> Result<()> {
    let component: AccountComponent =
        XReserveStablecoinBuilder::auth_component(test_fee_parameters(), test_fee_asset_id())
            .map_err(|e| anyhow::anyhow!("auth_component() must build: {e}"))?
            .into_iter()
            .next()
            .expect("the auth component is yielded first");

    let note_keys = allowlisted_keys(&component, AuthNetworkAccount::allowed_note_scripts_slot());
    assert_eq!(
        note_keys.len(),
        10,
        "the auth component's note-script allowlist must contain exactly 10 roots; \
         found {}",
        note_keys.len(),
    );
    assert!(
        !note_keys.contains(&forbidden_root()),
        "NetworkAccountConfigNote must stay absent",
    );
    for (name, root) in required_fee_roots() {
        assert!(
            note_keys.contains(&root),
            "the auth component must allow {name}",
        );
    }
    Ok(())
}

/// The built faucet contains the same ten-root allowlist as the auth component.
#[test]
fn built_account_materializes_the_exact_fee_enabled_allowlist() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let account = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .context("the production faucet must be committed")?
        .clone();

    let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())
        .map_err(|e| anyhow::anyhow!("the faucet must carry the allowlist slot: {e}"))?;
    let roots: BTreeSet<Word> = allowlist
        .allowed_script_roots()
        .iter()
        .map(|r| r.as_word())
        .collect();

    assert_eq!(
        roots.len(),
        10,
        "the built faucet's on-chain note-script allowlist must contain exactly 10 \
         roots; found {}",
        roots.len(),
    );
    assert!(
        !roots.contains(&forbidden_root()),
        "NetworkAccountConfigNote must stay absent on chain",
    );
    for (name, root) in required_fee_roots() {
        assert!(roots.contains(&root), "the built account must allow {name}",);
    }
    Ok(())
}
