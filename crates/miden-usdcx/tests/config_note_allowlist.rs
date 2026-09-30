//! The faucet admits network configuration notes and requires ADMIN for every allowlist change.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::Word;
use miden_protocol::account::{
    AccountComponent,
    AccountProcedureRoot,
    StorageMapKey,
    StorageSlotContent,
    StorageSlotName,
};
use miden_protocol::note::{Note, NoteScriptRoot};
use miden_protocol::transaction::TransactionScriptRoot;
use miden_standards::account::auth::{AuthNetworkAccount, NetworkAccountNoteAllowlist};
use miden_standards::account::fees::FeePolicyManager;
use miden_standards::note::FeeSponsorshipNote;
use miden_standards::note::config::{
    ConstantFeePolicyConfigNote,
    NetworkAccountConfig,
    NetworkAccountConfigNote,
};
use miden_usdcx::account::xreserve::XReserveStablecoinBuilder;
use support::w2admin::*;
use support::*;

fn config_root() -> Word {
    NetworkAccountConfigNote::script_root().as_word()
}

fn required_fee_roots() -> [(&'static str, Word); 2] {
    [
        (
            "ConstantFeePolicyConfigNote",
            ConstantFeePolicyConfigNote::script_root().as_word(),
        ),
        ("FeeSponsorshipNote", FeeSponsorshipNote::script_root().as_word()),
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

/// The builder includes network-account configuration and both fee notes.
#[test]
fn builder_allowlist_includes_network_and_fee_configuration() {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    assert!(
        allowlist.iter().any(|root| root.as_word() == config_root()),
        "NetworkAccountConfigNote must be in the builder allowlist",
    );
    for (name, root) in required_fee_roots() {
        assert!(
            allowlist.iter().any(|candidate| candidate.as_word() == root),
            "the {name} script root must be present",
        );
    }
}

/// The auth component contains network-account configuration and both fee roots.
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
        12,
        "the auth component's note-script allowlist must contain exactly 12 roots; \
         found {}",
        note_keys.len(),
    );
    assert!(note_keys.contains(&config_root()), "NetworkAccountConfigNote must be present",);
    for (name, root) in required_fee_roots() {
        assert!(note_keys.contains(&root), "the auth component must allow {name}",);
    }
    Ok(())
}

/// The built faucet admits the configuration note, but only ADMIN can apply its six actions.
#[tokio::test]
async fn built_account_requires_admin_for_allowlist_changes() -> Result<()> {
    let root = Word::from([21u32, 22, 23, 24]);
    let actions = [
        (
            NetworkAccountConfig::AddAllowedNoteScript {
                script_root: NoteScriptRoot::from_raw(root),
            },
            AuthNetworkAccount::allowed_note_scripts_slot(),
            true,
        ),
        (
            NetworkAccountConfig::RemoveAllowedNoteScript {
                script_root: NoteScriptRoot::from_raw(root),
            },
            AuthNetworkAccount::allowed_note_scripts_slot(),
            false,
        ),
        (
            NetworkAccountConfig::AddAllowedTxScript {
                script_root: TransactionScriptRoot::from_raw(root),
            },
            AuthNetworkAccount::allowed_tx_scripts_slot(),
            true,
        ),
        (
            NetworkAccountConfig::RemoveAllowedTxScript {
                script_root: TransactionScriptRoot::from_raw(root),
            },
            AuthNetworkAccount::allowed_tx_scripts_slot(),
            false,
        ),
        (
            NetworkAccountConfig::AddAllowedFeePolicy {
                policy_root: AccountProcedureRoot::from_raw(root),
            },
            FeePolicyManager::allowed_fee_policies_slot(),
            true,
        ),
        (
            NetworkAccountConfig::RemoveAllowedFeePolicy {
                policy_root: AccountProcedureRoot::from_raw(root),
            },
            FeePolicyManager::allowed_fee_policies_slot(),
            false,
        ),
    ];
    let mut pf = setup_production_faucet(0, |_, faucet_id| {
        actions
            .iter()
            .flat_map(|(config, ..)| {
                [stranger(), pauser_holder(), admin_holder()].map(|sender| {
                    Note::from(
                        NetworkAccountConfigNote::builder()
                            .sender(sender)
                            .target(faucet_id)
                            .config(*config)
                            .serial_number(root)
                            .build()
                            .expect("configuration note"),
                    )
                })
            })
            .collect()
    })
    .context("building the production network-auth faucet")?;
    let account = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .context("the production faucet must be committed")?
        .clone();

    let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())
        .map_err(|e| anyhow::anyhow!("the faucet must carry the allowlist slot: {e}"))?;
    let roots: BTreeSet<Word> =
        allowlist.allowed_script_roots().iter().map(|r| r.as_word()).collect();

    assert_eq!(
        roots.len(),
        12,
        "the built faucet's on-chain note-script allowlist must contain exactly 12 \
         roots; found {}",
        roots.len(),
    );
    assert!(
        roots.contains(&config_root()),
        "NetworkAccountConfigNote must be present on chain",
    );
    for (name, root) in required_fee_roots() {
        assert!(roots.contains(&root), "the built account must allow {name}",);
    }
    let notes = pf.seeded_notes.clone();
    assert_eq!(notes.len(), actions.len() * 3);
    for ((_, slot, added), notes) in actions.iter().zip(notes.as_chunks::<3>().0) {
        let before = pf.mock_chain.committed_account(pf.faucet_id)?.to_commitment();
        for note in &notes[..2] {
            let result = consume(&pf, note).await;
            miden_testing::assert_transaction_executor_error!(result, err_sender_lacks_role());
            assert_eq!(pf.mock_chain.committed_account(pf.faucet_id)?.to_commitment(), before);
        }
        let account = consume_and_commit(&mut pf, &notes[2], "ADMIN allowlist change").await?;
        let value = account.storage().get_map_item(slot, StorageMapKey::new(root))?;
        assert_eq!(value, if *added { set_word() } else { Word::empty() });
    }
    Ok(())
}
