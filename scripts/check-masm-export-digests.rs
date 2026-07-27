#!/usr/bin/env -S cargo +nightly -Zscript
---cargo
[package]
edition = "2024"

[dependencies]
miden-agglayer-current = { package = "miden-agglayer", path = "../crates/miden-agglayer" }
miden-protocol-current = { package = "miden-protocol", path = "../crates/miden-protocol" }
miden-standards-current = { package = "miden-standards", path = "../crates/miden-standards" }

# The tags below are placeholders: check-masm-root-stability.sh rewrites them to the latest release
# tag. This script should not be run standalone.
miden-agglayer-previous = { package = "miden-agglayer", git = "https://github.com/0xMiden/protocol", tag = "v0.0.0" }
miden-protocol-previous = { package = "miden-protocol", git = "https://github.com/0xMiden/protocol", tag = "v0.0.0" }
miden-standards-previous = { package = "miden-standards", git = "https://github.com/0xMiden/protocol", tag = "v0.0.0" }
---

use std::collections::{BTreeMap, BTreeSet};
use std::process;

// Maps the fully-qualified path of an exported procedure to its MAST root (hex digest).
type Roots = BTreeMap<String, String>;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let previous = previous::collect_roots();
    let current = current::collect_roots();
    compare_roots(previous, current)
}

fn compare_roots(previous: Roots, current: Roots) -> Result<(), String> {
    let mut status = Ok(());
    let names = previous.keys().chain(current.keys()).cloned().collect::<BTreeSet<_>>();

    for name in names {
        match (previous.get(&name), current.get(&name)) {
            (Some(previous_root), Some(current_root)) if previous_root == current_root => {
                println!("{name} {current_root}");
            },
            (Some(previous_root), Some(current_root)) => {
                eprintln!(
                    "::error::procedure root changed for {name}: previous={previous_root}, current={current_root}"
                );
                status = Err("procedure roots changed".to_string());
            },
            (Some(previous_root), None) => {
                eprintln!("::error::procedure removed: {name} (previous root {previous_root})");
                status = Err("procedure roots changed".to_string());
            },
            (None, Some(_)) => {
                eprintln!("::error::procedure added: {name}");
                status = Err("procedure roots changed".to_string());
            },
            (None, None) => unreachable!("name came from at least one side"),
        }
    }

    status
}

mod current {
    use miden_agglayer_current::{
        B2AggNote, ClaimNote, ConfigAggBridgeNote, UpdateGerNote, agglayer_library, bridge, faucet,
    };
    use miden_protocol_current::ProtocolLib;
    use miden_protocol_current::account::component::StorageSchema;
    use miden_protocol_current::account::{AccountComponent, AccountComponentCode};
    use miden_protocol_current::assembly::Library;
    use miden_protocol_current::note::NoteScriptRoot;
    use miden_protocol_current::transaction::TransactionKernel;
    use miden_standards_current::StandardsLib;
    use miden_standards_current::account::access::{
        Authority, Ownable2Step, Pausable, PausableManager, RoleBasedAccessControl,
    };
    use miden_standards_current::account::auth::{
        AuthGuardedMultisig, AuthMultisig, AuthMultisigSmart, AuthNetworkAccount, AuthSingleSig,
        AuthSingleSigAcl, NoAuth,
    };
    use miden_standards_current::account::faucets::FungibleFaucet;
    use miden_standards_current::account::metadata::AccountSchemaCommitment;
    use miden_standards_current::account::policies::{
        AllowlistOwnerControlled, BasicAllowlist, BasicBlocklist, BlocklistOwnerControlled,
        BurnAllowAll, BurnOwnerOnly, MintAllowAll, MintOwnerOnly, TokenPolicyManager,
        TransferAllowAll,
    };
    use miden_standards_current::account::wallets::BasicWallet;

    use super::*;

    // Every installable standard account component that exposes a `code()` accessor. The
    // `schema_commitment` component is collected separately since it has no such accessor.
    const COMPONENT_CODE: &[fn() -> &'static AccountComponentCode] = &[
        Authority::code,
        Ownable2Step::code,
        Pausable::code,
        PausableManager::code,
        RoleBasedAccessControl::code,
        NoAuth::code,
        AuthSingleSig::code,
        AuthSingleSigAcl::code,
        AuthMultisig::code,
        AuthMultisigSmart::code,
        AuthGuardedMultisig::code,
        AuthNetworkAccount::code,
        BurnAllowAll::code,
        BurnOwnerOnly::code,
        MintAllowAll::code,
        MintOwnerOnly::code,
        TransferAllowAll::code,
        AllowlistOwnerControlled::code,
        BasicAllowlist::code,
        BasicBlocklist::code,
        BlocklistOwnerControlled::code,
        TokenPolicyManager::code,
        FungibleFaucet::code,
        BasicWallet::code,
    ];

    // The agglayer note scripts are compiled into standalone artifacts, so no library root covers
    // them. They need to be checked separately.
    //
    // TODO: this can be removed once the agglayer note scripts get added to the agglayer lib.
    const AGGLAYER_NOTE_SCRIPT_ROOTS: &[(&str, fn() -> NoteScriptRoot)] = &[
        ("agglayer::note_scripts::b2agg", B2AggNote::script_root),
        ("agglayer::note_scripts::claim", ClaimNote::script_root),
        ("agglayer::note_scripts::config_agg_bridge", ConfigAggBridgeNote::script_root),
        ("agglayer::note_scripts::update_ger", UpdateGerNote::script_root),
    ];

    pub fn collect_roots() -> Roots {
        let mut roots = Roots::new();

        collect_library(ProtocolLib::default().as_ref(), &mut roots);

        // The transaction kernel is compiled into its own artifact so its roots are collected
        // separately.
        collect_library(TransactionKernel::kernel().as_ref(), &mut roots);

        // Also collect the kernel commitment since the order of the kernel procedure roots it
        // hashes is not covered by the library.
        roots.insert(
            "transaction_kernel::TX_KERNEL_COMMITMENT".to_string(),
            TransactionKernel.to_commitment().to_hex(),
        );

        collect_library(StandardsLib::default().as_ref(), &mut roots);

        collect_library(&agglayer_library(), &mut roots);

        // Also collect the agglayer account code commitments since they are not covered by the
        // library root.
        roots.insert(
            "agglayer::BRIDGE_CODE_COMMITMENT".to_string(),
            bridge::BRIDGE_CODE_COMMITMENT.to_hex(),
        );
        roots.insert(
            "agglayer::FAUCET_CODE_COMMITMENT".to_string(),
            faucet::FAUCET_CODE_COMMITMENT.to_hex(),
        );

        for code in COMPONENT_CODE {
            collect_library(code().as_ref(), &mut roots);
        }

        // The `schema_commitment` component only re-exports a `StandardsLib` procedure, but which
        // procedure it re-exports can itself change, and that would show up in none of the roots
        // collected above.
        let schema_commitment = AccountComponent::from(
            // The schemas set the component's storage value, not its code, so any list works.
            AccountSchemaCommitment::new(core::iter::empty::<&StorageSchema>())
                .expect("an empty list of storage schemas has no conflicting definitions"),
        );
        collect_library(schema_commitment.component_code().as_ref(), &mut roots);

        for (name, script_root) in AGGLAYER_NOTE_SCRIPT_ROOTS {
            roots.insert((*name).to_string(), script_root().as_word().to_hex());
        }

        roots
    }

    fn collect_library(library: &Library, roots: &mut Roots) {
        for module in library.module_infos() {
            for (_, procedure) in module.procedures() {
                roots.insert(
                    format!("{}::{}", module.path(), procedure.name),
                    procedure.digest.to_hex(),
                );
            }
        }
    }
}

mod previous {
    use miden_agglayer_previous::{
        B2AggNote, ClaimNote, ConfigAggBridgeNote, UpdateGerNote, agglayer_library, bridge, faucet,
    };
    use miden_protocol_previous::ProtocolLib;
    use miden_protocol_previous::account::component::StorageSchema;
    use miden_protocol_previous::account::{AccountComponent, AccountComponentCode};
    use miden_protocol_previous::assembly::Library;
    use miden_protocol_previous::note::NoteScriptRoot;
    use miden_protocol_previous::transaction::TransactionKernel;
    use miden_standards_previous::StandardsLib;
    use miden_standards_previous::account::access::{
        Authority, Ownable2Step, Pausable, PausableManager, RoleBasedAccessControl,
    };
    use miden_standards_previous::account::auth::{
        AuthGuardedMultisig, AuthMultisig, AuthMultisigSmart, AuthNetworkAccount, AuthSingleSig,
        AuthSingleSigAcl, NoAuth,
    };
    use miden_standards_previous::account::faucets::FungibleFaucet;
    use miden_standards_previous::account::metadata::AccountSchemaCommitment;
    use miden_standards_previous::account::policies::{
        AllowlistOwnerControlled, BasicAllowlist, BasicBlocklist, BlocklistOwnerControlled,
        BurnAllowAll, BurnOwnerOnly, MintAllowAll, MintOwnerOnly, TokenPolicyManager,
        TransferAllowAll,
    };
    use miden_standards_previous::account::wallets::BasicWallet;

    use super::*;

    // Every installable standard account component that exposes a `code()` accessor. The
    // `schema_commitment` component is collected separately since it has no such accessor.
    const COMPONENT_CODE: &[fn() -> &'static AccountComponentCode] = &[
        Authority::code,
        Ownable2Step::code,
        Pausable::code,
        PausableManager::code,
        RoleBasedAccessControl::code,
        NoAuth::code,
        AuthSingleSig::code,
        AuthSingleSigAcl::code,
        AuthMultisig::code,
        AuthMultisigSmart::code,
        AuthGuardedMultisig::code,
        AuthNetworkAccount::code,
        BurnAllowAll::code,
        BurnOwnerOnly::code,
        MintAllowAll::code,
        MintOwnerOnly::code,
        TransferAllowAll::code,
        AllowlistOwnerControlled::code,
        BasicAllowlist::code,
        BasicBlocklist::code,
        BlocklistOwnerControlled::code,
        TokenPolicyManager::code,
        FungibleFaucet::code,
        BasicWallet::code,
    ];

    // The agglayer note scripts are compiled into standalone artifacts, so no library root covers
    // them. They need to be checked separately.
    //
    // TODO: this can be removed once the agglayer note scripts get added to the agglayer lib.
    const AGGLAYER_NOTE_SCRIPT_ROOTS: &[(&str, fn() -> NoteScriptRoot)] = &[
        ("agglayer::note_scripts::b2agg", B2AggNote::script_root),
        ("agglayer::note_scripts::claim", ClaimNote::script_root),
        ("agglayer::note_scripts::config_agg_bridge", ConfigAggBridgeNote::script_root),
        ("agglayer::note_scripts::update_ger", UpdateGerNote::script_root),
    ];

    pub fn collect_roots() -> Roots {
        let mut roots = Roots::new();

        collect_library(ProtocolLib::default().as_ref(), &mut roots);

        // The transaction kernel is compiled into its own artifact so its roots are collected
        // separately.
        collect_library(TransactionKernel::kernel().as_ref(), &mut roots);

        // Also collect the kernel commitment since the order of the kernel procedure roots it
        // hashes is not covered by the library.
        roots.insert(
            "transaction_kernel::TX_KERNEL_COMMITMENT".to_string(),
            TransactionKernel.to_commitment().to_hex(),
        );

        collect_library(StandardsLib::default().as_ref(), &mut roots);

        collect_library(&agglayer_library(), &mut roots);

        // Also collect the agglayer account code commitments since they are not covered by the
        // library root.
        roots.insert(
            "agglayer::BRIDGE_CODE_COMMITMENT".to_string(),
            bridge::BRIDGE_CODE_COMMITMENT.to_hex(),
        );
        roots.insert(
            "agglayer::FAUCET_CODE_COMMITMENT".to_string(),
            faucet::FAUCET_CODE_COMMITMENT.to_hex(),
        );

        for code in COMPONENT_CODE {
            collect_library(code().as_ref(), &mut roots);
        }

        // The `schema_commitment` component only re-exports a `StandardsLib` procedure, but which
        // procedure it re-exports can itself change, and that would show up in none of the roots
        // collected above.
        let schema_commitment = AccountComponent::from(
            // The schemas set the component's storage value, not its code, so any list works.
            AccountSchemaCommitment::new(core::iter::empty::<&StorageSchema>())
                .expect("an empty list of storage schemas has no conflicting definitions"),
        );
        collect_library(schema_commitment.component_code().as_ref(), &mut roots);

        for (name, script_root) in AGGLAYER_NOTE_SCRIPT_ROOTS {
            roots.insert((*name).to_string(), script_root().as_word().to_hex());
        }

        roots
    }

    fn collect_library(library: &Library, roots: &mut Roots) {
        for module in library.module_infos() {
            for (_, procedure) in module.procedures() {
                roots.insert(
                    format!("{}::{}", module.path(), procedure.name),
                    procedure.digest.to_hex(),
                );
            }
        }
    }
}
