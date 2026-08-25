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

// Compares the collected roots and fails if any of them changed or disappeared.
//
// Procedures that only exist in the current version are reported but do not fail the check: a new
// procedure moves no existing root, so backporting one is safe. Additions to artifacts that commit
// to their whole procedure set (the transaction kernel and the account components) are still
// caught, since they move the corresponding commitment.
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
            (None, Some(current_root)) => {
                eprintln!("::warning::procedure added: {name} (root {current_root})");
            },
            (None, None) => unreachable!("name came from at least one side"),
        }
    }

    status
}

mod current {
    use miden_agglayer_current::{AggLayerBridge, agglayer_package, bridge, faucet};
    use miden_protocol_current::account::AccountComponentCode;
    use miden_protocol_current::account::component::AUTH_SCRIPT_ATTRIBUTE;
    use miden_protocol_current::transaction::TransactionKernel;
    use miden_protocol_current::vm::Package;
    use miden_protocol_current::{Felt, Hasher, ProtocolLib};
    use miden_standards_current::StandardsLib;
    use miden_standards_current::account::access::{
        Authority,
        Ownable2Step,
        Pausable,
        PausableManager,
        RoleBasedAccessControl,
    };
    use miden_standards_current::account::auth::{
        AuthGuardedMultisig,
        AuthMultisig,
        AuthMultisigSmart,
        AuthNetworkAccount,
        AuthSingleSig,
        NoAuth,
    };
    use miden_standards_current::account::faucets::{FungibleFaucet, NonFungibleFaucet};
    use miden_standards_current::account::fees::{BasicConstantFeePolicy, ConstantFeeManager};
    use miden_standards_current::account::inspection::{AccountSchemaCommitment, CodeInspection};
    use miden_standards_current::account::policies::{
        AllowlistManager,
        BasicAllowlist,
        BasicBlocklist,
        BlocklistManager,
        BurnAllowAll,
        BurnOwnerOnly,
        MinBurnAmount,
        MintAllowAll,
        MintOwnerOnly,
        TokenPolicyManager,
        TransferAllowAll,
    };
    use miden_standards_current::account::upgrade::UpgradeManager;
    use miden_standards_current::account::pass_through::PassThrough;
    use miden_standards_current::account::wallets::{BasicWallet, NoteCreator};

    use super::*;

    // Every installable account component.
    const COMPONENT_CODE: &[fn() -> &'static AccountComponentCode] = &[
        Authority::code,
        Ownable2Step::code,
        Pausable::code,
        PausableManager::code,
        RoleBasedAccessControl::code,
        NoAuth::code,
        AuthSingleSig::code,
        AuthMultisig::code,
        AuthMultisigSmart::code,
        AuthGuardedMultisig::code,
        AuthNetworkAccount::code,
        BurnAllowAll::code,
        BurnOwnerOnly::code,
        MinBurnAmount::code,
        MintAllowAll::code,
        MintOwnerOnly::code,
        TransferAllowAll::code,
        AllowlistManager::code,
        BasicAllowlist::code,
        BasicBlocklist::code,
        BlocklistManager::code,
        TokenPolicyManager::code,
        BasicConstantFeePolicy::code,
        ConstantFeeManager::code,
        FungibleFaucet::code,
        NonFungibleFaucet::code,
        BasicWallet::code,
        NoteCreator::code,
        PassThrough::code,
        CodeInspection::code,
        AccountSchemaCommitment::code,
        UpgradeManager::code,
        AggLayerBridge::code,
    ];

    pub fn collect_roots() -> Roots {
        let mut roots = Roots::new();

        collect_package(ProtocolLib::default().as_ref(), &mut roots);

        // The transaction kernel is compiled into its own artifact so its roots are collected
        // separately.
        collect_package(&TransactionKernel::package(), &mut roots);

        // Collect the kernel commitment since the order of the kernel procedure roots it
        // hashes is not covered by the package.
        roots.insert(
            "transaction_kernel::TX_KERNEL_COMMITMENT".to_string(),
            TransactionKernel.to_commitment().to_hex(),
        );

        // Collect the kernel programs since they include the prologue and epilogue that are not
        // covered by the kernel package exports.
        roots.insert(
            "transaction_kernel::MAIN_PROGRAM_ROOT".to_string(),
            TransactionKernel::main().hash().to_hex(),
        );
        roots.insert(
            "transaction_kernel::TX_SCRIPT_MAIN_PROGRAM_ROOT".to_string(),
            TransactionKernel::tx_script_main().hash().to_hex(),
        );

        // The standards and agglayer note scripts are exports of these packages, so walking them
        // covers the note script roots too.
        collect_package(StandardsLib::default().as_ref(), &mut roots);

        collect_package(&agglayer_package(), &mut roots);

        // Collect the agglayer account code commitments since they are not covered by the
        // package exports.
        roots.insert(
            "agglayer::BRIDGE_CODE_COMMITMENT".to_string(),
            bridge::BRIDGE_CODE_COMMITMENT.to_hex(),
        );
        roots.insert(
            "agglayer::FAUCET_CODE_COMMITMENT".to_string(),
            faucet::FAUCET_CODE_COMMITMENT.to_hex(),
        );

        for code in COMPONENT_CODE {
            collect_component(code(), &mut roots);
        }

        roots
    }

    fn collect_package(package: &Package, roots: &mut Roots) {
        for module in package.module_infos() {
            for (_, procedure) in module.procedures() {
                roots.insert(
                    format!("{}::{}", module.path(), procedure.name),
                    procedure.digest.to_hex(),
                );
            }
        }
    }

    // Collects the component's procedure roots plus a commitment over its procedure set as a whole,
    // keyed by the path of the component's module.
    fn collect_component(code: &AccountComponentCode, roots: &mut Roots) {
        collect_package(code.as_package(), roots);

        let mut elements = Vec::new();
        // Both iterators walk the component's exports, so they are in the same order.
        for (root, export) in code.procedure_roots().zip(code.exports()) {
            elements.extend_from_slice(root.as_elements());
            // Add whether the export is an auth script since changing that would result in a
            // different account code commitment even if all individual roots are the same.
            elements.push(Felt::from(export.attributes.has(AUTH_SCRIPT_ATTRIBUTE) as u8));
        }
        let commitment = Hasher::hash_elements(&elements).to_hex();

        for module in code.as_package().module_infos() {
            roots.insert(format!("{}::CODE_COMMITMENT", module.path()), commitment.clone());
        }
    }
}

mod previous {
    use miden_agglayer_previous::{AggLayerBridge, agglayer_package, bridge, faucet};
    use miden_protocol_previous::account::AccountComponentCode;
    use miden_protocol_previous::account::component::AUTH_SCRIPT_ATTRIBUTE;
    use miden_protocol_previous::transaction::TransactionKernel;
    use miden_protocol_previous::vm::Package;
    use miden_protocol_previous::{Felt, Hasher, ProtocolLib};
    use miden_standards_previous::StandardsLib;
    use miden_standards_previous::account::access::{
        Authority,
        Ownable2Step,
        Pausable,
        PausableManager,
        RoleBasedAccessControl,
    };
    use miden_standards_previous::account::auth::{
        AuthGuardedMultisig,
        AuthMultisig,
        AuthMultisigSmart,
        AuthNetworkAccount,
        AuthSingleSig,
        NoAuth,
    };
    use miden_standards_previous::account::faucets::{FungibleFaucet, NonFungibleFaucet};
    use miden_standards_previous::account::fees::{BasicConstantFeePolicy, ConstantFeeManager};
    use miden_standards_previous::account::inspection::{AccountSchemaCommitment, CodeInspection};
    use miden_standards_previous::account::policies::{
        AllowlistManager,
        BasicAllowlist,
        BasicBlocklist,
        BlocklistManager,
        BurnAllowAll,
        BurnOwnerOnly,
        MinBurnAmount,
        MintAllowAll,
        MintOwnerOnly,
        TokenPolicyManager,
        TransferAllowAll,
    };
    use miden_standards_previous::account::upgrade::UpgradeManager;
    use miden_standards_previous::account::wallets::{BasicWallet, NoteCreator};

    use super::*;

    // Every installable account component.
    const COMPONENT_CODE: &[fn() -> &'static AccountComponentCode] = &[
        Authority::code,
        Ownable2Step::code,
        Pausable::code,
        PausableManager::code,
        RoleBasedAccessControl::code,
        NoAuth::code,
        AuthSingleSig::code,
        AuthMultisig::code,
        AuthMultisigSmart::code,
        AuthGuardedMultisig::code,
        AuthNetworkAccount::code,
        BurnAllowAll::code,
        BurnOwnerOnly::code,
        MinBurnAmount::code,
        MintAllowAll::code,
        MintOwnerOnly::code,
        TransferAllowAll::code,
        AllowlistManager::code,
        BasicAllowlist::code,
        BasicBlocklist::code,
        BlocklistManager::code,
        TokenPolicyManager::code,
        BasicConstantFeePolicy::code,
        ConstantFeeManager::code,
        FungibleFaucet::code,
        NonFungibleFaucet::code,
        BasicWallet::code,
        NoteCreator::code,
        CodeInspection::code,
        AccountSchemaCommitment::code,
        UpgradeManager::code,
        AggLayerBridge::code,
    ];

    pub fn collect_roots() -> Roots {
        let mut roots = Roots::new();

        collect_package(ProtocolLib::default().as_ref(), &mut roots);

        // The transaction kernel is compiled into its own artifact so its roots are collected
        // separately.
        collect_package(&TransactionKernel::package(), &mut roots);

        // Collect the kernel commitment since the order of the kernel procedure roots it
        // hashes is not covered by the package.
        roots.insert(
            "transaction_kernel::TX_KERNEL_COMMITMENT".to_string(),
            TransactionKernel.to_commitment().to_hex(),
        );

        // Collect the kernel programs since they include the prologue and epilogue that are not
        // covered by the kernel package exports.
        roots.insert(
            "transaction_kernel::MAIN_PROGRAM_ROOT".to_string(),
            TransactionKernel::main().hash().to_hex(),
        );
        roots.insert(
            "transaction_kernel::TX_SCRIPT_MAIN_PROGRAM_ROOT".to_string(),
            TransactionKernel::tx_script_main().hash().to_hex(),
        );

        // The standards and agglayer note scripts are exports of these packages, so walking them
        // covers the note script roots too.
        collect_package(StandardsLib::default().as_ref(), &mut roots);

        collect_package(&agglayer_package(), &mut roots);

        // Collect the agglayer account code commitments since they are not covered by the
        // package exports.
        roots.insert(
            "agglayer::BRIDGE_CODE_COMMITMENT".to_string(),
            bridge::BRIDGE_CODE_COMMITMENT.to_hex(),
        );
        roots.insert(
            "agglayer::FAUCET_CODE_COMMITMENT".to_string(),
            faucet::FAUCET_CODE_COMMITMENT.to_hex(),
        );

        for code in COMPONENT_CODE {
            collect_component(code(), &mut roots);
        }

        roots
    }

    fn collect_package(package: &Package, roots: &mut Roots) {
        for module in package.module_infos() {
            for (_, procedure) in module.procedures() {
                roots.insert(
                    format!("{}::{}", module.path(), procedure.name),
                    procedure.digest.to_hex(),
                );
            }
        }
    }

    // Collects the component's procedure roots plus a commitment over its procedure set as a whole,
    // keyed by the path of the component's module.
    fn collect_component(code: &AccountComponentCode, roots: &mut Roots) {
        collect_package(code.as_package(), roots);

        let mut elements = Vec::new();
        // Both iterators walk the component's exports, so they are in the same order.
        for (root, export) in code.procedure_roots().zip(code.exports()) {
            elements.extend_from_slice(root.as_elements());
            // Add whether the export is an auth script since changing that would result in a
            // different account code commitment even if all individual roots are the same.
            elements.push(Felt::from(export.attributes.has(AUTH_SCRIPT_ATTRIBUTE) as u8));
        }
        let commitment = Hasher::hash_elements(&elements).to_hex();

        for module in code.as_package().module_infos() {
            roots.insert(format!("{}::CODE_COMMITMENT", module.path()), commitment.clone());
        }
    }
}
