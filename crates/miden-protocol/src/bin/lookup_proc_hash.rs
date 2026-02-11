use miden_core::field::PrimeField64;
use miden_core::mast::MastNodeExt;
use miden_protocol::{CoreLibrary, ProtocolLib, Word};
use miden_protocol::transaction::TransactionKernel;

fn matches(word: &Word, target: [u64; 4], target_rev: [u64; 4]) -> bool {
    let elems: [u64; 4] = word.map(|felt| felt.as_canonical_u64());
    elems == target || elems == target_rev
}

fn main() {
    let target: [u64; 4] = [
        1247505852200688489,
        2630944015656778766,
        3701814040622573770,
        1573442245793545208,
    ];
    let target_rev: [u64; 4] = [target[3], target[2], target[1], target[0]];

    let mut found = false;

    let kernel_lib = TransactionKernel::kernel();
    let kernel = kernel_lib.as_ref();
    let kernel_export_map = kernel
        .exports()
        .filter_map(|export| export.as_procedure())
        .map(|proc_export| (proc_export.node, proc_export.path.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    for (idx, node) in kernel.mast_forest().nodes().iter().enumerate() {
        let digest = node.digest();
        if matches(&digest, target, target_rev) {
            let node_id = miden_core::mast::MastNodeId::from(idx as u32);
            if let Some(path) = kernel_export_map.get(&node_id) {
                println!("kernel node match: {} (export)", path);
            } else {
                println!("kernel node match: node_id={}", idx);
            }
            found = true;
        }
    }

    let kernel_main = TransactionKernel::main();
    for (idx, node) in kernel_main.mast_forest().nodes().iter().enumerate() {
        let digest = node.digest();
        if matches(&digest, target, target_rev) {
            println!("kernel main node match: node_id={}", idx);
            found = true;
        }
    }

    let tx_script_main = TransactionKernel::tx_script_main();
    for (idx, node) in tx_script_main.mast_forest().nodes().iter().enumerate() {
        let digest = node.digest();
        if matches(&digest, target, target_rev) {
            println!("tx script main node match: node_id={}", idx);
            found = true;
        }
    }

    let core_lib = CoreLibrary::default();
    let core = core_lib.library();
    let core_export_map = core
        .exports()
        .filter_map(|export| export.as_procedure())
        .map(|proc_export| (proc_export.node, proc_export.path.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    for (idx, node) in core.mast_forest().nodes().iter().enumerate() {
        let digest = node.digest();
        if matches(&digest, target, target_rev) {
            let node_id = miden_core::mast::MastNodeId::from(idx as u32);
            if let Some(path) = core_export_map.get(&node_id) {
                println!("core node match: {} (export)", path);
            } else {
                println!("core node match: node_id={}", idx);
            }
            found = true;
        }
    }

    let protocol_lib = ProtocolLib::default();
    let protocol = protocol_lib.as_ref();
    let protocol_export_map = protocol
        .exports()
        .filter_map(|export| export.as_procedure())
        .map(|proc_export| (proc_export.node, proc_export.path.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    for (idx, node) in protocol.mast_forest().nodes().iter().enumerate() {
        let digest = node.digest();
        if matches(&digest, target, target_rev) {
            let node_id = miden_core::mast::MastNodeId::from(idx as u32);
            if let Some(path) = protocol_export_map.get(&node_id) {
                println!("protocol node match: {} (export)", path);
            } else {
                println!("protocol node match: node_id={}", idx);
            }
            found = true;
        }
    }

    if !found {
        println!("no matching export found");
    }
}
