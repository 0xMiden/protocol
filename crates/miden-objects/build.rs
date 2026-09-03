use std::env;
use std::path::PathBuf;

use prost::Message;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=proto");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_dir = manifest_dir.join("proto");
    let files = [
        "primitives.proto",
        "block_number.proto",
        "account.proto",
        "asset.proto",
        "protocol_config.proto",
        "note.proto",
        "transaction.proto",
        "block.proto",
        "partial_blockchain.proto",
        "transaction_inputs.proto",
        "batch.proto",
    ];

    let mut compiler = protox::Compiler::new([&proto_dir])?;
    compiler.include_imports(true);
    compiler.open_files(files.iter().map(|file| proto_dir.join(file)))?;
    let descriptors = compiler.file_descriptor_set();

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    std::fs::write(out_dir.join("miden_objects_descriptor.bin"), descriptors.encode_to_vec())?;

    let mut prost = prost_build::Config::new();
    prost.out_dir(out_dir);
    miden_protobuf::configure_proto_decodes! {
        prost: &mut prost,
        descriptors: &descriptors,
        ".account.StorageSlotId" => {
            target: ::miden_protocol::account::StorageSlotId,
            constructor: ::miden_protocol::account::StorageSlotId::new(
                suffix,
                prefix,
            ),
        },
        ".primitives.MerklePath" => {
            target: ::miden_protocol::crypto::merkle::MerklePath,
            constructor: ::miden_protocol::crypto::merkle::MerklePath::new(
                siblings,
            ),
        },
        ".primitives.SparseMerklePath" => {
            target: ::miden_protocol::crypto::merkle::SparseMerklePath,
            try_constructor: ::miden_protocol::crypto::merkle::SparseMerklePath::from_parts(
                empty_nodes_mask,
                siblings,
            ),
        },
        ".protocol_config.KernelConfig" => {
            target: ::miden_protocol::protocol_config::KernelConfig,
            try_constructor: ::miden_protocol::protocol_config::KernelConfig::new(
                main_proc,
                kernel_procs,
            ),
        },
        ".protocol_config.ProofSecurityPolicy" => {
            target: ::miden_protocol::protocol_config::ProofSecurityPolicy,
            try_constructor: ::miden_protocol::protocol_config::ProofSecurityPolicy::new(
                security_estimator_root,
                minimum_bits,
            ),
        },
        ".protocol_config.ProofVerificationConfig" => {
            target: ::miden_protocol::protocol_config::ProofVerificationConfig,
            constructor: ::miden_protocol::protocol_config::ProofVerificationConfig::new(
                vm_verifier_root,
                precompile_verifier_root,
                security_policy,
            ),
        },
        ".protocol_config.ProtocolConfig" => {
            target: ::miden_protocol::protocol_config::ProtocolConfig,
            try_constructor: ::miden_protocol::protocol_config::ProtocolConfig::new(
                fee_asset_id,
                tx_kernel,
                batch_kernel,
                block_kernel,
                proof_verification,
            ),
        },
    }?;
    prost.compile_fds(descriptors)?;
    Ok(())
}
