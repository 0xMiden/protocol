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
        ".account.AccountWitness" => {
            target: ::miden_protocol::block::account_tree::AccountWitness,
            try_constructor: ::miden_protocol::block::account_tree::AccountWitness::new(
                witness_id,
                commitment,
                path,
            ),
        },
        ".account.PartialAccount" => {
            target: ::miden_protocol::account::PartialAccount,
            try_constructor: ::miden_protocol::account::PartialAccount::new(
                account_id,
                nonce,
                code,
                storage,
                vault,
                seed,
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
        ".primitives.SmtOpening" => {
            target: ::miden_protocol::crypto::merkle::smt::SmtProof,
            try_constructor: ::miden_protocol::crypto::merkle::smt::SmtProof::new(
                path,
                leaf,
            ),
        },
        ".primitives.AdviceInputs" => {
            target: ::miden_protocol::vm::AdviceInputs,
            constructor: ::miden_protocol::vm::AdviceInputs::new(
                advice_stack,
                advice_map,
                merkle_store,
            ),
        },
        ".note.NoteRecipient" => {
            target: ::miden_protocol::note::NoteRecipient,
            constructor: ::miden_protocol::note::NoteRecipient::new(
                serial_num,
                script,
                storage,
            ),
        },
        ".note.NoteDetails" => {
            target: ::miden_protocol::note::NoteDetails,
            constructor: ::miden_protocol::note::NoteDetails::new(
                assets,
                recipient,
            ),
        },
        ".note.NoteStorage" => {
            target: ::miden_protocol::note::NoteStorage,
            try_constructor: crate::conversion::decode_note_storage(
                items,
            ),
        },
        ".note.NoteAttachment" => {
            target: ::miden_protocol::note::NoteAttachment,
            try_constructor: crate::conversion::decode_note_attachment(
                scheme,
                words,
            ),
        },
        ".note.NoteAttachments" => {
            target: ::miden_protocol::note::NoteAttachments,
            try_constructor: crate::conversion::validate_note_attachments(
                attachments,
            ),
        },
        ".blockchain.BlockAccountUpdate" => {
            target: ::miden_protocol::block::BlockAccountUpdate,
            try_constructor: ::miden_protocol::block::BlockAccountUpdate::new(
                account_id,
                final_state_commitment,
                details,
            ),
        },
        ".blockchain.NextProtocolConfig" => {
            target: ::miden_protocol::protocol_config::NextProtocolConfig,
            try_constructor: ::miden_protocol::protocol_config::NextProtocolConfig::new(
                effective_from,
                protocol_config,
            ),
        },
        ".blockchain.ValidatorConfig" => {
            target: ::miden_protocol::block::ValidatorConfig,
            try_constructor: ::miden_protocol::block::ValidatorConfig::new(
                keys,
                quorum,
            ),
        },
        ".transaction.BatchAccountUpdate" => {
            target: ::miden_protocol::batch::BatchAccountUpdate,
            try_constructor: ::miden_protocol::batch::BatchAccountUpdate::new(
                account_id,
                initial_state_commitment,
                final_state_commitment,
                details,
            ),
        },
        ".transaction.TxAccountUpdate" => {
            target: ::miden_protocol::transaction::TxAccountUpdate,
            try_constructor: ::miden_protocol::transaction::TxAccountUpdate::new(
                account_id,
                initial_state_commitment,
                final_state_commitment,
                account_patch_commitment,
                details,
            ),
        },
        ".transaction.PublicOutputNote" => {
            target: ::miden_protocol::transaction::PublicOutputNote,
            try_constructor: ::miden_protocol::transaction::PublicOutputNote::new(
                note,
            ),
        },
        ".transaction.PrivateOutputNote" => {
            target: ::miden_protocol::transaction::PrivateOutputNote,
            try_constructor: ::miden_protocol::transaction::PrivateOutputNote::new(
                header,
                attachments,
            ),
        },
        ".transaction.TransactionId" => {
            target: ::miden_protocol::transaction::TransactionId,
            constructor: ::miden_protocol::transaction::TransactionId::from_raw(
                id,
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
