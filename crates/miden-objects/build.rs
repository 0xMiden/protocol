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
        ".account.AccountId" => {
            target: ::miden_protocol::account::AccountId,
            try_constructor: crate::conversion::decode_account_id(
                id,
            ),
        },
        ".account.AccountHeader" => {
            target: ::miden_protocol::account::AccountHeader,
            validate: {
                version: crate::conversion::decode_account_version,
            },
            try_constructor: crate::conversion::decode_account_header(
                account_id,
                vault_root,
                storage_commitment,
                code_commitment,
                nonce,
            ),
        },
        ".account.AccountCode" => {
            target: ::miden_protocol::account::AccountCode,
            try_constructor: crate::conversion::decode_account_code(
                mast,
                procedure_roots,
            ),
        },
        ".account.AccountStorageHeader" => {
            target: ::miden_protocol::account::AccountStorageHeader,
            try_constructor: ::miden_protocol::account::AccountStorageHeader::new(
                slots,
            ),
        },
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
        ".account.PartialStorageMap" => {
            target: ::miden_protocol::account::PartialStorageMap,
            try_constructor: crate::conversion::decode_partial_storage_map(
                smt,
                keys,
            ),
        },
        ".account.PartialStorage" => {
            target: ::miden_protocol::account::PartialStorage,
            try_constructor: crate::conversion::decode_partial_storage(
                header,
                maps,
            ),
        },
        ".account.PartialVault" => {
            target: ::miden_protocol::asset::PartialVault,
            try_constructor: crate::conversion::decode_partial_vault(
                smt,
                asset_ids,
            ),
        },
        ".account.AccountVaultPatchEntry" => {
            target: (::miden_protocol::asset::AssetId, ::miden_protocol::Word),
            constructor: (asset_id, value),
        },
        ".account.AccountVaultPatch" => {
            target: ::miden_protocol::account::AccountVaultPatch,
            try_constructor: crate::conversion::decode_account_vault_patch(
                entries,
            ),
        },
        ".account.StorageSlotPatch" => {
            target: (
                ::miden_protocol::account::StorageSlotName,
                ::miden_protocol::account::StorageSlotPatch
            ),
            decode: {
                slot_name: crate::conversion::decode_storage_slot_name,
            },
            oneof: {
                patch: {
                    Value: constructor(::miden_protocol::account::StorageSlotPatch::Value),
                    Map: constructor(::miden_protocol::account::StorageSlotPatch::Map),
                },
            },
            constructor: (slot_name, patch),
        },
        ".account.AccountStoragePatch" => {
            target: ::miden_protocol::account::AccountStoragePatch,
            try_constructor: crate::conversion::decode_account_storage_patch(
                slots,
            ),
        },
        ".account.AccountPatch" => {
            target: ::miden_protocol::account::AccountPatch,
            validate: {
                version: crate::conversion::decode_account_patch_version,
            },
            try_constructor: ::miden_protocol::account::AccountPatch::new(
                account_id,
                storage,
                vault,
                code,
                final_nonce,
            ),
        },
        ".account.AccountUpdateDetails" => {
            target: ::miden_protocol::account::AccountUpdateDetails,
            oneof: {
                update: {
                    Private: constructor(crate::conversion::decode_private_account_update),
                    Public: constructor(
                        ::miden_protocol::account::AccountUpdateDetails::Public
                    ),
                },
            },
            constructor: update,
        },
        ".asset.AssetClass" => {
            target: ::miden_protocol::asset::AssetClass,
            constructor: ::miden_protocol::asset::AssetClass::new(
                suffix,
                prefix,
            ),
        },
        ".asset.Asset" => {
            target: ::miden_protocol::asset::Asset,
            try_constructor: ::miden_protocol::asset::Asset::new(
                asset_id,
                value,
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
        ".primitives.MmrDelta" => {
            target: ::miden_protocol::crypto::merkle::mmr::MmrDelta,
            try_constructor: crate::conversion::decode_mmr_delta(
                forest,
                update_data,
            ),
        },
        ".primitives.SmtOpening" => {
            target: ::miden_protocol::crypto::merkle::smt::SmtProof,
            try_constructor: ::miden_protocol::crypto::merkle::smt::SmtProof::new(
                path,
                leaf,
            ),
        },
        ".primitives.SmtLeafEntry" => {
            target: (::miden_protocol::Word, ::miden_protocol::Word),
            constructor: (key, value),
        },
        ".primitives.AdviceStack" => {
            target: ::miden_protocol::vm::AdviceStack,
            constructor: crate::conversion::decode_advice_stack(
                values,
            ),
        },
        ".primitives.AdviceMapEntry" => {
            target: (::miden_protocol::Word, ::alloc::vec::Vec<::miden_protocol::Felt>),
            constructor: (key, values),
        },
        ".primitives.AdviceMap" => {
            target: ::miden_protocol::vm::AdviceMap,
            try_constructor: crate::conversion::decode_advice_map(
                entries,
            ),
        },
        ".primitives.MerkleStore" => {
            target: ::miden_protocol::crypto::merkle::store::MerkleStore,
            try_constructor: crate::conversion::decode_merkle_store(
                nodes,
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
        ".note.NoteHeader" => {
            target: ::miden_protocol::note::NoteHeader,
            constructor: ::miden_protocol::note::NoteHeader::new(
                details_commitment,
                metadata,
            ),
        },
        ".note.NoteScript" => {
            target: ::miden_protocol::note::NoteScript,
            try_constructor: crate::conversion::decode_note_script(
                mast,
                entrypoint,
            ),
        },
        ".blockchain.BlockHeader" => {
            target: ::miden_protocol::block::BlockHeader,
            validate: {
                version: crate::conversion::decode_block_version,
            },
            constructor: crate::conversion::decode_block_header(
                block_num,
                prev_block_commitment,
                chain_commitment,
                account_root,
                nullifier_root,
                note_root,
                tx_commitment,
                validator_config,
                fee_parameters,
                protocol_config_commitment,
                next_protocol_config,
                timestamp,
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
        ".blockchain.BlockBody" => {
            target: ::miden_protocol::block::BlockBody,
            try_constructor: crate::conversion::decode_block_body(
                updated_accounts,
                output_note_batches,
                created_nullifiers,
                transactions,
            ),
        },
        ".blockchain.IndexedOutputNote" => {
            target: (usize, ::miden_protocol::transaction::OutputNote),
            constructor: (note_index_in_batch, note),
        },
        ".blockchain.OutputNoteBatch" => {
            target: ::miden_protocol::block::OutputNoteBatch,
            constructor: crate::conversion::decode_output_note_batch(
                notes,
            ),
        },
        ".blockchain.SignedBlock" => {
            target: ::miden_protocol::block::SignedBlock,
            try_constructor: crate::conversion::decode_signed_block(
                header,
                body,
                signatures,
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
        ".transaction.TransactionScript" => {
            target: ::miden_protocol::transaction::TransactionScript,
            try_constructor: crate::conversion::decode_transaction_script(
                mast,
                entrypoint,
            ),
        },
        ".transaction.InputNoteCommitment" => {
            target: ::miden_protocol::transaction::InputNoteCommitment,
            constructor: ::miden_protocol::transaction::InputNoteCommitment::from_parts_unchecked(
                nullifier,
                header,
            ),
        },
        ".transaction.ProvenTransaction" => {
            target: ::miden_protocol::transaction::ProvenTransaction,
            try_constructor: crate::conversion::decode_proven_transaction(
                account_update,
                input_notes,
                output_notes,
                reference_block_commitment,
                reference_block_num,
                expiration_block_num,
                proof,
            ),
        },
        ".transaction.TransactionHeader" => {
            target: ::miden_protocol::transaction::TransactionHeader,
            try_constructor: crate::conversion::decode_transaction_header(
                transaction_id,
                account_id,
                initial_state_commitment,
                final_state_commitment,
                input_notes,
                output_notes,
            ),
        },
        ".transaction.TransactionArgs" => {
            target: ::miden_protocol::transaction::TransactionArgs,
            try_constructor: crate::conversion::decode_transaction_args(
                tx_script,
                tx_script_args,
                note_args,
                advice_inputs,
                auth_args,
            ),
        },
        ".transaction.InputNote" => {
            target: ::miden_protocol::transaction::InputNote,
            oneof: {
                note: {
                    Authenticated: constructor(::core::convert::identity),
                    Unauthenticated: constructor(
                        ::miden_protocol::transaction::InputNote::unauthenticated
                    ),
                },
            },
            constructor: note,
        },
        ".transaction.InputNotes" => {
            target: ::miden_protocol::transaction::InputNotes<
                ::miden_protocol::transaction::InputNote
            >,
            try_constructor: crate::conversion::decode_input_notes(
                notes,
            ),
        },
        ".transaction.TransactionInputsV1" => {
            target: ::miden_protocol::transaction::TransactionInputs,
            try_constructor: crate::conversion::decode_transaction_inputs_v1(
                account,
                block_header,
                protocol_config,
                partial_blockchain,
                input_notes,
                tx_args,
                advice_inputs,
                foreign_account_code,
                foreign_account_slot_names,
            ),
        },
        ".transaction.TransactionInputs" => {
            target: ::miden_protocol::transaction::TransactionInputs,
            oneof: {
                version: {
                    V1: constructor(::core::convert::identity),
                },
            },
            constructor: version,
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
        ".transaction.OutputNote" => {
            target: ::miden_protocol::transaction::OutputNote,
            oneof: {
                note: {
                    Public: constructor(::miden_protocol::transaction::OutputNote::Public),
                    Private: constructor(::miden_protocol::transaction::OutputNote::Private),
                },
            },
            constructor: note,
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
