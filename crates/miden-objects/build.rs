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
        ".primitives.Felt" => {
            target: ::miden_protocol::Felt,
            constructor: value,
        },
        ".primitives.Word" => {
            target: ::miden_protocol::Word,
            decode: {
                encoded: crate::conversion::decode_word,
            },
            constructor: encoded,
        },
        ".primitives.ExecutionProof" => {
            target: ::miden_protocol::vm::ExecutionProof,
            decode: {
                encoded: crate::conversion::decode_execution_proof,
            },
            constructor: encoded,
        },
        ".primitives.MastForest" => {
            target: ::miden_protocol::MastForest,
            decode: {
                encoded: crate::conversion::decode_mast_forest,
            },
            constructor: encoded,
        },
        ".account.AccountId" => {
            target: ::miden_protocol::account::AccountId,
            try_constructor: crate::conversion::decode_account_id(
                id,
            ),
        },
        ".account.AccountHeader" => {
            target: ::miden_protocol::account::AccountHeader,
            enumeration: {
                version: {
                    Unspecified: reject("account header version is unspecified"),
                    V1: accept,
                },
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
        ".account.AccountStorageHeader.StorageSlot" => {
            target: ::miden_protocol::account::StorageSlotHeader,
            decode: {
                slot_name: crate::conversion::decode_storage_slot_name,
            },
            enumeration: {
                slot_type: {
                    Unspecified: reject("storage slot type is unspecified"),
                    Value: map(::miden_protocol::account::StorageSlotType::Value),
                    Map: map(::miden_protocol::account::StorageSlotType::Map),
                },
            },
            constructor: ::miden_protocol::account::StorageSlotHeader::new(
                slot_name,
                slot_type,
                commitment,
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
        ".account.StorageValuePatch" => {
            target: ::miden_protocol::account::StorageValuePatch,
            oneof: {
                patch: {
                    Create: constructor(crate::conversion::decode_storage_value_patch_create),
                    Update: constructor(crate::conversion::decode_storage_value_patch_update),
                    Remove: constant(::miden_protocol::account::StorageValuePatch::Remove),
                },
            },
            constructor: patch,
        },
        ".account.StorageMapEntry" => {
            target: (
                ::miden_protocol::account::StorageMapKey,
                ::miden_protocol::Word
            ),
            constructor: (key, value),
        },
        ".account.StorageMapPatch.Entries" => {
            target: ::miden_protocol::account::StorageMapPatchEntries,
            try_constructor: crate::conversion::decode_storage_map_patch_entries(
                entries,
            ),
        },
        ".account.StorageMapPatch" => {
            target: ::miden_protocol::account::StorageMapPatch,
            oneof: {
                patch: {
                    Create: constructor(crate::conversion::decode_storage_map_patch_create),
                    Update: try_constructor(crate::conversion::decode_storage_map_patch_update),
                    Remove: constant(::miden_protocol::account::StorageMapPatch::Remove),
                },
            },
            constructor: patch,
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
            enumeration: {
                version: {
                    Unspecified: reject("account patch version is unspecified"),
                    V1: accept,
                },
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
        ".asset.AssetId" => {
            target: ::miden_protocol::asset::AssetId,
            enumeration: {
                version: {
                    Unspecified: reject("asset id version is unspecified"),
                    V1: accept,
                },
                composition: {
                    Unspecified: reject("asset composition is unspecified"),
                    None: map(::miden_protocol::asset::AssetComposition::None),
                    Fungible: map(::miden_protocol::asset::AssetComposition::Fungible),
                    Custom: map(::miden_protocol::asset::AssetComposition::Custom),
                },
            },
            try_constructor: ::miden_protocol::asset::AssetId::new(
                asset_class,
                faucet_id,
                composition,
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
        ".primitives.PartialSmtNode" => {
            target: (u64, ::miden_protocol::Word),
            constructor: (index, digest),
        },
        ".primitives.PartialSmtNodeLevel" => {
            target: (u32, ::alloc::vec::Vec<(u64, ::miden_protocol::Word)>),
            constructor: (depth, nodes),
        },
        ".primitives.IndexedSmtLeaf" => {
            target: (
                u64,
                ::miden_protocol::crypto::merkle::smt::SmtLeaf
            ),
            constructor: (index, leaf),
        },
        ".primitives.IndexedDigest" => {
            target: (u64, ::miden_protocol::Word),
            constructor: (index, value),
        },
        ".primitives.PartialSmt" => {
            target: ::miden_protocol::crypto::merkle::smt::PartialSmt,
            try_constructor: crate::conversion::decode_partial_smt(
                root,
                node_levels,
                leaves,
                value_only_leaves,
            ),
        },
        ".primitives.SmtLeafEntryList" => {
            target: ::alloc::vec::Vec<(
                ::miden_protocol::Word,
                ::miden_protocol::Word
            )>,
            constructor: entries,
        },
        ".primitives.SmtLeaf" => {
            target: ::miden_protocol::crypto::merkle::smt::SmtLeaf,
            oneof: {
                leaf: {
                    EmptyLeafIndex: constructor(crate::conversion::decode_empty_smt_leaf),
                    Single: constructor(
                        ::miden_protocol::crypto::merkle::smt::SmtLeaf::Single
                    ),
                    Multiple: try_constructor(
                        ::miden_protocol::crypto::merkle::smt::SmtLeaf::new_multiple
                    ),
                },
            },
            constructor: leaf,
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
        ".primitives.MerkleStoreNode" => {
            target: ::miden_protocol::crypto::merkle::InnerNodeInfo,
            constructor: ::miden_protocol::crypto::merkle::InnerNodeInfo {
                value,
                left,
                right,
            },
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
        ".primitives.PublicKey" => {
            target: ::miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey,
            decode: {
                encoded: crate::conversion::decode_public_key,
            },
            enumeration: {
                variant: {
                    Unspecified: reject("public key variant is unspecified"),
                    EcdsaK256Keccak: accept,
                },
            },
            constructor: encoded,
        },
        ".primitives.Signature" => {
            target: ::miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature,
            decode: {
                encoded: crate::conversion::decode_signature,
            },
            enumeration: {
                variant: {
                    Unspecified: reject("signature variant is unspecified"),
                    EcdsaK256Keccak: accept,
                },
            },
            constructor: encoded,
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
        ".note.NoteId" => {
            target: ::miden_protocol::note::NoteId,
            constructor: ::miden_protocol::note::NoteId::from_raw(
                id,
            ),
        },
        ".note.NoteInclusionProof" => {
            target: (
                ::miden_protocol::note::NoteId,
                ::miden_protocol::note::NoteInclusionProof
            ),
            try_constructor: crate::conversion::decode_note_inclusion_proof(
                note_id,
                block_num,
                note_index_in_block,
                inclusion_path,
            ),
        },
        ".note.PartialNoteMetadata" => {
            target: ::miden_protocol::note::PartialNoteMetadata,
            enumeration: {
                version: {
                    Unspecified: reject("note metadata version is unspecified"),
                    V1: accept,
                },
                note_type: {
                    Unspecified: reject("enum variant discriminant out of range"),
                    Private: map(::miden_protocol::note::NoteType::Private),
                    Public: map(::miden_protocol::note::NoteType::Public),
                },
            },
            constructor: crate::conversion::decode_partial_note_metadata(
                sender,
                note_type,
                tag,
            ),
        },
        ".note.NoteMetadata" => {
            target: ::miden_protocol::note::NoteMetadata,
            decode: {
                attachment_schemes: crate::conversion::decode_note_attachment_schemes,
            },
            enumeration: {
                version: {
                    Unspecified: reject("note metadata version is unspecified"),
                    V1: accept,
                },
                note_type: {
                    Unspecified: reject("enum variant discriminant out of range"),
                    Private: map(::miden_protocol::note::NoteType::Private),
                    Public: map(::miden_protocol::note::NoteType::Public),
                },
            },
            constructor: crate::conversion::decode_note_metadata(
                sender,
                note_type,
                tag,
                attachment_schemes,
                attachments_commitment,
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
        ".note.Note" => {
            target: ::miden_protocol::note::Note,
            constructor: crate::conversion::decode_note(
                metadata,
                note_details,
                note_attachments,
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
        ".blockchain.TrackedMmrLeaf" => {
            target: (
                u64,
                ::miden_protocol::Word,
                ::alloc::vec::Vec<::miden_protocol::Word>
            ),
            constructor: (position, leaf, path),
        },
        ".blockchain.PartialBlockchain" => {
            target: ::miden_protocol::transaction::PartialBlockchain,
            try_constructor: crate::conversion::decode_partial_blockchain(
                forest,
                peaks,
                tracked_leaves,
                block_headers,
            ),
        },
        ".blockchain.BlockHeader" => {
            target: ::miden_protocol::block::BlockHeader,
            enumeration: {
                version: {
                    Unspecified: reject("block header version is unspecified"),
                    V1: accept,
                },
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
            target: ::miden_protocol::block::UnverifiedSignedBlock,
            constructor: ::miden_protocol::block::UnverifiedSignedBlock::new(
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
        ".transaction.ProposedBatch" => {
            target: ::miden_protocol::batch::UnverifiedProposedBatch,
            try_constructor: crate::conversion::construct_unverified_proposed_batch(
                transactions,
                reference_block_header,
                partial_blockchain,
                unauthenticated_note_proofs,
            ),
        },
        ".transaction.ProvenBatch" => {
            target: ::miden_protocol::batch::ProvenBatch,
            try_constructor: crate::conversion::construct_proven_batch(
                reference_block_commitment,
                reference_block_num,
                account_updates,
                input_notes,
                output_notes,
                expiration_block_num,
                transactions,
                proof,
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
        ".transaction.NoteArgument" => {
            target: (
                ::miden_protocol::note::NoteId,
                ::miden_protocol::Word
            ),
            constructor: (note_id, args),
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
        ".transaction.AuthenticatedInputNote" => {
            target: ::miden_protocol::transaction::InputNote,
            try_constructor: crate::conversion::decode_authenticated_input_note(
                note,
                proof,
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
        ".transaction.ForeignAccountSlotName" => {
            target: (
                ::miden_protocol::account::StorageSlotId,
                ::miden_protocol::account::StorageSlotName
            ),
            try_constructor: crate::conversion::decode_foreign_account_slot_name(
                slot_id,
                slot_name,
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
