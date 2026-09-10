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
    for message in ["primitives.Felt", "primitives.Word", "primitives.ExecutionProof"] {
        prost.message_attribute(
            message,
            quote::quote!(#[derive(::miden_protobuf::ProtoDecodeValue)]).to_string(),
        );
    }
    miden_protobuf::build::configure_proto_decode_fields(
        &mut prost,
        &descriptors,
        [
            ".primitives.MastForest",
            ".account.AccountId",
            ".account.AccountIdV1",
            ".transaction.TransactionInputs",
            ".transaction.TransactionInputsV1",
            ".transaction.ProvenBatch",
            ".transaction.ProposedBatch",
            ".transaction.ProvenTransaction",
            ".blockchain.SignedBlock",
            ".blockchain.BlockBody",
            ".blockchain.OutputNoteBatch",
            ".blockchain.IndexedOutputNote",
            ".blockchain.BlockAccountUpdate",
            ".transaction.BatchAccountUpdate",
            ".transaction.TxAccountUpdate",
            ".transaction.InputNotes",
            ".transaction.InputNote",
            ".transaction.AuthenticatedInputNote",
            ".transaction.OutputNote",
            ".transaction.PublicOutputNote",
            ".note.Note",
            ".note.PartialNoteMetadata",
            ".blockchain.PartialBlockchain",
            ".blockchain.BlockHeader",
            ".blockchain.ValidatorConfig",
            ".primitives.Signature",
            ".primitives.PublicKey",
            ".account.PartialAccount",
            ".account.PartialVault",
            ".account.PartialStorage",
            ".account.PartialStorageMap",
            ".primitives.PartialSmt",
            ".primitives.SmtOpening",
            ".primitives.IndexedSmtLeaf",
            ".primitives.SmtLeaf",
            ".account.AccountUpdateDetails",
            ".account.AccountPatch",
            ".account.AccountStoragePatch",
            ".account.StorageSlotPatch",
            ".account.StorageValuePatch",
            ".transaction.TransactionHeader",
            ".transaction.PrivateOutputNote",
            ".transaction.InputNoteCommitment",
            ".note.NoteHeader",
            ".note.NoteDetails",
            ".note.NoteMetadata",
            ".asset.Asset",
            ".asset.AssetId",
            ".account.StorageMapPatch",
            ".account.StorageMapPatchEntries",
            ".account.AccountStorageHeader",
            ".account.AccountStorageHeader.StorageSlot",
            ".account.AccountHeader",
            ".account.PrivateAccountUpdate",
            ".note.NoteInclusionProof",
            ".transaction.ForeignAccountSlotName",
            ".transaction.TransactionArgs",
            ".transaction.NoteArgument",
            ".transaction.TransactionScript",
            ".account.AccountVaultPatch",
            ".account.AccountVaultPatchEntry",
            ".account.AccountWitness",
            ".primitives.MmrDelta",
            ".primitives.AdviceInputs",
            ".primitives.MerkleStore",
            ".primitives.AdviceMap",
            ".note.NoteRecipient",
            ".note.NoteScript",
            ".note.NoteAttachments",
            ".note.NoteAttachment",
            ".note.NoteStorage",
            ".account.AccountCode",
            ".blockchain.NextProtocolConfig",
            ".note.NoteId",
            ".primitives.AdviceStack",
            ".blockchain.FeeParameters",
            ".blockchain.BlockNumber",
            ".blockchain.TrackedMmrLeaf",
            ".account.StorageMapEntry",
            ".primitives.AdviceMapEntry",
            ".primitives.MerkleStoreNode",
            ".primitives.SmtLeafEntryList",
            ".primitives.IndexedDigest",
            ".primitives.PartialSmtNodeLevel",
            ".primitives.PartialSmtNode",
            ".transaction.TransactionId",
            ".asset.AssetClass",
            ".account.StorageSlotId",
            ".primitives.SmtLeafEntry",
            ".primitives.SparseMerklePath",
            ".primitives.MerklePath",
            ".protocol_config.ProtocolConfig",
            ".protocol_config.ProofVerificationConfig",
            ".protocol_config.ProofSecurityPolicy",
            ".protocol_config.KernelConfig",
        ],
    )?;
    prost.field_attribute(
        ".primitives.MastForest.encoded",
        quote::quote!(#[proto_decode(bytes = crate::decoded::primitives::UntrustedMastForest)])
            .to_string(),
    );
    prost.field_attribute(
        ".primitives.PublicKey.key.ecdsa_k256_keccak",
        quote::quote!(#[proto_decode(bytes = crate::decoded::primitives::Canonical<
            miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey
        >)])
        .to_string(),
    );
    prost.field_attribute(
        ".primitives.Signature.signature.ecdsa_k256_keccak",
        quote::quote!(#[proto_decode(bytes = crate::decoded::primitives::Canonical<
            miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature
        >)])
        .to_string(),
    );
    prost.compile_fds(descriptors)?;
    Ok(())
}
