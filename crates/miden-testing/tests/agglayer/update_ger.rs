extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_agglayer::utils::felts_to_bytes;
use miden_agglayer::{ExitRoot, UpdateGerNote, agglayer_library, create_existing_bridge_account};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_core_lib::handlers::bytes_to_packed_u32_felts;
use miden_core_lib::handlers::keccak256::KeccakPreimage;
use miden_crypto::hash::rpo::Rpo256 as Hasher;
use miden_crypto::{Felt, FieldElement};
use miden_protocol::Word;
use miden_protocol::account::StorageSlotName;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::transaction::OutputNote;
use miden_protocol::utils::sync::LazyLock;
use miden_testing::{Auth, MockChain};
use miden_tx::utils::hex_to_bytes;
use serde::Deserialize;

use super::test_utils::execute_program_with_default_host;

// EXIT ROOT TEST VECTORS
// ================================================================================================
// Test vectors generated from Solidity's GlobalExitRootLib.calculateGlobalExitRoot
// Run `forge test --match-contract ExitRootsTestVectors` to regenerate.

/// Exit roots JSON embedded at compile time from the Foundry-generated file.
const EXIT_ROOTS_JSON: &str =
    include_str!("../../../miden-agglayer/solidity-compat/test-vectors/exit_roots.json");

/// Deserialized exit root vectors from Solidity GlobalExitRootLib
#[derive(Debug, Deserialize)]
struct ExitRootsFile {
    mainnet_exit_roots: Vec<String>,
    rollup_exit_roots: Vec<String>,
    global_exit_roots: Vec<String>,
}

/// Lazily parsed exit root vectors from the JSON file.
static EXIT_ROOTS_VECTORS: LazyLock<ExitRootsFile> = LazyLock::new(|| {
    serde_json::from_str(EXIT_ROOTS_JSON).expect("Failed to parse exit roots JSON")
});

#[tokio::test]
async fn update_ger_note_updates_storage() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(bridge_seed);
    builder.add_account(bridge_account.clone())?;

    // CREATE USER ACCOUNT (NOTE SENDER)
    // --------------------------------------------------------------------------------------------
    let user_account = builder.add_existing_wallet(Auth::BasicAuth)?;
    builder.add_account(user_account.clone())?;

    // CREATE UPDATE_GER NOTE WITH 8 STORAGE ITEMS (NEW GER AS TWO WORDS)
    // --------------------------------------------------------------------------------------------

    let ger_bytes: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];
    let ger = ExitRoot::from(ger_bytes);
    let update_ger_note =
        UpdateGerNote::create(ger, user_account.id(), bridge_account.id(), builder.rng_mut())?;

    builder.add_output_note(OutputNote::Full(update_ger_note.clone()));
    let mock_chain = builder.build()?;

    // EXECUTE UPDATE_GER NOTE AGAINST BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    // VERIFY GER HASH WAS STORED IN MAP
    // --------------------------------------------------------------------------------------------
    let mut updated_bridge_account = bridge_account.clone();
    updated_bridge_account.apply_delta(executed_transaction.account_delta())?;

    // Compute the expected GER hash: rpo256::merge(GER_UPPER, GER_LOWER)
    let mut ger_lower: [Felt; 4] = ger.to_elements()[0..4].try_into().unwrap();
    let mut ger_upper: [Felt; 4] = ger.to_elements()[4..8].try_into().unwrap();
    // Elements are reversed: rpo256::merge treats stack as if loaded BE from memory
    // The following will produce matching hashes:
    // Rust
    // Hasher::merge(&[a, b, c, d], &[e, f, g, h])
    // MASM
    // rpo256::merge(h, g, f, e, d, c, b, a)
    ger_lower.reverse();
    ger_upper.reverse();

    let ger_hash = Hasher::merge(&[ger_upper.into(), ger_lower.into()]);
    // Look up the GER hash in the map storage
    let ger_storage_slot = StorageSlotName::new("miden::agglayer::bridge::ger")?;
    let stored_value = updated_bridge_account
        .storage()
        .get_map_item(&ger_storage_slot, ger_hash)
        .expect("GER hash should be stored in the map");

    // The stored value should be [GER_KNOWN_FLAG, 0, 0, 0] = [1, 0, 0, 0]
    let expected_value: Word = [Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO].into();
    assert_eq!(stored_value, expected_value, "GER hash should map to [1, 0, 0, 0]");

    Ok(())
}

/// Tests compute_ger with known mainnet and rollup exit roots.
///
/// The GER (Global Exit Root) is computed as keccak256(mainnet_exit_root || rollup_exit_root).
#[tokio::test]
async fn compute_ger() -> anyhow::Result<()> {
    let agglayer_lib = agglayer_library();
    let vectors = &*EXIT_ROOTS_VECTORS;

    for i in 0..vectors.mainnet_exit_roots.len() {
        let mainnet_exit_root_bytes =
            hex_to_bytes(vectors.mainnet_exit_roots[i].as_str()).expect("Invalid hex string");
        let rollup_exit_root_bytes =
            hex_to_bytes(vectors.rollup_exit_roots[i].as_str()).expect("Invalid hex string");
        let expected_ger_bytes =
            hex_to_bytes(vectors.global_exit_roots[i].as_str()).expect("Invalid hex string");

        // Convert expected GER to felts for comparison
        let expected_ger_exit_root = ExitRoot::from(expected_ger_bytes);
        let expected_ger_felts = expected_ger_exit_root.to_elements();

        // Computed GER using keccak256
        let ger_preimage: Vec<u8> =
            [mainnet_exit_root_bytes.as_ref(), rollup_exit_root_bytes.as_ref()].concat();
        let ger_preimage = KeccakPreimage::new(ger_preimage);
        let computed_ger_felts: Vec<Felt> = ger_preimage.digest().as_ref().to_vec();

        assert_eq!(
            computed_ger_felts, expected_ger_felts,
            "Computed GER mismatch for test vector {}",
            i
        );

        // Convert exit roots to packed u32 felts for memory initialization
        let mainnet_felts = ExitRoot::from(mainnet_exit_root_bytes).to_elements();
        let rollup_felts = ExitRoot::from(rollup_exit_root_bytes).to_elements();

        // Build memory initialization: mainnet at ptr 0, rollup at ptr 8
        let mem_init: Vec<String> = mainnet_felts
            .iter()
            .chain(rollup_felts.iter())
            .enumerate()
            .map(|(idx, f)| format!("push.{} mem_store.{}", f.as_int(), idx))
            .collect();
        let mem_init_code = mem_init.join("\n");

        let source = format!(
            r#"
                use miden::core::sys
                use miden::agglayer::crypto_utils

                begin
                    # Initialize memory with exit roots
                    {mem_init_code}

                    # Call compute_ger with pointer to exit roots
                    push.0
                    exec.crypto_utils::compute_ger
                    exec.sys::truncate_stack
                end
            "#
        );

        let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
            .with_dynamic_library(CoreLibrary::default())
            .unwrap()
            .with_dynamic_library(agglayer_lib.clone())
            .unwrap()
            .assemble_program(&source)
            .unwrap();

        let exec_output = execute_program_with_default_host(program, None).await?;

        let result_digest: Vec<Felt> = exec_output.stack[0..8].to_vec();

        assert_eq!(result_digest, expected_ger_felts, "GER mismatch for test vector {}", i);
    }

    Ok(())
}

/// Tests compute_ger with known mainnet and rollup exit roots.
///
/// The GER (Global Exit Root) is computed as keccak256(mainnet_exit_root || rollup_exit_root).
#[tokio::test]
async fn test_compute_ger_basic() -> anyhow::Result<()> {
    let agglayer_lib = agglayer_library();

    // Define test exit roots (32 bytes each)
    let mainnet_exit_root: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];

    let rollup_exit_root: [u8; 32] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99,
    ];

    // Concatenate the two roots (64 bytes total)
    let mut ger_preimage = Vec::with_capacity(64);
    ger_preimage.extend_from_slice(&mainnet_exit_root);
    ger_preimage.extend_from_slice(&rollup_exit_root);

    // Compute expected GER using keccak256
    let expected_ger_preimage = KeccakPreimage::new(ger_preimage.clone());
    let expected_ger_felts: [Felt; 8] = expected_ger_preimage.digest().as_ref().try_into().unwrap();

    let ger_bytes: [u8; 32] = felts_to_bytes(&expected_ger_felts).try_into().unwrap();

    let ger = ExitRoot::from(ger_bytes);
    // sanity check
    assert_eq!(ger.to_elements(), expected_ger_felts);

    // Convert exit roots to packed u32 felts for memory initialization
    let mainnet_felts = bytes_to_packed_u32_felts(&mainnet_exit_root);
    let rollup_felts = bytes_to_packed_u32_felts(&rollup_exit_root);

    // Build memory initialization: mainnet at ptr 0, rollup at ptr 8
    let mem_init: Vec<String> = mainnet_felts
        .iter()
        .chain(rollup_felts.iter())
        .enumerate()
        .map(|(i, f)| format!("push.{} mem_store.{}", f.as_int(), i))
        .collect();
    let mem_init_code = mem_init.join("\n");

    let source = format!(
        r#"
            use miden::core::sys
            use miden::agglayer::crypto_utils

            begin
                # Initialize memory with exit roots
                {mem_init_code}

                # Call compute_ger with pointer to exit roots
                push.0
                exec.crypto_utils::compute_ger
                exec.sys::truncate_stack
            end
        "#
    );

    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib.clone())
        .unwrap()
        .assemble_program(&source)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;

    let result_digest: Vec<Felt> = exec_output.stack[0..8].to_vec();

    assert_eq!(result_digest, expected_ger_felts);

    Ok(())
}
