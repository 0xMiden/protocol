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
use miden_protocol::account::StorageSlotName;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::transaction::OutputNote;
use miden_protocol::{Felt, Word};
use miden_testing::{Auth, MockChain};

use super::test_utils::execute_program_with_default_host;

#[tokio::test]
async fn test_update_ger_note_updates_storage() -> anyhow::Result<()> {
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

    // VERIFY GER WAS UPDATED IN STORAGE
    // --------------------------------------------------------------------------------------------
    let mut updated_bridge_account = bridge_account.clone();
    updated_bridge_account.apply_delta(executed_transaction.account_delta())?;

    let ger_upper = updated_bridge_account
        .storage()
        .get_item(&StorageSlotName::new("miden::agglayer::bridge::ger_upper")?)
        .unwrap();
    let ger_lower = updated_bridge_account
        .storage()
        .get_item(&StorageSlotName::new("miden::agglayer::bridge::ger_lower")?)
        .unwrap();
    let expected_lower: Word = ger.to_elements()[0..4].try_into().unwrap();
    let expected_upper: Word = ger.to_elements()[4..8].try_into().unwrap();
    assert_eq!(ger_upper, expected_upper);
    assert_eq!(ger_lower, expected_lower);

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
