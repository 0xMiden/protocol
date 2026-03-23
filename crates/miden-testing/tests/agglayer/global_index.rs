extern crate alloc;

use alloc::sync::Arc;

use miden_agglayer::errors::{
    ERR_BRIDGE_NOT_MAINNET,
    ERR_BRIDGE_NOT_ROLLUP,
    ERR_LEADING_BITS_NON_ZERO,
    ERR_ROLLUP_INDEX_NON_ZERO,
};
use miden_agglayer::{GlobalIndex, agglayer_library};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_processor::Program;
use miden_testing::{ExecError, assert_execution_error};

use crate::agglayer::test_utils::execute_program_with_default_host;

fn assemble_process_global_index_program(global_index: GlobalIndex, proc_name: &str) -> Program {
    // Convert GlobalIndex to 8 field elements (big-endian: [0]=MSB, [7]=LSB)
    let elements = global_index.to_elements();
    let [g0, g1, g2, g3, g4, g5, g6, g7] = elements.try_into().unwrap();

    let script_code = format!(
        r#"
        use miden::core::sys
        use agglayer::bridge::bridge_in

        begin
            push.{g7}.{g6}.{g5}.{g4}.{g3}.{g2}.{g1}.{g0}
            exec.bridge_in::{proc_name}
            exec.sys::truncate_stack
        end
        "#
    );

    Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_library())
        .unwrap()
        .assemble_program(&script_code)
        .unwrap()
}

// MAINNET GLOBAL INDEX TESTS
// ================================================================================================

#[tokio::test]
async fn test_process_global_index_mainnet_returns_leaf_index() -> anyhow::Result<()> {
    // Global index format (32 bytes, big-endian like Solidity uint256):
    // - bytes[0..20]: leading zeros
    // - bytes[20..24]: mainnet_flag = 1 (BE u32)
    // - bytes[24..28]: rollup_index = 0 (BE u32)
    // - bytes[28..32]: leaf_index = 2 (BE u32)
    let mut bytes = [0u8; 32];
    bytes[23] = 1; // mainnet flag = 1 (BE: LSB at byte 23)
    bytes[31] = 2; // leaf index = 2 (BE: LSB at byte 31)
    let program = assemble_process_global_index_program(
        GlobalIndex::new(bytes),
        "process_global_index_mainnet",
    );

    let exec_output = execute_program_with_default_host(program, None).await?;

    assert_eq!(exec_output.stack[0].as_canonical_u64(), 2);
    Ok(())
}

#[tokio::test]
async fn test_process_global_index_mainnet_rejects_non_zero_leading_bits() {
    let mut bytes = [0u8; 32];
    bytes[3] = 1; // non-zero leading bits (BE: LSB of first u32 limb)
    bytes[23] = 1; // mainnet flag = 1
    bytes[31] = 2; // leaf index = 2
    let program = assemble_process_global_index_program(
        GlobalIndex::new(bytes),
        "process_global_index_mainnet",
    );

    let err = execute_program_with_default_host(program, None).await.map_err(ExecError::new);
    assert_execution_error!(err, ERR_LEADING_BITS_NON_ZERO);
}

#[tokio::test]
async fn test_process_global_index_mainnet_rejects_flag_limb_upper_bits() {
    let mut bytes = [0u8; 32];
    bytes[23] = 3; // mainnet flag limb = 3 (upper bits set, only lowest bit allowed)
    bytes[31] = 2; // leaf index = 2
    let program = assemble_process_global_index_program(
        GlobalIndex::new(bytes),
        "process_global_index_mainnet",
    );

    let err = execute_program_with_default_host(program, None).await.map_err(ExecError::new);
    assert_execution_error!(err, ERR_BRIDGE_NOT_MAINNET);
}

#[tokio::test]
async fn test_process_global_index_mainnet_rejects_non_zero_rollup_index() {
    let mut bytes = [0u8; 32];
    bytes[23] = 1; // mainnet flag = 1
    bytes[27] = 7; // rollup index = 7 (BE: LSB at byte 27)
    bytes[31] = 2; // leaf index = 2
    let program = assemble_process_global_index_program(
        GlobalIndex::new(bytes),
        "process_global_index_mainnet",
    );

    let err = execute_program_with_default_host(program, None).await.map_err(ExecError::new);
    assert_execution_error!(err, ERR_ROLLUP_INDEX_NON_ZERO);
}

// ROLLUP GLOBAL INDEX TESTS
// ================================================================================================

#[tokio::test]
async fn test_process_global_index_rollup_returns_leaf_and_rollup_index() -> anyhow::Result<()> {
    // Global index for rollup: mainnet_flag=0, rollup_index=5, leaf_index=42
    let mut bytes = [0u8; 32];
    // mainnet flag = 0 (already zero)
    bytes[27] = 5; // rollup index = 5 (BE: LSB at byte 27)
    bytes[31] = 42; // leaf index = 42 (BE: LSB at byte 31)
    let program = assemble_process_global_index_program(
        GlobalIndex::new(bytes),
        "process_global_index_rollup",
    );

    let exec_output = execute_program_with_default_host(program, None).await?;

    // process_global_index_rollup returns [leaf_index, rollup_index]
    // stack[0] = leaf_index (top), stack[1] = rollup_index
    assert_eq!(exec_output.stack[0].as_canonical_u64(), 42, "leaf_index should be 42");
    assert_eq!(exec_output.stack[1].as_canonical_u64(), 5, "rollup_index should be 5");
    Ok(())
}

#[tokio::test]
async fn test_process_global_index_rollup_rejects_non_zero_leading_bits() {
    let mut bytes = [0u8; 32];
    bytes[3] = 1; // non-zero leading bits
    bytes[27] = 5; // rollup index = 5
    bytes[31] = 42; // leaf index = 42
    let program = assemble_process_global_index_program(
        GlobalIndex::new(bytes),
        "process_global_index_rollup",
    );

    let err = execute_program_with_default_host(program, None).await.map_err(ExecError::new);
    assert_execution_error!(err, ERR_LEADING_BITS_NON_ZERO);
}

#[tokio::test]
async fn test_process_global_index_rollup_rejects_mainnet_flag() {
    let mut bytes = [0u8; 32];
    bytes[23] = 1; // mainnet flag = 1 (should be 0 for rollup)
    bytes[27] = 5; // rollup index = 5
    bytes[31] = 42; // leaf index = 42
    let program = assemble_process_global_index_program(
        GlobalIndex::new(bytes),
        "process_global_index_rollup",
    );

    let err = execute_program_with_default_host(program, None).await.map_err(ExecError::new);
    assert_execution_error!(err, ERR_BRIDGE_NOT_ROLLUP);
}
