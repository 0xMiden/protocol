extern crate alloc;

use alloc::sync::Arc;

use miden_agglayer::agglayer_library;
use miden_agglayer::errors::{
    ERR_BRIDGE_NOT_MAINNET,
    ERR_LEADING_BITS_NON_ZERO,
    ERR_ROLLUP_INDEX_NON_ZERO,
};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_processor::Program;
use miden_testing::{ExecError, assert_execution_error};

use crate::agglayer::test_utils::execute_program_with_default_host;

fn assemble_process_global_index_program(global_index_be_u32_limbs: [u32; 8]) -> Program {
    let [g0, g1, g2, g3, g4, g5, g6, g7] = global_index_be_u32_limbs;

    let script_code = format!(
        r#"
        use miden::core::sys
        use miden::agglayer::bridge_in

        begin
            push.{g7}.{g6}.{g5}.{g4}.{g3}.{g2}.{g1}.{g0}
            exec.bridge_in::process_global_index_mainnet
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

#[tokio::test]
async fn test_process_global_index_mainnet_returns_leaf_index() -> anyhow::Result<()> {
    // 256-bit globalIndex encoded as 8 u32 limbs (big-endian):
    // [top 191 bits = 0, mainnet flag = 1, rollup_index = 0, leaf_index = 2]
    let global_index = [0, 0, 0, 0, 0, 1, 0, 2];
    let program = assemble_process_global_index_program(global_index);

    let exec_output = execute_program_with_default_host(program, None).await?;

    assert_eq!(exec_output.stack[0].as_int(), 2);
    Ok(())
}

#[tokio::test]
async fn test_process_global_index_mainnet_rejects_non_zero_leading_bits() {
    let global_index = [1, 0, 0, 0, 0, 1, 0, 2];
    let program = assemble_process_global_index_program(global_index);

    let err = execute_program_with_default_host(program, None).await.map_err(ExecError::new);
    assert_execution_error!(err, ERR_LEADING_BITS_NON_ZERO);
}

#[tokio::test]
async fn test_process_global_index_mainnet_rejects_flag_limb_upper_bits() {
    // limb5 is the mainnet flag; only the lowest bit is allowed
    let global_index = [0, 0, 0, 0, 0, 3, 0, 2];
    let program = assemble_process_global_index_program(global_index);

    let err = execute_program_with_default_host(program, None).await.map_err(ExecError::new);
    assert_execution_error!(err, ERR_BRIDGE_NOT_MAINNET);
}

#[tokio::test]
async fn test_process_global_index_mainnet_rejects_non_zero_rollup_index() {
    let global_index = [0, 0, 0, 0, 0, 1, 7, 2];
    let program = assemble_process_global_index_program(global_index);

    let err = execute_program_with_default_host(program, None).await.map_err(ExecError::new);
    assert_execution_error!(err, ERR_ROLLUP_INDEX_NON_ZERO);
}
