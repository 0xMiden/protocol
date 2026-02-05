extern crate alloc;

use alloc::sync::Arc;

use miden_agglayer::{agglayer_library, utils};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_processor::fast::ExecutionOutput;
use miden_protocol::Felt;
use primitive_types::U256;

use super::test_utils::execute_program_with_default_host;

/// Convert a Vec<Felt> to a U256
fn felts_to_u256(felts: Vec<Felt>) -> U256 {
    assert_eq!(felts.len(), 8, "expected exactly 8 felts");
    let array: [Felt; 8] =
        [felts[0], felts[1], felts[2], felts[3], felts[4], felts[5], felts[6], felts[7]];
    let bytes = utils::felts_to_u256_bytes(array);
    U256::from_little_endian(&bytes)
}

/// Convert the top 8 u32 values from the execution stack to a U256
fn stack_to_u256(exec_output: &ExecutionOutput) -> U256 {
    let felts: Vec<Felt> = exec_output.stack[0..8].to_vec();
    felts_to_u256(felts)
}

/// Helper function to test convert_felt_to_u256_scaled with given parameters
async fn test_convert_to_u256_helper(
    miden_amount: Felt,
    scale_exponent: Felt,
    expected_result_array: [u32; 8],
    expected_result_u256: U256,
) -> anyhow::Result<()> {
    let asset_conversion_lib = agglayer_library();

    let script_code = format!(
        "
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            push.{}.{}
            exec.asset_conversion::scale_native_amount_to_u256
            exec.sys::truncate_stack
        end
        ",
        scale_exponent, miden_amount,
    );

    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(asset_conversion_lib.clone())
        .unwrap()
        .assemble_program(&script_code)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;

    // Extract the first 8 u32 values from the stack (the U256 representation)
    let actual_result: [u32; 8] = [
        exec_output.stack[0].as_int() as u32,
        exec_output.stack[1].as_int() as u32,
        exec_output.stack[2].as_int() as u32,
        exec_output.stack[3].as_int() as u32,
        exec_output.stack[4].as_int() as u32,
        exec_output.stack[5].as_int() as u32,
        exec_output.stack[6].as_int() as u32,
        exec_output.stack[7].as_int() as u32,
    ];

    let actual_result_u256 = stack_to_u256(&exec_output);

    assert_eq!(actual_result, expected_result_array);
    assert_eq!(actual_result_u256, expected_result_u256);

    Ok(())
}

#[tokio::test]
async fn test_convert_to_u256_basic_examples() -> anyhow::Result<()> {
    // Test case 1: amount=1, no scaling (scale_exponent=0)
    test_convert_to_u256_helper(
        Felt::new(1),
        Felt::new(0),
        [1, 0, 0, 0, 0, 0, 0, 0],
        U256::from(1u64),
    )
    .await?;

    // Test case 2: amount=1, scale to 1e18 (scale_exponent=18)
    test_convert_to_u256_helper(
        Felt::new(1),
        Felt::new(18),
        [2808348672, 232830643, 0, 0, 0, 0, 0, 0],
        U256::from_dec_str("1000000000000000000").unwrap(),
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_convert_to_u256_scaled_eth() -> anyhow::Result<()> {
    // 100 units base 1e6
    let miden_amount = Felt::new(100_000_000);

    // scale to 1e18
    let target_scale = Felt::new(12);

    let asset_conversion_lib = agglayer_library();

    let script_code = format!(
        "
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            push.{}.{}
            exec.asset_conversion::scale_native_amount_to_u256
            exec.sys::truncate_stack
        end
        ",
        target_scale, miden_amount,
    );

    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(asset_conversion_lib.clone())
        .unwrap()
        .assemble_program(&script_code)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;

    let expected_result = U256::from_dec_str("100000000000000000000").unwrap();
    let actual_result = stack_to_u256(&exec_output);

    assert_eq!(actual_result, expected_result);

    Ok(())
}

#[tokio::test]
async fn test_convert_to_u256_scaled_large_amount() -> anyhow::Result<()> {
    // 100,000,000 units (base 1e10)
    let miden_amount = Felt::new(1000000000000000000);

    // scale to base 1e18
    let scale_exponent = Felt::new(8);

    let asset_conversion_lib = agglayer_library();

    let script_code = format!(
        "
        use miden::core::sys
        use miden::agglayer::asset_conversion

        begin
            push.{}.{}

            exec.asset_conversion::scale_native_amount_to_u256
            exec.sys::truncate_stack
        end
        ",
        scale_exponent, miden_amount,
    );

    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(asset_conversion_lib.clone())
        .unwrap()
        .assemble_program(&script_code)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;

    let expected_result = U256::from_dec_str("100000000000000000000000000").unwrap();
    let actual_result = stack_to_u256(&exec_output);

    assert_eq!(actual_result, expected_result);

    Ok(())
}

#[test]
fn test_felts_to_u256_bytes_sequential_values() {
    let limbs = [
        Felt::new(1),
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
        Felt::new(8),
    ];
    let result = utils::felts_to_u256_bytes(limbs);
    assert_eq!(result.len(), 32);

    // Verify the byte layout: limbs are processed in little-endian order, each as little-endian u32
    // First byte should be 1 (limbs[0] = 1, least significant limb, least significant byte)
    assert_eq!(result[0], 1);
    // Byte at position 28 should be 8 (limbs[7] = 8, most significant limb, least significant
    // byte)
    assert_eq!(result[28], 8);
}

#[test]
fn test_felts_to_u256_bytes_edge_cases() {
    // Test case 1: All zeros (minimum)
    let limbs = [Felt::new(0); 8];
    let result = utils::felts_to_u256_bytes(limbs);
    assert_eq!(result.len(), 32);
    assert!(result.iter().all(|&b| b == 0));

    // Test case 2: All max u32 values (maximum)
    let limbs = [Felt::new(u32::MAX as u64); 8];
    let result = utils::felts_to_u256_bytes(limbs);
    assert_eq!(result.len(), 32);
    assert!(result.iter().all(|&b| b == 255));
}
