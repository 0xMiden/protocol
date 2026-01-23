extern crate alloc;

use miden_agglayer::utils;
use miden_protocol::Felt;
use primitive_types::U256;

use super::test_utils::{assert_execution_fails_with, execute_masm_script, stack_to_u256};

// ================================================================================================
// SCALE UP TESTS (Felt -> U256)
// ================================================================================================

/// Helper function to test scale_native_amount_to_u256 with given parameters
async fn test_scale_up_helper(
    miden_amount: Felt,
    scale_exponent: Felt,
    expected_result_u256: U256,
) -> anyhow::Result<()> {
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

    let exec_output = execute_masm_script(&script_code, vec![]).await?;
    let actual_result_u256 = stack_to_u256(&exec_output);

    assert_eq!(actual_result_u256, expected_result_u256);

    Ok(())
}

#[tokio::test]
async fn test_scale_up_basic_examples() -> anyhow::Result<()> {
    // Test case 1: amount=1, no scaling (scale_exponent=0)
    test_scale_up_helper(Felt::new(1), Felt::new(0), U256::from(1u64)).await?;

    // Test case 2: amount=1, scale to 1e18 (scale_exponent=18)
    test_scale_up_helper(
        Felt::new(1),
        Felt::new(18),
        U256::from_dec_str("1000000000000000000").unwrap(),
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_scale_up_realistic_amounts() -> anyhow::Result<()> {
    // 100 units base 1e6, scale to 1e18
    test_scale_up_helper(
        Felt::new(100_000_000),
        Felt::new(12),
        U256::from_dec_str("100000000000000000000").unwrap(),
    )
    .await?;

    // Large amount: 1e18 units scaled by 8
    test_scale_up_helper(
        Felt::new(1000000000000000000),
        Felt::new(8),
        U256::from_dec_str("100000000000000000000000000").unwrap(),
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_scale_up_exceeds_max_scale() {
    // scale_exp = 19 should fail
    let script_code = "
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            push.19.1
            exec.asset_conversion::scale_native_amount_to_u256
            exec.sys::truncate_stack
        end
    ";

    assert_execution_fails_with(script_code, vec![], "maximum scaling factor is 18").await;
}

// ================================================================================================
// SCALE DOWN TESTS (U256 -> Felt)
// ================================================================================================

/// Helper function to test scale_u256_to_native_amount with given parameters
async fn test_scale_down_helper(
    x_u256: U256,
    scale_exp: u32,
    expected_y: u64,
) -> anyhow::Result<()> {
    let x_felts = utils::u256_to_felts(x_u256);

    let script_code = format!(
        "
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            push.{}.{}.{}.{}.{}.{}.{}.{}.{}
            exec.asset_conversion::scale_u256_to_native_amount
            exec.sys::truncate_stack
        end
        ",
        scale_exp,
        x_felts[7].as_int(),
        x_felts[6].as_int(),
        x_felts[5].as_int(),
        x_felts[4].as_int(),
        x_felts[3].as_int(),
        x_felts[2].as_int(),
        x_felts[1].as_int(),
        x_felts[0].as_int(),
    );

    let exec_output = execute_masm_script(&script_code, vec![expected_y]).await?;

    let actual_y = exec_output.stack[0].as_int();
    assert_eq!(actual_y, expected_y, "expected y={}, got y={}", expected_y, actual_y);

    Ok(())
}

#[tokio::test]
async fn test_scale_down_basic_examples() -> anyhow::Result<()> {
    // Test case 1: 1e18 scaled down by 18 = 1
    test_scale_down_helper(U256::from_dec_str("1000000000000000000").unwrap(), 18, 1).await?;

    // Test case 2: 1000 scaled down by 0 = 1000 (no scaling)
    test_scale_down_helper(U256::from(1000u64), 0, 1000).await?;

    // Test case 3: 10e18 scaled down by 18 = 10
    test_scale_down_helper(U256::from_dec_str("10000000000000000000").unwrap(), 18, 10).await?;

    Ok(())
}

#[tokio::test]
async fn test_scale_down_realistic_scenarios() -> anyhow::Result<()> {
    // With remainder: 1.234e18 scaled down by 18 = 1
    test_scale_down_helper(U256::from_dec_str("1234567890123456789").unwrap(), 18, 1).await?;

    // ETH to Miden: 100 ETH (wei) scaled down by 12 = 100e6
    test_scale_down_helper(U256::from_dec_str("100000000000000000000").unwrap(), 12, 100_000_000)
        .await?;

    // USDC (no scaling): 100 USDC
    test_scale_down_helper(U256::from(100_000_000u64), 0, 100_000_000).await?;

    // Zero amount
    test_scale_down_helper(U256::zero(), 18, 0).await?;

    Ok(())
}

// ================================================================================================
// NEGATIVE TESTS - WRONG ADVICE
// ================================================================================================

#[tokio::test]
async fn test_scale_down_wrong_advice_y_minus_1() {
    // Use a clean example: 10e18 scaled down by 18 should give y=10
    let x_u256 = U256::from_dec_str("10000000000000000000").unwrap();
    let scale_exp = 18;
    let correct_y = 10u64;
    let wrong_y = correct_y - 1; // y=9 is incorrect

    let x_felts = utils::u256_to_felts(x_u256);

    let script_code = format!(
        "
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            push.{}.{}.{}.{}.{}.{}.{}.{}.{}
            exec.asset_conversion::scale_u256_to_native_amount
            exec.sys::truncate_stack
        end
        ",
        scale_exp,
        x_felts[7].as_int(),
        x_felts[6].as_int(),
        x_felts[5].as_int(),
        x_felts[4].as_int(),
        x_felts[3].as_int(),
        x_felts[2].as_int(),
        x_felts[1].as_int(),
        x_felts[0].as_int(),
    );

    // Providing y-1 should fail with remainder too large
    assert_execution_fails_with(&script_code, vec![wrong_y], "remainder z must be < 10^s").await;
}

#[tokio::test]
async fn test_scale_down_wrong_advice_y_plus_1() {
    // Use a clean example: 10e18 scaled down by 18 should give y=10
    let x_u256 = U256::from_dec_str("10000000000000000000").unwrap();
    let scale_exp = 18;
    let correct_y = 10u64;
    let wrong_y = correct_y + 1; // y=11 is incorrect

    let x_felts = utils::u256_to_felts(x_u256);

    let script_code = format!(
        "
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            push.{}.{}.{}.{}.{}.{}.{}.{}.{}
            exec.asset_conversion::scale_u256_to_native_amount
            exec.sys::truncate_stack
        end
        ",
        scale_exp,
        x_felts[7].as_int(),
        x_felts[6].as_int(),
        x_felts[5].as_int(),
        x_felts[4].as_int(),
        x_felts[3].as_int(),
        x_felts[2].as_int(),
        x_felts[1].as_int(),
        x_felts[0].as_int(),
    );

    // Providing y+1 should fail with underflow
    assert_execution_fails_with(&script_code, vec![wrong_y], "x < y*10^s (underflow detected)")
        .await;
}

#[tokio::test]
async fn test_scale_down_wrong_advice_with_remainder() {
    // Example with remainder: 1.5e18 scaled down by 18 should give y=1
    let x_u256 = U256::from_dec_str("1500000000000000000").unwrap();
    let scale_exp = 18;
    let correct_y = 1u64;

    let x_felts = utils::u256_to_felts(x_u256);

    let script_code = format!(
        "
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            push.{}.{}.{}.{}.{}.{}.{}.{}.{}
            exec.asset_conversion::scale_u256_to_native_amount
            exec.sys::truncate_stack
        end
        ",
        scale_exp,
        x_felts[7].as_int(),
        x_felts[6].as_int(),
        x_felts[5].as_int(),
        x_felts[4].as_int(),
        x_felts[3].as_int(),
        x_felts[2].as_int(),
        x_felts[1].as_int(),
        x_felts[0].as_int(),
    );

    // y-1 should fail
    assert_execution_fails_with(&script_code, vec![correct_y - 1], "remainder z must be < 10^s")
        .await;

    // y+1 should fail
    assert_execution_fails_with(
        &script_code,
        vec![correct_y + 1],
        "x < y*10^s (underflow detected)",
    )
    .await;
}

// ================================================================================================
// NEGATIVE TESTS - BOUNDS
// ================================================================================================

#[tokio::test]
async fn test_scale_down_exceeds_max_scale() {
    // scale_exp = 19 should fail in pow10
    let x_u256 = U256::from(1000u64);
    let x_felts = utils::u256_to_felts(x_u256);

    let script_code = format!(
        "
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            push.19.{}.{}.{}.{}.{}.{}.{}.{}
            exec.asset_conversion::scale_u256_to_native_amount
            exec.sys::truncate_stack
        end
        ",
        x_felts[7].as_int(),
        x_felts[6].as_int(),
        x_felts[5].as_int(),
        x_felts[4].as_int(),
        x_felts[3].as_int(),
        x_felts[2].as_int(),
        x_felts[1].as_int(),
        x_felts[0].as_int(),
    );

    assert_execution_fails_with(&script_code, vec![1], "maximum scaling factor is 18").await;
}

#[tokio::test]
async fn test_scale_down_x_too_large() {
    // Construct x with x4 = 1 (i.e., >= 2^128)
    let script_code = "
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            push.0.0.0.0.1.0.0.0.0
            exec.asset_conversion::scale_u256_to_native_amount
            exec.sys::truncate_stack
        end
    ";

    assert_execution_fails_with(
        script_code,
        vec![1],
        "x must fit into 128 bits (x4..x7 must be 0)",
    )
    .await;
}

// ================================================================================================
// REMAINDER EDGE TEST
// ================================================================================================

#[tokio::test]
async fn test_scale_down_remainder_edge() -> anyhow::Result<()> {
    // Force z = scale - 1: pick y=5, s=10, so scale=10^10
    // Set x = y*scale + (scale-1) = 5*10^10 + (10^10 - 1) = 59999999999
    let y = 5u64;
    let s = 10u32;
    let scale = 10u64.pow(s);
    let x = y * scale + (scale - 1);

    test_scale_down_helper(U256::from(x), s, y).await?;

    Ok(())
}

#[tokio::test]
async fn test_scale_down_remainder_exactly_scale_fails() {
    // If remainder z = scale, it should fail
    // Pick y=5, s=10, x = y*scale + scale = (y+1)*scale
    // This means the correct y should be y+1, so providing y should fail
    let y = 5u64;
    let s = 10u32;
    let scale = 10u64.pow(s);
    let x = y * scale + scale; // This is actually (y+1)*scale

    let x_felts = utils::u256_to_felts(U256::from(x));

    let script_code = format!(
        "
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            push.{}.{}.{}.{}.{}.{}.{}.{}.{}
            exec.asset_conversion::scale_u256_to_native_amount
            exec.sys::truncate_stack
        end
        ",
        s,
        x_felts[7].as_int(),
        x_felts[6].as_int(),
        x_felts[5].as_int(),
        x_felts[4].as_int(),
        x_felts[3].as_int(),
        x_felts[2].as_int(),
        x_felts[1].as_int(),
        x_felts[0].as_int(),
    );

    // Providing y (which is too small) should fail
    assert_execution_fails_with(&script_code, vec![y], "remainder z must be < 10^s").await;
}
