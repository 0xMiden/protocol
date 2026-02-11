extern crate alloc;

use miden_agglayer::errors::{
    ERR_REMAINDER_TOO_LARGE,
    ERR_SCALE_AMOUNT_EXCEEDED_LIMIT,
    ERR_UNDERFLOW,
    ERR_X_TOO_LARGE,
};
use miden_agglayer::eth_types::amount::EthAmount;
use miden_agglayer::utils;
use miden_protocol::Felt;
use miden_protocol::errors::MasmError;
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

    let exec_output = execute_masm_script(&script_code).await?;
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

    assert_execution_fails_with(script_code, "maximum scaling factor is 18").await;
}

// ================================================================================================
// SCALE DOWN TESTS (U256 -> Felt)
// ================================================================================================

/// Build MASM script for verify_u256_to_native_amount_conversion
fn build_scale_down_script(x: EthAmount, scale_exp: u32, y: u64) -> String {
    let x_felts = x.to_elements();
    format!(
        r#"
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            push.{}.{}.{}.{}.{}.{}.{}.{}.{}.{}
            exec.asset_conversion::verify_u256_to_native_amount_conversion
            exec.sys::truncate_stack
        end
        "#,
        y,
        scale_exp,
        x_felts[7].as_int(),
        x_felts[6].as_int(),
        x_felts[5].as_int(),
        x_felts[4].as_int(),
        x_felts[3].as_int(),
        x_felts[2].as_int(),
        x_felts[1].as_int(),
        x_felts[0].as_int(),
    )
}

/// Compute the expected quotient using Rust implementation
fn expected_y(x: U256, scale: u32) -> u64 {
    EthAmount::from_u256(x).scale_to_token_amount(scale).unwrap().as_int()
}

/// Assert that scaling down succeeds with the correct result
async fn assert_scale_down_ok(x: EthAmount, scale: u32) -> anyhow::Result<u64> {
    let y = expected_y(x.to_u256(), scale);
    let script = build_scale_down_script(x, scale, y);
    let out = execute_masm_script(&script).await?;
    assert_eq!(out.stack[0].as_int(), y);
    Ok(y)
}

/// Assert that scaling down fails with the given y and expected error
async fn assert_scale_down_fails(x: EthAmount, scale: u32, y: u64, expected_error: MasmError) {
    let script = build_scale_down_script(x, scale, y);
    assert_execution_fails_with(&script, expected_error.message()).await;
}

/// Test that y-1 and y+1 both fail appropriately
async fn assert_y_plus_minus_one_behavior(x: EthAmount, scale: u32) -> anyhow::Result<()> {
    let y = assert_scale_down_ok(x, scale).await?;
    if y > 0 {
        assert_scale_down_fails(x, scale, y - 1, ERR_REMAINDER_TOO_LARGE).await;
    }
    assert_scale_down_fails(x, scale, y + 1, ERR_UNDERFLOW).await;
    Ok(())
}

#[tokio::test]
async fn test_scale_down_basic_examples() -> anyhow::Result<()> {
    let cases = [
        (EthAmount::from_uint_str("1000000000000000000").unwrap(), 10u32),
        (EthAmount::from_uint_str("1000").unwrap(), 0u32),
        (EthAmount::from_uint_str("10000000000000000000").unwrap(), 18u32),
    ];

    for (x, s) in cases {
        assert_scale_down_ok(x, s).await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_scale_down_realistic_scenarios() -> anyhow::Result<()> {
    let cases = [
        // With remainder: 1.234e18 scaled down by 1e8 = 1.234e10
        (EthAmount::from_uint_str("1234567890123456789").unwrap(), 8u32),
        // ETH to Miden: 100 ETH (wei) scaled down by 10 = 100e8
        (EthAmount::from_uint_str("100000000000000000000").unwrap(), 10u32),
        // USDC (no scaling): 100 USDC
        (EthAmount::from_uint_str("100000000").unwrap(), 0u32),
        // Zero amount
        (EthAmount::from_uint_str("0").unwrap(), 18u32),
    ];

    for (x, scale) in cases {
        assert_scale_down_ok(x, scale).await?;
    }
    Ok(())
}

// ================================================================================================
// NEGATIVE TESTS
// ================================================================================================

#[tokio::test]
async fn test_scale_down_wrong_y_clean_case() -> anyhow::Result<()> {
    let x = EthAmount::from_uint_str("10000000000000000000").unwrap();
    assert_y_plus_minus_one_behavior(x, 18).await
}

#[tokio::test]
async fn test_scale_down_wrong_y_with_remainder() -> anyhow::Result<()> {
    let x = EthAmount::from_uint_str("1500000000000000000").unwrap();
    assert_y_plus_minus_one_behavior(x, 18).await
}

// ================================================================================================
// NEGATIVE TESTS - BOUNDS
// ================================================================================================

#[tokio::test]
async fn test_scale_down_exceeds_max_scale() {
    let x = EthAmount::from_uint_str("1000").unwrap();
    let s = 19u32;
    let y = 1u64;
    assert_scale_down_fails(x, s, y, ERR_SCALE_AMOUNT_EXCEEDED_LIMIT).await;
}

#[tokio::test]
async fn test_scale_down_x_too_large() {
    // Construct x with upper limbs non-zero (>= 2^128)
    let x = EthAmount::from_u256(U256::from(1u64) << 128);
    let s = 0u32;
    let y = 0u64;
    assert_scale_down_fails(x, s, y, ERR_X_TOO_LARGE).await;
}

// ================================================================================================
// REMAINDER EDGE TEST
// ================================================================================================

#[tokio::test]
async fn test_scale_down_remainder_edge() -> anyhow::Result<()> {
    // Force z = scale - 1: pick y=5, s=10, so scale=10^10
    // Set x = y*scale + (scale-1) = 5*10^10 + (10^10 - 1) = 59999999999
    let y = 5u64;
    let scale_exp = 10u32;
    let scale = 10u64.pow(scale_exp);
    let x_val = y * scale + (scale - 1);
    let x = EthAmount::from_u256(U256::from(x_val));

    assert_scale_down_ok(x, scale_exp).await?;
    Ok(())
}

#[tokio::test]
async fn test_scale_down_remainder_exactly_scale_fails() {
    // If remainder z = scale, it should fail
    // Pick y=5, s=10, x = y*scale + scale = (y+1)*scale
    // This means the correct y should be y+1, so providing y should fail
    let wrong_y = 5u64;
    let scale_exp = 10u32;
    let scale = 10u64.pow(scale_exp);
    let x = EthAmount::from_u256(U256::from(wrong_y * scale + scale)); // This is actually (wrong_y+1)*scale

    assert_scale_down_fails(x, scale_exp, wrong_y, ERR_REMAINDER_TOO_LARGE).await;
}

// ================================================================================================
// INLINE SCALE DOWN TEST
// ================================================================================================

#[tokio::test]
async fn test_verify_scale_down_inline() -> anyhow::Result<()> {
    // Test: Take 100 * 1e18 and scale to base 1e8
    // This means we divide by 1e10 (scale_exp = 10)
    // x = 100 * 1e18 = 100000000000000000000
    // y = x / 1e10 = 10000000000 (100 * 1e8)

    let x = EthAmount::from_uint_str("100000000000000000000").unwrap();
    let scale_exp = 10u32;
    let y = 10000000000u64;

    let x_felts = x.to_elements();

    // Build the MASM script inline
    let script_code = format!(
        r#"
        use miden::core::sys
        use miden::agglayer::asset_conversion
        
        begin
            # Push y (expected quotient)
            push.{}
            
            # Push scale_exp
            push.{}
            
            # Push x as 8 u32 limbs (little-endian, x0 at top)
            push.{}.{}.{}.{}.{}.{}.{}.{}
            
            # Call the scale down procedure
            exec.asset_conversion::verify_u256_to_native_amount_conversion
            
            # Truncate stack to just return y
            exec.sys::truncate_stack
        end
        "#,
        y,
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

    // Execute the script
    let exec_output = execute_masm_script(&script_code).await?;

    // Verify the result
    let result = exec_output.stack[0].as_int();
    assert_eq!(result, y);

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
    let result = utils::felts_to_bytes(&limbs);
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
    let result = utils::felts_to_bytes(&limbs);
    assert_eq!(result.len(), 32);
    assert!(result.iter().all(|&b| b == 0));

    // Test case 2: All max u32 values (maximum)
    let limbs = [Felt::new(u32::MAX as u64); 8];
    let result = utils::felts_to_bytes(&limbs);
    assert_eq!(result.len(), 32);
    assert!(result.iter().all(|&b| b == 255));
}
