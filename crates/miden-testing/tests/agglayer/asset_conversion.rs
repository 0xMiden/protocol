extern crate alloc;

use miden_agglayer::errors::{
    ERR_REMAINDER_TOO_LARGE,
    ERR_SCALE_AMOUNT_EXCEEDED_LIMIT,
    ERR_UNDERFLOW,
    ERR_X_TOO_LARGE,
};
use miden_agglayer::eth_types::amount::EthAmount;
use miden_processor::utils::packed_u32_elements_to_bytes;
use miden_protocol::Felt;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::errors::MasmError;
use primitive_types::U256;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::test_utils::{assert_execution_fails_with, execute_masm_script};

// ================================================================================================
// SCALE UP TESTS (Felt -> U256)
// ================================================================================================

/// Helper function to test scale_native_amount_to_u256 with given parameters
async fn test_scale_up_helper(
    miden_amount: Felt,
    scale_exponent: Felt,
    expected_result: EthAmount,
) -> anyhow::Result<()> {
    let script_code = format!(
        "
        use miden::core::sys
        use agglayer::common::asset_conversion
        
        begin
            push.{}.{}
            exec.asset_conversion::scale_native_amount_to_u256
            exec.sys::truncate_stack
        end
        ",
        scale_exponent, miden_amount,
    );

    let exec_output = execute_masm_script(&script_code).await?;
    let actual_felts: Vec<Felt> = exec_output.stack[0..8].to_vec();

    // to_elements() returns big-endian limb order with each limb byte-swapped (LE-interpreted
    // from BE source bytes). The scale-up output is native u32 limbs in LE limb order, so we
    // reverse the limbs and swap bytes within each u32 to match.
    let expected_felts: Vec<Felt> = expected_result
        .to_elements()
        .into_iter()
        .rev()
        .map(|f| Felt::new((f.as_canonical_u64() as u32).swap_bytes() as u64))
        .collect();

    assert_eq!(actual_felts, expected_felts);

    Ok(())
}

#[tokio::test]
async fn test_scale_up_basic_examples() -> anyhow::Result<()> {
    // Test case 1: amount=1, no scaling (scale_exponent=0)
    test_scale_up_helper(Felt::new(1), Felt::new(0), EthAmount::from_uint_str("1").unwrap())
        .await?;

    // Test case 2: amount=1, scale to 1e18 (scale_exponent=18)
    test_scale_up_helper(
        Felt::new(1),
        Felt::new(18),
        EthAmount::from_uint_str("1000000000000000000").unwrap(),
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
        EthAmount::from_uint_str("100000000000000000000").unwrap(),
    )
    .await?;

    // Large amount: 1e18 units scaled by 8
    test_scale_up_helper(
        Felt::new(1000000000000000000),
        Felt::new(8),
        EthAmount::from_uint_str("100000000000000000000000000").unwrap(),
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_scale_up_exceeds_max_scale() {
    // scale_exp = 19 should fail
    let script_code = "
        use miden::core::sys
        use agglayer::common::asset_conversion
        
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
        use agglayer::common::asset_conversion
        
        begin
            push.{}.{}.{}.{}.{}.{}.{}.{}.{}.{}
            exec.asset_conversion::verify_u256_to_native_amount_conversion
            exec.sys::truncate_stack
        end
        "#,
        y,
        scale_exp,
        x_felts[7].as_canonical_u64(),
        x_felts[6].as_canonical_u64(),
        x_felts[5].as_canonical_u64(),
        x_felts[4].as_canonical_u64(),
        x_felts[3].as_canonical_u64(),
        x_felts[2].as_canonical_u64(),
        x_felts[1].as_canonical_u64(),
        x_felts[0].as_canonical_u64(),
    )
}

/// Assert that scaling down succeeds with the correct result
async fn assert_scale_down_ok(x: EthAmount, scale: u32) -> anyhow::Result<u64> {
    let y = x.scale_to_token_amount(scale).unwrap().as_canonical_u64();
    let script = build_scale_down_script(x, scale, y);
    let output = execute_masm_script(&script).await?;
    assert_eq!(output.stack.as_slice(), &[Felt::ZERO; 16], "expected empty stack");
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

// ================================================================================================
// FUZZING TESTS
// ================================================================================================

// Fuzz test that validates verify_u256_to_native_amount_conversion (U256 → Felt)
// with random realistic amounts for all scale exponents (0..=18).
#[tokio::test]
async fn test_scale_down_realistic_scenarios_fuzzing() -> anyhow::Result<()> {
    const CASES_PER_SCALE: usize = 2;
    const MAX_SCALE: u32 = 18;

    let mut rng = StdRng::seed_from_u64(42);

    let min_x = U256::from(10_000_000_000_000u64); // 1e13
    let desired_max_x = U256::from_dec_str("1000000000000000000000000").unwrap(); // 1e24
    let max_y = U256::from(FungibleAsset::MAX_AMOUNT); // 2^63 - 2^31

    for scale in 0..=MAX_SCALE {
        let scale_factor = U256::from(10u64).pow(U256::from(scale));

        // Ensure x always scales down into a y that fits the fungible-token bound.
        let max_x = desired_max_x.min(max_y * scale_factor);

        assert!(max_x > min_x, "max_x must exceed min_x for scale={scale}");

        // Sample x uniformly from [min_x, max_x).
        let span: u128 = (max_x - min_x).try_into().expect("span fits in u128");

        for _ in 0..CASES_PER_SCALE {
            let offset: u128 = rng.random_range(0..span);
            let x = EthAmount::from_u256(min_x + U256::from(offset));
            assert_scale_down_ok(x, scale).await?;
        }
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
    let scale_exp = 10u32;
    let scale = 10u64.pow(scale_exp);
    let x_val = 5u64 * scale + (scale - 1);
    let x = EthAmount::from_u256(U256::from(x_val));

    assert_scale_down_ok(x, scale_exp).await?;
    Ok(())
}

#[tokio::test]
async fn test_scale_down_remainder_exactly_scale_fails() {
    // If remainder z = scale, it should fail
    // Pick s=10, x = 6*scale (where scale = 10^10)
    // The correct y should be 6, so providing y=5 should fail
    let scale_exp = 10u32;
    let scale = 10u64.pow(scale_exp);
    let x = EthAmount::from_u256(U256::from(6u64 * scale));

    // Calculate the correct y using scale_to_token_amount
    let correct_y = x.scale_to_token_amount(scale_exp).unwrap().as_canonical_u64();
    assert_eq!(correct_y, 6);

    // Providing wrong_y = correct_y - 1 should fail with ERR_REMAINDER_TOO_LARGE
    let wrong_y = correct_y - 1;
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
    let y = x.scale_to_token_amount(scale_exp).unwrap().as_canonical_u64();

    let x_felts = x.to_elements();

    // Build the MASM script inline
    let script_code = format!(
        r#"
        use miden::core::sys
        use agglayer::common::asset_conversion
        
        begin
            # Push expected quotient y used for verification (not returned as an output)
            push.{}
            
            # Push scale_exp
            push.{}
            
            # Push x as 8 u32 limbs in the order expected by the verifier
            push.{}.{}.{}.{}.{}.{}.{}.{}
            
            # Call the scale down procedure (verifies conversion and may panic on failure)
            exec.asset_conversion::verify_u256_to_native_amount_conversion
            
            # Truncate stack so the program returns with no public outputs (Outputs: [])
            exec.sys::truncate_stack
        end
        "#,
        y,
        scale_exp,
        x_felts[7].as_canonical_u64(),
        x_felts[6].as_canonical_u64(),
        x_felts[5].as_canonical_u64(),
        x_felts[4].as_canonical_u64(),
        x_felts[3].as_canonical_u64(),
        x_felts[2].as_canonical_u64(),
        x_felts[1].as_canonical_u64(),
        x_felts[0].as_canonical_u64(),
    );

    // Execute the script - verify_u256_to_native_amount_conversion panics on invalid
    // conversions, so successful execution is sufficient validation
    execute_masm_script(&script_code).await?;

    Ok(())
}

/// Exercises u128_sub_no_underflow when x > 2^64, so x has distinct high limbs (x2 != x3).
///
/// The u128 subtraction splits each 128-bit operand into two 64-bit halves. This test
/// ensures the high-half subtraction and borrow propagation work correctly when x_high
/// is non-zero.
#[tokio::test]
async fn test_scale_down_high_limb_subtraction() -> anyhow::Result<()> {
    let x_val = U256::from_dec_str("18999999999999999999").unwrap();

    // Verify the u32 limb structure that makes this test meaningful:
    //   x = x0 + x1*2^32 + x2*2^64 + x3*2^96
    // x2 and x3 must differ - otherwise the high subtraction is trivially correct
    // regardless of limb ordering.
    let x2 = ((x_val >> 64) & U256::from(u32::MAX)).as_u32();
    let x3 = ((x_val >> 96) & U256::from(u32::MAX)).as_u32();
    assert_eq!(x2, 1, "x2 must be non-zero for the high subtraction to be non-trivial");
    assert_eq!(x3, 0, "x3 must differ from x2");

    let x = EthAmount::from_u256(x_val);
    assert_scale_down_ok(x, 18).await?;
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
    let result = packed_u32_elements_to_bytes(&limbs);
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
    let result = packed_u32_elements_to_bytes(&limbs);
    assert_eq!(result.len(), 32);
    assert!(result.iter().all(|&b| b == 0));

    // Test case 2: All max u32 values (maximum)
    let limbs = [Felt::new(u32::MAX as u64); 8];
    let result = packed_u32_elements_to_bytes(&limbs);
    assert_eq!(result.len(), 32);
    assert!(result.iter().all(|&b| b == 255));
}
