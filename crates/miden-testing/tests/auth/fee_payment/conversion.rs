use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_CONVERSION_RATE_DENOMINATOR_ZERO,
    ERR_FEE_CONVERSION_RATE_NUMERATOR_ZERO,
    ERR_FEE_CONVERTED_AMOUNT_OVERFLOW,
};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use rstest::rstest;

// HELPER FUNCTIONS
// ================================================================================================

/// Executes a transaction script that converts `amount` at the rate `rate_num / rate_den` via
/// `fee::convert_amount`, asserting the result in-VM when `expected` is `Some`.
///
/// `pay_fee` pins the payment to the native fee asset at rate 1/1, so `convert_amount` is
/// exercised directly rather than through a fee-paying transaction.
async fn convert_amount(
    amount: u64,
    rate_num: u64,
    rate_den: u64,
    expected: Option<u64>,
) -> anyhow::Result<Result<(), miden_tx::TransactionExecutorError>> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::basic_ecdsa())?;
    let mock_chain = builder.build()?;

    let check = match expected {
        Some(expected) => format!(
            r#"push.{expected}
            assert_eq.err="convert_amount returned an unexpected amount""#
        ),
        None => "drop".to_string(),
    };

    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::standards::fee

        @transaction_script
        pub proc main
            push.{rate_den}.{rate_num}.{amount}
            # => [amount, rate_num, rate_den]

            exec.fee::convert_amount
            # => [converted_amount]

            {check}
        end
        "#
    ))?;

    let result = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    Ok(result.map(|_| ()))
}

// TESTS
// ================================================================================================

/// The converted amount is `ceil(amount * rate_num / rate_den)`.
///
/// The large rate scales between decimal conventions (10^16 / 10^4, a net factor of 10^12 as for
/// an 18-decimals vs 6-decimals asset pair): the numerator exceeds a u32 and the intermediate
/// product exceeds a u64, yet the conversion stays exact.
#[rstest]
#[case::identity(8500, 1, 1, 8500)]
#[case::doubling(8500, 2, 1, 17000)]
#[case::exact_division(9000, 1, 3, 3000)]
#[case::rounds_up(8500, 1, 3, 2834)]
#[case::zero_amount(0, 7, 5, 0)]
#[case::large_rate(8500, 10u64.pow(16), 10u64.pow(4), 8500 * 10u64.pow(12))]
#[tokio::test]
async fn convert_amount_rounds_up(
    #[case] amount: u64,
    #[case] rate_num: u64,
    #[case] rate_den: u64,
    #[case] expected: u64,
) -> anyhow::Result<()> {
    convert_amount(amount, rate_num, rate_den, Some(expected)).await??;

    Ok(())
}

/// A zero rate numerator or denominator is rejected by the in-VM rate validation.
#[rstest]
#[case::zero_numerator(0, 1, ERR_FEE_CONVERSION_RATE_NUMERATOR_ZERO)]
#[case::zero_denominator(2, 0, ERR_FEE_CONVERSION_RATE_DENOMINATOR_ZERO)]
#[tokio::test]
async fn zero_conversion_rate_aborts(
    #[case] rate_num: u64,
    #[case] rate_den: u64,
    #[case] expected_error: miden_protocol::errors::MasmError,
) -> anyhow::Result<()> {
    let result = convert_amount(8500, rate_num, rate_den, None).await?;

    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// A quotient that does not fit into a fungible asset amount aborts instead of wrapping: rate_num
/// 2^62 pushes it beyond a u64 and rate_num 2^50 lands it in [2^63, 2^64), exercising both
/// overflow asserts.
#[rstest]
#[case::quotient_exceeds_u64(1u64 << 62)]
#[case::quotient_exceeds_max_amount(1u64 << 50)]
#[tokio::test]
async fn converted_amount_overflow_aborts(#[case] rate_num: u64) -> anyhow::Result<()> {
    let result = convert_amount(8500, rate_num, 1, None).await?;

    assert_transaction_executor_error!(result, ERR_FEE_CONVERTED_AMOUNT_OVERFLOW);

    Ok(())
}
