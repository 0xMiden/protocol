use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_processor::ExecutionError;
use miden_processor::operation::OperationError;
use miden_protocol::account::Account;
use miden_protocol::errors::MasmError;
use miden_protocol::errors::tx_kernel::{
    ERR_TX_COMPUTE_FEE_EXCLUDE_NOTE_INDEX_OUT_OF_BOUNDS,
    ERR_TX_COMPUTE_FEE_EXCLUDE_NOTES_COMMITMENT_MISMATCH,
    ERR_TX_COMPUTE_FEE_EXCLUDE_NOTES_COUNT_EXCEEDS_MAX,
    ERR_TX_COMPUTE_FEE_EXCLUDE_NOTES_UNSORTED,
    ERR_TX_COMPUTE_FEE_EXTRA_CYCLES_NOT_U32,
};
use miden_protocol::testing::tx::TransactionFee;
use miden_protocol::{Felt, Hasher, MAX_OUTPUT_NOTES_PER_TX, Word};
use rstest::rstest;

use crate::kernel_tests::tx::ExecutionOutputExt;
use crate::{Auth, MockChain, assert_execution_error};

const VERIFICATION_BASE_FEE: u32 = 500;

// `num_extra_cycles` is chosen large enough to dominate the live cycle count of the small test
// program (a few thousand cycles). This makes `ilog2(clk + num_extra_cycles)` deterministically
// equal to 28, so the fee is `verification_base_fee * (28 + 1)` regardless of the exact `clk`.
const NUM_EXTRA_CYCLES: u32 = 1 << 28;
const EXPECTED_VERIFICATION_CYCLES: u32 = 29;

/// Builds a mock chain whose block header sets a non-zero verification base fee, together with a
/// mock account to execute transactions against.
fn mock_chain_with_fee() -> anyhow::Result<(MockChain, Account)> {
    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;
    Ok((mock_chain, account))
}

/// Builds the commitment over the given output note indices that the kernel's `compute_fee`
/// procedure validates the excluded notes against, matching the on-chain `hash_elements` scheme.
///
/// Returns the commitment together with the index elements that must be inserted into the advice
/// map under the commitment key so that the kernel can load them.
pub fn build_exclude_notes_commitment(indices: &[u32]) -> (Word, Vec<Felt>) {
    let elements: Vec<Felt> = indices.iter().copied().map(Felt::from).collect();
    let commitment = Hasher::hash_elements(&elements);
    (commitment, elements)
}

/// The transaction code that creates `num_output_notes` output notes (so that exclude indices below
/// that count are in bounds), then computes the fee with the given `num_extra_cycles` and the
/// provided `EXCLUDE_NOTES_COMMITMENT` (already formatted for a MASM `push`).
fn compute_fee_code(
    exclude_notes_commitment: &str,
    num_extra_cycles: u64,
    num_output_notes: u32,
) -> String {
    let create_output_notes =
        "exec.util::create_default_note drop\n".repeat(num_output_notes as usize);
    format!(
        "
        use miden::tx_kernel_core::prologue
        use miden::protocol::tx
        use miden::core::sys
        use mock::util

        begin
            exec.prologue::prepare_transaction

            {create_output_notes}

            push.{exclude_notes_commitment}
            push.{num_extra_cycles}
            exec.tx::compute_fee
            # => [fee_amount]

            exec.sys::truncate_stack
        end
        "
    )
}

#[tokio::test]
async fn get_fee_faucet_id_returns_reference_block_fee_faucet() -> anyhow::Result<()> {
    let (mock_chain, account) = mock_chain_with_fee()?;
    let tx_context = mock_chain.build_transaction(account).build()?;

    let fee_faucet_id = tx_context.tx_inputs().block_header().fee_parameters().fee_faucet_id();

    let code = "
        use miden::tx_kernel_core::prologue
        use miden::protocol::tx
        use miden::core::sys

        begin
            exec.prologue::prepare_transaction

            exec.tx::get_fee_faucet_id
            # => [fee_faucet_id_suffix, fee_faucet_id_prefix]

            exec.sys::truncate_stack
        end
    ";
    let exec_output = tx_context.execute_code(code).await?;

    assert_eq!(exec_output.get_stack_element(0), fee_faucet_id.suffix());
    assert_eq!(exec_output.get_stack_element(1), fee_faucet_id.prefix().as_felt());

    Ok(())
}

/// The `fee::native_conversion_info` standards helper returns the reference block's fee faucet
/// ID at rate 1/1 in the `ConversionInfo` layout expected by `fee::pay_fee`. This pins the word
/// layout `[faucet_id_suffix, faucet_id_prefix, rate_num, rate_den]`.
#[tokio::test]
async fn native_conversion_info_returns_native_fee_faucet_at_rate_one() -> anyhow::Result<()> {
    let (mock_chain, account) = mock_chain_with_fee()?;
    let tx_context = mock_chain.build_transaction(account).build()?;

    let fee_faucet_id = tx_context.tx_inputs().block_header().fee_parameters().fee_faucet_id();

    let code = "
        use miden::tx_kernel_core::prologue
        use miden::core::sys

        begin
            exec.prologue::prepare_transaction

            exec.::miden::standards::fee::native_conversion_info
            # => [fee_faucet_id_suffix, fee_faucet_id_prefix, rate_num, rate_den]

            exec.sys::truncate_stack
        end
    ";
    let exec_output = tx_context.execute_code(code).await?;

    assert_eq!(exec_output.get_stack_element(0), fee_faucet_id.suffix());
    assert_eq!(exec_output.get_stack_element(1), fee_faucet_id.prefix().as_felt());
    assert_eq!(exec_output.get_stack_element(2), Felt::from(1u32));
    assert_eq!(exec_output.get_stack_element(3), Felt::from(1u32));

    Ok(())
}

#[tokio::test]
async fn compute_fee_adds_extra_cycles() -> anyhow::Result<()> {
    let (mock_chain, account) = mock_chain_with_fee()?;
    let mock_tx = mock_chain.build_transaction(account).build()?;

    let code = compute_fee_code("0.0.0.0", u64::from(NUM_EXTRA_CYCLES), 0);
    let verification_base_fee =
        mock_tx.tx_inputs().block_header().fee_parameters().verification_base_fee();
    let exec_output = mock_tx.execute_code(&code).await?;

    let expected_fee = verification_base_fee * EXPECTED_VERIFICATION_CYCLES;

    assert_eq!(exec_output.get_stack_element(0), Felt::from(expected_fee));

    Ok(())
}

/// This test captures the VM cycle count right before invoking `compute_fee` with zero extra
/// cycles and checks the computed fee matches matches the expected fee using the captured clock.
#[tokio::test]
async fn compute_fee_derives_fee_from_concrete_clk() -> anyhow::Result<()> {
    let (mock_chain, account) = mock_chain_with_fee()?;
    let mock_tx = mock_chain.build_transaction(account).build()?;

    // Capture `clk`, then compute the fee with an empty exclude-notes commitment and no extra
    // cycles.
    let code = "
        use miden::tx_kernel_core::prologue
        use miden::protocol::tx
        use miden::core::sys

        begin
            exec.prologue::prepare_transaction

            clk padw push.0
            # => [num_extra_cycles = 0, EXCLUDE_NOTES_COMMITMENT = EMPTY_WORD, captured_clk]

            exec.tx::compute_fee
            # => [fee_amount, captured_clk]

            exec.sys::truncate_stack
        end
        ";

    let exec_output = mock_tx.execute_code(code).await?;

    let actual_fee = exec_output.get_stack_element(0).as_canonical_u64();
    let captured_clk = u32::try_from(exec_output.get_stack_element(1).as_canonical_u64())?;

    let expected_fee = TransactionFee::new(captured_clk.next_power_of_two())
        .compute_fee(mock_tx.tx_inputs().block_header().fee_parameters());

    // This assertion is somewhat brittle. If it fails, it is likely because log2(captured clock)
    // and log2(actual clock) differ, which shouldn't happen most of the time.
    assert_eq!(actual_fee, expected_fee.as_u64());

    Ok(())
}

#[tokio::test]
async fn compute_fee_fails_on_non_u32_extra_cycles() -> anyhow::Result<()> {
    let (mock_chain, account) = mock_chain_with_fee()?;
    let mock_tx = mock_chain.build_transaction(account).build()?;

    // A value that exceeds u32::MAX is not a valid number of extra cycles.
    let code = compute_fee_code("0.0.0.0", u64::from(u32::MAX) + 1, 0);
    let exec_output = mock_tx.execute_code(&code).await;

    // `u32assert` raises a `U32AssertionFailed` (not a plain `FailedAssertion`), so match the
    // variant explicitly and assert on its error code.
    assert_execution_error!(
        exec_output,
        matches ExecutionError::OperationError {
            err: OperationError::U32AssertionFailed { err_code, .. },
            ..
        } if err_code == ERR_TX_COMPUTE_FEE_EXTRA_CYCLES_NOT_U32.code()
    );

    Ok(())
}

#[tokio::test]
async fn compute_fee_fails_on_exclude_notes_commitment_mismatch() -> anyhow::Result<()> {
    let (mock_chain, account) = mock_chain_with_fee()?;

    // Seed the advice map with indices that do not hash to the provided commitment.
    let (commitment, _) = build_exclude_notes_commitment(&[1, 2, 3]);
    let (_, mismatching_elements) = build_exclude_notes_commitment(&[1, 2, 4]);
    let mock_tx = mock_chain
        .build_transaction(account)
        .add_advice_map_entry(commitment, mismatching_elements)
        .build()?;

    let code = compute_fee_code(&commitment.to_string(), 0, 0);
    let exec_output = mock_tx.execute_code(&code).await;

    assert_execution_error!(exec_output, ERR_TX_COMPUTE_FEE_EXCLUDE_NOTES_COMMITMENT_MISMATCH);

    Ok(())
}

/// The transaction creates 6 output notes, so exclude indices are in bounds only if they are below
/// that count.
#[rstest]
// One more index than allowed.
#[case::exceeds_max_output_notes(
    (0..=MAX_OUTPUT_NOTES_PER_TX as u32).collect(),
    ERR_TX_COMPUTE_FEE_EXCLUDE_NOTES_COUNT_EXCEEDS_MAX
)]
// Index 6 is out of bounds.
#[case::out_of_bounds(vec![6],  ERR_TX_COMPUTE_FEE_EXCLUDE_NOTE_INDEX_OUT_OF_BOUNDS)]
// In-bounds indices that are not in ascending order.
#[case::unsorted(vec![3, 1], ERR_TX_COMPUTE_FEE_EXCLUDE_NOTES_UNSORTED)]
// In-bounds indices with a duplicate, which the strict-increasing check must reject.
#[case::duplicate(vec![2, 2, 3], ERR_TX_COMPUTE_FEE_EXCLUDE_NOTES_UNSORTED)]
#[tokio::test]
async fn compute_fee_fails_on_invalid_exclude_notes(
    #[case] exclude_indices: Vec<u32>,
    #[case] expected_error: MasmError,
) -> anyhow::Result<()> {
    let num_output_notes = 6;
    let (mock_chain, account) = mock_chain_with_fee()?;

    let (commitment, elements) = build_exclude_notes_commitment(&exclude_indices);
    let mock_tx = mock_chain
        .build_transaction(account)
        .add_advice_map_entry(commitment, elements)
        .build()?;

    let code = compute_fee_code(&commitment.to_string(), 0, num_output_notes);
    let exec_output = mock_tx.execute_code(&code).await;

    assert_execution_error!(exec_output, expected_error);

    Ok(())
}

/// The transaction creates six output notes, so the excluded indices below are all in bounds. The
/// cases cover zero, one and multiple excluded notes, to exercise all branches of the sorting and
/// uniqueness validation.
#[rstest]
// No excluded notes.
#[case::none(vec![])]
// A single excluded note skips the adjacent-index comparison entirely.
#[case::single(vec![2])]
// Multiple sorted, duplicate-free indices, each below the six output notes.
#[case::multiple(vec![1, 3, 5])]
#[tokio::test]
async fn compute_fee_accepts_sorted_in_bounds_exclude_notes(
    #[case] exclude_indices: Vec<u32>,
) -> anyhow::Result<()> {
    let (mock_chain, account) = mock_chain_with_fee()?;

    let (commitment, elements) = build_exclude_notes_commitment(&exclude_indices);
    let mock_tx = mock_chain
        .build_transaction(account)
        .add_advice_map_entry(commitment, elements)
        .build()?;

    let code = compute_fee_code(&commitment.to_string(), u64::from(NUM_EXTRA_CYCLES), 6);
    let verification_base_fee =
        mock_tx.tx_inputs().block_header().fee_parameters().verification_base_fee();
    let exec_output = mock_tx.execute_code(&code).await?;

    // Excluding notes does not affect the fee yet, so it is still `base_fee * verification_cycles`.
    let expected_fee = verification_base_fee * EXPECTED_VERIFICATION_CYCLES;

    assert_eq!(exec_output.get_stack_element(0), Felt::from(expected_fee));

    Ok(())
}
