use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
};
use miden_standards::account::auth::{FeeConversionInfo, commit_fee_conversion_info};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_BOUND_DENOMINATOR_ZERO,
    ERR_FEE_PAYMENT_ASSET_NOT_NATIVE,
    ERR_FEE_PAYMENT_EXCEEDS_BOUND,
};
use miden_testing::{Auth, MockChain, MockTransaction, assert_transaction_executor_error};
use rstest::rstest;

use super::VERIFICATION_BASE_FEE;

/// Builds a transaction whose script runs `fee::assert_fee_bound` with the given inputs and
/// asserts that the payment comes back unchanged.
fn bound_transaction(
    payment_faucet: AccountId,
    payment_amount: u64,
    fee_amount: u64,
    bound_num: u64,
    bound_den: u64,
) -> anyhow::Result<MockTransaction> {
    let fee_faucet_id: AccountId = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [fee_asset],
    )?;
    let mock_chain = builder.build()?;

    let src = format!(
        r#"
        use miden::standards::fee

        @transaction_script
        pub proc main
            push.{fee_amount}.{payment_amount}
            push.{prefix}.{suffix}
            push.{bound_den}.{bound_num}
            exec.fee::assert_fee_bound
            # the payment must come back unchanged
            push.{suffix} assert_eq
            push.{prefix} assert_eq
            push.{payment_amount} assert_eq
        end
        "#,
        suffix = payment_faucet.suffix(),
        prefix = payment_faucet.prefix().as_felt(),
    );
    let tx_script = CodeBuilder::default().compile_tx_script(&src)?;

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([9u32, 10, 11, 12]),
    );

    mock_chain
        .build_transaction(account.id())
        .auth_args(args)
        .add_advice_map_entry(args, advice_value)
        .tx_script(tx_script)
        .build()
}

/// Payments at or below the bound are accepted; the boundary itself is inclusive.
#[rstest]
#[case::exact_one_to_one(100, 100, 1, 1)]
#[case::exact_double(200, 100, 2, 1)]
#[case::exact_three_halves(150, 100, 3, 2)]
#[case::below_bound(1, 100, 2, 1)]
#[case::zero_fee_zero_payment(0, 0, 2, 1)]
// a naive u64 product would wrap 2^32 * 2^32 to zero and reject this
#[case::wide_bound_product(1, 4294967296, 4294967296, 1)]
#[tokio::test]
async fn within_bound_passes(
    #[case] paid: u64,
    #[case] fee: u64,
    #[case] num: u64,
    #[case] den: u64,
) -> anyhow::Result<()> {
    let fee_faucet_id: AccountId = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    bound_transaction(fee_faucet_id, paid, fee, num, den)?.execute().await?;
    Ok(())
}

/// Payments above the bound are rejected.
#[rstest]
#[case::one_over_double(201, 100, 2, 1)]
#[case::one_over_three_halves(151, 100, 3, 2)]
#[case::nonzero_payment_on_zero_fee(1, 0, 2, 1)]
// a naive u64 product would wrap 2^32 * 2^32 to zero and accept this
#[case::wide_payment_product(4294967296, 1, 1, 4294967296)]
#[tokio::test]
async fn exceeding_bound_aborts(
    #[case] paid: u64,
    #[case] fee: u64,
    #[case] num: u64,
    #[case] den: u64,
) -> anyhow::Result<()> {
    let fee_faucet_id: AccountId = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let result = bound_transaction(fee_faucet_id, paid, fee, num, den)?.execute().await;
    assert_transaction_executor_error!(result, ERR_FEE_PAYMENT_EXCEEDS_BOUND);
    Ok(())
}

/// A zero denominator would make the bound vacuous, so it is rejected.
#[tokio::test]
async fn zero_denominator_aborts() -> anyhow::Result<()> {
    let fee_faucet_id: AccountId = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let result = bound_transaction(fee_faucet_id, 100, 100, 1, 0)?.execute().await;
    assert_transaction_executor_error!(result, ERR_FEE_BOUND_DENOMINATOR_ZERO);
    Ok(())
}

/// The bound compares against a fee denominated in the native fee asset, so a payment in any
/// other asset is rejected.
#[tokio::test]
async fn non_native_payment_asset_aborts() -> anyhow::Result<()> {
    let payment_faucet: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?;
    let result = bound_transaction(payment_faucet, 1, 100, 1, 1)?.execute().await;
    assert_transaction_executor_error!(result, ERR_FEE_PAYMENT_ASSET_NOT_NATIVE);
    Ok(())
}
