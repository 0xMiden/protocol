use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::errors::tx_kernel::ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{FeeConversionInfo, commit_fee_conversion_info};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_CONVERSION_INFO_COMMITMENT_MISMATCH,
    ERR_FEE_CONVERSION_INFO_MISSING,
    ERR_FEE_CONVERSION_INFO_NOT_NATIVE,
};
use miden_standards::note::TxFeeNote;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use rstest::rstest;

use super::{
    ECDSA_K256_KECCAK_AUTH_CYCLES,
    FALCON_512_POSEIDON2_AUTH_CYCLES,
    PAY_FEE_CYCLES,
    POST_AUTH_EPILOGUE_BASE_CYCLES,
    POST_AUTH_EPILOGUE_PER_NOTE_CYCLES,
    VERIFICATION_BASE_FEE,
};

// HELPER FUNCTIONS
// ================================================================================================

/// The post-auth epilogue estimate used by `pay_fee` for a transaction with the given number of
/// output notes (including the fee note).
fn post_auth_epilogue_estimate(num_output_notes: usize) -> usize {
    POST_AUTH_EPILOGUE_BASE_CYCLES + POST_AUTH_EPILOGUE_PER_NOTE_CYCLES * num_output_notes
}

/// Executes an empty transaction against a singlesig wallet on a fee-charging mock chain and
/// returns the executed transaction together with the wallet's initial nonce.
///
/// The fee is paid in the native fee asset via [`FeeConversionInfo::one_to_one`] at rate 1/1, the
/// only conversion info `pay_fee` accepts.
async fn execute_fee_paying_tx(
    auth_scheme: AuthScheme,
) -> anyhow::Result<(ExecutedTransaction, miden_protocol::Felt)> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account =
        builder.add_existing_wallet_with_assets(Auth::BasicAuth { auth_scheme }, [fee_asset])?;
    let mock_chain = builder.build()?;

    let initial_nonce = account.nonce();

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([9u32, 10, 11, 12]),
    );

    let executed_transaction = mock_chain
        .build_transaction(account.id())
        .auth_args(args)
        .add_advice_map_entry(args, advice_value)
        .build()?
        .execute()
        .await?;

    Ok((executed_transaction, initial_nonce))
}

// TESTS
// ================================================================================================

/// The singlesig auth procedure pays the transaction fee by creating a TX_FEE note funded with
/// the native fee asset, and the paid amount covers the fee required for the actual number of
/// cycles the transaction took. This is the regression guard for the cycle-estimate constants.
#[rstest]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn singlesig_pays_fee_note(#[case] auth_scheme: AuthScheme) -> anyhow::Result<()> {
    let (executed_transaction, _) = execute_fee_paying_tx(auth_scheme).await?;

    // exactly one output note is created: the fee note
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    assert_eq!(output_note.metadata().tag(), TxFeeNote::TAG);
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);

    // the note carries exactly one asset: the native fee asset
    let assets = output_note.assets();
    assert_eq!(assets.num_assets(), 1);
    let asset = assets.iter().next().expect("fee note should carry an asset");
    let fee_asset = asset.unwrap_fungible();
    assert_eq!(fee_asset.faucet_id(), ACCOUNT_ID_FEE_FAUCET.try_into()?);

    // the paid amount covers the fee required for the actual cycle count, and the overshoot is
    // bounded (the estimate should not overpay by more than a few base fee units)
    let required_fee = executed_transaction.compute_fee();
    assert!(
        fee_asset.amount() >= required_fee,
        "paid fee {} should cover the required fee {required_fee}",
        fee_asset.amount()
    );
    let max_overpayment = u64::from(3 * VERIFICATION_BASE_FEE);
    assert!(
        fee_asset.amount().as_u64() <= required_fee.as_u64() + max_overpayment,
        "paid fee {} should not exceed the required fee {required_fee} by more than \
         {max_overpayment}",
        fee_asset.amount()
    );

    Ok(())
}

/// The fee note created by the auth procedure has the serial number derived by
/// [`TxFeeNote::derive_serial_number`], so clients can predict the note ID before execution.
#[tokio::test]
async fn fee_note_serial_is_derivable() -> anyhow::Result<()> {
    let (executed_transaction, initial_nonce) =
        execute_fee_paying_tx(AuthScheme::Falcon512Poseidon2).await?;

    let output_note = executed_transaction.output_notes().get_note(0);
    let assets = output_note.assets();
    let asset = assets.iter().next().expect("fee note should carry an asset");

    let account_id = executed_transaction.account_id();
    let ref_block_num = executed_transaction.tx_inputs().block_header().block_num();

    let expected_note: Note = TxFeeNote::builder()
        .sender(account_id)
        .serial_number(TxFeeNote::derive_serial_number(account_id, initial_nonce, ref_block_num))
        .asset(*asset)
        .build()?
        .into();

    assert_eq!(output_note.id(), expected_note.id());

    Ok(())
}

/// Executes an empty transaction on a fee-charging chain with the given advice-map entry set as
/// the auth args, returning the raw execution result for error assertions.
async fn execute_with_conversion_entry(
    entry: (Word, Vec<Felt>),
) -> anyhow::Result<Result<ExecutedTransaction, miden_tx::TransactionExecutorError>> {
    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mock_chain = builder.build()?;

    let (key, value) = entry;
    let result = mock_chain
        .build_transaction(account.id())
        .auth_args(key)
        .add_advice_map_entry(key, value)
        .build()?
        .execute()
        .await;

    Ok(result)
}

/// A tampered advice-map preimage that does not hash to the auth args commitment aborts the
/// transaction.
#[tokio::test]
async fn conversion_commitment_mismatch_aborts() -> anyhow::Result<()> {
    let payment_faucet_id = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?;
    let conversion_info = FeeConversionInfo::new(payment_faucet_id, 2, 1)?;
    let salt = Word::from([5u32, 6, 7, 8]);

    let (key, mut value) = commit_fee_conversion_info(conversion_info, salt);
    // tamper with the conversion rate in the preimage
    value[6] += Felt::from(1u32);

    let result = execute_with_conversion_entry((key, value)).await?;

    assert_transaction_executor_error!(result, ERR_FEE_CONVERSION_INFO_COMMITMENT_MISMATCH);

    Ok(())
}

/// The fee is payable only in the chain's native fee asset at par, so a foreign payment faucet or
/// a rate other than 1/1 aborts.
#[rstest]
#[case::foreign_faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2, 1, 1)]
#[case::rate_above_par(ACCOUNT_ID_FEE_FAUCET, 2, 1)]
#[case::rate_below_par(ACCOUNT_ID_FEE_FAUCET, 1, 3)]
#[tokio::test]
async fn non_native_conversion_info_aborts(
    #[case] payment_faucet: u128,
    #[case] rate_num: u64,
    #[case] rate_den: u64,
) -> anyhow::Result<()> {
    let conversion_info = FeeConversionInfo::new(payment_faucet.try_into()?, rate_num, rate_den)?;
    let entry = commit_fee_conversion_info(conversion_info, Word::from([5u32, 6, 7, 8]));

    let result = execute_with_conversion_entry(entry).await?;

    assert_transaction_executor_error!(result, ERR_FEE_CONVERSION_INFO_NOT_NATIVE);

    Ok(())
}

/// On a chain with a zero verification base fee, no fee note is created and the transaction
/// behaves as before.
#[tokio::test]
async fn no_fee_note_on_zero_fee_chain() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mock_chain = builder.build()?;

    let executed_transaction =
        mock_chain.build_transaction(account.id()).build()?.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 0);

    Ok(())
}

/// Fee payment fails with the specific vault error when the account does not hold enough of the
/// fee asset.
#[tokio::test]
async fn fee_payment_fails_without_fee_asset() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mock_chain = builder.build()?;

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([9u32, 10, 11, 12]),
    );

    let result = mock_chain
        .build_transaction(account.id())
        .auth_args(args)
        .add_advice_map_entry(args, advice_value)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW
    );

    Ok(())
}

/// A non-zero fee without a conversion info entry for the auth args aborts with a dedicated error.
#[tokio::test]
async fn fee_payment_fails_without_conversion_info() -> anyhow::Result<()> {
    let fee_asset: Asset = FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 1_000_000)?.into();

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [fee_asset],
    )?;
    let mock_chain = builder.build()?;

    let result = mock_chain.build_transaction(account.id()).build()?.execute().await;

    assert_transaction_executor_error!(result, ERR_FEE_CONVERSION_INFO_MISSING);

    Ok(())
}

/// The static cycle-estimate constants are upper bounds of the actually measured cycle counts.
/// If this test fails, the constants in `miden::standards::auth::signature` /
/// `miden::standards::fee` must be raised (and the mirrors above updated).
#[rstest]
#[case::falcon(AuthScheme::Falcon512Poseidon2, FALCON_512_POSEIDON2_AUTH_CYCLES)]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak, ECDSA_K256_KECCAK_AUTH_CYCLES)]
#[tokio::test]
async fn cycle_estimates_are_upper_bounds(
    #[case] auth_scheme: AuthScheme,
    #[case] scheme_cycles: usize,
) -> anyhow::Result<()> {
    let (executed_transaction, _) = execute_fee_paying_tx(auth_scheme).await?;

    let measurements = executed_transaction.measurements();

    // the whole auth procedure (fee payment + summary + signature verification) must stay below
    // the scheme estimate plus the pay_fee margin
    assert!(
        measurements.auth_procedure <= scheme_cycles + PAY_FEE_CYCLES,
        "auth procedure took {} cycles, exceeding the estimate of {}",
        measurements.auth_procedure,
        scheme_cycles + PAY_FEE_CYCLES,
    );

    // the post-auth epilogue must stay below its margin (one output note: the fee note)
    let post_auth_epilogue = measurements.epilogue - measurements.auth_procedure;
    let epilogue_estimate = post_auth_epilogue_estimate(1);
    assert!(
        post_auth_epilogue <= epilogue_estimate,
        "post-auth epilogue took {post_auth_epilogue} cycles, exceeding the estimate of \
         {epilogue_estimate}",
    );

    Ok(())
}

/// The post-auth epilogue estimate must also hold for a note-heavy transaction, since the
/// epilogue cost scales with the number of output notes. Creates a large number of output notes
/// via a transaction script and asserts the measured post-auth epilogue stays within the margin.
#[tokio::test]
async fn post_auth_epilogue_estimate_covers_note_heavy_tx() -> anyhow::Result<()> {
    const NUM_NOTES: usize = 64;

    let fee_asset: Asset = FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 1_000_000)?.into();

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [fee_asset],
    )?;
    let mock_chain = builder.build()?;

    // create NUM_NOTES private, asset-less output notes with distinct recipients
    let mut body = String::new();
    for i in 0..NUM_NOTES {
        body.push_str(&format!(
            "
            push.{i}.0.0.1
            push.{note_type}
            push.0
            # => [tag, note_type, RECIPIENT, pad(16)]

            call.::miden::standards::note::note_creator::create_note
            # => [note_idx, pad(21)]

            drop dropw drop
            # => [pad(16)]
            ",
            note_type = NoteType::Private as u8,
        ));
    }
    let tx_script_src = format!("@transaction_script\npub proc main\n{body}\nend");
    let tx_script = CodeBuilder::default().compile_tx_script(&tx_script_src)?;

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(ACCOUNT_ID_FEE_FAUCET.try_into()?),
        Word::from([9u32, 10, 11, 12]),
    );

    let executed_transaction = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .auth_args(args)
        .add_advice_map_entry(args, advice_value)
        .build()?
        .execute()
        .await?;

    // all script-created notes plus the fee note are present
    assert_eq!(executed_transaction.output_notes().num_notes(), NUM_NOTES + 1);

    let measurements = executed_transaction.measurements();
    let post_auth_epilogue = measurements.epilogue - measurements.auth_procedure;
    let epilogue_estimate = post_auth_epilogue_estimate(NUM_NOTES + 1);
    assert!(
        post_auth_epilogue <= epilogue_estimate,
        "post-auth epilogue took {post_auth_epilogue} cycles for {NUM_NOTES} output notes, \
         exceeding the estimate of {epilogue_estimate}",
    );

    Ok(())
}
