use core::num::NonZeroU16;

use miden_protocol::account::auth::{AuthScheme, PublicKey};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::{ExecutedTransaction, TransactionSummary};
use miden_protocol::{Word, ZERO};
use miden_standards::account::auth::{Approver, ApproverSet, FeeConversionInfo, MultisigAuthArgs};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_MULTISIG_APPROVAL_EXPIRED;
use miden_standards::note::TxFeeNote;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rstest::rstest;

use super::super::multisig::{MultisigAuthArgsExt, setup_keys_and_authenticators_with_scheme};
use super::{
    FALCON_512_POSEIDON2_AUTH_CYCLES,
    MULTISIG_AUTH_BASE_CYCLES,
    PAY_FEE_CYCLES,
    VERIFICATION_BASE_FEE,
    assert_single_fee_note,
};

// HELPER FUNCTIONS
// ================================================================================================

/// The cycle estimate the multisig auth component passes to `pay_fee` for the given number of
/// signers, plus pay_fee's own tail margin. Used as the upper bound for the measured auth
/// procedure cycles.
fn multisig_auth_estimate(num_signers: usize) -> usize {
    num_signers * FALCON_512_POSEIDON2_AUTH_CYCLES + MULTISIG_AUTH_BASE_CYCLES + PAY_FEE_CYCLES
}

/// Builds an [`ApproverSet`] of `num_approvers` signers of the given scheme with the given
/// threshold, along with the (public key, authenticator) pairs of the first `threshold` signers.
fn multisig_fixture(
    num_approvers: usize,
    threshold: usize,
    auth_scheme: AuthScheme,
) -> anyhow::Result<(ApproverSet, Vec<(PublicKey, BasicAuthenticator)>)> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(num_approvers, threshold, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(public_key, auth_scheme)| Approver::new(public_key.to_commitment(), *auth_scheme))
        .collect();
    let approver_set = ApproverSet::new(approvers, u32::try_from(threshold)?)?;

    let signers = public_keys.into_iter().zip(authenticators).collect();

    Ok((approver_set, signers))
}

/// Asserts that `salt` is bound by the summary as the trailing word of its user parameters, which
/// is how the multisig auth component makes otherwise identical transactions distinguishable.
fn assert_salt_bound_as_user_params(tx_summary: &TransactionSummary, salt: Word) {
    assert_eq!(
        tx_summary.user_params().as_elements(),
        &[ZERO, ZERO, salt[0], salt[1], salt[2], salt[3]]
    );
}

/// Builds the auth args of a fee-paying multisig transaction: the given salt and a one-to-one
/// conversion of the fee asset, bound to the chain's latest block.
fn fee_paying_auth_args(mock_chain: &MockChain, salt: Word) -> anyhow::Result<MultisigAuthArgs> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    Ok(MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id)))
}

/// Executes an empty transaction against a wallet with the multisig auth component on a
/// fee-charging mock chain: runs once without signatures to obtain the transaction summary,
/// asserts the salt is bound as the trailing word of the summary's user params, signs the
/// summary with all provided signers, and executes the signed transaction.
async fn execute_fee_paying_multisig_tx(
    auth: Auth,
    signers: Vec<(PublicKey, BasicAuthenticator)>,
) -> anyhow::Result<ExecutedTransaction> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(auth, [fee_asset])?;
    let mock_chain = builder.build()?;

    let salt = Word::from([9u32, 10, 11, 12]);
    let auth_args = fee_paying_auth_args(&mock_chain, salt)?;

    let mock_tx_builder = mock_chain.build_transaction(account.id()).multisig_auth_args(auth_args);

    // execute once without signatures to obtain the transaction summary that must be signed
    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    assert_salt_bound_as_user_params(&tx_summary, salt);

    let msg = tx_summary.as_ref().to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    let mut signed_builder = mock_tx_builder;
    for (public_key, authenticator) in &signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    Ok(signed_builder.build()?.execute().await?)
}

// TESTS
// ================================================================================================

/// The multisig auth procedure pays the transaction fee by creating a TX_FEE note funded with
/// the native fee asset, and the measured auth cycles stay within the multisig cycle estimate.
/// This is the regression guard for `signature::estimate_multisig_authentication_cycles`. The
/// ECDSA case additionally exercises the (large) overshoot of the Falcon-based per-signer bound
/// for a cheaper scheme.
#[rstest]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn multisig_pays_fee_note(#[case] auth_scheme: AuthScheme) -> anyhow::Result<()> {
    let (approver_set, signers) = multisig_fixture(2, 2, auth_scheme)?;

    let executed_transaction = execute_fee_paying_multisig_tx(
        Auth::Multisig { approver_set, proc_threshold_map: vec![] },
        signers,
    )
    .await?;

    assert_single_fee_note(&executed_transaction)?;

    // two approver signatures are verified
    let measurements = executed_transaction.measurements();
    let auth_estimate = multisig_auth_estimate(2);
    assert!(
        measurements.auth_procedure <= auth_estimate,
        "multisig auth procedure took {} cycles, exceeding the estimate of {auth_estimate}",
        measurements.auth_procedure,
    );

    Ok(())
}

/// The transaction summary and fee note remain unchanged at a later reference block when the
/// account nonce, fee amount, and other signed effects are unchanged. The original signatures
/// remain valid until the approval expires. This test sets the expiration to 10 blocks after the
/// signed block. Execution succeeds at an offset of 9 blocks and fails at offsets of 10 and 11
/// blocks.
#[rstest]
#[case::zero_fee(AuthScheme::EcdsaK256Keccak, 0, 9)]
#[case::falcon_before_expiration(AuthScheme::Falcon512Poseidon2, VERIFICATION_BASE_FEE, 9)]
#[case::ecdsa_before_expiration(AuthScheme::EcdsaK256Keccak, VERIFICATION_BASE_FEE, 9)]
#[case::ecdsa_at_expiration(AuthScheme::EcdsaK256Keccak, VERIFICATION_BASE_FEE, 10)]
#[case::ecdsa_after_expiration(AuthScheme::EcdsaK256Keccak, VERIFICATION_BASE_FEE, 11)]
#[tokio::test]
async fn multisig_fee_note_is_stable_across_reference_blocks(
    #[case] auth_scheme: AuthScheme,
    #[case] base_fee: u32,
    #[case] blocks_advanced: u32,
) -> anyhow::Result<()> {
    const APPROVAL_EXPIRATION_DELTA: u16 = 10;

    let (approver_set, signers) = multisig_fixture(2, 2, auth_scheme)?;
    let fee_asset = FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 1_000_000)?;
    let mut builder = MockChain::builder().verification_base_fee(base_fee);
    let account = builder.add_existing_wallet_with_assets(
        Auth::Multisig { approver_set, proc_threshold_map: vec![] },
        [fee_asset.into()],
    )?;
    let mut mock_chain = builder.build()?;
    let signed_block = mock_chain.latest_block_header().block_num();
    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([17u32, 18, 19, 20]))?;
    let expiration_script =
        ExpirationTransactionScript::new(NonZeroU16::new(APPROVAL_EXPIRATION_DELTA).unwrap());

    let original_summary = mock_chain
        .build_transaction(account.id())
        .tx_script(expiration_script.into())
        .tx_script_args(expiration_script.tx_script_args())
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let msg = original_summary.to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(original_summary);
    let mut signatures = Vec::new();
    for (public_key, authenticator) in &signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signatures.push((public_key.to_commitment(), signature));
    }

    let mut original_builder = mock_chain
        .build_transaction(account.id())
        .tx_script(expiration_script.into())
        .tx_script_args(expiration_script.tx_script_args())
        .multisig_auth_args(auth_args);
    for (key, signature) in &signatures {
        original_builder = original_builder.add_signature(*key, msg, signature.clone());
    }
    let original_tx = original_builder.build()?.execute().await?;

    mock_chain.prove_until_block(signed_block + blocks_advanced)?;

    let mut later_builder = mock_chain
        .build_transaction(account.id())
        .tx_script(expiration_script.into())
        .tx_script_args(expiration_script.tx_script_args())
        .multisig_auth_args(auth_args);
    for (key, signature) in &signatures {
        later_builder = later_builder.add_signature(*key, msg, signature.clone());
    }
    if blocks_advanced >= u32::from(APPROVAL_EXPIRATION_DELTA) {
        let result = later_builder.build()?.execute().await;
        assert_transaction_executor_error!(result, ERR_MULTISIG_APPROVAL_EXPIRED);
        return Ok(());
    }

    let later_summary = mock_chain
        .build_transaction(account.id())
        .tx_script(expiration_script.into())
        .tx_script_args(expiration_script.tx_script_args())
        .multisig_auth_args(auth_args)
        .add_signature(signatures[0].0, msg, signatures[0].1.clone())
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    assert_eq!(later_summary.to_commitment(), msg);

    let later_tx = later_builder.build()?.execute().await?;

    assert_eq!(later_tx.block_header().block_num(), signed_block + blocks_advanced);
    assert_eq!(
        later_tx.expiration_block_num(),
        signed_block + u32::from(APPROVAL_EXPIRATION_DELTA)
    );
    assert_eq!(original_tx.output_notes().commitment(), later_tx.output_notes().commitment());
    if base_fee == 0 {
        assert_eq!(later_tx.output_notes().num_notes(), 0);
    } else {
        assert_eq!(assert_single_fee_note(&original_tx)?, assert_single_fee_note(&later_tx)?);
        let expected_serial =
            TxFeeNote::derive_serial_number(account.id(), account.nonce(), signed_block);
        let fee_note = later_tx.output_notes().get_note(0);
        assert_eq!(fee_note.recipient().unwrap().serial_num(), expected_serial);
    }

    Ok(())
}

/// This test uses a transaction script that executes a 65,536-iteration loop only when the
/// execution reference block differs from the signed block. The additional cycles increase the
/// fee without changing the signed block or account nonce. The fee note's recipient remains
/// unchanged, but its asset amount and the vault withdrawal increase, so execution requires new
/// signatures.
#[rstest]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn multisig_rejects_original_signatures_when_fee_changes(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (approver_set, signers) = multisig_fixture(2, 2, auth_scheme)?;
    let fee_asset = FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 1_000_000)?;
    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::Multisig { approver_set, proc_threshold_map: vec![] },
        [fee_asset.into()],
    )?;
    let mut mock_chain = builder.build()?;
    let signed_block = mock_chain.latest_block_header().block_num();
    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([21u32, 22, 23, 24]))?;

    // The conditional loop increases the cycle count enough to reach a higher fee cycle bucket.
    // The script itself does not create notes or modify account state.
    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        "
        use miden::protocol::tx

        @transaction_script
        pub proc main
            exec.tx::get_reference_block_number push.{signed_block} neq
            if.true
                push.65536
                dup neq.0
                while.true
                    sub.1 dup neq.0
                end
                drop
            end
        end
        "
    ))?;
    let original_builder = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script.clone())
        .multisig_auth_args(auth_args);
    let original_summary = original_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let original_msg = original_summary.to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(original_summary.clone());
    let mut signatures = Vec::new();
    let mut signed_builder = original_builder;
    for (key, authenticator) in &signers {
        let signature = authenticator.get_signature(key.to_commitment(), &signing_inputs).await?;
        signed_builder =
            signed_builder.add_signature(key.to_commitment(), original_msg, signature.clone());
        signatures.push((key.to_commitment(), signature));
    }
    let original_tx = signed_builder.build()?.execute().await?;
    let original_fee = assert_single_fee_note(&original_tx)?;

    // Do not apply the original transaction: the account and its nonce must remain unchanged.
    mock_chain.prove_until_block(signed_block + 5)?;
    let later_builder = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .multisig_auth_args(auth_args);
    let mut stale_builder = later_builder.clone();
    for (key, signature) in signatures {
        stale_builder = stale_builder.add_signature(key, original_msg, signature);
    }
    let later_summary =
        stale_builder.build()?.execute().await.unwrap_err().unwrap_unauthorized_err();

    assert_eq!(later_summary.metadata(), original_summary.metadata());
    assert_eq!(later_summary.block_commitment(), original_summary.block_commitment());
    assert_eq!(later_summary.user_params(), original_summary.user_params());
    assert_eq!(later_summary.input_notes(), original_summary.input_notes());
    assert_eq!(
        later_summary.account_delta().storage(),
        original_summary.account_delta().storage()
    );
    assert_eq!(
        later_summary.account_delta().nonce_delta(),
        original_summary.account_delta().nonce_delta()
    );
    assert_ne!(later_summary.account_delta().vault(), original_summary.account_delta().vault());
    let later_msg = later_summary.to_commitment();
    assert_ne!(later_msg, original_msg);

    // Fresh approvals must succeed, ruling out an unrelated execution failure.
    let signing_inputs = SigningInputs::TransactionSummary(later_summary);
    let mut signed_builder = later_builder;
    for (key, authenticator) in signers {
        let signature = authenticator.get_signature(key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(key.to_commitment(), later_msg, signature);
    }
    let later_tx = signed_builder.build()?.execute().await?;
    let later_fee = assert_single_fee_note(&later_tx)?;
    assert!(later_fee.amount() > original_fee.amount());
    assert_eq!(later_tx.initial_account().nonce(), original_tx.initial_account().nonce());
    assert_eq!(
        later_tx.output_notes().get_note(0).recipient(),
        original_tx.output_notes().get_note(0).recipient()
    );
    assert_ne!(later_tx.output_notes().commitment(), original_tx.output_notes().commitment());

    Ok(())
}

/// On a fee-charging chain, replaying a signed multisig transaction (same auth args and
/// signatures) is rejected: after the first execution the account nonce advances, so the replayed
/// transaction's fee note serial number and thus its summary commitment differ from the signed
/// one, and the stale signatures fail verification.
#[rstest]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn multisig_fee_payment_preserves_replay_protection(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (approver_set, signers) = multisig_fixture(2, 2, auth_scheme)?;

    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::Multisig { approver_set, proc_threshold_map: vec![] },
        [fee_asset],
    )?;
    let mut mock_chain = builder.build()?;

    let salt = Word::from([13u32, 14, 15, 16]);
    let auth_args = fee_paying_auth_args(&mock_chain, salt)?;

    let mock_tx_builder = mock_chain.build_transaction(account.id()).multisig_auth_args(auth_args);

    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    assert_salt_bound_as_user_params(&tx_summary, salt);

    let msg = tx_summary.as_ref().to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    let mut signatures = Vec::new();
    for (public_key, authenticator) in &signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signatures.push((public_key.to_commitment(), signature));
    }

    let mut signed_builder = mock_tx_builder;
    for (pub_key_commitment, signature) in &signatures {
        signed_builder = signed_builder.add_signature(*pub_key_commitment, msg, signature.clone());
    }
    let executed_transaction = signed_builder.build()?.execute().await?;
    assert_single_fee_note(&executed_transaction)?;

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // attempt to replay the same transaction with the same auth args and signatures
    let mut replay_builder =
        mock_chain.build_transaction(account.id()).multisig_auth_args(auth_args);
    for (pub_key_commitment, signature) in &signatures {
        replay_builder = replay_builder.add_signature(*pub_key_commitment, msg, signature.clone());
    }
    let result = replay_builder.build()?.execute().await;

    assert!(
        matches!(result, Err(TransactionExecutorError::Unauthorized(_))),
        "replayed multisig transaction should be rejected as unauthorized"
    );

    Ok(())
}
