use miden_protocol::account::auth::{AuthScheme, PublicKey};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::{ExecutedTransaction, TransactionSummary};
use miden_protocol::{Word, ZERO};
use miden_standards::account::auth::{Approver, ApproverSet, FeeConversionInfo, MultisigAuthArgs};
use miden_testing::{Auth, MockChain, MockTransactionBuilder};
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
pub(super) fn multisig_auth_estimate(num_signers: usize) -> usize {
    num_signers * FALCON_512_POSEIDON2_AUTH_CYCLES + MULTISIG_AUTH_BASE_CYCLES + PAY_FEE_CYCLES
}

/// Builds an [`ApproverSet`] of `num_approvers` signers of the given scheme with the given
/// threshold, along with the (public key, authenticator) pairs of the first `threshold` signers.
pub(super) fn multisig_fixture(
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
pub(super) fn fee_paying_auth_args(
    mock_chain: &MockChain,
    salt: Word,
) -> anyhow::Result<MultisigAuthArgs> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    Ok(MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id)))
}

/// Executes the transaction once unsigned to obtain the summary the signers must sign, then adds
/// every signer's signature over it to the builder.
pub(super) async fn sign_with_all<'a, 's>(
    mock_tx_builder: MockTransactionBuilder<'a>,
    signers: impl IntoIterator<Item = &'s (PublicKey, BasicAuthenticator)>,
) -> anyhow::Result<MockTransactionBuilder<'a>> {
    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    let msg = tx_summary.as_ref().to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    let mut signed_builder = mock_tx_builder;
    for (public_key, authenticator) in signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    Ok(signed_builder)
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

/// On a fee-charging chain, replaying a signed multisig transaction (same auth args and
/// signatures) is rejected: after the first execution the account nonce advances, so the replayed
/// transaction's fee note serial number and thus its summary commitment differ from the signed
/// one, and the stale signatures fail verification.
#[tokio::test]
async fn multisig_fee_payment_preserves_replay_protection() -> anyhow::Result<()> {
    let (approver_set, signers) = multisig_fixture(2, 2, AuthScheme::Falcon512Poseidon2)?;

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
