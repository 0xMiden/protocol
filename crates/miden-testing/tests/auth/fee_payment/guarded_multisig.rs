use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKey};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::account::auth::AuthGuardedMultisig;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::Word;
use miden_standards::account::auth::{
    Approver,
    ApproverSet,
    FeeConversionInfo,
    GuardianConfig,
    commit_fee_conversion_info,
};
use miden_testing::{Auth, MockChain};
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};

use super::super::multisig::setup_keys_and_authenticators_with_scheme;
use super::{
    FALCON_512_POSEIDON2_AUTH_CYCLES,
    MULTISIG_AUTH_BASE_CYCLES,
    PAY_FEE_CYCLES,
    VERIFICATION_BASE_FEE,
    assert_single_fee_note,
};

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a guarded multisig fixture: an approver set of `num_approvers` Falcon signers with the
/// threshold set to all of them, plus a separate ECDSA guardian.
#[allow(clippy::type_complexity)]
fn guarded_fixture(
    num_approvers: usize,
) -> anyhow::Result<(
    ApproverSet,
    Vec<(PublicKey, BasicAuthenticator)>,
    GuardianConfig,
    PublicKey,
    BasicAuthenticator,
)> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(
            num_approvers,
            num_approvers,
            AuthScheme::Falcon512Poseidon2,
        )?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(public_key, auth_scheme)| Approver::new(public_key.to_commitment(), *auth_scheme))
        .collect();
    let approver_set = ApproverSet::new(approvers, u32::try_from(num_approvers)?)?;
    let signers: Vec<(PublicKey, BasicAuthenticator)> =
        public_keys.into_iter().zip(authenticators).collect();

    let guardian_secret_key = AuthSecretKey::new_ecdsa_k256_keccak();
    let guardian_public_key = guardian_secret_key.public_key();
    let guardian_authenticator =
        BasicAuthenticator::new(core::slice::from_ref(&guardian_secret_key));
    let guardian_config = GuardianConfig::new(Approver::new(
        guardian_public_key.to_commitment(),
        AuthScheme::EcdsaK256Keccak,
    ));

    Ok((
        approver_set,
        signers,
        guardian_config,
        guardian_public_key,
        guardian_authenticator,
    ))
}

/// Executes an empty transaction against a guarded multisig wallet on a fee-charging mock chain,
/// signing the summary with every approver and the guardian.
async fn execute_fee_paying_guarded_multisig_tx(
    num_approvers: usize,
) -> anyhow::Result<ExecutedTransaction> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let (approver_set, signers, guardian_config, guardian_public_key, guardian_authenticator) =
        guarded_fixture(num_approvers)?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::GuardedMultisig {
            approver_set,
            guardian_config,
            proc_threshold_map: vec![],
        },
        [fee_asset],
    )?;
    let mock_chain = builder.build()?;

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([9u32, 10, 11, 12]),
    );

    let mock_tx_builder = mock_chain
        .build_transaction(account.id())
        .auth_args(args)
        .add_advice_map_entry(args, advice_value);

    // Execute once unsigned to obtain the summary that every signer must sign.
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
    for (public_key, authenticator) in &signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    let guardian_signature = guardian_authenticator
        .get_signature(guardian_public_key.to_commitment(), &signing_inputs)
        .await?;
    signed_builder =
        signed_builder.add_signature(guardian_public_key.to_commitment(), msg, guardian_signature);

    Ok(signed_builder.build()?.execute().await?)
}

// TESTS
// ================================================================================================

/// The guarded multisig auth procedure must pay the transaction fee, exactly as the plain multisig
/// component does.
///
/// It never called `fee::pay_fee`, so a guarded account transacted for free on a fee-charging
/// chain. Nothing else covered for it: the fee moved out of the kernel epilogue into the auth
/// procedure, and neither the batch nor the block kernel validates that a transaction paid one, so
/// the result was a silent economic hole rather than a loud failure.
#[tokio::test]
async fn guarded_multisig_pays_fee_note() -> anyhow::Result<()> {
    let executed_transaction = execute_fee_paying_guarded_multisig_tx(2).await?;

    assert_single_fee_note(&executed_transaction)?;

    Ok(())
}

/// The cycle estimate passed to `pay_fee` must remain an upper bound on the cycles actually spent
/// authenticating.
///
/// The guarded component does strictly more work than the plain multisig one — it additionally
/// verifies the guardian signature — so the estimate counts one more signer than there are
/// approvers. An estimate that is too low is the dangerous direction.
#[tokio::test]
async fn guarded_multisig_auth_cycles_stay_within_the_estimate() -> anyhow::Result<()> {
    let num_approvers = 2;
    let executed_transaction = execute_fee_paying_guarded_multisig_tx(num_approvers).await?;

    let auth_estimate = (num_approvers + 1) * FALCON_512_POSEIDON2_AUTH_CYCLES
        + MULTISIG_AUTH_BASE_CYCLES
        + PAY_FEE_CYCLES;

    let measurements = executed_transaction.measurements();
    assert!(
        measurements.auth_procedure <= auth_estimate,
        "guarded multisig auth took {} cycles, exceeding the estimate of {auth_estimate}",
        measurements.auth_procedure,
    );

    Ok(())
}

/// Guardian key rotation must still work on a fee-charging chain.
///
/// `pay_fee` creates a `TX_FEE` output note, and the rotation branch of
/// `guardian::verify_signature` calls `tx_policy::assert_no_output_notes`, which reads the live
/// output-note counter. The account's own mandatory fee note therefore trips a guard meant for
/// user notes, and a lost or compromised guardian key could never be rotated.
///
/// Invisible to the existing rotation tests because they build the chain with
/// `MockChainBuilder::with_accounts`, whose `verification_base_fee` defaults to 0 — no fee is
/// charged, so no fee note is created and the guard never sees one.
#[tokio::test]
async fn guarded_multisig_rotates_guardian_key_while_paying_the_fee() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let (approver_set, signers, guardian_config, _guardian_public_key, _guardian_authenticator) =
        guarded_fixture(2)?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::GuardedMultisig { approver_set, guardian_config, proc_threshold_map: vec![] },
        [fee_asset],
    )?;
    let mock_chain = builder.build()?;

    let new_guardian_secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let new_guardian_public_key = new_guardian_secret_key.public_key();
    let new_guardian_scheme_id = new_guardian_secret_key.auth_scheme() as u32;
    let new_guardian_key_word: Word = new_guardian_public_key.to_commitment().into();

    let update_guardian_script = CodeBuilder::new()
        .with_dynamically_linked_package(AuthGuardedMultisig::code())?
        .compile_tx_script(format!(
            "
            @transaction_script
            pub proc main
                push.{new_guardian_key_word}
                push.{new_guardian_scheme_id}
                call.::miden::standards::components::auth::guarded_multisig::update_guardian_public_key
                drop dropw
            end
            "
        ))?;

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([21u32, 22, 23, 24]),
    );

    let mock_tx_builder = mock_chain
        .build_transaction(account.id())
        .tx_script(update_guardian_script)
        .auth_args(args)
        .add_advice_map_entry(args, advice_value);

    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    let msg = tx_summary.as_ref().to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    // Rotation intentionally skips the guardian signature — that is the point of the path.
    let mut signed_builder = mock_tx_builder;
    for (public_key, authenticator) in &signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    let executed_transaction = signed_builder.build()?.execute().await?;

    // The fee is still paid, and the rotation is not blocked by the note it creates.
    assert_single_fee_note(&executed_transaction)?;

    Ok(())
}
