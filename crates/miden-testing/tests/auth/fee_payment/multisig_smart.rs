use core::num::NonZeroU32;

use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, PublicKey};
use miden_protocol::account::{AccountId, AccountProcedureRoot};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::{ExecutedTransaction, TransactionScript};
use miden_standards::account::auth::multisig_smart::{DelayedExecutionPolicy, ProcedurePolicy};
use miden_standards::account::auth::{
    Approver,
    ApproverSet,
    AuthMultisigSmart,
    FeeConversionInfo,
    MultisigAuthArgs,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_FEE_EXCEEDS_MAX_FEE;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};

use super::super::multisig::{MultisigAuthArgsExt, setup_keys_and_authenticators_with_scheme};
use super::{VERIFICATION_BASE_FEE, assert_single_fee_note};

// CONSTANTS
// ================================================================================================

/// `min_delay` of the delayed-execution policy the test accounts are built with, in blocks.
const MIN_DELAY: u32 = 30;

/// `propose_expiration_delta` of the delayed-execution policy the test accounts are built with.
const PROPOSE_EXPIRATION_DELTA: u16 = 2;

/// `cancel_threshold` of the delayed-execution policy the test accounts are built with.
const CANCEL_THRESHOLD: u32 = 1;

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a fee-charging mock chain holding a wallet with the smart multisig auth component:
/// `num_approvers` ECDSA approvers with the given threshold and procedure policies, and a balance
/// of the native fee asset. Returns the chain, the account ID and the approvers' keys and
/// authenticators.
fn fee_charging_multisig_smart(
    num_approvers: usize,
    threshold: usize,
    proc_policy_map: Vec<(AccountProcedureRoot, ProcedurePolicy)>,
) -> anyhow::Result<(MockChain, AccountId, Vec<PublicKey>, Vec<BasicAuthenticator>)> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(
            num_approvers,
            threshold,
            AuthScheme::EcdsaK256Keccak,
        )?;
    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(public_key, auth_scheme)| Approver::new(public_key.to_commitment(), *auth_scheme))
        .collect();
    let auth = Auth::MultisigSmart {
        approver_set: ApproverSet::new(approvers, u32::try_from(threshold)?)?,
        proc_policy_map,
        delayed_execution_policy: DelayedExecutionPolicy::new(
            MIN_DELAY,
            PROPOSE_EXPIRATION_DELTA,
            CANCEL_THRESHOLD,
        )?,
    };

    let fee_asset: Asset = FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 1_000_000)?.into();
    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(auth, [fee_asset])?;
    let mock_chain = builder.build()?;

    Ok((mock_chain, account.id(), public_keys, authenticators))
}

/// Builds the auth args of a fee-paying transaction: the given salt and a one-to-one conversion
/// of the fee asset, bound to the chain's latest block. No max fee is set, so the auth procedure
/// estimates it.
fn fee_paying_auth_args(mock_chain: &MockChain, salt: Word) -> anyhow::Result<MultisigAuthArgs> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    Ok(MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id)))
}

/// Compiles a transaction script that links against the smart multisig package so it can `call.`
/// the component's exported procedures.
fn compile_multisig_smart_tx_script(script: impl AsRef<str>) -> anyhow::Result<TransactionScript> {
    Ok(CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisigSmart::code())?
        .compile_tx_script(script.as_ref())?)
}

/// Executes the transaction with the given script and auth args, signed by the given approvers:
/// runs once without signatures to obtain the summary and the max fee the auth procedure
/// estimated, signs the summary and executes the signed transaction with that max fee.
async fn execute_signed(
    mock_chain: &MockChain,
    account_id: AccountId,
    tx_script: Option<TransactionScript>,
    auth_args: MultisigAuthArgs,
    signer_indices: &[usize],
    public_keys: &[PublicKey],
    authenticators: &[BasicAuthenticator],
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let build = |auth_args| {
        let mut builder = mock_chain.build_transaction(account_id).multisig_auth_args(auth_args);
        if let Some(tx_script) = &tx_script {
            builder = builder.tx_script(tx_script.clone());
        }
        builder
    };

    let tx_summary =
        build(auth_args).build()?.execute().await.unwrap_err().unwrap_unauthorized_err();
    let signed_auth_args = auth_args.with_max_fee_from_summary(&tx_summary)?;
    let msg = tx_summary.to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    let mut builder = build(signed_auth_args);
    for signer_idx in signer_indices {
        let public_key = public_keys[*signer_idx].to_commitment();
        let signature =
            authenticators[*signer_idx].get_signature(public_key, &signing_inputs).await?;
        builder = builder.add_signature(public_key, msg, signature);
    }

    Ok(builder.build()?.execute().await)
}

// TESTS
// ================================================================================================

/// The smart multisig auth procedure pays the transaction fee after verifying the signatures by
/// creating a TX_FEE note funded with the native fee asset, within the max fee it estimated.
#[tokio::test]
async fn multisig_smart_pays_fee_note() -> anyhow::Result<()> {
    let (mock_chain, account_id, public_keys, authenticators) =
        fee_charging_multisig_smart(2, 2, vec![])?;
    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([1u32, 2, 3, 4]))?;

    let executed = execute_signed(
        &mock_chain,
        account_id,
        None,
        auth_args,
        &[0, 1],
        &public_keys,
        &authenticators,
    )
    .await??;

    assert_single_fee_note(&executed)?;

    Ok(())
}

/// A signed transaction whose fee exceeds the max fee the summary binds is rejected after the
/// signatures are verified.
#[tokio::test]
async fn multisig_smart_rejects_fee_exceeding_max_fee() -> anyhow::Result<()> {
    let (mock_chain, account_id, public_keys, authenticators) =
        fee_charging_multisig_smart(2, 2, vec![])?;
    // any non-zero fee exceeds a cap of one unit
    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([5u32, 6, 7, 8]))?
        .with_max_fee(AssetAmount::new(1)?);

    let result = execute_signed(
        &mock_chain,
        account_id,
        None,
        auth_args,
        &[0, 1],
        &public_keys,
        &authenticators,
    )
    .await?;
    assert_transaction_executor_error!(result, ERR_FEE_EXCEEDS_MAX_FEE);

    Ok(())
}

/// Delayed execution with fees: the proposal is keyed by the target transaction's summary
/// commitment, which carries the max fee the auth procedure estimated before proposing, so the
/// execution after the timelock passes that max fee back and pays its fee within it. The propose
/// transaction pays its own fee as well.
#[tokio::test]
async fn multisig_smart_delayed_execution_pays_fees_within_the_proposed_max_fee()
-> anyhow::Result<()> {
    let (mut mock_chain, account_id, public_keys, authenticators) = fee_charging_multisig_smart(
        2,
        2,
        vec![(
            AuthMultisigSmart::update_delayed_execution_policy_root(),
            ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1)?,
        )],
    )?;
    let execute_script = compile_multisig_smart_tx_script(
        "
        @transaction_script
        pub proc main
            push.1
            push.2
            push.40
            call.::miden::standards::components::auth::multisig_smart::update_delayed_execution_policy
            drop
            drop
            drop
        end
        ",
    )?;

    // the execution's summary, obtained before proposing, carries the estimated max fee
    let bound_block = mock_chain.latest_block_header().block_num();
    let exec_auth_args = fee_paying_auth_args(&mock_chain, Word::from([9u32, 10, 11, 12]))?
        .with_approval_expiration_delta(NonZeroU32::new(100).unwrap())?;
    let exec_summary = mock_chain
        .build_transaction(account_id)
        .tx_script(execute_script.clone())
        .multisig_auth_args(exec_auth_args)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let signed_exec_auth_args = exec_auth_args.with_max_fee_from_summary(&exec_summary)?;
    let target_commitment = exec_summary.to_commitment();

    // propose the commitment; the propose transaction pays its own fee
    let propose_script = compile_multisig_smart_tx_script(format!(
        "
        @transaction_script
        pub proc main
            push.{target_commitment}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let mut propose_builder = mock_chain
        .build_transaction(account_id)
        .tx_script(propose_script)
        .multisig_auth_args(fee_paying_auth_args(&mock_chain, Word::from([13u32, 14, 15, 16]))?);
    let proposal_signing = SigningInputs::Blind(target_commitment);
    for signer_idx in [0, 1] {
        let public_key = public_keys[signer_idx].to_commitment();
        let signature =
            authenticators[signer_idx].get_signature(public_key, &proposal_signing).await?;
        propose_builder = propose_builder.add_signature(public_key, target_commitment, signature);
    }
    let propose_tx = propose_builder.build()?.execute().await?;
    assert_single_fee_note(&propose_tx)?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    // once the timelock elapsed, one signature over the proposed summary executes it, and the fee
    // paid at this later block stays within the max fee estimated before proposing
    mock_chain.prove_until_block(bound_block + u32::from(PROPOSE_EXPIRATION_DELTA) + MIN_DELAY)?;
    let exec_signing = SigningInputs::TransactionSummary(exec_summary);
    let public_key = public_keys[0].to_commitment();
    let signature = authenticators[0].get_signature(public_key, &exec_signing).await?;
    let executed = mock_chain
        .build_transaction(account_id)
        .tx_script(execute_script)
        .multisig_auth_args(signed_exec_auth_args)
        .add_signature(public_key, target_commitment, signature)
        .build()?
        .execute()
        .await?;

    let paid_fee = assert_single_fee_note(&executed)?;
    assert!(paid_fee.amount() <= signed_exec_auth_args.max_fee());

    Ok(())
}
