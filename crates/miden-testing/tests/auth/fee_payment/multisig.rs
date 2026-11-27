use core::num::NonZeroU32;
use std::collections::BTreeSet;

use miden_protocol::account::auth::{AuthScheme, PublicKey};
use miden_protocol::account::{AccountId, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::crypto::rand::EidosRandomCoin;
use miden_protocol::note::{Note, PartialNote};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote, TransactionSummary};
use miden_protocol::{Felt, Word, ZERO};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::auth::{
    Approver,
    ApproverSet,
    FeeConversionInfo,
    MultisigAuthArgs,
    NetworkAccount,
    SponsorshipPolicy,
};
use miden_standards::account::fees::{
    BasicConstantFeePolicy,
    ConstantFeeManager,
    FeePolicyManager,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_EXCEEDS_MAX_FEE,
    ERR_MULTISIG_APPROVAL_EXPIRED,
    ERR_TX_ALREADY_EXECUTED,
};
use miden_standards::note::config::ConstantFeePolicyConfigNote;
use miden_standards::note::{FeeSponsorshipNote, P2idNote, TxFeeNote};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{Auth, MockChain, MockTransactionBuilder, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rstest::rstest;

use super::super::multisig::{MultisigAuthArgsExt, setup_keys_and_authenticators_with_scheme};
use super::{VERIFICATION_BASE_FEE, assert_single_fee_note, sponsorship};
use crate::consume_note;

// HELPER FUNCTIONS
// ================================================================================================

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

/// Asserts that the auth args are bound by the summary's user parameters: the approval
/// expiration (or zero) leads and the salt is the trailing word, which is how the multisig auth
/// component makes otherwise identical transactions distinguishable. Returns the max fee bound
/// in between: the one the auth args set, or the auth procedure's estimate if they set none.
fn assert_auth_args_bound_as_user_params(
    tx_summary: &TransactionSummary,
    auth_args: &MultisigAuthArgs,
) -> anyhow::Result<AssetAmount> {
    let approval_expiration = auth_args.approval_expiration_block_num().map_or(ZERO, Felt::from);
    let salt = auth_args.salt();
    let params = *tx_summary.user_params().as_elements();
    assert_eq!(params[0], approval_expiration);
    assert_eq!(&params[2..], salt.as_slice());

    let bound_max_fee = AssetAmount::try_from(params[1])?;
    if auth_args.max_fee() != AssetAmount::ZERO {
        assert_eq!(bound_max_fee, auth_args.max_fee());
    }

    Ok(bound_max_fee)
}

/// Builds the auth args of a fee-paying multisig transaction: the given salt and a one-to-one
/// conversion of the fee asset, bound to the chain's latest block. No max fee is set, so the auth
/// procedure estimates it.
fn fee_paying_auth_args(mock_chain: &MockChain, salt: Word) -> anyhow::Result<MultisigAuthArgs> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    Ok(MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id)))
}

/// Executes an empty transaction against a wallet with the multisig auth component on a
/// fee-charging mock chain: runs once without signatures to obtain the transaction summary and
/// the max fee the auth procedure estimated, asserts the salt is bound as the trailing word of the
/// summary's user params, signs the summary with all provided signers, and executes the signed
/// transaction with that max fee.
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

    // execute once without signatures: the auth procedure estimates the fee, binds the max fee
    // into the summary and reports the summary that must be signed
    let tx_summary = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    assert_auth_args_bound_as_user_params(&tx_summary, &auth_args)?;

    // the signed execution passes the estimated max fee back, which keeps the summary unchanged
    let signed_auth_args = auth_args.with_max_fee_from_summary(&tx_summary)?;
    let msg = tx_summary.to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    let mut signed_builder =
        mock_chain.build_transaction(account.id()).multisig_auth_args(signed_auth_args);
    for (public_key, authenticator) in &signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    Ok(signed_builder.build()?.execute().await?)
}

/// Signs the transaction of the given builder with all `signers` and executes it: runs once
/// without signatures to obtain the transaction summary, then executes with the signatures added
/// and returns the execution result.
async fn execute_signed_multisig_tx(
    builder: MockTransactionBuilder<'_>,
    signers: &[(PublicKey, BasicAuthenticator)],
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let tx_summary =
        builder.clone().build()?.execute().await.unwrap_err().unwrap_unauthorized_err();
    let msg = tx_summary.to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    let mut signed_builder = builder;
    for (public_key, authenticator) in signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    Ok(signed_builder.build()?.execute().await)
}

// TESTS
// ================================================================================================

/// The multisig auth procedure pays the transaction fee after verifying the signatures by
/// creating a TX_FEE note funded with the native fee asset.
#[rstest]
#[case::falcon(AuthScheme::Falcon512Eidos)]
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

    Ok(())
}

/// The transaction summary and fee note remain unchanged at a later reference block when the
/// account nonce, fee amount, and other signed effects are unchanged. The original signatures
/// remain valid until the approval expires. This test sets the expiration to 10 blocks after the
/// signed block. Execution succeeds at an offset of 9 blocks and fails at offsets of 10 and 11
/// blocks.
#[rstest]
#[case::zero_fee(AuthScheme::EcdsaK256Keccak, 0, 9)]
#[case::falcon_before_expiration(AuthScheme::Falcon512Eidos, VERIFICATION_BASE_FEE, 9)]
#[case::ecdsa_before_expiration(AuthScheme::EcdsaK256Keccak, VERIFICATION_BASE_FEE, 9)]
#[case::ecdsa_at_expiration(AuthScheme::EcdsaK256Keccak, VERIFICATION_BASE_FEE, 10)]
#[case::ecdsa_after_expiration(AuthScheme::EcdsaK256Keccak, VERIFICATION_BASE_FEE, 11)]
#[tokio::test]
async fn multisig_fee_note_is_stable_across_reference_blocks(
    #[case] auth_scheme: AuthScheme,
    #[case] base_fee: u32,
    #[case] blocks_advanced: u32,
) -> anyhow::Result<()> {
    const APPROVAL_EXPIRATION_DELTA: u32 = 10;

    let (approver_set, signers) = multisig_fixture(2, 2, auth_scheme)?;
    let fee_asset = FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 1_000_000)?;
    let mut builder = MockChain::builder().verification_base_fee(base_fee);
    let account = builder.add_existing_wallet_with_assets(
        Auth::Multisig { approver_set, proc_threshold_map: vec![] },
        [fee_asset.into()],
    )?;
    let mut mock_chain = builder.build()?;
    let signed_block = mock_chain.latest_block_header().block_num();
    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([17u32, 18, 19, 20]))?
        .with_approval_expiration_delta(NonZeroU32::new(APPROVAL_EXPIRATION_DELTA).unwrap())?;

    // Fixed script work keeps both executions in the same fee bucket as the block advances.
    let tx_script = CodeBuilder::default().compile_tx_script(
        r"
        @transaction_script
        pub proc main
            push.256 dup neq.0
            while.true
                sub.1 dup neq.0
            end
            drop
        end
        ",
    )?;

    let original_summary = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args)
        .tx_script(tx_script.clone())
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let auth_args = auth_args.with_max_fee_from_summary(&original_summary)?;
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
        .multisig_auth_args(auth_args)
        .tx_script(tx_script.clone());
    for (key, signature) in &signatures {
        original_builder = original_builder.add_signature(*key, msg, signature.clone());
    }
    let original_tx = original_builder.build()?.execute().await?;

    mock_chain.prove_until_block(signed_block + blocks_advanced)?;

    let mut later_builder = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args)
        .tx_script(tx_script.clone());
    for (key, signature) in &signatures {
        later_builder = later_builder.add_signature(*key, msg, signature.clone());
    }
    if blocks_advanced >= APPROVAL_EXPIRATION_DELTA {
        let result = later_builder.build()?.execute().await;
        assert_transaction_executor_error!(result, ERR_MULTISIG_APPROVAL_EXPIRED);
        return Ok(());
    }

    let later_summary = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args)
        .tx_script(tx_script)
        .add_signature(signatures[0].0, msg, signatures[0].1.clone())
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    assert_eq!(later_summary.to_commitment(), msg);

    let later_tx = later_builder.build()?.execute().await?;

    assert_eq!(later_tx.block_header().block_num(), signed_block + blocks_advanced);
    assert_eq!(later_tx.expiration_block_num(), signed_block + APPROVAL_EXPIRATION_DELTA);
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

/// The original signatures remain valid when the fee changes between the signed execution and a
/// later one, as long as it stays within the signed max fee. This test uses a transaction script
/// that executes a 65,536-iteration loop only when the execution reference block differs from the
/// signed block. The additional cycles increase the fee without changing the signed block, the
/// account nonce or the transaction summary, which binds the max fee rather than the fee note.
#[rstest]
#[case::falcon(AuthScheme::Falcon512Eidos)]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn multisig_accepts_original_signatures_when_fee_changes_within_max_fee(
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
    let estimated_summary = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script.clone())
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    // a margin leaves the later execution room for its extra cycles
    let (auth_args, original_summary) =
        auth_args.with_estimated_max_fee(&estimated_summary, 150)?;
    let original_msg = original_summary.to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(Box::new(original_summary));
    let mut signatures = Vec::new();
    let mut signed_builder = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script.clone())
        .multisig_auth_args(auth_args);
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
    let later_summary = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script.clone())
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    assert_eq!(later_summary.to_commitment(), original_msg);

    let mut later_builder = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .multisig_auth_args(auth_args);
    for (key, signature) in signatures {
        later_builder = later_builder.add_signature(key, original_msg, signature);
    }
    let later_tx = later_builder.build()?.execute().await?;
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

/// A signed transaction whose fee exceeds the max fee the summary binds is rejected after the
/// signatures are verified.
#[tokio::test]
async fn multisig_rejects_fee_exceeding_max_fee() -> anyhow::Result<()> {
    let (approver_set, signers) = multisig_fixture(2, 2, AuthScheme::EcdsaK256Keccak)?;
    let fee_asset = FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 1_000_000)?;
    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::Multisig { approver_set, proc_threshold_map: vec![] },
        [fee_asset.into()],
    )?;
    let mock_chain = builder.build()?;

    // any non-zero fee exceeds a cap of one unit
    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([25u32, 26, 27, 28]))?
        .with_max_fee(AssetAmount::new(1)?);
    let result = execute_signed_multisig_tx(
        mock_chain.build_transaction(account.id()).multisig_auth_args(auth_args),
        &signers,
    )
    .await?;
    assert_transaction_executor_error!(result, ERR_FEE_EXCEEDS_MAX_FEE);

    Ok(())
}

/// The max fee caps the transaction fee together with the sponsorships of the transaction's
/// network output notes, which their targets' fee policies price via FPI: a cap that covers the
/// transaction fee alone rejects a sponsoring transaction, so a target raising its price while
/// the signatures are collected cannot drain the account's fee asset balance. The Falcon case
/// leaves the estimate little signature slack, so it also checks that the estimate charges the
/// pricing `pay_fee` repeats.
#[rstest]
#[case::falcon(AuthScheme::Falcon512Eidos)]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn multisig_max_fee_covers_sponsored_fees(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let mut rng = EidosRandomCoin::new(Word::from([5u32, 6, 7, 8]));
    let (approver_set, signers) = multisig_fixture(2, 2, auth_scheme)?;
    // a payload asset issued by a faucet other than the fee faucet, carried by the network note
    let payload_asset: Asset = FungibleAsset::mock(50);

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let sponsor = builder.add_existing_wallet_with_assets(
        Auth::Multisig { approver_set, proc_threshold_map: vec![] },
        [sponsorship::fee_asset(1_000_000)?, payload_asset],
    )?;
    // the target network account prices the P2ID script root at FEE_AMOUNT
    let target = sponsorship::network_account(
        [2; 32],
        [P2idNote::script_root(), FeeSponsorshipNote::script_root()],
        &[(P2idNote::script_root(), sponsorship::FEE_AMOUNT)],
        [],
        SponsorshipPolicy::default(),
    )?;
    builder.add_account(target.clone())?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let network_note =
        sponsorship::p2id_network_note(sponsor.id(), target.id(), payload_asset, &mut rng)?;
    let tx_script = SendNotesTransactionScript::new(
        &sponsor.code().interface(sponsor.id()),
        &[PartialNote::from(network_note.clone())],
    )?;
    let foreign_target = mock_chain.get_foreign_account_inputs(target.id())?;

    // with an estimated max fee the transaction creates the network note, its sponsorship note
    // and the fee note, so the estimate covers the sponsorship
    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([29u32, 30, 31, 32]))?;
    let executed = execute_signed_multisig_tx(
        mock_chain
            .build_transaction(sponsor.id())
            .foreign_accounts([foreign_target.clone()])
            .send_notes_script(&tx_script)
            .expected_output_note(RawOutputNote::Full(network_note.clone()))
            .multisig_auth_args(auth_args),
        &signers,
    )
    .await??;
    let output_notes = executed.output_notes();
    assert_eq!(output_notes.num_notes(), 3);
    let fee_note = output_notes
        .iter()
        .find(|note| note.metadata().tag() == TxFeeNote::TAG)
        .expect("the sponsor should pay its own fee note");
    let paid_fee = fee_note
        .assets()
        .iter()
        .next()
        .expect("fee note carries one asset")
        .unwrap_fungible()
        .amount();
    let sponsorship_note = output_notes
        .iter()
        .find(|note| {
            note.recipient().map(|recipient| recipient.script().root())
                == Some(FeeSponsorshipNote::script_root())
        })
        .expect("a sponsorship note should be created for the network note");
    let sponsored_fee = sponsorship_note
        .assets()
        .iter()
        .next()
        .expect("sponsorship note carries one asset")
        .unwrap_fungible()
        .amount();
    assert_eq!(sponsored_fee.as_u64(), sponsorship::FEE_AMOUNT);

    // a cap one unit short of the fee and the sponsorship together still covers the transaction
    // fee alone, yet the transaction is rejected
    let tight_auth_args = fee_paying_auth_args(&mock_chain, Word::from([33u32, 34, 35, 36]))?
        .with_max_fee(AssetAmount::new(paid_fee.as_u64() + sponsored_fee.as_u64() - 1)?);
    let result = execute_signed_multisig_tx(
        mock_chain
            .build_transaction(sponsor.id())
            .foreign_accounts([foreign_target])
            .send_notes_script(&tx_script)
            .expected_output_note(RawOutputNote::Full(network_note))
            .multisig_auth_args(tight_auth_args),
        &signers,
    )
    .await?;
    assert_transaction_executor_error!(result, ERR_FEE_EXCEEDS_MAX_FEE);

    Ok(())
}

/// On a fee-charging chain, replaying a signed multisig transaction (same auth args and
/// signatures) is rejected by the replay protection: the fee note is created after the summary,
/// so the replayed transaction's summary commitment equals the signed one, which the account
/// recorded as executed.
#[rstest]
#[case::falcon(AuthScheme::Falcon512Eidos)]
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

    let tx_summary = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    assert_auth_args_bound_as_user_params(&tx_summary, &auth_args)?;
    let auth_args = auth_args.with_max_fee_from_summary(&tx_summary)?;

    let msg = tx_summary.to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    let mut signatures = Vec::new();
    for (public_key, authenticator) in &signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signatures.push((public_key.to_commitment(), signature));
    }

    let mut signed_builder =
        mock_chain.build_transaction(account.id()).multisig_auth_args(auth_args);
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
    assert_transaction_executor_error!(result, ERR_TX_ALREADY_EXECUTED);

    Ok(())
}

/// Without a max fee in the auth args, the auth procedure estimates the fee and binds the
/// estimate, which covers the fee the signed execution pays; a margin applied off-chain scales the
/// cap the next execution binds.
#[tokio::test]
async fn multisig_estimates_max_fee() -> anyhow::Result<()> {
    let (approver_set, signers) = multisig_fixture(2, 2, AuthScheme::EcdsaK256Keccak)?;
    let fee_asset = FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, 1_000_000)?;
    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::Multisig { approver_set, proc_threshold_map: vec![] },
        [fee_asset.into()],
    )?;
    let mock_chain = builder.build()?;
    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([37u32, 38, 39, 40]))?;

    let tx_summary = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let estimate = assert_auth_args_bound_as_user_params(&tx_summary, &auth_args)?;
    assert!(estimate > AssetAmount::ZERO);

    // a margin applied off-chain scales the cap; the summary to sign is derived without another
    // execution and matches what an execution with the scaled cap reports
    let (scaled_auth_args, scaled_summary) = auth_args.with_estimated_max_fee(&tx_summary, 200)?;
    assert_eq!(scaled_auth_args.max_fee().as_u64(), 2 * estimate.as_u64());
    let reported_summary = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(scaled_auth_args)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    assert_eq!(*reported_summary, scaled_summary);

    // the signed execution pays at most the estimate
    let executed = execute_signed_multisig_tx(
        mock_chain
            .build_transaction(account.id())
            .multisig_auth_args(auth_args.with_max_fee(estimate)),
        &signers,
    )
    .await??;
    assert!(assert_single_fee_note(&executed)?.amount() <= estimate);

    Ok(())
}

/// A target raising the price of a network note after the max fee was estimated cannot drain the
/// account: the approvers' signatures still verify, since the summary binds the max fee rather
/// than the sponsorship, but the inflated sponsorship no longer fits under it and the transaction
/// fails.
#[tokio::test]
async fn multisig_rejects_sponsorship_inflated_after_estimating_max_fee() -> anyhow::Result<()> {
    let mut rng = EidosRandomCoin::new(Word::from([9u32, 10, 11, 12]));
    let (approver_set, signers) = multisig_fixture(2, 2, AuthScheme::EcdsaK256Keccak)?;
    // a payload asset issued by a faucet other than the fee faucet, carried by the network note
    let payload_asset: Asset = FungibleAsset::mock(50);
    let fee_faucet_id: AccountId = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let owner = AccountId::builder()
        .account_type(AccountType::Private)
        .build_with_seed([70; 32]);

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let sponsor = builder.add_existing_wallet_with_assets(
        Auth::Multisig { approver_set, proc_threshold_map: vec![] },
        [sponsorship::fee_asset(1_000_000)?, payload_asset],
    )?;

    // the target prices the P2ID script root at FEE_AMOUNT and lets its owner reprice it through
    // a ConstantFeePolicyConfigNote, which it consumes for free; it holds fee asset to pay its own
    // fee for that consumption
    let policy = BasicConstantFeePolicy::new()
        .with_fee(P2idNote::script_root(), AssetAmount::new(sponsorship::FEE_AMOUNT)?)
        .with_fee(ConstantFeePolicyConfigNote::script_root(), AssetAmount::ZERO);
    let fee_policy_manager = FeePolicyManager::builder()
        .active_fee_policy(policy.into())
        .fee_faucet_id(fee_faucet_id)
        .build();
    let target = NetworkAccount::builder(
        [2; 32],
        BTreeSet::from([
            P2idNote::script_root(),
            FeeSponsorshipNote::script_root(),
            ConstantFeePolicyConfigNote::script_root(),
        ]),
        fee_policy_manager,
    )?
    .with_component(Ownable2Step::new(owner))
    .with_component(Authority::OwnerControlled)
    .with_component(ConstantFeeManager::for_basic_constant_fee_policy())
    .with_assets([sponsorship::fee_asset(1_000_000)?])
    .build_existing()?;
    builder.add_account(target.clone())?;

    // the owner's note repricing the P2ID script root twentyfold
    let repricing_note = Note::from(
        ConstantFeePolicyConfigNote::builder()
            .sender(owner)
            .target(target.id())
            .note_script_root(P2idNote::script_root())
            .fee_asset(FungibleAsset::new(fee_faucet_id, 20 * sponsorship::FEE_AMOUNT)?)
            .serial_number(Word::from([1u32, 0, 0, 0]))
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(repricing_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // the approvers sign a summary whose max fee the auth procedure estimated at the current price
    let network_note =
        sponsorship::p2id_network_note(sponsor.id(), target.id(), payload_asset, &mut rng)?;
    let tx_script = SendNotesTransactionScript::new(
        &sponsor.code().interface(sponsor.id()),
        &[PartialNote::from(network_note.clone())],
    )?;
    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([45u32, 46, 47, 48]))?;
    let tx_summary = mock_chain
        .build_transaction(sponsor.id())
        .foreign_accounts([mock_chain.get_foreign_account_inputs(target.id())?])
        .send_notes_script(&tx_script)
        .expected_output_note(RawOutputNote::Full(network_note.clone()))
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let signed_auth_args = auth_args.with_max_fee_from_summary(&tx_summary)?;
    let msg = tx_summary.to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);
    let mut signatures = Vec::new();
    for (public_key, authenticator) in &signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signatures.push((public_key.to_commitment(), signature));
    }

    // meanwhile the target raises the note's price
    consume_note(&mut mock_chain, target.id(), &repricing_note).await?;

    // the signatures still verify, but the sponsorship no longer fits under the signed max fee
    let mut signed_builder = mock_chain
        .build_transaction(sponsor.id())
        .foreign_accounts([mock_chain.get_foreign_account_inputs(target.id())?])
        .send_notes_script(&tx_script)
        .expected_output_note(RawOutputNote::Full(network_note))
        .multisig_auth_args(signed_auth_args);
    for (public_key_commitment, signature) in signatures {
        signed_builder = signed_builder.add_signature(public_key_commitment, msg, signature);
    }
    let result = signed_builder.build()?.execute().await;
    assert_transaction_executor_error!(result, ERR_FEE_EXCEEDS_MAX_FEE);

    Ok(())
}
