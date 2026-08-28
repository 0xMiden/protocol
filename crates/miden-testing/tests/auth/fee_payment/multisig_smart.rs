use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Word;
use miden_protocol::account::Account;
use miden_protocol::account::auth::{AuthScheme, PublicKey};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_standards::account::auth::multisig_smart::{
    ProcedurePolicy,
    ProcedurePolicyNoteRestriction,
};
use miden_standards::account::auth::{Approver, ApproverSet, FeeConversionInfo, MultisigAuthArgs};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::{
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES,
    ERR_FEE_CONVERSION_INFO_MISSING,
};
use miden_standards::note::{P2idNote, TxFeeNote};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};

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

/// Amount of the fee asset the fixture funds the account with.
const FEE_ASSET_AMOUNT: u64 = 1_000_000;

/// A smart multisig wallet funded with the fee asset, with the keys needed to sign for it.
///
/// The chain is left unbuilt so a test can add input notes to it; call `builder.build()` to finish.
struct MultisigSmartFixture {
    builder: MockChainBuilder,
    account: Account,
    signers: Vec<(PublicKey, BasicAuthenticator)>,
}

/// Builds a wallet with the smart multisig auth component and the given procedure policies, on a
/// mock chain charging `verification_base_fee`, funded with enough of the fee asset to pay the fee.
///
/// The approver set is `num_approvers` Falcon signers with the threshold set to the full set.
fn multisig_smart_fixture(
    num_approvers: usize,
    verification_base_fee: u32,
    proc_policy_map: Vec<(Word, ProcedurePolicy)>,
) -> anyhow::Result<MultisigSmartFixture> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, FEE_ASSET_AMOUNT)?.into();

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

    let mut builder = MockChain::builder().verification_base_fee(verification_base_fee);
    let account = builder.add_existing_wallet_with_assets(
        Auth::MultisigSmart { approver_set, proc_policy_map },
        [fee_asset],
    )?;

    Ok(MultisigSmartFixture {
        builder,
        account,
        signers: public_keys.into_iter().zip(authenticators).collect(),
    })
}

/// Executes an empty transaction against a wallet with the multisig smart auth component on a
/// fee-charging mock chain, signing the summary with every approver.
async fn execute_fee_paying_multisig_smart_tx(
    num_approvers: usize,
) -> anyhow::Result<ExecutedTransaction> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    let MultisigSmartFixture { builder, account, signers } =
        multisig_smart_fixture(num_approvers, VERIFICATION_BASE_FEE, vec![])?;
    let mock_chain = builder.build()?;

    let salt = Word::from([9u32, 10, 11, 12]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id));

    let mock_tx_builder = mock_chain.build_transaction(account.id()).multisig_auth_args(auth_args);

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

    Ok(signed_builder.build()?.execute().await?)
}

// TESTS
// ================================================================================================

/// The multisig smart auth procedure must pay the transaction fee, exactly as the plain multisig
/// component does.
///
/// Before this was fixed, the component decoded the conversion info through
/// `multisig::resolve_auth_args` and then discarded it, so a smart account transacted for free on a
/// fee-charging chain. Nothing else covered for it: the transaction kernel stopped charging the fee
/// when it moved into the auth procedure, and neither the batch nor the block kernel validates that
/// a transaction paid one. The result was a silent economic hole rather than a loud failure — smart
/// accounts settled nothing while singlesig and plain multisig accounts paid.
#[tokio::test]
async fn multisig_smart_pays_fee_note() -> anyhow::Result<()> {
    let executed_transaction = execute_fee_paying_multisig_smart_tx(2).await?;

    assert_single_fee_note(&executed_transaction)?;

    Ok(())
}

/// The cycle estimate the component passes to `pay_fee` must remain an upper bound on the cycles
/// actually spent authenticating, and must bill every approver.
///
/// Unlike the guarded component, the smart component verifies no signature beyond the approvers',
/// so it passes the approver count through unchanged. Two assertions, because the two properties
/// are different: the upper bound is a statement about measured cycles, while billing the right
/// number of signers shows up only in the fee, since the estimate feeds `compute_fee` and nothing
/// else. The second reads the fee note's amount against the bracket an estimate one signer short
/// would land in.
///
/// This runs on the account with no procedure policies, so it does not cover the cost of the
/// per-procedure policy scan in `multisig_smart::auth_tx`. That is covered by
/// `multisig_smart_honors_no_output_notes_policy_while_paying_the_fee`, whose fee assertion
/// compares the paid amount against the fee computed from the cycles that transaction actually
/// spent.
#[tokio::test]
async fn multisig_smart_auth_cycles_stay_within_the_estimate() -> anyhow::Result<()> {
    let num_approvers = 2;
    let executed_transaction = execute_fee_paying_multisig_smart_tx(num_approvers).await?;

    let auth_estimate = num_approvers * FALCON_512_POSEIDON2_AUTH_CYCLES
        + MULTISIG_AUTH_BASE_CYCLES
        + PAY_FEE_CYCLES;

    let measured_cycles = executed_transaction.measurements().auth_procedure;
    assert!(
        measured_cycles <= auth_estimate,
        "measured auth cycles {measured_cycles} should stay within the estimate {auth_estimate}",
    );

    // A fee floor for an estimate that bills one approver too few. `pay_fee` adds its own margins
    // on top of the estimate, so this is a floor rather than the exact amount such a component
    // would pay; the paid amount exceeding it is what shows every approver was billed.
    let estimate_one_signer_short = (num_approvers - 1) * FALCON_512_POSEIDON2_AUTH_CYCLES
        + MULTISIG_AUTH_BASE_CYCLES
        + PAY_FEE_CYCLES;
    let fee_floor_one_signer_short =
        u64::from(VERIFICATION_BASE_FEE) * u64::from(estimate_one_signer_short.ilog2() + 1);

    let fee_asset = assert_single_fee_note(&executed_transaction)?;
    assert!(
        fee_asset.amount().as_u64() > fee_floor_one_signer_short,
        "paid fee {} should exceed the {fee_floor_one_signer_short} floor for an estimate billing \
         only {} of the {num_approvers} approvers",
        fee_asset.amount().as_u64(),
        num_approvers - 1,
    );

    Ok(())
}

/// A transaction with no note restrictions must be able to pay the fee and create its own output
/// note in the same transaction.
///
/// Every other fee-paying test here asserts the fee note is the transaction's *only* output note,
/// which is only true because those transactions create none of their own. That leaves the ordinary
/// case — send a note, pay the fee — asserted nowhere, and it is the case a mistake would break: if
/// the no-output-notes check were applied to the default policy path rather than only where a
/// policy sets the restriction bit, this transaction would abort and no other test would notice.
#[tokio::test]
async fn multisig_smart_pays_fee_alongside_a_user_output_note() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let sent_asset = FungibleAsset::new(fee_faucet_id, 7)?;

    let MultisigSmartFixture { builder, account, signers } =
        multisig_smart_fixture(2, VERIFICATION_BASE_FEE, vec![])?;
    let mock_chain = builder.build()?;

    let output_note: Note = P2idNote::builder()
        .sender(account.id())
        .target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into()?)
        .asset(sent_asset)
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::from([57u32, 58, 59, 60])))
        .build()?
        .into();

    let send_note_script =
        SendNotesTransactionScript::new(&account.code_interface(), &[output_note.clone().into()])?;

    let salt = Word::from([61u32, 62, 63, 64]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id));

    let mock_tx_builder = mock_chain
        .build_transaction(account.id())
        .expected_output_note(RawOutputNote::Full(output_note))
        .send_notes_script(&send_note_script)
        .multisig_auth_args(auth_args);

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

    let executed_transaction = signed_builder.build()?.execute().await?;

    // Both notes are present, and the fee still covers what the transaction actually cost.
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 2);
    let fee_note = (0..output_notes.num_notes())
        .map(|index| output_notes.get_note(index))
        .find(|note| note.metadata().tag() == TxFeeNote::TAG)
        .expect("the transaction should create a fee note alongside the user's note");
    let paid = fee_note
        .assets()
        .iter()
        .next()
        .expect("the fee note should carry an asset")
        .unwrap_fungible();
    assert!(
        paid.amount() >= executed_transaction.compute_fee(),
        "paid fee {} should cover the required fee {}",
        paid.amount(),
        executed_transaction.compute_fee(),
    );

    Ok(())
}

/// Omitting the conversion info on a fee-charging chain must fail, and say why.
///
/// This is the other half of the change's declared breaking requirement: callers must now supply
/// `MultisigAuthArgs::with_conversion_info` wherever the fee is non-zero. The singlesig test of the
/// same rule does not cover this path — it omits the advice map entry entirely, taking `pay_fee`'s
/// empty-auth-args shortcut, whereas the multisig components decode through
/// `multisig::resolve_auth_args` and reach the assertion with an empty conversion info word.
///
/// The fee is paid before any signature is verified, so an unsigned transaction reports the fee
/// error rather than an authorization failure.
#[tokio::test]
async fn multisig_smart_fee_payment_fails_without_conversion_info() -> anyhow::Result<()> {
    let MultisigSmartFixture { builder, account, .. } =
        multisig_smart_fixture(2, VERIFICATION_BASE_FEE, vec![])?;
    let mock_chain = builder.build()?;

    let salt = Word::from([49u32, 50, 51, 52]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt);

    let result = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_CONVERSION_INFO_MISSING);

    Ok(())
}

/// The fee payment must be inside what the signers sign.
///
/// This is the reason `pay_fee` runs before the transaction summary is created, and it is otherwise
/// unguarded: every other test derives the message it signs by executing the same transaction
/// unsigned first, so the message is whatever production computes and no assertion looks at what
/// went into it. Here the signatures are taken over a summary produced at rate 1/1 and then
/// replayed against a transaction that pays at rate 2/1. The larger payment changes the fee note
/// and the vault withdrawal, so it must change the summary and invalidate those signatures. Only
/// the rate differs between the two runs — the bound block and the salt are the same, and the auth
/// args themselves are not part of the summary — so the fee payment is the only thing that can move
/// it.
///
/// If the fee were paid after the summary, both runs would produce the same summary and the
/// replayed signatures would authorize a payment the signers never saw.
#[tokio::test]
async fn multisig_smart_fee_payment_is_covered_by_the_signatures() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    let MultisigSmartFixture { builder, account, signers } =
        multisig_smart_fixture(2, VERIFICATION_BASE_FEE, vec![])?;
    let mock_chain = builder.build()?;

    let salt = Word::from([41u32, 42, 43, 44]);
    let block_num = mock_chain.latest_block_header().block_num();
    let auth_args_at_rate =
        |rate_num: u64| -> anyhow::Result<MultisigAuthArgs> {
            Ok(
                MultisigAuthArgs::new(block_num, salt)
                    .with_conversion_info(FeeConversionInfo::new(fee_faucet_id, rate_num, 1)?),
            )
        };

    // Sign the summary of the transaction that pays at rate 1/1.
    let tx_summary = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args_at_rate(1)?)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    let msg = tx_summary.as_ref().to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    // Replay those signatures against the transaction that pays at rate 2/1.
    let mut signed_builder = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args_at_rate(2)?);
    for (public_key, authenticator) in &signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    signed_builder.build()?.execute().await.unwrap_err().unwrap_unauthorized_err();

    Ok(())
}

/// On a chain with a zero verification base fee, no fee note is created and the caller need not
/// commit any conversion info.
///
/// This is the compatibility half of the change: the component now always runs `pay_fee`, so a
/// caller that supplied no conversion info — which every caller did before this change — must still
/// succeed wherever the fee is zero, and the account's assets must be left untouched.
#[tokio::test]
async fn multisig_smart_no_fee_note_on_zero_fee_chain() -> anyhow::Result<()> {
    let MultisigSmartFixture { builder, account, signers } = multisig_smart_fixture(2, 0, vec![])?;
    let mock_chain = builder.build()?;

    let salt = Word::from([33u32, 34, 35, 36]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt);

    let mock_tx_builder = mock_chain.build_transaction(account.id()).multisig_auth_args(auth_args);

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

    let executed_transaction = signed_builder.build()?.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 0);
    assert!(
        executed_transaction.account_patch().vault().is_empty(),
        "a zero fee must leave the account vault untouched",
    );

    Ok(())
}

/// A procedure policy that forbids output notes must still permit the transaction fee note.
///
/// The restriction exists to stop a policied procedure from being used in a transaction that sends
/// assets away. Paying the transaction fee inside the auth procedure creates a TX_FEE output note,
/// so the account's own fee payment must not be counted against the restriction — otherwise the
/// policy would be unsatisfiable on a fee-charging chain and the procedure it guards could never be
/// called again.
#[tokio::test]
async fn multisig_smart_honors_no_output_notes_policy_while_paying_the_fee() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    let no_output_notes_policy = ProcedurePolicy::with_immediate_threshold(1)?
        .with_note_restriction(ProcedurePolicyNoteRestriction::NoOutputNotes);

    let MultisigSmartFixture { mut builder, account, signers } = multisig_smart_fixture(
        2,
        VERIFICATION_BASE_FEE,
        vec![(BasicWallet::receive_asset_root().as_word(), no_output_notes_policy)],
    )?;

    // Consuming a P2ID note invokes the policied `receive_asset` procedure without creating any
    // output note of its own, so the TX_FEE note is the only output note the transaction has.
    let p2id_note = builder.add_p2id_note(
        account.id(),
        account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;
    let mock_chain = builder.build()?;

    let salt = Word::from([17u32, 18, 19, 20]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id));

    let mock_tx_builder = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(p2id_note.id())
        .multisig_auth_args(auth_args);

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

    let executed_transaction = signed_builder.build()?.execute().await?;

    assert_single_fee_note(&executed_transaction)?;

    Ok(())
}

/// A procedure policy that forbids output notes must still reject a transaction that creates an
/// output note of its own, even on a fee-charging chain.
///
/// This is the counterpart to the test above and the reason the restriction is checked against a
/// count sampled before the fee is paid rather than being dropped altogether: tolerating the TX_FEE
/// note must not turn into tolerating the user's notes.
///
/// It does not pin where the count is sampled. With one user note the count is non-zero whether it
/// is read before or after the fee payment, so the transaction aborts either way; the test above is
/// what pins the sampling point. What this one covers is the configuration the change introduces —
/// a restriction still rejecting on a chain where the fee note also exists.
#[tokio::test]
async fn multisig_smart_rejects_user_output_note_under_no_output_notes_policy() -> anyhow::Result<()>
{
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    // The note carries the fee asset simply because the fixture funds the account with it; which
    // asset leaves is immaterial to the restriction under test.
    let sent_asset = FungibleAsset::new(fee_faucet_id, 5)?;

    let no_output_notes_policy = ProcedurePolicy::with_immediate_threshold(1)?
        .with_note_restriction(ProcedurePolicyNoteRestriction::NoOutputNotes);

    let MultisigSmartFixture { builder, account, .. } = multisig_smart_fixture(
        2,
        VERIFICATION_BASE_FEE,
        vec![(BasicWallet::move_asset_to_note_root().as_word(), no_output_notes_policy)],
    )?;
    let mock_chain = builder.build()?;

    let output_note: Note = P2idNote::builder()
        .sender(account.id())
        .target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into()?)
        .asset(sent_asset)
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::from([21u32, 22, 23, 24])))
        .build()?
        .into();

    let send_note_script =
        SendNotesTransactionScript::new(&account.code_interface(), &[output_note.clone().into()])?;

    let salt = Word::from([25u32, 26, 27, 28]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id));

    // The policy check runs before signature verification, so an unsigned transaction still
    // surfaces the output-note error rather than an unauthorized error.
    let result = mock_chain
        .build_transaction(account.id())
        .expected_output_note(RawOutputNote::Full(output_note))
        .send_notes_script(&send_note_script)
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES);

    Ok(())
}
