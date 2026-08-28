use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKey};
use miden_protocol::account::{Account, AccountProcedureRoot, StorageMapKey};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_standards::account::auth::{
    Approver,
    ApproverSet,
    AuthGuardedMultisig,
    FeeConversionInfo,
    GuardianConfig,
    MultisigAuthArgs,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES,
    ERR_FEE_CONVERSION_INFO_MISSING,
    ERR_FEE_PAYMENT_EXCEEDS_MARGIN,
};
use miden_standards::note::{P2idNote, TxFeeNote};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};

use super::super::multisig::{MultisigAuthArgsExt, setup_keys_and_authenticators_with_scheme};
use super::{
    FALCON_512_POSEIDON2_AUTH_CYCLES,
    MULTISIG_AUTH_BASE_CYCLES,
    PAY_FEE_CYCLES,
    VERIFICATION_BASE_FEE,
    assert_single_fee_note,
};
use crate::prove_and_verify_transaction;

// HELPER FUNCTIONS
// ================================================================================================

/// Amount of the fee asset the fixture funds the account with.
const FEE_ASSET_AMOUNT: u64 = 1_000_000;

/// A guarded multisig wallet on a fee-charging chain, with the keys needed to sign for it.
struct GuardedMultisigFixture {
    mock_chain: MockChain,
    account: Account,
    signers: Vec<(PublicKey, BasicAuthenticator)>,
    guardian_public_key: PublicKey,
    guardian_authenticator: BasicAuthenticator,
}

/// Builds a wallet with the guarded multisig auth component on a mock chain charging
/// `verification_base_fee`, funded with enough of the fee asset to pay the transaction fee.
///
/// The guardian signs with Falcon so that the guardian's verification costs the same as an
/// approver's. That keeps the cycle estimate assertion load-bearing: with a cheaper ECDSA guardian
/// the slack left by the component's per-signer Falcon bound would hide a missing signer.
fn guarded_multisig_fixture(
    num_approvers: usize,
    verification_base_fee: u32,
) -> anyhow::Result<GuardedMultisigFixture> {
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

    let guardian_secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let guardian_public_key = guardian_secret_key.public_key();
    let guardian_authenticator =
        BasicAuthenticator::new(core::slice::from_ref(&guardian_secret_key));
    let guardian_config = GuardianConfig::new(Approver::new(
        guardian_public_key.to_commitment(),
        AuthScheme::Falcon512Poseidon2,
    ));

    let mut builder = MockChain::builder().verification_base_fee(verification_base_fee);
    let account = builder.add_existing_wallet_with_assets(
        Auth::GuardedMultisig {
            approver_set,
            guardian_config,
            proc_threshold_map: vec![],
        },
        [fee_asset],
    )?;
    let mock_chain = builder.build()?;

    Ok(GuardedMultisigFixture {
        mock_chain,
        account,
        signers: public_keys.into_iter().zip(authenticators).collect(),
        guardian_public_key,
        guardian_authenticator,
    })
}

/// Like [`guarded_multisig_fixture`] but with an explicit default spending threshold (which may be
/// below the number of signers) and a per-procedure threshold map, so a reduced-quorum
/// authorization path can be exercised.
fn guarded_multisig_fixture_with_thresholds(
    num_signers: usize,
    default_threshold: u32,
    verification_base_fee: u32,
    proc_threshold_map: Vec<(AccountProcedureRoot, u32)>,
) -> anyhow::Result<GuardedMultisigFixture> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, FEE_ASSET_AMOUNT)?.into();

    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(
            num_signers,
            default_threshold as usize,
            AuthScheme::Falcon512Poseidon2,
        )?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(public_key, auth_scheme)| Approver::new(public_key.to_commitment(), *auth_scheme))
        .collect();
    let approver_set = ApproverSet::new(approvers, default_threshold)?;

    let guardian_secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let guardian_public_key = guardian_secret_key.public_key();
    let guardian_authenticator =
        BasicAuthenticator::new(core::slice::from_ref(&guardian_secret_key));
    let guardian_config = GuardianConfig::new(Approver::new(
        guardian_public_key.to_commitment(),
        AuthScheme::Falcon512Poseidon2,
    ));

    let mut builder = MockChain::builder().verification_base_fee(verification_base_fee);
    let account = builder.add_existing_wallet_with_assets(
        Auth::GuardedMultisig {
            approver_set,
            guardian_config,
            proc_threshold_map,
        },
        [fee_asset],
    )?;
    let mock_chain = builder.build()?;

    Ok(GuardedMultisigFixture {
        mock_chain,
        account,
        signers: public_keys.into_iter().zip(authenticators).collect(),
        guardian_public_key,
        guardian_authenticator,
    })
}

/// Executes an empty transaction against a wallet with the guarded multisig auth component on a
/// fee-charging mock chain, signing the summary with every approver and the guardian.
async fn execute_fee_paying_guarded_multisig_tx(
    num_approvers: usize,
) -> anyhow::Result<ExecutedTransaction> {
    let fixture = guarded_multisig_fixture(num_approvers, VERIFICATION_BASE_FEE)?;
    let mock_chain = &fixture.mock_chain;

    let salt = Word::from([9u32, 10, 11, 12]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(ACCOUNT_ID_FEE_FAUCET.try_into()?));

    let mock_tx_builder =
        mock_chain.build_transaction(fixture.account.id()).multisig_auth_args(auth_args);

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
    for (public_key, authenticator) in &fixture.signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    let guardian_signature = fixture
        .guardian_authenticator
        .get_signature(fixture.guardian_public_key.to_commitment(), &signing_inputs)
        .await?;
    signed_builder = signed_builder.add_signature(
        fixture.guardian_public_key.to_commitment(),
        msg,
        guardian_signature,
    );

    Ok(signed_builder.build()?.execute().await?)
}

// TESTS
// ================================================================================================

/// The guarded multisig auth procedure must pay the transaction fee, exactly as the plain multisig
/// component does.
///
/// Before this was fixed, the component decoded the conversion info through
/// `multisig::resolve_auth_args` and then discarded it, so a guarded account transacted for free on
/// a fee-charging chain. Nothing else covered for it: the transaction kernel stopped charging the
/// fee when it moved into the auth procedure, and neither the batch nor the block kernel validates
/// that a transaction paid one. The result was a silent economic hole rather than a loud failure —
/// guarded accounts settled nothing while singlesig and plain multisig accounts paid.
#[tokio::test]
async fn guarded_multisig_pays_fee_note() -> anyhow::Result<()> {
    let executed_transaction = execute_fee_paying_guarded_multisig_tx(2).await?;

    assert_single_fee_note(&executed_transaction)?;

    Ok(())
}

/// The cycle estimate the component passes to `pay_fee` must remain an upper bound on the cycles
/// actually spent authenticating, and the guardian's verification must be billed for.
///
/// Two separate properties, and they need different assertions. That the estimate is an upper bound
/// is a statement about measured cycles. That the guardian is billed for is not: the estimate feeds
/// `compute_fee` only, so removing the component's `add.1` leaves the measured cycle count
/// unchanged and shows up solely in the fee the account pays. The second assertion therefore reads
/// the fee note's amount.
///
/// The fee is `verification_base_fee` times the bit length of the estimated cycle count, so billing
/// one signer fewer costs a whole power-of-two step. The fixture's guardian signs with Falcon so
/// that step is actually crossed; with the cheaper ECDSA scheme the two estimates would land in the
/// same bracket and the assertion would say nothing.
#[tokio::test]
async fn guarded_multisig_auth_cycles_stay_within_the_estimate() -> anyhow::Result<()> {
    let num_approvers = 2;
    let executed_transaction = execute_fee_paying_guarded_multisig_tx(num_approvers).await?;
    let measured_cycles = executed_transaction.measurements().auth_procedure;

    // The approvers plus the guardian each contribute a signature verification.
    let auth_estimate = (num_approvers + 1) * FALCON_512_POSEIDON2_AUTH_CYCLES
        + MULTISIG_AUTH_BASE_CYCLES
        + PAY_FEE_CYCLES;
    assert!(
        measured_cycles <= auth_estimate,
        "measured auth cycles {measured_cycles} should stay within the estimate {auth_estimate}",
    );

    // A fee floor for an estimate that bills only the approvers. `pay_fee` adds its own margins on
    // top of the estimate, so this is a floor rather than the exact amount such a component would
    // pay; the paid amount exceeding it is what shows the guardian's signer was billed.
    let estimate_without_guardian = num_approvers * FALCON_512_POSEIDON2_AUTH_CYCLES
        + MULTISIG_AUTH_BASE_CYCLES
        + PAY_FEE_CYCLES;
    let fee_floor_without_guardian =
        u64::from(VERIFICATION_BASE_FEE) * u64::from(estimate_without_guardian.ilog2() + 1);

    let fee_asset = assert_single_fee_note(&executed_transaction)?;
    assert!(
        fee_asset.amount().as_u64() > fee_floor_without_guardian,
        "paid fee {} should exceed the {fee_floor_without_guardian} floor for an estimate billing \
         only the {num_approvers} approvers, otherwise the component's extra signer is not \
         load-bearing",
        fee_asset.amount().as_u64(),
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
async fn guarded_multisig_fee_payment_fails_without_conversion_info() -> anyhow::Result<()> {
    let fixture = guarded_multisig_fixture(2, VERIFICATION_BASE_FEE)?;
    let mock_chain = &fixture.mock_chain;

    let salt = Word::from([45u32, 46, 47, 48]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt);

    let result = mock_chain
        .build_transaction(fixture.account.id())
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
async fn guarded_multisig_fee_payment_is_covered_by_the_signatures() -> anyhow::Result<()> {
    let fixture = guarded_multisig_fixture(2, VERIFICATION_BASE_FEE)?;
    let mock_chain = &fixture.mock_chain;
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    let salt = Word::from([37u32, 38, 39, 40]);
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
        .build_transaction(fixture.account.id())
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
        .build_transaction(fixture.account.id())
        .multisig_auth_args(auth_args_at_rate(2)?);
    for (public_key, authenticator) in &fixture.signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }
    let guardian_signature = fixture
        .guardian_authenticator
        .get_signature(fixture.guardian_public_key.to_commitment(), &signing_inputs)
        .await?;
    signed_builder = signed_builder.add_signature(
        fixture.guardian_public_key.to_commitment(),
        msg,
        guardian_signature,
    );

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
async fn guarded_multisig_no_fee_note_on_zero_fee_chain() -> anyhow::Result<()> {
    let fixture = guarded_multisig_fixture(2, 0)?;
    let mock_chain = &fixture.mock_chain;

    let salt = Word::from([29u32, 30, 31, 32]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt);

    let mock_tx_builder =
        mock_chain.build_transaction(fixture.account.id()).multisig_auth_args(auth_args);

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
    for (public_key, authenticator) in &fixture.signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    let guardian_signature = fixture
        .guardian_authenticator
        .get_signature(fixture.guardian_public_key.to_commitment(), &signing_inputs)
        .await?;
    signed_builder = signed_builder.add_signature(
        fixture.guardian_public_key.to_commitment(),
        msg,
        guardian_signature,
    );

    let executed_transaction = signed_builder.build()?.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 0);
    assert!(
        executed_transaction.account_patch().vault().is_empty(),
        "a zero fee must leave the account vault untouched",
    );

    Ok(())
}

/// Rotating the guardian public key must keep working on a fee-charging chain.
///
/// The rotation path is the account's only way to replace a lost or compromised guardian key, and
/// it deliberately runs without a guardian signature. To keep that exemption narrow,
/// `guardian::verify_signature` requires the rotation to be the transaction's only non-auth
/// procedure call and to touch no notes at all. Paying the transaction fee inside the auth
/// procedure creates a TX_FEE output note, so the account's own fee payment must not be counted
/// against that no-output-notes requirement — otherwise a guarded account on a fee-charging chain
/// could never rotate its guardian key again.
#[tokio::test]
async fn guarded_multisig_rotates_guardian_key_while_paying_the_fee() -> anyhow::Result<()> {
    let fixture = guarded_multisig_fixture(2, VERIFICATION_BASE_FEE)?;
    let mock_chain = &fixture.mock_chain;

    let new_guardian_secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let new_guardian_key_word: Word = new_guardian_secret_key.public_key().to_commitment().into();
    let new_guardian_scheme_id = new_guardian_secret_key.auth_scheme() as u32;

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

    let salt = Word::from([13u32, 14, 15, 16]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(ACCOUNT_ID_FEE_FAUCET.try_into()?));

    let mock_tx_builder = mock_chain
        .build_transaction(fixture.account.id())
        .tx_script(update_guardian_script)
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

    // The rotation path verifies no guardian signature, only the approvers'.
    let mut signed_builder = mock_tx_builder;
    for (public_key, authenticator) in &fixture.signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    let executed_transaction = signed_builder.build()?.execute().await?;

    let fee_asset = assert_single_fee_note(&executed_transaction)?;

    // The rotation must have taken effect, not merely been authorized, and the fee must have left
    // the vault.
    let mut rotated_account = fixture.account.clone();
    rotated_account.apply_patch(executed_transaction.account_patch())?;
    assert_eq!(
        rotated_account.storage().get_map_item(
            AuthGuardedMultisig::guardian_public_key_slot(),
            StorageMapKey::empty()
        )?,
        new_guardian_key_word,
    );
    assert_eq!(
        rotated_account.vault().get_balance(fee_asset.into())?.as_u64(),
        FEE_ASSET_AMOUNT - fee_asset.amount().as_u64(),
    );

    Ok(())
}

/// An ordinary transaction must be able to pay the fee and create its own output note in the same
/// transaction.
///
/// Every other fee-paying test here asserts the fee note is the transaction's *only* output note,
/// which is only true because those transactions create none of their own. The guardian key
/// rotation path is the only one that forbids output notes; if that restriction leaked onto the
/// ordinary path, this transaction would abort and no other test would notice.
#[tokio::test]
async fn guarded_multisig_pays_fee_alongside_a_user_output_note() -> anyhow::Result<()> {
    let fee_faucet_id: miden_protocol::account::AccountId = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let sent_asset = FungibleAsset::new(fee_faucet_id, 7)?;

    let fixture = guarded_multisig_fixture(2, VERIFICATION_BASE_FEE)?;
    let mock_chain = &fixture.mock_chain;

    let output_note: Note = P2idNote::builder()
        .sender(fixture.account.id())
        .target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into()?)
        .asset(sent_asset)
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::from([65u32, 66, 67, 68])))
        .build()?
        .into();

    let send_note_script = SendNotesTransactionScript::new(
        &fixture.account.code_interface(),
        &[output_note.clone().into()],
    )?;

    let salt = Word::from([69u32, 70, 71, 72]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id));

    let mock_tx_builder = mock_chain
        .build_transaction(fixture.account.id())
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
    for (public_key, authenticator) in &fixture.signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }
    let guardian_signature = fixture
        .guardian_authenticator
        .get_signature(fixture.guardian_public_key.to_commitment(), &signing_inputs)
        .await?;
    signed_builder = signed_builder.add_signature(
        fixture.guardian_public_key.to_commitment(),
        msg,
        guardian_signature,
    );

    let executed_transaction = signed_builder.build()?.execute().await?;

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

/// A fee-paying transaction must prove, and prove to the same transaction ID it executed to.
///
/// The fee amount is a function of the cycle count at the `compute_fee` call, so it depends on the
/// executor and the prover agreeing on that count — the executor runs the fast processor, the
/// prover the trace-generating one. A disagreement large enough to cross a power-of-two boundary
/// would change the fee, therefore the TX_FEE note, therefore the transaction ID, and the proof
/// would commit to a different transaction than the one the signers authorized.
///
/// No other test in the repository proves a transaction that pays a non-zero fee: the proving tests
/// all run on chains with a zero verification base fee, which take `pay_fee`'s no-note branch. This
/// is the one place that axis is covered, so it is worth its proving time.
#[tokio::test]
async fn guarded_multisig_fee_paying_transaction_proves() -> anyhow::Result<()> {
    let executed_transaction = execute_fee_paying_guarded_multisig_tx(2).await?;
    assert_single_fee_note(&executed_transaction)?;

    prove_and_verify_transaction(executed_transaction).await?;

    Ok(())
}

/// The guardian key rotation path must still reject the transaction's own output notes on a
/// fee-charging chain.
///
/// The counterpart to the test above, and the reason the rotation path checks a count sampled
/// before the fee is paid rather than dropping the check: exempting the TX_FEE note must not exempt
/// the user's notes. The pre-existing coverage of this rejection
/// (`test_guarded_multisig_update_guardian_enforces_no_notes`) runs on a chain with a zero
/// verification base fee, so it never reaches `pay_fee`'s paying branch — the branch that creates
/// the note the sampled count exists to tolerate.
#[tokio::test]
async fn guarded_multisig_rotation_rejects_user_output_note_while_paying_the_fee()
-> anyhow::Result<()> {
    let fixture = guarded_multisig_fixture(2, VERIFICATION_BASE_FEE)?;
    let mock_chain = &fixture.mock_chain;

    let new_guardian_key_word: Word =
        AuthSecretKey::new_falcon512_poseidon2().public_key().to_commitment().into();

    // Rotate the guardian key and create an output note in the same transaction.
    let script = CodeBuilder::new()
        .with_dynamically_linked_package(AuthGuardedMultisig::code())?
        .compile_tx_script(format!(
            "
            @transaction_script
            pub proc main
                push.1.0.0.1
                push.{note_type}
                push.0
                # => [tag, note_type, RECIPIENT, pad(16)]

                call.::miden::standards::note::note_creator::create_note
                # => [note_idx, pad(21)]

                drop dropw drop
                # => [pad(16)]

                push.{new_guardian_key_word}
                push.{scheme_id}
                call.::miden::standards::components::auth::guarded_multisig::update_guardian_public_key
                drop dropw
            end
            ",
            note_type = NoteType::Private as u8,
            scheme_id = AuthScheme::Falcon512Poseidon2 as u32,
        ))?;

    let salt = Word::from([53u32, 54, 55, 56]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::one_to_one(ACCOUNT_ID_FEE_FAUCET.try_into()?));

    let mock_tx_builder = mock_chain
        .build_transaction(fixture.account.id())
        .tx_script(script)
        .multisig_auth_args(auth_args);

    // The guardian check runs after the approvers are verified, so the approvers must sign for the
    // transaction to reach it at all — an unsigned one fails as unauthorized instead.
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
    for (public_key, authenticator) in &fixture.signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    let result = signed_builder.build()?.execute().await;

    assert_transaction_executor_error!(result, ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES);

    Ok(())
}

/// A reduced-quorum authorization path must not be able to drain the vault through an inflated fee
/// conversion rate.
///
/// This is the guarded-multisig instance of the fee-drain tracked in #3763. The guardian-rotation
/// path runs without a guardian signature, and a per-procedure threshold override lets it run below
/// the account's default spending quorum. Before the paid amount was bounded, a single approver
/// could rotate the guardian while supplying a conversion rate that moved the account's entire
/// fee-asset balance into the TX_FEE note — theft or griefing authorized by one signer where a spend
/// needs two. The bound in `pay_fee` now rejects any payment exceeding `MAX_FEE_PAYMENT_MARGIN`
/// times the computed fee. Because `pay_fee` runs before the transaction summary is created, the
/// inflated rate aborts the transaction before it reaches signature verification, so no summary is
/// produced to sign.
#[tokio::test]
async fn guarded_multisig_rotation_cannot_drain_the_vault_via_the_fee_rate() -> anyhow::Result<()> {
    let update_guardian_root = AuthGuardedMultisig::code()
        .get_procedure_root_by_path(
            "miden::standards::components::auth::guarded_multisig::update_guardian_public_key",
        )
        .expect("guarded multisig should export update_guardian_public_key");

    // Three signers, default spending threshold two, but guardian rotation overridden to a single
    // signature — the reduced-quorum path the drain abuses.
    let fixture = guarded_multisig_fixture_with_thresholds(
        3,
        2,
        VERIFICATION_BASE_FEE,
        vec![(update_guardian_root, 1)],
    )?;
    let mock_chain = &fixture.mock_chain;
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    let new_guardian_key_word: Word =
        AuthSecretKey::new_falcon512_poseidon2().public_key().to_commitment().into();
    let new_guardian_scheme_id = AuthScheme::Falcon512Poseidon2 as u32;

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

    // Pay the fee in the native asset, but at a rate that would move the account's entire fee-asset
    // balance into the fee note — orders of magnitude above the allowed margin over the fee.
    let salt = Word::from([81u32, 82, 83, 84]);
    let auth_args = MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), salt)
        .with_conversion_info(FeeConversionInfo::new(fee_faucet_id, FEE_ASSET_AMOUNT, 1)?);

    let result = mock_chain
        .build_transaction(fixture.account.id())
        .tx_script(update_guardian_script)
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_PAYMENT_EXCEEDS_MARGIN);

    Ok(())
}
