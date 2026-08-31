use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKey};
use miden_protocol::account::{AccountProcedureRoot, StorageMapKey};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::errors::tx_kernel::ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteRecipient,
    NoteStorage,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
};
use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote, TransactionSummary};
use miden_protocol::{Felt, Word, ZERO};
use miden_standards::account::auth::{
    Approver,
    ApproverSet,
    AuthGuardedMultisig,
    FeeConversionInfo,
    GuardianConfig,
    commit_fee_conversion_info,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES,
    ERR_FEE_PAYMENT_EXCEEDS_BOUND,
    ERR_FEE_PAYMENT_FAUCET_NOT_NATIVE,
};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rstest::rstest;

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

/// A guarded multisig fixture: an approver set of Falcon signers with the threshold set to all of
/// them, plus a separate guardian using `guardian_scheme`.
struct GuardedFixture {
    approver_set: ApproverSet,
    signers: Vec<(PublicKey, BasicAuthenticator)>,
    guardian_config: GuardianConfig,
    guardian_public_key: PublicKey,
    guardian_authenticator: BasicAuthenticator,
}

fn guarded_fixture(
    num_approvers: usize,
    guardian_scheme: AuthScheme,
) -> anyhow::Result<GuardedFixture> {
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

    let guardian_secret_key = match guardian_scheme {
        AuthScheme::EcdsaK256Keccak => AuthSecretKey::new_ecdsa_k256_keccak(),
        AuthScheme::Falcon512Poseidon2 => AuthSecretKey::new_falcon512_poseidon2(),
        _ => anyhow::bail!("unsupported guardian auth scheme for this test: {guardian_scheme:?}"),
    };
    let guardian_public_key = guardian_secret_key.public_key();
    let guardian_authenticator =
        BasicAuthenticator::new(core::slice::from_ref(&guardian_secret_key));
    let guardian_config =
        GuardianConfig::new(Approver::new(guardian_public_key.to_commitment(), guardian_scheme));

    Ok(GuardedFixture {
        approver_set,
        signers,
        guardian_config,
        guardian_public_key,
        guardian_authenticator,
    })
}

/// Asserts that `auth_args` is bound by the summary as the trailing word of its user parameters,
/// which is how the guarded multisig auth component uses the auth args as the summary salt after
/// `load_conversion_info` has consumed the original.
fn assert_auth_args_bound_as_salt(tx_summary: &TransactionSummary, auth_args: Word) {
    assert_eq!(
        tx_summary.user_params().as_elements(),
        &[ZERO, ZERO, ZERO, auth_args[0], auth_args[1], auth_args[2], auth_args[3]]
    );
}

/// Executes an empty transaction against a guarded multisig wallet on a fee-charging mock chain,
/// signing the summary with every approver and the guardian.
async fn execute_fee_paying_guarded_multisig_tx(
    num_approvers: usize,
    guardian_scheme: AuthScheme,
) -> anyhow::Result<ExecutedTransaction> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let fixture = guarded_fixture(num_approvers, guardian_scheme)?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::GuardedMultisig {
            approver_set: fixture.approver_set,
            guardian_config: fixture.guardian_config,
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

    // The auth args (the conversion info commitment) still serve as the transaction summary salt.
    assert_auth_args_bound_as_salt(&tx_summary, args);

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

/// Builds the source of a tx script that rotates the guardian public key, optionally creating
/// `output_note` first so the rotation path's output-note guard is exercised.
fn build_update_guardian_script_source(
    new_guardian_key_word: Word,
    new_guardian_scheme_id: u32,
    output_note: Option<&Note>,
) -> String {
    let create_note_prelude = match output_note {
        Some(out) => {
            let recipient = out.recipient().digest();
            let note_type = NoteType::Public as u8;
            let tag = Felt::from(out.metadata().tag());
            format!(
                "
                    push.{recipient}
                    push.{note_type}
                    push.{tag}
                    call.::miden::standards::note::note_creator::create_note
                    movdn.15 dropw dropw dropw drop drop drop
                    swapdw
                    dropw
                    dropw
                "
            )
        },
        None => String::new(),
    };

    format!(
        "
        @transaction_script
        pub proc main
            {create_note_prelude}
            push.{new_guardian_key_word}
            push.{new_guardian_scheme_id}
            call.::miden::standards::components::auth::guarded_multisig::update_guardian_public_key
            drop dropw
        end
        "
    )
}

/// Runs a guardian rotation against a funded guarded multisig account, paying the fee with the
/// given conversion info. Returns the execution result, signed by the approvers only — rotation
/// intentionally skips the guardian signature, which is the point of the path.
async fn execute_rotation_with_conversion_info(
    conversion_info: FeeConversionInfo,
    salt: Word,
    proc_threshold_map: Vec<(AccountProcedureRoot, u32)>,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let fixture = guarded_fixture(2, AuthScheme::EcdsaK256Keccak)?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::GuardedMultisig {
            approver_set: fixture.approver_set,
            guardian_config: fixture.guardian_config,
            proc_threshold_map,
        },
        [fee_asset],
    )?;
    let mock_chain = builder.build()?;

    let new_guardian_key_word: Word =
        AuthSecretKey::new_falcon512_poseidon2().public_key().to_commitment().into();
    let update_guardian_script = CodeBuilder::new()
        .with_dynamically_linked_package(AuthGuardedMultisig::code())?
        .compile_tx_script(build_update_guardian_script_source(
            new_guardian_key_word,
            AuthScheme::Falcon512Poseidon2 as u32,
            None,
        ))?;

    let (args, advice_value) = commit_fee_conversion_info(conversion_info, salt);

    Ok(mock_chain
        .build_transaction(account.id())
        .tx_script(update_guardian_script)
        .auth_args(args)
        .add_advice_map_entry(args, advice_value)
        .build()?
        .execute()
        .await)
}

// TESTS
// ================================================================================================

/// The guarded multisig auth procedure must pay the transaction fee, exactly as the plain multisig
/// component does, and must do so within the cycle estimate it hands to the fee flow.
///
/// It never paid one, so a guarded account transacted for free on a fee-charging chain. Nothing
/// else covered for it: the fee moved out of the kernel epilogue into the auth procedure, and
/// neither the batch nor the block kernel validates that a transaction paid one.
///
/// The guarded component verifies the guardian signature on top of the approvers', so its estimate
/// counts one more signer than there are approvers. Only the `paid >= required` assertion inside
/// `assert_single_fee_note` can catch an estimate that is too low, and only where the missing slot
/// straddles a fee bucket edge — which is the sole reason the `single_falcon_approver` case exists.
/// Dropping the extra signer there under-pays, at 8500 against a required 9000.
#[rstest]
#[case::ecdsa_guardian(AuthScheme::EcdsaK256Keccak, 2)]
#[case::falcon_guardian(AuthScheme::Falcon512Poseidon2, 2)]
#[case::single_falcon_approver(AuthScheme::Falcon512Poseidon2, 1)]
#[tokio::test]
async fn guarded_multisig_pays_fee_note_within_the_cycle_estimate(
    #[case] guardian_scheme: AuthScheme,
    #[case] num_approvers: usize,
) -> anyhow::Result<()> {
    let executed_transaction =
        execute_fee_paying_guarded_multisig_tx(num_approvers, guardian_scheme).await?;

    let fee_asset = assert_single_fee_note(&executed_transaction)?;

    // The overshoot is bounded: the estimate should not overpay by more than a few base fee units.
    let required_fee = executed_transaction.compute_fee();
    let max_overpayment = u64::from(3 * VERIFICATION_BASE_FEE);
    assert!(
        fee_asset.amount().as_u64() <= required_fee.as_u64() + max_overpayment,
        "paid fee {} should not exceed the required fee {required_fee} by more than \
         {max_overpayment}",
        fee_asset.amount()
    );

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

/// Guardian key rotation must still work on a fee-charging chain, and must still reject a
/// transaction that creates output notes of its own.
///
/// The rotation branch of `guardian::verify_signature` calls `tx_policy::assert_no_output_notes`,
/// which compared the live output-note counter against zero. The account's own mandatory fee note
/// therefore tripped a guard meant for user notes, and a lost or compromised guardian key could
/// never be rotated. The auth procedure now passes the number of notes it created itself, which
/// excludes the fee note without excluding the transaction's own notes.
///
/// The two cases pin opposite directions. `without_output_note` fails without this change, because
/// the fee note alone trips the guard. `with_output_note` guards the other direction, that
/// excluding the fee note did not weaken the check into accepting a user note. The fee note could
/// not have been caught by the neighbouring `assert_only_one_non_auth_procedure_called`, since it
/// is created outside any account procedure, which is why the count had to be threaded.
///
/// Invisible to the existing rotation tests because their chains default `verification_base_fee`
/// to 0 — no fee is charged, so no fee note is created and the guard never sees one.
#[rstest]
#[case::without_output_note(false)]
#[case::with_output_note(true)]
#[tokio::test]
async fn guarded_multisig_rotates_guardian_key_while_paying_the_fee(
    #[case] include_output_note: bool,
) -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let fixture = guarded_fixture(2, AuthScheme::EcdsaK256Keccak)?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::GuardedMultisig {
            approver_set: fixture.approver_set,
            guardian_config: fixture.guardian_config,
            proc_threshold_map: vec![],
        },
        [fee_asset],
    )?;
    let mock_chain = builder.build()?;

    let new_guardian_secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let new_guardian_public_key = new_guardian_secret_key.public_key();
    let new_guardian_scheme = new_guardian_secret_key.auth_scheme();
    let new_guardian_key_word: Word = new_guardian_public_key.to_commitment().into();

    // A no-op output note, created by the tx script before the rotation when the case asks for it.
    let output_note = if include_output_note {
        let recipient = NoteRecipient::new(
            Word::from([1u32, 2, 3, 4]),
            CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT)?,
            NoteStorage::default(),
        );
        Some(Note::new(
            NoteAssets::new(vec![])?,
            PartialNoteMetadata::new(account.id(), NoteType::Public),
            recipient,
        ))
    } else {
        None
    };

    let update_guardian_script = CodeBuilder::new()
        .with_dynamically_linked_package(AuthGuardedMultisig::code())?
        .compile_tx_script(build_update_guardian_script_source(
            new_guardian_key_word,
            new_guardian_scheme as u32,
            output_note.as_ref(),
        ))?;

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([21u32, 22, 23, 24]),
    );

    let mut mock_tx_builder = mock_chain
        .build_transaction(account.id())
        .tx_script(update_guardian_script)
        .auth_args(args)
        .add_advice_map_entry(args, advice_value);
    if let Some(note) = output_note {
        mock_tx_builder = mock_tx_builder.expected_output_note(RawOutputNote::Full(note));
    }

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
    for (public_key, authenticator) in &fixture.signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    let result = signed_builder.build()?.execute().await;

    if include_output_note {
        assert_transaction_executor_error!(
            result,
            ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES
        );
        return Ok(());
    }

    let executed_transaction = result?;

    // The fee is still paid, and the rotation is not blocked by the note it creates.
    assert_single_fee_note(&executed_transaction)?;

    // The new guardian key actually landed in storage.
    let mut rotated_account = account.clone();
    rotated_account.apply_patch(executed_transaction.account_patch())?;
    assert_eq!(
        rotated_account.storage().get_map_item(
            AuthGuardedMultisig::guardian_public_key_slot(),
            StorageMapKey::empty()
        )?,
        Word::from(new_guardian_public_key.to_commitment())
    );
    assert_eq!(
        rotated_account
            .storage()
            .get_map_item(AuthGuardedMultisig::guardian_scheme_id_slot(), StorageMapKey::empty())?,
        Word::from([new_guardian_scheme as u32, 0, 0, 0])
    );

    Ok(())
}

/// Guardian key rotation cannot outrun the fee: an unfunded vault fails on the withdrawal.
///
/// This pins the recovery constraint documented on [`AuthGuardedMultisig`]. Rotation forbids input
/// notes and assets reach a vault only through one, so the funding transaction must be a separate
/// one — and a separate one takes the ordinary path, which needs a guardian signature. An account
/// that loses its guardian key while holding no fee asset is therefore unrecoverable, which is a
/// property of paying the fee from the authentication procedure rather than an oversight in the
/// rotation guard.
#[tokio::test]
async fn guarded_multisig_rotation_fails_when_the_vault_cannot_fund_the_fee() -> anyhow::Result<()>
{
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fixture = guarded_fixture(2, AuthScheme::EcdsaK256Keccak)?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet(Auth::GuardedMultisig {
        approver_set: fixture.approver_set,
        guardian_config: fixture.guardian_config,
        proc_threshold_map: vec![],
    })?;
    let mock_chain = builder.build()?;

    let new_guardian_public_key = AuthSecretKey::new_falcon512_poseidon2().public_key();
    let update_guardian_script = CodeBuilder::new()
        .with_dynamically_linked_package(AuthGuardedMultisig::code())?
        .compile_tx_script(build_update_guardian_script_source(
            new_guardian_public_key.to_commitment().into(),
            AuthScheme::Falcon512Poseidon2 as u32,
            None,
        ))?;

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([31u32, 32, 33, 34]),
    );

    let result = mock_chain
        .build_transaction(account.id())
        .tx_script(update_guardian_script)
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

/// A reduced-quorum authorization path must not be able to drain the vault through an inflated fee
/// conversion rate.
///
/// This is the guarded-multisig instance of the fee drain tracked in #3763. The guardian-rotation
/// path runs without a guardian signature, and a per-procedure threshold override lets it run below
/// the account's default spending quorum. Unbounded, a single approver could rotate the guardian
/// while supplying a rate that moved the account's entire fee-asset balance into the TX_FEE note —
/// theft authorized by one signer where a spend needs two. The component now calls
/// `fee::assert_fee_bound` between the estimate and the payment, and does so before the summary is
/// created, so the inflated rate aborts before signature verification is even reached.
#[tokio::test]
async fn guarded_multisig_rotation_cannot_drain_the_vault_via_the_fee_rate() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    let update_guardian_root = AuthGuardedMultisig::code()
        .get_procedure_root_by_path(
            "miden::standards::components::auth::guarded_multisig::update_guardian_public_key",
        )
        .expect("guarded multisig should export update_guardian_public_key");

    let result = execute_rotation_with_conversion_info(
        FeeConversionInfo::new(fee_faucet_id, 1_000_000, 1)?,
        Word::from([81u32, 82, 83, 84]),
        vec![(update_guardian_root, 1)],
    )
    .await?;

    assert_transaction_executor_error!(result, ERR_FEE_PAYMENT_EXCEEDS_BOUND);

    Ok(())
}

/// The same path must not be able to pay the fee in an arbitrary asset either.
///
/// The bound compares the payment against a fee denominated in the native fee asset, so it is
/// meaningless across denominations: a foreign token at rate 1/1 satisfies the arithmetic while
/// moving an unrelated asset out of the vault. `assert_fee_bound` therefore pins the payment
/// faucet, and this pins that it is the guarded component reaching that check. `pay_fee` itself
/// still accepts any faucet, which is what keeps foreign-asset fees available to the components
/// that authenticate with full spending authority.
#[tokio::test]
async fn guarded_multisig_rotation_cannot_pay_the_fee_in_a_foreign_asset() -> anyhow::Result<()> {
    let payment_faucet_id = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?;

    let result = execute_rotation_with_conversion_info(
        FeeConversionInfo::one_to_one(payment_faucet_id),
        Word::from([91u32, 92, 93, 94]),
        vec![],
    )
    .await?;

    assert_transaction_executor_error!(result, ERR_FEE_PAYMENT_FAUCET_NOT_NATIVE);

    Ok(())
}
