use miden_processor::advice::AdviceInputs;
use miden_protocol::account::auth::{AuthScheme, PublicKey};
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::transaction::TransactionScript;
use miden_protocol::vm::AdviceMap;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::auth::multisig_smart::{
    DelayedExecutionPolicy,
    ProcedurePolicy,
    ProcedurePolicyNoteRestriction,
};
use miden_standards::account::auth::{AuthMultisigSmart, AuthMultisigSmartConfig};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_NOTES,
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES,
};
use miden_testing::{MockChainBuilder, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{SigningInputs, TransactionAuthenticator};
use rstest::rstest;

use super::multisig::{
    build_update_signers_config_vector,
    setup_keys_and_authenticators_with_scheme,
};

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================

/// Builds a multisig smart account with the given approvers, threshold, starting balance, and
/// procedure policy map. Uses `BasicWallet` so the account exposes `receive_asset` and friends.
fn create_multisig_smart_account(
    threshold: u32,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
    starting_balance: u64,
    proc_policy_map: Vec<(Word, ProcedurePolicy)>,
) -> anyhow::Result<Account> {
    let approvers: Vec<_> =
        public_keys.iter().map(|pk| (pk.to_commitment(), auth_scheme)).collect();
    let config =
        AuthMultisigSmartConfig::new(approvers, threshold, DelayedExecutionPolicy::new(30, 2)?)?
            .with_proc_policies(proc_policy_map)?;

    let asset = FungibleAsset::new(
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?,
        starting_balance,
    )?;

    let multisig_account = AccountBuilder::new([0; 32])
        .with_auth_component(AuthMultisigSmart::new(config)?)
        .with_component(BasicWallet)
        .account_type(AccountType::Public)
        .with_assets(core::iter::once(asset.into()))
        .build_existing()?;

    Ok(multisig_account)
}

/// Compiles a transaction script that links against the multisig smart library so it can `call.`
/// the wrapper-exported procedures.
fn compile_multisig_smart_tx_script(script: impl AsRef<str>) -> anyhow::Result<TransactionScript> {
    Ok(CodeBuilder::default()
        .with_dynamically_linked_library(AuthMultisigSmart::code())?
        .compile_tx_script(script.as_ref())?)
}

/// Builds a 4-lane salt `Word` from a single `u32` seed for transaction `auth_args`. Each
/// transaction in a test should pick a unique seed so that the resulting tx-summary commitments
/// stay distinct across calls.
fn salt(seed: u32) -> Word {
    Word::from([Felt::from(seed); 4])
}

// ================================================================================================
// TESTS
// ================================================================================================

/// A 3-of-3 multisig with a `receive_asset` procedure policy that lowers the threshold to 1
/// should let a single-signature transaction that only calls `receive_asset` succeed.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_receive_asset_policy_overrides_default_three_of_three_to_one_signature(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 3, auth_scheme)?;

    let receive_asset_one_signature_policy = ProcedurePolicy::with_immediate_threshold(1)?;
    let proc_policy_map =
        vec![(BasicWallet::receive_asset_root().as_word(), receive_asset_one_signature_policy)];

    let mut multisig_account =
        create_multisig_smart_account(3, &public_keys, auth_scheme, 10, proc_policy_map)?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();
    let note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        multisig_account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;
    let mut mock_chain = mock_chain_builder.build()?;

    let salt = salt(1);
    let tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .auth_args(salt)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_summary) => tx_summary,
        error => panic!("expected abort with tx summary: {error:?}"),
    };

    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary);
    let one_signature = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;

    let tx_result = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .add_signature(public_keys[0].to_commitment(), msg, one_signature)
        .auth_args(salt)
        .build()?
        .execute()
        .await;

    assert!(
        tx_result.is_ok(),
        "receive_asset policy threshold=1 should override the default 3-of-3 requirement"
    );

    multisig_account.apply_delta(tx_result.as_ref().unwrap().account_delta())?;
    mock_chain.add_pending_executed_transaction(&tx_result.unwrap())?;
    mock_chain.prove_next_block()?;

    Ok(())
}

/// `enforce_note_restrictions` must abort transactions whose note layout violates the configured
/// policy bit set. The receive_asset proc policy carries each restriction variant and the tx
/// consumes a P2ID note (calls receive_asset). The test checks every variant against the
/// "tx has input notes" axis.
#[rstest]
#[case::no_restriction(ProcedurePolicyNoteRestriction::None)]
#[case::no_input_notes(ProcedurePolicyNoteRestriction::NoInputNotes)]
#[case::no_output_notes(ProcedurePolicyNoteRestriction::NoOutputNotes)]
#[case::no_input_or_output_notes(ProcedurePolicyNoteRestriction::NoInputOrOutputNotes)]
#[tokio::test]
async fn test_multisig_smart_enforces_note_restrictions_on_tx_with_input_notes(
    #[case] restriction: ProcedurePolicyNoteRestriction,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, AuthScheme::EcdsaK256Keccak)?;

    let multisig_account = create_multisig_smart_account(
        2,
        &public_keys,
        AuthScheme::EcdsaK256Keccak,
        100,
        vec![(
            BasicWallet::receive_asset_root().as_word(),
            ProcedurePolicy::with_immediate_threshold(1)?.with_note_restriction(restriction),
        )],
    )?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();
    let note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        multisig_account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;
    let mock_chain = mock_chain_builder.build()?;

    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .auth_args(salt(2))
        .build()?
        .execute()
        .await;

    // For restrictions that include the input bit (1, 3), enforce_note_restrictions panics with
    // the input-notes error before signatures are even checked. For the other variants the input
    // bit is unset, so the tx falls through to signature verification and aborts there
    // (no signatures were provided). The output bit (2) does not trigger because the tx has no
    // output notes.
    match restriction {
        ProcedurePolicyNoteRestriction::NoInputNotes
        | ProcedurePolicyNoteRestriction::NoInputOrOutputNotes => {
            assert_transaction_executor_error!(
                result,
                ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_NOTES
            );
        },
        ProcedurePolicyNoteRestriction::None | ProcedurePolicyNoteRestriction::NoOutputNotes => {
            match result {
                Err(TransactionExecutorError::Unauthorized(_)) => {},
                other => panic!("expected Unauthorized (no signatures provided), got: {other:?}"),
            }
        },
    }

    Ok(())
}

/// Mirror of the input-notes test for the output-notes axis. The policy lives on
/// `move_asset_to_note` (the BasicWallet proc invoked when sending notes) and the tx creates a
/// P2ID output note rather than consuming one.
#[rstest]
#[case::no_restriction(ProcedurePolicyNoteRestriction::None)]
#[case::no_input_notes(ProcedurePolicyNoteRestriction::NoInputNotes)]
#[case::no_output_notes(ProcedurePolicyNoteRestriction::NoOutputNotes)]
#[case::no_input_or_output_notes(ProcedurePolicyNoteRestriction::NoInputOrOutputNotes)]
#[tokio::test]
async fn test_multisig_smart_enforces_note_restrictions_on_tx_with_output_notes(
    #[case] restriction: ProcedurePolicyNoteRestriction,
) -> anyhow::Result<()> {
    use miden_processor::crypto::random::RandomCoin;
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
    use miden_protocol::transaction::RawOutputNote;
    use miden_standards::account::interface::{AccountInterface, AccountInterfaceExt};
    use miden_standards::note::P2idNote;

    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, AuthScheme::EcdsaK256Keccak)?;

    let multisig_account = create_multisig_smart_account(
        2,
        &public_keys,
        AuthScheme::EcdsaK256Keccak,
        100,
        vec![(
            BasicWallet::move_asset_to_note_root().as_word(),
            ProcedurePolicy::with_immediate_threshold(1)?.with_note_restriction(restriction),
        )],
    )?;

    let output_note = P2idNote::create(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        vec![FungibleAsset::mock(5)],
        NoteType::Public,
        Default::default(),
        &mut RandomCoin::new(Word::from([Felt::new_unchecked(7); 4])),
    )?;

    let send_note_script = AccountInterface::from_account(&multisig_account)
        .build_send_notes_script(&[output_note.clone().into()], None)?;

    let mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
        .tx_script(send_note_script)
        .auth_args(salt(2))
        .build()?
        .execute()
        .await;

    // For restrictions that include the output bit (2, 3), enforce_note_restrictions panics with
    // the output-notes error after the input check passes. For the other variants neither check
    // trips and the tx falls through to signature verification (no signatures were provided).
    match restriction {
        ProcedurePolicyNoteRestriction::NoOutputNotes
        | ProcedurePolicyNoteRestriction::NoInputOrOutputNotes => {
            assert_transaction_executor_error!(
                result,
                ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES
            );
        },
        ProcedurePolicyNoteRestriction::None | ProcedurePolicyNoteRestriction::NoInputNotes => {
            match result {
                Err(TransactionExecutorError::Unauthorized(_)) => {},
                other => panic!("expected Unauthorized (no signatures provided), got: {other:?}"),
            }
        },
    }

    Ok(())
}

/// Tests `update_signers_and_threshold`: a 2-of-2 multisig is rotated to a 4-of-3
/// signer set with new public keys. The new threshold and signers are persisted in storage.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_update_signers_and_thresholds(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let mut multisig_account =
        create_multisig_smart_account(2, &public_keys, auth_scheme, 10, vec![])?;
    let account_id = multisig_account.id();
    let mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    // Generate a fresh 4-signer set; rotate the multisig to 4-of-3 (threshold=3, num_approvers=4).
    let (_new_secret_keys, _new_auth_schemes, new_public_keys, _new_authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;

    let new_threshold: u64 = 3;
    let new_num_approvers: u64 = 4;
    let multisig_config_data = build_update_signers_config_vector(
        new_threshold,
        new_num_approvers,
        &new_public_keys,
        auth_scheme,
    );
    let multisig_config_hash = Hasher::hash_elements(&multisig_config_data);

    let mut advice_map = AdviceMap::default();
    advice_map.insert(multisig_config_hash, multisig_config_data);
    let advice_inputs = AdviceInputs { map: advice_map, ..Default::default() };

    let update_signers_script = compile_multisig_smart_tx_script(
        "
        begin
            call.::miden::standards::components::auth::multisig_smart::update_signers_and_threshold
        end
        ",
    )?;

    let salt = salt(3);

    // Dry-run to obtain the tx summary that the current approvers must sign.
    let tx_summary = match mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(update_signers_script.clone())
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs.clone())
        .auth_args(salt)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_summary) => tx_summary,
        error => panic!("expected abort with tx summary: {error:?}"),
    };

    let msg = tx_summary.as_ref().to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);
    let sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &signing_inputs)
        .await?;
    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &signing_inputs)
        .await?;

    let executed_tx = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(update_signers_script)
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs)
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_delta(executed_tx.account_delta())?;

    // Verify the new threshold/num_approvers config is persisted.
    let threshold_config = multisig_account
        .storage()
        .get_item(AuthMultisigSmart::threshold_config_slot())
        .expect("threshold config slot should be present");
    assert_eq!(threshold_config[0], Felt::new_unchecked(new_threshold));
    assert_eq!(threshold_config[1], Felt::new_unchecked(new_num_approvers));

    // Verify each new public key is stored at its expected map index.
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let storage_key = Word::from([i as u32, 0, 0, 0]);
        let stored_pub_key = multisig_account
            .storage()
            .get_map_item(AuthMultisigSmart::approver_public_keys_slot(), storage_key)
            .expect("approver public key map item should be present");
        let expected_word: Word = expected_key.to_commitment().into();
        assert_eq!(stored_pub_key, expected_word, "public key at index {i} mismatch");
    }

    Ok(())
}

/// `set_procedure_policy` invoked from a transaction script must persist the policy to the
/// `procedure_policies` storage map so subsequent transactions see the new policy.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_set_procedure_policy(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    // Account starts with no procedure policies configured.
    let mut multisig_account =
        create_multisig_smart_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let account_id = multisig_account.id();
    let mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let receive_asset_root = BasicWallet::receive_asset_root().as_word();
    let immediate_threshold = 1u32;
    let delay_threshold = 0u32;
    let note_restrictions = ProcedurePolicyNoteRestriction::NoInputNotes;
    // `call.` does not consume operand-stack inputs (the procedure sees a snapshot, the caller's
    // stack is preserved across the boundary), so we must manually drop the 7 elements we pushed.
    let set_policy_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{root}
            push.{note_restrictions}
            push.{delay_threshold}
            push.{immediate_threshold}
            call.::miden::standards::components::auth::multisig_smart::set_procedure_policy
            drop drop drop  # immediate, delayed, note_restrictions
            dropw           # PROC_ROOT
        end
        ",
        root = receive_asset_root,
        note_restrictions = note_restrictions as u8,
        delay_threshold = delay_threshold,
        immediate_threshold = immediate_threshold,
    ))?;

    let salt = salt(4);

    // Dry-run to obtain the tx summary that the approvers must sign.
    let tx_summary = match mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(set_policy_script.clone())
        .auth_args(salt)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_summary) => tx_summary,
        error => panic!("expected abort with tx summary: {error:?}"),
    };

    let msg = tx_summary.as_ref().to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);
    let sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &signing_inputs)
        .await?;
    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &signing_inputs)
        .await?;

    let executed_tx = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(set_policy_script)
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_delta(executed_tx.account_delta())?;

    // Policy word layout: [immediate, delayed, note_restrictions, 0]
    let stored_policy = multisig_account
        .storage()
        .get_map_item(AuthMultisigSmart::procedure_policies_slot(), receive_asset_root)
        .expect("procedure policies slot should be present");
    assert_eq!(
        stored_policy,
        Word::from([immediate_threshold, delay_threshold, note_restrictions as u32, 0])
    );

    Ok(())
}

/// Regression test for the per-procedure contribution semantic of `compute_called_proc_policy`:
/// a transaction that mixes a low-policy procedure (receive_asset = 1) with an unpolicied
/// procedure (set_procedure_policy) must require `max(policy, default) = default` signatures,
/// not just the low policy threshold. Without per-proc-contribute this is a privilege escalation
/// — the unpolicied call would be silently authorized at the receive_asset threshold of 1.
#[tokio::test]
async fn test_multisig_smart_unpolicied_proc_call_requires_default_threshold() -> anyhow::Result<()>
{
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
    let default_threshold = 3u32;
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(
            default_threshold as usize,
            default_threshold as usize,
            auth_scheme,
        )?;

    // receive_asset configured with a low policy (1 sig), update_signers and
    // set_procedure_policy intentionally left unpolicied.
    let receive_policy = ProcedurePolicy::with_immediate_threshold(1)?;
    let proc_policy_map = vec![(BasicWallet::receive_asset_root().as_word(), receive_policy)];
    let multisig_account = create_multisig_smart_account(
        default_threshold,
        &public_keys,
        auth_scheme,
        10,
        proc_policy_map,
    )?;

    // Tx-script calls the unpolicied `set_procedure_policy` proc. The tx also consumes a P2ID
    // note (which calls the policied receive_asset). With per-proc-contribute, set_procedure_policy
    // contributes `default_threshold` to the max.
    let target_root = BasicWallet::move_asset_to_note_root().as_word();
    let set_policy_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{root}
            push.0     # note_restrictions
            push.0     # delay_threshold
            push.1     # immediate_threshold
            call.::miden::standards::components::auth::multisig_smart::set_procedure_policy
            drop drop drop
            dropw
        end
        ",
        root = target_root,
    ))?;

    let mut chain_builder = MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();
    let note = chain_builder.add_p2id_note(
        multisig_account.id(),
        multisig_account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;
    let mock_chain = chain_builder.build()?;

    let salt = salt(42);

    // Dry-run to capture the tx summary.
    let tx_summary = match mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .tx_script(set_policy_script.clone())
        .auth_args(salt)
        .build()?
        .execute()
        .await
        .unwrap_err()
    {
        TransactionExecutorError::Unauthorized(tx_summary) => tx_summary,
        error => panic!("expected dry-run abort with tx summary: {error:?}"),
    };

    let msg = tx_summary.as_ref().to_commitment();
    let signing = SigningInputs::TransactionSummary(tx_summary);
    let sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &signing)
        .await?;
    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &signing)
        .await?;
    let sig_2 = authenticators[2]
        .get_signature(public_keys[2].to_commitment(), &signing)
        .await?;

    // With only 1 signature (matching the low receive_asset policy), the tx must fail because
    // the unpolicied set_procedure_policy call contributes `default_threshold = 3`.
    let one_sig_result = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .tx_script(set_policy_script.clone())
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0.clone())
        .build()?
        .execute()
        .await;
    match one_sig_result {
        Err(TransactionExecutorError::Unauthorized(_)) => {},
        other => {
            panic!("expected Unauthorized with 1 sig (escalation would let it pass): {other:?}")
        },
    }

    // With all 3 signatures the unpolicied default contribution is met and the tx succeeds.
    let three_sig_result = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .tx_script(set_policy_script)
        .auth_args(salt)
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .add_signature(public_keys[2].to_commitment(), msg, sig_2)
        .build()?
        .execute()
        .await;
    three_sig_result.expect("3 signatures should satisfy the default-threshold contribution");

    Ok(())
}

// ================================================================================================
// DELAYED-EXECUTION HELPERS
// ================================================================================================

use miden_protocol::transaction::ExecutedTransaction;
use miden_standards::errors::standards::{
    ERR_CANCEL_INSUFFICIENT_SIGNATURES,
    ERR_PENDING_ALREADY_SET,
    ERR_TX_ALREADY_PROPOSED,
    ERR_TX_NOT_PROPOSED,
    ERR_TX_STILL_TIMELOCKED,
};
use miden_testing::MockChain;
use miden_tx::auth::BasicAuthenticator;

#[allow(clippy::too_many_arguments)]
async fn execute_script_with_signers(
    mock_chain: &MockChain,
    account_id: AccountId,
    tx_script: TransactionScript,
    salt: Word,
    signer_indices: &[usize],
    public_keys: &[PublicKey],
    authenticators: &[BasicAuthenticator],
    tx_script_args: Option<Word>,
    advice_inputs: Option<AdviceInputs>,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let mut tx_context_init_builder = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(tx_script.clone())
        .auth_args(salt);

    if let Some(tx_script_args) = tx_script_args {
        tx_context_init_builder = tx_context_init_builder.tx_script_args(tx_script_args);
    }

    if let Some(advice_inputs) = advice_inputs.clone() {
        tx_context_init_builder = tx_context_init_builder.extend_advice_inputs(advice_inputs);
    }

    let tx_summary = tx_context_init_builder
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let mut tx_context_signed_builder = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(tx_script)
        .auth_args(salt);

    if let Some(tx_script_args) = tx_script_args {
        tx_context_signed_builder = tx_context_signed_builder.tx_script_args(tx_script_args);
    }

    if let Some(advice_inputs) = advice_inputs {
        tx_context_signed_builder = tx_context_signed_builder.extend_advice_inputs(advice_inputs);
    }

    for signer_idx in signer_indices {
        let sig = authenticators[*signer_idx]
            .get_signature(public_keys[*signer_idx].to_commitment(), &tx_summary)
            .await?;

        tx_context_signed_builder = tx_context_signed_builder.add_signature(
            public_keys[*signer_idx].to_commitment(),
            msg,
            sig,
        );
    }

    Ok(tx_context_signed_builder.build()?.execute().await)
}

// ================================================================================================
// DELAYED-EXECUTION TESTS
// ================================================================================================

/// A procedure whose policy only declares a `delay_threshold` (no `immediate_threshold`) must not
/// be executable on the immediate path: providing the would-be required signatures and calling it
/// directly should fail at the procedure-policy enforcement layer with
/// `ERR_PROC_POLICY_INVALID_MODE`.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_delayed_only_proc_rejects_signed_direct_path(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 2, auth_scheme)?;
    let multisig_account = create_multisig_smart_account(
        2,
        &public_keys,
        auth_scheme,
        100,
        vec![(
            AuthMultisigSmart::update_delayed_execution_policy_root().as_word(),
            ProcedurePolicy::with_delay_threshold(1)?,
        )],
    )?;
    let account_id = multisig_account.id();
    let mock_chain = MockChainBuilder::with_accounts([multisig_account]).unwrap().build()?;

    let update_timelock_script = compile_multisig_smart_tx_script(
        "
        begin
            push.2
            push.40
            call.::miden::standards::components::auth::multisig_smart::update_delayed_execution_policy
            drop
            drop
        end
        ",
    )?;

    let blind_inputs = SigningInputs::Blind(salt(900));
    let blind_msg = blind_inputs.to_commitment();
    let sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &blind_inputs)
        .await?;
    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &blind_inputs)
        .await?;

    let result = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(update_timelock_script)
        .auth_args(salt(901))
        .add_signature(public_keys[0].to_commitment(), blind_msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), blind_msg, sig_1)
        .build()?
        .execute()
        .await;

    match result {
        Err(TransactionExecutorError::TransactionProgramExecutionFailed(_)) => {},
        Err(err) => panic!("expected transaction program failure, got: {err}"),
        Ok(_) => panic!("execution was unexpectedly successful"),
    }

    Ok(())
}

/// Calling `execute_proposed_transaction` should still produce a `TX_SUMMARY_COMMITMENT` (via the
/// unauthorized dry-run) even when the tx only touches a delayed-only procedure: the auth path
/// runs to threshold check, fails without signatures, but emits the summary needed to drive the
/// propose/execute round-trip.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_delayed_only_execute_proc_returns_tx_summary_on_dry_run(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let multisig_account = create_multisig_smart_account(
        2,
        &public_keys,
        auth_scheme,
        100,
        vec![(
            AuthMultisigSmart::update_delayed_execution_policy_root().as_word(),
            ProcedurePolicy::with_delay_threshold(1)?,
        )],
    )?;
    let account_id = multisig_account.id();
    let mock_chain = MockChainBuilder::with_accounts([multisig_account]).unwrap().build()?;

    let execute_update_timelock_script = compile_multisig_smart_tx_script(
        "
        begin
            call.::miden::standards::components::auth::multisig_smart::execute_proposed_transaction
            push.2
            push.40
            call.::miden::standards::components::auth::multisig_smart::update_delayed_execution_policy
            drop
            drop
        end
        ",
    )?;

    let result = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(execute_update_timelock_script)
        .auth_args(salt(902))
        .build()?
        .execute()
        .await;

    match result {
        Err(TransactionExecutorError::Unauthorized(_)) => Ok(()),
        error => panic!("expected unauthorized dry-run with tx summary, got: {error:?}"),
    }
}

/// The `PENDING_PROPOSE` / `PENDING_CANCEL` / `PENDING_EXECUTE` scratch slots must be mutually
/// exclusive within a single transaction. Calling `propose_transaction` twice, or
/// `cancel_transaction_proposal` twice, or `execute_proposed_transaction` twice should all panic
/// with `ERR_PENDING_ALREADY_SET`.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_pending_actions_are_mutually_exclusive(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;
    let mut multisig_account =
        create_multisig_smart_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let pending_propose_commitment =
        Word::from([Felt::from(11u32), Felt::from(22u32), Felt::from(33u32), Felt::from(44u32)]);
    let pending_cancel_commitment =
        Word::from([Felt::from(55u32), Felt::from(66u32), Felt::from(77u32), Felt::from(88u32)]);

    let propose_twice_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{pending_propose_commitment}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            push.{pending_propose_commitment}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(propose_twice_script)
        .auth_args(salt(301))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_PENDING_ALREADY_SET);

    let propose_once_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{pending_cancel_commitment}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let propose_tx = execute_script_with_signers(
        &mock_chain,
        multisig_account.id(),
        propose_once_script,
        salt(302),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("proposal setup transaction should succeed");
    multisig_account.apply_delta(propose_tx.account_delta())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    let cancel_twice_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{pending_cancel_commitment}
            call.::miden::standards::components::auth::multisig_smart::cancel_transaction_proposal
            push.{pending_cancel_commitment}
            call.::miden::standards::components::auth::multisig_smart::cancel_transaction_proposal
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(cancel_twice_script)
        .auth_args(salt(303))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_PENDING_ALREADY_SET);

    let execute_twice_script = compile_multisig_smart_tx_script(
        "
        begin
            call.::miden::standards::components::auth::multisig_smart::execute_proposed_transaction
            call.::miden::standards::components::auth::multisig_smart::execute_proposed_transaction
            dropw dropw dropw dropw dropw
        end
        ",
    )?;
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(execute_twice_script)
        .auth_args(salt(304))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_PENDING_ALREADY_SET);

    Ok(())
}

/// A successfully recorded proposal must not be executable before its `unlock_timestamp` has been
/// reached. Propose a delayed action, then immediately try to execute it on the next block (only
/// `TIMESTAMP_STEP_SECS` after the propose) — far short of the configured `min_delay` of 30
/// seconds. The execute path's `enforce_tx_timelock` should fail with `ERR_TX_STILL_TIMELOCKED`.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_execute_before_min_delay_fails(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let mut multisig_account = create_multisig_smart_account(
        2,
        &public_keys,
        auth_scheme,
        100,
        vec![(
            AuthMultisigSmart::update_delayed_execution_policy_root().as_word(),
            ProcedurePolicy::with_delay_threshold(1)?,
        )],
    )?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    // The execute script that the proposal is for.
    let execute_script = compile_multisig_smart_tx_script(
        "
        begin
            call.::miden::standards::components::auth::multisig_smart::execute_proposed_transaction
            push.2
            push.40
            call.::miden::standards::components::auth::multisig_smart::update_delayed_execution_policy
            drop
            drop
        end
        ",
    )?;

    // Simulate the execute tx to obtain the tx-summary commitment that will be staged.
    let tx_summary = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(execute_script.clone())
        .auth_args(salt(500))
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let tx_summary_commitment_word = tx_summary.as_ref().to_commitment();

    // Propose the tx hash (2 sigs, default threshold). The propose script signs over its own
    // tx-summary; only the propose-tx itself needs sigs, not the proposed action.
    let propose_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{tx_summary_commitment_word}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let propose_tx = execute_script_with_signers(
        &mock_chain,
        account_id,
        propose_script,
        salt(501),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("propose tx should succeed");
    multisig_account.apply_delta(propose_tx.account_delta())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    // Immediately try to execute — only one block step (~10s) has passed; min_delay is 30s.
    // Execute threshold is `max(default=2, delay=1) = 2`, so sign with both keys.
    let result = execute_script_with_signers(
        &mock_chain,
        account_id,
        execute_script,
        salt(500),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?;
    assert_transaction_executor_error!(result, ERR_TX_STILL_TIMELOCKED);

    Ok(())
}

/// End-to-end happy-path round-trip: propose a delayed action, advance the chain past `min_delay`,
/// then execute it. After execution the proposal entry must be removed from `TX_PROPOSALS_SLOT`.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_full_propose_wait_execute_lifecycle(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let mut multisig_account = create_multisig_smart_account(
        2,
        &public_keys,
        auth_scheme,
        100,
        vec![(
            AuthMultisigSmart::update_delayed_execution_policy_root().as_word(),
            ProcedurePolicy::with_delay_threshold(1)?,
        )],
    )?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let execute_script = compile_multisig_smart_tx_script(
        "
        begin
            call.::miden::standards::components::auth::multisig_smart::execute_proposed_transaction
            push.2
            push.40
            call.::miden::standards::components::auth::multisig_smart::update_delayed_execution_policy
            drop
            drop
        end
        ",
    )?;

    let tx_summary = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(execute_script.clone())
        .auth_args(salt(600))
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let tx_summary_commitment_word = tx_summary.as_ref().to_commitment();

    let propose_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{tx_summary_commitment_word}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let propose_tx = execute_script_with_signers(
        &mock_chain,
        account_id,
        propose_script,
        salt(601),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("propose tx should succeed");
    multisig_account.apply_delta(propose_tx.account_delta())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    // After propose, the proposal entry is present.
    let stored_before = multisig_account
        .storage()
        .get_map_item(AuthMultisigSmart::tx_proposals_slot(), tx_summary_commitment_word)
        .expect("tx proposals slot should exist");
    assert_ne!(stored_before, Word::empty(), "proposal must be written to storage");

    // Fast-forward past `min_delay` (30s). `prove_next_block_at` writes the next block with the
    // given timestamp, so we move the chain to well past unlock time in a single step.
    let target_timestamp = mock_chain.latest_block_header().timestamp() + 60;
    mock_chain.prove_next_block_at(target_timestamp)?;

    // Execute. Threshold = `max(default=2, delay=1) = 2`, so both keys sign.
    let executed_tx = execute_script_with_signers(
        &mock_chain,
        account_id,
        execute_script,
        salt(600),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("execute tx should succeed after min_delay elapses");
    multisig_account.apply_delta(executed_tx.account_delta())?;

    // Proposal entry should be cleared after execute.
    let stored_after = multisig_account
        .storage()
        .get_map_item(AuthMultisigSmart::tx_proposals_slot(), tx_summary_commitment_word)
        .expect("tx proposals slot should still exist");
    assert_eq!(
        stored_after,
        Word::empty(),
        "proposal must be removed from storage after successful execute"
    );

    Ok(())
}

/// `min_cancel_sigs` is recorded as the number of signatures verified at propose time. Cancelling
/// later requires at least as many signatures. A propose tx signed by 4 keys must not be
/// cancellable by a tx signed by only 2 keys, even though 2 sigs meets the account's default
/// threshold. The cancel finalizer should panic with `ERR_CANCEL_INSUFFICIENT_SIGNATURES`.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_cancel_with_insufficient_signatures_fails(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;
    let mut multisig_account =
        create_multisig_smart_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let pending_hash = Word::from([Felt::from(701u32); 4]);

    // Propose the mock hash with 4 sigs — this stamps min_cancel_sigs = 4 onto the entry.
    let propose_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{pending_hash}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let propose_tx = execute_script_with_signers(
        &mock_chain,
        account_id,
        propose_script,
        salt(702),
        &[0, 1, 2, 3],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("propose tx with 4 sigs should succeed");
    multisig_account.apply_delta(propose_tx.account_delta())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    // Cancel with only 2 sigs — meets default_threshold but below min_cancel_sigs (4).
    let cancel_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{pending_hash}
            call.::miden::standards::components::auth::multisig_smart::cancel_transaction_proposal
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let result = execute_script_with_signers(
        &mock_chain,
        account_id,
        cancel_script,
        salt(703),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?;
    assert_transaction_executor_error!(result, ERR_CANCEL_INSUFFICIENT_SIGNATURES);

    Ok(())
}

/// After `update_delayed_execution_policy` rotates `min_delay`, subsequent proposals must compute
/// `unlock_timestamp` using the new `min_delay`, not the previous one.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_policy_rotation_applies_to_new_proposals(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    // No proc policy on `update_delayed_execution_policy` — it runs on the immediate path under
    // the default threshold, which makes the rotation a single round-trip.
    let mut multisig_account =
        create_multisig_smart_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let new_min_delay = 90u32;
    let new_expiration_delta = 5u32;
    let rotate_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{new_expiration_delta}
            push.{new_min_delay}
            call.::miden::standards::components::auth::multisig_smart::update_delayed_execution_policy
            drop
            drop
        end
        "
    ))?;
    let rotate_tx = execute_script_with_signers(
        &mock_chain,
        account_id,
        rotate_script,
        salt(800),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("policy rotation tx should succeed");
    multisig_account.apply_delta(rotate_tx.account_delta())?;
    mock_chain.add_pending_executed_transaction(&rotate_tx)?;
    mock_chain.prove_next_block()?;

    // Stored policy reflects the new values.
    let stored_policy = multisig_account
        .storage()
        .get_item(AuthMultisigSmart::delayed_execution_slot())
        .expect("delayed-execution slot should exist");
    assert_eq!(
        stored_policy,
        Word::from([new_min_delay, new_expiration_delta, 0, 0]),
        "stored DelayedExecutionPolicy must reflect the rotated values"
    );

    // A subsequent proposal uses the new `min_delay`. Propose a mock hash and verify
    // `unlock_timestamp - proposal_timestamp == new_min_delay`.
    let pending_hash = Word::from([Felt::from(801u32); 4]);
    let propose_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{pending_hash}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let propose_tx = execute_script_with_signers(
        &mock_chain,
        account_id,
        propose_script,
        salt(802),
        &[0, 1],
        &public_keys,
        &authenticators,
        None,
        None,
    )
    .await?
    .expect("propose tx should succeed after rotation");
    multisig_account.apply_delta(propose_tx.account_delta())?;

    let proposal_entry = multisig_account
        .storage()
        .get_map_item(AuthMultisigSmart::tx_proposals_slot(), pending_hash)
        .expect("tx proposals slot should exist");
    // Entry layout: [unlock_timestamp, proposal_timestamp, min_cancel_sigs, 1]
    let elements: &[Felt] = proposal_entry.as_ref();
    let unlock_ts = elements[0].as_canonical_u64();
    let proposal_ts = elements[1].as_canonical_u64();
    assert_eq!(
        unlock_ts - proposal_ts,
        new_min_delay as u64,
        "post-rotation propose must use the new min_delay"
    );

    Ok(())
}

/// Two distinct proposals must be storable side-by-side in `TX_PROPOSALS_SLOT`. After two
/// independent propose tx's complete, both entries must remain in the map.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_multiple_concurrent_proposals_coexist(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let mut multisig_account =
        create_multisig_smart_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let hash_a = Word::from([Felt::from(901u32); 4]);
    let hash_b = Word::from([Felt::from(902u32); 4]);

    for (hash, salt_seed) in [(hash_a, 903u32), (hash_b, 904u32)] {
        let script = compile_multisig_smart_tx_script(format!(
            "
            begin
                push.{hash}
                call.::miden::standards::components::auth::multisig_smart::propose_transaction
                dropw dropw dropw dropw dropw
            end
            "
        ))?;
        let tx = execute_script_with_signers(
            &mock_chain,
            account_id,
            script,
            salt(salt_seed),
            &[0, 1],
            &public_keys,
            &authenticators,
            None,
            None,
        )
        .await?
        .expect("propose tx should succeed");
        multisig_account.apply_delta(tx.account_delta())?;
        mock_chain.add_pending_executed_transaction(&tx)?;
        mock_chain.prove_next_block()?;
    }

    // Both proposals must exist in storage.
    for hash in [hash_a, hash_b] {
        let entry = multisig_account
            .storage()
            .get_map_item(AuthMultisigSmart::tx_proposals_slot(), hash)
            .expect("tx proposals slot should exist");
        assert_ne!(entry, Word::empty(), "proposal entry must be present in storage");
    }

    Ok(())
}

/// `cancel_and_propose_new_transaction` has two failure branches that fire during the
/// user-script phase (before any signature verification):
/// - The OLD tx hash must already be proposed, otherwise `ERR_TX_NOT_PROPOSED`.
/// - The NEW tx hash must NOT already be proposed, otherwise `ERR_TX_ALREADY_PROPOSED`.
///
/// Both branches panic via `assert.err=...` deep inside the proc, so the tx never reaches the
/// auth finalizer and signatures are irrelevant — we execute without signers.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_cancel_and_propose_failure_modes(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let mut multisig_account =
        create_multisig_smart_account(2, &public_keys, auth_scheme, 100, vec![])?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let hash_a = Word::from([Felt::from(1001u32); 4]);
    let hash_b = Word::from([Felt::from(1002u32); 4]);
    let hash_never_proposed = Word::from([Felt::from(1003u32); 4]);

    // ----- Branch 1: OLD_TX_SUMMARY_COMMITMENT was never proposed → ERR_TX_NOT_PROPOSED.
    //
    // MASM stack convention: `cancel_and_propose_new_transaction` consumes
    // [OLD_TX_SUMMARY_COMMITMENT, NEW_TX_SUMMARY_COMMITMENT] (top → bottom). The script pushes
    // NEW first so it lands below OLD.
    let old_not_proposed_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{hash_b}
            push.{hash_never_proposed}
            call.::miden::standards::components::auth::multisig_smart::cancel_and_propose_new_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let result = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(old_not_proposed_script)
        .auth_args(salt(1010))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_TX_NOT_PROPOSED);

    // Pre-propose `hash_a` and `hash_b` so that branch 2 can fail on the NEW side.
    for (hash, seed) in [(hash_a, 1011u32), (hash_b, 1012u32)] {
        let propose_script = compile_multisig_smart_tx_script(format!(
            "
            begin
                push.{hash}
                call.::miden::standards::components::auth::multisig_smart::propose_transaction
                dropw dropw dropw dropw dropw
            end
            "
        ))?;
        let propose_tx = execute_script_with_signers(
            &mock_chain,
            account_id,
            propose_script,
            salt(seed),
            &[0, 1],
            &public_keys,
            &authenticators,
            None,
            None,
        )
        .await?
        .expect("propose tx should succeed");
        multisig_account.apply_delta(propose_tx.account_delta())?;
        mock_chain.add_pending_executed_transaction(&propose_tx)?;
        mock_chain.prove_next_block()?;
    }

    // ----- Branch 2: NEW_TX_SUMMARY_COMMITMENT is already proposed → ERR_TX_ALREADY_PROPOSED.
    //
    // OLD = hash_a (valid existing proposal), NEW = hash_b (also already exists).
    let new_already_proposed_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{hash_b}
            push.{hash_a}
            call.::miden::standards::components::auth::multisig_smart::cancel_and_propose_new_transaction
            dropw dropw dropw dropw dropw
        end
        "
    ))?;
    let result = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(new_already_proposed_script)
        .auth_args(salt(1013))
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_TX_ALREADY_PROPOSED);

    Ok(())
}
