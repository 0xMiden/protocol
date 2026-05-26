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
        AuthMultisigSmartConfig::new(approvers, threshold)?.with_proc_policies(proc_policy_map)?;

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

    let salt = Word::from([Felt::new_unchecked(1); 4]);
    let tx_context_builder = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .auth_args(salt);

    let tx_summary = tx_context_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary);
    let one_signature = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;

    let tx_result = tx_context_builder
        .add_signature(public_keys[0].to_commitment(), msg, one_signature)
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
        .auth_args(Word::from([Felt::new_unchecked(2); 4]))
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
            result.unwrap_err().unwrap_unauthorized_err();
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
        .auth_args(Word::from([Felt::new_unchecked(2); 4]))
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
            result.unwrap_err().unwrap_unauthorized_err();
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

    let salt = Word::from([Felt::new_unchecked(3); 4]);

    let tx_context_builder = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(update_signers_script)
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs)
        .auth_args(salt);

    // Dry-run to obtain the tx summary that the current approvers must sign.
    let tx_summary = tx_context_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    let msg = tx_summary.as_ref().to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);
    let sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &signing_inputs)
        .await?;
    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &signing_inputs)
        .await?;

    let executed_tx = tx_context_builder
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
    let delayed_threshold = 0u32;
    let note_restrictions = ProcedurePolicyNoteRestriction::NoInputNotes;
    // `call.` does not consume operand-stack inputs (the procedure sees a snapshot, the caller's
    // stack is preserved across the boundary), so we must manually drop the 7 elements we pushed.
    let set_policy_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{root}
            push.{note_restrictions}
            push.{delayed_threshold}
            push.{immediate_threshold}
            call.::miden::standards::components::auth::multisig_smart::set_procedure_policy
            drop drop drop  # immediate, delayed, note_restrictions
            dropw           # PROC_ROOT
        end
        ",
        root = receive_asset_root,
        note_restrictions = note_restrictions as u8,
        delayed_threshold = delayed_threshold,
        immediate_threshold = immediate_threshold,
    ))?;

    let salt = Word::from([Felt::new_unchecked(4); 4]);

    let tx_context_builder = mock_chain
        .build_tx_context(account_id, &[], &[])?
        .tx_script(set_policy_script)
        .auth_args(salt);

    // Dry-run to obtain the tx summary that the approvers must sign.
    let tx_summary = tx_context_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    let msg = tx_summary.as_ref().to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);
    let sig_0 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &signing_inputs)
        .await?;
    let sig_1 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &signing_inputs)
        .await?;

    let executed_tx = tx_context_builder
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
        Word::from([immediate_threshold, delayed_threshold, note_restrictions as u32, 0])
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
            push.0     # delayed_threshold
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

    let salt = Word::from([Felt::new_unchecked(42); 4]);

    let tx_context_builder = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .tx_script(set_policy_script)
        .auth_args(salt);

    // Dry-run to capture the tx summary.
    let tx_summary = tx_context_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

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
    let one_sig_result = tx_context_builder
        .clone()
        .add_signature(public_keys[0].to_commitment(), msg, sig_0.clone())
        .build()?
        .execute()
        .await;
    one_sig_result.unwrap_err().unwrap_unauthorized_err();

    // With all 3 signatures the unpolicied default contribution is met and the tx succeeds.
    let three_sig_result = tx_context_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .add_signature(public_keys[2].to_commitment(), msg, sig_2)
        .build()?
        .execute()
        .await;
    three_sig_result.expect("3 signatures should satisfy the default-threshold contribution");

    Ok(())
}
