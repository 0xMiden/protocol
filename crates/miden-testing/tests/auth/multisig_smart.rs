use miden_processor::advice::AdviceInputs;
use miden_protocol::account::auth::{AuthScheme, PublicKey};
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, StorageMapKey};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::transaction::TransactionScript;
use miden_protocol::vm::AdviceMap;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::auth::multisig_smart::{
    DelayedExecutionPolicy,
    ProcedurePolicy,
    ProcedurePolicyNoteRestriction,
    TransactionEffects,
};
use miden_standards::account::auth::{
    Approver,
    ApproverSet,
    AuthMultisigSmart,
    AuthMultisigSmartConfig,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_AUTH_PROCEDURE_MUST_BE_CALLED_ALONE,
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_NOTES,
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES,
    ERR_DUPLICATE_APPROVER_PUBLIC_KEY,
    ERR_PROC_ROOT_NOT_IN_ACCOUNT,
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
    starting_balance: u64,
    proc_policy_map: Vec<(Word, ProcedurePolicy)>,
) -> anyhow::Result<Account> {
    let approvers: Vec<_> = public_keys.iter().map(Approver::from).collect();
    let approver_set = ApproverSet::new(approvers, threshold)?;
    let config = AuthMultisigSmartConfig::new(approver_set, DelayedExecutionPolicy::new(30, 2)?)
        .with_proc_policies(proc_policy_map)?;

    let asset = FungibleAsset::new(
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?,
        starting_balance,
    )?;

    let multisig_account = AccountBuilder::new([0; 32])
        .with_component(AuthMultisigSmart::new(config)?)
        .with_component(BasicWallet)
        .account_type(AccountType::Public)
        .with_assets(core::iter::once(asset.into()))
        .build_existing()?;

    Ok(multisig_account)
}

/// Compiles a transaction script that links against the multisig smart package so it can `call.`
/// the component's exported procedures.
fn compile_multisig_smart_tx_script(script: impl AsRef<str>) -> anyhow::Result<TransactionScript> {
    Ok(CodeBuilder::default()
        .with_dynamically_linked_package(AuthMultisigSmart::code())?
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
#[tokio::test]
async fn test_multisig_smart_receive_asset_policy_overrides_default_three_of_three_to_one_signature(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 3, auth_scheme)?;

    let receive_asset_one_signature_policy = ProcedurePolicy::with_immediate_threshold(1)?;
    let proc_policy_map =
        vec![(BasicWallet::receive_asset_root().as_word(), receive_asset_one_signature_policy)];

    let mut multisig_account = create_multisig_smart_account(3, &public_keys, 10, proc_policy_map)?;

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
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .authenticated_input_note(note.id())
        .auth_args(salt);

    let tx_summary = mock_tx_builder
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

    let tx_result = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, one_signature)
        .build()?
        .execute()
        .await;

    assert!(
        tx_result.is_ok(),
        "receive_asset policy threshold=1 should override the default 3-of-3 requirement"
    );

    multisig_account.apply_patch(tx_result.as_ref().unwrap().account_patch())?;
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
        .build_transaction(multisig_account.id())
        .authenticated_input_note(note.id())
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
    use miden_standards::note::P2idNote;
    use miden_standards::tx_script::SendNotesTransactionScript;

    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, AuthScheme::EcdsaK256Keccak)?;

    let multisig_account = create_multisig_smart_account(
        2,
        &public_keys,
        100,
        vec![(
            BasicWallet::move_asset_to_note_root().as_word(),
            ProcedurePolicy::with_immediate_threshold(1)?.with_note_restriction(restriction),
        )],
    )?;

    let output_note: Note = P2idNote::builder()
        .sender(multisig_account.id())
        .target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap())
        .asset(FungibleAsset::mock(5))
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::from([Felt::new_unchecked(7); 4])))
        .build()?
        .into();

    let send_note_script = SendNotesTransactionScript::new(
        &multisig_account.code_interface(),
        &[output_note.clone().into()],
    )?;

    let mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let result = mock_chain
        .build_transaction(multisig_account.id())
        .expected_output_note(RawOutputNote::Full(output_note))
        .send_notes_script(&send_note_script)
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
#[tokio::test]
async fn test_multisig_smart_update_signers_and_thresholds(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let mut multisig_account = create_multisig_smart_account(2, &public_keys, 10, vec![])?;
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
        @transaction_script
        pub proc main
            call.::miden::standards::components::auth::multisig_smart::update_signers_and_threshold
        end
        ",
    )?;

    let salt = salt(3);

    let mock_tx_builder = mock_chain
        .build_transaction(account_id)
        .tx_script(update_signers_script)
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs)
        .auth_args(salt);

    // Dry-run a clone to obtain the tx summary that the current approvers must sign.
    let tx_summary = mock_tx_builder
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

    let executed_tx = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_patch(executed_tx.account_patch())?;

    // Verify the new threshold/num_approvers config is persisted.
    let threshold_config = multisig_account
        .storage()
        .get_item(AuthMultisigSmart::threshold_config_slot())
        .expect("threshold config slot should be present");
    assert_eq!(threshold_config[0], Felt::new_unchecked(new_threshold));
    assert_eq!(threshold_config[1], Felt::new_unchecked(new_num_approvers));

    // Verify each new public key is stored at its expected map index.
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let storage_key = StorageMapKey::from_index(i as u32);
        let stored_pub_key = multisig_account
            .storage()
            .get_map_item(AuthMultisigSmart::approver_public_keys_slot(), storage_key)
            .expect("approver public key map item should be present");
        let expected_word: Word = expected_key.to_commitment().into();
        assert_eq!(stored_pub_key, expected_word, "public key at index {i} mismatch");
    }

    Ok(())
}

/// Tests that `multisig_smart::update_signers_and_threshold` rejects a signer set containing
/// duplicate public keys, mirroring the check on the plain `multisig` variant.
#[tokio::test]
async fn test_multisig_smart_update_signers_rejects_duplicate_public_keys() -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::Falcon512Poseidon2;
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(3, 2, auth_scheme)?;

    let multisig_account = create_multisig_smart_account(2, &public_keys, 10, vec![])?;
    let mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    // Update to a signer set of [PK_A, PK_A, PK_B]: the first key is repeated.
    let duplicate_public_keys =
        vec![public_keys[0].clone(), public_keys[0].clone(), public_keys[1].clone()];
    let new_threshold: u64 = 2;
    let new_num_approvers: u64 = 3;

    let multisig_config_data = build_update_signers_config_vector(
        new_threshold,
        new_num_approvers,
        &duplicate_public_keys,
        auth_scheme,
    );
    let multisig_config_hash = Hasher::hash_elements(&multisig_config_data);

    let mut advice_map = AdviceMap::default();
    advice_map.insert(multisig_config_hash, multisig_config_data);
    let advice_inputs = AdviceInputs { map: advice_map, ..Default::default() };

    let update_signers_script = compile_multisig_smart_tx_script(
        "
        @transaction_script
        pub proc main
            call.::miden::standards::components::auth::multisig_smart::update_signers_and_threshold
        end
        ",
    )?;

    let salt = Word::from([Felt::new_unchecked(3); 4]);

    let result = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(update_signers_script)
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs)
        .auth_args(salt)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_DUPLICATE_APPROVER_PUBLIC_KEY);

    Ok(())
}

/// `set_procedure_policy` invoked from a transaction script must persist the policy to the
/// `procedure_policies` storage map so subsequent transactions see the new policy.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn test_multisig_smart_set_procedure_policy(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    // Account starts with no procedure policies configured.
    let mut multisig_account = create_multisig_smart_account(2, &public_keys, 100, vec![])?;
    let account_id = multisig_account.id();
    let mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let receive_asset_root = StorageMapKey::from_raw(BasicWallet::receive_asset_root().as_word());
    let immediate_threshold = 1u32;
    let delay_threshold = 0u32;
    let note_restrictions = ProcedurePolicyNoteRestriction::NoInputNotes;
    // `call.` does not consume operand-stack inputs (the procedure sees a snapshot, the caller's
    // stack is preserved across the boundary), so we must manually drop the 7 elements we pushed.
    let set_policy_script = compile_multisig_smart_tx_script(format!(
        "
        @transaction_script
        pub proc main
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

    let mock_tx_builder = mock_chain
        .build_transaction(account_id)
        .tx_script(set_policy_script)
        .auth_args(salt);

    // Dry-run a clone to obtain the tx summary that the approvers must sign.
    let tx_summary = mock_tx_builder
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

    let executed_tx = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_0)
        .add_signature(public_keys[1].to_commitment(), msg, sig_1)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_patch(executed_tx.account_patch())?;

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

/// `set_procedure_policy` must reject a `PROC_ROOT` that is not one of the account's procedures, so
/// a policy can never be stored under a foreign root. The `has_procedure` guard aborts during
/// execution, before the epilogue auth check, so no signatures are required.
#[tokio::test]
async fn test_multisig_smart_set_procedure_policy_rejects_foreign_root() -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;

    let multisig_account = create_multisig_smart_account(2, &public_keys, 100, vec![])?;
    let mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    // A root that is not one of the account's procedures.
    let foreign_root = Word::from([Felt::new_unchecked(123); 4]);

    // Valid threshold/note-restriction values so execution reaches the `has_procedure` guard.
    let set_policy_script = compile_multisig_smart_tx_script(format!(
        "
        @transaction_script
        pub proc main
            push.{root}
            push.0
            push.0
            push.1
            call.::miden::standards::components::auth::multisig_smart::set_procedure_policy
        end
        ",
        root = foreign_root,
    ))?;

    let salt = Word::from([Felt::new_unchecked(7); 4]);
    let result = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(set_policy_script)
        .auth_args(salt)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PROC_ROOT_NOT_IN_ACCOUNT);

    Ok(())
}

/// Regression test for the per-procedure contribution semantic of `compute_tx_threshold`:
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
    let multisig_account =
        create_multisig_smart_account(default_threshold, &public_keys, 10, proc_policy_map)?;

    // Tx-script calls the unpolicied `set_procedure_policy` proc. The tx also consumes a P2ID
    // note (which calls the policied receive_asset). With per-proc-contribute, set_procedure_policy
    // contributes `default_threshold` to the max.
    let target_root = BasicWallet::move_asset_to_note_root().as_word();
    let set_policy_script = compile_multisig_smart_tx_script(format!(
        "
        @transaction_script
        pub proc main
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

    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .authenticated_input_note(note.id())
        .tx_script(set_policy_script)
        .auth_args(salt);

    // Dry-run a clone to capture the tx summary.
    let tx_summary = mock_tx_builder
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
    let one_sig_result = mock_tx_builder
        .clone()
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
    let three_sig_result = mock_tx_builder
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
    ERR_PROC_POLICY_INVALID_MODE,
    ERR_TX_ALREADY_PROPOSED,
    ERR_TX_STILL_TIMELOCKED,
};
use miden_testing::MockChain;
use miden_tx::auth::BasicAuthenticator;

/// Drives a delay-action procedure (`propose_transaction` or `cancel_transaction_proposal`), which
/// verifies its own signatures over the *target* transaction commitment. The signers blind-sign
/// that commitment directly. Because the kernel skips transaction-summary reconstruction when a
/// signature is already present, the target summary need not be supplied — the commitment alone is
/// enough — and there is no unauthorized dry-run round-trip as in [`execute_script_with_signers`].
#[allow(clippy::too_many_arguments)]
async fn execute_delay_action(
    mock_chain: &MockChain,
    account_id: AccountId,
    proc_name: &str,
    target_commitment: Word,
    action_salt: Word,
    signer_indices: &[usize],
    public_keys: &[PublicKey],
    authenticators: &[BasicAuthenticator],
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let script = compile_multisig_smart_tx_script(format!(
        "
        @transaction_script
        pub proc main
            push.{target_commitment}
            call.::miden::standards::components::auth::multisig_smart::{proc_name}
            dropw dropw dropw dropw dropw
        end
        "
    ))?;

    let signing = SigningInputs::Blind(target_commitment);

    let mut builder = mock_chain
        .build_transaction(account_id)
        .tx_script(script)
        .auth_args(action_salt);

    for signer_idx in signer_indices {
        let sig = authenticators[*signer_idx]
            .get_signature(public_keys[*signer_idx].to_commitment(), &signing)
            .await?;
        builder =
            builder.add_signature(public_keys[*signer_idx].to_commitment(), target_commitment, sig);
    }

    Ok(builder.build()?.execute().await)
}

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
    let mut builder = mock_chain.build_transaction(account_id).tx_script(tx_script).auth_args(salt);

    if let Some(tx_script_args) = tx_script_args {
        builder = builder.tx_script_args(tx_script_args);
    }

    if let Some(advice_inputs) = advice_inputs {
        builder = builder.extend_advice_inputs(advice_inputs);
    }

    // Dry-run a clone of the builder to capture the tx summary the signers must sign over.
    let tx_summary =
        builder.clone().build()?.execute().await.unwrap_err().unwrap_unauthorized_err();

    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    for signer_idx in signer_indices {
        let sig = authenticators[*signer_idx]
            .get_signature(public_keys[*signer_idx].to_commitment(), &tx_summary)
            .await?;

        builder = builder.add_signature(public_keys[*signer_idx].to_commitment(), msg, sig);
    }

    Ok(builder.build()?.execute().await)
}

// ================================================================================================
// DELAYED-EXECUTION TESTS
// ================================================================================================

/// A procedure whose policy only declares a `delay_threshold` (no `immediate_threshold`) cannot run
/// on the immediate path. The execution mode is derived from proposal presence, so calling such a
/// procedure directly (with no matching proposal) evaluates it in immediate mode, which its policy
/// does not support — the transaction aborts at the procedure-policy layer with
/// `ERR_PROC_POLICY_INVALID_MODE` before any signature check.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn test_multisig_smart_delayed_only_proc_rejects_direct_path_without_proposal(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, _authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let multisig_account = create_multisig_smart_account(
        2,
        &public_keys,
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
        @transaction_script
        pub proc main
            push.2
            push.40
            call.::miden::standards::components::auth::multisig_smart::update_delayed_execution_policy
            drop
            drop
        end
        ",
    )?;

    // Called directly with no proposal, the execution mode is immediate, which a delay-only
    // procedure does not support, so it aborts at the policy layer before verifying signatures.
    let result = mock_chain
        .build_transaction(account_id)
        .tx_script(update_timelock_script)
        .auth_args(salt(901))
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PROC_POLICY_INVALID_MODE);

    Ok(())
}

/// A delay-action procedure may not be bundled with another non-auth procedure in the same
/// transaction: the auth procedure calls `assert_only_one_non_auth_procedure_called`, which aborts
/// the program. Here a single transaction calls both `propose_transaction` and
/// `update_delayed_execution_policy`.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn test_multisig_smart_delay_action_cannot_be_bundled(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let multisig_account = create_multisig_smart_account(2, &public_keys, 100, vec![])?;
    let account_id = multisig_account.id();
    let mock_chain = MockChainBuilder::with_accounts([multisig_account]).unwrap().build()?;

    let bundled_commitment = Word::from([Felt::from(11u32); 4]);
    let bundled_script = compile_multisig_smart_tx_script(format!(
        "
        @transaction_script
        pub proc main
            push.{bundled_commitment}
            call.::miden::standards::components::auth::multisig_smart::propose_transaction
            dropw dropw dropw dropw
            push.2
            push.40
            call.::miden::standards::components::auth::multisig_smart::update_delayed_execution_policy
            drop
            drop
        end
        "
    ))?;

    // Sign the target commitment so `propose_transaction`'s own signature check passes. The
    // transaction must still abort, because the bundled `update_delayed_execution_policy` call
    // means the delay action is no longer the sole non-auth procedure.
    let signing = SigningInputs::Blind(bundled_commitment);
    let mut builder = mock_chain
        .build_transaction(account_id)
        .tx_script(bundled_script)
        .auth_args(salt(305));
    for signer_idx in [0, 1] {
        let sig = authenticators[signer_idx]
            .get_signature(public_keys[signer_idx].to_commitment(), &signing)
            .await?;
        builder =
            builder.add_signature(public_keys[signer_idx].to_commitment(), bundled_commitment, sig);
    }

    let result = builder.build()?.execute().await;

    assert_transaction_executor_error!(result, ERR_AUTH_PROCEDURE_MUST_BE_CALLED_ALONE);

    Ok(())
}

/// Proposing the same commitment twice must fail the second time with `ERR_TX_ALREADY_PROPOSED`.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn test_multisig_smart_double_propose_fails(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let mut multisig_account = create_multisig_smart_account(2, &public_keys, 100, vec![])?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let commitment = Word::from([Felt::from(44u32); 4]);

    let propose_tx = execute_delay_action(
        &mock_chain,
        account_id,
        "propose_transaction",
        commitment,
        salt(310),
        &[0, 1],
        &public_keys,
        &authenticators,
    )
    .await?
    .expect("first propose should succeed");
    multisig_account.apply_patch(propose_tx.account_patch())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    let result = execute_delay_action(
        &mock_chain,
        account_id,
        "propose_transaction",
        commitment,
        salt(311),
        &[0, 1],
        &public_keys,
        &authenticators,
    )
    .await?;
    assert_transaction_executor_error!(result, ERR_TX_ALREADY_PROPOSED);

    Ok(())
}

/// A successfully recorded proposal must not be executable before its `unlock_timestamp` has been
/// reached. Propose a delayed action, then immediately try to execute it on the next block (only
/// `TIMESTAMP_STEP_SECS` after the propose) — far short of the configured `min_delay` of 30
/// seconds. The delayed execution path's `enforce_tx_timelock` should fail with
/// `ERR_TX_STILL_TIMELOCKED`.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn test_multisig_smart_execute_before_min_delay_fails(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let mut multisig_account = create_multisig_smart_account(
        2,
        &public_keys,
        100,
        vec![(
            AuthMultisigSmart::update_delayed_execution_policy_root().as_word(),
            ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1)?,
        )],
    )?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    // The execute transaction the proposal is for just calls the real procedure; auth detects it as
    // an execution because it is not a propose/cancel-only transaction.
    let execute_script = compile_multisig_smart_tx_script(
        "
        @transaction_script
        pub proc main
            push.2
            push.40
            call.::miden::standards::components::auth::multisig_smart::update_delayed_execution_policy
            drop
            drop
        end
        ",
    )?;

    // Dry-run the execute tx to obtain its action commitment (the proposal target).
    let tx_summary = mock_chain
        .build_transaction(account_id)
        .tx_script(execute_script.clone())
        .auth_args(salt(500))
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    // Propose the target action (2 sigs over the action commitment, default threshold). The action
    // commitment is block-independent, so it matches when the tx is executed at a later block.
    let propose_tx = execute_delay_action(
        &mock_chain,
        account_id,
        "propose_transaction",
        TransactionEffects::from_summary(tx_summary.as_ref()).commitment(),
        salt(501),
        &[0, 1],
        &public_keys,
        &authenticators,
    )
    .await?
    .expect("propose tx should succeed");
    multisig_account.apply_patch(propose_tx.account_patch())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    // Immediately try to execute — only one block step (~10s) has passed; min_delay is 30s.
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
#[tokio::test]
async fn test_multisig_smart_full_propose_wait_execute_lifecycle(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let mut multisig_account = create_multisig_smart_account(
        2,
        &public_keys,
        100,
        vec![(
            AuthMultisigSmart::update_delayed_execution_policy_root().as_word(),
            ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1)?,
        )],
    )?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let execute_script = compile_multisig_smart_tx_script(
        "
        @transaction_script
        pub proc main
            push.2
            push.40
            call.::miden::standards::components::auth::multisig_smart::update_delayed_execution_policy
            drop
            drop
        end
        ",
    )?;

    let tx_summary = mock_chain
        .build_transaction(account_id)
        .tx_script(execute_script.clone())
        .auth_args(salt(600))
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    // The proposal is keyed by the block-independent action commitment, so it matches when the tx
    // is executed at a later block.
    let tx_effects_commitment_word =
        TransactionEffects::from_summary(tx_summary.as_ref()).commitment();

    let propose_tx = execute_delay_action(
        &mock_chain,
        account_id,
        "propose_transaction",
        tx_effects_commitment_word,
        salt(601),
        &[0, 1],
        &public_keys,
        &authenticators,
    )
    .await?
    .expect("propose tx should succeed");
    multisig_account.apply_patch(propose_tx.account_patch())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    // After propose, the proposal entry is present.
    let stored_before = multisig_account
        .storage()
        .get_map_item(
            AuthMultisigSmart::tx_proposals_slot(),
            StorageMapKey::from_raw(tx_effects_commitment_word),
        )
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
    multisig_account.apply_patch(executed_tx.account_patch())?;

    // Proposal entry should be cleared after execute.
    let stored_after = multisig_account
        .storage()
        .get_map_item(
            AuthMultisigSmart::tx_proposals_slot(),
            StorageMapKey::from_raw(tx_effects_commitment_word),
        )
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
#[tokio::test]
async fn test_multisig_smart_cancel_with_insufficient_signatures_fails(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(4, 4, auth_scheme)?;
    let mut multisig_account = create_multisig_smart_account(2, &public_keys, 100, vec![])?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let commitment = Word::from([Felt::from(701u32); 4]);

    // Propose the commitment with 4 sigs — this stamps min_cancel_sigs = 4 onto the entry.
    let propose_tx = execute_delay_action(
        &mock_chain,
        account_id,
        "propose_transaction",
        commitment,
        salt(702),
        &[0, 1, 2, 3],
        &public_keys,
        &authenticators,
    )
    .await?
    .expect("propose tx with 4 sigs should succeed");
    multisig_account.apply_patch(propose_tx.account_patch())?;
    mock_chain.add_pending_executed_transaction(&propose_tx)?;
    mock_chain.prove_next_block()?;

    // Cancel with only 2 sigs — meets default_threshold but below min_cancel_sigs (4).
    let result = execute_delay_action(
        &mock_chain,
        account_id,
        "cancel_transaction_proposal",
        commitment,
        salt(703),
        &[0, 1],
        &public_keys,
        &authenticators,
    )
    .await?;
    assert_transaction_executor_error!(result, ERR_CANCEL_INSUFFICIENT_SIGNATURES);

    Ok(())
}

/// After `update_delayed_execution_policy` rotates `min_delay`, subsequent proposals must compute
/// `unlock_timestamp` using the new `min_delay`, not the previous one.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn test_multisig_smart_policy_rotation_applies_to_new_proposals(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    // No proc policy on `update_delayed_execution_policy` — it runs on the immediate path under
    // the default threshold, which makes the rotation a single round-trip.
    let mut multisig_account = create_multisig_smart_account(2, &public_keys, 100, vec![])?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let new_min_delay = 90u32;
    let new_expiration_delta = 5u32;
    let rotate_script = compile_multisig_smart_tx_script(format!(
        "
        @transaction_script
        pub proc main
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
    multisig_account.apply_patch(rotate_tx.account_patch())?;
    mock_chain.add_pending_executed_transaction(&rotate_tx)?;
    mock_chain.prove_next_block()?;

    // Stored policy reflects the new values.
    let stored_policy = multisig_account
        .storage()
        .get_item(AuthMultisigSmart::delay_mode_config_slot())
        .expect("delayed-execution slot should exist");
    assert_eq!(
        stored_policy,
        Word::from([new_min_delay, new_expiration_delta, 0, 0]),
        "stored DelayedExecutionPolicy must reflect the rotated values"
    );

    // A subsequent proposal uses the new `min_delay`. Propose a commitment and verify
    // `unlock_timestamp - proposal_timestamp == new_min_delay`.
    let target_commitment = Word::from([Felt::from(801u32); 4]);
    let propose_tx = execute_delay_action(
        &mock_chain,
        account_id,
        "propose_transaction",
        target_commitment,
        salt(802),
        &[0, 1],
        &public_keys,
        &authenticators,
    )
    .await?
    .expect("propose tx should succeed after rotation");
    multisig_account.apply_patch(propose_tx.account_patch())?;

    let proposal_entry = multisig_account
        .storage()
        .get_map_item(
            AuthMultisigSmart::tx_proposals_slot(),
            StorageMapKey::from_raw(target_commitment),
        )
        .expect("tx proposals slot should exist");
    // Entry layout: [unlock_timestamp, proposal_timestamp, min_cancel_sigs, 0]
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
#[tokio::test]
async fn test_multisig_smart_multiple_concurrent_proposals_coexist(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, _auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let mut multisig_account = create_multisig_smart_account(2, &public_keys, 100, vec![])?;
    let account_id = multisig_account.id();
    let mut mock_chain =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap().build()?;

    let commitment_a = Word::from([Felt::from(901u32); 4]);
    let commitment_b = Word::from([Felt::from(902u32); 4]);

    for (commitment, propose_salt) in [(commitment_a, 903u32), (commitment_b, 904u32)] {
        let tx = execute_delay_action(
            &mock_chain,
            account_id,
            "propose_transaction",
            commitment,
            salt(propose_salt),
            &[0, 1],
            &public_keys,
            &authenticators,
        )
        .await?
        .expect("propose tx should succeed");
        multisig_account.apply_patch(tx.account_patch())?;
        mock_chain.add_pending_executed_transaction(&tx)?;
        mock_chain.prove_next_block()?;
    }

    // Both proposals must exist in storage.
    for commitment in [commitment_a, commitment_b] {
        let entry = multisig_account
            .storage()
            .get_map_item(
                AuthMultisigSmart::tx_proposals_slot(),
                StorageMapKey::from_raw(commitment),
            )
            .expect("tx proposals slot should exist");
        assert_ne!(entry, Word::empty(), "proposal entry must be present in storage");
    }

    Ok(())
}
