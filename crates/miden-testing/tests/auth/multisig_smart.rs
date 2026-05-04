use miden_processor::advice::AdviceInputs;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountStorageMode,
    AccountType,
};
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
use miden_standards::account::components::multisig_smart_library;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_OR_OUTPUT_NOTES;
use miden_testing::{MockChainBuilder, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================

type MultisigTestSetup =
    (Vec<AuthSecretKey>, Vec<AuthScheme>, Vec<PublicKey>, Vec<BasicAuthenticator>);

/// Sets up secret keys, auth schemes, public keys, and authenticators for a specific scheme.
fn setup_keys_and_authenticators_with_scheme(
    num_approvers: usize,
    threshold: usize,
    auth_scheme: AuthScheme,
) -> anyhow::Result<MultisigTestSetup> {
    let seed: [u8; 32] = rand::random();
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut secret_keys = Vec::new();
    let mut auth_schemes = Vec::new();
    let mut public_keys = Vec::new();
    let mut authenticators = Vec::new();

    for _ in 0..num_approvers {
        let sec_key = match auth_scheme {
            AuthScheme::EcdsaK256Keccak => AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng),
            AuthScheme::Falcon512Poseidon2 => {
                AuthSecretKey::new_falcon512_poseidon2_with_rng(&mut rng)
            },
            _ => anyhow::bail!("unsupported auth scheme for this test: {auth_scheme:?}"),
        };
        let pub_key = sec_key.public_key();

        secret_keys.push(sec_key);
        auth_schemes.push(auth_scheme);
        public_keys.push(pub_key);
    }

    for secret_key in secret_keys.iter().take(threshold) {
        authenticators.push(BasicAuthenticator::new(core::slice::from_ref(secret_key)));
    }

    Ok((secret_keys, auth_schemes, public_keys, authenticators))
}

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
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_assets(core::iter::once(asset.into()))
        .build_existing()?;

    Ok(multisig_account)
}

/// Compiles a transaction script that links against the multisig smart library so it can `call.`
/// the wrapper-exported procedures.
fn compile_multisig_smart_tx_script(script: impl AsRef<str>) -> anyhow::Result<TransactionScript> {
    Ok(CodeBuilder::default()
        .with_dynamically_linked_library(multisig_smart_library())?
        .compile_tx_script(script.as_ref())?)
}

/// Layout expected by `update_signers_and_threshold` when looking up the new multisig config in
/// the advice map: `[threshold, num_approvers, 0, 0, (PUB_KEY, SCHEME_WORD) for each approver]`.
/// Public keys are appended in reverse so the procedure pops them in ascending index order.
fn build_update_signers_config_vector(
    threshold: u64,
    num_of_approvers: u64,
    public_keys: &[PublicKey],
    auth_scheme: AuthScheme,
) -> Vec<Felt> {
    let mut config_and_pubkeys_vector = Vec::new();
    config_and_pubkeys_vector.extend_from_slice(&[
        Felt::new(threshold),
        Felt::new(num_of_approvers),
        Felt::new(0),
        Felt::new(0),
    ]);

    let scheme_word = [Felt::new(auth_scheme as u64), Felt::new(0), Felt::new(0), Felt::new(0)];

    for public_key in public_keys.iter().rev() {
        let key_word: Word = public_key.to_commitment().into();
        config_and_pubkeys_vector.extend_from_slice(key_word.as_elements());
        config_and_pubkeys_vector.extend_from_slice(&scheme_word);
    }

    config_and_pubkeys_vector
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
        vec![(BasicWallet::receive_asset_digest(), receive_asset_one_signature_policy)];

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

    let salt = Word::from([Felt::new(1); 4]);
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

/// A procedure policy with `NoInputOrOutputNotes` restriction must abort any transaction that
/// reaches that procedure while carrying input or output notes.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_smart_proc_policy_no_notes_constraint_is_enforced(
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
            BasicWallet::receive_asset_digest(),
            ProcedurePolicy::with_immediate_threshold(1)?
                .with_note_restriction(ProcedurePolicyNoteRestriction::NoInputOrOutputNotes),
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

    let salt = Word::from([Felt::new(2); 4]);
    let result = mock_chain
        .build_tx_context(multisig_account.id(), &[note.id()], &[])?
        .auth_args(salt)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_OR_OUTPUT_NOTES
    );

    Ok(())
}

/// Tests `update_signers_and_threshold` happy path: a 2-of-2 multisig is rotated to a 4-of-3
/// signer set with new public keys; the new threshold and signers are persisted in storage.
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

    let salt = Word::from([Felt::new(3); 4]);

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
    assert_eq!(threshold_config[0], Felt::new(new_threshold));
    assert_eq!(threshold_config[1], Felt::new(new_num_approvers));

    // Verify each new public key is stored at its expected map index.
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let storage_key =
            Word::from([Felt::new(i as u64), Felt::new(0), Felt::new(0), Felt::new(0)]);
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

    let receive_asset_root = BasicWallet::receive_asset_digest();
    // `call.` does not consume operand-stack inputs (the procedure sees a snapshot, the caller's
    // stack is preserved across the boundary), so we must manually drop the 7 elements we pushed.
    let set_policy_script = compile_multisig_smart_tx_script(format!(
        "
        begin
            push.{root}
            push.0    # note_restrictions
            push.0    # delayed_threshold
            push.1    # immediate_threshold
            call.::miden::standards::components::auth::multisig_smart::set_procedure_policy
            drop drop drop  # immediate, delayed, note_restrictions
            dropw           # PROC_ROOT
        end
        ",
        root = receive_asset_root,
    ))?;

    let salt = Word::from([Felt::new(4); 4]);

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
    assert_eq!(stored_policy, Word::from([1u32, 0, 0, 0]));

    Ok(())
}
