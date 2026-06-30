use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountProcedureRoot,
    AccountType,
    StorageMapKey,
};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteRecipient,
    NoteStorage,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{
    Approver,
    ApproverSet,
    AuthGuardedMultisig,
    AuthGuardedMultisigConfig,
    GuardianConfig,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_AUTH_PROCEDURE_MUST_BE_CALLED_ALONE,
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_NOTES,
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES,
};
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

/// Sets up secret keys, public keys, and authenticators for multisig testing for the given scheme.
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

    // Create authenticators for required signers
    for secret_key in secret_keys.iter().take(threshold) {
        let authenticator = BasicAuthenticator::new(core::slice::from_ref(secret_key));
        authenticators.push(authenticator);
    }

    Ok((secret_keys, auth_schemes, public_keys, authenticators))
}

/// Builds the source for a tx-script that calls `update_guardian_public_key`. When `output_note`
/// is `Some`, the script also creates that note before the guardian update so a single call
/// exercises both `assert_no_input_notes` and `assert_no_output_notes` paths.
fn build_update_guardian_script_source(
    new_guardian_key_word: Word,
    new_guardian_scheme_id: u32,
    output_note: Option<&Note>,
) -> String {
    match output_note {
        Some(out) => {
            let recipient = out.recipient().digest();
            let note_type = NoteType::Public as u8;
            let tag = Felt::from(out.metadata().tag());
            format!(
                "
                use miden::protocol::output_note

                begin
                    push.{recipient}
                    push.{note_type}
                    push.{tag}
                    exec.output_note::create
                    swapdw
                    dropw
                    dropw
                    push.{new_guardian_key_word}
                    push.{new_guardian_scheme_id}
                    call.::miden::standards::components::auth::guarded_multisig::update_guardian_public_key
                    drop
                    dropw
                end
                "
            )
        },
        None => format!(
            "
            begin
                push.{new_guardian_key_word}
                push.{new_guardian_scheme_id}
                call.::miden::standards::components::auth::guarded_multisig::update_guardian_public_key
                drop
                dropw
            end
            "
        ),
    }
}

/// Creates a guarded multisig account configured with a guardian signer.
fn create_guarded_multisig_account(
    threshold: u32,
    approvers: &[(PublicKey, AuthScheme)],
    guardian: GuardianConfig,
    asset_amount: u64,
    proc_threshold_map: Vec<(AccountProcedureRoot, u32)>,
) -> anyhow::Result<Account> {
    let approvers = approvers
        .iter()
        .map(|(pub_key, auth_scheme)| Approver::new(pub_key.to_commitment(), *auth_scheme))
        .collect();
    let approver_set = ApproverSet::new(approvers, threshold)?;

    let config = AuthGuardedMultisigConfig::new(approver_set, guardian)?
        .with_proc_thresholds(proc_threshold_map)?;

    let multisig_account = AccountBuilder::new([0; 32])
        .account_type(AccountType::Public)
        .with_auth_component(AuthGuardedMultisig::new(config)?)
        .with_component(BasicWallet)
        .with_assets(vec![FungibleAsset::mock(asset_amount)])
        .build_existing()?;

    Ok(multisig_account)
}

// ================================================================================================
// TESTS
// ================================================================================================

/// Tests that guarded multisig authentication requires an additional guardian signature when
/// configured.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_guarded_multisig_signature_required(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let guardian_secret_key = AuthSecretKey::new_ecdsa_k256_keccak();
    let guardian_public_key = guardian_secret_key.public_key();
    let guardian_authenticator =
        BasicAuthenticator::new(core::slice::from_ref(&guardian_secret_key));

    let mut multisig_account = create_guarded_multisig_account(
        2,
        &approvers,
        GuardianConfig::new(Approver::new(
            guardian_public_key.to_commitment(),
            AuthScheme::EcdsaK256Keccak,
        )),
        10,
        vec![],
    )?;

    let output_note_asset = FungibleAsset::mock(0);
    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        &[output_note_asset],
        NoteType::Public,
    )?;
    let input_note = mock_chain_builder.add_spawn_note([&output_note])?;
    let mut mock_chain = mock_chain_builder.build().unwrap();

    let salt = Word::from([Felt::new_unchecked(777); 4]);
    let tx_context_builder = mock_chain
        .build_tx_context(multisig_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
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

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_signing)
        .await?;

    // Missing guardian signature must fail.
    let without_guardian_result = tx_context_builder
        .clone()
        .add_signature(public_keys[0].to_commitment(), msg, sig_1.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_2.clone())
        .build()?
        .execute()
        .await;
    assert!(matches!(
        without_guardian_result,
        Err(TransactionExecutorError::Unauthorized(_))
    ));

    let guardian_signature = guardian_authenticator
        .get_signature(guardian_public_key.to_commitment(), &tx_summary_signing)
        .await?;

    // With guardian signature the transaction should succeed.
    let tx_context_execute = tx_context_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(guardian_public_key.to_commitment(), msg, guardian_signature)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_patch(tx_context_execute.account_patch())?;

    mock_chain.add_pending_executed_transaction(&tx_context_execute)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        multisig_account.vault().get_balance(output_note_asset.vault_key())?.as_u64(),
        10 - output_note_asset.unwrap_fungible().amount().as_u64()
    );

    Ok(())
}

/// Tests that the guardian public key can be updated and then enforced for guarded multisig.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_guarded_multisig_update_guardian_public_key(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let old_guardian_secret_key = AuthSecretKey::new_ecdsa_k256_keccak();
    let old_guardian_public_key = old_guardian_secret_key.public_key();
    let old_guardian_authenticator =
        BasicAuthenticator::new(core::slice::from_ref(&old_guardian_secret_key));

    let new_guardian_secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let new_guardian_public_key = new_guardian_secret_key.public_key();
    let new_guardian_auth_scheme = new_guardian_secret_key.auth_scheme();
    let new_guardian_authenticator =
        BasicAuthenticator::new(core::slice::from_ref(&new_guardian_secret_key));

    let multisig_account = create_guarded_multisig_account(
        2,
        &approvers,
        GuardianConfig::new(Approver::new(
            old_guardian_public_key.to_commitment(),
            AuthScheme::EcdsaK256Keccak,
        )),
        10,
        vec![],
    )?;

    let mut mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let new_guardian_key_word: Word = new_guardian_public_key.to_commitment().into();
    let new_guardian_scheme_id = new_guardian_auth_scheme as u32;
    let update_guardian_script = CodeBuilder::new()
        .with_dynamically_linked_library(AuthGuardedMultisig::code())?
        .compile_tx_script(format!(
            "begin\n    push.{new_guardian_key_word}\n    push.{new_guardian_scheme_id}\n    call.::miden::standards::components::auth::guarded_multisig::update_guardian_public_key\n    drop\n    dropw\nend"
        ))?;

    let update_salt = Word::from([Felt::new_unchecked(991); 4]);
    let tx_context_builder = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(update_guardian_script)
        .auth_args(update_salt);

    let tx_summary = tx_context_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    let update_msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary);
    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_signing)
        .await?;

    // Guardian key rotation intentionally skips guardian signature for this update tx.
    let update_guardian_tx = tx_context_builder
        .add_signature(public_keys[0].to_commitment(), update_msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), update_msg, sig_2)
        .build()?
        .execute()
        .await?;

    let mut updated_multisig_account = multisig_account.clone();
    updated_multisig_account.apply_patch(update_guardian_tx.account_patch())?;
    let updated_guardian_public_key = updated_multisig_account
        .storage()
        .get_map_item(AuthGuardedMultisig::guardian_public_key_slot(), StorageMapKey::empty())?;
    assert_eq!(updated_guardian_public_key, Word::from(new_guardian_public_key.to_commitment()));
    let updated_guardian_scheme_id = updated_multisig_account.storage().get_map_item(
        AuthGuardedMultisig::guardian_scheme_id_slot(),
        StorageMapKey::from_index(0),
    )?;
    assert_eq!(
        updated_guardian_scheme_id,
        Word::from([new_guardian_auth_scheme as u32, 0u32, 0u32, 0u32])
    );

    mock_chain.add_pending_executed_transaction(&update_guardian_tx)?;
    mock_chain.prove_next_block()?;

    // Build one tx summary after key update. Old GUARDIAN must fail and new GUARDIAN must pass on
    // this same transaction.
    let next_salt = Word::from([Felt::new_unchecked(992); 4]);
    let tx_context_builder_next = mock_chain
        .build_tx_context(updated_multisig_account.id(), &[], &[])?
        .auth_args(next_salt);

    let tx_summary_next =
        match tx_context_builder_next.clone().build()?.execute().await.unwrap_err() {
            TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
            error => anyhow::bail!("expected abort with tx effects: {error}"),
        };
    let next_msg = tx_summary_next.as_ref().to_commitment();
    let tx_summary_next_signing = SigningInputs::TransactionSummary(tx_summary_next);

    let next_sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_next_signing)
        .await?;
    let next_sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_next_signing)
        .await?;
    let old_guardian_sig_next = old_guardian_authenticator
        .get_signature(old_guardian_public_key.to_commitment(), &tx_summary_next_signing)
        .await?;
    let new_guardian_sig_next = new_guardian_authenticator
        .get_signature(new_guardian_public_key.to_commitment(), &tx_summary_next_signing)
        .await?;

    // Old guardian signature must fail after key update.
    let with_old_guardian_result = tx_context_builder_next
        .clone()
        .add_signature(public_keys[0].to_commitment(), next_msg, next_sig_1.clone())
        .add_signature(public_keys[1].to_commitment(), next_msg, next_sig_2.clone())
        .add_signature(old_guardian_public_key.to_commitment(), next_msg, old_guardian_sig_next)
        .build()?
        .execute()
        .await;
    assert!(matches!(
        with_old_guardian_result,
        Err(TransactionExecutorError::Unauthorized(_))
    ));

    // New guardian signature must pass.
    tx_context_builder_next
        .add_signature(public_keys[0].to_commitment(), next_msg, next_sig_1)
        .add_signature(public_keys[1].to_commitment(), next_msg, next_sig_2)
        .add_signature(new_guardian_public_key.to_commitment(), next_msg, new_guardian_sig_next)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Tests that `update_guardian_public_key` must be the only account action in the transaction.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_guarded_multisig_update_guardian_public_key_must_be_called_alone(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let old_guardian_secret_key = AuthSecretKey::new_ecdsa_k256_keccak();
    let old_guardian_public_key = old_guardian_secret_key.public_key();
    let old_guardian_authenticator =
        BasicAuthenticator::new(core::slice::from_ref(&old_guardian_secret_key));

    let new_guardian_secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let new_guardian_public_key = new_guardian_secret_key.public_key();
    let new_guardian_auth_scheme = new_guardian_secret_key.auth_scheme();

    let multisig_account = create_guarded_multisig_account(
        2,
        &approvers,
        GuardianConfig::new(Approver::new(
            old_guardian_public_key.to_commitment(),
            AuthScheme::EcdsaK256Keccak,
        )),
        10,
        vec![],
    )?;

    let new_guardian_key_word: Word = new_guardian_public_key.to_commitment().into();
    let new_guardian_scheme_id = new_guardian_auth_scheme as u32;
    let update_guardian_script = CodeBuilder::new()
        .with_dynamically_linked_library(AuthGuardedMultisig::code())?
        .compile_tx_script(format!(
            "begin\n    push.{new_guardian_key_word}\n    push.{new_guardian_scheme_id}\n    call.::miden::standards::components::auth::guarded_multisig::update_guardian_public_key\n    drop\n    dropw\nend"
        ))?;

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();
    let receive_asset_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        multisig_account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;
    let mock_chain = mock_chain_builder.build().unwrap();

    let salt = Word::from([Felt::new_unchecked(993); 4]);
    let tx_context_builder = mock_chain
        .build_tx_context(multisig_account.id(), &[receive_asset_note.id()], &[])?
        .tx_script(update_guardian_script)
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
    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_signing)
        .await?;

    let without_guardian_result = tx_context_builder
        .clone()
        .add_signature(public_keys[0].to_commitment(), msg, sig_1.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_2.clone())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        without_guardian_result,
        ERR_AUTH_PROCEDURE_MUST_BE_CALLED_ALONE
    );

    let old_guardian_signature = old_guardian_authenticator
        .get_signature(old_guardian_public_key.to_commitment(), &tx_summary_signing)
        .await?;

    let with_guardian_result = tx_context_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(old_guardian_public_key.to_commitment(), msg, old_guardian_signature)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        with_guardian_result,
        ERR_AUTH_PROCEDURE_MUST_BE_CALLED_ALONE
    );

    // Also reject rotation transactions that touch notes even when no other account procedure is
    // called.
    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT)?;
    let note_serial_num = Word::from([1_u32, 2_u32, 3_u32, 4_u32]);
    let note_recipient =
        NoteRecipient::new(note_serial_num, note_script.clone(), NoteStorage::default());
    let output_note = Note::new(
        NoteAssets::new(vec![])?,
        PartialNoteMetadata::new(multisig_account.id(), NoteType::Public),
        note_recipient,
    );

    let new_guardian_key_word: Word = new_guardian_public_key.to_commitment().into();
    let new_guardian_scheme_id = new_guardian_auth_scheme as u32;
    let update_guardian_with_output_script = CodeBuilder::new()
        .with_dynamically_linked_library(AuthGuardedMultisig::code())?
        .compile_tx_script(format!(
            "use miden::protocol::output_note\nbegin\n    push.{recipient}\n    push.{note_type}\n    push.{tag}\n    exec.output_note::create\n    swapdw\n    dropw\n    dropw\n    push.{new_guardian_key_word}\n    push.{new_guardian_scheme_id}\n    call.::miden::standards::components::auth::guarded_multisig::update_guardian_public_key\n    drop\n    dropw\nend",
            recipient = output_note.recipient().digest(),
            note_type = NoteType::Public as u8,
            tag = Felt::from(output_note.metadata().tag()),
        ))?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let salt = Word::from([Felt::new_unchecked(994); 4]);
    let tx_context_builder = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(update_guardian_with_output_script)
        .add_note_script(note_script)
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
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
    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_signing)
        .await?;

    let result = tx_context_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .build()?
        .execute()
        .await;

    // The transaction creates an output note (no input notes), so after the input check passes
    // the output check fires.
    assert_transaction_executor_error!(result, ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES);

    Ok(())
}

/// `update_guardian_public_key` rejects every transaction that consumes input notes or creates
/// output notes. Parametrized over the (input, output) tx layout so each path through the two
/// separate `assert_no_*_notes` calls in `guardian.masm` is exercised — and the input check
/// firing before the output check is verified explicitly via the (true, true) case.
#[rstest]
#[case::no_notes(false, false)]
#[case::input_only(true, false)]
#[case::output_only(false, true)]
#[case::both(true, true)]
#[tokio::test]
async fn test_guarded_multisig_update_guardian_enforces_no_notes(
    #[case] include_input_note: bool,
    #[case] include_output_note: bool,
) -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let old_guardian_secret_key = AuthSecretKey::new_ecdsa_k256_keccak();
    let old_guardian_public_key = old_guardian_secret_key.public_key();
    let old_guardian_authenticator =
        BasicAuthenticator::new(core::slice::from_ref(&old_guardian_secret_key));

    let new_guardian_secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let new_guardian_public_key = new_guardian_secret_key.public_key();
    let new_guardian_auth_scheme = new_guardian_secret_key.auth_scheme();

    let multisig_account = create_guarded_multisig_account(
        2,
        &approvers,
        GuardianConfig::new(Approver::new(
            old_guardian_public_key.to_commitment(),
            AuthScheme::EcdsaK256Keccak,
        )),
        10,
        vec![],
    )?;

    let new_guardian_key_word: Word = new_guardian_public_key.to_commitment().into();
    let new_guardian_scheme_id = new_guardian_auth_scheme as u32;

    // Optional output note (no-op script — doesn't trigger any account procedure).
    let output_note = if include_output_note {
        let serial = Word::from([1_u32, 2_u32, 3_u32, 4_u32]);
        let recipient = NoteRecipient::new(
            serial,
            CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT)?,
            NoteStorage::default(),
        );
        Some(Note::new(
            NoteAssets::new(vec![])?,
            PartialNoteMetadata::new(multisig_account.id(), NoteType::Public),
            recipient,
        ))
    } else {
        None
    };

    // Compile the tx-script: bare update_guardian, or one that also creates the output note.
    let script_source = build_update_guardian_script_source(
        new_guardian_key_word,
        new_guardian_scheme_id,
        output_note.as_ref(),
    );
    let update_guardian_script = CodeBuilder::new()
        .with_dynamically_linked_library(AuthGuardedMultisig::code())?
        .compile_tx_script(script_source)?;

    // Optional no-op input note seeded into the chain so the multisig account can consume it
    // without invoking any non-auth procedure (DEFAULT_NOTE_SCRIPT is a single `nop`).
    let mut chain_builder = MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();
    let input_note = if include_input_note {
        let serial = Word::from([5_u32, 6_u32, 7_u32, 8_u32]);
        let recipient = NoteRecipient::new(
            serial,
            CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT)?,
            NoteStorage::default(),
        );
        let note = Note::new(
            NoteAssets::new(vec![])?,
            PartialNoteMetadata::new(multisig_account.id(), NoteType::Public),
            recipient,
        );
        chain_builder.add_output_note(RawOutputNote::Full(note.clone()));
        Some(note)
    } else {
        None
    };
    let mock_chain = chain_builder.build()?;

    let input_ids: Vec<_> = input_note.as_ref().map(|n| vec![n.id()]).unwrap_or_default();
    let salt = Word::from([Felt::new_unchecked(995); 4]);

    // Dry-run to obtain the tx summary the signers must sign.
    let mut tx_context_builder = mock_chain
        .build_tx_context(multisig_account.id(), &input_ids, &[])?
        .tx_script(update_guardian_script)
        .auth_args(salt);
    if let Some(out) = output_note {
        tx_context_builder =
            tx_context_builder.extend_expected_output_notes(vec![RawOutputNote::Full(out)]);
    }
    let tx_summary = tx_context_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    let msg = tx_summary.as_ref().to_commitment();
    let signing = SigningInputs::TransactionSummary(tx_summary);
    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &signing)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &signing)
        .await?;
    let guardian_sig = old_guardian_authenticator
        .get_signature(old_guardian_public_key.to_commitment(), &signing)
        .await?;

    let result = tx_context_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(old_guardian_public_key.to_commitment(), msg, guardian_sig)
        .build()?
        .execute()
        .await;

    // Input check fires first, output check fires only when no input notes are present.
    match (include_input_note, include_output_note) {
        (false, false) => {
            result.expect("tx must succeed when neither input nor output notes are present");
        },
        (true, _) => assert_transaction_executor_error!(
            result,
            ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_NOTES
        ),
        (false, true) => assert_transaction_executor_error!(
            result,
            ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES
        ),
    }

    Ok(())
}
