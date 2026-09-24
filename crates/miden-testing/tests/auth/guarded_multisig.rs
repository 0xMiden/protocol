use core::num::NonZeroU32;

use miden_processor::advice::AdviceInputs;
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
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::auth::{
    Approver,
    ApproverSet,
    AuthGuardedMultisig,
    AuthGuardedMultisigConfig,
    FeeConversionInfo,
    GuardianConfig,
    MultisigAuthArgs,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_AUTH_PROCEDURE_MUST_BE_CALLED_ALONE,
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_NOTES,
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES,
    ERR_PUBLIC_KEY_IS_APPROVER,
};
use miden_testing::{Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

use super::fee_payment::{VERIFICATION_BASE_FEE, assert_single_fee_note, multisig_auth_estimate};
use super::multisig::{
    MultisigAuthArgsExt,
    build_update_signers_config_vector,
    eip712_signature_witness,
};

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

                @transaction_script
                pub proc main
                    push.{recipient}
                    push.{note_type}
                    push.{tag}
                    call.::miden::standards::note::note_creator::create_note
                    movdn.15 dropw dropw dropw drop drop drop
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
            @transaction_script
            pub proc main
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
        .with_component(AuthGuardedMultisig::new(config)?)
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
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .authenticated_input_note(input_note.id())
        .expected_output_note(RawOutputNote::Full(output_note))
        .multisig_auth_args(MultisigAuthArgs::new(
            mock_chain.latest_block_header().block_num(),
            salt,
        ));

    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary.clone());

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_signing)
        .await?;

    // Missing guardian signature must fail.
    let without_guardian_result = mock_tx_builder
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

    let (guardian_eip712_key, guardian_eip712_witness) =
        eip712_signature_witness(&guardian_secret_key, &guardian_public_key, tx_summary.as_ref())?;

    // Guardian acknowledgements accept the same EIP-712 fallback as multisig approvers.
    mock_tx_builder
        .clone()
        .add_signature(public_keys[0].to_commitment(), msg, sig_1.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_2.clone())
        .add_advice_map_entry(guardian_eip712_key, guardian_eip712_witness)
        .build()?
        .execute()
        .await?;

    let guardian_signature = guardian_authenticator
        .get_signature(guardian_public_key.to_commitment(), &tx_summary_signing)
        .await?;

    // With guardian signature the transaction should succeed.
    let mock_tx_execute = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(guardian_public_key.to_commitment(), msg, guardian_signature)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_patch(mock_tx_execute.account_patch())?;

    mock_chain.add_pending_executed_transaction(&mock_tx_execute)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        multisig_account.vault().get_balance(output_note_asset.id())?.as_u64(),
        10 - output_note_asset.unwrap_fungible().amount().as_u64()
    );

    Ok(())
}

/// Tests that a guarded multisig whose approval expires still shows the guardian the summary the
/// approvers signed.
///
/// The approval expiration is written to the kernel only after the guardian signature has been
/// requested, so the summary the host re-derives for that request still matches the kernel state.
/// Applying it earlier would make the guardian's request fail with an expiration mismatch instead.
///
/// **Roles:**
/// - 2 Approvers (2 signers required)
/// - 1 Guardian
/// - 1 Guarded Multisig Contract
#[tokio::test]
async fn test_guarded_multisig_approval_expiration_is_applied_after_the_guardian_signature()
-> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, AuthScheme::Falcon512Poseidon2)?;
    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let guardian_secret_key = AuthSecretKey::new_ecdsa_k256_keccak();
    let guardian_public_key = guardian_secret_key.public_key();
    let guardian_authenticator =
        BasicAuthenticator::new(core::slice::from_ref(&guardian_secret_key));

    let multisig_account = create_guarded_multisig_account(
        2,
        &approvers,
        GuardianConfig::new(Approver::new(
            guardian_public_key.to_commitment(),
            AuthScheme::EcdsaK256Keccak,
        )),
        10,
        vec![],
    )?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])?.build()?;

    let salt = Word::from([Felt::from(31u32); 4]);
    let approval_expiration_delta = NonZeroU32::new(10).unwrap();
    let signed_block = mock_chain.latest_block_header().block_num();
    let auth_args = MultisigAuthArgs::new(signed_block, salt)
        .with_approval_expiration_delta(approval_expiration_delta)?;

    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
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

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &signing_inputs)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &signing_inputs)
        .await?;

    // Without the guardian signature the guardian is shown the very summary the approvers signed,
    // rather than the transaction aborting while re-deriving it.
    let guardian_summary = mock_tx_builder
        .clone()
        .add_signature(public_keys[0].to_commitment(), msg, sig_1.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_2.clone())
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    assert_eq!(guardian_summary.as_ref().to_commitment(), msg);

    let guardian_signature = guardian_authenticator
        .get_signature(guardian_public_key.to_commitment(), &signing_inputs)
        .await?;

    let executed_transaction = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(guardian_public_key.to_commitment(), msg, guardian_signature)
        .build()?
        .execute()
        .await?;

    assert_eq!(
        executed_transaction.expiration_block_num(),
        signed_block + approval_expiration_delta.get()
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

    let update_salt = Word::from([Felt::new_unchecked(991); 4]);
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(update_guardian_script)
        .multisig_auth_args(MultisigAuthArgs::new(
            mock_chain.latest_block_header().block_num(),
            update_salt,
        ));

    let tx_summary = mock_tx_builder
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
    let update_guardian_tx = mock_tx_builder
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
    let mock_tx_builder_next =
        mock_chain.build_transaction(updated_multisig_account.id()).multisig_auth_args(
            MultisigAuthArgs::new(mock_chain.latest_block_header().block_num(), next_salt),
        );

    let tx_summary_next = mock_tx_builder_next
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
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
    let with_old_guardian_result = mock_tx_builder_next
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
    mock_tx_builder_next
        .add_signature(public_keys[0].to_commitment(), next_msg, next_sig_1)
        .add_signature(public_keys[1].to_commitment(), next_msg, next_sig_2)
        .add_signature(new_guardian_public_key.to_commitment(), next_msg, new_guardian_sig_next)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Tests that a `update_guardian_public_key` rotation must not touch notes, and that a valid
/// guardian signature does not bypass that requirement.
///
/// Three ways to violate the "called alone" requirement are exercised: an input note (which invokes
/// `receive_asset`), an output note (created via `create_note`), and a note-free second procedure
/// (a direct `receive_asset` vault write). Because `guardian.masm` runs the input- and output-note
/// guards before `assert_only_one_non_auth_procedure_called`, the note cases surface the specific
/// note errors, while the note-free case is what actually trips
/// `assert_only_one_non_auth_procedure_called`.
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
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .authenticated_input_note(receive_asset_note.id())
        .tx_script(update_guardian_script)
        .multisig_auth_args(MultisigAuthArgs::new(
            mock_chain.latest_block_header().block_num(),
            salt,
        ));

    let tx_summary = mock_tx_builder
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

    let without_guardian_result = mock_tx_builder
        .clone()
        .add_signature(public_keys[0].to_commitment(), msg, sig_1.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_2.clone())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        without_guardian_result,
        ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_NOTES
    );

    let old_guardian_signature = old_guardian_authenticator
        .get_signature(old_guardian_public_key.to_commitment(), &tx_summary_signing)
        .await?;

    let with_guardian_result = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(old_guardian_public_key.to_commitment(), msg, old_guardian_signature)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        with_guardian_result,
        ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_INPUT_NOTES
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
        .with_dynamically_linked_package(AuthGuardedMultisig::code())?
        .compile_tx_script(format!(
            "
            @transaction_script
            pub proc main
                push.{recipient}
                push.{note_type}
                push.{tag}
                call.::miden::standards::note::note_creator::create_note
                drop
                # => [pad(21)]
                
                push.{new_guardian_key_word}
                push.{new_guardian_scheme_id}
                call.::miden::standards::components::auth::guarded_multisig::update_guardian_public_key

                dropw dropw drop drop
            end
            ",
            recipient = output_note.recipient().digest(),
            note_type = NoteType::Public as u8,
            tag = Felt::from(output_note.metadata().tag()),
        ))?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let salt = Word::from([Felt::new_unchecked(994); 4]);
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(update_guardian_with_output_script)
        .add_note_script(note_script)
        .expected_output_note(RawOutputNote::Full(output_note))
        .multisig_auth_args(MultisigAuthArgs::new(
            mock_chain.latest_block_header().block_num(),
            salt,
        ));

    let tx_summary = mock_tx_builder
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

    let result = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .build()?
        .execute()
        .await;

    // The rotation creates an output note (and no input notes), so the output-note guard - which
    // runs before `assert_only_one_non_auth_procedure_called` - rejects it.
    assert_transaction_executor_error!(result, ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES);

    // Finally, combine the rotation with a note-free second procedure: a direct `receive_asset`
    // vault write. With no input or output notes, both note guards pass and
    // `assert_only_one_non_auth_procedure_called` is the guard that fires. (The unsourced asset
    // would break asset preservation, but the auth procedure runs before that check in the
    // epilogue, so the "called alone" error surfaces first.)
    let extra_asset = FungibleAsset::mock(1);
    let update_guardian_with_receive_script = CodeBuilder::new()
        .with_dynamically_linked_package(AuthGuardedMultisig::code())?
        .compile_tx_script(format!(
            "
            use miden::standards::wallets::basic as wallet
            
            @transaction_script
            pub proc main
                push.{asset_value}
                push.{asset_id}
                call.wallet::receive_asset
                # => [pad(24)]

                push.{new_guardian_key_word}
                push.{new_guardian_scheme_id}
                call.::miden::standards::components::auth::guarded_multisig::update_guardian_public_key
                # => [pad(29)]
                
                dropw dropw dropw dropw drop
            end
            ",
            asset_value = extra_asset.to_value_word(),
            asset_id = extra_asset.to_id_word(),
        ))?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let salt = Word::from([Felt::new_unchecked(995); 4]);
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(update_guardian_with_receive_script)
        .multisig_auth_args(MultisigAuthArgs::new(
            mock_chain.latest_block_header().block_num(),
            salt,
        ));

    let tx_summary = mock_tx_builder
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

    let result = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTH_PROCEDURE_MUST_BE_CALLED_ALONE);

    Ok(())
}

/// `update_guardian_public_key` rejects every transaction that consumes input notes or creates
/// output notes. Parametrized over the (input, output) tx layout. Since output notes can only be
/// created by calling the account's `create_note` procedure, any output note trips the "called
/// alone" guard before `assert_no_output_notes` is reached; a plain input note that invokes no
/// account procedure reaches `assert_no_input_notes` directly.
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
        .with_dynamically_linked_package(AuthGuardedMultisig::code())?
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
    let mut mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .authenticated_input_notes(input_ids)
        .tx_script(update_guardian_script)
        .multisig_auth_args(MultisigAuthArgs::new(
            mock_chain.latest_block_header().block_num(),
            salt,
        ));
    if let Some(out) = output_note {
        mock_tx_builder = mock_tx_builder.expected_output_note(RawOutputNote::Full(out));
    }
    let tx_summary = mock_tx_builder
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

    let result = mock_tx_builder
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

/// Tests that the guarded multisig auth script rejects a guardian rotation onto an existing
/// approver's public key, the configuration `AuthGuardedMultisigConfig::new` already rejects at
/// deployment time.
///
/// The rotation path is the one that skips guardian verification, so without this check the quorum
/// could make one of its own signatures satisfy both the multisig and the guardian check.
#[tokio::test]
async fn test_guarded_multisig_rotation_to_approver_public_key_is_rejected() -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let guardian_secret_key = AuthSecretKey::new_ecdsa_k256_keccak();
    let guardian_public_key = guardian_secret_key.public_key();

    let multisig_account = create_guarded_multisig_account(
        2,
        &approvers,
        GuardianConfig::new(Approver::new(
            guardian_public_key.to_commitment(),
            AuthScheme::EcdsaK256Keccak,
        )),
        10,
        vec![],
    )?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    // Rotate the guardian onto the first approver's public key.
    let new_guardian_key_word: Word = public_keys[0].to_commitment().into();
    let update_guardian_script = CodeBuilder::new()
        .with_dynamically_linked_package(AuthGuardedMultisig::code())?
        .compile_tx_script(build_update_guardian_script_source(
            new_guardian_key_word,
            auth_scheme as u32,
            None,
        ))?;

    let salt = Word::from([Felt::new_unchecked(994); 4]);
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(update_guardian_script)
        .multisig_auth_args(MultisigAuthArgs::new(
            mock_chain.latest_block_header().block_num(),
            salt,
        ));

    let tx_summary = mock_tx_builder
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

    // A quorum alone is enough to reach the rotation path, which is exactly why the auth script has
    // to reject the resulting configuration.
    let result = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PUBLIC_KEY_IS_APPROVER);

    Ok(())
}

/// Tests the symmetric case of the check above: the approver set must not be updated to include
/// the configured guardian public key, while an update that keeps the guardian outside the new
/// approver set still goes through.
#[rstest]
#[case::guardian_added_as_approver(true)]
#[case::guardian_outside_approver_set(false)]
#[tokio::test]
async fn test_guarded_multisig_signer_update_enforces_the_guardian_invariant(
    #[case] add_guardian_as_approver: bool,
) -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
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

    let multisig_account = create_guarded_multisig_account(
        2,
        &approvers,
        GuardianConfig::new(Approver::new(
            guardian_public_key.to_commitment(),
            AuthScheme::EcdsaK256Keccak,
        )),
        10,
        vec![],
    )?;

    let mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    // Grow the signer set by one key: either the guardian's, which must be rejected, or an
    // unrelated one, which must be accepted.
    let new_approver_public_key = if add_guardian_as_approver {
        guardian_public_key.clone()
    } else {
        AuthSecretKey::new_ecdsa_k256_keccak().public_key()
    };
    let new_public_keys =
        vec![public_keys[0].clone(), public_keys[1].clone(), new_approver_public_key.clone()];
    let config_and_pubkeys_vector =
        build_update_signers_config_vector(2, 3, &new_public_keys, auth_scheme);
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);

    let update_signers_script = CodeBuilder::new()
        .with_dynamically_linked_package(AuthGuardedMultisig::code())?
        .compile_tx_script(
            "
            @transaction_script
            pub proc main
                call.::miden::standards::components::auth::guarded_multisig::update_signers_and_threshold
            end
            ",
        )?;

    let advice_inputs =
        AdviceInputs::default().with_map([(multisig_config_hash, config_and_pubkeys_vector)]);
    let salt = Word::from([Felt::new_unchecked(995); 4]);
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
        .tx_script(update_signers_script)
        .tx_script_args(multisig_config_hash)
        .extend_advice_inputs(advice_inputs)
        .multisig_auth_args(MultisigAuthArgs::new(
            mock_chain.latest_block_header().block_num(),
            salt,
        ));

    let tx_summary = mock_tx_builder
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
    let guardian_signature = guardian_authenticator
        .get_signature(guardian_public_key.to_commitment(), &tx_summary_signing)
        .await?;

    let result = mock_tx_builder
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(guardian_public_key.to_commitment(), msg, guardian_signature)
        .build()?
        .execute()
        .await;

    if add_guardian_as_approver {
        assert_transaction_executor_error!(result, ERR_PUBLIC_KEY_IS_APPROVER);

        return Ok(());
    }

    // The new signer set is applied and the guardian keeps its own key.
    let mut updated_multisig_account = multisig_account.clone();
    updated_multisig_account.apply_patch(result?.account_patch())?;

    let stored_new_approver = updated_multisig_account.storage().get_map_item(
        AuthGuardedMultisig::approver_public_keys_slot(),
        StorageMapKey::from_index(2),
    )?;
    assert_eq!(stored_new_approver, Word::from(new_approver_public_key.to_commitment()));

    let stored_guardian = updated_multisig_account.storage().get_map_item(
        AuthGuardedMultisig::guardian_public_key_slot(),
        StorageMapKey::from_index(0),
    )?;
    assert_eq!(stored_guardian, Word::from(guardian_public_key.to_commitment()));

    Ok(())
}

/// Tests that guarded multisig pays the transaction fee with a TX_FEE note funded from the vault,
/// and that the measured auth cycles stay within the estimate, which counts the guardian as a
/// signer.
#[tokio::test]
async fn test_guarded_multisig_pays_fee_note() -> anyhow::Result<()> {
    let auth_scheme = AuthScheme::Falcon512Poseidon2;
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(public_key, auth_scheme)| Approver::new(public_key.to_commitment(), *auth_scheme))
        .collect();

    let guardian_secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let guardian_public_key = guardian_secret_key.public_key();
    let guardian_authenticator =
        BasicAuthenticator::new(core::slice::from_ref(&guardian_secret_key));

    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let initial_fee_asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let mut multisig_account = builder.add_existing_wallet_with_assets(
        Auth::GuardedMultisig {
            approver_set: ApproverSet::new(approvers, 2)?,
            guardian_config: GuardianConfig::new(Approver::new(
                guardian_public_key.to_commitment(),
                auth_scheme,
            )),
            proc_threshold_map: vec![],
        },
        [initial_fee_asset.into()],
    )?;
    let mock_chain = builder.build()?;

    let auth_args = MultisigAuthArgs::new(
        mock_chain.latest_block_header().block_num(),
        Word::from([Felt::from(5u32); 4]),
    )
    .with_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id));
    let mock_tx_builder = mock_chain
        .build_transaction(multisig_account.id())
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
    for (public_key, authenticator) in public_keys.iter().zip(&authenticators) {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }
    let guardian_signature = guardian_authenticator
        .get_signature(guardian_public_key.to_commitment(), &signing_inputs)
        .await?;
    let executed_transaction = signed_builder
        .add_signature(guardian_public_key.to_commitment(), msg, guardian_signature)
        .build()?
        .execute()
        .await?;

    let paid_fee_asset = assert_single_fee_note(&executed_transaction)?;

    multisig_account.apply_patch(executed_transaction.account_patch())?;
    assert_eq!(
        multisig_account.vault().get_balance(initial_fee_asset.id())?.as_u64(),
        initial_fee_asset.amount().as_u64() - paid_fee_asset.amount().as_u64()
    );

    // two approver signatures and the guardian signature are verified
    let auth_procedure_cycles = executed_transaction.measurements().auth_procedure;
    let auth_estimate = multisig_auth_estimate(3);
    assert!(
        auth_procedure_cycles <= auth_estimate,
        "guarded multisig auth procedure took {auth_procedure_cycles} cycles, exceeding the estimate of {auth_estimate}",
    );

    Ok(())
}
