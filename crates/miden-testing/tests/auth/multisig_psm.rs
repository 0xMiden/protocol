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
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::transaction::OutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{AuthMultisigPsm, AuthMultisigPsmConfig, PsmConfig};
use miden_standards::account::components::multisig_psm_library;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::MockChainBuilder;
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

/// Creates a multisig account configured with a private state manager signer.
fn create_multisig_account_with_psm(
    threshold: u32,
    approvers: &[(PublicKey, AuthScheme)],
    psm: PsmConfig,
    asset_amount: u64,
    proc_threshold_map: Vec<(Word, u32)>,
) -> anyhow::Result<Account> {
    let approvers = approvers
        .iter()
        .map(|(pub_key, auth_scheme)| (pub_key.to_commitment(), *auth_scheme))
        .collect();

    let config = AuthMultisigPsmConfig::new(approvers, threshold, psm)?
        .with_proc_thresholds(proc_threshold_map)?;

    let multisig_account = AccountBuilder::new([0; 32])
        .with_auth_component(AuthMultisigPsm::new(config)?)
        .with_component(BasicWallet)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_assets(vec![FungibleAsset::mock(asset_amount)])
        .build_existing()?;

    Ok(multisig_account)
}

// ================================================================================================
// TESTS
// ================================================================================================

/// Tests that multisig authentication requires an additional PSM signature when
/// configured.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_psm_signature_required(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let psm_secret_key = AuthSecretKey::new_ecdsa_k256_keccak();
    let psm_public_key = psm_secret_key.public_key();
    let psm_authenticator = BasicAuthenticator::new(core::slice::from_ref(&psm_secret_key));

    let mut multisig_account = create_multisig_account_with_psm(
        2,
        &approvers,
        PsmConfig::new(psm_public_key.to_commitment(), AuthScheme::EcdsaK256Keccak),
        10,
        vec![],
    )?;
    let psm_config = multisig_account.storage().get_item(AuthMultisigPsm::psm_config_slot())?;
    assert_eq!(psm_config, Word::from([1u32, 0u32, 0u32, 0u32]));

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

    let salt = Word::from([Felt::new(777); 4]);
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => anyhow::bail!("expected abort with tx effects: {error}"),
    };
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_signing)
        .await?;

    // Missing PSM signature must fail.
    let without_psm_result = mock_chain
        .build_tx_context(multisig_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .add_signature(public_keys[0].to_commitment(), msg, sig_1.clone())
        .add_signature(public_keys[1].to_commitment(), msg, sig_2.clone())
        .auth_args(salt)
        .build()?
        .execute()
        .await;
    assert!(matches!(without_psm_result, Err(TransactionExecutorError::Unauthorized(_))));

    let psm_signature = psm_authenticator
        .get_signature(psm_public_key.to_commitment(), &tx_summary_signing)
        .await?;

    // With PSM signature the transaction should succeed.
    let tx_context_execute = mock_chain
        .build_tx_context(multisig_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(psm_public_key.to_commitment(), msg, psm_signature)
        .auth_args(salt)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_delta(tx_context_execute.account_delta())?;
    let psm_config = multisig_account.storage().get_item(AuthMultisigPsm::psm_config_slot())?;
    assert_eq!(psm_config, Word::from([1u32, 0u32, 0u32, 0u32]));

    mock_chain.add_pending_executed_transaction(&tx_context_execute)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        multisig_account
            .vault()
            .get_balance(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?)?,
        10 - output_note_asset.unwrap_fungible().amount()
    );

    Ok(())
}

/// Tests that the PSM public key can be updated and then enforced.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_multisig_update_psm_public_key(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(2, 2, auth_scheme)?;
    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(pk, scheme)| (pk.clone(), *scheme))
        .collect::<Vec<_>>();

    let old_psm_secret_key = AuthSecretKey::new_ecdsa_k256_keccak();
    let old_psm_public_key = old_psm_secret_key.public_key();
    let old_psm_authenticator = BasicAuthenticator::new(core::slice::from_ref(&old_psm_secret_key));

    let new_psm_secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let new_psm_public_key = new_psm_secret_key.public_key();
    let new_psm_auth_scheme = new_psm_secret_key.auth_scheme();
    let new_psm_authenticator = BasicAuthenticator::new(core::slice::from_ref(&new_psm_secret_key));

    let multisig_account = create_multisig_account_with_psm(
        2,
        &approvers,
        PsmConfig::new(old_psm_public_key.to_commitment(), AuthScheme::EcdsaK256Keccak),
        10,
        vec![],
    )?;
    let psm_config = multisig_account.storage().get_item(AuthMultisigPsm::psm_config_slot())?;
    assert_eq!(psm_config, Word::from([1u32, 0u32, 0u32, 0u32]));

    let mut mock_chain = MockChainBuilder::with_accounts([multisig_account.clone()])
        .unwrap()
        .build()
        .unwrap();

    let new_psm_key_word: Word = new_psm_public_key.to_commitment().into();
    let new_psm_scheme_id = new_psm_auth_scheme as u32;
    let update_psm_script = CodeBuilder::new()
        .with_dynamically_linked_library(multisig_psm_library())?
        .compile_tx_script(format!(
            "begin\n    push.{new_psm_key_word}\n    push.{new_psm_scheme_id}\n    call.::multisig_psm::update_psm_public_key\n    drop\n    dropw\nend"
        ))?;

    let update_salt = Word::from([Felt::new(991); 4]);
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(update_psm_script.clone())
        .auth_args(update_salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => anyhow::bail!("expected abort with tx effects: {error}"),
    };

    let update_msg = tx_summary.as_ref().to_commitment();
    let tx_summary_signing = SigningInputs::TransactionSummary(tx_summary);
    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_signing)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_signing)
        .await?;

    // PSM key rotation intentionally skips PSM signature for this update tx.
    let update_psm_tx = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(update_psm_script)
        .add_signature(public_keys[0].to_commitment(), update_msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), update_msg, sig_2)
        .auth_args(update_salt)
        .build()?
        .execute()
        .await?;

    let mut updated_multisig_account = multisig_account.clone();
    updated_multisig_account.apply_delta(update_psm_tx.account_delta())?;
    let psm_config = updated_multisig_account
        .storage()
        .get_item(AuthMultisigPsm::psm_config_slot())?;
    assert_eq!(psm_config, Word::from([1u32, 0u32, 0u32, 0u32]));

    let updated_psm_public_key = updated_multisig_account
        .storage()
        .get_map_item(AuthMultisigPsm::psm_public_key_slot(), Word::from([0u32, 0, 0, 0]))?;
    assert_eq!(updated_psm_public_key, Word::from(new_psm_public_key.to_commitment()));
    let updated_psm_scheme_id = updated_multisig_account
        .storage()
        .get_map_item(AuthMultisigPsm::psm_scheme_id_slot(), Word::from([0u32, 0, 0, 0]))?;
    assert_eq!(
        updated_psm_scheme_id,
        Word::from([new_psm_auth_scheme as u32, 0u32, 0u32, 0u32])
    );

    mock_chain.add_pending_executed_transaction(&update_psm_tx)?;
    mock_chain.prove_next_block()?;

    // Run one tx after key update to ensure the new PSM key is enforced in subsequent auth flows.
    let reenable_salt = Word::from([Felt::new(992); 4]);
    let tx_context_init_reenable = mock_chain
        .build_tx_context(updated_multisig_account.id(), &[], &[])?
        .auth_args(reenable_salt)
        .build()?;
    let tx_summary_reenable = match tx_context_init_reenable.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => anyhow::bail!("expected abort with tx effects: {error}"),
    };
    let reenable_msg = tx_summary_reenable.as_ref().to_commitment();
    let tx_summary_reenable_signing = SigningInputs::TransactionSummary(tx_summary_reenable);
    let reenable_sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_reenable_signing)
        .await?;
    let reenable_sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary_reenable_signing)
        .await?;
    let reenable_psm_sig = new_psm_authenticator
        .get_signature(new_psm_public_key.to_commitment(), &tx_summary_reenable_signing)
        .await?;

    let reenable_tx = mock_chain
        .build_tx_context(updated_multisig_account.id(), &[], &[])?
        .add_signature(public_keys[0].to_commitment(), reenable_msg, reenable_sig_1)
        .add_signature(public_keys[1].to_commitment(), reenable_msg, reenable_sig_2)
        .add_signature(new_psm_public_key.to_commitment(), reenable_msg, reenable_psm_sig)
        .auth_args(reenable_salt)
        .build()?
        .execute()
        .await?;
    updated_multisig_account.apply_delta(reenable_tx.account_delta())?;
    let psm_config = updated_multisig_account
        .storage()
        .get_item(AuthMultisigPsm::psm_config_slot())?;
    assert_eq!(psm_config, Word::from([1u32, 0u32, 0u32, 0u32]));

    mock_chain.add_pending_executed_transaction(&reenable_tx)?;
    mock_chain.prove_next_block()?;

    // Build the next tx summary used for signature generation.
    let next_salt = Word::from([Felt::new(993); 4]);
    let tx_context_init_next = mock_chain
        .build_tx_context(updated_multisig_account.id(), &[], &[])?
        .auth_args(next_salt)
        .build()?;

    let tx_summary_next = match tx_context_init_next.execute().await.unwrap_err() {
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
    let old_psm_sig_next = old_psm_authenticator
        .get_signature(old_psm_public_key.to_commitment(), &tx_summary_next_signing)
        .await?;
    let new_psm_sig_next = new_psm_authenticator
        .get_signature(new_psm_public_key.to_commitment(), &tx_summary_next_signing)
        .await?;

    // Old PSM signature must fail after key update.
    let with_old_psm_result = mock_chain
        .build_tx_context(updated_multisig_account.id(), &[], &[])?
        .add_signature(public_keys[0].to_commitment(), next_msg, next_sig_1.clone())
        .add_signature(public_keys[1].to_commitment(), next_msg, next_sig_2.clone())
        .add_signature(old_psm_public_key.to_commitment(), next_msg, old_psm_sig_next)
        .auth_args(next_salt)
        .build()?
        .execute()
        .await;
    assert!(matches!(with_old_psm_result, Err(TransactionExecutorError::Unauthorized(_))));

    // New PSM signature must pass.
    mock_chain
        .build_tx_context(updated_multisig_account.id(), &[], &[])?
        .add_signature(public_keys[0].to_commitment(), next_msg, next_sig_1)
        .add_signature(public_keys[1].to_commitment(), next_msg, next_sig_2)
        .add_signature(new_psm_public_key.to_commitment(), next_msg, new_psm_sig_next)
        .auth_args(next_salt)
        .build()?
        .execute()
        .await?;

    Ok(())
}
