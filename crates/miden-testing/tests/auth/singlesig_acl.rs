use core::slice;

use assert_matches::assert_matches;
use miden_processor::ExecutionError;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountStorage,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::note::Note;
use miden_protocol::testing::storage::MOCK_VALUE_SLOT0;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::AuthSingleSigAcl;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain};
use miden_tx::auth::BasicAuthenticator;
use miden_tx::{AuthenticationError, TransactionExecutorError, TransactionKernelError};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

use crate::prove_and_verify_transaction;

// CONSTANTS
// ================================================================================================

const TX_SCRIPT_NO_TRIGGER: &str = r#"
    use mock::account
    begin
        call.account::account_procedure_1
        drop
    end
    "#;

// HELPER FUNCTIONS
// ================================================================================================

/// Sets up the basic components needed for ACL tests.
/// Returns (account, mock_chain, note).
fn setup_acl_test(
    allow_unauthorized_output_notes: bool,
    allow_unauthorized_input_notes: bool,
    auth_scheme: AuthScheme,
) -> anyhow::Result<(Account, MockChain, Note)> {
    let component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();

    let get_item_proc_root = component
        .get_procedure_root_by_path("mock::account::get_item")
        .expect("get_item procedure should exist");
    let set_item_proc_root = component
        .get_procedure_root_by_path("mock::account::set_item")
        .expect("set_item procedure should exist");
    let auth_trigger_procedures = vec![get_item_proc_root, set_item_proc_root];

    let (auth_component, _authenticator) = Auth::Acl {
        auth_trigger_procedures: auth_trigger_procedures.clone(),
        allow_unauthorized_output_notes,
        allow_unauthorized_input_notes,
        auth_scheme,
    }
    .build_component();

    let account = AccountBuilder::new([0; 32])
        .with_auth_component(auth_component)
        .with_component(component)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    // Create a mock note to consume (needed to make the transaction non-empty)
    let note = NoteBuilder::new(account.id(), &mut rand::rng())
        .build()
        .expect("failed to create mock note");
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mock_chain = builder.build()?;

    Ok((account, mock_chain, note))
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl(#[case] auth_scheme: AuthScheme) -> anyhow::Result<()> {
    let (account, mock_chain, note) = setup_acl_test(false, true, auth_scheme)?;

    // We need to get the authenticator separately for this test
    let component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();

    let get_item_proc_root = component
        .get_procedure_root_by_path("mock::account::get_item")
        .expect("get_item procedure should exist");
    let set_item_proc_root = component
        .get_procedure_root_by_path("mock::account::set_item")
        .expect("set_item procedure should exist");
    let auth_trigger_procedures = vec![get_item_proc_root, set_item_proc_root];

    let (_, authenticator) = Auth::Acl {
        auth_trigger_procedures: auth_trigger_procedures.clone(),
        allow_unauthorized_output_notes: false,
        allow_unauthorized_input_notes: true,
        auth_scheme,
    }
    .build_component();

    let tx_script_with_trigger_1 = format!(
        r#"
        use mock::account

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        begin
            push.MOCK_VALUE_SLOT0[0..2]
            call.account::get_item
            dropw
        end
        "#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
    );

    let tx_script_with_trigger_2 = format!(
        r#"
        use mock::account

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        begin
            push.1.2.3.4
            push.MOCK_VALUE_SLOT0[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
    );

    let tx_script_trigger_1 =
        CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_with_trigger_1)?;

    let tx_script_trigger_2 =
        CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_with_trigger_2)?;

    let tx_script_no_trigger =
        CodeBuilder::with_mock_libraries().compile_tx_script(TX_SCRIPT_NO_TRIGGER)?;

    // Test 1: Transaction WITH authenticator calling trigger procedure 1 (should succeed)
    let tx_context_with_auth_1 = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(authenticator.clone())
        .tx_script(tx_script_trigger_1.clone())
        .build()?;

    let executed_tx_with_auth_1 = tx_context_with_auth_1
        .execute()
        .await
        .expect("trigger 1 with auth should succeed");
    prove_and_verify_transaction(executed_tx_with_auth_1).await?;

    // Test 2: Transaction WITH authenticator calling trigger procedure 2 (should succeed)
    let tx_context_with_auth_2 = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(authenticator)
        .tx_script(tx_script_trigger_2)
        .build()?;

    tx_context_with_auth_2
        .execute()
        .await
        .expect("trigger 2 with auth should succeed");

    // Test 3: Transaction WITHOUT authenticator calling trigger procedure (should fail)
    let tx_context_no_auth = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(None)
        .tx_script(tx_script_trigger_1)
        .build()?;

    let executed_tx_no_auth = tx_context_no_auth.execute().await;

    assert_matches!(executed_tx_no_auth, Err(TransactionExecutorError::MissingAuthenticator));

    // Test 4: Transaction WITHOUT authenticator calling non-trigger procedure (should succeed)
    let tx_context_no_trigger = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(None)
        .tx_script(tx_script_no_trigger)
        .build()?;

    let executed = tx_context_no_trigger
        .execute()
        .await
        .expect("no trigger, no auth should succeed");
    assert_eq!(
        executed.account_delta().nonce_delta(),
        Felt::ZERO,
        "no auth but should still trigger nonce increment"
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_with_allow_unauthorized_output_notes(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (account, mock_chain, note) = setup_acl_test(true, true, auth_scheme)?;

    // Verify the storage layout includes both authorization flags
    let config_slot = account
        .storage()
        .get_item(AuthSingleSigAcl::config_slot())
        .expect("config storage slot access failed");
    // Config Slot should be [num_trigger_procs, allow_unauthorized_output_notes,
    // allow_unauthorized_input_notes, 0] With 2 procedures,
    // allow_unauthorized_output_notes=true, and allow_unauthorized_input_notes=true, this should be
    // [2, 1, 1, 0]
    assert_eq!(config_slot, Word::from([2u32, 1, 1, 0]));

    let tx_script_no_trigger =
        CodeBuilder::with_mock_libraries().compile_tx_script(TX_SCRIPT_NO_TRIGGER)?;

    // Test: Transaction WITHOUT authenticator calling non-trigger procedure (should succeed)
    // This tests that when allow_unauthorized_output_notes=true, transactions without
    // authenticators can still succeed even if they create output notes
    let tx_context_no_trigger = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(None)
        .tx_script(tx_script_no_trigger)
        .build()?;

    let executed = tx_context_no_trigger
        .execute()
        .await
        .expect("no trigger, no auth should succeed");
    assert_eq!(
        executed.account_delta().nonce_delta(),
        Felt::ZERO,
        "no auth but should still trigger nonce increment"
    );

    Ok(())
}

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_with_disallow_unauthorized_input_notes(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (account, mock_chain, note) = setup_acl_test(true, false, auth_scheme)?;

    // Verify the storage layout includes both flags
    let config_slot = account
        .storage()
        .get_item(AuthSingleSigAcl::config_slot())
        .expect("config storage slot access failed");
    // Config Slot should be [num_trigger_procs, allow_unauthorized_output_notes,
    // allow_unauthorized_input_notes, 0] With 2 procedures,
    // allow_unauthorized_output_notes=true, and allow_unauthorized_input_notes=false, this should
    // be [2, 1, 0, 0]
    assert_eq!(config_slot, Word::from([2u32, 1, 0, 0]));

    let tx_script_no_trigger =
        CodeBuilder::with_mock_libraries().compile_tx_script(TX_SCRIPT_NO_TRIGGER)?;

    // Test: Transaction WITHOUT authenticator calling non-trigger procedure but consuming input
    // notes This should FAIL because allow_unauthorized_input_notes=false and we're consuming
    // input notes
    let tx_context_no_auth = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(None)
        .tx_script(tx_script_no_trigger)
        .build()?;

    let executed_tx_no_auth = tx_context_no_auth.execute().await;

    // This should fail with MissingAuthenticator error because input notes are being consumed
    // and allow_unauthorized_input_notes is false
    assert_matches!(executed_tx_no_auth, Err(TransactionExecutorError::MissingAuthenticator));

    Ok(())
}

/// Tests that the singlesig ACL auth procedure reads the initial (pre-rotation) public key
/// when verifying signatures. The transaction script overwrites the public key slot with
/// a bogus value via `set_item` (which also triggers authentication); the test verifies
/// that authentication still succeeds because the auth procedure uses `get_initial_item`
/// to retrieve the original key, rather than `get_item` which would return the
/// overwritten (bogus) value.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_auth_uses_initial_public_key(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (account, mock_chain, note) = setup_acl_test(false, true, auth_scheme)?;

    // Build the authenticator separately (same seed as Auth::Acl uses)
    let component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();

    let get_item_proc_root = component
        .get_procedure_root_by_path("mock::account::get_item")
        .expect("get_item procedure should exist");
    let set_item_proc_root = component
        .get_procedure_root_by_path("mock::account::set_item")
        .expect("set_item procedure should exist");
    let auth_trigger_procedures = vec![get_item_proc_root, set_item_proc_root];

    let (_, authenticator) = Auth::Acl {
        auth_trigger_procedures,
        allow_unauthorized_output_notes: false,
        allow_unauthorized_input_notes: true,
        auth_scheme,
    }
    .build_component();

    // Get the singlesig_acl public key slot name
    let pub_key_slot = AuthSingleSigAcl::public_key_slot();

    // This tx script calls set_item (a trigger procedure) to overwrite the public key slot
    // with a bogus value. This both:
    // 1. Triggers authentication (because set_item is a trigger procedure)
    // 2. Rotates the public key to a bogus value
    //
    // Because the auth procedure uses `get_initial_item`, it reads the original key and
    // signature verification succeeds. If it used `get_item`, it would read the bogus
    // key and fail.
    let tx_script_rotate_key = format!(
        r#"
        use mock::account

        const PUB_KEY_SLOT = word("{pub_key_slot}")

        begin
            # Overwrite the public key slot with a bogus value via set_item (trigger procedure)
            push.99.98.97.96
            push.PUB_KEY_SLOT[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_rotate_key)?;

    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(authenticator)
        .tx_script(tx_script)
        .build()?;

    // This should succeed because the auth procedure reads the INITIAL public key,
    // not the rotated one.
    let executed_tx = tx_context
        .execute()
        .await
        .expect("singlesig_acl auth should use initial public key, not the rotated one");

    prove_and_verify_transaction(executed_tx).await?;

    Ok(())
}

/// Tests the negative scenario: the transaction script rotates the public key to a new
/// *valid* key (key B), and the authenticator signs with that new key. The auth procedure
/// should reject the signature because it reads the *initial* public key (key A), not the
/// rotated one (key B). This proves that even with a valid signature from the new key, the
/// auth procedure correctly uses the initial storage state.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_auth_rejects_rotated_key_signature(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (account, mock_chain, note) = setup_acl_test(false, true, auth_scheme)?;

    // Generate a second valid key pair (key B) using a different seed.
    // The account was built with key A (seed = [0; 32] via Auth::Acl).
    let mut rng_b = ChaCha20Rng::from_seed([1u8; 32]);
    let sec_key_b = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng_b)
        .expect("failed to create second secret key");
    let pub_key_b_commitment: Word = sec_key_b.public_key().to_commitment().into();

    // Create an authenticator that only knows key B (the new key).
    let authenticator_b = BasicAuthenticator::new(&[sec_key_b]);

    // Get the singlesig_acl public key slot name
    let pub_key_slot = AuthSingleSigAcl::public_key_slot();

    // This tx script calls set_item (a trigger procedure) to overwrite the public key slot
    // with key B's valid commitment. The authenticator will sign with key B, but the auth
    // procedure reads the initial key (key A) via `get_initial_item`, so verification
    // should fail.
    let tx_script_rotate_key = format!(
        r#"
        use mock::account

        const PUB_KEY_SLOT = word("{pub_key_slot}")
        const NEW_PUB_KEY = word("{new_pub_key}")

        begin
            # Overwrite the public key slot with key B's valid public key commitment
            push.NEW_PUB_KEY
            push.PUB_KEY_SLOT[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
        new_pub_key = pub_key_b_commitment,
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_rotate_key)?;

    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(Some(authenticator_b))
        .tx_script(tx_script)
        .build()?;

    // This should FAIL because the auth procedure asks the authenticator for a signature
    // against the INITIAL public key (key A), but the authenticator only has key B. The
    // authenticator returns `UnknownPublicKey`, which surfaces as a signature generation
    // failure in the kernel's auth event handler. If the bug were reintroduced, the auth
    // procedure would read the rotated key (key B), the authenticator would happily sign
    // with it, and the transaction would succeed.
    let err = tx_context
        .execute()
        .await
        .expect_err("transaction must fail when auth reads initial key but signer has rotated key");

    let inner_err = match &err {
        TransactionExecutorError::TransactionProgramExecutionFailed(
            ExecutionError::EventError { error, .. },
        ) => error,
        other => panic!("expected EventError from signature generation, got: {other}"),
    };

    let kernel_err = inner_err
        .downcast_ref::<TransactionKernelError>()
        .expect("event error should wrap a TransactionKernelError");
    assert_matches!(
        kernel_err,
        TransactionKernelError::SignatureGenerationFailed(AuthenticationError::UnknownPublicKey(_))
    );

    Ok(())
}
