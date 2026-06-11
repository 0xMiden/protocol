use core::slice;

use assert_matches::assert_matches;
use miden_processor::ExecutionError;
use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountProcedureRoot,
    AccountStorage,
    AccountType,
};
use miden_protocol::errors::MasmError;
use miden_protocol::note::Note;
use miden_protocol::testing::storage::MOCK_VALUE_SLOT0;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::auth::AuthSingleSigAcl;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::BasicAuthenticator;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

use crate::prove_and_verify_transaction;

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the procedure roots used by the ACL tests, in this order:
///   (`get_item`, `set_item`, `account_procedure_1`).
fn mock_component_proc_roots() -> (AccountProcedureRoot, AccountProcedureRoot, AccountProcedureRoot)
{
    let component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();

    let get_item = component
        .get_procedure_root_by_path("mock::account::get_item")
        .expect("get_item procedure should exist");
    let set_item = component
        .get_procedure_root_by_path("mock::account::set_item")
        .expect("set_item procedure should exist");
    let account_procedure_1 = component
        .get_procedure_root_by_path("mock::account::account_procedure_1")
        .expect("account_procedure_1 procedure should exist");

    (get_item, set_item, account_procedure_1)
}

/// Sets up an account using `AuthSingleSigAcl` with the supplied exempt list, registers it
/// on a fresh mock chain, and returns a note ready to be consumed by the account.
fn setup_acl_test(
    exempt_procedures: Vec<AccountProcedureRoot>,
    auth_scheme: AuthScheme,
) -> anyhow::Result<(Account, MockChain, Note)> {
    let component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();

    let (auth_component, _authenticator) =
        Auth::Acl { exempt_procedures, auth_scheme }.build_component();

    let account = AccountBuilder::new([0; 32])
        .with_auth_component(auth_component)
        .with_component(component)
        .account_type(AccountType::Public)
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

/// Builds an authenticator using the same seed `Auth::Acl` uses internally.
fn build_acl_authenticator(
    exempt_procedures: Vec<AccountProcedureRoot>,
    auth_scheme: AuthScheme,
) -> Option<BasicAuthenticator> {
    let (_, authenticator) = Auth::Acl { exempt_procedures, auth_scheme }.build_component();
    authenticator
}

// TESTS
// ================================================================================================

#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl(#[case] auth_scheme: AuthScheme) -> anyhow::Result<()> {
    let (_get_item, _set_item, account_procedure_1) = mock_component_proc_roots();
    let exempt_procedures = vec![account_procedure_1];
    let (account, mock_chain, note) = setup_acl_test(exempt_procedures.clone(), auth_scheme)?;

    let authenticator = build_acl_authenticator(exempt_procedures, auth_scheme);

    let tx_script_call_get_item = format!(
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

    let tx_script_call_set_item = format!(
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

    let tx_script_get_item =
        CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_call_get_item)?;

    let tx_script_set_item =
        CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_call_set_item)?;

    // Test 1: non-exempt `get_item` WITH authenticator (should succeed).
    let tx_context_get_item_with_auth = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(authenticator.clone())
        .tx_script(tx_script_get_item.clone())
        .build()?;

    let executed_tx_get_item_with_auth = tx_context_get_item_with_auth
        .execute()
        .await
        .expect("get_item with auth should succeed");
    prove_and_verify_transaction(executed_tx_get_item_with_auth).await?;

    // Test 2: non-exempt `set_item` WITH authenticator (should succeed).
    let tx_context_set_item_with_auth = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(authenticator)
        .tx_script(tx_script_set_item)
        .build()?;

    tx_context_set_item_with_auth
        .execute()
        .await
        .expect("set_item with auth should succeed");

    // Test 3: non-exempt `get_item` WITHOUT authenticator (should fail).
    let tx_context_get_item_no_auth = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(None)
        .tx_script(tx_script_get_item)
        .build()?;

    let result_no_auth = tx_context_get_item_no_auth.execute().await;
    assert_matches!(result_no_auth, Err(TransactionExecutorError::MissingAuthenticator));

    Ok(())
}

/// Output notes always require a signature, even when the procedure that produced them is on
/// the exempt list. This is the regression guard for the unconditional output-note gate
/// (condition 3 in the auth logic); without it, an exempt procedure that emits notes would
/// be able to move assets out of the account without authentication.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_output_note_creation_requires_auth_even_when_caller_exempt(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    use miden_processor::crypto::random::RandomCoin;
    use miden_protocol::Hasher;
    use miden_protocol::account::AccountId;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::note::NoteType;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    };
    use miden_protocol::transaction::TransactionScript;
    use miden_standards::account::wallets::BasicWallet;
    use miden_standards::note::P2idNote;
    use miden_standards::tx_script::SendNotesTransactionScript;
    use miden_testing::MockChainBuilder;

    let move_asset_to_note = BasicWallet::move_asset_to_note_root();

    let (auth_component, _authenticator) = Auth::Acl {
        exempt_procedures: vec![move_asset_to_note],
        auth_scheme,
    }
    .build_component();

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
    let starting_asset = FungibleAsset::new(faucet_id, 100)?;

    let account = AccountBuilder::new([0; 32])
        .with_auth_component(auth_component)
        .with_component(BasicWallet)
        .account_type(AccountType::Public)
        .with_assets(core::iter::once(starting_asset.into()))
        .build_existing()?;

    let recipient = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE).unwrap();
    let output_note = P2idNote::create(
        account.id(),
        recipient,
        vec![FungibleAsset::new(faucet_id, 5)?.into()],
        NoteType::Public,
        Default::default(),
        &mut RandomCoin::new(Hasher::hash(b"singlesig-acl-output-note-test")),
    )?;

    let send_note_script = TransactionScript::from(SendNotesTransactionScript::new(
        &account.code_interface(),
        &[output_note.clone().into()],
    )?);

    let mock_chain = MockChainBuilder::with_accounts([account.clone()]).unwrap().build()?;

    let result = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
        .tx_script(send_note_script)
        .authenticator(None)
        .build()?
        .execute()
        .await;

    // Exempting `move_asset_to_note` clears condition 1, so the only thing forcing
    // authentication here is the unconditional output-note check.
    assert_matches!(result, Err(TransactionExecutorError::MissingAuthenticator));

    Ok(())
}

/// Positive exempt-path: a kernel-detected procedure that *is* on the exempt list can be
/// called without a signature, and the input note consumption is vouched for by the exempt
/// call so the input note auth check doesn't fire either. This is the main path the exempt
/// map lookup is supposed to enable.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_exempt_detected_procedure_succeeds_without_auth(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (get_item, _set_item, _account_procedure_1) = mock_component_proc_roots();
    let exempt_procedures = vec![get_item];
    let (account, mock_chain, note) = setup_acl_test(exempt_procedures, auth_scheme)?;

    let tx_script_src = format!(
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
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_src)?;

    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(None)
        .tx_script(tx_script)
        .build()?;

    tx_context
        .execute()
        .await
        .expect("exempt detected procedure without auth should succeed");

    Ok(())
}

/// Isolates condition 2: input note consumption without any detected procedure must
/// force a signature even when no account procedure is called by a tx script. This guards
/// against a regression that drops the input note branch of the MASM `and or`; deleting that
/// block today would let unsigned note consumption sneak through any time the script is
/// inert.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_input_note_consumption_requires_auth_without_exempt(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (account, mock_chain, note) = setup_acl_test(vec![], auth_scheme)?;

    // No tx script - the only side effect of the transaction is consuming the mock note
    // produced by `setup_acl_test`. With an empty exempt list and no exempt procedure
    // detected, the input note gate must trip.
    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(None)
        .build()?;

    let result = tx_context.execute().await;
    assert_matches!(result, Err(TransactionExecutorError::MissingAuthenticator));

    Ok(())
}

/// Empty exempt list is the safe default: any kernel-detected procedure call without a
/// signature must be rejected. Uses `get_item` because it interacts with a kernel-restricted
/// account API (so `was_procedure_called` fires for it).
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_empty_exempt_list_default_denies_unsigned(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (account, mock_chain, note) = setup_acl_test(vec![], auth_scheme)?;

    let tx_script_src = format!(
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
    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_src)?;

    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(None)
        .tx_script(tx_script)
        .build()?;

    let result = tx_context.execute().await;
    assert_matches!(result, Err(TransactionExecutorError::MissingAuthenticator));

    Ok(())
}

/// A transaction that calls a mix of detected exempt and detected non-exempt procedures must
/// still require a signature: a detected exempt call must not suppress the signature
/// requirement for a co-occurring non-exempt call.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_mixed_exempt_and_protected_requires_auth(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (get_item, _set_item, _account_procedure_1) = mock_component_proc_roots();
    let exempt_procedures = vec![get_item];
    let (account, mock_chain, note) = setup_acl_test(exempt_procedures.clone(), auth_scheme)?;

    let authenticator = build_acl_authenticator(exempt_procedures, auth_scheme);

    // Call `get_item` (detected & exempt) and `set_item` (detected & non-exempt) in the same
    // transaction so both branches of the per-procedure check are exercised.
    let tx_script_mixed = format!(
        r#"
        use mock::account

        const MOCK_VALUE_SLOT0 = word("{mock_value_slot0}")

        begin
            push.MOCK_VALUE_SLOT0[0..2]
            call.account::get_item
            dropw
            push.1.2.3.4
            push.MOCK_VALUE_SLOT0[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
        mock_value_slot0 = &*MOCK_VALUE_SLOT0,
    );

    let tx_script_mixed_compiled =
        CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_mixed)?;

    // Without auth: must fail because `get_item` is not exempt.
    let tx_context_no_auth = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(None)
        .tx_script(tx_script_mixed_compiled.clone())
        .build()?;
    let result_no_auth = tx_context_no_auth.execute().await;
    assert_matches!(result_no_auth, Err(TransactionExecutorError::MissingAuthenticator));

    // With auth: must succeed.
    let tx_context_with_auth = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(authenticator)
        .tx_script(tx_script_mixed_compiled)
        .build()?;
    tx_context_with_auth
        .execute()
        .await
        .expect("mixed exempt + non-exempt with auth should succeed");

    Ok(())
}

/// Tests that the singlesig ACL auth procedure reads the initial (pre-rotation) public key
/// when verifying signatures. The transaction script overwrites the public key slot with
/// a bogus value via `set_item` (which is not exempt, so it forces authentication); the
/// test verifies that authentication still succeeds because the auth procedure uses
/// `get_initial_item` to retrieve the original key, rather than `get_item` which would
/// return the overwritten (bogus) value.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_auth_uses_initial_public_key(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_get_item, _set_item, account_procedure_1) = mock_component_proc_roots();
    let exempt_procedures = vec![account_procedure_1];
    let (account, mock_chain, note) = setup_acl_test(exempt_procedures.clone(), auth_scheme)?;

    let authenticator = build_acl_authenticator(exempt_procedures, auth_scheme);

    let pub_key_slot = AuthSingleSigAcl::public_key_slot();
    let tx_script_src = format!(
        r#"
        use mock::account

        const PUB_KEY_SLOT = word("{pub_key_slot}")

        begin
            push.99.98.97.96
            push.PUB_KEY_SLOT[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_src)?;
    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(authenticator)
        .tx_script(tx_script)
        .build()?;

    let executed_tx = tx_context
        .execute()
        .await
        .expect("singlesig_acl auth should use initial public key, not the rotated one");

    prove_and_verify_transaction(executed_tx).await?;

    Ok(())
}

/// Rotated-key negative (ACL): mirrors the singlesig version. `set_item` is not exempt so
/// auth runs; the authenticator signs with sec_b under key A's commitment, and MASM verify
/// must reject the mismatched signature.
#[rstest]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[tokio::test]
async fn test_acl_auth_rejects_rotated_key_signature(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let (_get_item, _set_item, account_procedure_1) = mock_component_proc_roots();
    let exempt_procedures = vec![account_procedure_1];
    let (account, mock_chain, note) = setup_acl_test(exempt_procedures, auth_scheme)?;

    let mut rng_a = ChaCha20Rng::from_seed(Default::default());
    let pub_key_a = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng_a)
        .expect("failed to derive original public key")
        .public_key();

    let mut rng_b = ChaCha20Rng::from_seed([1u8; 32]);
    let sec_key_b = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng_b)
        .expect("failed to create second secret key");
    let pub_key_b_commitment: Word = sec_key_b.public_key().to_commitment().into();

    let authenticator = BasicAuthenticator::from_key_pairs(&[(sec_key_b, pub_key_a)]);

    let pub_key_slot = AuthSingleSigAcl::public_key_slot();
    let tx_script_src = format!(
        r#"
        use mock::account

        const PUB_KEY_SLOT = word("{pub_key_slot}")
        const NEW_PUB_KEY = word("{new_pub_key}")

        begin
            push.NEW_PUB_KEY
            push.PUB_KEY_SLOT[0..2]
            call.account::set_item
            dropw dropw
        end
        "#,
        new_pub_key = pub_key_b_commitment,
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(tx_script_src)?;
    let tx_context = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .authenticator(Some(authenticator))
        .tx_script(tx_script)
        .build()?;

    let result = tx_context.execute().await;

    match auth_scheme {
        AuthScheme::EcdsaK256Keccak => {
            assert_transaction_executor_error!(
                result,
                MasmError::from_static_str("invalid public key commitment")
            );
        },
        AuthScheme::Falcon512Poseidon2 => {
            assert_matches!(
                result,
                Err(TransactionExecutorError::TransactionProgramExecutionFailed(
                    ExecutionError::OperationError {
                        err: miden_processor::operation::OperationError::FailedAssertion { .. },
                        ..
                    }
                ))
            );
        },
        _ => unreachable!("only the two rstest cases are parameterized"),
    }

    Ok(())
}
