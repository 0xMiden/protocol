use core::slice;

use assert_matches::assert_matches;
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
use miden_protocol::transaction::OutputNote;
use miden_protocol::{Felt, FieldElement, Word};
use miden_standards::account::auth::AuthEcdsaK256KeccakAcl;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain};
use miden_tx::TransactionExecutorError;

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

/// Sets up the basic components needed for ECDSA ACL tests.
/// Returns (account, mock_chain, note).
fn setup_ecdsa_acl_test(
    allow_unauthorized_output_notes: bool,
    allow_unauthorized_input_notes: bool,
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

    let (auth_component, _authenticator) = Auth::EcdsaK256KeccakAcl {
        auth_trigger_procedures: auth_trigger_procedures.clone(),
        allow_unauthorized_output_notes,
        allow_unauthorized_input_notes,
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
    builder.add_output_note(OutputNote::Full(note.clone()));
    let mock_chain = builder.build()?;

    Ok((account, mock_chain, note))
}

#[tokio::test]
async fn test_ecdsa_acl() -> anyhow::Result<()> {
    let (account, mock_chain, note) = setup_ecdsa_acl_test(false, true)?;

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

    let (_, authenticator) = Auth::EcdsaK256KeccakAcl {
        auth_trigger_procedures: auth_trigger_procedures.clone(),
        allow_unauthorized_output_notes: false,
        allow_unauthorized_input_notes: true,
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
    prove_and_verify_transaction(executed_tx_with_auth_1)?;

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

#[tokio::test]
async fn test_ecdsa_acl_with_allow_unauthorized_output_notes() -> anyhow::Result<()> {
    let (account, mock_chain, note) = setup_ecdsa_acl_test(true, true)?;

    // Verify the storage layout includes both authorization flags
    let config_slot = account
        .storage()
        .get_item(AuthEcdsaK256KeccakAcl::config_slot())
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

#[tokio::test]
async fn test_ecdsa_acl_with_disallow_unauthorized_input_notes() -> anyhow::Result<()> {
    let (account, mock_chain, note) = setup_ecdsa_acl_test(true, false)?;

    // Verify the storage layout includes both flags
    let config_slot = account
        .storage()
        .get_item(AuthEcdsaK256KeccakAcl::config_slot())
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
