use core::slice;

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountStorageMode, AccountType};
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED,
    ERR_NOTE_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{MockChain, assert_transaction_executor_error};

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a minimal account that uses the [`AuthNetworkAccount`] auth component with the provided
/// allowlist of input-note script roots.
fn build_allowlist_account(allowed_script_roots: Vec<Word>) -> anyhow::Result<Account> {
    Ok(AccountBuilder::new([0; 32])
        .with_auth_component(AuthNetworkAccount::new(allowed_script_roots))
        .with_component(BasicWallet)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .build_existing()?)
}

// TESTS
// ================================================================================================

/// A transaction that executes a tx script must be rejected by `AuthNetworkAccount`, even if the
/// allowlist and input notes are otherwise valid.
#[tokio::test]
async fn test_auth_network_account_rejects_tx_script() -> anyhow::Result<()> {
    let account = build_allowlist_account(Vec::new())?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let tx_script = CodeBuilder::default().compile_tx_script("begin nop end")?;

    let result = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    Ok(())
}

/// A transaction that consumes a mix of allowed and disallowed input notes must be rejected: the
/// allowlist check must fail as soon as any single consumed note is not in the allowlist, even if
/// the others are.
#[tokio::test]
async fn test_auth_network_account_rejects_when_any_note_disallowed() -> anyhow::Result<()> {
    // Build a template note with the default code to learn the "allowed" script root.
    let bootstrap_account = build_allowlist_account(Vec::new())?;
    let template_allowed = NoteBuilder::new(bootstrap_account.id(), &mut rand::rng())
        .build()
        .expect("failed to build template allowed note");
    let allowed_root = template_allowed.script().root();

    // Build the real account with only that one root in the allowlist.
    let account = build_allowlist_account(vec![allowed_root.into()])?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    // Allowed note: uses the default note code so its script root matches `allowed_root`.
    let note_allowed = NoteBuilder::new(account.id(), &mut rand::rng())
        .build()
        .expect("failed to build allowed input note");
    assert_eq!(
        note_allowed.script().root(),
        allowed_root,
        "default-code NoteBuilder should reproduce the allowed script root",
    );

    // Disallowed note: distinct code → distinct script root → not in the allowlist.
    let note_disallowed = NoteBuilder::new(account.id(), &mut rand::rng())
        .code(
            "\
        @note_script
        pub proc main
            push.1 drop
        end
        ",
        )
        .build()
        .expect("failed to build disallowed input note");
    assert_ne!(
        note_disallowed.script().root(),
        allowed_root,
        "disallowed note must have a different script root than the allowed one",
    );

    builder.add_output_note(RawOutputNote::Full(note_allowed.clone()));
    builder.add_output_note(RawOutputNote::Full(note_disallowed.clone()));

    let mock_chain = builder.build()?;

    let input_notes = [note_allowed, note_disallowed];
    let result = mock_chain
        .build_tx_context(account.id(), &[], &input_notes)?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);

    Ok(())
}

/// Consuming an input note whose script root is in the allowlist must succeed.
#[tokio::test]
async fn test_auth_network_account_accepts_allowed_note() -> anyhow::Result<()> {
    // First build a template note so we know its script root, then use that root to configure the
    // account's allowlist.
    let bootstrap_account = build_allowlist_account(Vec::new())?;
    let template_note = NoteBuilder::new(bootstrap_account.id(), &mut rand::rng())
        .build()
        .expect("failed to build template note");
    let allowed_root = template_note.script().root();

    // Now build the real account with the allowlist containing that root.
    let account = build_allowlist_account(vec![allowed_root.into()])?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    // Build a note that uses the same code but is sent from the real account so its script root
    // matches `allowed_root`.
    let note = NoteBuilder::new(account.id(), &mut rand::rng())
        .build()
        .expect("failed to build input note");
    assert_eq!(
        note.script().root(),
        allowed_root,
        "NoteBuilder with default code should produce a fixed script root"
    );
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .build()?
        .execute()
        .await
        .expect("consuming an allowed note should succeed");

    Ok(())
}
