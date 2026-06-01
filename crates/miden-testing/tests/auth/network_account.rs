use core::slice;
use std::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::{RawOutputNote, TransactionScript, TransactionScriptRoot};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED,
    ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{MockChain, assert_transaction_executor_error};

// HELPER FUNCTIONS
// ================================================================================================

/// A placeholder script root used when a test needs an [`AuthNetworkAccount`] account whose
/// allowlist contents are not material to the test logic (e.g. for bootstrap accounts that only
/// exist to seed a [`NoteBuilder`]). The constructor rejects empty allowlists, so tests must
/// supply at least one root.
fn placeholder_script_root() -> Word {
    NoteScriptRoot::from_array([1, 0, 0, 0]).into()
}

/// Builds a minimal account that uses the [`AuthNetworkAccount`] auth component with the provided
/// allowlist of input-note script roots and an empty tx-script allowlist.
fn build_allowlist_account(allowed_script_roots: Vec<Word>) -> anyhow::Result<Account> {
    build_account_with_allowlists(allowed_script_roots, Vec::new())
}

/// Builds a minimal account that uses the [`AuthNetworkAccount`] auth component with the provided
/// note-script and tx-script allowlists.
fn build_account_with_allowlists(
    allowed_note_script_roots: Vec<Word>,
    allowed_tx_script_roots: Vec<TransactionScriptRoot>,
) -> anyhow::Result<Account> {
    let auth_component = AuthNetworkAccount::with_allowlist(
        allowed_note_script_roots.into_iter().map(NoteScriptRoot::from_raw).collect(),
    )?
    .with_allowed_tx_scripts(allowed_tx_script_roots.into_iter().collect::<BTreeSet<_>>());

    Ok(AccountBuilder::new([0; 32])
        .with_auth_component(auth_component)
        .with_component(BasicWallet)
        .account_type(AccountType::Public)
        .build_existing()?)
}

/// Compiles a transaction script that sets the transaction expiration delta to `delta`. This is the
/// canonical kind of tx script a network account would allowlist (see protocol issue #3027).
fn expiration_tx_script(delta: u16) -> TransactionScript {
    let code = format!(
        "
        use miden::protocol::tx

        begin
            push.{delta}
            exec.tx::update_expiration_block_delta
        end
        "
    );

    CodeBuilder::default()
        .compile_tx_script(code)
        .expect("expiration tx script should compile")
}

// TESTS
// ================================================================================================

/// A transaction that executes a tx script whose root is not in the tx-script allowlist must be
/// rejected by `AuthNetworkAccount`. An empty tx-script allowlist rejects every tx script.
#[tokio::test]
async fn test_auth_network_account_rejects_tx_script() -> anyhow::Result<()> {
    // Empty tx-script allowlist => no tx script is permitted.
    let account = build_allowlist_account(vec![placeholder_script_root()])?;

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

    assert_transaction_executor_error!(result, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    Ok(())
}

/// A transaction that executes a tx script whose root IS in the tx-script allowlist must succeed,
/// and the script's effect (setting the expiration delta) must be reflected in the transaction.
///
/// The transaction also consumes an allowlisted note, both because a network transaction does so in
/// practice and because the kernel rejects a transaction that neither changes the account state nor
/// consumes a note.
#[tokio::test]
async fn test_auth_network_account_accepts_allowlisted_tx_script() -> anyhow::Result<()> {
    const DELTA: u16 = 10;
    let tx_script = expiration_tx_script(DELTA);

    // Learn the allowed note script root from a template note.
    let bootstrap_account = build_allowlist_account(vec![placeholder_script_root()])?;
    let template_note = NoteBuilder::new(bootstrap_account.id(), &mut rand::rng())
        .build()
        .expect("failed to build template note");
    let allowed_note_root: Word = template_note.script().root().into();

    // Allowlist the note script root and the expiration tx script's root.
    let account = build_account_with_allowlists(vec![allowed_note_root], vec![tx_script.root()])?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let note = NoteBuilder::new(account.id(), &mut rand::rng())
        .build()
        .expect("failed to build input note");
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await
        .expect("executing an allowlisted tx script should succeed");

    // The expiration delta script set the expiration to reference_block + DELTA.
    let reference_block = executed.block_header().block_num();
    assert_eq!(
        executed.expiration_block_num(),
        reference_block + u32::from(DELTA),
        "the allowlisted expiration script should have set the expiration block number",
    );

    Ok(())
}

/// A transaction that runs no tx script must be allowed regardless of the tx-script allowlist
/// contents: the empty-root case short-circuits before any allowlist lookup.
#[tokio::test]
async fn test_auth_network_account_allows_no_tx_script_with_non_empty_allowlist()
-> anyhow::Result<()> {
    // Learn the allowed note script root from a template note.
    let bootstrap_account = build_allowlist_account(vec![placeholder_script_root()])?;
    let template_note = NoteBuilder::new(bootstrap_account.id(), &mut rand::rng())
        .build()
        .expect("failed to build template note");
    let allowed_note_root: Word = template_note.script().root().into();

    // Non-empty tx-script allowlist, but the transaction below runs no tx script at all.
    let account = build_account_with_allowlists(
        vec![allowed_note_root],
        vec![expiration_tx_script(10).root()],
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;

    let note = NoteBuilder::new(account.id(), &mut rand::rng())
        .build()
        .expect("failed to build input note");
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .build()?
        .execute()
        .await
        .expect("a transaction with no tx script should be allowed");

    Ok(())
}

/// A non-empty tx-script allowlist must still reject a tx script whose root is not in it.
#[tokio::test]
async fn test_auth_network_account_rejects_non_allowlisted_tx_script() -> anyhow::Result<()> {
    // Allowlist the expiration script, then try to run a different (non-allowlisted) tx script.
    let allowed_script = expiration_tx_script(10);
    let account = build_account_with_allowlists(
        vec![placeholder_script_root()],
        vec![allowed_script.root()],
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let other_script = CodeBuilder::default().compile_tx_script("begin nop end")?;
    assert_ne!(
        other_script.root(),
        allowed_script.root(),
        "the other script must differ from the allowlisted one",
    );

    let result = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(other_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    Ok(())
}

/// A transaction that consumes a mix of allowed and disallowed input notes must be rejected: the
/// allowlist check must fail as soon as any single consumed note is not in the allowlist, even if
/// the others are.
#[tokio::test]
async fn test_auth_network_account_rejects_when_any_note_disallowed() -> anyhow::Result<()> {
    // Build a template note with the default code to learn the "allowed" script root. The
    // bootstrap account never executes a transaction, so its allowlist contents don't matter.
    let bootstrap_account = build_allowlist_account(vec![placeholder_script_root()])?;
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
    // account's allowlist. The bootstrap account never executes a transaction, so its allowlist
    // contents don't matter.
    let bootstrap_account = build_allowlist_account(vec![placeholder_script_root()])?;
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
