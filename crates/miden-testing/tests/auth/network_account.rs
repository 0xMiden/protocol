use core::num::NonZeroU16;
use core::slice;
use std::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::note::{Note, NoteScriptRoot};
use miden_protocol::testing::account_id::{ACCOUNT_ID_FEE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::{RawOutputNote, TransactionScript, TransactionScriptRoot};
use miden_standards::account::access::AccessControl;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::{ConstantFeePolicy, FeeManager};
use miden_standards::account::upgrade::UpgradeManager;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED,
    ERR_SENDER_NOT_OWNER,
    ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::{MockChain, assert_transaction_executor_error};
use rstest::rstest;

// HELPER FUNCTIONS
// ================================================================================================

/// A placeholder note script root used when a test needs an [`AuthNetworkAccount`] account whose
/// allowlist contents are not material to the test logic (e.g. an account that never consumes a
/// note). The constructor rejects empty allowlists, so tests must supply at least one root.
fn placeholder_script_root() -> Word {
    NoteScriptRoot::from_array([1, 0, 0, 0]).into()
}

/// Builds a minimal account that uses the [`AuthNetworkAccount`] auth component with the provided
/// allowlist of input-note script roots and an empty tx-script allowlist.
fn build_allowlist_account(allowed_script_roots: Vec<Word>) -> anyhow::Result<Account> {
    build_account_with_allowlists(allowed_script_roots, Vec::new())
}

/// A zero-fee `FeeManager` (empty `ConstantFeePolicy`) giving a network account an active fee
/// policy for `collect_sponsored_fees`. With an empty schedule every note prices to zero, so
/// collection is a no-op on these fee-free chains.
fn zero_fee_manager() -> anyhow::Result<FeeManager> {
    Ok(FeeManager::builder()
        .active_fee_policy(ConstantFeePolicy::new(ACCOUNT_ID_FEE_FAUCET.try_into()?).into())
        .build())
}

/// Builds a minimal account that uses the [`AuthNetworkAccount`] auth component with the provided
/// note-script and tx-script allowlists.
fn build_account_with_allowlists(
    allowed_note_script_roots: Vec<Word>,
    allowed_tx_script_roots: Vec<TransactionScriptRoot>,
) -> anyhow::Result<Account> {
    let auth_component = AuthNetworkAccount::with_allowed_notes(
        allowed_note_script_roots.into_iter().map(NoteScriptRoot::from_raw).collect(),
    )?
    .with_allowed_tx_scripts(allowed_tx_script_roots.into_iter().collect::<BTreeSet<_>>());

    Ok(AccountBuilder::new([0; 32])
        .with_auth_component(auth_component)
        .with_component(BasicWallet)
        .with_components(zero_fee_manager()?)
        .account_type(AccountType::Public)
        .build_existing()?)
}

/// Builds a default-code input note from a fixed sender. The note's script root is independent of
/// its sender, so this is a convenient way to obtain a note whose root can be allowlisted.
fn build_input_note() -> anyhow::Result<Note> {
    Ok(NoteBuilder::new(ACCOUNT_ID_SENDER.try_into()?, &mut rand::rng()).build()?)
}

/// Compiles a transaction script that sets the transaction expiration delta to `delta`. This is the
/// canonical kind of tx script a network account would allowlist (see protocol issue #3027).
fn expiration_tx_script(delta: u16) -> TransactionScript {
    let code = format!(
        "
        use miden::protocol::tx

        @transaction_script
        pub proc main
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

    let tx_script =
        CodeBuilder::default().compile_tx_script("@transaction_script pub proc main nop end")?;

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

    let mut builder = MockChain::builder();
    let note = build_input_note()?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    // Allowlist the note script root and the expiration tx script's root.
    let account =
        build_account_with_allowlists(vec![note.script().root().into()], vec![tx_script.root()])?;
    builder.add_account(account.clone())?;

    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

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
    let mut builder = MockChain::builder();
    let note = build_input_note()?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    // Non-empty tx-script allowlist, but the transaction below runs no tx script at all.
    let account = build_account_with_allowlists(
        vec![note.script().root().into()],
        vec![expiration_tx_script(10).root()],
    )?;
    builder.add_account(account.clone())?;

    let mock_chain = builder.build()?;

    mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .build()?
        .execute()
        .await?;

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

    let other_script =
        CodeBuilder::default().compile_tx_script("@transaction_script pub proc main nop end")?;
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

/// Allowlisting several *distinct* tx-script roots must let a transaction run any one of them. Both
/// hardcoded expiration scripts (delta 10 and delta 30) are allowlisted, and running either one
/// end-to-end succeeds and produces the corresponding expiration block number.
#[rstest]
#[case(10)]
#[case(30)]
#[tokio::test]
async fn test_auth_network_account_accepts_any_of_multiple_allowlisted_roots(
    #[case] delta: u16,
) -> anyhow::Result<()> {
    let script_10 = expiration_tx_script(10);
    let script_30 = expiration_tx_script(30);
    let tx_script = expiration_tx_script(delta);

    let mut builder = MockChain::builder();
    let note = build_input_note()?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    // Allowlist the note root and both distinct expiration script roots.
    let account = build_account_with_allowlists(
        vec![note.script().root().into()],
        vec![script_10.root(), script_30.root()],
    )?;
    builder.add_account(account.clone())?;

    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    assert_eq!(
        executed.expiration_block_num(),
        executed.block_header().block_num() + u32::from(delta),
        "running one of several allowlisted scripts should set the expiration to reference + delta",
    );

    Ok(())
}

/// An allowlisted tx script may read caller-supplied `TX_SCRIPT_ARGS`: the allowlist pins the
/// script's *code* (its root), not its arguments. Here a single expiration-delta script that takes
/// the delta from `TX_SCRIPT_ARGS` is allowlisted, and transactions supplying different arbitrary
/// deltas all run end-to-end and produce the corresponding expiration block number.
///
/// This is the input-dependent pattern the type docs caution against in general; it is acceptable
/// for the expiration delta specifically because the delta only bounds the inclusion window of the
/// caller's own transaction (it cannot touch account nonce, state, or assets) and the kernel
/// hard-caps it at `0xFFFF` blocks. Network accounts that want this (e.g. for the ntx-builder) can
/// allowlist such a script knowingly.
#[rstest]
#[case(10)]
#[case(30)]
#[case(u16::MAX)]
#[tokio::test]
async fn test_auth_network_account_accepts_allowlisted_tx_script_with_caller_args(
    #[case] delta: u16,
) -> anyhow::Result<()> {
    // Use the canonical, args-driven expiration script from miden-standards - the same script the
    // node allowlists - so this exercises the standardized root rather than a local copy.
    let script = ExpirationTransactionScript::new(
        NonZeroU16::new(delta).expect("rstest delta cases are non-zero"),
    );

    let mut builder = MockChain::builder();
    let note = build_input_note()?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    // Allowlist the note root and the single caller-parameterized expiration script.
    let account = build_account_with_allowlists(
        vec![note.script().root().into()],
        vec![ExpirationTransactionScript::script_root()],
    )?;
    builder.add_account(account.clone())?;

    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .tx_script(script.into())
        .tx_script_args(script.tx_script_args())
        .build()?
        .execute()
        .await?;

    assert_eq!(
        executed.expiration_block_num(),
        executed.block_header().block_num() + u32::from(delta),
        "the caller-supplied expiration delta should be applied",
    );

    Ok(())
}

/// A transaction that consumes a mix of allowed and disallowed input notes must be rejected: the
/// allowlist check must fail as soon as any single consumed note is not in the allowlist, even if
/// the others are.
#[tokio::test]
async fn test_auth_network_account_rejects_when_any_note_disallowed() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Allowed note: uses the default note code, so its script root is the one we allowlist.
    let note_allowed = build_input_note()?;
    let account = build_allowlist_account(vec![note_allowed.script().root().into()])?;
    builder.add_account(account.clone())?;

    // Disallowed note: distinct code => distinct script root => not in the allowlist.
    let note_disallowed = NoteBuilder::new(ACCOUNT_ID_SENDER.try_into()?, &mut rand::rng())
        .code(
            "\
        @note_script
        pub proc main
            push.1 drop
        end
        ",
        )
        .build()?;
    assert_ne!(
        note_disallowed.script().root(),
        note_allowed.script().root(),
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
    let mut builder = MockChain::builder();

    let note = build_input_note()?;
    let account = build_allowlist_account(vec![note.script().root().into()])?;
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .build()?
        .execute()
        .await?;

    Ok(())
}

// UPGRADE NOTE
// ================================================================================================

/// Builds an upgradeable network account: the [`AuthNetworkAccount`] auth component with the given
/// note-script allowlist, `OwnerControlled` authority (via [`AccessControl::Ownable2Step`]) so the
/// `UpgradeManager::upgrade` procedure authorizes the note sender against `owner`, plus the
/// [`UpgradeManager`] procedure itself.
fn build_upgradeable_network_account(
    owner: AccountId,
    allowed_note_script_roots: Vec<Word>,
) -> anyhow::Result<Account> {
    let auth_component = AuthNetworkAccount::with_allowed_notes(
        allowed_note_script_roots.into_iter().map(NoteScriptRoot::from_raw).collect(),
    )?;

    Ok(AccountBuilder::new([7; 32])
        .with_auth_component(auth_component)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(UpgradeManager)
        .with_component(BasicWallet)
        .with_components(zero_fee_manager()?)
        .account_type(AccountType::Public)
        .build_existing()?)
}

/// Builds an ad-hoc note from `sender` whose script calls the `UpgradeManager::upgrade` procedure
/// with two fixed commitment words pushed directly on the stack, matching the procedure layout
/// `[CODE_UPGRADE_COMMITMENT, STORAGE_UPGRADE_COMMITMENT, pad(8)]`.
///
/// The commitment values are immaterial here; these tests only exercise the allowlist and authority
/// paths, not the stored commitments. The script root is independent of `sender`, so it can be
/// allowlisted regardless of who sends the note.
fn build_upgrade_note(sender: AccountId) -> anyhow::Result<Note> {
    let script = "
        use miden::standards::account_upgrade

        @note_script
        pub proc main
            padw padw
            push.5.6.7.8
            push.1.2.3.4
            call.account_upgrade::upgrade
            dropw dropw dropw dropw
        end
    ";
    Ok(NoteBuilder::new(sender, &mut rand::rng()).code(script).build()?)
}

/// Consuming an allowlisted upgrade note sent by the owner runs the full note -> `upgrade` ->
/// `assert_authorized` -> kernel path without panicking.
#[tokio::test]
async fn test_auth_network_account_accepts_authorized_upgrade_note() -> anyhow::Result<()> {
    let owner: AccountId = ACCOUNT_ID_SENDER.try_into()?;
    let note = build_upgrade_note(owner)?;
    let account = build_upgradeable_network_account(owner, vec![note.script().root().into()])?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// An upgrade note whose script root is not in the allowlist must be rejected by the auth
/// component, even though its sender is the owner.
#[tokio::test]
async fn test_auth_network_account_rejects_non_allowlisted_upgrade_note() -> anyhow::Result<()> {
    let owner: AccountId = ACCOUNT_ID_SENDER.try_into()?;
    // Allowlist a placeholder root, not the upgrade note root.
    let account = build_upgradeable_network_account(owner, vec![placeholder_script_root()])?;
    let note = build_upgrade_note(owner)?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);

    Ok(())
}

/// An allowlisted upgrade note whose sender is not the owner must be rejected: the `upgrade`
/// procedure's `assert_authorized` owner check fails while the note script runs.
#[tokio::test]
async fn test_auth_network_account_rejects_unauthorized_upgrade_note() -> anyhow::Result<()> {
    let owner: AccountId = ACCOUNT_ID_SENDER.try_into()?;

    // The note sender is not the owner, so the OwnerControlled authority check must reject it.
    let not_owner = AccountId::builder().account_type(AccountType::Public).build_with_seed([3; 32]);
    let note = build_upgrade_note(not_owner)?;
    let account = build_upgradeable_network_account(owner, vec![note.script().root().into()])?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}
