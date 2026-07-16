use miden_processor::Word;
use miden_protocol::account::{AccountBuilder, AccountId, AccountType};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteScriptRoot};
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::memory::{
    CODE_UPGRADE_COMMITMENT_PTR,
    STORAGE_UPGRADE_COMMITMENT_PTR,
};
use miden_standards::account::access::AccessControl;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::upgrade::UpgradeManager;
use miden_standards::testing::note::NoteBuilder;

use crate::TestTransactionBuilder;
use crate::kernel_tests::tx::ExecutionOutputExt;

/// Builds an ad-hoc note authored by `sender`. It only serves to set the active note sender
/// (against which `UpgradeManager::upgrade` authorizes); its script is never executed by the
/// harness below.
fn build_note(sender: AccountId) -> anyhow::Result<Note> {
    let mut rng = RandomCoin::new(Word::empty());
    Ok(NoteBuilder::new(sender, &mut rng).build()?)
}

/// Tests that the standards `UpgradeManager::upgrade` procedure stores the two upgrade commitments
/// in the dedicated kernel memory region.
#[tokio::test]
async fn test_upgrade_manager_stores_commitments_when_authorized() -> anyhow::Result<()> {
    let owner: AccountId = ACCOUNT_ID_SENDER.try_into()?;

    // A network-style account: OwnerControlled authority (via Ownable2Step) + the UpgradeManager
    // procedure, plus the network-account auth component (unused by `execute_code`, but
    // representative).
    let account = AccountBuilder::new([42; 32])
        .with_auth_component(AuthNetworkAccount::with_allowed_notes(
            [placeholder_script_root()].into_iter().collect(),
        )?)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(UpgradeManager)
        .account_type(AccountType::Public)
        .build_existing()?;

    // An active note whose sender is the owner, so the authority check in `upgrade` passes.
    let input_note = build_note(owner)?;

    let tx_context = TestTransactionBuilder::new(account)
        .extend_input_notes(vec![input_note])
        .build()?;

    let code_upgrade_commitment = Word::from([1, 2, 3, 4u32]);
    let storage_upgrade_commitment = Word::from([5, 6, 7, 8u32]);

    // Set the active note (making its sender the active note sender), then invoke the standards
    // `upgrade` procedure directly with the two commitments carried on the stack.
    let code = format!(
        r#"
        use miden::tx_kernel_core::prologue
        use miden::tx_kernel_core::note as note_internal
        use miden::standards::account_upgrade

        begin
            exec.prologue::prepare_transaction

            exec.note_internal::prepare_note
            # => [note_script_root_ptr, NOTE_ARGS, pad(11), pad(16)]
            dropw dropw dropw dropw
            # => [pad(16)]

            push.{storage_upgrade_commitment}
            push.{code_upgrade_commitment}
            # => [CODE_UPGRADE_COMMITMENT, STORAGE_UPGRADE_COMMITMENT, pad(8)]

            call.account_upgrade::upgrade
            # => [pad(16)]
            dropw dropw dropw dropw
        end
        "#,
        code_upgrade_commitment = &code_upgrade_commitment,
        storage_upgrade_commitment = &storage_upgrade_commitment,
    );

    let exec_output = &tx_context.execute_code(&code).await?;

    assert_eq!(
        exec_output.get_kernel_mem_word(CODE_UPGRADE_COMMITMENT_PTR),
        code_upgrade_commitment,
        "code upgrade commitment should be stored in kernel memory"
    );
    assert_eq!(
        exec_output.get_kernel_mem_word(STORAGE_UPGRADE_COMMITMENT_PTR),
        storage_upgrade_commitment,
        "storage upgrade commitment should be stored in kernel memory"
    );

    Ok(())
}

/// A placeholder note-script root: the account's allowlist must be non-empty, but its contents are
/// immaterial to this test (the auth epilogue that enforces the allowlist is not run by
/// `execute_code`).
fn placeholder_script_root() -> NoteScriptRoot {
    NoteScriptRoot::from_array([1, 0, 0, 0])
}
