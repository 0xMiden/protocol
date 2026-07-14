use std::collections::BTreeSet;

use miden_processor::Word;
use miden_protocol::account::{AccountBuilder, AccountId, AccountType};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::memory::{
    CODE_UPGRADE_COMMITMENT_PTR,
    STORAGE_UPGRADE_COMMITMENT_PTR,
};
use miden_standards::account::access::AccessControl;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::extensions::UpgradeManager;
use miden_standards::note::{UpgradeNote, UpgradeNoteStorage};

use crate::TestTransactionBuilder;
use crate::kernel_tests::tx::ExecutionOutputExt;

/// Tests that the standards `UpgradeManager::upgrade` procedure stores the two upgrade commitments
/// in the dedicated kernel memory region.
#[tokio::test]
async fn test_upgrade_manager_stores_commitments_when_authorized() -> anyhow::Result<()> {
    let owner: AccountId = ACCOUNT_ID_SENDER.try_into()?;

    // A network-style account: OwnerControlled authority (via Ownable2Step) + the UpgradeManager
    // procedure, plus the network-account auth component (unused by `execute_code`, but
    // representative).
    let account = AccountBuilder::new([42; 32])
        .with_auth_component(AuthNetworkAccount::with_allowed_notes(BTreeSet::from([
            UpgradeNote::script_root(),
        ]))?)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(UpgradeManager)
        .account_type(AccountType::Public)
        .build_existing()?;

    let code_upgrade_commitment = Word::from([1, 2, 3, 4u32]);
    let storage_upgrade_commitment = Word::from([5, 6, 7, 8u32]);

    // Build the Upgrade note that, when consumed, invokes `upgrade` with the commitments carried in
    // its storage. Its sender is the owner so the authority check on the active note passes.
    let mut rng = RandomCoin::new(Word::empty());
    let storage = UpgradeNoteStorage::new(code_upgrade_commitment, storage_upgrade_commitment);
    let input_note = UpgradeNote::builder()
        .sender(owner)
        .target(account.id())
        .generate_serial_number(&mut rng)
        .storage(storage)
        .build()?
        .into();

    let tx_context = TestTransactionBuilder::new(account)
        .extend_input_notes(vec![input_note])
        .build()?;

    // Execute the input note's script: process the note (making its sender the active note sender)
    // and run its script via `dyncall`, which calls `upgrade::upgrade`.
    let code = r#"
        use miden::tx_kernel_core::prologue
        use miden::tx_kernel_core::note as note_internal

        begin
            exec.prologue::prepare_transaction

            exec.note_internal::prepare_note
            # => [note_script_root_ptr, NOTE_ARGS, pad(11), pad(16)]

            dyncall
            # => [pad(16)]
            dropw dropw dropw dropw
        end
    "#;

    let exec_output = &tx_context.execute_code(code).await?;

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
