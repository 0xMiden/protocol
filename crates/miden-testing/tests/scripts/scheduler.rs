//! Tests for the `Scheduler` timelock: proposing, cancelling and consuming administrative notes
//! for procedures flagged as scheduled.

use std::collections::BTreeMap;

use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountProcedureRoot,
    AccountType,
    RoleSymbol,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::{Note, NoteId};
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::pausable::{Pausable, PausableManager};
use miden_standards::account::access::{AccessControl, Authority, Scheduler, SchedulerManager};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::errors::standards::{
    ERR_SCHEDULER_ALREADY_PROPOSED,
    ERR_SCHEDULER_CANNOT_SCHEDULE_OWN_PROCEDURES,
    ERR_SCHEDULER_NOT_PROPOSED,
    ERR_SCHEDULER_NOT_READY,
    ERR_SENDER_LACKS_ROLE,
};
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

use super::pausable::{
    ADMIN_ID,
    NON_ADMIN_ID,
    build_pause_note,
    build_set_max_supply_note,
    execute_note_on_faucet,
};
use super::rbac::{build_grant_role_note, build_note, role, test_account_id};

const MIN_DELAY_SECS: u32 = 3_600;

// FAUCET BUILDERS
// ================================================================================================

/// Builds an RBAC faucet with `Pausable + PausableManager + Scheduler + SchedulerManager`. `pause`
/// requires a proposal, `cancel` is mapped to `CANCELLER`, everything else falls back to `ADMIN`.
fn add_scheduled_faucet(
    builder: &mut MockChainBuilder,
    admin: AccountId,
    min_delay: u32,
    scheduled: impl IntoIterator<Item = AccountProcedureRoot>,
    seed: u8,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .is_max_supply_mutable(true)
        .build()?;

    let procedure_roles: BTreeMap<AccountProcedureRoot, RoleSymbol> =
        BTreeMap::from([(SchedulerManager::cancel_root(), role("CANCELLER"))]);

    let account_builder = AccountBuilder::new([seed; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_components(AccessControl::Rbac { admin, procedure_roles })
        .with_component(Pausable::unpaused())
        .with_component(PausableManager)
        .with_component(Scheduler::new(min_delay).with_scheduled_procedures(scheduled)?)
        .with_component(SchedulerManager);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// NOTE BUILDERS
// ================================================================================================

fn build_schedule_note(sender: AccountId, note_id: NoteId) -> anyhow::Result<Note> {
    build_note(sender, word_arg_script("schedule", note_id.as_word()))
}

fn build_cancel_note(sender: AccountId, note_id: NoteId) -> anyhow::Result<Note> {
    build_note(sender, word_arg_script("cancel", note_id.as_word()))
}

/// Builds the script of a note calling `proc_name` on the scheduler manager with a single word
/// argument.
fn word_arg_script(proc_name: &str, arg: Word) -> String {
    format!(
        r#"
        use miden::standards::access::scheduler::manager

        @note_script
        pub proc main
            repeat.12 push.0 end
            push.{arg}
            call.manager::{proc_name}
            dropw dropw dropw dropw
        end
        "#
    )
}

fn build_set_min_delay_note(sender: AccountId, min_delay: u32) -> anyhow::Result<Note> {
    build_note(
        sender,
        format!(
            r#"
            use miden::standards::access::scheduler::manager

            @note_script
            pub proc main
                repeat.15 push.0 end
                push.{min_delay}
                call.manager::set_min_delay
                dropw dropw dropw dropw
            end
            "#
        ),
    )
}

fn build_set_procedure_scheduling_note(
    sender: AccountId,
    is_scheduled: bool,
    procedure_root: AccountProcedureRoot,
) -> anyhow::Result<Note> {
    build_note(
        sender,
        format!(
            r#"
            use miden::standards::access::scheduler::manager

            @note_script
            pub proc main
                repeat.11 push.0 end
                push.{procedure_root}
                push.{is_scheduled}
                call.manager::set_procedure_scheduling
                dropw dropw dropw dropw
            end
            "#,
            procedure_root = procedure_root.as_word(),
            is_scheduled = u8::from(is_scheduled),
        ),
    )
}

/// Builds a note that calls `authority::set_procedure_role`, mapping `procedure_root` to `role`.
fn build_set_procedure_role_note(
    sender: AccountId,
    role_symbol: &RoleSymbol,
    procedure_root: AccountProcedureRoot,
) -> anyhow::Result<Note> {
    build_note(
        sender,
        format!(
            r#"
            use miden::standards::access::authority

            @note_script
            pub proc main
                repeat.11 push.0 end
                push.{procedure_root}
                push.{role_symbol}
                call.authority::set_procedure_role
                dropw dropw dropw dropw
            end
            "#,
            procedure_root = procedure_root.as_word(),
            role_symbol = miden_protocol::Felt::from(role_symbol),
        ),
    )
}

// HELPERS
// ================================================================================================

fn ready_at(
    mock_chain: &MockChain,
    faucet_id: AccountId,
    note: &Note,
) -> anyhow::Result<Option<u32>> {
    let account = mock_chain.committed_account(faucet_id)?;
    Ok(Scheduler::try_read_ready_at(account.storage(), note.id())?)
}

fn min_delay(mock_chain: &MockChain, faucet_id: AccountId) -> anyhow::Result<u32> {
    let account = mock_chain.committed_account(faucet_id)?;
    Ok(Scheduler::try_read_min_delay(account.storage())?)
}

fn is_scheduled(
    mock_chain: &MockChain,
    faucet_id: AccountId,
    root: &AccountProcedureRoot,
) -> anyhow::Result<bool> {
    let account = mock_chain.committed_account(faucet_id)?;
    Ok(Scheduler::is_scheduled_procedure(account.storage(), root)?)
}

/// Executes `note` against the faucet and returns the result without applying it.
async fn try_execute(
    mock_chain: &MockChain,
    faucet_id: AccountId,
    note: &Note,
) -> Result<miden_protocol::transaction::ExecutedTransaction, miden_tx::TransactionExecutorError> {
    mock_chain
        .build_transaction(faucet_id)
        .authenticated_input_note(note.id())
        .build()
        .expect("transaction should build")
        .execute()
        .await
}

/// Proposes `note` and advances the chain to its readiness timestamp.
async fn propose_and_wait(
    mock_chain: &mut MockChain,
    faucet_id: AccountId,
    schedule_note: &Note,
    proposed: &Note,
) -> anyhow::Result<()> {
    execute_note_on_faucet(mock_chain, faucet_id, schedule_note).await?;
    let ready = ready_at(mock_chain, faucet_id, proposed)?.expect("note should be proposed");
    mock_chain.prove_next_block_at(ready)?;
    Ok(())
}

// TESTS
// ================================================================================================

#[tokio::test]
async fn scheduled_procedure_requires_a_proposal_and_others_do_not() -> anyhow::Result<()> {
    let admin = *ADMIN_ID;
    let mut builder = MockChain::builder();
    let faucet = add_scheduled_faucet(
        &mut builder,
        admin,
        MIN_DELAY_SECS,
        [PausableManager::pause_root()],
        90,
    )?;

    let pause_note = build_pause_note(admin)?;
    let set_max_supply_note = build_set_max_supply_note(admin, 500_000)?;
    for note in [&pause_note, &set_max_supply_note] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // `pause` is flagged: without a proposal it cannot be consumed, even by ADMIN.
    let result = try_execute(&mock_chain, faucet.id(), &pause_note).await;
    assert_transaction_executor_error!(result, ERR_SCHEDULER_NOT_PROPOSED);

    // `set_max_supply` is not flagged and is unaffected by the scheduler.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &set_max_supply_note).await?;

    Ok(())
}

#[tokio::test]
async fn proposal_becomes_ready_after_the_delay_and_is_consumed_once() -> anyhow::Result<()> {
    let admin = *ADMIN_ID;
    let mut builder = MockChain::builder();
    let faucet = add_scheduled_faucet(
        &mut builder,
        admin,
        MIN_DELAY_SECS,
        [PausableManager::pause_root()],
        91,
    )?;

    let pause_note = build_pause_note(admin)?;
    let schedule_note = build_schedule_note(admin, pause_note.id())?;
    for note in [&pause_note, &schedule_note] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // The proposal records `now + min_delay` and caps the expiration so `now` cannot be stale.
    let proposed_at = mock_chain.latest_block_header().timestamp();
    let executed = try_execute(&mock_chain, faucet.id(), &schedule_note).await?;
    super::assert_default_expiration_limit(&executed);
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    assert_eq!(
        ready_at(&mock_chain, faucet.id(), &pause_note)?,
        Some(proposed_at + MIN_DELAY_SECS)
    );

    // Too early.
    let result = try_execute(&mock_chain, faucet.id(), &pause_note).await;
    assert_transaction_executor_error!(result, ERR_SCHEDULER_NOT_READY);

    // Ready: the note is consumed and the proposal removed.
    mock_chain.prove_next_block_at(proposed_at + MIN_DELAY_SECS)?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;
    assert_eq!(ready_at(&mock_chain, faucet.id(), &pause_note)?, None);

    Ok(())
}

#[tokio::test]
async fn proposing_twice_is_rejected() -> anyhow::Result<()> {
    let admin = *ADMIN_ID;
    let mut builder = MockChain::builder();
    let faucet = add_scheduled_faucet(
        &mut builder,
        admin,
        MIN_DELAY_SECS,
        [PausableManager::pause_root()],
        92,
    )?;

    let pause_note = build_pause_note(admin)?;
    let schedule_note = build_schedule_note(admin, pause_note.id())?;
    let schedule_again = build_schedule_note(admin, pause_note.id())?;
    for note in [&pause_note, &schedule_note, &schedule_again] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &schedule_note).await?;
    let result = try_execute(&mock_chain, faucet.id(), &schedule_again).await;
    assert_transaction_executor_error!(result, ERR_SCHEDULER_ALREADY_PROPOSED);

    Ok(())
}

/// A proposal can be withdrawn by its proposer or by `CANCELLER`, and by nobody else. A cancelled
/// note stays unconsumable until proposed again.
#[tokio::test]
async fn proposer_and_canceller_can_cancel_others_cannot() -> anyhow::Result<()> {
    let admin = *ADMIN_ID;
    let outsider = *NON_ADMIN_ID;
    let canceller = test_account_id(40);

    let mut builder = MockChain::builder();
    let faucet = add_scheduled_faucet(
        &mut builder,
        admin,
        MIN_DELAY_SECS,
        [PausableManager::pause_root()],
        93,
    )?;

    let grant_canceller = build_grant_role_note(admin, &role("CANCELLER"), canceller)?;
    let pause_note = build_pause_note(admin)?;
    let schedule_note = build_schedule_note(admin, pause_note.id())?;
    let outsider_cancel = build_cancel_note(outsider, pause_note.id())?;
    let canceller_cancel = build_cancel_note(canceller, pause_note.id())?;
    let schedule_again = build_schedule_note(admin, pause_note.id())?;
    let proposer_cancel = build_cancel_note(admin, pause_note.id())?;
    for note in [
        &grant_canceller,
        &pause_note,
        &schedule_note,
        &outsider_cancel,
        &canceller_cancel,
        &schedule_again,
        &proposer_cancel,
    ] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &grant_canceller).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &schedule_note).await?;

    // Neither the proposer nor CANCELLER: `cancel` is mapped to CANCELLER, which the outsider
    // lacks.
    let result = try_execute(&mock_chain, faucet.id(), &outsider_cancel).await;
    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);

    // CANCELLER withdraws ADMIN's proposal; the note is unconsumable even after the delay.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &canceller_cancel).await?;
    assert_eq!(ready_at(&mock_chain, faucet.id(), &pause_note)?, None);
    let now = mock_chain.latest_block_header().timestamp();
    mock_chain.prove_next_block_at(now + MIN_DELAY_SECS)?;
    let result = try_execute(&mock_chain, faucet.id(), &pause_note).await;
    assert_transaction_executor_error!(result, ERR_SCHEDULER_NOT_PROPOSED);

    // The proposer withdraws its own proposal without holding CANCELLER.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &schedule_again).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &proposer_cancel).await?;
    assert_eq!(ready_at(&mock_chain, faucet.id(), &pause_note)?, None);

    Ok(())
}

/// Changing the waiting period is itself scheduled, so lowering it waits out the current delay.
#[tokio::test]
async fn set_min_delay_is_itself_scheduled() -> anyhow::Result<()> {
    let admin = *ADMIN_ID;
    let mut builder = MockChain::builder();
    let faucet = add_scheduled_faucet(&mut builder, admin, MIN_DELAY_SECS, [], 94)?;

    let lower_delay = build_set_min_delay_note(admin, 60)?;
    let schedule_note = build_schedule_note(admin, lower_delay.id())?;
    for note in [&lower_delay, &schedule_note] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = try_execute(&mock_chain, faucet.id(), &lower_delay).await;
    assert_transaction_executor_error!(result, ERR_SCHEDULER_NOT_PROPOSED);
    assert_eq!(min_delay(&mock_chain, faucet.id())?, MIN_DELAY_SECS);

    propose_and_wait(&mut mock_chain, faucet.id(), &schedule_note, &lower_delay).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &lower_delay).await?;
    assert_eq!(min_delay(&mock_chain, faucet.id())?, 60);

    Ok(())
}

/// Flags are toggled through scheduled notes; unflagging returns the procedure to immediate
/// execution, and the scheduler's own procedures cannot be flagged.
#[tokio::test]
async fn set_procedure_scheduling_toggles_flags_and_guards_its_own_procedures() -> anyhow::Result<()>
{
    let admin = *ADMIN_ID;
    let mut builder = MockChain::builder();
    let faucet = add_scheduled_faucet(
        &mut builder,
        admin,
        MIN_DELAY_SECS,
        [PausableManager::pause_root()],
        95,
    )?;

    let unflag_pause =
        build_set_procedure_scheduling_note(admin, false, PausableManager::pause_root())?;
    let schedule_unflag = build_schedule_note(admin, unflag_pause.id())?;
    let pause_note = build_pause_note(admin)?;
    let flag_schedule =
        build_set_procedure_scheduling_note(admin, true, SchedulerManager::schedule_root())?;
    let schedule_flag_schedule = build_schedule_note(admin, flag_schedule.id())?;
    for note in [
        &unflag_pause,
        &schedule_unflag,
        &pause_note,
        &flag_schedule,
        &schedule_flag_schedule,
    ] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Unflag `pause` through a scheduled note; afterwards `pause` needs no proposal.
    propose_and_wait(&mut mock_chain, faucet.id(), &schedule_unflag, &unflag_pause).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &unflag_pause).await?;
    assert!(!is_scheduled(&mock_chain, faucet.id(), &PausableManager::pause_root())?);
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    // Flagging `schedule` itself would make proposals unreachable and is refused.
    propose_and_wait(&mut mock_chain, faucet.id(), &schedule_flag_schedule, &flag_schedule).await?;
    let result = try_execute(&mock_chain, faucet.id(), &flag_schedule).await;
    assert_transaction_executor_error!(result, ERR_SCHEDULER_CANNOT_SCHEDULE_OWN_PROCEDURES);

    Ok(())
}

/// `set_procedure_role` bypasses the frozen flag but honours the scheduler when flagged.
#[tokio::test]
async fn set_procedure_role_can_be_scheduled() -> anyhow::Result<()> {
    let admin = *ADMIN_ID;
    let mut builder = MockChain::builder();
    let faucet = add_scheduled_faucet(
        &mut builder,
        admin,
        MIN_DELAY_SECS,
        [Authority::set_procedure_role_root()],
        96,
    )?;

    let reassign =
        build_set_procedure_role_note(admin, &role("PAUSER"), PausableManager::pause_root())?;
    let schedule_note = build_schedule_note(admin, reassign.id())?;
    for note in [&reassign, &schedule_note] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = try_execute(&mock_chain, faucet.id(), &reassign).await;
    assert_transaction_executor_error!(result, ERR_SCHEDULER_NOT_PROPOSED);

    propose_and_wait(&mut mock_chain, faucet.id(), &schedule_note, &reassign).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &reassign).await?;

    Ok(())
}
