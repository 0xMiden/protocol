//! Tests for the `AuthNetworkAccountWithFees` component's allowlist gates.
//!
//! The fee-settlement half of the component is covered end to end by the `fee_flow` tests; these
//! pin the tx-script gate, which those flows never exercise.

use core::slice;
use std::collections::BTreeSet;

use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::{RawOutputNote, TransactionScript, TransactionScriptRoot};
use miden_standards::account::access::Authority;
use miden_standards::account::auth::AuthNetworkAccountWithFees;
use miden_standards::account::fees::{FeeManager, FeeScheduleEntry};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{MockChain, assert_transaction_executor_error};

/// A default-code input note whose root the account prices for free and allowlists.
fn build_input_note() -> anyhow::Result<Note> {
    Ok(NoteBuilder::new(ACCOUNT_ID_SENDER.try_into()?, &mut rand::rng()).build()?)
}

/// The canonical kind of tx script a network account would allowlist.
fn expiration_tx_script(delta: u16) -> anyhow::Result<TransactionScript> {
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

    Ok(CodeBuilder::default().compile_tx_script(code)?)
}

/// Builds a fee-managed account pricing `note`'s root for free, with the provided tx-script
/// allowlist.
fn build_account(
    note: &Note,
    allowed_tx_scripts: Vec<TransactionScriptRoot>,
) -> anyhow::Result<Account> {
    let fee_manager = FeeManager::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?)?
        .with_fee(note.script().root(), FeeScheduleEntry::new(0, 0)?);

    let auth =
        AuthNetworkAccountWithFees::with_allowed_notes(BTreeSet::from([note.script().root()]))?
            .with_allowed_tx_scripts(allowed_tx_scripts.into_iter().collect());

    Ok(AccountBuilder::new([0; 32])
        .account_type(AccountType::Public)
        .with_auth_component(auth)
        .with_component(BasicWallet)
        .with_component(Authority::AuthControlled)
        .with_component(fee_manager)
        .build_existing()?)
}

/// A tx script whose root is not allowlisted is rejected before settlement runs. An empty
/// tx-script allowlist rejects every tx script.
#[tokio::test]
async fn rejects_non_allowlisted_tx_script() -> anyhow::Result<()> {
    let note = build_input_note()?;
    let account = build_account(&note, Vec::new())?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mock_chain = builder.build()?;

    let tx_script =
        CodeBuilder::default().compile_tx_script("@transaction_script pub proc main nop end")?;

    let result = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    Ok(())
}

/// An allowlisted tx script runs, and the free-priced note settles without any sponsorship or FEE
/// note.
#[tokio::test]
async fn accepts_allowlisted_tx_script_and_settles_free_note() -> anyhow::Result<()> {
    const DELTA: u16 = 10;
    let tx_script = expiration_tx_script(DELTA)?;
    let note = build_input_note()?;
    let account = build_account(&note, vec![tx_script.root()])?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_tx_context(account.id(), &[], slice::from_ref(&note))?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    let reference_block = executed.block_header().block_num();
    assert_eq!(
        executed.expiration_block_num(),
        reference_block + u32::from(DELTA),
        "the allowlisted expiration script should have set the expiration block number",
    );
    assert_eq!(executed.output_notes().num_notes(), 0, "a free note emits no FEE note");

    Ok(())
}
