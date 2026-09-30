//! The transaction-script allowlist: exactly one script may run against the faucet.
//!
//! A network account's transaction-script allowlist decides which scripts a transaction may carry.
//! Left empty it admits none, and left open it would admit any script an attacker cared to write —
//! against an account whose own procedures move supply. The faucet allowlists precisely one entry,
//! the canonical expiration script, which is what a relayer needs to set a transaction's expiry and
//! nothing more.
//!
//! This file checks that from the SOURCE side — the builder's auth component, read as component
//! storage — which is a different vantage point from `f5_network_account_auth.rs`, where the same
//! property is read off a finalized account. Both matter: the builder is where the value is decided,
//! the account is where it is enforced.
//!
//! Three things are asserted:
//!
//! - the tx-script allowlist holds exactly the one expiration root — an extra entry is as much a
//!   failure as a missing one;
//! - the note-script allowlist contains all ten roots independently of the transaction-script
//!   allowlist;
//! - and enforcement actually happens on-chain: the expiration script is admitted and executes,
//!   while an arbitrary no-op script is refused with the allowlist's own error.

mod support;

use core::num::NonZeroU16;
use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::account::{AccountComponent, StorageSlotContent, StorageSlotName};
use miden_protocol::Word;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

/// Reads the non-empty keys of the named MAP storage slot out of an `AccountComponent`. Only
/// non-empty values mark an allowlisted key (matching the MASM `word::eqz` check), so this view
/// agrees with on-chain enforcement.
fn allowlisted_keys(component: &AccountComponent, slot: &StorageSlotName) -> BTreeSet<Word> {
    let content = component
        .storage_slots()
        .iter()
        .find(|s| s.name() == slot)
        .unwrap_or_else(|| panic!("the auth component must carry the {slot} slot"))
        .content();
    let StorageSlotContent::Map(map) = content else {
        panic!("the {slot} slot must be a MAP slot");
    };
    map.entries()
        .filter(|(_key, value)| **value != Word::empty())
        .map(|(key, _value)| key.as_word())
        .collect()
}

/// DIRECT test of the changed function: `auth_component()`'s tx-script allowlist slot must carry
/// EXACTLY the one canonical `ExpirationTransactionScript::script_root()` — nothing more, nothing
/// less.
#[test]
fn auth_component_tx_script_allowlist_is_exactly_the_expiration_root() -> Result<()> {
    let component: AccountComponent =
        XReserveStablecoinBuilder::auth_component(test_fee_parameters(), test_fee_asset_id())
            .map_err(|e| anyhow::anyhow!("auth_component() must build: {e}"))?
            .into_iter()
            .next()
            .expect("the auth component is yielded first");

    let tx_keys = allowlisted_keys(&component, AuthNetworkAccount::allowed_tx_scripts_slot());
    let expected = BTreeSet::from([ExpirationTransactionScript::script_root().as_word()]);
    assert_eq!(
        tx_keys,
        expected,
        "auth_component()'s tx-script allowlist must equal EXACTLY {{ script_root() }} (S12); \
         found {} key(s)",
        tx_keys.len(),
    );
    Ok(())
}

/// The note and transaction allowlists occupy separate slots in the auth component.
#[test]
fn auth_component_note_script_allowlist_is_untouched_by_s12() -> Result<()> {
    let component: AccountComponent =
        XReserveStablecoinBuilder::auth_component(test_fee_parameters(), test_fee_asset_id())
            .map_err(|e| anyhow::anyhow!("auth_component() must build: {e}"))?
            .into_iter()
            .next()
            .expect("the auth component is yielded first");

    let note_keys = allowlisted_keys(&component, AuthNetworkAccount::allowed_note_scripts_slot());
    assert_eq!(
        note_keys.len(),
        10,
        "S12 must leave the note-script allowlist at EXACTLY the 10 roots; found {}",
        note_keys.len(),
    );
    // The exact ten-root set is checked in `f5_network_account_auth.rs`.
    Ok(())
}

/// On-chain enforcement: the canonical expiration script is ADMITTED (clears the allowlist gate and
/// executes) while an arbitrary no-op tx-script is REJECTED.
#[tokio::test]
async fn expiration_is_admitted_and_every_other_tx_script_is_rejected() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;

    // NEGATIVE — a nop tx script is not the expiration root, so the one-root allowlist rejects it.
    let bogus = CodeBuilder::new()
        .compile_tx_script("@transaction_script\npub proc main\n    nop\nend\n")
        .context("compiling the nop probe tx script")?;
    let rejected = pf
        .mock_chain
        .build_transaction(pf.faucet_id)
        .tx_script(bogus)
        .build()
        .context("nop tx-script build")?
        .execute()
        .await;
    assert_transaction_executor_error!(rejected, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    // POSITIVE — the canonical expiration script IS allowlisted, so it CLEARS the allowlist gate.
    // An expiration-only tx changes no account state and consumes no notes, so the kernel then
    // rejects it with the empty-tx epilogue assertion — which is DOWNSTREAM of, and orthogonal to,
    // the tx-script allowlist gate. The precise invariant is that the expiration script is
    // NOT rejected by the tx-script allowlist; a mutation dropping the expiration root flips this
    // back to `ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED` (the RED state), which this catches.
    let expiration = ExpirationTransactionScript::new(NonZeroU16::new(64).expect("64 is non-zero"));
    let admitted = pf
        .mock_chain
        .build_transaction(pf.faucet_id)
        .tx_script(expiration.into())
        .tx_script_args(expiration.tx_script_args())
        .build()
        .context("expiration tx-script build")?
        .execute()
        .await;
    match admitted {
        Ok(_) => {}
        Err(TransactionExecutorError::TransactionProgramExecutionFailed(actual)) => assert!(
            !ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED.matches_execution_error(&actual),
            "the canonical ExpirationTransactionScript must be ADMITTED by the S12 allowlist, but \
             it was rejected by the tx-script allowlist: {actual}",
        ),
        Err(other) => {
            panic!("the expiration tx failed with an unexpected non-execution error: {other}")
        }
    }
    Ok(())
}
