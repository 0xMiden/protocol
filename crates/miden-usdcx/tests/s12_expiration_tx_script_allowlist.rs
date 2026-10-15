//! A new faucet allows only the expiration transaction script, which sets a transaction's expiry.
//!
//! These tests read the builder's allowlist and check it during transaction execution.
//! The note-script allowlist is stored separately and contains twelve scripts.

mod support;

use core::num::NonZeroU16;
use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::Word;
use miden_protocol::account::{AccountComponent, StorageSlotContent, StorageSlotName};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use miden_usdcx::account::xreserve::XReserveStablecoinBuilder;
use support::*;

/// Reads allowlist keys whose stored value is nonzero.
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

/// The builder allows only the expiration transaction script.
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
        12,
        "S12 must leave the note-script allowlist at EXACTLY the 12 roots; found {}",
        note_keys.len(),
    );
    // The exact twelve-root set is checked in `f5_network_account_auth.rs`.
    Ok(())
}

/// The expiration script passes the allowlist check; an unlisted no-op script does not.
#[tokio::test]
async fn expiration_is_admitted_and_every_other_tx_script_is_rejected() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;

    // A no-op script is not allowlisted.
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

    // The expiration script must pass the allowlist check. The transaction may still fail
    // because it consumes no notes and changes no state.
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
        Ok(_) => {},
        Err(TransactionExecutorError::TransactionProgramExecutionFailed(actual)) => assert!(
            !ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED.matches_execution_error(&actual),
            "the canonical ExpirationTransactionScript must be ADMITTED by the S12 allowlist, but \
             it was rejected by the tx-script allowlist: {actual}",
        ),
        Err(other) => {
            panic!("the expiration tx failed with an unexpected non-execution error: {other}")
        },
    }
    Ok(())
}
