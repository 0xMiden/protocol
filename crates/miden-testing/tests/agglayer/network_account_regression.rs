//! Regression tests for issue #2797.
//!
//! Before the `NetworkAccount` auth component existed, the AggLayer bridge was installed with
//! `NoAuth`. Because the transaction kernel's `output_note::create` does not require any specific
//! bridge procedure to appear on the call stack, an attacker could run any transaction that caused
//! a state change against the bridge, emit a MINT note whose metadata sender was therefore the
//! bridge, and have the faucet's owner-only mint policy accept it as owner-authorised.
//!
//! PR #2815 fixes this by swapping `NoAuth` for `NetworkAccount`. The tests below exercise the two
//! rejection paths that together close the forged-MINT attack surface:
//!
//! 1. A transaction script cannot be executed against the bridge.
//! 2. Any consumed input note whose script root is not in the bridge's whitelist is rejected.

extern crate alloc;

use core::slice;

use miden_agglayer::create_existing_bridge_account;
use miden_crypto::rand::FeltRng;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NETWORK_ACCOUNT_NOTE_NOT_WHITELISTED,
    ERR_NETWORK_ACCOUNT_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// The attack in #2797 required the attacker's transaction to finalize against the bridge. The
/// attacker can no longer attach a tx script that drives an output-note creation, because the
/// bridge's `NetworkAccount` auth procedure rejects any transaction that executed a tx script.
#[tokio::test]
async fn bridge_rejects_tx_script_after_2797_fix() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let mock_chain = builder.build()?;

    // An attacker tries to run an arbitrary transaction script against the bridge.
    let tx_script = CodeBuilder::default().compile_tx_script("begin nop end")?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NETWORK_ACCOUNT_TX_SCRIPT_NOT_ALLOWED);

    Ok(())
}

/// The second rejection path: consuming any note not in the bridge whitelist is forbidden, so the
/// attacker cannot finalize a transaction by consuming an arbitrary zero-asset note.
#[tokio::test]
async fn bridge_rejects_non_whitelisted_input_note_after_2797_fix() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Build a note whose script root is not CLAIM, B2AGG, CONFIG_AGG_BRIDGE, or UPDATE_GER.
    let attack_note = NoteBuilder::new(bridge_account.id(), &mut rand::rng())
        .build()
        .expect("failed to build attack note");
    builder.add_output_note(RawOutputNote::Full(attack_note.clone()));

    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[], slice::from_ref(&attack_note))?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NETWORK_ACCOUNT_NOTE_NOT_WHITELISTED);

    Ok(())
}
