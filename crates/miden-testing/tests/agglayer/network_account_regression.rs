//! Tests that the AggLayer bridge's [`AuthNetworkAccount`] component enforces both rejection
//! paths required to keep its metadata sender from being attached to attacker-authored output
//! notes:
//!
//! 1. The bridge rejects any transaction that executes a tx script.
//! 2. The bridge rejects any input note whose script root is not in
//!    [`miden_agglayer::AggLayerBridge::allowed_notes`].
//!
//! [`AuthNetworkAccount`]: miden_standards::account::auth::AuthNetworkAccount

extern crate alloc;

use core::slice;

use miden_agglayer::create_existing_bridge_account;
use miden_crypto::rand::FeltRng;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED,
    ERR_NOTE_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// Asserts that a transaction submitting any tx script against a bridge account fails with
/// [`ERR_NOTE_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED`].
#[tokio::test]
async fn bridge_rejects_tx_script() -> anyhow::Result<()> {
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

    let tx_script = CodeBuilder::default().compile_tx_script("begin nop end")?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    Ok(())
}

/// Asserts that a transaction consuming an input note whose script root is outside the bridge
/// allowlist (CLAIM, B2AGG, CONFIG_AGG_BRIDGE, UPDATE_GER) fails with
/// [`ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED`].
#[tokio::test]
async fn bridge_rejects_non_allowlisted_input_note() -> anyhow::Result<()> {
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

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);

    Ok(())
}
