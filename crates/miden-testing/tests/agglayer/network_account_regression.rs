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

use miden_agglayer::{
    B2AggNote,
    ExitRoot,
    UpdateGerNote,
    agglayer_library,
    create_existing_bridge_account,
};
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

/// MASM source for an "attack" note script that mirrors B2AGG's bridge entrypoint (a
/// `call.bridge_out::bridge_out`) but resolves to a different script root — the actual exploit
/// shape an attacker would construct to try to slip a near-copy of an allowed note past the
/// allowlist check.
///
/// The bridge entrypoint is wrapped in a never-taken branch: the assembler still resolves the
/// `bridge_out::bridge_out` reference (so the script lexically mirrors B2AGG's bridge interface
/// and the script root necessarily differs), but the call is skipped at runtime so the note
/// script executes successfully and reaches the auth-component allowlist check that this test
/// targets.
const ATTACK_NOTE_CODE: &str = "\
use agglayer::bridge::bridge_out

@note_script
pub proc main
    push.0
    if.true
        call.bridge_out::bridge_out
    end
end
";

/// Asserts that a transaction submitting any tx script against a bridge account fails with
/// [`ERR_NOTE_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED`], even when the transaction also consumes
/// an allowlisted input note (UPDATE_GER). This proves the tx-script check fires regardless of
/// what allowlisted input notes accompany it — the two allowlist checks are independent.
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

    // Allowlisted UPDATE_GER input note: included so the test exercises the case where a real,
    // allowed note is consumed in the same transaction as the rejected tx script. The tx-script
    // rejection must still fire — the note's allowlist status is independent of the tx-script
    // check.
    let ger = ExitRoot::from([0u8; 32]);
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mock_chain = builder.build()?;

    let tx_script = CodeBuilder::default().compile_tx_script("begin nop end")?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[], slice::from_ref(&update_ger_note))?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    Ok(())
}

/// Asserts that a transaction consuming an "attack" input note — one whose script calls the same
/// bridge procedure as the real B2AGG note but differs by a single no-op — fails with
/// [`ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED`]. This exercises the real exploit shape: the
/// bridge enforces an exact script-root allowlist, so a near-copy with even a one-instruction
/// perturbation is rejected even though it would otherwise call the same bridge entrypoint.
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

    let attack_note = NoteBuilder::new(bridge_admin.id(), &mut rand::rng())
        .code(ATTACK_NOTE_CODE)
        .dynamically_linked_libraries([agglayer_library()])
        .build()
        .expect("failed to build attack note");

    // Sanity-check the exploit shape: the attack note must call the same bridge entrypoint as
    // B2AGG (textually mirrored above) but resolve to a different script root.
    assert_ne!(
        attack_note.script().root(),
        B2AggNote::script_root(),
        "attack note must have a different script root than B2AGG",
    );

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
