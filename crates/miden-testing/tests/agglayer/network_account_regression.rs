//! Tests that the AggLayer bridge's and AggLayer faucet's [`AuthNetworkAccount`] components
//! enforce both rejection paths required to keep their metadata senders from being attached to
//! attacker-authored output notes:
//!
//! 1. The account rejects any transaction that executes a tx script.
//! 2. The account rejects any input note whose script root is not in its
//!    [`allowed_notes`](miden_agglayer::AggLayerBridge::allowed_notes) /
//!    [`allowed_notes`](miden_agglayer::AggLayerFaucet::allowed_notes) set.
//!
//! [`AuthNetworkAccount`]: miden_standards::account::auth::AuthNetworkAccount

use core::slice;

use miden_agglayer::{
    ExitRoot,
    UpdateGerNote,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_crypto::rand::FeltRng;
use miden_protocol::Felt;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED,
    ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// Attack note script: trivial body whose root falls outside the bridge's allowlist.
const ATTACK_NOTE_CODE: &str = "\
@note_script
pub proc main
    push.0 drop
end
";

/// Asserts that a transaction submitting any tx script against a bridge account fails with
/// [`ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED`], even when the transaction also consumes
/// an allowlisted input note (UPDATE_GER). This proves the tx-script check fires regardless of
/// what allowlisted input notes accompany it — the two allowlist checks are independent.
#[tokio::test]
async fn bridge_rejects_tx_script() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_injector.id(),
        ger_remover.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Allowlisted UPDATE_GER input note: included so the test exercises the case where a real,
    // allowed note is consumed in the same transaction as the rejected tx script. The tx-script
    // rejection must still fire — the note's allowlist status is independent of the tx-script
    // check.
    let ger = ExitRoot::from([0u8; 32]);
    let update_ger_note =
        UpdateGerNote::create(ger, ger_injector.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mock_chain = builder.build()?;

    let tx_script = CodeBuilder::default().compile_tx_script("begin nop end")?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[], slice::from_ref(&update_ger_note))?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    Ok(())
}

/// Asserts that a transaction consuming an input note whose script root falls outside the
/// bridge's allowlist (CLAIM, B2AGG, CONFIG_AGG_BRIDGE, UPDATE_GER) fails with
/// [`ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED`].
#[tokio::test]
async fn bridge_rejects_non_allowlisted_input_note() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_injector.id(),
        ger_remover.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let attack_note = NoteBuilder::new(bridge_admin.id(), &mut rand::rng())
        .code(ATTACK_NOTE_CODE)
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

/// Asserts that a transaction submitting any tx script against an AggLayer faucet account fails
/// with [`ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED`]. Symmetric to
/// [`bridge_rejects_tx_script`]: the faucet's [`AuthNetworkAccount`] allowlist (MINT, BURN) must
/// reject every tx script, regardless of which input notes (if any) accompany it.
///
/// [`AuthNetworkAccount`]: miden_standards::account::auth::AuthNetworkAccount
#[tokio::test]
async fn faucet_rejects_tx_script() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // The bridge_account_id is wired into the faucet at creation time as the registered owner;
    // we never execute against the bridge in this test, so a placeholder admin wallet is enough.
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        "TEST",
        8,
        Felt::new(1_000_000).unwrap(),
        Felt::ZERO,
        bridge_admin.id(),
    );
    builder.add_account(faucet.clone())?;

    let mock_chain = builder.build()?;

    let tx_script = CodeBuilder::default().compile_tx_script("begin nop end")?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    Ok(())
}

/// Asserts that a transaction consuming an input note whose script root falls outside the
/// faucet's allowlist (MINT, BURN) fails with [`ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED`].
/// Symmetric to [`bridge_rejects_non_allowlisted_input_note`]: the faucet's
/// [`AuthNetworkAccount`] component must reject any non-MINT/BURN input note.
///
/// [`AuthNetworkAccount`]: miden_standards::account::auth::AuthNetworkAccount
#[tokio::test]
async fn faucet_rejects_non_allowlisted_input_note() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        "TEST",
        8,
        Felt::new(1_000_000).unwrap(),
        Felt::ZERO,
        bridge_admin.id(),
    );
    builder.add_account(faucet.clone())?;

    let attack_note = NoteBuilder::new(bridge_admin.id(), &mut rand::rng())
        .code(ATTACK_NOTE_CODE)
        .build()
        .expect("failed to build attack note");

    builder.add_output_note(RawOutputNote::Full(attack_note.clone()));

    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[], slice::from_ref(&attack_note))?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);

    Ok(())
}
