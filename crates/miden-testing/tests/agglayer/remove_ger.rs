extern crate alloc;

use miden_agglayer::errors::{ERR_GER_NOT_FOUND, ERR_SENDER_NOT_GER_REMOVER};
use miden_agglayer::{
    AggLayerBridge,
    ExitRoot,
    RemoveGerNote,
    UpdateGerNote,
    create_existing_bridge_account,
};
use miden_core_lib::handlers::keccak256::KeccakPreimage;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::transaction::RawOutputNote;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

const GER_BYTES: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];

/// Tests the happy path: register a GER via UPDATE_GER, then remove it via REMOVE_GER.
/// Verifies that the GER is no longer registered and that the removed-GER hash chain
/// advanced to `keccak256(0...0 || ger)`.
#[tokio::test]
async fn remove_ger_note_clears_storage_and_updates_chain() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_manager.id(),
        ger_remover.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // STEP 1: Register the GER via UPDATE_GER
    let ger = ExitRoot::from(GER_BYTES);
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    // STEP 2: Remove the GER via REMOVE_GER (sent by the GER remover)
    let remove_ger_note =
        RemoveGerNote::create(ger, ger_remover.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(remove_ger_note.clone()));

    let mut mock_chain = builder.build()?;

    let update_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_executed = update_tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&update_executed)?;
    mock_chain.prove_next_block()?;

    let remove_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[remove_ger_note.id()], &[])?
        .build()?;
    let remove_executed = remove_tx_context.execute().await?;

    // VERIFY GER IS NO LONGER REGISTERED AND CHAIN HASH ADVANCED
    let mut updated_bridge_account = bridge_account.clone();
    updated_bridge_account.apply_delta(update_executed.account_delta())?;
    updated_bridge_account.apply_delta(remove_executed.account_delta())?;

    let is_registered = AggLayerBridge::is_ger_registered(ger, updated_bridge_account.clone())?;
    assert!(!is_registered, "GER should have been removed from the bridge account");

    // Expected chain = keccak256(0...0 || ger_bytes)
    let mut preimage = [0u8; 64];
    preimage[32..].copy_from_slice(&GER_BYTES);
    let expected_chain_felts: alloc::vec::Vec<_> =
        KeccakPreimage::new(preimage.to_vec()).digest().as_ref().to_vec();
    let mut expected_chain_bytes = [0u8; 32];
    for (i, felt) in expected_chain_felts.iter().enumerate() {
        let limb = u32::try_from(felt.as_canonical_u64()).expect("felt fits in u32");
        expected_chain_bytes[i * 4..(i + 1) * 4].copy_from_slice(&limb.to_le_bytes());
    }

    let actual_chain = AggLayerBridge::removed_ger_hash_chain(&updated_bridge_account)?;
    assert_eq!(actual_chain, expected_chain_bytes, "removed-GER hash chain mismatch");

    Ok(())
}

/// Tests that REMOVE_GER reverts when the GER was never registered in the first place.
#[tokio::test]
async fn remove_ger_unknown_ger_reverts() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_manager.id(),
        ger_remover.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let ger = ExitRoot::from(GER_BYTES);
    let remove_ger_note =
        RemoveGerNote::create(ger, ger_remover.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(remove_ger_note.clone()));

    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[remove_ger_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_GER_NOT_FOUND);

    Ok(())
}

/// Tests that REMOVE_GER reverts when the note sender is not the GER remover.
#[tokio::test]
async fn remove_ger_non_remover_sender_reverts() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_manager.id(),
        ger_remover.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // Register a GER first so the failure is exclusively due to the sender check.
    let ger = ExitRoot::from(GER_BYTES);
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    // The GER manager (not the remover) attempts to send the REMOVE_GER note.
    let remove_ger_note =
        RemoveGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(remove_ger_note.clone()));

    let mut mock_chain = builder.build()?;

    let update_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_executed = update_tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&update_executed)?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[remove_ger_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_GER_REMOVER);

    Ok(())
}
