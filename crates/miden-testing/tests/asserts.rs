//! Integration tests for the note-lifecycle assertions

extern crate alloc;

use anyhow::Result;
use miden_protocol::account::AccountId;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_testing::{Auth, MockChain, assert_note_created};

/// Builds a chain and runs a SPAWN tx that emits one P2ID output note with the given assets.
/// The returned chain is still in post-build state — execute doesn't mutate it.
async fn execute_with_output(
    output_assets: &[Asset],
) -> Result<(AccountId, Note, MockChain, ExecutedTransaction)> {
    let mut builder = MockChain::builder();

    let sender = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        output_assets.iter().copied(),
    )?;
    let target = builder.create_new_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let sender_id = sender.id();

    let output = builder.add_p2id_note(sender_id, target.id(), output_assets, NoteType::Public)?;
    let spawn = builder.add_spawn_note([&output])?;

    let chain = builder.build()?;

    let executed = chain
        .build_tx_context(sender, &[spawn.id()], &[])?
        .extend_expected_output_notes(vec![RawOutputNote::Full(output)])
        .build()?
        .execute()
        .await?;

    Ok((sender_id, spawn, chain, executed))
}

/// Full lifecycle: build, execute, prove block.
#[tokio::test]
async fn note_lifecycle_full_flow() -> Result<()> {
    let asset: Asset = FungibleAsset::mock(7);
    let (sender_id, spawn, mut chain, executed) = execute_with_output(&[asset]).await?;

    // post-build: spawn is committed and unspent.
    assert!(chain.is_note_committed(&spawn.id()));
    assert!(chain.is_note_unspent(&spawn.nullifier()));

    // post-execute: tx-level checks against the executed transaction.
    assert!(executed.consumes_note(&spawn.id()));

    assert_note_created!(
        executed,
        note_type: NoteType::Public,
        sender: sender_id,
        assets: [asset],
    );

    // post-block: spawn's nullifier is now on-chain.
    chain.add_pending_executed_transaction(&executed)?;
    chain.prove_next_block()?;

    assert!(chain.is_note_consumed(&spawn.nullifier()));

    Ok(())
}

/// Each field can be set on its own; unset fields aren't checked.
#[tokio::test]
async fn assert_note_created_partial_specs_match() -> Result<()> {
    let asset: Asset = FungibleAsset::mock(7);
    let (sender_id, _spawn, _chain, executed) = execute_with_output(&[asset]).await?;

    assert_note_created!(executed, note_type: NoteType::Public);
    assert_note_created!(executed, sender: sender_id);
    assert_note_created!(executed, assets: [asset]);
    assert_note_created!(executed, note_type: NoteType::Public, assets: [asset]);
    Ok(())
}

#[tokio::test]
#[should_panic(expected = "no output note matches")]
async fn assert_note_created_panics_on_sender_mismatch() {
    let asset: Asset = FungibleAsset::mock(7);
    let (_sender_id, _spawn, _chain, executed) = execute_with_output(&[asset]).await.unwrap();

    // Faucet ID can't be the sender of a wallet-emitted P2ID.
    assert_note_created!(executed, sender: FungibleAsset::mock_issuer());
}

#[tokio::test]
#[should_panic(expected = "no output note matches")]
async fn assert_note_created_panics_on_asset_count_mismatch() {
    let asset: Asset = FungibleAsset::mock(7);
    let (_sender_id, _spawn, _chain, executed) = execute_with_output(&[asset]).await.unwrap();

    assert_note_created!(executed, assets: [asset, asset]);
}
