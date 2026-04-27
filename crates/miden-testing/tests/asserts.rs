//! Integration tests for the note-lifecycle assertion macros.

extern crate alloc;

use anyhow::Result;
use miden_protocol::account::AccountId;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::Word;
use miden_protocol::note::{Note, NoteId, NoteType};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_testing::{
    Auth,
    MockChain,
    assert_note_committed,
    assert_note_consumed,
    assert_note_consumed_by,
    assert_note_created,
    assert_note_unspent,
};

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
async fn lifecycle_macros_full_round_trip() -> Result<()> {
    let asset: Asset = FungibleAsset::mock(7);
    let (sender_id, spawn, mut chain, executed) = execute_with_output(&[asset]).await?;

    // post-build: spawn is committed and unspent.
    assert_note_committed!(chain, &spawn);
    assert_note_committed!(chain, spawn.id());
    assert_note_unspent!(chain, &spawn);
    assert_note_unspent!(chain, spawn.id());

    // post-execute: tx-level checks against the executed transaction.
    assert_note_consumed_by!(executed, &spawn);
    assert_note_consumed_by!(executed, spawn.id());
    assert_note_consumed_by!(executed, spawn.nullifier());

    assert_note_created!(
        executed,
        note_type: NoteType::Public,
        sender: sender_id,
        assets: [asset],
    );

    // post-block: spawn's nullifier is now on-chain.
    chain.add_pending_executed_transaction(&executed)?;
    chain.prove_next_block()?;

    assert_note_consumed!(chain, &spawn);
    assert_note_consumed!(chain, spawn.nullifier());

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

#[tokio::test]
#[should_panic(expected = "not in chain.committed_notes()")]
async fn assert_note_unspent_panics_for_unknown_note_id() {
    let asset: Asset = FungibleAsset::mock(7);
    let (_sender_id, _spawn, chain, _executed) = execute_with_output(&[asset]).await.unwrap();

    let unknown = NoteId::new(Word::default(), Word::default());
    assert_note_unspent!(chain, unknown);
}
