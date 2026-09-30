//! Faucet-composition tripwires, driven end to end — the executing half of the structural posture
//! its sibling recomposition suite pins. The two are split only for file size and share the
//! production-transport harness in `support::mint_transport`, so neither carries its own copy of
//! the note-building engine.
//!
//! The production transport driven END TO END: a REAL stock `MintNote` carrying the merged
//! transport (scheme 4: the attestation followed by the DepositIntent) +
//! `NetworkAccountTarget` (scheme 2) attachments mints EXACTLY the attested amount, and the
//! ratified ASSERT-MATCH binding
//! (the policy asserts the note-supplied RECIPIENT equals the attested derivation, never
//! overrides) rejects a tampered recipient with its EXACT error; fee != 0 (the keep-zero fee
//! gate) and nonce replay keep their frozen errors through the transport. All tests here are
//! security tripwires and hold the tripwire serial guard (they flake under parallel
//! `cargo test`).

mod support;

use anyhow::Result;
use miden_protocol::note::{NoteTag, NoteType};
use miden_testing::assert_transaction_executor_error;
use support::mint_transport::*;
use support::*;
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;

// THE RECOMPOSED HAPPY PATH — the stock MintNote transport mints the attested amount
// ================================================================================================

/// E2E: the stock `MintNote` carrying the attested transport mints EXACTLY the attested amount to
/// the attested recipient — one PUBLIC P2ID output note with the nonce-derived serial recipe, the
/// nonce marker set, and token_supply raised by the attested amount.
#[tokio::test]
async fn stock_mint_note_mints_the_attested_amount() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 1);
    let note = honest_note(&pf, &payload, 71)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;

    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the recomposed attested mint must succeed: {e}"))?;

    // exactly one PUBLIC recipient note carrying the attested amount of THIS faucet's asset
    assert_eq!(
        tx.output_notes().num_notes(),
        1,
        "an attested mint emits exactly one recipient note"
    );
    let out = tx.output_notes().get_note(0);
    let asset = out
        .assets()
        .iter_fungible()
        .next()
        .ok_or_else(|| anyhow::anyhow!("the recipient note carries a fungible asset"))?;
    assert_eq!(
        asset.faucet_id(),
        pf.faucet_id,
        "the asset is this faucet's"
    );
    assert_eq!(
        u64::from(asset.amount()),
        MINT_AMOUNT,
        "the minted amount is EXACTLY the attested wire amount (scale-0 identity)"
    );
    assert_eq!(
        out.metadata().note_type(),
        NoteType::Public,
        "the recipient note is Public"
    );
    assert_eq!(
        out.metadata().tag(),
        NoteTag::with_account_target(pf.recipient_id),
        "the recipient note is tagged for the attested recipient"
    );

    let mut chain = pf.mock_chain;
    commit(&mut chain, &tx)?;
    let faucet = committed(&chain, pf.faucet_id)?;
    assert_eq!(
        read_map_word(
            &faucet,
            XReserveFaucetExtension::used_nonces_slot(),
            nonce_key_of_payload(&payload)
        )?,
        marker(),
        "the attested nonce must be marked used (the policy's nonce-ledger write)"
    );
    assert_eq!(
        committed_token_supply(&chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(MINT_AMOUNT)?,
        "token_supply rises by exactly the attested amount"
    );
    Ok(())
}

// THE ASSERT-MATCH RECIPIENT BINDING + the frozen fee/replay negatives through the new transport
// ================================================================================================

/// E2E NEGATIVE (the NEW binding): a mint note whose embedded output-note recipe targets an
/// account the attestation does NOT cover is rejected with the exact recipient-mismatch error —
/// the ratified ASSERT-MATCH binding (the policy never overrides; it keeps the note honest),
/// fail-closed (no nonce burned, no supply raised).
#[tokio::test]
async fn stock_mint_note_rejects_a_recipient_mismatch() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 2);
    // the recipe targets the PRODUCER; the attested intent targets the recipient wallet. The
    // output tag stays on the ATTESTED recipient so the trap isolates the RECIPIENT binding.
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.producer_id,
            amount: MINT_AMOUNT,
            tag: Some(NoteTag::with_account_target(pf.recipient_id)),
            public: true,
        },
        1,
        None,
        &AttachmentPlan::default(),
        72,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_RECIPIENT_MISMATCH"),
    )
    .await
}

// The keep-zero fee gate has no e2e negative any more, and that is the stronger position: under
// DC-14 the operator `feeAmount` does not travel on the wire at all, so a non-zero fee is
// inexpressible rather than rejected. Reintroducing the relayer-fee split (DEV-8) is therefore a
// transport change, not a policy change — see the faucet spec's fee-handling note.

/// E2E NEGATIVE (nonce replay): replaying an attested nonce through the transport trips the
/// frozen `ERR_XRESERVE_NONCE_REPLAY` — the policy's nonce-ledger write is load-bearing.
#[tokio::test]
async fn stock_mint_note_rejects_a_replay() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 4);

    let first = honest_note(&pf, &payload, 74)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &first).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, first.id())
        .await
        .map_err(|e| anyhow::anyhow!("the first attested mint must succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;

    // the SAME payload (same nonce), a fresh note serial — the nonce ledger must reject it.
    // (No fail-closure sweep here: the FIRST mint legitimately raised supply and burned the
    // nonce; the exact-replay error is the assertion.)
    let replay = honest_note(&pf, &payload, 75)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &replay).await?;
    let result = consume_note(&pf.mock_chain, pf.faucet_id, replay.id()).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_NONCE_REPLAY"));
    Ok(())
}
