//! The attester allowlist can be seeded at build time: a faucet composed with `attesters` carries
//! their rows from its first block and accepts their attestations with no `set_attester` bring-up
//! note, while a key it was not built with is still refused. A key listed twice is rejected at
//! construction.

mod support;

use anyhow::Result;
use assert_matches::assert_matches;
use miden_crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::errors::StorageMapError;
use support::mint_transport::*;
use support::*;
use xusdc_encoding::account::xreserve::{XReserveFaucetExtension, XReserveStablecoinBuilderError};

/// Attester 1's public key, the key `honest_note` signs with; the seed alone fixes the key.
fn attester_1() -> PublicKey {
    gen_attester(1, b"").pubkey
}

/// A production faucet built with attester 1 allowlisted and no admin note seeded.
fn seeded_fixture() -> Result<ProductionFaucet> {
    setup_production_faucet_with_attesters(0, vec![attester_1()], |_, _| Vec::new())
}

/// The built faucet carries attester 1's enabled row on chain, and an attestation it signed mints
/// without any admin note being consumed first.
#[tokio::test]
async fn a_build_seeded_attester_mints_with_no_bring_up() -> Result<()> {
    let mut pf = seeded_fixture()?;
    let faucet = committed(&pf.mock_chain, pf.faucet_id)?;
    assert_eq!(
        read_map_word(
            &faucet,
            XReserveFaucetExtension::xreserve_attesters_slot(),
            attester_1().to_commitment()
        )?,
        marker(),
        "the built faucet carries the enabled row for attester 1"
    );

    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 31);
    let note = honest_note(&pf, &payload, 2011)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("a faucet with a build-seeded attester must mint: {e}"))?;
    assert_eq!(
        tx.output_notes().num_notes(),
        1,
        "the mint must emit the attested output note"
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
        "the accepted mint marks its nonce"
    );
    Ok(())
}

/// A faucet built with attester 1 refuses an attestation signed by attester 2.
#[tokio::test]
async fn a_key_the_faucet_was_not_built_with_is_refused() -> Result<()> {
    let mut pf = seeded_fixture()?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 32);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        2,
        None,
        &AttachmentPlan::default(),
        2012,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_DISALLOWED_PUB_KEY"),
    )
    .await
}

/// Listing the same key twice is rejected at construction.
#[test]
fn a_key_listed_twice_is_rejected() -> Result<()> {
    let err = production_builder_verdict_with_attesters(
        0,
        TEST_DOMAIN,
        None,
        vec![attester_1(), attester_1()],
    )?
    .expect_err("a duplicated attester must not build");
    assert_matches!(
        err,
        XReserveStablecoinBuilderError::AttesterAllowlist(StorageMapError::DuplicateKey { .. })
    );
    Ok(())
}
