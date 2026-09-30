//! End-to-end mint rejects, driven through the real note transport.
//!
//! Every test here mints — or fails to mint — the way production does: a real standard mint note
//! carrying the deposit intent, the attestation, and the network-account target, consumed by a
//! faucet composed by the production builder, whose standard `mint_and_send` dispatches the
//! faucet's `check_policy` as its active mint policy. Nothing is stubbed, so a reject proves the
//! whole chain refuses, not just one procedure in isolation.
//!
//! This file covers the verification failures and the supply cap: an attester who is not
//! allowlisted, an attester whose allowlist entry was removed, a forged signature, an intent for
//! the wrong remote domain, an intent for the wrong identifier, an amount that cannot cover its
//! own maxFee, and amounts that exceed the faucet's remaining headroom (including the interplay
//! with the max-supply setter — lowering the cap below the pending mint, minting exactly at the
//! cap, and raising it again).
//!
//! The other half of the matrix — how the note's fields bind to what is actually minted, recipient
//! extraction, transport shape, pause behavior, and routing — lives in `mint_policy_binding_e2e.rs`.
//! Both share the transport harness in `support::mint_transport`, which owns the fixtures and the
//! tampering helpers.
//!
//! Two rules hold throughout: every negative asserts its exact error rather than merely failing,
//! and the security-critical rejects also assert fail-closure — no nonce consumed, no supply
//! raised — so a reject cannot leave the faucet in a state the attacker wanted.

mod support;

use anyhow::Result;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use support::mint_transport::*;
use support::*;
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;

// ATTESTER ALLOWLIST AND SIGNATURE — who signed, and were they allowed to
// ================================================================================================

/// A stranger's signature is refused even though it verifies: their key is not allowlisted.
#[tokio::test]
async fn mint_rejects_a_non_allowlisted_attester() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 11);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        2, // a DIFFERENT keypair — its commitment is not allowlisted
        None,
        &AttachmentPlan::default(),
        81,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_DISALLOWED_PUB_KEY"),
    )
    .await
}

/// An allowlisted attester's key paired with a signature over different bytes is refused: the
/// signature does not verify against the digest of the deposit actually presented.
#[tokio::test]
async fn mint_rejects_a_forged_signature() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 12);
    let other = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 13);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        1,
        Some(&other), // allowlisted key, signature over the WRONG payload
        &AttachmentPlan::default(),
        82,
    )?;
    expect_ecdsa_reject(&mut pf, note, &payload).await
}

/// Removing an attester really revokes them, end to end.
///
/// The account starts with attester 1 allowlisted; a further owner-sent `set_attester` note with
/// `enabled = 0` writes the empty Word back over their entry. A mint attested by that key is then
/// refused by the same allowlist check a never-allowlisted key hits. This is the test that proves
/// the disable path clears the marker rather than merely overwriting it with something else
/// non-empty — key rotation depends on it.
#[tokio::test]
async fn mint_rejects_a_removed_attester() -> Result<()> {
    let mut pf = fixture_with(0, |recipient, faucet_id| {
        let commitment =
            gen_attester(1, &payload_for(recipient, faucet_id, MINT_AMOUNT, 0)).commitment;
        vec![XReserveSetAttesterNote::create(
            administrator(),
            faucet_id,
            commitment,
            0,
            &mut note_rng(954),
        )
        .expect("building the administrator remove-attester note")]
    })?;
    bring_up(&mut pf, 2).await?; // set_attester(enable) + set_attester(REMOVE)
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 30);
    let note = honest_note(&pf, &payload, 99)?; // attested by the (now removed) attester 1
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_DISALLOWED_PUB_KEY"),
    )
    .await
}

/// Attester ROTATION: attester 1 is rotated OUT (removed) and attester 2 rotated IN. A mint
/// attested by the rotated-out key rejects (fail-closed), then a mint attested by the NEW key
/// lands on the SAME chain — the allowlist reflects exactly the rotated state.
#[tokio::test]
async fn mint_rotation_rejects_the_old_attester_and_accepts_the_new() -> Result<()> {
    let mut pf = fixture_with(0, |recipient, faucet_id| {
        let base = payload_for(recipient, faucet_id, MINT_AMOUNT, 0);
        vec![
            XReserveSetAttesterNote::create(
                administrator(),
                faucet_id,
                gen_attester(1, &base).commitment,
                0,
                &mut note_rng(955),
            )
            .expect("building the rotate-out note"),
            XReserveSetAttesterNote::create(
                administrator(),
                faucet_id,
                gen_attester(2, &base).commitment,
                1,
                &mut note_rng(956),
            )
            .expect("building the rotate-in note"),
        ]
    })?;
    bring_up(&mut pf, 3).await?; // enable(1) + remove(1) + enable(2)

    // the ROTATED-OUT key rejects (exact error + no nonce burned + no supply raised)
    let payload_old = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 31);
    let note_old = tampered_mint_note(
        &pf,
        &payload_old,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        1, // the rotated-out keypair
        None,
        &AttachmentPlan::default(),
        100,
    )?;
    expect_reject(
        &mut pf,
        note_old,
        &payload_old,
        shell_error_by_name("ERR_XRESERVE_DISALLOWED_PUB_KEY"),
    )
    .await?;

    // the ROTATED-IN key mints on the same chain
    let payload_new = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 32);
    let note_new = tampered_mint_note(
        &pf,
        &payload_new,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        2, // the rotated-in keypair
        None,
        &AttachmentPlan::default(),
        101,
    )?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note_new).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note_new.id())
        .await
        .map_err(|e| anyhow::anyhow!("the rotated-in attester's mint must succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(MINT_AMOUNT)?,
        "the rotated-in attester's mint raises supply by the attested amount"
    );
    Ok(())
}

// DOMAIN AND IDENTIFIER COMPARES — is this deposit even addressed to this faucet?
// ================================================================================================

/// A deposit intent naming a different remote domain is refused, compared against the domain the
/// builder seeded into the account.
#[tokio::test]
async fn mint_rejects_a_wrong_domain() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 14);
    payload[REMOTE_DOMAIN_BYTE_OFF..REMOTE_DOMAIN_BYTE_OFF + 4]
        .copy_from_slice(&TEST_WRONG_DOMAIN.as_u32().to_be_bytes());
    let note = honest_note(&pf, &payload, 83)?;
    expect_ecdsa_reject(&mut pf, note, &payload).await
}

/// A deposit intent whose `remoteToken` is not this faucet's identifier is refused, compared
/// against the faucet's own account id.
///
/// The substituted token is another live account's id in the SAME frozen packaging, so it decodes
/// cleanly and the IDENTITY compare is what refuses it. Corrupting the packaging instead would trap
/// earlier, inside the decode, and prove nothing about the identity check.
#[tokio::test]
async fn mint_rejects_a_wrong_identifier() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 15);
    payload[REMOTE_TOKEN_BYTE_OFF..REMOTE_TOKEN_BYTE_OFF + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(pf.recipient_id).to_bytes32());
    let note = honest_note(&pf, &payload, 84)?;
    expect_ecdsa_reject(&mut pf, note, &payload).await
}

// AMOUNT AND FEE BOUNDS — checked inside the policy, before anything is minted
// ================================================================================================

/// An attested amount strictly below its own attested maxFee is refused: the deposit could never
/// cover the fee it declares.
#[tokio::test]
async fn mint_rejects_an_amount_below_max_fee() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 33);
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(MINT_AMOUNT + 1)); // maxFee = amount + 1 -> amount < maxFee
    let note = honest_note(&pf, &payload, 102)?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_AMOUNT_BELOW_FEE"),
    )
    .await
}

// SUPPLY CAP — the STOCK mint_and_send discipline (the policy carries no supply arithmetic)
// ================================================================================================

/// A mint that would push total supply past the faucet's maximum is refused by the standard
/// `mint_and_send` cap check — the faucet's own policy does no supply arithmetic at all — and
/// fails closed. The cap is fixed at the maximum asset amount, so the over-cap condition is a
/// build-time supply one short of leaving room for the attested amount.
#[tokio::test]
async fn mint_rejects_an_over_cap_amount() -> Result<()> {
    let over_cap_supply = miden_protocol::asset::AssetAmount::MAX.as_u64() - MINT_AMOUNT + 1;
    let mut pf = fixture_with(over_cap_supply, |_, _| vec![])?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 16);
    let note = honest_note(&pf, &payload, 85)?;
    expect_reject(&mut pf, note, &payload, &err_stock_over_cap()).await
}

// ADMIN INTERPLAY — set_max_supply x mint through the recomposed transport (the runtime cap and
// the attested mint interact exactly as the stock discipline dictates)
// ================================================================================================

/// LOWER-then-over-cap: the administrator's `set_max_supply` note LOWERS the cap below the attested
/// amount BEFORE the mint; the attested mint then rejects in the stock cap discipline,
/// fail-closed (no nonce burned, no supply raised).
#[tokio::test]
async fn mint_rejects_after_the_administrator_lowers_max_supply_below_the_amount() -> Result<()> {
    let mut pf = fixture_with(0, |_, faucet_id| {
        vec![
            stock_set_max_supply_note(administrator(), faucet_id, MINT_AMOUNT - 1, 957)
                .expect("building the administrator lower-cap note"),
        ]
    })?;
    bring_up(&mut pf, 2).await?; // set_attester + set_max_supply(lower)
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 34);
    let note = honest_note(&pf, &payload, 103)?;
    expect_reject(&mut pf, note, &payload, &err_stock_over_cap()).await
}

/// AT-CAP boundary: the administrator's note sets the cap to EXACTLY the attested amount; the
/// mint then lands with `token_supply == max_supply` — the boundary ACCEPTS (the cap is `<=`,
/// not `<`), and the acceptance is attributable to the admin note.
#[tokio::test]
async fn mint_accepts_at_the_exact_raised_cap_boundary() -> Result<()> {
    let mut pf = fixture_with(0, |_, faucet_id| {
        vec![
            stock_set_max_supply_note(administrator(), faucet_id, MINT_AMOUNT, 958)
                .expect("building the administrator set-to-boundary note"),
        ]
    })?;
    bring_up(&mut pf, 2).await?; // set_attester + set_max_supply(= amount)
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 35);
    let note = honest_note(&pf, &payload, 104)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the at-cap boundary mint must succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(MINT_AMOUNT)?,
        "the boundary mint fills the raised cap exactly (supply == max_supply)"
    );
    Ok(())
}

/// RAISE-then-accepts: under a too-low runtime cap (the administrator's lowering note) the
/// attested mint REJECTS over-cap (the low cap binds); after the administrator's raise note
/// lands, a fresh-nonce mint of the SAME amount succeeds — the runtime raise is what unlocks
/// the mint.
#[tokio::test]
async fn mint_accepts_after_the_administrator_raises_max_supply() -> Result<()> {
    let mut pf = fixture_with(0, |_, faucet_id| {
        vec![
            stock_set_max_supply_note(administrator(), faucet_id, MINT_AMOUNT - 1, 961)
                .expect("building the administrator lower-cap note"),
            stock_set_max_supply_note(administrator(), faucet_id, MAX_SUPPLY, 959)
                .expect("building the administrator raise-cap note"),
        ]
    })?;
    bring_up(&mut pf, 2).await?; // set_attester + set_max_supply(lower) — the raise stays unconsumed

    // under the lowered cap the attested amount rejects (the cap binds pre-raise)
    let payload_low = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 36);
    let note_low = honest_note(&pf, &payload_low, 105)?;
    expect_reject(&mut pf, note_low, &payload_low, &err_stock_over_cap()).await?;

    // the administrator's raise lands, then a fresh-nonce mint of the same amount succeeds
    consume_seeded_admin_note(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 37);
    let note = honest_note(&pf, &payload, 106)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the post-raise mint must succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(MINT_AMOUNT)?,
        "the post-raise mint raises supply by the attested amount"
    );
    Ok(())
}
