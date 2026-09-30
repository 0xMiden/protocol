//! What deriving the identifier changes for a deployed faucet, and what it removes from it.
//!
//! Under the stored-identifier design a freshly deployed faucet could not mint. Its identifier slot
//! shipped empty, every deposit intent compared against that empty Word, and so every mint failed
//! until an administrator got an init note through — a window in which the faucet was live,
//! addressable, and useless. Deriving the identifier from the account's own id closes that window
//! by construction: there is nothing to seed, so there is no pre-init state to be caught in.
//!
//! The first two tests are that claim stated as behavior. A faucet whose only bring-up note is the
//! attester allowlist entry — no identifier init, ever — mints; and an intent whose `remoteToken`
//! is somebody else's still rejects, with the byte-identical error the stored-identifier design
//! rejected with, because the check did not get weaker, only differently sourced.
//!
//! The rest assert the mechanism is gone rather than merely unused: no callable procedure for it
//! on the assembled component, and no identifier slot in the composed account's storage. Each is
//! written so it keeps meaning after the deletion lands — they name what must be absent by string,
//! not by importing the thing that has to disappear. (The note-script allowlist itself is pinned
//! by `f5_network_account_auth.rs` against `XReserveStablecoinBuilder::allowed_note_scripts`.)

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::StorageSlotName;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use support::mint_transport::*;
use support::*;
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;

/// The identifier slot label, spelled out rather than imported: the constant that carried it is one
/// of the things this slice deletes, and the test has to outlive it.
const IDENTIFIER_SLOT_LABEL: &str = "xusdc::xreserve::domain_config::identifier";

/// The fully-qualified path of the initializer that must no longer exist on the component.
const INIT_IDENTIFIER_PATH: &str = "::xreserve::identifier_init::init_identifier";

// MINT IMMEDIACY — a faucet that was never initialized still mints
// ================================================================================================

/// A production faucet whose bring-up consists of the attester note ALONE mints an own-id-bound
/// deposit intent.
///
/// No identifier-init note is built, seeded, or consumed anywhere in this test. Under the stored
/// design the identifier slot would still be empty here and the compare would fail on every intent;
/// the mint succeeding is the whole point of the change.
#[tokio::test]
async fn a_never_initialized_faucet_mints() -> Result<()> {
    let mut pf = setup_production_faucet(0, |recipient, faucet_id| {
        let commitment =
            gen_attester(1, &payload_for(recipient, faucet_id, MINT_AMOUNT, 0)).commitment;
        vec![XReserveSetAttesterNote::create(
            administrator(),
            faucet_id,
            commitment,
            1,
            &mut note_rng(2001),
        )
        .expect("building the administrator set_attester note")]
    })?;
    assert_eq!(
        pf.seeded_notes.len(),
        1,
        "bring-up must be the attester note and nothing else"
    );
    bring_up(&mut pf, 1).await?;

    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 31);
    let note = honest_note(&pf, &payload, 2011)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("a faucet with no identifier init must still mint: {e}"))?;

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

// REJECT IDENTITY — a foreign remoteToken still rejects, with the same error
// ================================================================================================

/// An intent whose `remoteToken` is not this faucet's own id rejects with EXACTLY
/// `ERR_XRESERVE_WRONG_IDENTIFIER`, on a faucet that accepts the own-id-bound intent.
///
/// Both halves are needed, and the second is what makes the first mean anything. A faucet that
/// rejected EVERY intent would pass the reject leg on its own — which is precisely what the
/// uninitialized stored-identifier faucet did, comparing every deposit against an empty Word. So
/// the same faucet, in the same test, then mints an own-id-bound intent: the compare discriminates
/// rather than refuses.
///
/// The rejected token is another live account's id in the SAME frozen packaging. That is what makes
/// the row an identity test rather than a shape test: `remoteToken` is read through the bytes32
/// account-id decode, so opaque bytes are refused for being un-decodable long before any identity
/// compare runs, and only a well-formed foreign packaging can reach
/// `ERR_XRESERVE_WRONG_IDENTIFIER`. (The un-decodable shape has its own row in
/// `masm_mint_shell.rs`.)
#[tokio::test]
async fn a_foreign_remote_token_rejects_while_the_own_id_intent_mints() -> Result<()> {
    let mut pf = setup_production_faucet(0, |recipient, faucet_id| {
        let commitment =
            gen_attester(1, &payload_for(recipient, faucet_id, MINT_AMOUNT, 0)).commitment;
        vec![XReserveSetAttesterNote::create(
            administrator(),
            faucet_id,
            commitment,
            1,
            &mut note_rng(2002),
        )
        .expect("building the administrator set_attester note")]
    })?;
    bring_up(&mut pf, 1).await?;

    // another live account's id, in the same frozen packaging: decodable, valid, and not ours
    let foreign_token: [u8; 32] =
        EthEmbeddedAccountId::from_account_id(pf.recipient_id).to_bytes32();
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 32);
    payload[REMOTE_TOKEN_BYTE_OFF..REMOTE_TOKEN_BYTE_OFF + 32].copy_from_slice(&foreign_token);
    assert_ne!(
        foreign_token,
        EthEmbeddedAccountId::from_account_id(pf.faucet_id).to_bytes32(),
        "the foreign token must genuinely differ from the faucet's own id encoding"
    );

    let note = honest_note(&pf, &payload, 2012)?;
    expect_ecdsa_reject(&mut pf, note, &payload).await?;

    // the discrimination proof: the SAME faucet mints the own-id-bound intent
    let bound = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 33);
    let bound_note = honest_note(&pf, &bound, 2013)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &bound_note).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, bound_note.id())
        .await
        .map_err(|e| {
            anyhow::anyhow!("the own-id-bound intent must mint on the same faucet: {e}")
        })?;
    assert_eq!(
        tx.output_notes().num_notes(),
        1,
        "the accepted mint must emit the attested output note"
    );
    Ok(())
}

/// The reject error text is the one pinned for the mint, character for character.
///
/// The string is part of what a relayer matches on, so a reworded message is a wire change dressed
/// up as a comment fix. Under `DC-14` a foreign identifier has no error of its own — the faucet
/// stamps its own id into the message, so the reject arrives as the signature failing over a
/// preimage Circle never signed. Since the signature verdict settles through the `uint256`
/// precompile, which traps rather than returning a flag, the frozen string is that precompile's.
#[test]
fn the_wrong_identifier_error_text_is_unchanged() {
    assert_eq!(
        ECDSA_VERIFY_REJECT_RENDERING,
        "precompile `uint256`: deferred assertion failed: values disagree",
        "the wrong-identifier reject text is frozen"
    );
}

// STRUCTURAL REMOVAL — the mechanism is gone, not merely unused
// ================================================================================================

/// The assembled xreserve component exports no `init_identifier` procedure at all.
///
/// A procedure left exported but unreachable would still be part of the account's callable surface,
/// which is the thing the removal is meant to shrink.
#[test]
fn the_component_exports_no_identifier_initializer() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    assert!(
        !exports.iter().any(|e| e == INIT_IDENTIFIER_PATH),
        "{INIT_IDENTIFIER_PATH} must not be exported; exports: {exports:?}"
    );
    assert!(
        !exports.iter().any(|e| e.contains("identifier_init")),
        "no identifier_init module may survive; exports: {exports:?}"
    );
    Ok(())
}

/// A faucet composed by the production builder declares no identifier storage slot.
///
/// The slot is what forced the initializer to exist. With the comparand derived there is nothing to
/// store, and leaving a dead slot behind would keep the account's storage commitment — and so its
/// id — carrying a field nothing reads.
#[test]
fn the_composed_faucet_declares_no_identifier_slot() -> Result<()> {
    let account = production_faucet_account()?;
    let name = StorageSlotName::new(IDENTIFIER_SLOT_LABEL).context("identifier slot label")?;
    assert!(
        !account
            .storage()
            .slots()
            .iter()
            .any(|slot| slot.name() == &name),
        "the composed faucet must declare no {IDENTIFIER_SLOT_LABEL} slot"
    );
    assert!(
        account.storage().get_item(&name).is_err(),
        "reading the identifier slot must fail — the slot does not exist"
    );
    Ok(())
}

// HELPERS
// ================================================================================================

/// Composes the production faucet through the shipped fixture and returns the built account, so
/// its declared storage can be inspected.
fn production_faucet_account() -> Result<miden_protocol::account::Account> {
    let pf = setup_production_faucet(0, |_, _| vec![])?;
    committed(&pf.mock_chain, pf.faucet_id)
}
