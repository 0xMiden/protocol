//! Admin notes end to end: both layers of authorization, on the production network account.
//!
//! Every admin operation reaches the faucet as a note, and two independent things must hold for it
//! to take effect. The note's script must be allowlisted, or network auth refuses it before any of
//! its code runs; and the admin procedure it calls must accept the sender, which is the built-in
//! administrator role or a specific role depending on the operation. Each test here drives a real
//! shipped note and pins both layers, so neither can start carrying the other.
//!
//! Parameters travel in note STORAGE, committed by whoever created the note — never in note
//! arguments, which the network executor controls and could therefore rewrite. The `set_attester`
//! note is the worked example the others follow.
//!
//! Role management is the standard role-action note, and its ONE script root carries four actions:
//! grant, revoke, set-role-admin and renounce. Allowlisting is per root, so admitting it admits all
//! four, and the sections below drive each of them against the production account. Every seeded
//! role is administered directly by ADMIN, which may deliberately re-point its administration;
//! a holder can renounce its own membership.

mod support;

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{
    Account, AccountId, RoleSymbol, StorageMapKey, StorageSlotName, StorageSlotPatch,
};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::MasmError;
use miden_protocol::note::Note;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::PausableStorage;
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::note::config::{RbacConfig, RbacConfigNote};
use miden_testing::{assert_transaction_executor_error, MockChain};
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveFaucetExtension, BLK_MANAGER_ROLE, DOM_PAUSER_ROLE,
};
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;

/// The exact stock RBAC delegation error (v0.16: rbac.masm:66 ERR_SENDER_NOT_ROLE_ADMIN — #3215
/// re-keyed the v15 ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN and dropped its owner leg).
fn err_not_role_admin() -> MasmError {
    // v16 #3215: the administrator path is gone — the stock error re-keyed from
    // ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN to ERR_SENDER_NOT_ROLE_ADMIN (rbac.masm:66).
    MasmError::from_static_str("note sender does not hold the role's admin role")
}

fn pauser_sym() -> RoleSymbol {
    RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol")
}

fn blk_manager_sym() -> RoleSymbol {
    RoleSymbol::new(BLK_MANAGER_ROLE).expect("BLK_MANAGER is a fixed valid role symbol")
}

/// The exact stock error the membership assertion raises when a role is cleared for an account
/// that does not hold it (`rbac.masm` ERR_ACCOUNT_NOT_IN_ROLE) — the trap a renounce by a
/// non-holder hits.
fn err_account_not_in_role() -> MasmError {
    MasmError::from_static_str("account does not hold the role")
}

/// The `[is_member,0,0,0]` / marker word.
fn member_marker() -> Word {
    Word::from([1u32, 0, 0, 0])
}

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

/// A standard role-action note carrying `action`, sent by `sender` and tagged for `faucet_id`. The
/// serial is drawn from `rng` so note ids stay deterministic; every gate reads the sender.
fn stock_role_note<R: FeltRng>(
    sender: AccountId,
    faucet_id: AccountId,
    action: RbacConfig,
    rng: &mut R,
) -> Result<Note> {
    let note = RbacConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(action)
        .serial_number(rng.draw_word())
        .build()
        .map_err(|e| anyhow::anyhow!("building the standard role-action note: {e}"))?;
    Ok(Note::from(note))
}

/// A standard role-action note granting `role` to `member`.
fn stock_grant_role_note<R: FeltRng>(
    sender: AccountId,
    faucet_id: AccountId,
    role: RoleSymbol,
    member: AccountId,
    rng: &mut R,
) -> Result<Note> {
    stock_role_note(
        sender,
        faucet_id,
        RbacConfig::GrantRole {
            role,
            account: member,
        },
        rng,
    )
}

/// A standard role-action note revoking `role` from `member`.
fn stock_revoke_role_note<R: FeltRng>(
    sender: AccountId,
    faucet_id: AccountId,
    role: RoleSymbol,
    member: AccountId,
    rng: &mut R,
) -> Result<Note> {
    stock_role_note(
        sender,
        faucet_id,
        RbacConfig::RevokeRole {
            role,
            account: member,
        },
        rng,
    )
}

/// The shipped `set_attester` admin note, consumed against the production network-auth faucet: an
/// `ADMIN` holder SUCCEEDS and writes the attester marker at the creator-committed commitment key
/// (the storage-param marshaling is correct); anyone else PASSES network auth (the script is
/// allowlisted) but TRAPS at the proc's authority gate — the layered-auth proof.
#[tokio::test]
async fn set_attester_admin_note_admin_writes_and_nonadmin_traps() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    // setup_production_faucet seeds the administrator as test_account_id(1).
    let owner = test_account_id(1);
    let commitment = gen_attester(1, b"attester").commitment;

    // Owner-sent: PASSES network auth (allowlisted) AND the proc owner gate — writes state.
    let note = XReserveSetAttesterNote::create(owner, faucet_id, commitment, 1, &mut note_rng(1))
        .context("building the administrator set_attester note")?;
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("owner set_attester tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("owner-sent set_attester must succeed under network auth: {e}")
        })?;

    // Marshaling correct: the account delta writes the enabled marker [1,0,0,0] at the CREATOR-
    // committed commitment key (a scrambled marshaling would write a different key).
    let StorageSlotPatch::Map(delta) = tx
        .account_patch()
        .storage()
        .get(XReserveFaucetExtension::xreserve_attesters_slot())
        .context("xReserveAttesters slot delta")?
    else {
        panic!("xReserveAttesters must be a Map slot delta");
    };
    let written = delta
        .entries()
        .expect("map patch carries entries")
        .as_map()
        .get(&StorageMapKey::new(commitment))
        .copied()
        .context("the commitment key must appear in the xReserveAttesters delta")?;
    assert_eq!(
        written,
        Word::from([1u32, 0, 0, 0]),
        "owner set_attester must write the enabled marker at the creator-committed commitment key \
         (storage-param marshaling correct)",
    );

    // Non-administrator-sent: PASSES network auth (allowlisted script) but TRAPS at the proc owner gate.
    let bad = XReserveSetAttesterNote::create(
        test_account_id(9),
        faucet_id,
        commitment,
        0,
        &mut note_rng(2),
    )
    .context("building the non-administrator set_attester note")?;
    let result = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(bad.clone())
        .build()
        .context("non-administrator set_attester tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

// SHARED READ-BACK HELPERS
// ================================================================================================

/// Reads a single value-slot's post-tx word from the account delta (the slot's new value).
fn value_delta(tx: &ExecutedTransaction, name: &StorageSlotName) -> Word {
    match tx.account_patch().storage().get(name) {
        Some(StorageSlotPatch::Value(w)) => w.value().expect("value patch carries a value"),
        other => panic!("value slot {name} expected a value delta, got {other:?}"),
    }
}

/// A single felt as its value-slot word `[f, 0, 0, 0]`.
fn scalar_word(f: Felt) -> Word {
    Word::from([f, Felt::from(0u32), Felt::from(0u32), Felt::from(0u32)])
}

// MIN BURN (allowlist row 4) — ADMIN-gated floor setter. The standard min-burn-amount config note
// calls the standard `min_burn_amount::set_min_burn_amount`, which writes the standard policy's
// own slot; the factory it is built through refuses a sub-floor value before assembly
// ================================================================================================

const NEW_MIN_BURN: u64 = 5_000;

fn expected_min_burn() -> Word {
    scalar_word(Felt::try_from(NEW_MIN_BURN).expect("min burn within the field"))
}

/// An ADMIN-sent min-burn note PASSES auth (allowlisted) + the proc's authority gate and writes
/// `[new_min,0,0,0]` into the STOCK `MinBurnAmount` slot.
#[tokio::test]
async fn min_burn_administrator_writes_slot() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let owner = test_account_id(1);

    let note = stock_min_burn_note(owner, faucet_id, NEW_MIN_BURN, 40)
        .context("building the administrator min-burn note")?;
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("owner min-burn tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("owner-sent min-burn note must succeed under network auth: {e}")
        })?;
    let mut evolved = chain
        .committed_account(faucet_id)
        .context("committed faucet")?
        .clone();
    evolved.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_min_burn_size(&evolved)?,
        expected_min_burn(),
        "the owner min-burn note must write [new_min,0,0,0] into the STOCK MinBurnAmount slot",
    );
    Ok(())
}

/// A min-burn note from a sender without ADMIN PASSES auth but TRAPS at the authority gate.
async fn assert_min_burn_nonadmin_traps(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = stock_min_burn_note(sender, faucet_id, NEW_MIN_BURN, seed)
        .context("building the non-administrator min-burn note")?;
    let result = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("non-administrator min-burn tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

#[tokio::test]
async fn min_burn_dom_pauser_traps() -> Result<()> {
    assert_min_burn_nonadmin_traps(test_account_id(2), 41).await
}

#[tokio::test]
async fn min_burn_dom_unpauser_traps() -> Result<()> {
    assert_min_burn_nonadmin_traps(test_account_id(3), 42).await
}

#[tokio::test]
async fn min_burn_third_party_traps() -> Result<()> {
    assert_min_burn_nonadmin_traps(test_account_id(99), 43).await
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the written min burn size.
#[tokio::test]
async fn min_burn_note_args_are_inert() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let owner = test_account_id(1);

    let note = stock_min_burn_note(owner, faucet_id, NEW_MIN_BURN, 44)
        .context("building the administrator min-burn note")?;
    let bogus_args = Word::from([999u32, 1, 2, 3]);
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("min-burn note-args tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("the min-burn note with bogus NOTE_ARGS must still succeed: {e}")
        })?;
    let mut evolved = chain
        .committed_account(faucet_id)
        .context("committed faucet")?
        .clone();
    evolved.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_min_burn_size(&evolved)?,
        expected_min_burn(),
        "the min-burn note must write the storage-committed param regardless of executor NOTE_ARGS",
    );
    Ok(())
}

// PAUSE (allowlist row 6) — DOM_PAUSER-gated emergency halt (owner has NO pause path)
// ================================================================================================

/// DOM_PAUSER-sent pause PASSES auth (allowlisted) + the proc's DOM_PAUSER gate and sets is_paused=1.
#[tokio::test]
async fn pause_dom_pauser_sets_is_paused() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;

    let note = stock_pause_note(test_account_id(2), faucet_id, 50)
        .context("building the DOM_PAUSER pause note")?;
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("DOM_PAUSER pause tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("DOM_PAUSER pause must succeed under network auth: {e}"))?;
    assert_eq!(
        value_delta(&tx, PausableStorage::is_paused_slot()),
        scalar_word(Felt::from(1u32)),
        "DOM_PAUSER pause must set is_paused = 1",
    );
    Ok(())
}

/// A non-DOM_PAUSER pause note PASSES auth but TRAPS at the proc's role gate — including the OWNER
/// (Circle model: the administrator has NO pause path).
async fn assert_pause_nonpauser_traps(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note =
        stock_pause_note(sender, faucet_id, seed).context("building the non-pauser pause note")?;
    let result = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("non-pauser pause tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

#[tokio::test]
async fn pause_administrator_traps() -> Result<()> {
    assert_pause_nonpauser_traps(test_account_id(1), 51).await
}

#[tokio::test]
async fn pause_third_party_traps() -> Result<()> {
    assert_pause_nonpauser_traps(test_account_id(99), 52).await
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the pause effect.
#[tokio::test]
async fn pause_note_args_are_inert() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;

    let note = stock_pause_note(test_account_id(2), faucet_id, 53)
        .context("building the DOM_PAUSER pause note")?;
    let bogus_args = Word::from([5u32, 5, 5, 5]);
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("pause note-args tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("pause with bogus NOTE_ARGS must still succeed: {e}"))?;
    assert_eq!(
        value_delta(&tx, PausableStorage::is_paused_slot()),
        scalar_word(Felt::from(1u32)),
        "pause must set is_paused=1 regardless of executor NOTE_ARGS",
    );
    Ok(())
}

// UNPAUSE (allowlist row 7) — DOM_UNPAUSER-gated resume
// ================================================================================================

/// A production faucet paused by a SEEDED DOM_PAUSER pause note (brought up on-chain), so an unpause
/// tx has a 1 -> 0 `is_paused` transition to observe. Placeholder PUBLIC routing target (routing-only).
async fn paused_faucet() -> Result<(MockChain, AccountId)> {
    let pf = setup_production_faucet(0, |_, faucet_id| {
        vec![stock_pause_note(test_account_id(2), faucet_id, 60)
            .expect("building the seeded pause note")]
    })
    .context("building the production faucet with a seeded pause")?;
    let mut chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    for note in pf.seeded_notes.clone() {
        let tx = chain
            .build_transaction(faucet_id)
            .authenticated_input_note(note.id())
            .build()
            .context("pause bring-up tx build")?
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("pause bring-up must succeed: {e}"))?;
        chain.add_pending_executed_transaction(&tx)?;
        chain.prove_next_block()?;
    }
    Ok((chain, faucet_id))
}

/// DOM_UNPAUSER-sent unpause PASSES auth + its role gate and clears is_paused to 0.
#[tokio::test]
async fn unpause_dom_unpauser_clears_is_paused() -> Result<()> {
    let (chain, faucet_id) = paused_faucet().await?;
    let note = stock_unpause_note(test_account_id(3), faucet_id, 61)
        .context("building the DOM_UNPAUSER unpause note")?;
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("DOM_UNPAUSER unpause tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("DOM_UNPAUSER unpause must succeed under network auth: {e}")
        })?;
    assert_eq!(
        value_delta(&tx, PausableStorage::is_paused_slot()),
        scalar_word(Felt::from(0u32)),
        "DOM_UNPAUSER unpause must clear is_paused to 0",
    );
    Ok(())
}

/// An unpause note without DOM_UNPAUSER PASSES auth but TRAPS at the role gate (owner included).
async fn assert_unpause_nonpauser_traps(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = stock_unpause_note(sender, faucet_id, seed)
        .context("building the unpause note without DOM_UNPAUSER")?;
    let result = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("unpause tx without DOM_UNPAUSER build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

#[tokio::test]
async fn unpause_administrator_traps() -> Result<()> {
    assert_unpause_nonpauser_traps(test_account_id(1), 62).await
}

#[tokio::test]
async fn unpause_third_party_traps() -> Result<()> {
    assert_unpause_nonpauser_traps(test_account_id(99), 63).await
}

#[tokio::test]
async fn unpause_dom_pauser_traps() -> Result<()> {
    assert_unpause_nonpauser_traps(test_account_id(2), 65).await
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the unpause effect.
#[tokio::test]
async fn unpause_note_args_are_inert() -> Result<()> {
    let (chain, faucet_id) = paused_faucet().await?;
    let note = stock_unpause_note(test_account_id(3), faucet_id, 64)
        .context("building the DOM_UNPAUSER unpause note")?;
    let bogus_args = Word::from([8u32, 8, 8, 8]);
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("unpause note-args tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("unpause with bogus NOTE_ARGS must still succeed: {e}"))?;
    assert_eq!(
        value_delta(&tx, PausableStorage::is_paused_slot()),
        scalar_word(Felt::from(0u32)),
        "unpause must clear is_paused=0 regardless of executor NOTE_ARGS",
    );
    Ok(())
}

// GRANT_ROLE (allowlist row 8) — STOCK RBAC grant (CANARY: a note calling a stock component proc)
// ================================================================================================

/// Authorized grant: `sender` grants DOM_PAUSER to id(4); the membership map is written. Proves the
/// note's absolute-path `call` resolves to the installed stock `rbac::grant_role` root (the canary).
async fn assert_grant_role_authorized(
    sender: AccountId,
    role: RoleSymbol,
    seed: u64,
) -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let grantee = test_account_id(4);
    let note = stock_grant_role_note(
        sender,
        faucet_id,
        role.clone(),
        grantee,
        &mut note_rng(seed),
    )
    .context("building the grant_role note")?;
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("grant_role tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("authorized grant_role must succeed under network auth: {e}")
        })?;
    let mut evolved = chain
        .committed_account(faucet_id)
        .context("committed faucet")?
        .clone();
    evolved.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved, &role, grantee)?,
        member_marker(),
        "authorized grant_role must make id(4) a role member",
    );
    Ok(())
}

/// The administrator directly grants DOM_PAUSER through its ADMIN membership.
#[tokio::test]
async fn grant_role_administrator_authorized() -> Result<()> {
    assert_grant_role_authorized(test_account_id(1), pauser_sym(), 70).await
}

/// A third party without ADMIN PASSES auth but TRAPS at the role-administration gate.
#[tokio::test]
async fn grant_role_third_party_traps() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = stock_grant_role_note(
        test_account_id(99),
        faucet_id,
        pauser_sym(),
        test_account_id(4),
        &mut note_rng(72),
    )
    .context("building the third-party grant_role note")?;
    let result = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("third-party grant_role tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_not_role_admin());
    Ok(())
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the granted membership.
#[tokio::test]
async fn grant_role_note_args_are_inert() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let grantee = test_account_id(5);
    // DOM_PAUSER's effective admin is ADMIN, so the grant is administrator-sent.
    let note = stock_grant_role_note(
        test_account_id(1),
        faucet_id,
        pauser_sym(),
        grantee,
        &mut note_rng(73),
    )
    .context("building the administrator grant_role note")?;
    let bogus_args = Word::from([7u32, 7, 7, 7]);
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("grant_role note-args tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("grant_role with bogus NOTE_ARGS must still succeed: {e}"))?;
    let mut evolved = chain
        .committed_account(faucet_id)
        .context("committed faucet")?
        .clone();
    evolved.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), grantee)?,
        member_marker(),
        "grant_role must write the storage-committed member regardless of executor NOTE_ARGS",
    );
    Ok(())
}

// SET_MAX_SUPPLY — administrator-gated stock max-supply setter, driven by the standard
// faucet-metadata config note (one script root carries all four metadata setters; only the max
// supply is built mutable)
// ================================================================================================

const NEW_MAX_SUPPLY: u64 = 2_000_000;

/// Owner-sent set_max_supply PASSES auth + the administrator Authority gate (the production faucet is
/// max-supply-mutable + unpaused) and writes word[1] (max_supply) of the token_config slot.
#[tokio::test]
async fn set_max_supply_administrator_writes_cap() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = stock_set_max_supply_note(test_account_id(1), faucet_id, NEW_MAX_SUPPLY, 90)
        .context("building the administrator set_max_supply note")?;
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("owner set_max_supply tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("owner-sent set_max_supply must succeed under network auth: {e}")
        })?;
    assert_eq!(
        value_delta(&tx, FungibleFaucet::token_config_slot())[1],
        Felt::try_from(NEW_MAX_SUPPLY).expect("cap within the field"),
        "owner set_max_supply must write word[1] = the new cap",
    );
    Ok(())
}

/// A set_max_supply note from a sender without ADMIN PASSES auth but TRAPS at the Authority gate.
async fn assert_set_max_supply_nonadmin_traps(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = stock_set_max_supply_note(sender, faucet_id, NEW_MAX_SUPPLY, seed)
        .context("building the non-administrator set_max_supply note")?;
    let result = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("non-administrator set_max_supply tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

#[tokio::test]
async fn set_max_supply_dom_pauser_traps() -> Result<()> {
    assert_set_max_supply_nonadmin_traps(test_account_id(2), 91).await
}

#[tokio::test]
async fn set_max_supply_dom_unpauser_traps() -> Result<()> {
    assert_set_max_supply_nonadmin_traps(test_account_id(3), 92).await
}

#[tokio::test]
async fn set_max_supply_third_party_traps() -> Result<()> {
    assert_set_max_supply_nonadmin_traps(test_account_id(99), 93).await
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the written cap.
#[tokio::test]
async fn set_max_supply_note_args_are_inert() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = stock_set_max_supply_note(test_account_id(1), faucet_id, NEW_MAX_SUPPLY, 94)
        .context("building the administrator set_max_supply note")?;
    let bogus_args = Word::from([3u32, 3, 3, 3]);
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("set_max_supply note-args tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("set_max_supply with bogus NOTE_ARGS must still succeed: {e}")
        })?;
    assert_eq!(
        value_delta(&tx, FungibleFaucet::token_config_slot())[1],
        Felt::try_from(NEW_MAX_SUPPLY).expect("cap within the field"),
        "set_max_supply must write the storage-committed cap regardless of executor NOTE_ARGS",
    );
    Ok(())
}

// REVOKE_ROLE (allowlist row 9) — STOCK RBAC revoke (needs a prior grant)
// ================================================================================================

/// A production faucet where id(4) has been granted DOM_PAUSER by the administrator, applied as a delta to an
/// evolved (not-committed) account. Returns (chain, faucet_id, evolved account, grantee).
async fn faucet_with_granted_role(
    role: RoleSymbol,
    grantor: AccountId,
    grant_seed: u64,
) -> Result<(MockChain, AccountId, Account, AccountId)> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let grantee = test_account_id(4);
    // Every role is administered directly by ADMIN.
    let grant = stock_grant_role_note(
        grantor,
        faucet_id,
        role.clone(),
        grantee,
        &mut note_rng(grant_seed),
    )
    .context("building the seeding grant note")?;
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(grant.clone())
        .build()
        .context("grant seed tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("seeding the administrator grant must succeed: {e}"))?;
    let mut evolved = chain
        .committed_account(faucet_id)
        .context("committed faucet")?
        .clone();
    evolved.apply_patch(tx.account_patch())?;
    Ok((chain, faucet_id, evolved, grantee))
}

/// Authorized revoke: the administrator revokes id(4)'s `role` membership, clearing the marker.
async fn assert_revoke_authorized(
    sender: AccountId,
    role: RoleSymbol,
    grantor: AccountId,
    grant_seed: u64,
    revoke_seed: u64,
) -> Result<()> {
    let (chain, faucet_id, evolved, grantee) =
        faucet_with_granted_role(role.clone(), grantor, grant_seed).await?;
    let note = stock_revoke_role_note(
        sender,
        faucet_id,
        role.clone(),
        grantee,
        &mut note_rng(revoke_seed),
    )
    .context("building the revoke note")?;
    let tx = chain
        .build_transaction(evolved.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .context("authorized revoke tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("authorized revoke must succeed under network auth: {e}"))?;
    let mut evolved2 = evolved.clone();
    evolved2.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved2, &role, grantee)?,
        Word::from([0u32, 0, 0, 0]),
        "authorized revoke must clear id(4)'s role membership",
    );
    Ok(())
}

/// The administrator grants and revokes DOM_PAUSER directly.
#[tokio::test]
async fn revoke_role_administrator_authorized() -> Result<()> {
    assert_revoke_authorized(
        test_account_id(1),
        pauser_sym(),
        test_account_id(1),
        110,
        100,
    )
    .await
}

/// A third party without ADMIN PASSES auth but TRAPS at the role-administration gate.
#[tokio::test]
async fn revoke_role_third_party_traps() -> Result<()> {
    let (chain, faucet_id, evolved, grantee) =
        faucet_with_granted_role(pauser_sym(), test_account_id(1), 112).await?;
    let note = stock_revoke_role_note(
        test_account_id(99),
        faucet_id,
        pauser_sym(),
        grantee,
        &mut note_rng(102),
    )
    .context("building the third-party revoke note")?;
    let result = chain
        .build_transaction(evolved)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("third-party revoke tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_not_role_admin());
    Ok(())
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the revocation.
#[tokio::test]
async fn revoke_role_note_args_are_inert() -> Result<()> {
    let (chain, faucet_id, evolved, grantee) =
        faucet_with_granted_role(pauser_sym(), test_account_id(1), 113).await?;
    // DOM_PAUSER's effective admin is ADMIN, so the revoke is administrator-sent.
    let note = stock_revoke_role_note(
        test_account_id(1),
        faucet_id,
        pauser_sym(),
        grantee,
        &mut note_rng(103),
    )
    .context("building the administrator revoke note")?;
    let bogus_args = Word::from([6u32, 6, 6, 6]);
    let tx = chain
        .build_transaction(evolved.clone())
        .unauthenticated_input_note(note.clone())
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("revoke note-args tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("revoke with bogus NOTE_ARGS must still succeed: {e}"))?;
    let mut evolved2 = evolved.clone();
    evolved2.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved2, &pauser_sym(), grantee)?,
        Word::from([0u32, 0, 0, 0]),
        "revoke must clear membership regardless of executor NOTE_ARGS",
    );
    Ok(())
}

// SET_ROLE_ADMIN — reachable through the standard role note, gated on the target role's own admin
// ================================================================================================

/// ADMIN can deliberately re-point a role on the production network account: network auth
/// admits the standard role root, the role's administration gate passes, and its admin field moves.
#[tokio::test]
async fn set_role_admin_administrator_authorized() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;

    let before = read_role_config(
        &chain
            .committed_account(faucet_id)
            .context("reading the committed faucet")?
            .clone(),
        &pauser_sym(),
    )?;
    assert_eq!(
        before[1],
        Felt::ZERO,
        "the build seed must administer DOM_PAUSER directly through ADMIN"
    );

    let note = stock_role_note(
        test_account_id(1),
        faucet_id,
        RbacConfig::SetRoleAdmin {
            role: pauser_sym(),
            admin_role: Some(blk_manager_sym()),
        },
        &mut note_rng(150),
    )
    .context("building the administrator set_role_admin note")?;
    let account = chain
        .committed_account(faucet_id)
        .context("reading the committed faucet")?
        .clone();
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("set_role_admin tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("the administrator's set_role_admin must succeed: {e}"))?;

    let mut evolved = account;
    evolved.apply_patch(tx.account_patch())?;
    let after = read_role_config(&evolved, &pauser_sym())?;
    assert_eq!(
        after[1],
        Felt::from(&blk_manager_sym()),
        "ADMIN must be able to re-point the role it administers",
    );
    assert_eq!(
        after[0], before[0],
        "re-pointing must preserve the role's member count",
    );
    Ok(())
}

/// A sender without ADMIN cannot re-point the administration of a seeded role.
async fn assert_set_role_admin_rejected(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let account = chain
        .committed_account(faucet_id)
        .context("reading the committed faucet")?
        .clone();
    let before = read_role_config(&account, &pauser_sym())?;

    let note = stock_role_note(
        sender,
        faucet_id,
        RbacConfig::SetRoleAdmin {
            role: pauser_sym(),
            admin_role: None,
        },
        &mut note_rng(seed),
    )
    .context("building the unauthorized set_role_admin note")?;
    let result = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("unauthorized set_role_admin tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_not_role_admin());
    assert_eq!(
        read_role_config(&account, &pauser_sym())?,
        before,
        "a rejected set_role_admin leaves the role config untouched",
    );
    Ok(())
}

#[tokio::test]
async fn set_role_admin_role_holder_rejects() -> Result<()> {
    assert_set_role_admin_rejected(test_account_id(3), 151).await
}

#[tokio::test]
async fn set_role_admin_third_party_rejects() -> Result<()> {
    assert_set_role_admin_rejected(test_account_id(99), 152).await
}

// RENOUNCE_ROLE — reachable through the standard role note, self-only and ungated
// ================================================================================================

/// A role holder drops its own membership on the production network account. No administrator is
/// involved: the standard procedure clears the membership of the note SENDER, and there is no
/// target argument it could be pointed at anyone else.
#[tokio::test]
async fn renounce_role_holder_clears_own_membership() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let account = chain
        .committed_account(faucet_id)
        .context("reading the committed faucet")?
        .clone();

    let note = stock_role_note(
        test_account_id(2),
        faucet_id,
        RbacConfig::RenounceRole { role: pauser_sym() },
        &mut note_rng(153),
    )
    .context("building the DOM_PAUSER renounce note")?;
    let tx = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("renounce tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("a holder's renounce of its own role must succeed: {e}"))?;

    let mut evolved = account;
    evolved.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), test_account_id(2))?,
        Word::from([0u32, 0, 0, 0]),
        "the holder must have dropped its own DOM_PAUSER membership",
    );
    assert_eq!(
        read_role_config(&evolved, &pauser_sym())?[0],
        Felt::ZERO,
        "the role must be left with no members",
    );
    Ok(())
}

/// An account that does not hold the role cannot renounce it — the standard procedure requires a
/// membership to clear, so the refusal is the membership assertion, not an admin gate.
#[tokio::test]
async fn renounce_role_non_holder_rejects() -> Result<()> {
    let pf = setup_production_faucet(0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;

    let note = stock_role_note(
        test_account_id(99),
        faucet_id,
        RbacConfig::RenounceRole { role: pauser_sym() },
        &mut note_rng(154),
    )
    .context("building the non-holder renounce note")?;
    let result = chain
        .build_transaction(faucet_id)
        .unauthenticated_input_note(note.clone())
        .build()
        .context("non-holder renounce tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_account_not_in_role());
    Ok(())
}
