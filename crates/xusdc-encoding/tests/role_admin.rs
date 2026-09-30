//! Role administration: ADMIN directly appoints and removes the Domain Pauser.
//!
//! The builder seeds ADMIN, ATTEST_ADMIN, DOM_PAUSER, DOM_UNPAUSER and BLK_MANAGER, each
//! administered directly by ADMIN. The Domain Pauser can halt the faucet; the Domain Unpauser
//! can resume it. The standard role-action note can deliberately re-point administration later.
//!
//! The rotation seams prove capability: an administrator grant lets the new pauser halt a real
//! attested mint, and a revoke removes its pause power. The role graph read-back pins the initial
//! configuration and all five memberships alongside those executable checks.
//!
//! Every test uses the production builder. The support replica's fidelity is pinned separately in
//! `set_min_burn.rs::support_replica_matches_the_production_role_seed`.

mod support;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{AccountId, RoleSymbol};
use miden_protocol::errors::MasmError;
use miden_protocol::note::Note;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_standards::note::config::{RbacConfig, RbacConfigNote};
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::DOM_PAUSER_ROLE;
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;
use xusdc_encoding::note::xreserve_mint::DepositAttestation;
use xusdc_encoding::vectors::{load, MiVector};
use xusdc_encoding::xreserve::encoding::Signature;

// The production builder seeds ADMIN / ATTEST_ADMIN = id(1), DOM_PAUSER = id(2),
// DOM_UNPAUSER = id(3), BLK_MANAGER = id(4). The rotation grants DOM_PAUSER to id(4).
fn administrator() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn new_pauser() -> AccountId {
    test_account_id(4)
}

// The fixed role aliases, via the production Rust constants (builder.rs) — the single source the
// seed, the notes, and the read-backs all share.
fn pauser_sym() -> RoleSymbol {
    RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol (<=12)")
}

// The exact stock errors these tests pin (assert-specific-error-in-tests; read from the pinned
// rbac.masm:50-51 / the stock pausable).
fn err_paused() -> MasmError {
    MasmError::from_static_str("the contract is paused")
}
fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}

// PRODUCTION FIXTURES (both compose via XReserveStablecoinBuilder::build_components — never the
// burn-oracle replica). Recreated from public support helpers per the established per-file pattern
// (set_attester.rs `guarded_faucet`, pause_admin.rs `guarded_mint_ready` are private to their files).
// ================================================================================================

/// Placeholder domain configuration. These tests reach the account through role-administration
/// notes and never run a mint, so nothing ever reads these words — they exist because the fixture
/// requires a value.
fn dummy_config() -> Word {
    Word::from([7u32, 0, 0, 0])
}

/// A do-nothing component that satisfies the shared fixture's requirement for a driver.
///
/// The gating tests never invoke it — they drive the account through notes — so it only has to
/// compile.
fn placeholder_driver_src() -> String {
    "#! Test driver stand-in: never invoked by this suite (the custom mint entry was deleted by\n\
     #! the Wave-1 S1 recomposition); the guarded fixture only requires a compilable component.\n\
     #!\n\
     #! Inputs:  [pad(16)]\n\
     #! Outputs: [pad(16)]\n\
     #!\n\
     #! Invocation: call\n\
     @account_procedure\n\
     pub proc drive\n\
     \x20\x20\x20\x20push.0 drop\n\
     end\n"
        .to_string()
}

/// The LEAN production faucet — the base for the gating-matrix cells that never execute a mint.
fn production_faucet() -> Result<GuardedMint> {
    let driver = placeholder_driver_src();
    let probe = composition_supply_probe_src(0);
    let domain = dummy_config();
    setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
        1_000_000,
        0,
        domain,
        None,
        None,
        &driver,
        &probe,
        true,
    )
}

// FIXTURES FOR THE CAPABILITY SEAMS — a real attested mint through the real note transport, so a
// pause can be shown to halt something that would otherwise succeed (same shape as mint_policy_e2e.rs)
// ================================================================================================

// the DC-14 rows are the ones whose localToken / localDepositor are address-shaped,
// which the mint transport requires
const BASE_VECTOR: &str = "mi-pos-empty-hookdata";
const MINT_AMOUNT: u64 = 250_000_000;
const MAX_FEE_RAW: u64 = 1;

/// Byte offset of the 32-byte `remoteRecipient` field in a DepositIntent (felt 19, 4 bytes/felt).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
/// Byte offset of the 32-byte `remoteToken` field in a DepositIntent (felt 11, 4 bytes/felt).
const REMOTE_TOKEN_BYTE_OFF: usize = 11 * 4;
/// Byte offset of the 32-byte `nonce` field in a DepositIntent (felt 51, 4 bytes/felt).
const NONCE_BYTE_OFF: usize = 51 * 4;

fn mi(id: &str) -> &'static MiVector {
    load()
        .families
        .mi
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing mp vector {id}"))
}

/// The canonical accept payload with the wire amount / maxFee spliced in, `remoteRecipient`
/// replaced by the real recipient wallet, `remoteToken` replaced by
/// `EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()` (the own-id key the mint path derives, so the identifier
/// compare passes), and one nonce byte perturbed per variant so each mint consumes
/// a nonce the replay guard has not seen.
fn payload_for(
    recipient: AccountId,
    amount: u64,
    nonce_variant: u8,
    faucet_id: AccountId,
) -> Vec<u8> {
    let mut payload = mi(BASE_VECTOR).payload();
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(amount));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(MAX_FEE_RAW));
    payload[REMOTE_RECIPIENT_BYTE_OFF..REMOTE_RECIPIENT_BYTE_OFF + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(recipient).to_bytes32());
    payload[REMOTE_TOKEN_BYTE_OFF..REMOTE_TOKEN_BYTE_OFF + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32());
    payload[NONCE_BYTE_OFF] ^= nonce_variant;
    payload
}

/// Deterministic note rng for the production admin/mint notes (serial only; never affects a gate).
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]))
}

/// A standard role-action note carrying `action`, sent by `sender` and tagged for `faucet_id`. The
/// serial is derived from `seed` so note ids stay stable; the gate reads the sender, never the
/// serial or the tag.
fn role_action_note(
    sender: AccountId,
    faucet_id: AccountId,
    action: RbacConfig,
    seed: u32,
) -> Result<Note> {
    let note = RbacConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(action)
        .serial_number(Word::from([seed, 3, 4, 5]))
        .build()
        .map_err(|e| anyhow::anyhow!("building the standard role-action note: {e}"))?;
    Ok(Note::from(note))
}

/// A standard role-action note granting the Domain Pauser role to `member`.
fn grant_role_note(
    sender: AccountId,
    faucet_id: AccountId,
    member: AccountId,
    seed: u32,
) -> Result<Note> {
    role_action_note(
        sender,
        faucet_id,
        RbacConfig::GrantRole {
            role: pauser_sym(),
            account: member,
        },
        seed,
    )
}

/// A standard role-action note revoking the Domain Pauser role from `member`.
fn revoke_role_note(
    sender: AccountId,
    faucet_id: AccountId,
    member: AccountId,
    seed: u32,
) -> Result<Note> {
    role_action_note(
        sender,
        faucet_id,
        RbacConfig::RevokeRole {
            role: pauser_sym(),
            account: member,
        },
        seed,
    )
}

/// Brings up a production faucet ready to run a real mint, for the tests that check what a
/// rotated role can and cannot do.
///
/// It uses the real note transport and the account's own network authentication, allowlists one
/// attester, and adds whatever extra admin notes the caller needs. Everything is seeded at genesis so each admin transaction can be proved
/// into its own block. The same shape is used by `mint_policy_e2e.rs`.
fn mint_fixture(extra_notes: impl Fn(AccountId) -> Vec<Note>) -> Result<ProductionFaucet> {
    setup_production_faucet(0, |recipient, faucet_id| {
        let commitment =
            gen_attester(1, &payload_for(recipient, MINT_AMOUNT, 0, faucet_id)).commitment;
        let route = faucet_id;
        let mut notes = vec![XReserveSetAttesterNote::create(
            administrator(),
            route,
            commitment,
            1,
            &mut note_rng(952),
        )
        .expect("building the administrator set_attester note")];
        notes.extend(extra_notes(faucet_id));
        notes
    })
}

/// Consumes the seeded bring-up notes `0..count`, committing a block each.
async fn bring_up(pf: &mut ProductionFaucet, count: usize) -> Result<()> {
    for (i, note) in pf.seeded_notes.clone().iter().take(count).enumerate() {
        let tx = pf
            .mock_chain
            .build_transaction(pf.faucet_id)
            .authenticated_input_note(note.id())
            .build()
            .with_context(|| format!("bring-up note {i}: tx build"))?
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("bring-up note {i} must succeed: {e}"))?;
        pf.mock_chain.add_pending_executed_transaction(&tx)?;
        pf.mock_chain.prove_next_block()?;
    }
    Ok(())
}

/// Consumes a committed (seeded) note on the faucet, returning the raw result so callers assert
/// success or the exact trap. A REJECTED consume leaves the note unspent, so the SAME note can be
/// re-consumed after a capability change — exactly the rotation-seam artifact.
async fn consume_note(
    pf: &ProductionFaucet,
    note: &Note,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    pf.mock_chain
        .build_transaction(pf.faucet_id)
        .authenticated_input_note(note.id())
        .build()
        .expect("building the consume tx")
        .execute()
        .await
}

/// Consumes a committed note expecting success, committing a block.
async fn consume_and_commit(pf: &mut ProductionFaucet, note: &Note, what: &str) -> Result<()> {
    let tx = consume_note(pf, note)
        .await
        .map_err(|e| anyhow::anyhow!("{what}: {e}"))?;
    pf.mock_chain.add_pending_executed_transaction(&tx)?;
    pf.mock_chain.prove_next_block()?;
    Ok(())
}

/// Builds, emits, and consumes the REAL stock mint note over an attested payload (the production
/// `XUsdcMintNote` factory transport), returning the consume result.
async fn emit_and_consume_mint(
    pf: &mut ProductionFaucet,
    payload: &[u8],
    rng_seed: u64,
) -> Result<std::result::Result<ExecutedTransaction, TransactionExecutorError>> {
    let attester = gen_attester(1, payload);
    let note = mint_note_from_payload(
        pf.producer_id,
        pf.faucet_id,
        payload,
        DepositAttestation::new(Signature::new(attester.sig_bytes), attester.pubkey.clone()),
        &mut note_rng(rng_seed),
    )?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    Ok(pf
        .mock_chain
        .build_transaction(pf.faucet_id)
        .authenticated_input_note(note.id())
        .build()
        .context("building the mint consume tx")?
        .execute()
        .await)
}

// THE ROTATION SEAMS — role administration must change REAL pause capability, end-to-end
// ================================================================================================

/// The grant seam: before the grant, id(4) has no pause power (exact role trap on the seeded
/// production pause note); an administrator-sent
/// `grant_role(DOM_PAUSER, id4)` then flips REAL capability — the SAME pause note (left unspent by
/// the rejected consume) now succeeds, and id(4)'s pause HALTS a real attested mint (the
/// recomposed stock-`MintNote` transport) at the exact `ERR_PAUSABLE_IS_PAUSED`.
#[tokio::test]
async fn administrator_grants_pauser_then_new_pauser_halts_mint() -> Result<()> {
    let mut pf = mint_fixture(|faucet_id| {
        vec![
            grant_role_note(administrator(), faucet_id, new_pauser(), 31)
                .expect("building the administrator grant_role note"),
            stock_pause_note(new_pauser(), faucet_id, 32)
                .expect("building the candidate's pause note"),
        ]
    })?;
    bring_up(&mut pf, 1).await?; // set_attester
    let grant_note = pf.seeded_notes[1].clone();
    let pause_note = pf.seeded_notes[2].clone();

    // Pre-grant: the candidate's pause REJECTS — the capability is genuinely absent before the grant.
    let pre = consume_note(&pf, &pause_note).await;
    assert_transaction_executor_error!(pre, err_sender_lacks_role());

    // The administrator grants DOM_PAUSER to id(4) directly.
    consume_and_commit(&mut pf, &grant_note, "the administrator grant must pass").await?;
    let faucet = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    assert_eq!(
        read_role_membership(&faucet, &pauser_sym(), new_pauser())?[0],
        Felt::from(1u32),
        "the administrator grant landed the membership flag"
    );

    // The SAME pause note now succeeds...
    consume_and_commit(
        &mut pf,
        &pause_note,
        "the newly granted DOM_PAUSER member's pause must succeed",
    )
    .await?;

    // ...and HALTS the real attested mint at the exact stock pause error — the capability change
    // is REAL.
    let payload = payload_for(pf.recipient_id, MINT_AMOUNT, 1, pf.faucet_id);
    let result = emit_and_consume_mint(&mut pf, &payload, 33).await?;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// The revoke seam: an administrator-sent `revoke_role(DOM_PAUSER, id2)` strips the seeded
/// pauser's power. Its pause rejects the exact role error and leaves `is_paused` untouched;
/// membership clears, member_count becomes zero, and administration stays on ADMIN.
#[tokio::test]
async fn administrator_revokes_pauser_then_pause_rejects() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        administrator(),
        &pauser_sym(),
        dom_pauser(),
        34,
    )
    .await
    .expect("the administrator revoke passes");
    let mut evolved = account.clone();
    evolved.apply_patch(revoked.account_patch())?;

    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), dom_pauser())?[0],
        Felt::ZERO,
        "the revoked member's membership flag is cleared"
    );
    let config = read_role_config(&evolved, &pauser_sym())?;
    assert_eq!(
        config[0],
        Felt::ZERO,
        "DOM_PAUSER member_count decremented to 0"
    );
    assert_eq!(
        config[1],
        Felt::ZERO,
        "ADMIN remains the effective admin after the last-member revoke"
    );

    // The revoked member's pause now REJECTS with the exact role error; is_paused is unchanged.
    let result = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, dom_pauser(), 35).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&evolved)?[0],
        Felt::ZERO,
        "a failed pause leaves is_paused untouched"
    );
    Ok(())
}

/// The full rotation, revoke first: ADMIN revokes the incumbent id(2) (member_count -> 0), then
/// grants the successor id(4). The old pauser's pause rejects; the new pauser's pause halts a real
/// attested mint through the stock `MintNote` transport.
#[tokio::test]
async fn administrator_rotates_pauser_revoke_then_grant() -> Result<()> {
    let mut pf = mint_fixture(|faucet_id| {
        let route = faucet_id;
        vec![
            revoke_role_note(administrator(), route, dom_pauser(), 36)
                .expect("building the administrator revoke_role note"),
            grant_role_note(administrator(), route, new_pauser(), 37)
                .expect("building the administrator grant_role note"),
            stock_pause_note(dom_pauser(), route, 38)
                .expect("building the OLD pauser's pause note"),
            stock_pause_note(new_pauser(), route, 39)
                .expect("building the NEW pauser's pause note"),
        ]
    })?;
    bring_up(&mut pf, 1).await?; // set_attester
    let revoke_note = pf.seeded_notes[1].clone();
    let grant_note = pf.seeded_notes[2].clone();
    let old_pause_note = pf.seeded_notes[3].clone();
    let new_pause_note = pf.seeded_notes[4].clone();

    consume_and_commit(
        &mut pf,
        &revoke_note,
        "the rotation's revoke leg must pass under ADMIN",
    )
    .await?;
    consume_and_commit(
        &mut pf,
        &grant_note,
        "the rotation's grant leg must pass through the empty role (admin config retained)",
    )
    .await?;

    // The OLD pauser's pause rejects — rotation genuinely removed the incumbent's power.
    let old = consume_note(&pf, &old_pause_note).await;
    assert_transaction_executor_error!(old, err_sender_lacks_role());

    // The NEW pauser pauses, and the pause halts a REAL attested mint.
    consume_and_commit(
        &mut pf,
        &new_pause_note,
        "the rotated-in DOM_PAUSER member's pause must succeed",
    )
    .await?;
    let payload = payload_for(pf.recipient_id, MINT_AMOUNT, 2, pf.faucet_id);
    let result = emit_and_consume_mint(&mut pf, &payload, 40).await?;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

// THE SHIPPED ROLE GRAPH — what the builder wrote, read back off a production account
// ================================================================================================

/// The production seed has five populated roles administered directly by ADMIN.
#[tokio::test]
async fn shipped_role_graph_reads_back() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);
    let marker = Word::from([1u32, 0, 0, 0]);

    for (name, holder) in [
        ("ADMIN", 1),
        ("ATTEST_ADMIN", 1),
        ("DOM_PAUSER", 2),
        ("DOM_UNPAUSER", 3),
        ("BLK_MANAGER", 4),
    ] {
        let role = RoleSymbol::new(name)?;
        assert_eq!(
            read_role_config(&account, &role)?,
            marker,
            "{name} has one member and resolves directly to ADMIN"
        );
        assert_eq!(
            read_role_membership(&account, &role, test_account_id(holder))?,
            marker,
            "{name} is seeded on id({holder})"
        );
    }
    assert_eq!(
        read_role_config(&account, &RoleSymbol::new("DOM_MANAGER")?)?,
        Word::empty(),
        "the retired role is absent"
    );
    Ok(())
}
