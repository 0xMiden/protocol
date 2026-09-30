//! The emergency halt: who can pause the faucet, and what pausing actually stops.
//!
//! Circle's model gives pausing to a dedicated Domain Pauser and gives the administrator no direct
//! pause path at all. That is expressed entirely through composition: the faucet installs the
//! standard `PausableManager` and maps pause to Domain Pauser and unpause to Domain Unpauser in the
//! account's procedure-role map, so it ships no pause MASM of its own — an absence one test here
//! pins directly against the assembled library. The administrator's two rejections are therefore
//! role-assertion failures, and their exact error is what proves the map is really doing the
//! gating rather than the capability having fallen back to the administrator.
//!
//! Everything else about the standard manager — its authorization matrix, and the fact that its
//! writes are unconditional — belongs to `miden-standards` and is tested there.
//!
//! The load-bearing proof is not that pausing flips a flag — it is that pausing HALTS the faucet.
//! A real attested mint and a real burn are both driven against a paused faucet and both trap with
//! the standard paused error, because the standard mint and burn wrappers check the pause flag
//! before they run their policies. Both resume after unpause. That covers Circle's requirement
//! that a pause stops deposits and withdrawals alike.
//!
//! Those halt tests double as guards on the `is_paused` slot's provenance: the slot is installed
//! by the base pausable component the builder adds, never by the manager (which installs no
//! storage at all). If the slot ever went missing, the halt would silently stop happening.

mod support;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::errors::MasmError;
use miden_protocol::note::Note;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;
use xusdc_encoding::note::xreserve_mint::DepositAttestation;
use xusdc_encoding::vectors::{load, MiVector};
use xusdc_encoding::xreserve::encoding::Signature;

/// Deterministic note rng for the production admin notes (serial only; never affects the gate).
fn prod_note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]))
}

// The production builder seeds the administrator = id(1) (the sole seeded `ADMIN` member) and
// DOM_PAUSER = id(2), DOM_UNPAUSER = id(3).
fn administrator() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn dom_unpauser() -> AccountId {
    test_account_id(3)
}

// Burn-faucet parameters (mirrors set_min_burn.rs).
const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
const MIN_BURN_SIZE: u64 = 1_000;
const VALID_BURN: u64 = 5_000;

// The exact stock pause / role errors these tests pin (assert-specific-error-in-tests).
fn err_paused() -> MasmError {
    MasmError::from_static_str("the contract is paused")
}
// MINT-SEAM FIXTURES (the recomposed REAL stock-MintNote transport — mirrors mint_policy_e2e.rs)
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

/// A do-nothing component that satisfies the shared fixture's requirement for a driver.
///
/// The fixture used by the standard-pause negative probes takes a driver component, but those
/// probes never invoke it — they only need the account to build. Rather than assemble a real mint
/// driver for tests that will not call it, this supplies something that merely compiles.
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

/// A PRODUCTION-composed faucet under permissive (IncrNonce) auth — the fixture for the stock-pause
/// negative probes, where the missing stock PROC (not note-script auth) must be what fails.
fn production_pause_fixture() -> Result<GuardedMint> {
    let driver = placeholder_driver_src();
    let probe = composition_supply_probe_src(0);
    setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
        MAX_SUPPLY,
        0,
        Word::from([Felt::from(TEST_DOMAIN), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        None,
        None,
        &driver,
        &probe,
        true,
    )
}

/// Brings up a production faucet ready to run a real mint, for the tests that check a pause
/// actually halts one.
///
/// It uses the real note transport and the account's own network authentication, seeds the domain
/// allowlists one attester, and adds whatever extra admin
/// notes the caller needs. Everything is seeded at genesis so each admin transaction can be proved
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
            &mut prod_note_rng(952),
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

/// Builds the REAL stock mint note over an attested payload (the production `XUsdcMintNote`
/// factory transport: intent + attestation + routing attachments).
fn attested_mint_note(pf: &ProductionFaucet, payload: &[u8], rng_seed: u64) -> Result<Note> {
    let attester = gen_attester(1, payload);
    mint_note_from_payload(
        pf.producer_id,
        pf.faucet_id,
        payload,
        DepositAttestation::new(Signature::new(attester.sig_bytes), attester.pubkey.clone()),
        &mut prod_note_rng(rng_seed),
    )
}

/// Emits the attested mint note from the producer and consumes it on the faucet by id (the REAL
/// stock-note transport), returning the consume result for success- or exact-trap assertions.
async fn emit_and_consume_mint(
    pf: &mut ProductionFaucet,
    payload: &[u8],
    rng_seed: u64,
) -> Result<std::result::Result<ExecutedTransaction, TransactionExecutorError>> {
    let note = attested_mint_note(pf, payload, rng_seed)?;
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

/// Reads the committed `token_supply` (token_config word element 0) of a burn faucet.
fn token_supply_of(account: &Account) -> Result<Felt> {
    Ok(read_token_config(account)?[0])
}

// EXPORT PROBE — the faucet library ships no pause procedure of its own
// ================================================================================================

#[test]
fn the_xreserve_library_exports_no_pause_procedure() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    assert!(
        !exports.iter().any(|e| e.contains("pause")),
        "pausing is the stock manager's job now; the faucet library must export no pause \
         procedure of its own, or two pause surfaces would exist. exports: {exports:?}"
    );
    Ok(())
}

// PAUSE-HALT SEAM — the non-vacuity must-have: a pause HALTS the real mint AND the real burn
// ================================================================================================

/// The administrator has no pause path.
///
/// The standard pause manager IS installed now, so the rejection is an authorization check rather
/// than a missing procedure: the account's procedure-role map gates `pause` on the Domain pauser
/// role, the administrator does not hold it, and the role assertion traps. What matters is that the outcome
/// is unchanged — the administrator cannot pause, and `is_paused` is left untouched.
///
/// The exact error is the point. A missing-procedure failure would now mean the manager was dropped
/// from the composition; anything other than the role error would mean the map is not gating this
/// procedure at all, and the capability had quietly fallen back to the administrator role — which
/// the administrator does hold.
#[tokio::test]
async fn administrator_has_no_pause_path() -> Result<()> {
    let gm = production_pause_fixture()?;
    let account = faucet_account(&gm.harness);

    let result = run_pause_against(&gm.harness.mock_chain, &account, administrator(), 5).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&account)?,
        Word::from([0u32, 0, 0, 0]),
        "a rejected pause leaves is_paused unpaused"
    );
    Ok(())
}

/// The unpause twin: the Domain pauser pauses first (the flag REALLY flips), then an administrator-sent
/// unpause note fails with the EXACT role error and the faucet STAYS paused — an administrator who could
/// unpause would visibly clear the flag.
#[tokio::test]
async fn administrator_has_no_unpause_path() -> Result<()> {
    let gm = production_pause_fixture()?;
    let account = faucet_account(&gm.harness);

    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "precondition: the DOM_PAUSER pause really flipped is_paused"
    );

    let result =
        run_stock_unpause_against(&gm.harness.mock_chain, &evolved, administrator(), 6).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "a rejected unpause leaves the faucet paused"
    );
    Ok(())
}

/// A DOM_PAUSER-triggered pause HALTS the real mint: the seeded standard pause-action note
/// (DOM_PAUSER-sent, consumed by id under the network auth) pauses the faucet, then a REAL attested
/// stock mint note (the recomposed transport, emitted and consumed by id) traps the EXACT
/// `ERR_PAUSABLE_IS_PAUSED` at the policy dispatcher's stock pause gate — fail-closed (no supply
/// raised).
#[tokio::test]
async fn dom_pauser_pause_halts_mint() -> Result<()> {
    let mut pf = mint_fixture(|faucet_id| {
        vec![stock_pause_note(dom_pauser(), faucet_id, 7)
            .expect("building the DOM_PAUSER pause note")]
    })?;
    bring_up(&mut pf, 2).await?; // set_attester + pause
    assert_eq!(
        read_is_paused(&pf.mock_chain.committed_account(pf.faucet_id)?.clone())?,
        Word::from([1u32, 0, 0, 0]),
        "precondition: the DOM_PAUSER pause really flipped is_paused"
    );

    let payload = payload_for(pf.recipient_id, MINT_AMOUNT, 1, pf.faucet_id);
    let result = emit_and_consume_mint(&mut pf, &payload, 71).await?;
    assert_transaction_executor_error!(result, err_paused());
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(0)?,
        "a halted mint must not raise supply"
    );
    Ok(())
}

/// The shipped, allowlisted standard pause-action note, sent by the Domain Pauser, HALTS the real attested
/// mint through the UNAUTHENTICATED-note transport: the pause note executes as an unauthenticated
/// input (never block-committed first — routing target a placeholder PUBLIC id, routing-only), its
/// `is_paused=1` delta is applied to the evolved faucet, and the REAL stock mint note consumed
/// (unauthenticated) against that paused faucet traps the exact stock pause error — the emergency
/// stop reaches the mint gate whichever note transport carries it.
#[tokio::test]
async fn dom_pauser_production_pause_note_halts_mint() -> Result<()> {
    let mut pf = mint_fixture(|_| vec![])?;
    bring_up(&mut pf, 1).await?; // set_attester

    let account = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    let note = stock_pause_note(dom_pauser(), pf.faucet_id, 8)?;
    let paused = pf
        .mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("production pause tx build")
        .execute()
        .await
        .expect("the DOM_PAUSER production pause note pauses the mint faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "precondition: the production pause note really flipped is_paused"
    );

    let payload = payload_for(pf.recipient_id, MINT_AMOUNT, 2, pf.faucet_id);
    let mint_note = attested_mint_note(&pf, &payload, 72)?;
    let result = pf
        .mock_chain
        .build_transaction(evolved)
        .unauthenticated_input_note(mint_note.clone())
        .build()
        .expect("mint consume tx build")
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// The shipped, allowlisted standard pause-action note HALTS the real burn — the note-driven twin of
/// `dom_pauser_pause_halts_burn`, which pauses through the procedure directly.
#[tokio::test]
async fn dom_pauser_production_pause_note_halts_burn() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = bh;

    // Block N: the user emits + commits the (valid-amount) burn note (faucet not yet paused).
    let tx0 = try_emit_burn_note(&chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("the user emits the burn note (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    // The DOM_PAUSER production pause note pauses the faucet; apply its delta to the evolved account.
    let account = chain.committed_account(faucet_id)?.clone();
    let note = stock_pause_note(dom_pauser(), faucet_id, 8)?;
    let paused = chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("production pause tx build")
        .execute()
        .await
        .expect("the DOM_PAUSER production pause note pauses the burn faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;

    // The faucet consumes the committed burn note against the paused account → assert_not_paused traps.
    let result = chain
        .build_transaction(evolved)
        .authenticated_input_note(burn_note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// A DOM_PAUSER-triggered pause HALTS the real burn: DOM_PAUSER pauses, then a real `receive_and_burn`
/// traps the EXACT `ERR_PAUSABLE_IS_PAUSED` (execute_burn_policy's stock pause gate). RED: the pause
/// placeholder traps first.
#[tokio::test]
async fn dom_pauser_pause_halts_burn() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = bh;

    // Block N: the user emits + commits the (valid-amount) burn note (faucet not yet paused).
    let tx0 = try_emit_burn_note(&chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("the user emits the burn note (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    // DOM_PAUSER pauses the faucet; evolve the committed faucet with the (uncommitted) pause delta.
    let account = chain.committed_account(faucet_id)?.clone();
    let paused = run_dom_pauser_pause(&chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the burn faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;

    // The faucet consumes the committed burn note against the paused account → execute_burn_policy's
    // assert_not_paused traps the stock pause error (the valid amount isolates the pause gate).
    let result = chain
        .build_transaction(evolved)
        .authenticated_input_note(burn_note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// UNPAUSE RESUMES both surfaces: after a DOM_PAUSER pause and DOM_UNPAUSER unpause (both seeded
/// production admin notes), a REAL attested stock mint emits one recipient note and raises
/// token_supply by the attested amount, AND a real burn decrements token_supply.
#[tokio::test]
async fn dom_pauser_unpause_resumes_mint_and_burn() -> Result<()> {
    // --- mint side ---
    let mut pf = mint_fixture(|faucet_id| {
        vec![
            stock_pause_note(dom_pauser(), faucet_id, 9)
                .expect("building the DOM_PAUSER pause note"),
            stock_unpause_note(dom_unpauser(), faucet_id, 10)
                .expect("building the DOM_UNPAUSER unpause note"),
        ]
    })?;
    bring_up(&mut pf, 3).await?; // set_attester + pause + unpause
    assert_eq!(
        read_is_paused(&pf.mock_chain.committed_account(pf.faucet_id)?.clone())?,
        Word::from([0u32, 0, 0, 0]),
        "precondition: the pause→unpause round trip leaves the faucet unpaused"
    );

    let payload = payload_for(pf.recipient_id, MINT_AMOUNT, 3, pf.faucet_id);
    let minted = emit_and_consume_mint(&mut pf, &payload, 73)
        .await?
        .map_err(|e| anyhow::anyhow!("after unpause, the real attested mint mints again: {e}"))?;
    assert_eq!(
        minted.output_notes().num_notes(),
        1,
        "unpause resumes minting (one recipient note)"
    );
    pf.mock_chain.add_pending_executed_transaction(&minted)?;
    pf.mock_chain.prove_next_block()?;
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(MINT_AMOUNT)?,
        "token_supply rose by exactly the attested amount"
    );

    // --- burn side ---
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = bh;
    let tx0 = try_emit_burn_note(&chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("the user emits the burn note (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    let bacct = chain.committed_account(faucet_id)?.clone();
    let bpaused = run_dom_pauser_pause(&chain, &bacct, dom_pauser(), 7)
        .await
        .expect("DOM_PAUSER pauses the burn faucet");
    let mut bevolved = bacct.clone();
    bevolved.apply_patch(bpaused.account_patch())?;
    let bunpaused = run_dom_pauser_unpause(&chain, &bevolved, dom_unpauser(), 8)
        .await
        .expect("DOM_UNPAUSER unpauses the burn faucet");
    bevolved.apply_patch(bunpaused.account_patch())?;

    // The faucet consumes the committed burn note against the UNPAUSED account → the burn succeeds.
    let burned = chain
        .build_transaction(bevolved.clone())
        .authenticated_input_note(burn_note.id())
        .build()?
        .execute()
        .await
        .expect("after unpause, the real receive_and_burn decrements supply");
    let mut bfinal = bevolved.clone();
    bfinal.apply_patch(burned.account_patch())?;
    assert_eq!(
        token_supply_of(&bfinal)?,
        Felt::from((TOKEN_SUPPLY - VALID_BURN) as u32),
        "unpause resumes burning (token_supply decremented by the burn amount)"
    );
    Ok(())
}
