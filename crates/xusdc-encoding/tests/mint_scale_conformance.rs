//! DEPOSIT-SCALE CONFORMANCE: the Circle-anchored amount pin on the PRODUCTION mint path.
//!
//! The coverage hole this closes: every other amount assertion in the suite round-trips its OWN
//! scale — the golden vectors compute the expected quotient with the same `scale_exp` they encode,
//! and the composition/e2e drivers inject a TEST-SIDE `scale_exp` straight into
//! `mint_composition_driver_src(...)`. Both are green for ANY value of the faucet's
//! `DEPOSIT_SCALE_EXP`, which is how an incorrect scale stayed deploy-reachable.
//!
//! Everything here instead rides the REAL stock `MintNote` (built by the `XUsdcMintNote`
//! factory) consumed by the production faucet, so the only scale in play is the
//! `DEPOSIT_SCALE_EXP` the shipped `deposit_intent_parser.masm` amount/fee stage applies.
//! NOTHING in this file injects,
//! derives, or even names a test-side scale — grep-provable, and deliberately so: the assertions
//! below are only meaningful because they depend on the production constant.
//!
//! THE INVARIANT (the PROVISIONAL scale-0 position — the cap/scale/dust decision stays OPEN,
//! pending Circle confirmation):
//! Circle's on-wire deposit `amount` is denominated in xUSDC smallest units (6 decimals) and the
//! Miden xUSDC asset is 6-decimal, so the faucet mints `y = x` — `DEPOSIT_SCALE_EXP = 0`,
//! `y = floor(x / 10^0)`, an identity with no rescale and no dust. Just-inside/just-outside intuition: at `DEPOSIT_SCALE_EXP = 0` a wire amount of
//! `100_000_000` (= 100.000000 USDC) mints `100_000_000` smallest units (GREEN); at the former
//! placeholder `= 6` the same deposit would mint `100_000_000 / 10^6 = 100` smallest units — a
//! 100-USDC deposit landing as 0.000100 xUSDC, 10^6 too small (RED). The non-round amounts below
//! sharpen it further: any nonzero scale floors the low digits away, so `123_456_789` mints
//! `123` at `= 6` and `12_345_678` at `= 1`; only `= 0` returns the input verbatim.

mod support;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::note::{NoteId, NoteType};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_testing::MockChain;
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;
use xusdc_encoding::note::xreserve_mint::DepositAttestation;
use xusdc_encoding::vectors::{load, MiVector};
use xusdc_encoding::xreserve::encoding::{bytes32_to_storage_map_key, Signature};

// CIRCLE-FORMAT FIXTURE VALUES
// ================================================================================================

// the DC-14 rows are the ones whose localToken / localDepositor are address-shaped,
// which the mint transport requires
const BASE_VECTOR: &str = "mi-pos-empty-hookdata";

/// The headline Circle deposit: 100.000000 USDC expressed in 6-decimal smallest units. Written as
/// a literal on purpose — it is a WIRE value, not something derived from any local scale constant.
const CIRCLE_DEPOSIT_100_USDC: u64 = 100_000_000;

/// A deposit whose low decimal digits are NOT a multiple of any power of ten above 1 — it can only
/// survive the mint intact if the faucet applies no rescale at all (123.456789 USDC).
const CIRCLE_DEPOSIT_NON_ROUND: u64 = 123_456_789;

/// The smallest representable Circle deposit: one smallest unit (0.000001 USDC). Any nonzero scale
/// floors this to ZERO.
const CIRCLE_DEPOSIT_ONE_UNIT: u64 = 1;

/// Just under one whole USDC (0.999999) — floors to zero at any scale >= 6.
const CIRCLE_DEPOSIT_SUB_UNIT: u64 = 999_999;

/// The sweep, in mint order. Distinct nonces are derived per index below.
const CIRCLE_DEPOSITS: [u64; 4] = [
    CIRCLE_DEPOSIT_100_USDC,
    CIRCLE_DEPOSIT_NON_ROUND,
    CIRCLE_DEPOSIT_ONE_UNIT,
    CIRCLE_DEPOSIT_SUB_UNIT,
];

/// `maxFee` in the SAME 6-decimal wire units. Kept at or below the smallest swept deposit so
/// the amount-covers-fee reject (`amount >= maxFee`) holds for every case at every scale — the
/// amount assertion, not the fee gate, is what must decide these tests.
const MAX_FEE_RAW: u64 = 1;

/// First byte of the 32-byte `remoteRecipient` field (felt 19 x 4 bytes of the fixed header).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
/// First byte of the 32-byte `remoteToken` field (felt 11 x 4 bytes of the fixed header).
const REMOTE_TOKEN_BYTE_OFF: usize = 11 * 4;
/// First byte of the 32-byte `nonce` field (felt 51 x 4 bytes of the fixed header).
const NONCE_BYTE_OFF: usize = 51 * 4;

fn administrator() -> AccountId {
    test_account_id(1)
}

/// The BLK_MANAGER holder seeded by the production builder (role id 4).
fn blk_manager() -> AccountId {
    test_account_id(4)
}

fn mi(id: &str) -> &'static MiVector {
    load()
        .families
        .mi
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing mp vector {id}"))
}

/// The canonical accept payload with the Circle `amount` / `maxFee` spliced in, `remoteRecipient`
/// replaced by the real recipient wallet, `remoteToken` bound to the faucet's own-id identifier
/// fixpoint (what the identifier compare checks against), and one nonce byte perturbed by
/// `nonce_variant` so each mint in a sweep consumes a nonce the replay guard has not seen.
fn payload_for(
    recipient: AccountId,
    faucet_id: AccountId,
    amount: u64,
    nonce_variant: u8,
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

/// The usedNonces key for a payload's nonce bytes.
fn nonce_key_of_payload(payload: &[u8]) -> Word {
    let nonce: [u8; 32] = payload[NONCE_BYTE_OFF..NONCE_BYTE_OFF + 32]
        .try_into()
        .expect("32 nonce bytes");
    Word::from(bytes32_to_storage_map_key(&nonce))
}

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]))
}

fn marker() -> Word {
    Word::from([1u32, 0, 0, 0])
}

// HARNESS (the production component set + the production bring-up notes; no drivers, no probes)
// ================================================================================================

/// The production-faucet fixture with the administrator's `set_attester` seeded on-chain.
/// The allowlisted attester is `gen_attester(1, ..)`, whose commitment is payload-independent.
fn fixture() -> Result<ProductionFaucet> {
    setup_production_faucet(0, |recipient, faucet_id| {
        let commitment = gen_attester(
            1,
            &payload_for(recipient, faucet_id, CIRCLE_DEPOSIT_100_USDC, 0),
        )
        .commitment;
        vec![XReserveSetAttesterNote::create(
            administrator(),
            faucet_id,
            commitment,
            1,
            &mut note_rng(952),
        )
        .expect("building the administrator set_attester note")]
    })
}

/// Consumes the two seeded admin notes, committing a block each (the production bring-up path).
async fn bring_up(pf: &mut ProductionFaucet) -> Result<()> {
    for (i, note) in pf.seeded_notes.clone().iter().enumerate() {
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

fn attestation_for(seed: u64, payload: &[u8]) -> DepositAttestation {
    let attester = gen_attester(seed, payload);
    DepositAttestation::new(Signature::new(attester.sig_bytes), attester.pubkey.clone())
}

/// Consumes a committed mint note on the faucet with no transaction script and no consume-side
/// advice — the production path, in which the standard mint-note script drives the standard
/// `mint_and_send`, which dispatches the faucet's `check_policy`. That policy is the only place a
/// scale exponent enters a mint, so consuming this way is what makes the sweep meaningful.
async fn consume_mint_note(
    chain: &MockChain,
    faucet_id: AccountId,
    note_id: NoteId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    chain
        .build_transaction(faucet_id)
        .authenticated_input_note(note_id)
        .build()
        .expect("building the consume tx")
        .execute()
        .await
}

fn commit(chain: &mut MockChain, tx: &ExecutedTransaction) -> Result<()> {
    chain.add_pending_executed_transaction(tx)?;
    chain.prove_next_block()?;
    Ok(())
}

fn committed(chain: &MockChain, id: AccountId) -> Result<Account> {
    Ok(chain
        .committed_account(id)
        .context("fetching the committed account")?
        .clone())
}

fn committed_token_supply(chain: &MockChain, faucet_id: AccountId) -> Result<u64> {
    let storage = chain.committed_account(faucet_id)?.storage();
    Ok(u64::from(FungibleFaucet::try_from(storage)?.token_supply()))
}

fn read_map_word(account: &Account, slot_name: &StorageSlotName, key: Word) -> Result<Word> {
    account
        .storage()
        .get_map_item(slot_name, StorageMapKey::new(key))
        .map_err(|e| anyhow::anyhow!("reading map slot {slot_name}: {e}"))
}

/// The recipient wallet's total balance of the faucet's fungible asset (vault iteration).
fn wallet_balance(account: &Account, faucet_id: AccountId) -> u64 {
    account
        .vault()
        .assets()
        .filter_map(|asset| match asset.as_fungible() {
            Some(f) if f.faucet_id() == faucet_id => Some(u64::from(f.amount())),
            _ => None,
        })
        .sum()
}

/// Emits a REAL stock mint note (the `XUsdcMintNote` factory) for `payload` and consumes it on the faucet, returning the
/// minted transaction. Every scale decision inside is the production faucet's own.
async fn mint_via_production_note(
    pf: &mut ProductionFaucet,
    payload: &[u8],
    rng_seed: u64,
) -> Result<ExecutedTransaction> {
    let note = mint_note_from_payload(
        pf.producer_id,
        pf.faucet_id,
        payload,
        attestation_for(1, payload),
        &mut note_rng(rng_seed),
    )?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    consume_mint_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the production-path attested mint must succeed: {e}"))
}

/// The single fungible asset amount carried by a mint tx's one recipient note.
fn minted_amount(tx: &ExecutedTransaction, faucet_id: AccountId) -> u64 {
    assert_eq!(
        tx.output_notes().num_notes(),
        1,
        "an attested mint emits exactly one recipient note"
    );
    let note = tx.output_notes().get_note(0);
    let asset = note
        .assets()
        .iter_fungible()
        .next()
        .expect("the recipient note carries a fungible asset");
    assert_eq!(
        asset.faucet_id(),
        faucet_id,
        "the recipient note's asset was minted by this faucet"
    );
    assert_eq!(
        note.metadata().note_type(),
        NoteType::Public,
        "the recipient note is Public"
    );
    u64::from(asset.amount())
}

// 1 — THE PIN: a Circle 6-decimal deposit mints the SAME number of smallest units
// ================================================================================================

/// A 100.000000 USDC Circle deposit (`amount = 100_000_000` smallest units on the wire) must land
/// in the recipient's wallet as EXACTLY 100_000_000 xUSDC smallest units.
///
/// This assertion is load-bearing precisely because nothing here supplies a scale: the value used
/// is whatever the amount/fee stage applies from `DEPOSIT_SCALE_EXP`. At `= 0` (correct) the mint is
/// an identity and this passes; at the former placeholder `= 6` the faucet mints
/// `100_000_000 / 10^6 = 100` and this fails on the amount assertion — a 100-USDC deposit
/// delivered as 0.000100 xUSDC.
#[tokio::test]
async fn production_mint_delivers_the_circle_amount_unrescaled() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf).await?;

    let payload = payload_for(pf.recipient_id, pf.faucet_id, CIRCLE_DEPOSIT_100_USDC, 0);
    let minted = mint_via_production_note(&mut pf, &payload, 61).await?;

    assert_eq!(
        minted_amount(&minted, pf.faucet_id),
        CIRCLE_DEPOSIT_100_USDC,
        "the minted note asset must equal the Circle 6-decimal deposit amount EXACTLY \
         (6-decimal wire == 6-decimal asset; DEPOSIT_SCALE_EXP must be 0, so y = x). A minted \
         value of {} would mean the faucet is still dividing by 10^6.",
        CIRCLE_DEPOSIT_100_USDC / 1_000_000
    );

    // The ledger and the recipient's custody agree with the note — the identity is not a
    // note-metadata artifact.
    commit(&mut pf.mock_chain, &minted)?;
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        CIRCLE_DEPOSIT_100_USDC,
        "token_supply rose by exactly the Circle deposit amount"
    );
    assert_eq!(
        read_map_word(
            &committed(&pf.mock_chain, pf.faucet_id)?,
            XReserveFaucetExtension::used_nonces_slot(),
            nonce_key_of_payload(&payload)
        )?,
        marker(),
        "usedNonces[key] marker set (the mint really executed the mint effects write path)"
    );

    let p2id_id = minted.output_notes().get_note(0).id();
    let recipient = committed(&pf.mock_chain, pf.recipient_id)?;
    // Consuming policed xUSDC fires the receive callback, so the faucet
    // must be attached as a foreign account for the kernel to run basic_blocklist::check_policy.
    let faucet_foreign = pf
        .mock_chain
        .get_foreign_account_inputs(pf.faucet_id)
        .context("faucet foreign-account inputs")?;
    let consume = pf
        .mock_chain
        .build_transaction(recipient.clone())
        .authenticated_input_note(p2id_id)
        .foreign_accounts([faucet_foreign])
        .build()
        .context("building the recipient consume tx")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("the recipient must consume its P2ID mint note: {e}"))?;
    commit(&mut pf.mock_chain, &consume)?;
    assert_eq!(
        wallet_balance(&committed(&pf.mock_chain, pf.recipient_id)?, pf.faucet_id),
        CIRCLE_DEPOSIT_100_USDC,
        "the recipient's vault holds the full Circle deposit amount (custody-traced identity)"
    );
    Ok(())
}

// 2 — THE SWEEP: the identity holds for round, non-round, sub-unit and one-unit deposits
// ================================================================================================

/// Four Circle deposits — one round, one whose low six digits are non-zero, one sub-whole-unit and
/// one of a single smallest unit — minted in sequence on ONE faucet. Each must mint its own input
/// verbatim and the ledger must equal the running sum.
///
/// The non-round cases are what make this stronger than a single round amount: floor division by
/// ANY power of ten above 1 destroys their low digits (`123_456_789 -> 123` at scale 6,
/// `-> 12_345_678` at scale 1), and both `1` and `999_999` collapse to `0` at scale 6. Only an
/// exact identity (`DEPOSIT_SCALE_EXP = 0`) returns every input unchanged.
#[tokio::test]
async fn production_mint_is_an_identity_across_circle_amounts() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf).await?;

    let mut expected_supply = 0u64;
    for (i, amount) in CIRCLE_DEPOSITS.iter().copied().enumerate() {
        // A distinct nonce byte per case, so the replay guard never fires; the amount is spliced verbatim.
        let payload = payload_for(pf.recipient_id, pf.faucet_id, amount, (i as u8) + 1);
        let minted = mint_via_production_note(&mut pf, &payload, 70 + i as u64)
            .await
            .with_context(|| format!("minting Circle deposit #{i} ({amount} smallest units)"))?;

        assert_eq!(
            minted_amount(&minted, pf.faucet_id),
            amount,
            "Circle deposit #{i} of {amount} smallest units must mint {amount} smallest units \
             verbatim — no rescale, no floored dust"
        );

        commit(&mut pf.mock_chain, &minted)?;
        expected_supply += amount;
        assert_eq!(
            committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
            expected_supply,
            "after Circle deposit #{i} the ledger equals the running sum of the WIRE amounts"
        );
    }

    assert_eq!(
        expected_supply,
        CIRCLE_DEPOSITS.iter().sum::<u64>(),
        "the sweep accounted for every deposit"
    );
    Ok(())
}

// 3 — NO DUST: the faucet does not silently retain a fractional remainder
// ================================================================================================

/// A nonzero scale does not merely shrink the mint — it silently DISCARDS the remainder
/// (`x mod 10^scale`), so the depositor is short-changed by an amount that never appears anywhere
/// on chain. Pinned here as the exact complement: minted + retained == the wire amount, with
/// retained == 0.
#[tokio::test]
async fn production_mint_leaves_no_fractional_remainder() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf).await?;

    let payload = payload_for(
        pf.recipient_id,
        pf.faucet_id,
        CIRCLE_DEPOSIT_NON_ROUND,
        0x5A,
    );
    let minted = mint_via_production_note(&mut pf, &payload, 80).await?;
    let delivered = minted_amount(&minted, pf.faucet_id);

    assert_eq!(
        delivered, CIRCLE_DEPOSIT_NON_ROUND,
        "the full wire amount is delivered"
    );
    assert_eq!(
        CIRCLE_DEPOSIT_NON_ROUND - delivered,
        0,
        "ZERO of the depositor's {CIRCLE_DEPOSIT_NON_ROUND} smallest units is discarded as \
         post-scale dust (a scale of 6 would silently drop 456_789 of them)"
    );

    commit(&mut pf.mock_chain, &minted)?;
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        CIRCLE_DEPOSIT_NON_ROUND,
        "supply == the wire amount, not a floored quotient"
    );
    Ok(())
}

// 4 — THE SOURCE PIN: the shipped faucet writes the amount at the identity scale
// ================================================================================================

/// The behavioural tests above are the real gate; this reads the shipped MASM so a regression that
/// re-introduces a rescale names itself in the failure output instead of surfacing only as an
/// arithmetic mismatch three tests up.
///
/// Under `DC-14` the scale is no longer a constant the faucet applies — it is structural. The
/// writer stores the note's `AssetAmount` as two byte-swapped limbs at its uint256 field's low
/// eight bytes, which IS `y = x` zero-extended. Anything other than the identity would have to
/// reconstruct the dropped remainder, which the note does not carry, so a rescale cannot be
/// introduced here without changing the transport (`DEV-5` stays OPEN).
#[test]
fn shipped_faucet_writes_the_amount_at_the_identity_scale() -> Result<()> {
    let src = include_str!("../asm/xreserve/deposit_intent.masm");
    assert!(
        src.contains(
            "const WRITE_AMOUNT_FELT_OFF = AMOUNT_FELT_OFF + UINT256_ASSET_AMOUNT_LIMB_OFF"
        ),
        "the writer must place the amount at the uint256's low eight bytes — the zero-extension \
         that makes the identity scale structural"
    );
    // scoped to `rebuild`'s own body: the module still HOSTS the DC-5 reducer for DEV-5's sake,
    // and its signature names a scale exponent. What must stay scale-free is the write path.
    let body = src
        .split_once("pub proc rebuild")
        .and_then(|(_, rest)| rest.split_once("\nend\n"))
        .map(|(body, _)| body)
        .context("the module declares pub proc rebuild")?;
    assert!(
        !body.to_ascii_lowercase().contains("scale"),
        "the writer applies no scale at all; a scale here would mean a rescale crept back"
    );

    Ok(())
}

// TRANSFER BLOCKLIST — mint TO a blocked recipient SUCCEEDS, then STRANDS at the recipient's
// consume
// ================================================================================================

/// The blocked-recipient mint semantics, on the REAL attested-mint path: the mint fires the SEND callback with
/// the native account = the FAUCET (never blocked), so a mint to a BLOCKED recipient still creates the
/// P2ID (the target is not inspected at mint time). The blocked recipient then CANNOT consume it —
/// the receive callback traps the exact stock `"account is blocked"` and the minted funds STRAND
/// (unspent, recipient vault empty). Uses the production fixture but seeds a third bring-up note that
/// blocks the recipient before the mint.
#[tokio::test]
async fn mint_to_a_blocked_recipient_succeeds_then_strands() -> anyhow::Result<()> {
    use miden_protocol::errors::MasmError;
    use miden_testing::assert_transaction_executor_error;

    // A fixture that additionally seeds a BLK_MANAGER block note targeting the recipient; bring_up
    // consumes set_attester AND the block note (so the recipient is blocked pre-mint).
    let mut pf = setup_production_faucet(0, |recipient, faucet_id| {
        let commitment = gen_attester(
            1,
            &payload_for(recipient, faucet_id, CIRCLE_DEPOSIT_100_USDC, 0),
        )
        .commitment;
        vec![
            XReserveSetAttesterNote::create(
                administrator(),
                faucet_id,
                commitment,
                1,
                &mut note_rng(962),
            )
            .expect("building the administrator set_attester note"),
            stock_block_note(blk_manager(), faucet_id, recipient, 963)
                .expect("building the BLK_MANAGER block note targeting the recipient"),
        ]
    })?;
    bring_up(&mut pf).await?;

    // MINT to the (now blocked) recipient — the mint SUCCEEDS: the send callback's native is the
    // faucet, so the recipient's block does not stop note creation.
    let payload = payload_for(pf.recipient_id, pf.faucet_id, CIRCLE_DEPOSIT_100_USDC, 0);
    let minted = mint_via_production_note(&mut pf, &payload, 61)
        .await
        .context(
            "the mint to a blocked recipient must SUCCEED (the target is not checked at mint)",
        )?;
    assert_eq!(
        minted.output_notes().num_notes(),
        1,
        "the mint to a blocked recipient still creates exactly one recipient P2ID"
    );
    commit(&mut pf.mock_chain, &minted)?;
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        CIRCLE_DEPOSIT_100_USDC,
        "the mint really executed (token_supply rose by the deposit amount)"
    );

    // The BLOCKED recipient CANNOT consume the minted P2ID (receive callback) → it strands.
    let p2id_id = minted.output_notes().get_note(0).id();
    let recipient = committed(&pf.mock_chain, pf.recipient_id)?;
    let faucet_foreign = pf
        .mock_chain
        .get_foreign_account_inputs(pf.faucet_id)
        .context("faucet foreign-account inputs")?;
    let result = pf
        .mock_chain
        .build_transaction(recipient.clone())
        .authenticated_input_note(p2id_id)
        .foreign_accounts([faucet_foreign])
        .build()
        .context("blocked-recipient consume tx")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, MasmError::from_static_str("account is blocked"));

    // The funds strand: the note is unspent and the recipient's vault holds nothing.
    assert!(
        pf.mock_chain.is_note_committed(&p2id_id),
        "the minted P2ID strands (still committed; the stock P2ID has NO sender/faucet reclaim, so \
         recovery is by unblocking the recipient)"
    );
    assert_eq!(
        wallet_balance(&committed(&pf.mock_chain, pf.recipient_id)?, pf.faucet_id),
        0,
        "the blocked recipient received nothing (the mint stranded at consume)"
    );
    Ok(())
}
