//! FULL FAUCET ASSEMBLY E2E: the single-instance, sequential, full-lifecycle dress rehearsal for
//! local-node validation, on the production faucet composition.
//!
//! ONE faucet composed by the PRODUCTION `XReserveStablecoinBuilder` — domain
//! BUILD-SEEDED, attester allowlist EMPTY, the stock
//! `MinBurnAmount` floor at the builder default — is driven through the whole lifecycle IN ORDER
//! on ONE evolving MockChain. The stages, in the order the S-labels below number them:
//!
//! - S0 the build-seeded config read-backs;
//! - S3 admin bring-up: attester, max_supply, and min_burn, each
//!   with its non-administrator reject;
//! - S4-S6 a REAL attested mint through the STOCK `MintNote` transport (the `XUsdcMintNote`
//!   factory: the merged scheme-4 transport + scheme-2 routing), then the nonce replay
//!   trap, then the tx-script `mint_and_send` leg — the stock path IS the attestation-gated path,
//!   so a policy-less tx-script mint traps in the kernel;
//! - S7-S9 the holder wallet consumes the minted P2ID note (custody-traced funds), a below-min
//!   burn rejects on the stock `MinBurnAmount` policy, and a real burn goes through (two-block
//!   consume, burn-item schema asserted);
//! - S10-S11 DOM_PAUSER pause halts BOTH mint and burn (and the administrator has NO pause path);
//!   unpause resumes BOTH, and the SAME halted mint note lands;
//! - S12 role rotation: ADMIN grant → the new pauser pauses; revoke → rejected;
//! - S13 the final ledger: the exact whole-arc supply equation and the config read-backs.
//!
//! Every tx is COMMITTED (`add_pending_executed_transaction` + `prove_next_block`) so all stages
//! run on one chain — no stitched fixtures. Every reject pins its EXACT error (S6's kernel
//! host-event is the one documented exception), and every state change is read back.
//!
//! MECHANICS: the admin notes are deterministic and pre-seeded ON-CHAIN at build
//! (`setup_production_faucet` seeded_notes), so every admin step consumes its note BY ID as an
//! authenticated input — block-provable, which the commit-each-step design requires (an
//! unauthenticated note cannot be committed: no inclusion proof). Reject-path notes stay
//! unconsumed after their tx traps. The MINT notes cannot be genesis-seeded (their embedded
//! asset carries the REAL faucet id, unknown until the chain is built), so each is constructed at
//! its step and emitted through a REAL producer tx (`emit_note_with_attachments`), then consumed
//! by id like every other committed note.

mod support;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountId, RoleSymbol, StorageMapKey, StorageSlotName};
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteId, NoteTag, NoteType};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_standards::note::config::{RbacConfig, RbacConfigNote};
use miden_standards::note::{P2idNote, P2idNoteStorage};
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveFaucetExtension, DOM_PAUSER_ROLE, DOM_UNPAUSER_ROLE,
};
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;
use xusdc_encoding::note::xreserve_burn::{
    XReserveBurnNote, FIXED_XUSDC_BURN_TAG, XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME,
};
use xusdc_encoding::note::xreserve_mint::DepositAttestation;
use xusdc_encoding::vectors::{load, MiVector};
use xusdc_encoding::xreserve::encoding::{
    bytes32_to_storage_map_key, DepositIntent, ForeignChainAddress, Signature, XReserveBurnItems,
};

// ACTORS (the builder seeds ADMIN / ATTEST_ADMIN = id(1), DOM_PAUSER = id(2),
// DOM_UNPAUSER = id(3), BLK_MANAGER = id(4); id(5) is the unseeded rotation candidate)
// ================================================================================================

fn administrator() -> AccountId {
    test_account_id(1)
}
fn pauser() -> AccountId {
    test_account_id(2)
}
fn unpauser() -> AccountId {
    test_account_id(3)
}
fn new_pauser() -> AccountId {
    test_account_id(5)
}
fn stranger() -> AccountId {
    test_account_id(99)
}

// FIXTURE VALUES (all Circle-owned values are test parameters — the domain id, the identifier
// encoding, and the attester scheme stay OPEN with Circle;
// the build-seeded TEST_DOMAIN comes from support)
// ================================================================================================

// the DC-14 rows are the ones the mint transport can carry; their localToken / localDepositor are
// deliberately NOT address-shaped, so every mint below is a non-EVM source chain's deposit
const BASE_VECTOR: &str = "mi-pos-empty-hookdata";

/// The attested wire amount of BOTH lifecycle mints. Under the provisional identity scale
/// (`DEPOSIT_SCALE_EXP = 0`, `y = x` — the cap/scale decision stays OPEN, pending Circle) the
/// minted amount IS the wire amount — one value chosen to keep the
/// whole-arc "170" ledger story: 2 * 100 - 20 - 10 = 170.
const MINT_AMOUNT: u64 = 100;
/// The distinct-recipient test's second attested amount (distinct from `MINT_AMOUNT` so each
/// wallet's final balance identifies WHICH mint it received).
const SECOND_MINT_AMOUNT: u64 = 250;
/// maxFee 1 (amount >= maxFee holds for every attested amount here); feeAmount stays 0 (the MVP
/// rejects any nonzero fee).
const MAX_FEE_RAW: u64 = 1;

const NEW_MAX_SUPPLY: u64 = 500_000;
const MIN_BURN: u64 = 10;
const BURN_LOW: u64 = 5; // < MIN_BURN -> the stock MinBurnAmount reject
const BURN_OK: u64 = 20;
const BURN_PAUSED: u64 = 10; // the paused-era emit traps (S10b); burned for real after unpause (S11b)

/// First byte of the 32-byte `remoteRecipient` field (felt 19 x 4 bytes of the fixed header).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
/// First byte of the 32-byte `remoteToken` field (felt 11 x 4 bytes of the fixed header).
const REMOTE_TOKEN_BYTE_OFF: usize = 11 * 4;
/// First byte of the 32-byte `nonce` field (felt 51 x 4 bytes of the fixed header).
const NONCE_BYTE_OFF: usize = 51 * 4;

fn mi(id: &str) -> &'static MiVector {
    load()
        .families
        .mi
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing mp vector {id}"))
}

/// The deposit every mint in this file is built from names a source chain whose addresses do not
/// fit an EVM address, and the faucet mints it anyway.
///
/// This is what the widened `localToken` / `localDepositor` buy. It is asserted here rather than
/// left implicit in the artifact because the whole end-to-end claim — that a non-EVM source chain
/// is mintable — rests on the payload these lifecycle mints actually carry. Narrowing the fixture
/// back to a padded 20-byte address would leave every test in this file passing while silently
/// retiring the coverage.
#[test]
fn the_lifecycle_deposit_names_a_non_evm_source_chain() -> Result<()> {
    let intent = DepositIntent::try_from(mi(BASE_VECTOR).payload().as_slice())?;
    for (field, value) in [
        ("localToken", intent.header().local_token()),
        ("localDepositor", intent.header().local_depositor()),
    ] {
        assert_ne!(
            value.as_bytes()[..12],
            [0u8; 12],
            "{field} must carry bytes an EVM address could never occupy, or these mints prove \
             nothing about a non-EVM source chain"
        );
    }
    Ok(())
}

/// The canonical accept payload with amount/maxFee spliced, `remoteRecipient` REPLACED by the REAL
/// target wallet's right-aligned bytes32 (so the emitted P2ID note targets an account that exists
/// on this chain and can consume it), `remoteToken` REPLACED by `EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()`
/// (the own-id key the mint path derives, so the identifier compare passes), and
/// one nonce byte XOR-perturbed per `nonce_variant` so each mint consumes a nonce the replay guard
/// has not seen.
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

/// The usedNonces key (== the attested P2ID serial) for a payload's nonce bytes.
fn nonce_key_of_payload(payload: &[u8]) -> Word {
    let nonce: [u8; 32] = payload[NONCE_BYTE_OFF..NONCE_BYTE_OFF + 32]
        .try_into()
        .expect("32 nonce bytes");
    Word::from(bytes32_to_storage_map_key(&nonce))
}

fn err_paused() -> MasmError {
    MasmError::from_static_str("the contract is paused")
}
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(31u32),
        Felt::from(32u32),
    ]))
}

/// A standard role-action note carrying `action`, sent by `sender` and tagged for `faucet_id`. The
/// serial is drawn from `rng`; every action is gated by the standard role component on the sender.
fn stock_role_action_note<R: miden_protocol::crypto::rand::FeltRng>(
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

/// The allowlisted (seed 1) attester's `DepositAttestation` over `payload` — the wire-form signature
/// + pubkey the `XUsdcMintNote` factory embeds in the merged transport's attestation section.
fn attestation_for(seed: u64, payload: &[u8]) -> DepositAttestation {
    let attester = gen_attester(seed, payload);
    DepositAttestation::new(Signature::new(attester.sig_bytes), attester.pubkey.clone())
}

/// The REAL stock mint note for `payload`: the production `XUsdcMintNote` factory (the merged
/// scheme-4 transport + `NetworkAccountTarget` scheme-2 attachments over a stock
/// `MintNote`), signed by the allowlisted attester. Built per step — never genesis-seeded — because
/// the embedded output asset carries the REAL faucet id.
fn production_mint_note(
    producer: AccountId,
    faucet_id: AccountId,
    payload: &[u8],
    rng_seed: u64,
) -> Result<Note> {
    mint_note_from_payload(
        producer,
        faucet_id,
        payload,
        attestation_for(1, payload),
        &mut note_rng(rng_seed),
    )
}

// CHAIN MECHANICS — commit-each-step (the run_burn_consume pattern), committed-state re-fetch
// ================================================================================================

fn commit(chain: &mut MockChain, tx: &ExecutedTransaction) -> Result<()> {
    chain
        .add_pending_executed_transaction(tx)
        .context("queuing the executed tx into the block")?;
    chain.prove_next_block().context("proving the block")?;
    Ok(())
}

fn committed(chain: &MockChain, id: AccountId) -> Result<Account> {
    Ok(chain
        .committed_account(id)
        .context("fetching the committed account")?
        .clone())
}

/// Consumes a COMMITTED note (by id) with `account` as the executing/consuming account — the
/// faucet's seeded-admin-note, mint-note, and `receive_and_burn` consumes all ride this (the
/// faucet is the native account, so no foreign attachment is needed; the burn flow fires no
/// receive callback either).
async fn consume_committed_note(
    chain: &MockChain,
    account: &Account,
    note_id: NoteId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    chain
        .build_transaction(account.clone())
        .authenticated_input_note(note_id)
        .build()
        .expect("building the consume tx")
        .execute()
        .await
}

/// Consumes a COMMITTED P2ID note carrying POLICED xUSDC with a NON-faucet `account` as the consumer.
/// The receive callback (`on_before_asset_added_to_account`) fires with the consumer as the native
/// account, so the kernel dyncalls the issuing faucet to run `basic_blocklist::check_policy` — the
/// faucet MUST be attached as a foreign account (the policed-asset client-side coupling). This is what a
/// real wallet consuming policed xUSDC has to do; the coupling is pinned executable by
/// `transfer_blocklist_e2e::send_without_faucet_foreign_account_fails`.
async fn consume_committed_note_with_faucet_foreign(
    chain: &MockChain,
    account: &Account,
    note_id: NoteId,
    faucet_id: AccountId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let foreign = chain
        .get_foreign_account_inputs(faucet_id)
        .expect("faucet foreign-account inputs (committed)");
    chain
        .build_transaction(account.clone())
        .authenticated_input_note(note_id)
        .foreign_accounts([foreign])
        .build()
        .expect("building the consume tx")
        .execute()
        .await
}

/// Asserts the committed faucet supply equals `expected` (the whole-arc ledger read).
fn assert_supply(chain: &MockChain, faucet_id: AccountId, expected: u64, what: &str) -> Result<()> {
    assert_eq!(
        committed_token_supply(chain, faucet_id)?,
        AssetAmount::new(expected).context("expected supply is a valid AssetAmount")?,
        "token_supply ledger mismatch: {what}",
    );
    Ok(())
}

/// Reads a map-slot entry word from an account (the attester-allowlist / usedNonces read-backs).
fn read_map_word(account: &Account, slot_name: &StorageSlotName, key: Word) -> Result<Word> {
    account
        .storage()
        .get_map_item(slot_name, StorageMapKey::new(key))
        .map_err(|e| anyhow::anyhow!("reading map slot {slot_name}: {e}"))
}

/// A wallet's total balance of the faucet's fungible asset (vault iteration — the custody
/// read-back for S7 and the distinct-recipient test).
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

/// The map marker word `[1, 0, 0, 0]` (attester enabled / nonce used / role member).
fn marker() -> Word {
    Word::from([1u32, 0, 0, 0])
}

// THE FULL LIFECYCLE
// ================================================================================================

/// The single-instance, sequential, full-lifecycle E2E on ONE production-composed faucet.
#[tokio::test]
async fn assembled_faucet_full_lifecycle() -> Result<()> {
    // ── S0 — ASSEMBLY: the production builder composes the faucet; domain
    // BUILD-SEEDED, attester allowlist EMPTY. The admin notes are
    // seeded here in the order the indices below list, per the header's mechanics. `route` is the
    // routing-only faucet target the factories stamp into tags/attachments; consume-by-id never
    // reads it, so the pre-build dummy id is sound.
    let mut pf = setup_production_faucet(0, |recipient, faucet_id| {
        let commitment =
            gen_attester(1, &payload_for(recipient, MINT_AMOUNT, 0, faucet_id)).commitment;
        let route = faucet_id;
        let psym = RoleSymbol::new(DOM_PAUSER_ROLE).expect("valid role symbol");
        vec![
            // 0: S3a stranger set_attester (reject)
            XReserveSetAttesterNote::create(stranger(), route, commitment, 1, &mut note_rng(913))
                .expect("building the seeded attester-stranger note"),
            // 1: S3a owner set_attester
            XReserveSetAttesterNote::create(
                administrator(),
                route,
                commitment,
                1,
                &mut note_rng(914),
            )
            .expect("building the seeded attester-owner note"),
            // 2: S3b stranger set_max_supply (reject)
            stock_set_max_supply_note(stranger(), route, NEW_MAX_SUPPLY, 915)
                .expect("building the seeded max-stranger note"),
            // 3: S3b owner set_max_supply
            stock_set_max_supply_note(administrator(), route, NEW_MAX_SUPPLY, 916)
                .expect("building the seeded max-owner note"),
            // 4: S3c stranger min-burn (reject)
            stock_min_burn_note(stranger(), route, MIN_BURN, 917)
                .expect("building the seeded min-stranger note"),
            // 5: S3c owner min-burn
            stock_min_burn_note(administrator(), route, MIN_BURN, 918)
                .expect("building the seeded min-owner note"),
            // 6: S10 DOM_PAUSER pause
            stock_pause_note(pauser(), route, 920).expect("building the seeded pause-pauser note"),
            // 7: S10c owner STOCK pause probe (traps UnknownAccountProcedure)
            manager_pause_call_note(administrator(), 921)
                .expect("building the seeded manager pause-call note sent by the administrator"),
            // 8: S10d stranger custom pause (reject)
            stock_pause_note(stranger(), route, 922)
                .expect("building the seeded pause-stranger note"),
            // 9: S11 DOM_UNPAUSER unpause
            stock_unpause_note(unpauser(), route, 923)
                .expect("building the seeded unpause-unpauser note"),
            // 10: S12 ADMIN grant_role(DOM_PAUSER, new_pauser)
            stock_role_action_note(
                administrator(),
                route,
                RbacConfig::GrantRole {
                    role: psym.clone(),
                    account: new_pauser(),
                },
                &mut note_rng(924),
            )
            .expect("building the seeded grant note"),
            // 11: S12 new pauser pause
            stock_pause_note(new_pauser(), route, 925).expect("building the seeded pause-new note"),
            // 12: S12 DOM_UNPAUSER lifts the new pauser's pause
            stock_unpause_note(unpauser(), route, 926)
                .expect("building the seeded unpause-after-rotation note"),
            // 13: S12 ADMIN revoke_role(DOM_PAUSER, new_pauser)
            stock_role_action_note(
                administrator(),
                route,
                RbacConfig::RevokeRole {
                    role: psym.clone(),
                    account: new_pauser(),
                },
                &mut note_rng(927),
            )
            .expect("building the seeded revoke note"),
            // 14: S12 revoked pauser pause attempt (reject)
            stock_pause_note(new_pauser(), route, 928)
                .expect("building the seeded pause-revoked note"),
        ]
    })?;
    let note_id = |i: usize| pf.seeded_notes[i].id();
    let faucet_id = pf.faucet_id;
    let producer_id = pf.producer_id;
    // The arc's fund HOLDER (attested deposit recipient + burner) is the PRODUCER wallet: it is
    // the fixture wallet carrying the emit helper that `try_emit_burn_note` drives (the plain
    // `recipient` wallet cannot emit burn notes), and the mint policy accepts any attested
    // recipient — the deposit-recipient and note-producer roles landing on one wallet is a
    // legitimate self-relay.
    let holder_id = pf.producer_id;
    let payload1 = payload_for(holder_id, MINT_AMOUNT, 0, faucet_id);
    let payload2 = payload_for(holder_id, MINT_AMOUNT, 0x5A, faucet_id);
    let payload3 = payload_for(holder_id, MINT_AMOUNT, 0xA5, faucet_id);
    let attester1 = gen_attester(1, &payload1);
    let pauser_sym = RoleSymbol::new(DOM_PAUSER_ROLE).expect("valid role symbol");
    let unpauser_sym = RoleSymbol::new(DOM_UNPAUSER_ROLE).expect("valid role symbol");

    // S0 read-backs: the BUILD-SEEDED domain config, supply 0, the
    // directly administered roles, the stock MinBurnAmount builder-default floor.
    let faucet0 = committed(&pf.mock_chain, faucet_id)?;
    let domain0 = faucet0
        .storage()
        .get_item(XReserveFaucetExtension::domain_config_slot())?;
    assert_eq!(
        domain0,
        Word::from([TEST_DOMAIN.as_u32(), 0, 0, 0]),
        "S0: domain ships BUILD-SEEDED (DEC-4)"
    );
    assert_supply(&pf.mock_chain, faucet_id, 0, "S0 assembly")?;
    assert_eq!(
        read_role_config(&faucet0, &pauser_sym)?,
        marker(),
        "S0: role_config[DOM_PAUSER] resolves directly to ADMIN"
    );
    assert_eq!(
        read_role_config(&faucet0, &unpauser_sym)?,
        marker(),
        "S0: role_config[DOM_UNPAUSER] resolves directly to ADMIN"
    );
    assert_eq!(
        read_min_burn_size(&faucet0)?,
        Word::from([1u32, 0, 0, 0]),
        "S0: the stock MinBurnAmount floor ships at the builder default [1,0,0,0]"
    );
    assert_eq!(
        read_map_word(
            &faucet0,
            XReserveFaucetExtension::xreserve_attesters_slot(),
            attester1.commitment
        )?,
        Word::from([0u32, 0, 0, 0]),
        "S0: the attester allowlist ships EMPTY (set_attester is the bring-up writer)"
    );

    // ── S3a — ADMIN: owner allowlists the attester; a stranger's attempt is rejected and leaves
    // the map unchanged.
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let result = consume_committed_note(&pf.mock_chain, &faucet, note_id(0)).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_map_word(
            &faucet,
            XReserveFaucetExtension::xreserve_attesters_slot(),
            attester1.commitment
        )?,
        Word::from([0u32, 0, 0, 0]),
        "S3a: the rejected set_attester left the allowlist unchanged"
    );
    let tx = consume_committed_note(&pf.mock_chain, &faucet, note_id(1))
        .await
        .expect("S3a: the administrator's set_attester must succeed");
    commit(&mut pf.mock_chain, &tx)?;
    assert_eq!(
        read_map_word(
            &committed(&pf.mock_chain, faucet_id)?,
            XReserveFaucetExtension::xreserve_attesters_slot(),
            attester1.commitment
        )?,
        marker(),
        "S3a: the allowlist marker [1,0,0,0] reads back for the commitment"
    );

    // ── S3b — ADMIN: owner sets max_supply; a stranger's attempt is rejected.
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let result = consume_committed_note(&pf.mock_chain, &faucet, note_id(2)).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    let tx = consume_committed_note(&pf.mock_chain, &faucet, note_id(3))
        .await
        .expect("S3b: the administrator's set_max_supply must succeed");
    commit(&mut pf.mock_chain, &tx)?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    assert_eq!(
        read_token_config(&faucet)?[1],
        Felt::from(AssetAmount::new(NEW_MAX_SUPPLY)?),
        "S3b: token_config[max_supply] read-back"
    );

    // ── S3c — ADMIN: owner sets the min-burn floor (the standard note targets the STOCK
    // `set_min_burn_amount`); a stranger's attempt is rejected.
    let result = consume_committed_note(&pf.mock_chain, &faucet, note_id(4)).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    let tx = consume_committed_note(&pf.mock_chain, &faucet, note_id(5))
        .await
        .expect("S3c: the administrator's min-burn note must succeed");
    commit(&mut pf.mock_chain, &tx)?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    assert_eq!(
        read_min_burn_size(&faucet)?,
        Word::from([
            Felt::from(AssetAmount::new(MIN_BURN)?),
            Felt::from(0u32),
            Felt::from(0u32),
            Felt::from(0u32)
        ]),
        "S3c: the stock MinBurnAmount floor slot reads [10,0,0,0]"
    );
    // ── S4 — ATTESTED MINT: a REAL stock MintNote (the XUsdcMintNote factory) emitted by the
    // producer and consumed by the faucet drives the FULL attestation policy chain (full validation pipeline).
    let note_m1 = production_mint_note(producer_id, faucet_id, &payload1, 61)?;
    emit_note_with_attachments(&mut pf.mock_chain, producer_id, &note_m1).await?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let minted = consume_committed_note(&pf.mock_chain, &faucet, note_m1.id())
        .await
        .expect(
            "S4: a fully valid deposit intent + attestation must mint on the production faucet",
        );
    assert_eq!(
        minted.output_notes().num_notes(),
        1,
        "S4: exactly one recipient note"
    );
    let note = minted.output_notes().get_note(0);
    let mint_note_id = note.id();
    let asset = note
        .assets()
        .iter_fungible()
        .next()
        .expect("S4: the recipient note carries a fungible asset");
    assert_eq!(
        u64::from(asset.amount()),
        MINT_AMOUNT,
        "S4: note asset == the attested amount (DEV-5 scale-0 identity)"
    );
    assert_eq!(
        asset.faucet_id(),
        faucet_id,
        "S4: asset minted by this faucet"
    );
    let recipient_digest = note
        .recipient()
        .expect("S4: public output note carries its recipient");
    assert_eq!(
        recipient_digest.serial_num(),
        nonce_key_of_payload(&payload1),
        "S4: note serial == the nonce-derived KEY"
    );
    assert_eq!(
        recipient_digest.script().root(),
        P2idNote::script_root(),
        "S4: canonical P2ID script root"
    );
    assert_eq!(
        note.metadata().tag(),
        NoteTag::with_account_target(holder_id),
        "S4: the recipient note is tagged for the attested recipient (account target)"
    );
    assert_eq!(
        note.metadata().note_type(),
        NoteType::Public,
        "S4: recipient note is Public"
    );
    commit(&mut pf.mock_chain, &minted)?;
    assert_supply(&pf.mock_chain, faucet_id, MINT_AMOUNT, "S4 after mint")?;
    assert_eq!(
        read_map_word(
            &committed(&pf.mock_chain, faucet_id)?,
            XReserveFaucetExtension::used_nonces_slot(),
            nonce_key_of_payload(&payload1)
        )?,
        marker(),
        "S4: usedNonces[key] marker set (the policy's nonce-ledger write)"
    );

    // ── S5 — REPLAY: a SECOND mint note over the SAME payload (same nonce, fresh serial) traps
    // the EXACT nonce-replay error; supply unchanged.
    let replay_note = production_mint_note(producer_id, faucet_id, &payload1, 62)?;
    emit_note_with_attachments(&mut pf.mock_chain, producer_id, &replay_note).await?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let result = consume_committed_note(&pf.mock_chain, &faucet, replay_note.id()).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_NONCE_REPLAY"));
    assert_supply(
        &pf.mock_chain,
        faucet_id,
        MINT_AMOUNT,
        "S5 after replay reject",
    )?;

    // ── S6 — NO POLICY-LESS MINT: a tx-script `mint_and_send` (no active
    // note, no attachments) CANNOT mint — the attestation policy's transport reads trap in the
    // kernel (there is no active note to read). The former deny-guard posture is preserved
    // STRUCTURALLY: every supply increase must ride the attested note transport. The failure is a
    // kernel host-event (active-note read outside a note context), NOT a MASM assert, so no
    // exact-string assert exists — asserted as is_err + no state change (the documented exception
    // to the exact-error discipline).
    let recipient_recipe =
        P2idNoteStorage::new(holder_id).into_recipient(Word::from([9u32, 9, 9, 9]));
    let src = format!(
        "
            @transaction_script
            pub proc main
                push.{recipient}
                push.{note_type}
                push.{tag}
                push.{amount}
                push.{faucet_id_prefix}
                push.{faucet_id_suffix}
                exec.::miden::standards::assets::fungible_asset::create
                call.::miden::standards::faucets::fungible::mint_and_send
                dropw dropw dropw dropw
            end
            ",
        recipient = recipient_recipe.digest(),
        note_type = Felt::from(NoteType::Public),
        tag = u32::from(NoteTag::with_account_target(holder_id)),
        amount = MINT_AMOUNT,
        faucet_id_prefix = faucet_id.prefix().as_felt(),
        faucet_id_suffix = faucet_id.suffix(),
    );
    let tx_script = miden_standards::code_builder::CodeBuilder::new()
        .compile_tx_script(&src)
        .map_err(|e| anyhow::anyhow!("mint_and_send tx script: {e}"))?;
    let result = pf
        .mock_chain
        .build_transaction(faucet_id)
        .tx_script(tx_script)
        .build()
        .context("S6: tx build")?
        .execute()
        .await;
    assert!(
        result.is_err(),
        "S6: a tx-script mint_and_send must NOT mint on the attestation-gated faucet"
    );
    assert_supply(
        &pf.mock_chain,
        faucet_id,
        MINT_AMOUNT,
        "S6 after the policy-less mint attempt",
    )?;

    // ── S7 — P2ID CONSUME: the holder wallet consumes the minted note (custody-traced funds).
    let holder = committed(&pf.mock_chain, holder_id)?;
    assert_eq!(
        wallet_balance(&holder, faucet_id),
        0,
        "S7: the holder holds nothing before consuming the mint note"
    );
    let consume = consume_committed_note_with_faucet_foreign(
        &pf.mock_chain,
        &holder,
        mint_note_id,
        faucet_id,
    )
    .await
    .expect("S7: the holder consumes its P2ID mint note");
    commit(&mut pf.mock_chain, &consume)?;
    assert_eq!(
        wallet_balance(&committed(&pf.mock_chain, holder_id)?, faucet_id),
        MINT_AMOUNT,
        "S7: the holder's vault holds the full minted amount (custody-traced)"
    );

    // ── S8 — BURN BELOW MIN: a real XReserveBurnNote below the floor is rejected at the faucet
    // consume with the EXACT stock MinBurnAmount error (the emit itself succeeds — the floor is a
    // burn-policy gate, not a transfer gate).
    let low_items = XReserveBurnItems {
        dest_domain: TEST_SOURCE_DOMAIN,
        dest_recipient: ForeignChainAddress::new([0xABu8; 32]),
    };
    let low_note = XReserveBurnNote::create(
        holder_id,
        faucet_id,
        AssetAmount::new(BURN_LOW)?,
        low_items,
        &mut note_rng(41),
    )?;
    let low_asset = FungibleAsset::new(faucet_id, BURN_LOW)?;
    let emit = try_emit_burn_note(&pf.mock_chain, &low_note, &low_asset, faucet_id, holder_id)
        .await
        .expect("S8: emitting the below-min burn note succeeds (the reject is at consume)");
    commit(&mut pf.mock_chain, &emit)?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let result = consume_committed_note(&pf.mock_chain, &faucet, low_note.id()).await;
    assert_transaction_executor_error!(result, err_burn_below_min_burn_amount());
    assert_supply(
        &pf.mock_chain,
        faucet_id,
        MINT_AMOUNT,
        "S8 after below-min reject",
    )?;

    // ── S9 — BURN: a real burn of the minted funds; burn-item schema asserted; two-block consume;
    // supply -= amount exactly (whole-arc conservation).
    let items = XReserveBurnItems {
        dest_domain: TEST_SOURCE_DOMAIN,
        dest_recipient: ForeignChainAddress::new([0xCDu8; 32]),
    };
    let burn_note = XReserveBurnNote::create(
        holder_id,
        faucet_id,
        AssetAmount::new(BURN_OK)?,
        items.clone(),
        &mut note_rng(42),
    )?;
    assert_eq!(
        burn_note.metadata().note_type(),
        NoteType::Public,
        "S9: burn note is Public"
    );
    assert_eq!(
        burn_note.metadata().tag().as_u32(),
        FIXED_XUSDC_BURN_TAG,
        "S9: the fixed full-32-bit xUSDC burn tag"
    );
    assert_eq!(
        burn_note.metadata().sender(),
        holder_id,
        "S9: metadata.sender == depositor"
    );
    // The withdrawal payload rides the scheme-6 attachment, zero-padded to the word boundary.
    let mut payload_felts = burn_note
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme().as_u16() == XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME)
        .expect("S9: burn note carries its withdrawal-payload attachment")
        .content()
        .to_elements();
    payload_felts.truncate(XReserveBurnNote::NUM_PAYLOAD_ITEMS);
    assert_eq!(
        XReserveBurnItems::decode(&payload_felts).expect("S9: DC-7 items decode"),
        items,
        "S9: the withdrawal-payload attachment carries the exact DC-7 payload"
    );
    let burn_asset = FungibleAsset::new(faucet_id, BURN_OK)?;
    let emit = try_emit_burn_note(
        &pf.mock_chain,
        &burn_note,
        &burn_asset,
        faucet_id,
        holder_id,
    )
    .await
    .expect("S9: emitting the burn note (block N)");
    commit(&mut pf.mock_chain, &emit)?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let consume = consume_committed_note(&pf.mock_chain, &faucet, burn_note.id())
        .await
        .expect(
            "S9: the faucet consumes the burn note at block >= N+1 (receive_and_burn -> the stock \
             MinBurnAmount policy)",
        );
    commit(&mut pf.mock_chain, &consume)?;
    assert_supply(
        &pf.mock_chain,
        faucet_id,
        MINT_AMOUNT - BURN_OK,
        "S9: supply == amount_minted - amount_burned (arc conservation)",
    )?;

    // ── S10 — PAUSE: DOM_PAUSER pauses; the halt is real on BOTH paths; the administrator has NO path.
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let tx = consume_committed_note(&pf.mock_chain, &faucet, note_id(6))
        .await
        .expect("S10: the DOM_PAUSER pause must succeed");
    commit(&mut pf.mock_chain, &tx)?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    assert_eq!(
        read_is_paused(&faucet)?,
        Word::from([1u32, 0, 0, 0]),
        "S10: is_paused publicly readable == paused"
    );
    // S10a: a fresh attested mint halts at the policy dispatcher's stock pause gate (the producer
    // EMIT itself still passes — no asset is attached to the mint note, the amount being in its
    // storage, so no transfer callback fires);
    // fail-closed: the fresh nonce stays unburned, so the SAME note can land after unpause.
    let note_m2 = production_mint_note(producer_id, faucet_id, &payload2, 63)?;
    emit_note_with_attachments(&mut pf.mock_chain, producer_id, &note_m2).await?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let result = consume_committed_note(&pf.mock_chain, &faucet, note_m2.id()).await;
    assert_transaction_executor_error!(result, err_paused());
    assert_eq!(
        read_map_word(
            &faucet,
            XReserveFaucetExtension::used_nonces_slot(),
            nonce_key_of_payload(&payload2)
        )?,
        Word::from([0u32, 0, 0, 0]),
        "S10a: the paused mint burned no nonce (fail-closed)"
    );
    // S10b (pause semantics on the policed asset): with an active transfer policy, PAUSE halts ALL
    // transfers. The holder's emit of a burn note fires the SEND callback, whose wrapper runs
    // `pausable::assert_not_paused` BEFORE the blocklist check, so the emit itself TRAPS while
    // paused — the halt lands at the holder-side send, not only the faucet consume (a chain-wide
    // freeze on xUSDC movement). This is the deliberate, ratified semantic.
    let paused_asset = FungibleAsset::new(faucet_id, BURN_PAUSED)?;
    let paused_items = XReserveBurnItems {
        dest_domain: TEST_SOURCE_DOMAIN,
        dest_recipient: ForeignChainAddress::new([0xEFu8; 32]),
    };
    let paused_note = XReserveBurnNote::create(
        holder_id,
        faucet_id,
        AssetAmount::new(BURN_PAUSED)?,
        paused_items,
        &mut note_rng(43),
    )?;
    let result = try_emit_burn_note(
        &pf.mock_chain,
        &paused_note,
        &paused_asset,
        faucet_id,
        holder_id,
    )
    .await;
    assert_transaction_executor_error!(result, err_paused());
    // S10c: the administrator has NO direct pause path. The stock manager IS installed, so the rejection is
    // the role assertion rather than a missing procedure: the procedure-role map gates pause on the
    // Domain pauser, which the administrator does not hold.
    let result = consume_committed_note(&pf.mock_chain, &faucet, note_id(7)).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    // S10d: a second non-DOM_PAUSER pause attempt is rejected with the same exact role error.
    let result = consume_committed_note(&pf.mock_chain, &faucet, note_id(8)).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());

    // ── S11 — UNPAUSE: DOM_UNPAUSER unpauses; BOTH paths resume.
    let tx = consume_committed_note(&pf.mock_chain, &faucet, note_id(9))
        .await
        .expect("S11: the DOM_UNPAUSER unpause must succeed");
    commit(&mut pf.mock_chain, &tx)?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    assert_eq!(
        read_is_paused(&faucet)?,
        Word::from([0u32, 0, 0, 0]),
        "S11: is_paused == unpaused"
    );
    // S11a: the SAME attested mint note the pause halted (fresh nonce, still committed and
    // unconsumed) now succeeds — the mint path resumed.
    let minted2 = consume_committed_note(&pf.mock_chain, &faucet, note_m2.id())
        .await
        .expect("S11a: after unpause the second attested mint must succeed");
    assert_eq!(
        minted2.output_notes().num_notes(),
        1,
        "S11a: one recipient note"
    );
    commit(&mut pf.mock_chain, &minted2)?;
    assert_supply(
        &pf.mock_chain,
        faucet_id,
        2 * MINT_AMOUNT - BURN_OK,
        "S11a after the second mint",
    )?;
    // S11b: with the faucet unpaused, a burn now EMITS and CONSUMES again — the burn path resumed.
    // (Under the policed pause semantics the S10b pause-era emit trapped at emit, so no note was
    // created then; this fresh burn proves the whole holder→note→faucet path is live again.)
    let resumed_items = XReserveBurnItems {
        dest_domain: TEST_SOURCE_DOMAIN,
        dest_recipient: ForeignChainAddress::new([0xEFu8; 32]),
    };
    let resumed_note = XReserveBurnNote::create(
        holder_id,
        faucet_id,
        AssetAmount::new(BURN_PAUSED)?,
        resumed_items,
        &mut note_rng(44),
    )?;
    let emit = try_emit_burn_note(
        &pf.mock_chain,
        &resumed_note,
        &paused_asset,
        faucet_id,
        holder_id,
    )
    .await
    .expect("S11b: after unpause the holder can emit a burn note again (send callback passes)");
    commit(&mut pf.mock_chain, &emit)?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let consume = consume_committed_note(&pf.mock_chain, &faucet, resumed_note.id())
        .await
        .expect("S11b: after unpause the resumed burn note consumes");
    commit(&mut pf.mock_chain, &consume)?;
    assert_supply(
        &pf.mock_chain,
        faucet_id,
        2 * MINT_AMOUNT - BURN_OK - BURN_PAUSED,
        "S11b after the resumed burn",
    )?;

    // ── S12 — ROTATION: ADMIN grants a new pauser -> the new member can pause
    // (capability-proven against a REAL attested mint); revoke -> they cannot.
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let tx = consume_committed_note(&pf.mock_chain, &faucet, note_id(10))
        .await
        .expect("S12: the ADMIN grant must succeed");
    commit(&mut pf.mock_chain, &tx)?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    assert_eq!(
        read_role_membership(&faucet, &pauser_sym, new_pauser())?,
        Word::from([1u32, 0, 0, 0]),
        "S12: the new pauser's membership reads back"
    );
    let tx = consume_committed_note(&pf.mock_chain, &faucet, note_id(11))
        .await
        .expect("S12: the NEW pauser can pause");
    commit(&mut pf.mock_chain, &tx)?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    // The new pauser's pause is capability-proven against a REAL attested mint (fresh nonce): the
    // probe note traps the pause gate and stays unconsumed (its nonce never burns).
    let note_m3 = production_mint_note(producer_id, faucet_id, &payload3, 64)?;
    emit_note_with_attachments(&mut pf.mock_chain, producer_id, &note_m3).await?;
    let result = consume_committed_note(&pf.mock_chain, &faucet, note_m3.id()).await;
    assert_transaction_executor_error!(result, err_paused());
    let tx = consume_committed_note(&pf.mock_chain, &faucet, note_id(12))
        .await
        .expect("S12: DOM_UNPAUSER lifts the new pauser's pause");
    commit(&mut pf.mock_chain, &tx)?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let tx = consume_committed_note(&pf.mock_chain, &faucet, note_id(13))
        .await
        .expect("S12: the ADMIN revoke must succeed");
    commit(&mut pf.mock_chain, &tx)?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    assert_eq!(
        read_role_membership(&faucet, &pauser_sym, new_pauser())?,
        Word::from([0u32, 0, 0, 0]),
        "S12: the revoked member's membership is cleared"
    );
    let result = consume_committed_note(&pf.mock_chain, &faucet, note_id(14)).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&faucet)?,
        Word::from([0u32, 0, 0, 0]),
        "S12: the revoked pause attempt left is_paused unchanged"
    );

    // ── S13 — FINAL LEDGER: the exact whole-arc equation + config read-backs on the ONE instance.
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    assert_supply(
        &pf.mock_chain,
        faucet_id,
        2 * MINT_AMOUNT - BURN_OK - BURN_PAUSED,
        "S13 final: 100 + 100 - 20 - 10 = 170",
    )?;
    assert_eq!(
        faucet
            .storage()
            .get_item(XReserveFaucetExtension::domain_config_slot())?,
        domain0,
        "S13: the domain word is byte-identical to its build-seed"
    );
    assert_eq!(
        read_token_config(&faucet)?[1],
        Felt::from(AssetAmount::new(NEW_MAX_SUPPLY)?),
        "S13: max_supply still the S3b value"
    );
    assert_eq!(
        read_min_burn_size(&faucet)?[0],
        Felt::from(AssetAmount::new(MIN_BURN)?),
        "S13: min_burn_size still the S3c value"
    );
    assert_eq!(
        read_map_word(
            &faucet,
            XReserveFaucetExtension::used_nonces_slot(),
            nonce_key_of_payload(&payload1)
        )?,
        marker(),
        "S13: nonce 1 still marked"
    );
    assert_eq!(
        read_map_word(
            &faucet,
            XReserveFaucetExtension::used_nonces_slot(),
            nonce_key_of_payload(&payload2)
        )?,
        marker(),
        "S13: nonce 2 still marked"
    );
    assert_eq!(
        read_map_word(
            &faucet,
            XReserveFaucetExtension::xreserve_attesters_slot(),
            attester1.commitment
        )?,
        marker(),
        "S13: the attester allowlist marker survives the whole arc"
    );
    assert_eq!(
        read_role_config(&faucet, &pauser_sym)?,
        marker(),
        "S13: DOM_PAUSER remains administered directly by ADMIN through the whole arc"
    );
    assert_eq!(
        read_role_membership(&faucet, &pauser_sym, pauser())?,
        marker(),
        "S13: the original DOM_PAUSER member is intact"
    );
    assert_eq!(
        read_role_membership(&faucet, &pauser_sym, new_pauser())?,
        Word::from([0u32, 0, 0, 0]),
        "S13: the rotated-out member stays revoked"
    );
    Ok(())
}

// SECOND-RECIPIENT ROUTING — a second attested mint targets a DIFFERENT wallet
// ================================================================================================

/// Full-path RECIPIENT ROUTING: the lifecycle E2E's mints all target the SAME wallet (the payload
/// variants only XOR a nonce byte), so recipient-encoding variety existed only at the
/// extraction-helper level. Here ONE production faucet mints twice — mint #1 to the recipient
/// wallet, mint #2 (distinct nonce, DISTINCT amount) whose `remoteRecipient` encodes the PRODUCER
/// wallet (a normal BasicWallet, standing in as the second P2ID target now that the fixture ships
/// exactly two wallets) — and EACH wallet consumes ITS P2ID note and holds exactly its own minted
/// amount: the intent's recipient bytes genuinely steer the funds end-to-end, not just at the
/// helper level.
#[tokio::test]
async fn second_mint_to_distinct_recipient() -> Result<()> {
    let mut pf = setup_production_faucet(0, |recipient, faucet_id| {
        let commitment =
            gen_attester(1, &payload_for(recipient, MINT_AMOUNT, 0, faucet_id)).commitment;
        let route = faucet_id;
        vec![
            // 0: owner set_attester (bring-up)
            XReserveSetAttesterNote::create(
                administrator(),
                route,
                commitment,
                1,
                &mut note_rng(931),
            )
            .expect("building the seeded attester-owner note"),
        ]
    })?;
    let faucet_id = pf.faucet_id;
    let recipient1_id = pf.recipient_id;
    let recipient2_id = pf.producer_id; // the second, DISTINCT P2ID target
    let payload1 = payload_for(recipient1_id, MINT_AMOUNT, 0, faucet_id);
    let payload2 = payload_for(recipient2_id, SECOND_MINT_AMOUNT, 0x5A, faucet_id);

    // Bring-up: set_attester (the production path), committed a block each.
    for (i, note) in pf.seeded_notes.clone().iter().enumerate() {
        let faucet = committed(&pf.mock_chain, faucet_id)?;
        let tx = consume_committed_note(&pf.mock_chain, &faucet, note.id())
            .await
            .unwrap_or_else(|e| panic!("bring-up note {i} must succeed: {e}"));
        commit(&mut pf.mock_chain, &tx)?;
    }

    // Mint #1 → recipient1's P2ID note.
    let note1 = production_mint_note(pf.producer_id, faucet_id, &payload1, 71)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note1).await?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let mint1 = consume_committed_note(&pf.mock_chain, &faucet, note1.id())
        .await
        .expect("mint #1 (recipient1) must pass");
    assert_eq!(
        mint1.output_notes().num_notes(),
        1,
        "mint #1: exactly one recipient note"
    );
    let p2id1_id = mint1.output_notes().get_note(0).id();
    assert_eq!(
        mint1.output_notes().get_note(0).metadata().tag(),
        NoteTag::with_account_target(recipient1_id),
        "mint #1's note targets recipient1"
    );
    commit(&mut pf.mock_chain, &mint1)?;

    // Mint #2 (distinct nonce, distinct amount) → the DIFFERENT wallet's P2ID note.
    let note2 = production_mint_note(pf.producer_id, faucet_id, &payload2, 72)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note2).await?;
    let faucet = committed(&pf.mock_chain, faucet_id)?;
    let mint2 = consume_committed_note(&pf.mock_chain, &faucet, note2.id())
        .await
        .expect("mint #2 (the DISTINCT recipient2) must pass");
    assert_eq!(
        mint2.output_notes().num_notes(),
        1,
        "mint #2: exactly one recipient note"
    );
    let p2id2_id = mint2.output_notes().get_note(0).id();
    assert_eq!(
        mint2.output_notes().get_note(0).metadata().tag(),
        NoteTag::with_account_target(recipient2_id),
        "mint #2's note targets the DISTINCT recipient2"
    );
    commit(&mut pf.mock_chain, &mint2)?;
    assert_supply(
        &pf.mock_chain,
        faucet_id,
        MINT_AMOUNT + SECOND_MINT_AMOUNT,
        "after both mints",
    )?;

    // Each recipient consumes ITS note; each holds exactly its own minted amount.
    let r1 = committed(&pf.mock_chain, recipient1_id)?;
    let c1 = consume_committed_note_with_faucet_foreign(&pf.mock_chain, &r1, p2id1_id, faucet_id)
        .await
        .expect("recipient1 consumes its P2ID note");
    commit(&mut pf.mock_chain, &c1)?;
    let r2 = committed(&pf.mock_chain, recipient2_id)?;
    let c2 = consume_committed_note_with_faucet_foreign(&pf.mock_chain, &r2, p2id2_id, faucet_id)
        .await
        .expect("recipient2 consumes ITS P2ID note");
    commit(&mut pf.mock_chain, &c2)?;
    assert_eq!(
        wallet_balance(&committed(&pf.mock_chain, recipient1_id)?, faucet_id),
        MINT_AMOUNT,
        "recipient1 holds exactly its minted amount"
    );
    assert_eq!(
        wallet_balance(&committed(&pf.mock_chain, recipient2_id)?, faucet_id),
        SECOND_MINT_AMOUNT,
        "recipient2 holds exactly ITS minted amount — the intent's recipient bytes steer the funds"
    );
    Ok(())
}
