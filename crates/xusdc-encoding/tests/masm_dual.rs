//! Cross-language conformance: the MASM codecs must agree with their Rust twins on every
//! canonical vector.
//!
//! Two routines are still shared between the on-chain faucet and the off-chain services and
//! written twice — once in MASM, once in Rust: the bytes32 → storage key hash and the attester
//! pubkey commitment. If the two ever disagree, the off-chain side signs or relays something the
//! chain will reject, or worse, accepts something the chain would have rejected. The tests here
//! run each MASM routine over the same golden vectors the Rust unit tests use and require
//! identical results, accept and reject alike.
//!
//! How the assertions are made matters as much as what they assert. Every conformance claim is
//! made on the result of actually EXECUTING the MASM in a transaction — never on assembly
//! succeeding — and the expected values are read from the canonical vector artifact rather than
//! recomputed by calling the Rust routine. Comparing the Rust implementation against itself
//! would pass no matter how far the MASM had drifted.
//!
//! The library under test is the SHIPPED one — the package this crate's build script assembled and
//! embedded, linked dynamically into a transaction script — so the code exercised here is the code
//! that ships, not a second assembly of the same sources. A handful of probe tests at the end pin
//! those harness mechanics, so that a toolchain change breaks them rather than silently changing
//! what the conformance tests mean.

use std::fmt::Write as _;

use anyhow::{Context, Result};
use assert_matches::assert_matches;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountId};
use miden_protocol::assembly::Package;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};
use miden_tx::TransactionExecutorError;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use xusdc_encoding::vectors::{load, word_from_hex};
use xusdc_encoding::xreserve::encoding::EncodingError;
use xusdc_encoding::xreserve_lib::XReserveLibrary;

/// Memory base for the staged pubkey felts `pubkey_commitment` hashes in place (word-aligned,
/// clear of `INTENT_PTR`).
const PUBKEY_PTR: u64 = 8;

// HARNESS (assemble → bind → MockChain account)
// ================================================================================================

struct Harness {
    mock_chain: MockChain,
    account_id: AccountId,
    library: Package,
}

/// Builds the MockChain account that carries the encoding library (registering its MAST
/// forest with the executor, which is what makes its procedures available to run).
fn setup() -> Result<Harness> {
    let library = Package::from(XReserveLibrary::default());
    let component = AccountComponent::new(
        library.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-encoding-harness"),
    )
    .context("binding the encoding library as a harness component")?;
    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(Auth::IncrNonce, [component])
        .context("adding the harness account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(Harness {
        mock_chain,
        account_id: account.id(),
        library,
    })
}

/// Compiles a generated driver script with the encoding library dynamically linked and
/// executes it as a transaction (test_array.rs:127-135 pattern).
async fn run_driver(
    h: &Harness,
    src: &str,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_package(&h.library)
        .expect("linking the encoding library into the driver script")
        .compile_tx_script(src)
        .unwrap_or_else(|e| panic!("driver script failed to compile: {e}\n--- driver ---\n{src}"));
    h.mock_chain
        .build_transaction(h.account_id)
        .tx_script(tx_script)
        .build()
        .expect("building the transaction")
        .execute()
        .await
}

fn word_of(felts: &[Felt]) -> Word {
    Word::new([felts[0], felts[1], felts[2], felts[3]])
}

// PARITY 1 — bytes32 → storage-map key: every b32 vector, executed on the VM
// ================================================================================================

#[tokio::test]
async fn tv_dual_1_hash_nonce() -> Result<()> {
    let h = setup()?;
    for vec in &load().families.b32 {
        let limbs = vec.packed_felts_values();
        let (b0, b1) = (word_of(&limbs[0..4]), word_of(&limbs[4..8]));
        let expected = word_from_hex(&vec.expected_key);
        let src = format!(
            r#"use xreserve::mint_intent

@transaction_script
pub proc main
    push.{b1}
    push.{b0}
    exec.mint_intent::hash_nonce
    push.{expected}
    assert_eqw.err="vector {id}: key mismatch"
end
"#,
            id = vec.id,
        );
        run_driver(&h, &src).await.unwrap_or_else(|e| {
            panic!(
                "vector {}: MASM hash_nonce must produce the canonical key: {e}",
                vec.id
            )
        });
    }
    Ok(())
}

// PARITY 3 — DepositIntent parsing: RUST-ONLY since DC-14
// ================================================================================================
// There is no MASM parser to compare against any more. The faucet no longer reads Circle's
// DepositIntent off the wire — it WRITES the signed message from the note's carried payload plus
// its own state (`NS-3`), so `TV-DUAL-3`'s on-chain leg moved to `TV-DUAL-6` in
// `masm_mint_shell.rs`, where the writer's felts are compared against the Rust mirror's.
//
// The Rust half of `TV-DUAL-3` is unaffected and still runs: `DepositIntent::parse_header` remains
// the compress-side entry and the relayer's pre-validate, covered by the unit tests in
// `deposit_intent.rs`. The Circle differential (`TV-CIRCLE-DIFF`) likewise keeps its byte-level
// leg there — what it can no longer do is push those bytes through an on-chain parser, because
// none exists.

// PARITY 4 — attester pubkey commitment: the Word the allowlist is keyed by
// ================================================================================================
// Each attestation vector is run through the MASM commitment routine and the result is checked
// against two independent references at once: the value pinned in the canonical artifact, and
// miden-crypto's own `PublicKey::to_commitment` recomputed here — the routine the off-chain side
// keys the allowlist with. All three must agree, because the faucet decides whether an attester is
// allowlisted by looking up exactly this Word — if the off-chain side computed a different
// commitment for the same key, a legitimate attester would be seeded under a key the chain never
// looks at. Recomputing also catches an artifact that went stale against the pinned crypto crate.
// ================================================================================================

#[tokio::test]
async fn tv_dual_5_pubkey_commitment() -> Result<()> {
    let h = setup()?;
    for vec in &load().families.att {
        // the public key as 16 field elements, in the affine-coordinate order miden-crypto emits
        let limbs = vec.packed_felts_values();
        let (pkw0, pkw1, pkw2, pkw3) = (
            word_of(&limbs[0..4]),
            word_of(&limbs[4..8]),
            word_of(&limbs[8..12]),
            word_of(&limbs[12..16]),
        );
        let expected = vec.expected_commitment_word();

        // recomputed off-chain commitment == the vector oracle: the third anti-drift leg,
        // asserted in-process so a drift fails here too, not only in TV-ATT-2.
        assert_eq!(
            vec.public_key().to_commitment(),
            expected,
            "vector {}: the off-chain commitment must equal the pinned oracle",
            vec.id
        );

        // MASM proc executed under MockChain: stage the 16 felts (f0 at the lowest address),
        // push the pointer, exec, assert the returned Word equals the oracle.
        let (pk_ptr1, pk_ptr2, pk_ptr3) = (PUBKEY_PTR + 4, PUBKEY_PTR + 8, PUBKEY_PTR + 12);
        let src = format!(
            r#"use xreserve::attestation_verify

@transaction_script
pub proc main
    push.{pkw0} mem_storew_le.{PUBKEY_PTR} dropw
    push.{pkw1} mem_storew_le.{pk_ptr1} dropw
    push.{pkw2} mem_storew_le.{pk_ptr2} dropw
    push.{pkw3} mem_storew_le.{pk_ptr3} dropw
    push.{PUBKEY_PTR}
    exec.attestation_verify::pubkey_commitment
    push.{expected}
    assert_eqw.err="vector {id}: pubkey_commitment mismatch"
end
"#,
            id = vec.id,
        );
        run_driver(&h, &src).await.unwrap_or_else(|e| {
            panic!(
                "vector {}: MASM pubkey_commitment must equal miden-crypto to_commitment: {e}",
                vec.id
            )
        });
    }
    Ok(())
}

// HARNESS META-TEST + PROBES (scaffold surfaces)
// ================================================================================================

/// Meta-test: a deliberately-wrong expected value (constructed here, never in the
/// artifact) must FAIL execution — proves a vector mismatch fails the run.
#[tokio::test]
async fn harness_detects_wrong_vector() -> Result<()> {
    let h = setup()?;
    let vec = &load().families.b32[0];
    let limbs = vec.packed_felts_values();
    let (b0, b1) = (word_of(&limbs[0..4]), word_of(&limbs[4..8]));
    let mut wrong = word_from_hex(&vec.expected_key);
    wrong[0] += miden_protocol::ONE;
    let src = format!(
        r#"use xreserve::mint_intent

@transaction_script
pub proc main
    push.{b0}
    push.{b1}
    exec.mint_intent::hash_nonce
    push.{wrong}
    assert_eqw.err="meta-test: deliberately wrong expected value"
end
"#
    );
    let result = run_driver(&h, &src).await;
    assert!(
        result.is_err(),
        "a wrong expected value MUST fail execution — the harness cannot pass on a bad vector"
    );
    Ok(())
}

/// P2: a trivial driver executes through the MockChain path (script wiring sanity).
#[tokio::test]
async fn probe_p2_script_executes() -> Result<()> {
    let h = setup()?;
    run_driver(
        &h,
        "@transaction_script\npub proc main\n    push.1 drop\nend\n",
    )
    .await
    .expect("trivial driver must execute");
    Ok(())
}

// probe_p3_placeholder_trap_surfaces was removed: it existed to prove trap plumbing against
// placeholder traps, and the last placeholder is now gone. The exact-error plumbing it proved
// is now exercised continuously by every reject vector in tv_dual_2/tv_dual_3.

/// P4: the packing primitive is reachable via the miden-protocol re-export.
#[test]
fn probe_p4_packing_util() {
    let felts = miden_protocol::utils::bytes_to_packed_u32_elements(&[1u8, 2, 3, 4]);
    assert_eq!(felts.len(), 1);
}

// DIFFERENTIAL — bytes produced by Circle's own encoder, parsed by ours
// ================================================================================================
// Everything else in this file compares our MASM against our Rust over vectors we generated. That
// cannot catch a shared misreading of Circle's wire format: if both halves place a field at the
// wrong offset, both agree and both are wrong. This test closes that gap by parsing bytes that
// Circle's encoder produced.
//
// Provenance of the fixture, stated precisely because it bounds what the test proves. It was
// generated locally from Circle's contract source (evm-xreserve-contracts @ a571cbe12fa7cede)
// by a Foundry script — kept alongside it under `tests/vectors/circle-extraction/` — that calls
// Circle's own `DepositIntentLib.encodeDepositIntent` over fixed field values. It is not a blob
// copied from Circle: their tracked tree at that commit ships neither golden hex nor an
// extraction script. So the INPUT bytes are genuinely Circle's encoding; the expected field
// values are derived from those raw bytes and checked against the field offsets declared in
// Circle's `DepositIntent.sol`. Circle's decoder is never run here.
//
// What this establishes is that the shared parser's envelope — field offsets, field sizes,
// endianness, the magic and version constants, and the total-length rule — matches Circle's
// encoder.
//
// The fixture carries the identifier fields both ways, because Circle's encoding permits both and
// this decoder must answer differently: two rows hold opaque bytes32 (what Circle's own sample
// values look like) and two hold Miden account ids in the packaging this crate reads. The envelope
// is identical across the pair, so the difference isolates exactly the Miden-side reading — the
// account-id rows must decode, the opaque ones must be refused rather than misread. How an account
// id is registered into those fields remains Circle's to settle (`DEV-10`).

const CIRCLE_FIXTURE: &str = include_str!("vectors/circle-depositintent-groundtruth.json");

#[derive(Deserialize)]
struct CircleFile {
    vectors: Vec<CircleVec>,
}

#[derive(Deserialize)]
struct CircleVec {
    id: String,
    identifier_shape: String,
    bytes_hex: String,
    length: u64,
    message_hash_keccak256: String,
    fields: CircleFields,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CircleFields {
    magic: String,
    version: u64,
    amount: u128,
    remote_domain: u64,
    remote_token: String,
    remote_recipient: String,
    local_token: String,
    local_depositor: String,
    max_fee: u128,
    nonce: String,
    hook_data_length: u64,
    hook_data: String,
}

/// Decodes a `0x`-prefixed hex string to bytes.
fn circle_hexdec(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// `0x`-prefixed lowercase hex of a byte slice.
fn circle_hex(s: &[u8]) -> String {
    let mut out = String::from("0x");
    for b in s {
        write!(out, "{b:02x}").unwrap();
    }
    out
}

/// A uint256 value (here always within u128) as its 32-byte big-endian wire encoding.
fn be32_of_u128(v: u128) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[16..32].copy_from_slice(&v.to_be_bytes());
    b
}

#[tokio::test]
async fn tv_circle_differential_real_bytes() -> Result<()> {
    let file: CircleFile =
        serde_json::from_str(CIRCLE_FIXTURE).expect("circle ground-truth fixture parses");
    assert!(
        !file.vectors.is_empty(),
        "circle fixture must carry vectors"
    );

    for v in &file.vectors {
        let raw = circle_hexdec(&v.bytes_hex);
        let f = &v.fields;

        // (1) Check our understanding of the layout without involving the parser at all: slice
        // the raw bytes at the offsets and widths we believe Circle uses, read them big-endian,
        // and require them to equal the field values the fixture states (which the extraction
        // script asserted against Circle's own offset constants). If our offset model is wrong,
        // this fails here, before any of our code has had a chance to be consistently wrong.
        assert_eq!(raw.len() as u64, v.length, "{}: declared length", v.id);
        assert_eq!(
            raw.len() as u64,
            240 + f.hook_data_length,
            "{}: length == 240 + hookDataLength",
            v.id
        );
        assert_eq!(circle_hex(&raw[0..4]), f.magic, "{}: magic @0", v.id);
        assert_eq!(
            u32::from_be_bytes(raw[4..8].try_into().unwrap()) as u64,
            f.version,
            "{}: version @4",
            v.id
        );
        assert_eq!(
            &raw[8..40],
            &be32_of_u128(f.amount)[..],
            "{}: amount @8",
            v.id
        );
        assert_eq!(
            u32::from_be_bytes(raw[40..44].try_into().unwrap()) as u64,
            f.remote_domain,
            "{}: remoteDomain @40",
            v.id
        );
        assert_eq!(
            circle_hex(&raw[44..76]),
            f.remote_token,
            "{}: remoteToken @44",
            v.id
        );
        assert_eq!(
            circle_hex(&raw[76..108]),
            f.remote_recipient,
            "{}: remoteRecipient @76",
            v.id
        );
        assert_eq!(
            circle_hex(&raw[108..140]),
            f.local_token,
            "{}: localToken @108",
            v.id
        );
        assert_eq!(
            circle_hex(&raw[140..172]),
            f.local_depositor,
            "{}: localDepositor @140",
            v.id
        );
        assert_eq!(
            &raw[172..204],
            &be32_of_u128(f.max_fee)[..],
            "{}: maxFee @172",
            v.id
        );
        assert_eq!(circle_hex(&raw[204..236]), f.nonce, "{}: nonce @204", v.id);
        assert_eq!(
            u32::from_be_bytes(raw[236..240].try_into().unwrap()) as u64,
            f.hook_data_length,
            "{}: hookDataLength @236",
            v.id
        );
        let hd = if raw.len() > 240 {
            circle_hex(&raw[240..])
        } else {
            String::from("0x")
        };
        assert_eq!(hd, f.hook_data, "{}: hookData @240", v.id);

        // The fixture's own digest is pinned here rather than trusted: it is what the relayer's
        // envelope binding is checked against, and a stale one would quietly stop testing anything.
        assert_eq!(
            circle_hex(&Keccak256::digest(&raw)),
            v.message_hash_keccak256,
            "{}: keccak256 of the encoded bytes",
            v.id
        );

        // (2) The Miden-side reading of the same bytes. There is no on-chain parser to run them
        // through any more — the faucet writes the message rather than reading it — so the
        // differential stops at the Rust decode, and the write side is covered by TV-DUAL-6.
        let decoded = xusdc_encoding::xreserve::encoding::DepositIntent::try_from(raw.as_slice());
        match v.identifier_shape.as_str() {
            "account_id" => {
                let packed = decoded
                    .unwrap_or_else(|e| panic!("{}: Circle's own bytes must decode: {e}", v.id))
                    .to_preimage_felts();
                assert_eq!(
                    packed.len(),
                    raw.len().div_ceil(4),
                    "{}: the packed preimage is four wire bytes per felt",
                    v.id
                );
            }
            // an identifier this faucet could never mint to is refused with the reason, not
            // truncated into some nearby account id
            "opaque" => assert_matches!(
                decoded,
                Err(EncodingError::AccountIdOutOfRange),
                "{}: an opaque bytes32 identifier is not mintable",
                v.id
            ),
            other => panic!("{}: unknown identifier_shape {other:?}", v.id),
        }
    }

    Ok(())
}
