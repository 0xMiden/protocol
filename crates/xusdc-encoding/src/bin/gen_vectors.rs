//! Committed generator of the ONE canonical golden-vector artifact
//! (`tests/vectors/xreserve-encoding-vectors.json`).
//!
//! Arithmetic and layout expectations are derived here with exact integer math (the formula is
//! recorded per entry); hash- and protocol-derived expectations (Poseidon2 Words, AccountIds) come
//! from the protocol crates via `Hasher::hash_elements`, `bytes_to_packed_u32_elements`, and
//! `AccountIdBuilder::build_with_seed`. Every family is derived independently of the code it
//! checks, except the `mi` carried and rebuilt felts, which are recorded from the Rust mirror and
//! pinned against the MASM writer. Regeneration is an explicit, reviewed act:
//! `cargo run --bin gen_vectors`.
//!
//! Wire-format byte offsets used below: magic@0, version@4, amount@8, remoteDomain@40,
//! remoteToken@44, remoteRecipient@76, localToken@108, localDepositor@140, maxFee@172,
//! nonce@204, hookDataLen@236, hookData@240; header = 240 bytes = 60 u32-LE felts.

use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey};
use miden_crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_crypto::utils::{Deserializable, Serializable};
use miden_crypto::SequentialCommit;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Hasher, Word};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use xusdc_encoding::xreserve::encoding::CircleDomain;

const ASSET_AMOUNT_MAX: u128 = (1u128 << 63) - (1u128 << 31); // 2^63 - 2^31

fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn felt_hex(f: Felt) -> String {
    format!("0x{:x}", f.as_canonical_u64())
}

fn felts_hex(felts: &[Felt]) -> Vec<String> {
    felts.iter().copied().map(felt_hex).collect()
}

fn word_hex(w: Word) -> Vec<String> {
    felts_hex(w.as_elements())
}

/// 32-byte big-endian wire encoding of a u128-sized uint256 value.
fn u256_be_from_u128(x: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&x.to_be_bytes());
    out
}

/// The u64 an accept vector's uint256 amount field reduces to (the shipped scale is zero, so the
/// reduction is the identity and the value is simply the low 8 bytes).
fn u64_from_be32(b: &[u8; 32]) -> u64 {
    u64::from_be_bytes(b[24..].try_into().expect("8-byte window"))
}

fn packed(bytes: &[u8]) -> Vec<Felt> {
    bytes_to_packed_u32_elements(bytes)
}

// clippy 1.93 flags the `Word::from` as `useless_conversion` when the `vectors` feature compiles
// this generator, but removing it would change executable behaviour, so the lint is suppressed in
// place instead.
#[allow(clippy::useless_conversion)]
fn poseidon2_key(bytes32: &[u8; 32]) -> Word {
    Word::from(Hasher::hash_elements(&packed(bytes32)))
}

// uint256 → AssetAmount reducer entries
// ================================================================================================

fn amt_accept(id: &str, tv: &[&str], x: u128, derivation: &str) -> Value {
    let b = u256_be_from_u128(x);
    assert!(
        x <= ASSET_AMOUNT_MAX,
        "{id}: accept vector must be within the cap"
    );
    json!({
        "id": id, "tv": tv, "kind": "accept",
        "uint256_be": hex_bytes(&b),
        // the shipped scale is zero, so the reduction is the identity
        "expected_y": x.to_string(),
        "cite": "CIR-FEE-3",
        "derivation": derivation,
    })
}

fn amt_reject(
    id: &str,
    tv: &[&str],
    b: [u8; 32],
    variant: &str,
    cite: &str,
    derivation: &str,
) -> Value {
    json!({
        "id": id, "tv": tv, "kind": "reject",
        "uint256_be": hex_bytes(&b),
        "expected_variant": variant,
        "cite": cite, "derivation": derivation,
    })
}

// DepositIntent entries
// ================================================================================================

struct IntentSpec {
    magic: u32,
    version: u32,
    amount: [u8; 32],
    remote_domain: u32,
    remote_token: [u8; 32],
    remote_recipient: [u8; 32],
    local_token: [u8; 32],
    local_depositor: [u8; 32],
    max_fee: [u8; 32],
    nonce: [u8; 32],
    hook_data: Vec<u8>,
    /// When set, the encoded hookDataLen field diverges from `hook_data.len()`, which is how the
    /// length-mismatch vectors are constructed.
    hook_data_len_override: Option<u32>,
}

fn pattern32(base: u8) -> [u8; 32] {
    core::array::from_fn(|i| base.wrapping_add(i as u8))
}

impl IntentSpec {
    /// A structurally well-formed intent. `remote_token` names a faucet OTHER than the `mi`
    /// family's, so a row that confused the destination token with the destination account would
    /// not pass.
    fn base(remote_token: [u8; 32], remote_recipient: [u8; 32]) -> Self {
        Self {
            magic: 0x5a2e_0acd, // DepositIntent magic
            version: 1,         // DepositIntent version
            amount: u256_be_from_u128(1_000_000),
            remote_domain: 7,
            remote_token,
            remote_recipient,
            local_token: pattern32(0xb0),
            local_depositor: pattern32(0xc0),
            max_fee: u256_be_from_u128(2_000_000),
            nonce: pattern32(0xd0),
            hook_data: Vec::new(),
            hook_data_len_override: None,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(240 + self.hook_data.len());
        out.extend_from_slice(&self.magic.to_be_bytes()); // @0
        out.extend_from_slice(&self.version.to_be_bytes()); // @4
        out.extend_from_slice(&self.amount); // @8
        out.extend_from_slice(&self.remote_domain.to_be_bytes()); // @40
        out.extend_from_slice(&self.remote_token); // @44
        out.extend_from_slice(&self.remote_recipient); // @76
        out.extend_from_slice(&self.local_token); // @108
        out.extend_from_slice(&self.local_depositor); // @140
        out.extend_from_slice(&self.max_fee); // @172
        out.extend_from_slice(&self.nonce); // @204
        let hdl = self
            .hook_data_len_override
            .unwrap_or(self.hook_data.len() as u32);
        out.extend_from_slice(&hdl.to_be_bytes()); // @236
        out.extend_from_slice(&self.hook_data); // @240
        assert_eq!(out.len(), 240 + self.hook_data.len());
        out
    }
}

/// Per-field felt offsets within the packed preimage (byte offset / 4; 4 bytes per felt).
const FIELD_FELT_OFFS: [(&str, usize, usize); 12] = [
    ("magic", 0, 1),
    ("version", 1, 1),
    ("amount", 2, 8),
    ("remote_domain", 10, 1),
    ("remote_token", 11, 8),
    ("remote_recipient", 19, 8),
    ("local_token", 27, 8),
    ("local_depositor", 35, 8),
    ("max_fee", 43, 8),
    ("nonce", 51, 8),
    ("hook_data_len", 59, 1),
    ("hook_data", 60, 0), // length = ceil(hookDataLen/4), variable
];

fn di_accept(id: &str, tv: &[&str], spec: &IntentSpec, derivation: &str) -> Value {
    let bytes = spec.encode();
    let preimage = packed(&bytes);
    let hook_felts = preimage.len() - 60;
    let packed_fields: Vec<Value> = FIELD_FELT_OFFS
        .iter()
        .map(|(name, off, len)| {
            let len = if *name == "hook_data" {
                hook_felts
            } else {
                *len
            };
            json!({
                "name": name, "felt_off": off,
                "felts": felts_hex(&preimage[*off..*off + len]),
            })
        })
        .collect();
    json!({
        "id": id, "tv": tv, "kind": "accept",
        "bytes_hex": hex_bytes(&bytes),
        "preimage_felts": felts_hex(&preimage),
        "len_felts": preimage.len(),
        "fields": {
            "magic": spec.magic, "version": spec.version,
            "remote_domain": spec.remote_domain,
            "hook_data_len": spec.hook_data.len() as u32,
            "amount": u64_from_be32(&spec.amount),
            "max_fee": u64_from_be32(&spec.max_fee),
            "amount_hex": hex_bytes(&spec.amount),
            "remote_token_hex": hex_bytes(&spec.remote_token),
            "remote_recipient_hex": hex_bytes(&spec.remote_recipient),
            "local_token_hex": hex_bytes(&spec.local_token),
            "local_depositor_hex": hex_bytes(&spec.local_depositor),
            "max_fee_hex": hex_bytes(&spec.max_fee),
            "nonce_hex": hex_bytes(&spec.nonce),
            "packed": packed_fields,
            "remote_token_felts": felts_hex(&preimage[11..19]),
        },
        "cite": "DC-1",
        "derivation": derivation,
    })
}

fn di_reject(
    id: &str,
    tv: &[&str],
    bytes: &[u8],
    variant: &str,
    masm_err: Option<&str>,
    cite: &str,
    derivation: &str,
) -> Value {
    let preimage = packed(bytes);
    json!({
        "id": id, "tv": tv, "kind": "reject",
        "bytes_hex": hex_bytes(bytes),
        "preimage_felts": felts_hex(&preimage),
        "len_felts": preimage.len(),
        "expected_variant": variant, "masm_err": masm_err,
        "cite": cite, "derivation": derivation,
    })
}

// Attestation (ATT) entries — Rust + MASM dual surface
// ================================================================================================
// the secp256k1 keypair and signature come from the INDEPENDENT `k256` crate and the keccak digest
// from `sha3`. The commitment oracle is miden-crypto
// `PublicKey::to_commitment` — the attester-allowlist keying primitive the faucet's attestation
// verify looks up — deserialized from the exact 33 compressed wire bytes.

/// Deterministic independent secp256k1 keypair (k256 + seeded StdRng).
fn att_keypair(seed: u64) -> SigningKey {
    let mut bytes = [0u8; 32];
    StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
    SigningKey::from_slice(&bytes).expect("the seed yields a valid non-zero scalar")
}

/// 33-byte compressed SEC1 public key.
fn att_pk33(sk: &SigningKey) -> [u8; 33] {
    sk.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 pubkey is 33 bytes")
}

/// keccak256 (original Keccak, not NIST SHA3-256) of `msg` via the INDEPENDENT `sha3` crate.
fn att_keccak256(msg: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(msg);
    h.finalize().into()
}

/// 65-byte `r || s || v` signature of `digest` under `sk`, generated entirely by `k256`
/// (`sign_prehash_recoverable`) and laid out as miden-crypto's `Signature` serialization does
/// (r‖s‖v, v = recovery id). RAW secp256k1 over the keccak digest: NO EIP-712 domain, no
/// struct; v is carried, unused on-chain.
fn att_sign65(sk: &SigningKey, digest: &[u8; 32]) -> [u8; 65] {
    let (sig, recid): (K256Signature, RecoveryId) = sk
        .sign_prehash_recoverable(digest)
        .expect("k256 prehash sign");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(sig.to_bytes().as_slice()); // 64-byte big-endian r || s
    out[64] = recid.to_byte(); // v in {0..3}
    out
}

/// The canonical commitment oracle: deserialize the exact 33 compressed wire bytes into the
/// miden-crypto `PublicKey` and take `to_commitment()` = Poseidon2 over the 16 affine-coordinate
/// pubkey felts. This is exactly what off-chain `set_attester` keys the `xReserveAttesters`
/// allowlist by.
fn att_commitment(pk33: &[u8; 33]) -> Word {
    att_pubkey(pk33).to_commitment()
}

/// The 33 compressed wire bytes as the miden-crypto key the affine packing and the commitment both
/// come off.
fn att_pubkey(pk33: &[u8; 33]) -> PublicKey {
    PublicKey::read_from_bytes(pk33).expect("valid compressed secp256k1 pubkey")
}

fn main() {
    // ---- b32 family -------------------------------------------------------------------
    let b32_inputs: [(&str, [u8; 32], &str); 3] = [
        ("b32-pos-1", [0u8; 32], "all-zero bytes32"),
        ("b32-pos-2", [0xffu8; 32], "all-0xff bytes32"),
        (
            "b32-pos-3",
            core::array::from_fn(|i| i as u8),
            "bytes 0x00..0x1f",
        ),
    ];
    let mut b32: Vec<Value> = b32_inputs
        .iter()
        .map(|(id, b, what)| {
            json!({
                "id": id, "tv": ["TV-B32-1", "TV-B32-3", "TV-B32-4", "TV-DUAL-1"],
                "bytes32": hex_bytes(b),
                "packed_felts": felts_hex(&packed(b)),
                "expected_key": word_hex(poseidon2_key(b)),
                "cite": "generated deterministically by gen_vectors @ protocol v0.17.0-rc.7",
                "derivation": format!(
                    "{what}; key = Hasher::hash_elements(bytes_to_packed_u32_elements(b)) @ protocol v0.17.0-rc.7 (gen_vectors)"
                ),
            })
        })
        .collect();
    // limb >= p: the first 8-byte LE limb is u64::MAX (> p = 2^64 - 2^32 + 1).
    let mut ge_p = [0u8; 32];
    ge_p[..8].copy_from_slice(&[0xff; 8]);
    for (i, byte) in ge_p[8..].iter_mut().enumerate() {
        *byte = i as u8;
    }
    b32.push(json!({
        "id": "b32-rej-limb-ge-p", "tv": ["TV-B32-2", "TV-DUAL-1"],
        "bytes32": hex_bytes(&ge_p),
        "packed_felts": felts_hex(&packed(&ge_p)),
        "expected_key": word_hex(poseidon2_key(&ge_p)),
        "lossless_error": "LimbOutOfField",
        "cite": "generated deterministically by gen_vectors @ protocol v0.17.0-rc.7",
        "derivation": "first 8-byte LE limb = u64::MAX >= p, so the fallible native path must reject while Option B hashes; key computed @ v0.17.0-rc.7",
    }));

    // ---- amt family -------------------------------------------------------------------
    let max = ASSET_AMOUNT_MAX;
    let amt = vec![
        amt_accept("amt-pos-1", &["TV-AMT-1"], 42, "y = x = 42"),
        amt_accept(
            "amt-cap-accept",
            &["TV-AMT-2"],
            max,
            "cap boundary: x = 2^63 - 2^31, y = x = AssetAmount::MAX exactly",
        ),
        amt_reject(
            "amt-rej-cap",
            &["TV-AMT-3"],
            u256_be_from_u128(max + 1),
            "AmountOverCap",
            "generated deterministically by gen_vectors @ protocol v0.17.0-rc.7",
            "x = y = 2^63 - 2^31 + 1 = MAX + 1 must reject (no saturation)",
        ),
        {
            // bit 130 set => high four limbs nonzero (> 2^128). BE byte 15, bit 2.
            let mut b = [0u8; 32];
            b[15] = 0x04;
            amt_reject(
                "amt-rej-limb-overflow",
                &["TV-AMT-4"],
                b,
                "AmountTooLarge",
                "generated deterministically by gen_vectors @ protocol v0.17.0-rc.7",
                "x = 2^130: high-4 limbs nonzero must reject (limb-overflow edge)",
            )
        },
    ];
    // ---- aid family -------------------------------------------------------------------
    let ids: Vec<miden_protocol::account::AccountId> = (1u8..=3)
        .map(|seed| AccountIdBuilder::new().build_with_seed([seed; 32]))
        .collect();
    // the right-aligned (Agglayer-mirroring) AccountId packaging — a draft that stays OPEN, pending
    // Circle confirmation: bytes[0..16]=0, bytes[16..24]=prefix u64 BE, bytes[24..32]=suffix u64 BE.
    // Derived inline from the protocol AccountId accessors.
    let r_b_bytes32 = |id: &miden_protocol::account::AccountId| -> [u8; 32] {
        let mut b = [0u8; 32];
        b[16..24].copy_from_slice(&id.prefix().as_u64().to_be_bytes());
        b[24..32].copy_from_slice(&id.suffix().as_canonical_u64().to_be_bytes());
        b
    };
    let mut aid: Vec<Value> = Vec::new();
    for (n, id) in ids.iter().enumerate() {
        let b32_bytes = r_b_bytes32(id);
        let prefix: Felt = id.prefix().as_felt();
        let suffix: Felt = id.suffix();
        aid.push(json!({
            "id": format!("aid-rt-{}", n + 1),
            "tv": ["TV-AID-1", "TV-AID-4"],
            "bytes32": hex_bytes(&b32_bytes),
            "prefix_felt": felt_hex(prefix), "suffix_felt": felt_hex(suffix),
            "cite": "DEV-10 + IMPL-ACCOUNTID-LAYOUT (R-B / Agglayer-mirroring draft, REQUIRES CIRCLE CONFIRMATION)",
            "derivation": format!(
                "AccountIdBuilder::new().build_with_seed([{}; 32]) @ v0.17.0-rc.7; R-B layout: bytes[0..16]=0, [16..24]=prefix u64 BE, [24..32]=suffix u64 BE",
                n + 1
            ),
        }));
    }
    // out-of-range: an otherwise valid encoding with a non-zero byte in the leading 16-byte pad.
    {
        let mut bad = r_b_bytes32(&ids[0]);
        bad[0] = 0x01;
        aid.push(json!({
            "id": "aid-rej-out-of-range", "tv": ["TV-AID-2"],
            "bytes32": hex_bytes(&bad),
            "expected_variant": "AccountIdOutOfRange",
            "cite": "generated deterministically by gen_vectors @ protocol v0.17.0-rc.7",
            "derivation": "aid-rt-1 R-B bytes32 with byte[0] = 0x01 (non-zero in the leading 16-byte pad)",
        }));
    }
    // non-canonical: zero pad, in-field prefix/suffix felts that do not form a canonical
    // AccountId (exercises AccountId::try_from_elements; a non-zero suffix low byte alone
    // breaks canonicity).
    {
        let (prefix, suffix) = (7u64, 7u64);
        let prefix_felt = Felt::try_from(prefix).expect("in-field");
        let suffix_felt = Felt::try_from(suffix).expect("in-field");
        assert!(
            miden_protocol::account::AccountId::try_from_elements(suffix_felt, prefix_felt)
                .is_err(),
            "generator invariant: candidate prefix/suffix must NOT form a canonical AccountId"
        );
        let mut bad = [0u8; 32];
        bad[16..24].copy_from_slice(&prefix.to_be_bytes());
        bad[24..32].copy_from_slice(&suffix.to_be_bytes());
        aid.push(json!({
            "id": "aid-rej-non-canonical", "tv": ["TV-AID-2"],
            "bytes32": hex_bytes(&bad),
            "expected_variant": "NonCanonicalAccountId",
            "cite": "generated deterministically by gen_vectors @ protocol v0.17.0-rc.7",
            "derivation": "R-B layout, zero pad; prefix=suffix=7 (in-field) rejected by AccountId::try_from_elements @ v0.17.0-rc.7",
        }));
    }
    let recipient_b32: [u8; 32] = r_b_bytes32(&ids[0]);
    // the structural family is addressed to a DIFFERENT faucet than the `mi` family's, so a row
    // that mixed up the destination token and the destination account could not pass
    let di_token_b32: [u8; 32] = r_b_bytes32(&ids[2]);

    // ---- di family --------------------------------------------------------------------
    let mut di: Vec<Value> = Vec::new();
    {
        let mut spec = IntentSpec::base(di_token_b32, recipient_b32);
        spec.hook_data = (0..10u8).map(|i| 0xe0 + i).collect();
        di.push(di_accept(
            "di-pos-hookdata",
            &["TV-DI-1", "TV-DI-7", "TV-DI-8", "TV-DUAL-3"],
            &spec,
            "valid intent, hookDataLen = 10 (3 hookData felts; total 63 felts)",
        ));
    }
    {
        let spec = IntentSpec::base(di_token_b32, recipient_b32);
        di.push(di_accept(
            "di-pos-empty-hookdata",
            &["TV-DI-1", "TV-DI-7", "TV-DUAL-3"],
            &spec,
            "valid intent, hookDataLen = 0 (exactly the 60-felt header)",
        ));
    }
    let base_bytes = IntentSpec::base(di_token_b32, recipient_b32).encode();
    {
        let mut spec = IntentSpec::base(di_token_b32, recipient_b32);
        spec.magic = 0xdead_beef;
        di.push(di_reject(
            "di-rej-bad-magic",
            &["TV-DI-2", "TV-DUAL-3"],
            &spec.encode(),
            "BadMagic",
            Some("ERR_DI_BAD_MAGIC"),
            "CIR-MINT-PRE-2",
            "magic = 0xdeadbeef != 0x5a2e0acd",
        ));
    }
    {
        let mut spec = IntentSpec::base(di_token_b32, recipient_b32);
        spec.version = 2;
        di.push(di_reject(
            "di-rej-bad-version",
            &["TV-DI-3", "TV-DUAL-3"],
            &spec.encode(),
            "BadVersion",
            Some("ERR_DI_BAD_VERSION"),
            "CIR-MINT-PRE-3",
            "version = 2 != 1",
        ));
    }
    for (id, tv, field, variant) in [
        (
            "di-rej-zero-amount",
            "TV-DI-4",
            "amount",
            "ZeroField:Amount",
        ),
        (
            "di-rej-zero-local-token",
            "TV-DI-5",
            "local_token",
            "ZeroField:LocalToken",
        ),
        (
            "di-rej-zero-local-depositor",
            "TV-DI-5",
            "local_depositor",
            "ZeroField:LocalDepositor",
        ),
    ] {
        let mut spec = IntentSpec::base(di_token_b32, recipient_b32);
        match field {
            "amount" => spec.amount = [0u8; 32],
            "local_token" => spec.local_token = [0u8; 32],
            "local_depositor" => spec.local_depositor = [0u8; 32],
            _ => unreachable!(),
        }
        di.push(di_reject(
            id,
            &[tv, "TV-DUAL-3"],
            &spec.encode(),
            variant,
            Some("ERR_DI_ZERO_FIELD"),
            "CIR-MINT-PRE-4/5",
            &format!("{field} = 0 must reject"),
        ));
    }
    {
        let mut spec = IntentSpec::base(di_token_b32, recipient_b32);
        spec.hook_data = vec![0xee; 4];
        spec.hook_data_len_override = Some(10);
        di.push(di_reject(
            "di-rej-length-mismatch",
            &["TV-DI-6", "TV-DUAL-3"],
            &spec.encode(),
            "LengthMismatch",
            // Rust-only: MASM derives the preimage length from hookDataLen instead of taking a
            // caller claim, so there is no on-chain length relation left to violate. The staged
            // word count carries that check now (see the mint policy's transport binding).
            None,
            "CIR-MINT-PRE-11",
            "hookDataLen field = 10 but only 4 hookData bytes appended (total 244 != 250)",
        ));
    }
    di.push(di_reject(
        "di-rej-truncated",
        &["TV-DI-6", "TV-DUAL-3"],
        &base_bytes[..100],
        "TruncatedHeader",
        // MASM reads the unstaged tail of the header as zeros, so the zero-field guard is what
        // refuses a truncated preimage.
        Some("ERR_DI_ZERO_FIELD"),
        "(the MASM reject is the zero-field guard over the unstaged tail)",
        "first 100 bytes only (< 240-byte header; 25 staged felts < 60)",
    ));
    {
        let mut spec = IntentSpec::base(di_token_b32, recipient_b32);
        let hook_len = (1024 - 60) * 4 + 4; // 3860 bytes => 965 felts => 1025 > 1024
        spec.hook_data = vec![0xab; hook_len];
        di.push(di_reject(
            "di-rej-hookdata-overflow",
            &["TV-DI-7"],
            &spec.encode(),
            "HookDataTooLarge",
            None, // Rust-only: the 1024-felt bound lives in the Rust packer
            "DEV-6 (REQUIRES CIRCLE CONFIRMATION)",
            "hookDataLen = 3860 => 60 + 965 = 1025 felts > 1024 NoteStorage bound",
        ));
    }
    // ---- mp family (DC-14 carried payload + preimage reconstruction) -------------------
    // The faucet id is SYNTHETIC and fixed: a real one hashes over the account's own code, so the
    // rebuilt preimage's identity fields could not be baked here at all. It is a different id from
    // the recipient's, so a row that confused the two would not pass.
    //
    // These intents are DC-14-shaped, which the older `di` rows are not: `remoteToken` carries the
    // faucet's account id in its bytes32 packaging. That narrowing is the point of the reject rows
    // below. `localToken` / `localDepositor` fill their whole bytes32 and are deliberately not
    // address-shaped, so the accept rows exercise a source chain that is not EVM-based.
    let faucet_id = &ids[1];
    let faucet_b32 = r_b_bytes32(faucet_id);
    let mi_domain = CircleDomain::new(7);
    // each row gets its own nonce: two deposits never share one, and the replay-guard tests need
    // a pair that keys distinctly
    let mi_spec = |hook_data: Vec<u8>, nonce_seed: u8| -> IntentSpec {
        let mut spec = IntentSpec::base(di_token_b32, recipient_b32);
        spec.nonce = pattern32(nonce_seed);
        spec.remote_domain = mi_domain.as_u32();
        spec.remote_token = faucet_b32;
        spec.local_token = pattern32(0xb0);
        spec.local_depositor = pattern32(0xc0);
        // the fee ceiling has to sit under the amount for the intent to be mintable at all
        spec.max_fee = u256_be_from_u128(1);
        spec.hook_data = hook_data;
        spec
    };
    let mut mi: Vec<Value> = Vec::new();
    let mi_accept = |mi: &mut Vec<Value>, id: &str, spec: &IntentSpec, derivation: &str| {
        let payload = spec.encode();
        let intent =
            xusdc_encoding::xreserve::encoding::DepositIntent::try_from(payload.as_slice())
                .expect("generator invariant: the spec encodes a valid deposit intent");
        let amount = intent.header().amount();
        let carried = xusdc_encoding::xreserve::encoding::MintIntent::from_deposit_intent(
            &intent, *faucet_id, mi_domain,
        )
        .expect("generator invariant: the mp accept specs are DC-14 shaped");
        let rebuilt = carried.to_deposit_intent(amount, mi_domain, *faucet_id);
        // the law the whole design rests on: what the faucet rebuilds is byte-for-byte what
        // Circle signed. If this ever fails, no note built from this payload could ever mint.
        assert_eq!(
            rebuilt.to_bytes(),
            payload,
            "generator invariant: the DC-14 round trip must be exact for {id}"
        );
        mi.push(json!({
            "id": id,
            "tv": ["TV-DUAL-6"],
            "kind": "accept",
            "payload_hex": hex_bytes(&payload),
            "faucet_prefix_felt": felt_hex(faucet_id.prefix().as_felt()),
            "faucet_suffix_felt": felt_hex(faucet_id.suffix()),
            "remote_domain": mi_domain,
            "amount_felt": felt_hex(Felt::from(amount)),
            "carried_felts": felts_hex(&carried.to_elements()),
            "rebuilt_preimage_felts": felts_hex(&rebuilt.to_preimage_felts()),
            "cite": "DC-14 + DEV-10 (REQUIRES CIRCLE CONFIRMATION)",
            "derivation": derivation,
        }));
    };
    mi_accept(
        &mut mi,
        "mi-pos-empty-hookdata",
        &mi_spec(Vec::new(), 0xd0),
        "DC-14 shaped intent, no hookData: 24 carried felts, 60 rebuilt felts",
    );
    mi_accept(
        &mut mi,
        "mi-pos-hookdata",
        &mi_spec((0..10u8).map(|i| 0xe0 + i).collect(), 0xd8),
        "DC-14 shaped intent, hookDataLen = 10: 24 + 3 carried felts, 63 rebuilt felts",
    );

    let mi_reject = |mi: &mut Vec<Value>,
                     id: &str,
                     spec: &IntentSpec,
                     expected_variant: &str,
                     derivation: &str| {
        let payload = spec.encode();
        // a reject row fails at whichever step owns its narrowing: the byte decode or the compress
        assert!(
            xusdc_encoding::xreserve::encoding::DepositIntent::try_from(payload.as_slice())
                .and_then(|intent| {
                    xusdc_encoding::xreserve::encoding::MintIntent::from_deposit_intent(
                        &intent, *faucet_id, mi_domain,
                    )
                })
                .is_err(),
            "generator invariant: {id} must not compress"
        );
        mi.push(json!({
            "id": id,
            "tv": ["TV-DUAL-6"],
            "kind": "reject",
            "payload_hex": hex_bytes(&payload),
            "faucet_prefix_felt": felt_hex(faucet_id.prefix().as_felt()),
            "faucet_suffix_felt": felt_hex(faucet_id.suffix()),
            "remote_domain": mi_domain,
            "expected_variant": expected_variant,
            "cite": "DC-14 (REQUIRES CIRCLE CONFIRMATION)",
            "derivation": derivation,
        }));
    };
    {
        let mut spec = mi_spec(Vec::new(), 0xd0);
        spec.remote_token = r_b_bytes32(&ids[2]);
        mi_reject(
            &mut mi,
            "mi-rej-remote-token-mismatch",
            &spec,
            "RemoteTokenMismatch",
            "remoteToken is a well-formed account id, but a different faucet's",
        );
    }
    {
        let mut spec = mi_spec(Vec::new(), 0xd0);
        spec.remote_token = pattern32(0xa0);
        mi_reject(
            &mut mi,
            "mi-rej-remote-token-malformed",
            &spec,
            "AccountIdOutOfRange",
            "remoteToken has non-zero bytes in the leading 16-byte account-id pad",
        );
    }
    {
        let mut spec = mi_spec(Vec::new(), 0xd0);
        spec.max_fee = u256_be_from_u128(ASSET_AMOUNT_MAX + 1);
        mi_reject(
            &mut mi,
            "mi-rej-max-fee-over-cap",
            &spec,
            "FieldNotAssetAmount",
            "maxFee exceeds AssetAmount::MAX, so it cannot be carried as one felt",
        );
    }
    {
        let mut spec = mi_spec(Vec::new(), 0xd0);
        let mut bad = [0u8; 32];
        bad[16..24].copy_from_slice(&7u64.to_be_bytes());
        bad[24..32].copy_from_slice(&7u64.to_be_bytes());
        spec.remote_recipient = bad;
        mi_reject(
            &mut mi,
            "mi-rej-recipient-non-canonical",
            &spec,
            "NonCanonicalAccountId",
            "remoteRecipient prefix=suffix=7 is in-field but not a canonical account id",
        );
    }

    // ---- att family (attestation surface) ----------------------------------------
    // each vector carries an independent k256 keypair; the digest is keccak256 of a FULL
    // DepositIntent payload (raw keccak, NOT EIP-712, no struct); the 65-byte r||s||v signature over
    // that digest; and the canonical commitment from miden-crypto `PublicKey::to_commitment`. The
    // nonce is varied per seed so digests, sigs, and pubkeys all differ.
    // The fourth entry has a ten-byte hookData tail so the digest covers bytes past the header.
    let mut att: Vec<Value> = Vec::new();
    let attestation_cases: [(u64, Vec<u8>); 4] = [
        (1, vec![]),
        (2, vec![]),
        (3, vec![]),
        (4, (0..10u8).map(|i| 0xe0 + i).collect()),
    ];
    for (seed, hook_data) in attestation_cases {
        let mut spec = IntentSpec::base(di_token_b32, recipient_b32);
        spec.nonce = pattern32(0xd0u8.wrapping_add(seed as u8));
        spec.hook_data = hook_data;
        let payload = spec.encode();

        let sk = att_keypair(seed);
        let pk = att_pk33(&sk);
        let digest = att_keccak256(&payload);
        let sig = att_sign65(&sk, &digest);
        let commitment = att_commitment(&pk);
        att.push(json!({
            "id": if spec.hook_data.is_empty() {
                format!("att-{seed}")
            } else {
                format!("att-{seed}-hookdata")
            },
            "tv": ["TV-ATT-1", "TV-ATT-2", "TV-ATT-3", "TV-DUAL-5"],
            "pubkey_hex": hex_bytes(&pk),
            "packed_felts": felts_hex(&att_pubkey(&pk).to_elements()),
            "expected_commitment": word_hex(commitment),
            "digest_hex": hex_bytes(&digest),
            "digest_felts": felts_hex(&packed(&digest)),
            "sig_hex": hex_bytes(&sig),
            "sig_felts": felts_hex(&packed(&sig)),
            "v_byte": sig[64],
            "payload_hex": hex_bytes(&payload),
            "cite": "miden-crypto-0.25.1 dsa/ecdsa_k256_keccak/mod.rs:253,:301 + src/lib.rs:156-170",
            "derivation": format!(
                "k256 SigningKey::random(StdRng seed {seed}); pk = 33B compressed SEC1 wire key, decompressed to affine qx_le_u32[8]||qy_le_u32[8] (16 felts, vm#3342); sig = 65B r||s||v (17 felts, v carried) over keccak256(full {plen}B DepositIntent payload) — raw secp256k1, NOT EIP-712, no struct; digest = 8 felts; commitment = miden-crypto PublicKey::to_commitment @ 0.33.0 (Poseidon2 over the 16 affine pubkey felts)",
                plen = payload.len(),
            ),
        }));
    }

    // ---- bn family (burn-note items) -------------------------------------------
    // items = destDomain(1) + destRecipient(8 u32-LE) = 9 felts.
    // destDomain is the canonical felt of the integer, and the bytes32 field uses the
    // same `packed` primitive as the b32 family.
    let bn_items = |domain: u32, recipient: &[u8; 32]| -> Vec<String> {
        let mut out = Vec::with_capacity(9);
        out.push(felt_hex(Felt::from(domain)));
        out.extend(felts_hex(&packed(recipient)));
        out
    };
    let bn_accept = |id: &str, domain: u32, recipient: [u8; 32], derivation: &str| {
        json!({
            "id": id, "tv": ["TV-BN-1", "TV-BN-2", "TV-BN-3"], "kind": "accept",
            "dest_domain": domain,
            "dest_recipient": hex_bytes(&recipient),
            "items": bn_items(domain, &recipient),
            "cite": "DC-7",
            "derivation": derivation,
        })
    };
    let mut bn: Vec<Value> = vec![
        bn_accept(
            "bn-pos-min",
            0,
            [0u8; 32],
            "lower boundary: destDomain=0, destRecipient all-zero",
        ),
        bn_accept(
            "bn-pos-typical",
            6,
            pattern32(0x11),
            "typical: destDomain=6 (Arbitrum CCTP), patterned bytes32",
        ),
        bn_accept(
            "bn-pos-max",
            u32::MAX,
            [0xffu8; 32],
            "upper boundary: destDomain=u32::MAX, recipient all-0xff",
        ),
    ];
    // each rejection vector changes one field or the length of a valid 9-felt payload
    let bn_base = bn_items(6, &pattern32(0x55));
    let over_u32 = felt_hex(Felt::try_from((u32::MAX as u64) + 1).expect("2^32 < p"));
    let bn_reject = |id: &str, items: Vec<String>, derivation: &str| {
        json!({
            "id": id, "tv": ["TV-BN-4"], "kind": "reject",
            "items": items,
            "expected_variant": "BurnItemsMalformed",
            "cite": "error-map ; ASG-13/ASG-17",
            "derivation": derivation,
        })
    };
    let mut short = bn_base.clone();
    short.pop(); // 8 felts
    let mut long = bn_base.clone();
    long.push(felt_hex(Felt::from(0u32))); // 10 felts
    let mut domain_over = bn_base.clone();
    domain_over[0] = over_u32.clone();
    let mut recip_limb = bn_base.clone();
    recip_limb[4] = over_u32; // within destRecipient [1..9]
    bn.push(bn_reject(
        "bn-rej-len-short",
        short,
        "8 felts (< 9) → wrong length",
    ));
    bn.push(bn_reject(
        "bn-rej-len-long",
        long,
        "10 felts (> 9) → wrong length",
    ));
    bn.push(bn_reject(
        "bn-rej-domain-over-u32",
        domain_over,
        "items[0] = 2^32 → destDomain not a u32",
    ));
    bn.push(bn_reject(
        "bn-rej-recipient-limb-not-u32",
        recip_limb,
        "items[4] = 2^32 → destRecipient limb not a u32",
    ));

    let file = json!({ "version": 1, "families": { "b32": b32, "amt": amt, "aid": aid, "di": di, "att": att, "bn": bn, "mi": mi } });
    let path = xusdc_encoding::vectors_path();
    std::fs::create_dir_all(path.parent().unwrap()).expect("create vectors dir");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&file).expect("serialize") + "\n",
    )
    .expect("write artifact");
    println!(
        "wrote {} ({} bytes)",
        path.display(),
        std::fs::metadata(&path).unwrap().len()
    );
}
