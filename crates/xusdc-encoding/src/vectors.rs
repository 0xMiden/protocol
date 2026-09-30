//! Loader for the ONE canonical golden-vector artifact
//! (`tests/vectors/xreserve-encoding-vectors.json`). Both the Rust unit tests and the
//! MASM execution tests load the same file by reference through this module.

use std::sync::OnceLock;

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::crypto::utils::Deserializable;
use miden_protocol::{Felt, Word};
use miden_standards::interop::eth::EthAmount;
use serde::Deserialize;

use crate::xreserve::encoding::CircleDomain;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorFile {
    pub version: u32,
    pub families: Families,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Families {
    pub b32: Vec<B32Vector>,
    pub amt: Vec<AmtVector>,
    pub aid: Vec<AidVector>,
    pub di: Vec<DiVector>,
    pub att: Vec<AttVector>,
    pub bn: Vec<BnVector>,
    pub mi: Vec<MiVector>,
}

/// bytes32 → Word vectors. `lossless_error` marks the TV-B32-2 limb-ge-p entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B32Vector {
    pub id: String,
    pub tv: Vec<String>,
    pub bytes32: String,
    pub packed_felts: Vec<String>,
    pub expected_key: [String; 4],
    #[serde(default)]
    pub lossless_error: Option<String>,
    pub cite: String,
    pub derivation: String,
}

/// uint256 → AssetAmount vectors. `kind`: accept | reject.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmtVector {
    pub id: String,
    pub tv: Vec<String>,
    pub kind: String,
    #[serde(default)]
    pub uint256_be: Option<String>,
    #[serde(default)]
    pub expected_y: Option<String>,
    #[serde(default)]
    pub expected_variant: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    pub cite: String,
    pub derivation: String,
}

/// AccountId ↔ bytes32 vectors (`expected_variant` set ⇒ reject entry).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AidVector {
    pub id: String,
    pub tv: Vec<String>,
    pub bytes32: String,
    #[serde(default)]
    pub prefix_felt: Option<String>,
    #[serde(default)]
    pub suffix_felt: Option<String>,
    #[serde(default)]
    pub expected_variant: Option<String>,
    pub cite: String,
    pub derivation: String,
}

/// DepositIntent vectors. `kind`: accept | reject. `mode: masm-only` for the felt-len
/// staging case (unrepresentable in the byte API).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiVector {
    pub id: String,
    pub tv: Vec<String>,
    pub kind: String,
    #[serde(default)]
    pub bytes_hex: Option<String>,
    pub preimage_felts: Vec<String>,
    pub len_felts: u64,
    /// Overrides `len_felts` for the masm-only wrong-length staging case.
    #[serde(default)]
    pub staging_len_felts: Option<u64>,
    #[serde(default)]
    pub fields: Option<DiFields>,
    #[serde(default)]
    pub expected_variant: Option<String>,
    #[serde(default)]
    pub masm_err: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    pub cite: String,
    pub derivation: String,
}

/// Per-field expectations for accept vectors: semantic values plus each field's packed
/// felts at its felt offset in the packed layout.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiFields {
    pub magic: u32,
    pub version: u32,
    pub remote_domain: CircleDomain,
    pub hook_data_len: u32,
    /// The two amount-shaped fields as the values they reduce to.
    pub amount: u64,
    pub max_fee: u64,
    pub amount_hex: String,
    pub remote_token_hex: String,
    pub remote_recipient_hex: String,
    pub local_token_hex: String,
    pub local_depositor_hex: String,
    pub max_fee_hex: String,
    pub nonce_hex: String,
    /// field name → (felt offset within the preimage, packed felts at that offset).
    pub packed: Vec<PackedField>,
    /// The stack-output expectation: [remote_domain, REMOTE_TOKEN_LOWER, REMOTE_TOKEN_UPPER,
    /// intent_num_bytes] — the words as felt-hex.
    pub remote_token_felts: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackedField {
    pub name: String,
    pub felt_off: u64,
    pub felts: Vec<String>,
}

/// Mint-payload (`DC-14`) vectors: a Circle DepositIntent, the faucet it is addressed to, the
/// felts the mint note would carry for it, and the preimage the faucet rebuilds from those felts.
/// `kind`: accept | reject.
///
/// The faucet id here is a fixed SYNTHETIC one. A real faucet's id is a hash over its own code, so
/// the rebuilt preimage's identity fields are not knowable when this artifact is generated — the
/// live-account tests check the MASM writer against the Rust mirror instead. The ownership map's
/// anti-duplication section records that split.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiVector {
    pub id: String,
    pub tv: Vec<String>,
    pub kind: String,
    pub payload_hex: String,
    pub faucet_prefix_felt: String,
    pub faucet_suffix_felt: String,
    pub remote_domain: CircleDomain,
    /// Accept rows only: the reduced amount the note carries and the faucet writes back.
    #[serde(default)]
    pub amount_felt: Option<String>,
    /// Accept rows only: the carried payload felts, and the 60-plus-hookData felts the writer
    /// must produce from them.
    #[serde(default)]
    pub carried_felts: Vec<String>,
    #[serde(default)]
    pub rebuilt_preimage_felts: Vec<String>,
    #[serde(default)]
    pub expected_variant: Option<String>,
    pub cite: String,
    pub derivation: String,
}

/// Attestation (ATT) vectors. One independent secp256k1 keypair each:
/// the 33-byte compressed pubkey (decompressed → 16 affine felts, vm#3342) and its
/// `PublicKey::to_commitment` Word, the
/// 32-byte keccak digest over a full DepositIntent payload (→ 8 felts), and the 65-byte
/// `r‖s‖v` signature (→ 17 felts; `v` carried in felt 16, unused on-chain).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttVector {
    pub id: String,
    pub tv: Vec<String>,
    pub pubkey_hex: String,
    pub packed_felts: Vec<String>,
    pub expected_commitment: [String; 4],
    pub digest_hex: String,
    pub digest_felts: Vec<String>,
    pub sig_hex: String,
    pub sig_felts: Vec<String>,
    pub v_byte: u8,
    /// The full DepositIntent payload that was keccak'd (raw keccak, NOT EIP-712, no struct).
    pub payload_hex: String,
    pub cite: String,
    pub derivation: String,
}

/// Burn-note item (BN) vectors. `kind`: accept | reject. Accept entries carry
/// the two destination fields plus the 9-felt expected `items` layout; reject entries carry the
/// malformed `items` felts plus `expected_variant` (`BurnItemsMalformed`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BnVector {
    pub id: String,
    pub tv: Vec<String>,
    pub kind: String,
    #[serde(default)]
    pub dest_domain: Option<CircleDomain>,
    #[serde(default)]
    pub dest_recipient: Option<String>,
    /// Accept: the 9-felt burn-payload golden layout (carried in note attachment scheme 6). Reject:
    /// the malformed felts.
    pub items: Vec<String>,
    #[serde(default)]
    pub expected_variant: Option<String>,
    pub cite: String,
    pub derivation: String,
}

// LOAD + PARSE HELPERS
// ================================================================================================

static FILE: OnceLock<VectorFile> = OnceLock::new();

/// Loads (once) the canonical artifact by reference.
pub fn load() -> &'static VectorFile {
    FILE.get_or_init(|| {
        let path = crate::vectors_path();
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read canonical vector artifact {path:?}: {e}"));
        serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("canonical vector artifact does not parse: {e}"))
    })
}

/// Parses a 0x-prefixed 32-byte hex string.
pub fn parse_hex32(s: &str) -> [u8; 32] {
    let bytes = parse_hex(s);
    bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("expected 32 bytes, got {}", bytes.len()))
}

/// Parses a 0x-prefixed hex string of any length.
pub fn parse_hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Parses a felt encoded as a 0x-prefixed u64 hex string.
pub fn felt_from_hex(s: &str) -> Felt {
    let v = u64::from_str_radix(s.strip_prefix("0x").expect("0x-prefixed felt"), 16)
        .expect("valid u64 hex");
    Felt::try_from(v).expect("felt within the field")
}

/// Parses a Word from four felt-hex strings.
pub fn word_from_hex(w: &[String; 4]) -> Word {
    Word::new([
        felt_from_hex(&w[0]),
        felt_from_hex(&w[1]),
        felt_from_hex(&w[2]),
        felt_from_hex(&w[3]),
    ])
}

impl B32Vector {
    pub fn bytes32(&self) -> [u8; 32] {
        parse_hex32(&self.bytes32)
    }

    pub fn packed_felts_values(&self) -> Vec<Felt> {
        self.packed_felts.iter().map(|s| felt_from_hex(s)).collect()
    }
}

impl AmtVector {
    /// The vector's uint256 in the wire domain type the reducer consumes.
    pub fn amount(&self) -> EthAmount {
        EthAmount::new(parse_hex32(
            self.uint256_be
                .as_deref()
                .expect("vector carries uint256_be"),
        ))
    }

    pub fn expected_amount(&self) -> miden_protocol::asset::AssetAmount {
        let y: u64 = self
            .expected_y
            .as_deref()
            .expect("accept vector")
            .parse()
            .expect("u64");
        miden_protocol::asset::AssetAmount::new(y).expect("vector amount within bounds")
    }
}

impl AidVector {
    pub fn expected_felts(&self) -> [Felt; 2] {
        [
            felt_from_hex(self.prefix_felt.as_deref().expect("prefix felt")),
            felt_from_hex(self.suffix_felt.as_deref().expect("suffix felt")),
        ]
    }
}

impl DiVector {
    pub fn bytes(&self) -> Vec<u8> {
        parse_hex(self.bytes_hex.as_deref().expect("byte-level vector"))
    }

    pub fn preimage_values(&self) -> Vec<Felt> {
        self.preimage_felts
            .iter()
            .map(|s| felt_from_hex(s))
            .collect()
    }
}

impl MiVector {
    pub fn payload(&self) -> Vec<u8> {
        parse_hex(&self.payload_hex)
    }

    /// The synthetic faucet this intent is addressed to.
    pub fn faucet_id(&self) -> AccountId {
        AccountId::try_from_elements(
            felt_from_hex(&self.faucet_suffix_felt),
            felt_from_hex(&self.faucet_prefix_felt),
        )
        .expect("the vector's faucet id is canonical")
    }

    pub fn amount(&self) -> AssetAmount {
        let felt = felt_from_hex(self.amount_felt.as_deref().expect("accept vector"));
        AssetAmount::new(felt.as_canonical_u64()).expect("the vector's amount is in range")
    }

    pub fn carried_values(&self) -> Vec<Felt> {
        self.carried_felts
            .iter()
            .map(|s| felt_from_hex(s))
            .collect()
    }

    pub fn rebuilt_preimage_values(&self) -> Vec<Felt> {
        self.rebuilt_preimage_felts
            .iter()
            .map(|s| felt_from_hex(s))
            .collect()
    }
}

impl AttVector {
    pub fn pubkey(&self) -> [u8; 33] {
        let b = parse_hex(&self.pubkey_hex);
        b.as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("expected 33 bytes, got {}", b.len()))
    }

    pub fn digest(&self) -> [u8; 32] {
        parse_hex32(&self.digest_hex)
    }

    /// The wire pubkey decoded into the key every consumer actually works with. A committed
    /// vector whose key is not a curve point is a broken artifact, so this panics rather than
    /// making every caller handle an impossible error.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::read_from_bytes(&self.pubkey()).unwrap_or_else(|e| {
            panic!(
                "vector {}: pubkey does not decode to a curve point: {e}",
                self.id
            )
        })
    }

    pub fn sig(&self) -> [u8; 65] {
        let b = parse_hex(&self.sig_hex);
        b.as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("expected 65 bytes, got {}", b.len()))
    }

    pub fn payload(&self) -> Vec<u8> {
        parse_hex(&self.payload_hex)
    }

    pub fn packed_felts_values(&self) -> Vec<Felt> {
        self.packed_felts.iter().map(|s| felt_from_hex(s)).collect()
    }

    pub fn digest_felts_values(&self) -> Vec<Felt> {
        self.digest_felts.iter().map(|s| felt_from_hex(s)).collect()
    }

    pub fn sig_felts_values(&self) -> Vec<Felt> {
        self.sig_felts.iter().map(|s| felt_from_hex(s)).collect()
    }

    pub fn expected_commitment_word(&self) -> Word {
        word_from_hex(&self.expected_commitment)
    }
}

impl DiFields {
    pub fn bytes32(&self, name: &str) -> [u8; 32] {
        let hex = match name {
            "amount" => &self.amount_hex,
            "remote_token" => &self.remote_token_hex,
            "remote_recipient" => &self.remote_recipient_hex,
            "local_token" => &self.local_token_hex,
            "local_depositor" => &self.local_depositor_hex,
            "max_fee" => &self.max_fee_hex,
            "nonce" => &self.nonce_hex,
            other => panic!("unknown bytes32 field {other}"),
        };
        parse_hex32(hex)
    }
}

impl BnVector {
    pub fn dest_recipient(&self) -> crate::xreserve::encoding::ForeignChainAddress {
        crate::xreserve::encoding::ForeignChainAddress::new(parse_hex32(
            self.dest_recipient
                .as_deref()
                .expect("accept vector carries dest_recipient"),
        ))
    }

    /// The felt slice under test (accept: 9-felt golden layout; reject: malformed felts).
    pub fn items_values(&self) -> Vec<Felt> {
        self.items.iter().map(|s| felt_from_hex(s)).collect()
    }

    /// Reconstructs the semantic `XReserveBurnItems` from an accept vector's inputs.
    pub fn expected_struct(&self) -> crate::xreserve::encoding::XReserveBurnItems {
        crate::xreserve::encoding::XReserveBurnItems {
            dest_domain: self.dest_domain.expect("accept vector carries dest_domain"),
            dest_recipient: self.dest_recipient(),
        }
    }
}

// ARTIFACT GUARD
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The artifact parses, every family is non-empty, every entry carries provenance
    /// (`cite` + `derivation`), and every entry carries non-empty `tv` tags unless it is on the
    /// explicit guard-vector allowlist.
    #[test]
    fn artifact_guard() {
        // guard-only vectors that intentionally trace to no spec row; they pin harness and trap
        // mechanics instead.
        const TV_TAG_ALLOWLIST: [&str; 3] = [
            "amt-guard-limb-not-u32",
            "amt-rej-witness-over",
            "amt-rej-witness-under",
        ];

        let v = load();
        assert_eq!(v.version, 1);
        assert_eq!(v.families.b32.len(), 4, "b32 family");
        assert_eq!(v.families.amt.len(), 4, "amt family");
        assert_eq!(v.families.aid.len(), 5, "aid family");
        assert_eq!(v.families.di.len(), 10, "di family");
        assert_eq!(v.families.att.len(), 4, "att family");
        assert_eq!(v.families.bn.len(), 7, "bn family");
        assert_eq!(v.families.mi.len(), 6, "mi family");
        let no_provenance = |cite: &str, derivation: &str| cite.is_empty() || derivation.is_empty();
        let tv_ok = |id: &str, tv: &[String]| !tv.is_empty() || TV_TAG_ALLOWLIST.contains(&id);
        let kind_ok = |kind: &str| kind == "accept" || kind == "reject";
        for e in &v.families.b32 {
            assert!(
                !no_provenance(&e.cite, &e.derivation),
                "{} provenance",
                e.id
            );
            assert!(
                tv_ok(&e.id, &e.tv),
                "{}: empty tv tags and not allowlisted",
                e.id
            );
        }
        for e in &v.families.amt {
            assert!(kind_ok(&e.kind), "{}: kind", e.id);
            assert!(
                !no_provenance(&e.cite, &e.derivation),
                "{} provenance",
                e.id
            );
            assert!(
                tv_ok(&e.id, &e.tv),
                "{}: empty tv tags and not allowlisted",
                e.id
            );
        }
        for e in &v.families.aid {
            assert!(
                !no_provenance(&e.cite, &e.derivation),
                "{} provenance",
                e.id
            );
            assert!(
                tv_ok(&e.id, &e.tv),
                "{}: empty tv tags and not allowlisted",
                e.id
            );
        }
        for e in &v.families.di {
            assert!(kind_ok(&e.kind), "{}: kind", e.id);
            assert!(
                !no_provenance(&e.cite, &e.derivation),
                "{} provenance",
                e.id
            );
            assert!(
                tv_ok(&e.id, &e.tv),
                "{}: empty tv tags and not allowlisted",
                e.id
            );
        }
        for e in &v.families.att {
            assert!(
                !no_provenance(&e.cite, &e.derivation),
                "{} provenance",
                e.id
            );
            assert!(
                tv_ok(&e.id, &e.tv),
                "{}: empty tv tags and not allowlisted",
                e.id
            );
        }
        for e in &v.families.bn {
            assert!(kind_ok(&e.kind), "{}: kind", e.id);
            assert!(
                !no_provenance(&e.cite, &e.derivation),
                "{} provenance",
                e.id
            );
            assert!(
                tv_ok(&e.id, &e.tv),
                "{}: empty tv tags and not allowlisted",
                e.id
            );
        }
        for e in &v.families.mi {
            assert!(kind_ok(&e.kind), "{}: kind", e.id);
            assert!(
                !no_provenance(&e.cite, &e.derivation),
                "{} provenance",
                e.id
            );
            assert!(
                tv_ok(&e.id, &e.tv),
                "{}: empty tv tags and not allowlisted",
                e.id
            );
        }
    }
}
