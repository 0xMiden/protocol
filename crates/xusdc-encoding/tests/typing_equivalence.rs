//! Typing-slice equivalence suite.
//!
//! Locks every new typed API this typing slice introduces to the FROZEN golden vectors: the typed
//! path must produce byte-for-byte / felt-for-felt identical output to the values the encoding
//! conformance suite already pins. A wire
//! change — a reordered signature felt, a swapped account-id pair, a drifted commitment — makes these
//! RED, which is what proves the typing refactor is wire-neutral.
//!
//! It also re-locks the inlined AccountId two-felt form: the `account_id_to_felts` helper and
//! its dedicated `tv_aid_4` unit test were deleted, so this suite carries the `[prefix, suffix]`
//! golden-vector coverage that test used to provide, and pins the exact ordering a call site must
//! inline.

use assert_matches::assert_matches;
use miden_protocol::utils::serde::{Deserializable, DeserializationError, Serializable};
use miden_standards::interop::eth::EthEmbeddedAccountId;
use xusdc_encoding::vectors::{load, parse_hex32};
use xusdc_encoding::xreserve::encoding::{
    bytes32_to_packed_felts, DepositIntent, EncodingError, EthEmbeddedAccountIdExt,
    ForeignChainAddress, Signature, XReserveBurnItems,
};

// Signature
// ================================================================================================

/// `Signature::new(bytes).to_felts()` is byte-identical to the golden signature felts. A
/// reordered/perturbed packing goes RED here.
#[test]
fn signature_type_matches_golden() {
    for v in &load().families.att {
        let sig = v.sig();
        let typed = Signature::new(sig);
        assert_eq!(
            typed.to_elements().as_slice(),
            v.sig_felts_values().as_slice(),
            "{}: Signature::to_felts == golden sig felts",
            v.id
        );
        assert_eq!(
            typed.as_bytes(),
            &sig,
            "{}: Signature round-trips its bytes",
            v.id
        );
    }
}

// The attester key is not a typed API of this crate at all: it is the protocol's own
// `ecdsa_k256_keccak::PublicKey`, whose affine packing and commitment are locked to the same golden
// vectors by TV-ATT-1 / TV-ATT-2 in `xreserve::encoding::attestation`.

// DepositIntent owns its codec
// ================================================================================================

/// The `TryFrom<&[u8]>` decode and the `Serializable` encode are inverses over the golden bytes,
/// and the packed preimage is the golden one.
#[test]
fn deposit_intent_type_matches_golden() {
    for vec in load().families.di.iter().filter(|v| v.kind == "accept") {
        let bytes = vec.bytes();
        let intent = DepositIntent::try_from(bytes.as_slice()).expect("accept vector decodes");

        assert_eq!(
            intent.to_preimage_felts(),
            vec.preimage_values(),
            "{}: DepositIntent::to_preimage_felts == golden preimage",
            vec.id
        );
        assert_eq!(
            intent.to_bytes(),
            bytes,
            "{}: the encode is the decode's inverse",
            vec.id
        );
        // and the standard reader is the same decode as the typed entry point
        assert_eq!(
            DepositIntent::read_from_bytes(&bytes).expect("Deserializable reads accept vector"),
            intent,
            "{}: Deserializable == TryFrom<&[u8]>",
            vec.id
        );
    }
}

/// The typed path rejects a truncated payload with the specific variant; the standard reader
/// carries the same reason across as a `DeserializationError`.
#[test]
fn deposit_intent_type_propagates_rejects() {
    let short = [0u8; 10];
    assert_matches!(
        DepositIntent::try_from(short.as_slice()),
        Err(EncodingError::TruncatedHeader)
    );
    assert_eq!(
        DepositIntent::read_from_bytes(&short)
            .expect_err("a truncated payload is not a deposit intent")
            .to_string(),
        DeserializationError::from(EncodingError::TruncatedHeader).to_string(),
        "the standard reader carries the codec's reason"
    );
}

// XReserveBurnItems methods
// ================================================================================================

/// `XReserveBurnItems::encode` / `decode` match the golden `items` layout, and
/// round-trip.
#[test]
fn burn_items_methods_match_golden() {
    for vec in load().families.bn.iter().filter(|v| v.kind == "accept") {
        let items = vec.expected_struct();
        let encoded = items.encode();
        assert_eq!(
            encoded,
            vec.items_values(),
            "{}: XReserveBurnItems::encode == golden layout",
            vec.id
        );
        assert_eq!(
            XReserveBurnItems::decode(&encoded).expect("round-trips"),
            items,
            "{}: XReserveBurnItems::decode(encode(x)) == x",
            vec.id
        );
    }
}

/// `XReserveBurnItems::decode` fail-closes on a malformed payload.
#[test]
fn burn_items_decode_fail_closes() {
    assert_matches!(
        XReserveBurnItems::decode(&[]),
        Err(EncodingError::BurnItemsMalformed)
    );
}

// The inlined AccountId two-felt form (replacing the deleted `account_id_to_felts` + `tv_aid_4`)
// ================================================================================================

/// The inlined `(prefix, suffix)` form every call site now uses matches the vector's golden
/// `[prefix, suffix]` pair — the coverage the deleted `tv_aid_4_two_felt_form` provided, kept alive.
/// A swap to `(suffix, prefix)` at a call site is caught by comparing against this golden ordering.
#[test]
fn account_id_two_felt_form_matches_golden() {
    for vec in load()
        .families
        .aid
        .iter()
        .filter(|v| v.expected_variant.is_none())
    {
        let b = parse_hex32(&vec.bytes32);
        let id = EthEmbeddedAccountId::try_from_bytes32(b)
            .expect("accept vector decodes")
            .into_account_id();
        let pair = [id.prefix().as_felt(), id.suffix()];
        assert_eq!(
            pair.as_slice(),
            vec.expected_felts().as_slice(),
            "{}: inlined (prefix, suffix) == golden felts",
            vec.id
        );
    }
}

// The stock EthEmbeddedAccountId bytes32 form (byte-identical)
// ================================================================================================

/// The AccountId bytes32 packaging IS `EthEmbeddedAccountId::to_bytes32()`, and must stay
/// byte-identical to the golden bytes32 — the adoption is not lossy.
#[test]
fn account_id_bytes32_form_is_stock_and_byte_identical() {
    for vec in load()
        .families
        .aid
        .iter()
        .filter(|v| v.expected_variant.is_none())
    {
        let b = parse_hex32(&vec.bytes32);
        let embedded = EthEmbeddedAccountId::try_from_bytes32(b).expect("accept vector decodes");
        assert_eq!(
            embedded.to_bytes32(),
            b,
            "{}: the stock bytes32 form stays byte-identical to the golden bytes32",
            vec.id
        );
    }
}

// Source-chain bytes32 address packing
// ================================================================================================

/// A source-chain address uses the shared `bytes32_to_packed_felts` packing. The address here has
/// non-zero leading bytes, which no EVM address has: a source chain wider than 20 bytes must survive
/// the packing unchanged.
#[test]
fn local_chain_address_packs_like_the_shared_codec() {
    let bytes: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
    let address = ForeignChainAddress::new(bytes);

    assert_ne!(bytes[..12], [0u8; 12], "the fixture must not be EVM-shaped");
    assert_eq!(
        address.to_packed_felts(),
        bytes32_to_packed_felts(&bytes),
        "the address packs through the shared bytes32 codec, all 8 limbs of it"
    );
}
