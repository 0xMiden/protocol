//! Turning an arbitrary 32-byte value into the Word the faucet derives from it.
//!
//! The value this hashes is the deposit nonce — a bytes32 that originates outside Miden. The faucet
//! derives exactly two Words from it, and both go through this one hashing routine
//! (`mint_intent::hash_nonce` on the MASM side): the key of the `usedNonces` replay-guard storage
//! map, and the serial number of
//! the attested output note the mint sends. A nonce carries no guarantee that it fits a field
//! element, so it cannot be reinterpreted as a Word directly; a value whose limbs exceed the field
//! modulus would have to be rejected or reduced, and reducing would let two distinct nonces collide.
//!
//! The canonical answer is to HASH instead of reinterpret: pack the bytes into eight
//! u32-little-endian field elements and take their Poseidon2 hash. That is total — every possible
//! bytes32 has a key — and collision-resistant, so distinct nonces stay distinct. The faucet's MASM
//! computes the identical Word on-chain.
//!
//! The fallible direct conversion also lives here, for the paths that genuinely need the original
//! bytes back rather than a one-way key.

use miden_protocol::account::StorageMapKey;
use miden_protocol::utils::{bytes_to_packed_u32_elements, packed_u32_elements_to_bytes};
use miden_protocol::{Felt, Hasher};
// `Word` is only named by the test-only lossless conversion and the unit tests.
#[cfg(test)]
use miden_protocol::Word;

use super::error::EncodingError;

/// Derives the canonical Word for an arbitrary 32-byte value (the deposit nonce): the `usedNonces`
/// replay-guard map key and the attested output note's serial are both this Word.
///
/// The bytes are packed into eight u32 field elements and hashed with Poseidon2. It cannot fail:
/// any 32 bytes pack to valid u32s, so every input has a key — which is what makes it safe for
/// values that arrive from outside Miden. The faucet's `hash_nonce` computes the same Word.
pub fn bytes32_to_storage_map_key(b: &[u8; 32]) -> StorageMapKey {
    let felts = bytes32_to_packed_felts(b);
    StorageMapKey::new(Hasher::hash_elements(&felts))
}

/// The 8x u32-LE packing primitive (infallible).
pub fn bytes32_to_packed_felts(b: &[u8; 32]) -> [Felt; 8] {
    bytes_to_packed_u32_elements(b)
        .try_into()
        // length is type-guaranteed (32 bytes / 4 bytes per u32 felt), not input-dependent
        .expect("32 bytes always pack to exactly 8 u32 felts")
}

/// The lossless direct conversion. Not usable for external map keys: it returns
/// `Err(LimbOutOfField)` if any 8-byte LE limb is at or above the field modulus.
///
/// Test-only: it backs the TV-B32-2 bypass-positive golden-vector row (the lossless path rejecting
/// a limb `>= p` while the hashing path succeeds); no production path performs the lossless direct
/// conversion.
#[cfg(test)]
pub fn bytes32_to_word_lossless(b: &[u8; 32]) -> Result<Word, EncodingError> {
    // `LimbOutOfField` is a unit variant, so the inner `WordError` source cannot be carried
    Word::try_from(*b).map_err(|_| EncodingError::LimbOutOfField)
}

/// Inverse of [`bytes32_to_packed_felts`]: 8 u32-LE-packed felts → the 32-byte value.
/// Fail-closed — any felt
/// `> u32::MAX` is not a valid packed limb and returns [`EncodingError::LimbNotU32`] rather
/// than truncating. Round-trip: `packed_felts_to_bytes32(bytes32_to_packed_felts(b)) == b`.
pub fn packed_felts_to_bytes32(felts: &[Felt; 8]) -> Result<[u8; 32], EncodingError> {
    // the upstream unpacker truncates a felt >= 2^32 to its low 32 bits, so the valid-u32 guard
    // must run first
    for f in felts {
        if f.as_canonical_u64() > u32::MAX as u64 {
            return Err(EncodingError::LimbNotU32);
        }
    }
    Ok(packed_u32_elements_to_bytes(felts)
        .try_into()
        // each guarded u32 limb contributes exactly 4 bytes, so 8 limbs => 32 bytes
        .expect("8 u32 limbs always unpack to exactly 32 bytes"))
}

// TESTS — TV-B32-1..4
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::vectors::{load, word_from_hex};

    /// TV-B32-1 (happy path, written first): known bytes32 → expected Poseidon2 Word.
    #[test]
    fn tv_b32_1_hash_to_word_positive() {
        let v = load();
        for vec in v.families.b32.iter().filter(|v| v.lossless_error.is_none()) {
            let key = bytes32_to_storage_map_key(&vec.bytes32());
            assert_eq!(
                Word::from(key),
                word_from_hex(&vec.expected_key),
                "vector {}: key mismatch",
                vec.id
            );
        }
    }

    /// TV-B32-2 (negative + bypass-positive): the lossless path rejects a limb >= p, while
    /// `bytes32_to_storage_map_key` succeeds on the same input.
    #[test]
    fn tv_b32_2_lossless_rejects_option_b_succeeds() {
        let v = load();
        let vec = v
            .families
            .b32
            .iter()
            .find(|v| v.lossless_error.is_some())
            .expect("artifact must carry the limb-ge-p vector");
        assert_matches!(
            bytes32_to_word_lossless(&vec.bytes32()),
            Err(EncodingError::LimbOutOfField),
            "vector {}: lossless path must reject",
            vec.id
        );
        let key = bytes32_to_storage_map_key(&vec.bytes32());
        assert_eq!(
            Word::from(key),
            word_from_hex(&vec.expected_key),
            "vector {}",
            vec.id
        );
    }

    /// TV-B32-3 (replay/determinism): same input → identical key twice.
    #[test]
    fn tv_b32_3_determinism() {
        let v = load();
        for vec in &v.families.b32 {
            let a = bytes32_to_storage_map_key(&vec.bytes32());
            let b = bytes32_to_storage_map_key(&vec.bytes32());
            assert_eq!(a, b, "vector {}: keying must be deterministic", vec.id);
        }
    }

    /// TV-B32-4 (boundary/width): the packing yields exactly 8 felts (2 Words — too wide
    /// for one key, which is why the hash-to-Word step exists).
    #[test]
    fn tv_b32_4_packing_is_8_felts_two_words() {
        let v = load();
        for vec in &v.families.b32 {
            let felts = bytes32_to_packed_felts(&vec.bytes32());
            assert_eq!(felts.len(), 8, "vector {}: packing width", vec.id);
            let expected: Vec<Felt> = vec.packed_felts_values();
            assert_eq!(
                felts.as_slice(),
                expected.as_slice(),
                "vector {}: limbs",
                vec.id
            );
        }
    }

    /// TV-B32-INV-1 (inverse round-trip): `packed_felts_to_bytes32` is the exact inverse of
    /// `bytes32_to_packed_felts` over every committed b32 vector (every limb is a valid u32).
    #[test]
    fn tv_b32_inverse_round_trip() {
        let v = load();
        for vec in &v.families.b32 {
            let b = vec.bytes32();
            let felts = bytes32_to_packed_felts(&b);
            let back = packed_felts_to_bytes32(&felts).expect("valid u32 limbs round-trip");
            assert_eq!(back, b, "vector {}: inverse round-trip", vec.id);
            assert_eq!(
                bytes32_to_packed_felts(&back),
                felts,
                "vector {}: forward∘inverse",
                vec.id
            );
        }
    }

    /// TV-B32-INV-2 (fail-closed): a packed felt `> u32::MAX` is rejected, never truncated.
    #[test]
    fn tv_b32_inverse_rejects_non_u32() {
        let mut felts = [Felt::from(0u32); 8];
        felts[3] = Felt::try_from((u32::MAX as u64) + 1).expect("2^32 < p");
        assert_matches!(
            packed_felts_to_bytes32(&felts),
            Err(EncodingError::LimbNotU32),
            "a 2^32 limb must be rejected, not truncated"
        );
    }
}
