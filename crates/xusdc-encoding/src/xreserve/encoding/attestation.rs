//! Attestation encoding: turning Circle's signature material into the form the faucet verifies
//! against.
//!
//! A deposit attestation is a raw secp256k1 ECDSA signature over `keccak256` of the full deposit
//! payload — 65 bytes of `r‖s‖v` — and deliberately not EIP-712. The signature is what makes a mint
//! legitimate, so how it is packed matters as much as the cryptography: the faucet recomputes the
//! digest on-chain and looks the signer up in its attester allowlist, and both sides have to agree
//! byte for byte or a valid attestation would be rejected (or, worse, the wrong key would be looked
//! up).
//!
//! This module owns the packing of the one value the protocol has no type for — the signature. It
//! goes into u32-little-endian field elements with the same primitive miden-crypto uses for byte
//! streams, four bytes per element, and the conversion cannot fail: every element is a `u32`, and
//! the length comes from a fixed-size array rather than from input.
//!
//! The digest is packed the same way, but nothing off-chain does it: the faucet computes and packs
//! its own digest on-chain, so the packing lives with the tests that pin the golden vectors.
//!
//! Producing the digest and running the signature check are the faucet's job, not this module's.

use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::Felt;

/// Number of u32 field elements an affine secp256k1 public key packs to
/// (`qx_le_u32[8] || qy_le_u32[8]`) — the element count the commitment hashes.
pub const PUBKEY_FELTS: usize = 16;

/// A Circle deposit attestation's raw 65-byte `r‖s‖v` ECDSA signature.
///
/// Wrapping the fixed-width byte array turns the packing into a method — `Signature::new(bytes)
/// .to_felts()` — so a caller states what the bytes ARE at the call site instead of passing a bare
/// `[u8; 65]` around. The type owns the packing (the golden-vector-locked felt layout below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 65]);

impl Signature {
    /// Wraps a raw 65-byte `r‖s‖v` signature (`v` carried in the last byte, unused on-chain).
    pub const fn new(bytes: [u8; 65]) -> Self {
        Self(bytes)
    }

    /// The raw 65 signature bytes.
    pub const fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }

    /// Packs the signature into the 17 u32-LE field elements the on-chain attestation surface reads,
    /// four bytes per element, with `v` carried in felt 16 (byte 64, upper three bytes zero-filled)
    /// and unused on-chain. Infallible: every element is a `u32` and the length comes from the
    /// fixed-size array, not from input.
    pub fn to_elements(&self) -> [Felt; 17] {
        bytes_to_packed_u32_elements(&self.0)
            .try_into()
            .expect("65 bytes always pack to exactly 17 u32 felts")
    }
}

// TESTS — TV-ATT-1..4
// ================================================================================================

#[cfg(test)]
mod tests {

    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
    use miden_protocol::crypto::SequentialCommit;
    use miden_protocol::utils::bytes_to_packed_u32_elements;
    use sha3::{Digest, Keccak256};

    use super::*;
    use crate::vectors::load;

    /// Packs a 32-byte keccak digest into 8 u32-LE field elements (4 bytes/felt) — the form the
    /// faucet's on-chain digest takes. No off-chain caller needs it, so it is the tests' own.
    fn keccak_digest_felts(digest: &[u8; 32]) -> [Felt; 8] {
        bytes_to_packed_u32_elements(digest)
            .try_into()
            .expect("32 bytes always pack to exactly 8 u32 felts")
    }

    /// TV-ATT-1 (felt shapes): the three packers yield exactly 8 / 16 / 17 felts and match
    /// the canonical packing of every vector's digest / pubkey / signature.
    #[test]
    fn tv_att_1_felt_shapes() {
        for v in &load().families.att {
            let pk = v.public_key().to_elements();
            assert_eq!(pk.len(), PUBKEY_FELTS, "{}: pubkey felt width", v.id);
            assert_eq!(
                pk.as_slice(),
                v.packed_felts_values().as_slice(),
                "{}: pubkey felts",
                v.id
            );

            let d = keccak_digest_felts(&v.digest());
            assert_eq!(d.len(), 8, "{}: digest felt width", v.id);
            assert_eq!(
                d.as_slice(),
                v.digest_felts_values().as_slice(),
                "{}: digest felts",
                v.id
            );

            let s = Signature::new(v.sig()).to_elements();
            assert_eq!(s.len(), 17, "{}: signature felt width", v.id);
            assert_eq!(
                s.as_slice(),
                v.sig_felts_values().as_slice(),
                "{}: signature felts",
                v.id
            );
        }
    }

    /// TV-ATT-2 (commitment): the golden vectors pin miden-crypto `PublicKey::to_commitment`, the
    /// attester-allowlist keying primitive the faucet's attestation verify looks up.
    #[test]
    fn tv_att_2_commitment() {
        for v in &load().families.att {
            let commitment = v.public_key().to_commitment();
            assert_eq!(
                commitment,
                v.expected_commitment_word(),
                "{}: the commitment must equal miden-crypto PublicKey::to_commitment",
                v.id
            );
        }
    }

    /// TV-ATT-3 (raw keccak, not EIP-712): the digest helper packs the raw keccak digest
    /// VERBATIM — it prepends no EIP-712 `\x19\x01` domain / personal-sign prefix and hashes
    /// no `depositAttestation` struct; the digest is over a FULL DepositIntent payload; the
    /// input is the RAW 65-byte `r‖s‖v` signature (`v` carried in felt 16).
    #[test]
    fn tv_att_3_raw_keccak_not_eip712() {
        for v in &load().families.att {
            let digest = v.digest();
            // pure verbatim packer — no domain/struct framing felts added.
            assert_eq!(
                keccak_digest_felts(&digest).as_slice(),
                bytes_to_packed_u32_elements(&digest).as_slice(),
                "{}: digest helper must pack the raw keccak digest verbatim (no EIP-712 framing)",
                v.id
            );
            // raw keccak is taken over the ENTIRE DepositIntent payload (>= the 240-byte header).
            assert!(
                v.payload().len() >= 240,
                "{}: digest must be keccak over a full DepositIntent payload, got {} bytes",
                v.id,
                v.payload().len()
            );
            // the input is the raw 65-byte r||s||v signature, NOT an EIP-712 typed-data sig.
            assert_eq!(
                v.sig().len(),
                65,
                "{}: raw r||s||v signature is 65 bytes",
                v.id
            );
            assert_eq!(
                Signature::new(v.sig()).to_elements()[16],
                Felt::from(u32::from(v.v_byte)),
                "{}: v byte carried in felt 16 (unused on-chain)",
                v.id
            );
        }
    }

    /// TV-ATT-4: each vector's full payload, digest, signature, public key, and recovery id agree.
    #[test]
    fn attestation_vectors_are_self_consistent() {
        for v in &load().families.att {
            let digest = v.digest();
            let actual: [u8; 32] = Keccak256::digest(v.payload()).into();
            assert_eq!(
                actual, digest,
                "{}: digest must equal keccak256 of the full payload",
                v.id
            );

            let pubkey = v.pubkey();
            let key = VerifyingKey::from_sec1_bytes(&pubkey)
                .unwrap_or_else(|e| panic!("{}: invalid public key: {e}", v.id));
            let sig = K256Signature::from_slice(&v.sig()[..64])
                .unwrap_or_else(|e| panic!("{}: invalid signature: {e}", v.id));
            assert!(
                key.verify_prehash(&digest, &sig).is_ok(),
                "{}: signature must verify over the digest under the vector's public key",
                v.id
            );

            let recovery_id = RecoveryId::from_byte(v.v_byte)
                .unwrap_or_else(|| panic!("{}: invalid recovery id", v.id));
            let recovered = VerifyingKey::recover_from_prehash(&digest, &sig, recovery_id)
                .unwrap_or_else(|e| panic!("{}: public key recovery failed: {e}", v.id));
            assert_eq!(
                recovered.to_encoded_point(true).as_bytes(),
                &pubkey,
                "{}: recovery id must recover the vector's public key",
                v.id
            );
        }
        assert!(
            load().families.att.iter().any(|v| v.payload().len() > 240),
            "att family must retain a vector with non-empty hookData"
        );
    }
}
