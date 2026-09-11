//! EIP-712 encoding for multisig transaction-summary signatures.
//!
//! The signed typed data is:
//! `MidenTransaction(bytes32 txSummaryHash)` in the domain
//! `EIP712Domain(string name,string version)` with name `Miden Multisig` and version `1`.
//! The domain deliberately omits `chainId` and `verifyingContract`; the transaction-summary hash
//! already commits to the Miden network state and executing account. `txSummaryHash` is encoded by
//! [`Word::as_bytes`]: four field elements in word order, each as a little-endian `u64`.
//!
//! The witness advice-map key is
//! `h(h(PK_COMM, txSummaryHash), [0x323137504945, 0, 0, 0])`, where the tag is little-endian ASCII
//! `EIP712`.
//!
//! A signature witness is stored under [`transaction_summary_signature_key`] and contains the
//! encoded secp256k1 public key followed by the ECDSA signature, as expected by Miden's
//! `ecdsa_k256_keccak` verifier.

use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::crypto::hash::keccak::Keccak256;
use miden_protocol::{Felt, Hasher, Word};

const DOMAIN_SEPARATOR: [u8; 32] = [
    0x07, 0xf3, 0x11, 0x5a, 0xea, 0xec, 0xca, 0xb9, 0xcf, 0x0a, 0xa4, 0x1a, 0x1a, 0x45, 0x8b, 0xa2,
    0x68, 0xb8, 0x45, 0x47, 0xc9, 0x4a, 0x40, 0x9b, 0xdf, 0x33, 0x01, 0x7f, 0xd8, 0x06, 0xaa, 0xe8,
];

const TRANSACTION_TYPE_HASH: [u8; 32] = [
    0xd4, 0x6c, 0xfc, 0xb2, 0xf8, 0x1c, 0xad, 0x54, 0x42, 0x3e, 0x73, 0x1d, 0x56, 0x4b, 0xb1, 0xa2,
    0x60, 0x60, 0xc1, 0xfe, 0xa0, 0x1f, 0xff, 0x7f, 0x86, 0xa0, 0xcd, 0x79, 0x6c, 0xaf, 0x2b, 0x63,
];

/// Little-endian ASCII `EIP712`; must match `SIGNATURE_KEY_DOMAIN` in the MASM transaction-summary
/// adapter.
const SIGNATURE_KEY_DOMAIN: u64 = 0x3231_3750_4945;

/// Computes the EIP-712 digest for a Miden transaction-summary commitment.
pub fn transaction_summary_digest(tx_summary_hash: Word) -> [u8; 32] {
    digest(DOMAIN_SEPARATOR, transaction_struct_hash(tx_summary_hash))
}

/// Computes an EIP-712 typed-data digest from an already-derived domain separator and struct hash.
///
/// Callers are responsible for deriving both hashes from the schema and trusted application state.
pub fn digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 66];
    preimage[..2].copy_from_slice(&[0x19, 0x01]);
    preimage[2..34].copy_from_slice(&domain_separator);
    preimage[34..].copy_from_slice(&struct_hash);
    keccak(&preimage)
}

/// Computes the struct hash for `MidenTransaction(bytes32 txSummaryHash)`.
fn transaction_struct_hash(tx_summary_hash: Word) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&TRANSACTION_TYPE_HASH);
    preimage[32..].copy_from_slice(&tx_summary_hash.as_bytes());
    keccak(&preimage)
}

/// Computes the advice-map key for an EIP-712 transaction-summary signature.
pub fn transaction_summary_signature_key(
    public_key: PublicKeyCommitment,
    tx_summary_hash: Word,
) -> Word {
    let raw_signature_key = Hasher::merge(&[public_key.into(), tx_summary_hash]);
    let domain =
        Word::new([Felt::new_unchecked(SIGNATURE_KEY_DOMAIN), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    Hasher::merge(&[raw_signature_key, domain])
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::hash(bytes).into()
}

#[cfg(test)]
mod tests {
    use miden_protocol::utils::{bytes_to_hex_string, bytes_to_packed_u32_elements};
    use miden_protocol::{Felt, Word};

    use super::*;

    const DOMAIN_TYPE: &str = "EIP712Domain(string name,string version)";
    const DOMAIN_NAME: &str = "Miden Multisig";
    const DOMAIN_VERSION: &str = "1";
    const TRANSACTION_TYPE: &str = "MidenTransaction(bytes32 txSummaryHash)";

    #[test]
    fn precomputed_hashes_match_schema() {
        let mut domain_preimage = [0u8; 96];
        domain_preimage[..32].copy_from_slice(&keccak(DOMAIN_TYPE.as_bytes()));
        domain_preimage[32..64].copy_from_slice(&keccak(DOMAIN_NAME.as_bytes()));
        domain_preimage[64..].copy_from_slice(&keccak(DOMAIN_VERSION.as_bytes()));

        assert_eq!(DOMAIN_SEPARATOR, keccak(&domain_preimage));
        assert_eq!(TRANSACTION_TYPE_HASH, keccak(TRANSACTION_TYPE.as_bytes()));
        assert_eq!(
            bytes_to_packed_u32_elements(&DOMAIN_SEPARATOR),
            [
                1511125767, 3117083882, 446958287, 2727036186, 1195751528, 2604681929, 2130785247,
                3903456984,
            ]
            .map(Felt::from_u32)
        );
        assert_eq!(
            bytes_to_packed_u32_elements(&TRANSACTION_TYPE_HASH),
            [
                3002887380, 1420631288, 494091842, 2729528150, 4274085984, 2147426208, 2043519110,
                1663807340,
            ]
            .map(Felt::from_u32)
        );
        assert_eq!(SIGNATURE_KEY_DOMAIN, u64::from_le_bytes(*b"EIP712\0\0"));
    }

    #[test]
    fn transaction_summary_digest_matches_reference_vector() {
        let tx_summary_hash = Word::new([
            Felt::new(0x0123_4567_89ab_cdef).expect("valid field element"),
            Felt::new(0x1020_3040_5060_7080).expect("valid field element"),
            Felt::new(0x0f1e_2d3c_4b5a_6978).expect("valid field element"),
            Felt::new(0x1122_3344_5566_7788).expect("valid field element"),
        ]);

        assert_eq!(
            bytes_to_hex_string(transaction_summary_digest(tx_summary_hash)),
            "0x03bc3b7d14f9c81dfa715b49b2297f070f91b4223adb2f6afe7d68b91122451d"
        );
    }
}
