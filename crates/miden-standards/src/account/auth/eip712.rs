use alloc::vec::Vec;

use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::crypto::hash::keccak::Keccak256;
use miden_protocol::{Felt, Hasher, Word};

/// EIP-712 domain type used for transaction-summary signatures.
pub const DOMAIN_TYPE: &str = "EIP712Domain(string name,string version)";

/// EIP-712 domain name used for transaction-summary signatures.
pub const DOMAIN_NAME: &str = "Miden Multisig";

/// EIP-712 domain version used for transaction-summary signatures.
pub const DOMAIN_VERSION: &str = "1";

/// EIP-712 primary type used for transaction-summary signatures.
pub const TRANSACTION_TYPE: &str = "MidenTransaction(bytes32 txSummaryHash)";

const SIGNATURE_KEY_DOMAIN: u64 = 0x3231_3750_4945;

/// Computes the EIP-712 digest for a Miden transaction-summary commitment.
pub fn transaction_summary_digest(tx_summary_hash: Word) -> [u8; 32] {
    digest(domain_separator(), transaction_struct_hash(tx_summary_hash))
}

/// Computes an EIP-712 typed-data digest from an already-derived domain separator and struct hash.
///
/// Callers are responsible for deriving both hashes from the schema and trusted application state.
pub fn digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(66);
    preimage.extend_from_slice(&[0x19, 0x01]);
    preimage.extend_from_slice(&domain_separator);
    preimage.extend_from_slice(&struct_hash);
    keccak(&preimage)
}

/// Computes the domain separator used by Miden transaction-summary signatures.
pub fn domain_separator() -> [u8; 32] {
    let mut preimage = Vec::with_capacity(96);
    preimage.extend_from_slice(&keccak(DOMAIN_TYPE.as_bytes()));
    preimage.extend_from_slice(&keccak(DOMAIN_NAME.as_bytes()));
    preimage.extend_from_slice(&keccak(DOMAIN_VERSION.as_bytes()));
    keccak(&preimage)
}

/// Computes the struct hash for `MidenTransaction(bytes32 txSummaryHash)`.
pub fn transaction_struct_hash(tx_summary_hash: Word) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&keccak(TRANSACTION_TYPE.as_bytes()));
    preimage.extend_from_slice(&word_to_bytes32(tx_summary_hash));
    keccak(&preimage)
}

/// Computes the advice-map key for an EIP-712 transaction-summary signature.
pub fn transaction_summary_signature_key(
    public_key: PublicKeyCommitment,
    tx_summary_hash: Word,
) -> Word {
    let raw_signature_key = Hasher::merge(&[public_key.into(), tx_summary_hash]);
    let domain = Word::new([
        Felt::new_unchecked(SIGNATURE_KEY_DOMAIN),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ]);
    Hasher::merge(&[raw_signature_key, domain])
}

/// Encodes a Miden word as the `bytes32` value used by the EIP-712 message.
pub fn word_to_bytes32(word: Word) -> [u8; 32] {
    word.as_bytes()
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::hash(bytes).into()
}

#[cfg(test)]
mod tests {
    use miden_protocol::utils::bytes_to_hex_string;
    use miden_protocol::{Felt, Word};

    use super::*;

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
