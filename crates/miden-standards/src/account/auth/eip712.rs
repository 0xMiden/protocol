//! EIP-712 encoding for Miden transaction-summary signatures.
//!
//! The signed typed data is:
//! `MidenTransaction(bytes32 txSummaryHash)` in the domain
//! `EIP712Domain(string name,string version)` with name `Miden Transaction` and version `1`.
//! The domain deliberately omits `chainId` and `verifyingContract`; the transaction-summary hash
//! already commits to the Miden network state and executing account. `txSummaryHash` is encoded by
//! [`Word::as_bytes`]: four field elements in word order, each as a little-endian `u64`.
//!
//! The witness advice-map key is
//! `h(h(PK_COMM, txSummaryHash), [0x323137504945, 0, 0, 0])`, where the tag is little-endian ASCII
//! `EIP712`.
//!
//! A signature witness is stored under the key returned by
//! [`Eip712TransactionSummary::eip712_signature_key`] and contains the encoded secp256k1 public
//! key followed by the ECDSA signature, as expected by Miden's `ecdsa_k256_keccak` verifier.

use alloc::vec::Vec;

use miden_core_lib::dsa::ecdsa_k256_keccak::encode_signature;
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::hash::keccak::Keccak256;
use miden_protocol::transaction::TransactionSummary;
use miden_protocol::{Felt, Hasher, Word};

// hashStruct(EIP712Domain({ name: "Miden Transaction", version: "1" })).
const DOMAIN_SEPARATOR: [u8; 32] = [
    0xd2, 0x99, 0x3b, 0x31, 0x72, 0x06, 0xdc, 0x17, 0xb9, 0x59, 0x70, 0x00, 0x08, 0x48, 0x82, 0x92,
    0x43, 0x11, 0xd2, 0x36, 0xaa, 0xa8, 0xfc, 0xcd, 0x54, 0xd6, 0xce, 0x4f, 0xaa, 0xce, 0xc6, 0xb7,
];

// keccak256("MidenTransaction(bytes32 txSummaryHash)").
const TRANSACTION_TYPE_HASH: [u8; 32] = [
    0xd4, 0x6c, 0xfc, 0xb2, 0xf8, 0x1c, 0xad, 0x54, 0x42, 0x3e, 0x73, 0x1d, 0x56, 0x4b, 0xb1, 0xa2,
    0x60, 0x60, 0xc1, 0xfe, 0xa0, 0x1f, 0xff, 0x7f, 0x86, 0xa0, 0xcd, 0x79, 0x6c, 0xaf, 0x2b, 0x63,
];

/// Must match `SIGNATURE_KEY_DOMAIN` in the MASM transaction-summary adapter.
const SIGNATURE_KEY_DOMAIN: u64 = u64::from_le_bytes(*b"EIP712\0\0");

/// A 32-byte EIP-712 signing digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Eip712Digest([u8; 32]);

impl Eip712Digest {
    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the digest and returns its raw bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// EIP-712 signing helpers for a Miden transaction summary.
pub trait Eip712TransactionSummary {
    /// Computes the [`Eip712Digest`] for this transaction summary.
    fn eip712_hash(&self) -> Eip712Digest;

    /// Computes the advice-map key for this transaction summary and public key.
    fn eip712_signature_key(&self, public_key: PublicKeyCommitment) -> Word;

    /// Builds the advice-map entry for an EIP-712 signature over this transaction summary.
    ///
    /// The returned tuple contains the advice-map key followed by the encoded public-key and
    /// signature witness. `signature` must sign the digest returned by [`Self::eip712_hash`] using
    /// the secret key corresponding to `public_key`.
    fn eip712_signature_advice(
        &self,
        public_key: &PublicKey,
        signature: &Signature,
    ) -> (Word, Vec<Felt>) {
        let key = self.eip712_signature_key(public_key.to_commitment().into());
        (key, encode_signature(public_key, signature))
    }
}

impl Eip712TransactionSummary for TransactionSummary {
    fn eip712_hash(&self) -> Eip712Digest {
        let mut struct_preimage = [0u8; 64];
        struct_preimage[..32].copy_from_slice(&TRANSACTION_TYPE_HASH);
        struct_preimage[32..].copy_from_slice(&self.to_commitment().as_bytes());
        let struct_hash: [u8; 32] = Keccak256::hash(&struct_preimage).into();

        let mut digest_preimage = [0u8; 66];
        digest_preimage[..2].copy_from_slice(&[0x19, 0x01]);
        digest_preimage[2..34].copy_from_slice(&DOMAIN_SEPARATOR);
        digest_preimage[34..].copy_from_slice(&struct_hash);

        Eip712Digest(Keccak256::hash(&digest_preimage).into())
    }

    fn eip712_signature_key(&self, public_key: PublicKeyCommitment) -> Word {
        let raw_signature_key = Hasher::merge(&[public_key.into(), self.to_commitment()]);
        let domain = Word::new([
            Felt::new_unchecked(SIGNATURE_KEY_DOMAIN),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ]);
        Hasher::merge(&[raw_signature_key, domain])
    }
}
