use alloc::vec::Vec;

use crate::Word;
use crate::block::{BlockSignatures, ValidatorConfig};
use crate::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use crate::testing::random_secret_key::random_secret_key;

impl ValidatorConfig {
    /// Returns the [`ValidatorConfig`] committing to the public keys of `signers`, with the quorum
    /// set to the full validator count.
    ///
    /// Panics if `signers` is not a valid validator set.
    pub fn from_signers(signers: &[SigningKey]) -> Self {
        let quorum = u16::try_from(signers.len()).expect("validator count should fit into a u16");
        Self::new(signers.iter().map(|signer| signer.public_key()).collect(), quorum)
            .expect("signers should form a valid validator set")
    }

    /// Generates `count` random validator signing keys alongside the [`ValidatorConfig`] committing
    /// to their public keys, with the quorum set to the full validator count.
    pub fn random_with_signers(count: usize) -> (Vec<SigningKey>, Self) {
        let signers: Vec<SigningKey> = (0..count).map(|_| random_secret_key()).collect();
        let config = Self::from_signers(&signers);
        (signers, config)
    }
}

impl BlockSignatures {
    /// Signs `commitment` with every one of `signers`, in the given order.
    ///
    /// Panics if `signers` does not form a valid signature set.
    pub fn sign(signers: &[SigningKey], commitment: Word) -> Self {
        let signatures = signers.iter().map(|signer| signer.sign(commitment)).collect();
        Self::new(signatures).expect("signers should form a valid signature set")
    }
}
