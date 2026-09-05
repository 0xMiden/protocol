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

    /// Signs `commitment` with every one of `signers`, ordering the resulting signatures to align
    /// positionally with the keys of this config.
    ///
    /// Panics if `signers` does not contain a matching signer for every key in this config.
    pub fn sign_all(&self, signers: &[SigningKey], commitment: Word) -> BlockSignatures {
        let signatures = self
            .keys()
            .iter()
            .map(|key| {
                let signer = signers
                    .iter()
                    .find(|signer| &signer.public_key() == key)
                    .expect("a signer should exist for every validator key");
                signer.sign(commitment)
            })
            .collect();
        BlockSignatures::new(signatures).expect("signature count same as validator key count")
    }
}
