use alloc::vec::Vec;

use crate::Word;
use crate::block::{BlockSignatures, ValidatorKeys};
use crate::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use crate::testing::random_secret_key::random_secret_key;

/// Generates `count` random validator signing keys alongside the [`ValidatorKeys`] set committing
/// to their public keys.
pub fn random_validator_set(count: usize) -> (Vec<SigningKey>, ValidatorKeys) {
    let signers: Vec<SigningKey> = (0..count).map(|_| random_secret_key()).collect();
    let keys = ValidatorKeys::new(signers.iter().map(|sk| sk.public_key()).collect()).unwrap();
    (signers, keys)
}

/// Signs `commitment` with every one of `signers`, ordering the resulting signatures to align
/// positionally with `keys`.
///
/// Panics if `signers` does not contain a matching signer for every key in `keys`.
pub fn sign_all(keys: &ValidatorKeys, signers: &[SigningKey], commitment: Word) -> BlockSignatures {
    let signatures = keys
        .as_keys()
        .iter()
        .map(|key| {
            let signer = signers
                .iter()
                .find(|sk| &sk.public_key() == key)
                .expect("a signer should exist for every validator key");
            signer.sign(commitment)
        })
        .collect();
    BlockSignatures::new(signatures)
}
