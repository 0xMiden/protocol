use alloc::vec::Vec;

use crate::Word;
use crate::block::{BlockSignatures, ValidatorConfig};
use crate::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use crate::testing::random_secret_key::random_secret_key;

/// Returns the [`ValidatorConfig`] committing to the public keys of `signers`, with the quorum set
/// to the full validator count.
///
/// Panics if `signers` is not a valid validator set.
pub fn validator_config_of(signers: &[SigningKey]) -> ValidatorConfig {
    let quorum = u16::try_from(signers.len()).expect("validator count should fit into a u16");
    ValidatorConfig::new(signers.iter().map(|sk| sk.public_key()).collect(), quorum)
        .expect("signers should form a valid validator set")
}

/// Generates `count` random validator signing keys alongside the [`ValidatorConfig`] committing to
/// their public keys, with the quorum set to the full validator count.
pub fn random_validator_set(count: usize) -> (Vec<SigningKey>, ValidatorConfig) {
    let signers: Vec<SigningKey> = (0..count).map(|_| random_secret_key()).collect();
    let config = validator_config_of(&signers);
    (signers, config)
}

/// Signs `commitment` with every one of `signers`, ordering the resulting signatures to align
/// positionally with the keys of `config`.
///
/// Panics if `signers` does not contain a matching signer for every key in `config`.
pub fn sign_all(
    config: &ValidatorConfig,
    signers: &[SigningKey],
    commitment: Word,
) -> BlockSignatures {
    let signatures = config
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
    BlockSignatures::new(signatures).expect("signature count same as validator key count")
}
