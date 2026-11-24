use core::fmt;

use miden_crypto::hash::blake::Blake3_256;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

use crate::Word;
use crate::crypto::ecdh::ecgfp5::{PublicKey, SecretKey};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// IES SEAL SEED
// ================================================================================================

/// The secret seed from which the transaction host derives the ephemeral secrets of the IES `seal`
/// requests of a transaction.
///
/// Each ephemeral secret is derived from the seed, the index of the request in the transaction,
/// the recipient and the digests of the context and the plaintext (see
/// [`Self::derive_ephemeral_secret`]). So
/// executing, re-executing and proving a transaction with the same seed produce the same
/// envelopes, and a seed reused for another plaintext derives an unrelated secret.
///
/// Anyone who knows the seed can check guesses of the plaintexts sealed with it, so draw it from a
/// cryptographic random number generator and keep it as private as the plaintexts.
#[derive(Clone, PartialEq, Eq)]
pub struct IesSealSeed([u8; 32]);

impl IesSealSeed {
    /// Domain separator of [`Self::derive_ephemeral_secret`], which versions the derivation.
    const DERIVATION_DOMAIN: &[u8] = b"miden IES EcGFp5/Eidos seal ephemeral secret v1";

    /// Returns a new [`IesSealSeed`] with the provided bytes.
    pub fn new(seed: [u8; 32]) -> Self {
        Self(seed)
    }

    /// Returns the ephemeral secret for the IES `seal` request with index `request_idx` in the
    /// transaction, which encrypts the plaintext with `plaintext_digest` under the context with
    /// `context_digest` to `recipient`.
    ///
    /// The secret is drawn from a ChaCha20 generator seeded with the BLAKE3 hash of a domain
    /// separator, the seed, the request index, the recipient key commitment and the two digests.
    pub fn derive_ephemeral_secret(
        &self,
        request_idx: u32,
        recipient: &PublicKey,
        context_digest: Word,
        plaintext_digest: Word,
    ) -> SecretKey {
        let rng_seed = Blake3_256::hash_iter(
            [
                Self::DERIVATION_DOMAIN,
                &self.0,
                &request_idx.to_le_bytes(),
                &recipient.to_commitment().as_bytes(),
                &context_digest.as_bytes(),
                &plaintext_digest.as_bytes(),
            ]
            .into_iter(),
        );

        SecretKey::with_rng(&mut ChaCha20Rng::from_seed(rng_seed.into()))
    }
}

impl fmt::Debug for IesSealSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IesSealSeed").finish_non_exhaustive()
    }
}

impl Serializable for IesSealSeed {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for IesSealSeed {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(source.read_array()?))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_secret_depends_on_every_input() {
        let seed = IesSealSeed::new([1; 32]);
        let recipient = SecretKey::from_bytes(&[2; 40]).unwrap().public_key();
        let [first_digest, second_digest] = [1_u32, 2].map(|value| Word::from([value; 4]));
        let ephemeral_key = |seed: &IesSealSeed, request_idx, recipient, context, plaintext| {
            seed.derive_ephemeral_secret(request_idx, recipient, context, plaintext)
                .public_key()
        };

        let expected = ephemeral_key(&seed, 0, &recipient, first_digest, second_digest);
        assert_eq!(ephemeral_key(&seed, 0, &recipient, first_digest, second_digest), expected);

        let other_recipient = SecretKey::from_bytes(&[3; 40]).unwrap().public_key();
        for other in [
            ephemeral_key(&IesSealSeed::new([4; 32]), 0, &recipient, first_digest, second_digest),
            ephemeral_key(&seed, 1, &recipient, first_digest, second_digest),
            ephemeral_key(&seed, 0, &other_recipient, first_digest, second_digest),
            ephemeral_key(&seed, 0, &recipient, second_digest, first_digest),
            ephemeral_key(&seed, 0, &recipient, first_digest, first_digest),
        ] {
            assert_ne!(other, expected);
        }
    }
}
