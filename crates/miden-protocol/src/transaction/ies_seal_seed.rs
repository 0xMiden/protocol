use core::fmt;

use miden_crypto::hash::blake::Blake3_256;
use rand::{CryptoRng, Rng};
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
/// Use a fresh seed for every transaction, e.g. from [`Self::with_rng`], and reuse it only to
/// re-execute or prove that same transaction, which reproduces its envelopes if the execution makes
/// the same seal requests in the same order.
///
/// Each secret is derived from the seed, the index of the request in the transaction, the
/// recipient and the digests of the context and the plaintext (see
/// [`Self::derive_ephemeral_secret`]). With a reused seed, the same request index, recipient,
/// context and plaintext give the same secret in any transaction, so never reuse a seed for a
/// different transaction.
///
/// Anyone who knows the seed can check guesses of the plaintexts sealed with it, so keep it as
/// private as the plaintexts.
#[derive(Clone, PartialEq, Eq)]
pub struct IesSealSeed([u8; 32]);

impl IesSealSeed {
    /// Domain separator of [`Self::derive_ephemeral_secret`], which versions the derivation.
    const DERIVATION_DOMAIN: &[u8] = b"miden IES EcGFp5/Eidos seal ephemeral secret v1";

    /// Returns a new [`IesSealSeed`] with the provided bytes.
    pub fn new(seed: [u8; 32]) -> Self {
        Self(seed)
    }

    /// Returns a new [`IesSealSeed`] drawn from the provided cryptographic random number generator.
    pub fn with_rng<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        Self(seed)
    }

    /// Returns the ephemeral secret for the IES `seal` request with index `request_idx` in a
    /// transaction, which encrypts the plaintext with `plaintext_digest` under the context with
    /// `context_digest` to `recipient`.
    ///
    /// The secret is drawn from a ChaCha20 generator seeded with the BLAKE3 hash of the
    /// concatenation of a domain separator, the seed, the request index (4 bytes), the recipient
    /// key commitment and the two digests (32 bytes each), all little-endian.
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
