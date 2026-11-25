use core::fmt;

use rand::{CryptoRng, Rng};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

use crate::crypto::ecdh::ecgfp5::{PublicKey, SecretKey};
use crate::utils::bytes_to_packed_u32_elements;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, IES_SEAL_EPHEMERAL_SECRET_DOMAIN, Word};

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
    /// The secret is the [`SecretKey::with_rng`] draw from a ChaCha20 generator seeded with
    /// [`Word::as_bytes`] of the Eidos hash in [`IES_SEAL_EPHEMERAL_SECRET_DOMAIN`] of 22 elements:
    /// the seed as eight `u32` limbs, each four consecutive seed bytes read as little-endian, the
    /// request index, the recipient's [`PublicKey::to_elements`], the context digest and the
    /// plaintext digest.
    pub fn derive_ephemeral_secret(
        &self,
        request_idx: u32,
        recipient: &PublicKey,
        context_digest: Word,
        plaintext_digest: Word,
    ) -> SecretKey {
        let mut elements = bytes_to_packed_u32_elements(&self.0);
        elements.push(Felt::from(request_idx));
        elements.extend(recipient.to_elements());
        elements.extend(context_digest);
        elements.extend(plaintext_digest);
        let rng_seed = Hasher::hash_elements_in_domain(&elements, IES_SEAL_EPHEMERAL_SECRET_DOMAIN);

        SecretKey::with_rng(&mut ChaCha20Rng::from_seed(rng_seed.as_bytes()))
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
