use core::fmt;

use miden_crypto::hash::blake::Blake3_256;
use rand::{CryptoRng, Rng};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

use crate::Word;
use crate::account::AccountId;
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
/// Use a fresh seed for every transaction, e.g. from [`Self::with_rng`], and reuse a seed only to
/// re-execute or prove that same transaction. Re-executing the transaction with the same arguments
/// reproduces its envelopes, also at a later reference block, provided the execution makes the
/// same seal requests in the same order: the request index counts the requests of the transaction.
///
/// Each secret is derived from the seed, the native account ID, the initial account commitment,
/// the input notes commitment, the index of the request in the transaction, the recipient and the
/// digests of the context and the plaintext (see [`Self::derive_ephemeral_secret`]). If a seed is
/// reused anyway, a different plaintext, context, recipient, request index or transaction gives an
/// unrelated secret, and the same values give the same envelope.
///
/// Code that runs in a re-execution with the same seed and repeats the exact inputs of another
/// request at the same index derives that request's secret, so a retry must use a fresh seed.
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

    /// Returns the ephemeral secret for the IES `seal` request with index `request_idx` in the
    /// transaction of the native account `account_id` that starts from the state with
    /// `initial_account_commitment` and consumes the notes with `input_notes_commitment`. The
    /// request encrypts the plaintext with `plaintext_digest` under the context with
    /// `context_digest` to `recipient`.
    ///
    /// The secret is drawn from a ChaCha20 generator seeded with the BLAKE3 hash of the
    /// concatenation of a domain separator, the seed, the account ID prefix and suffix (8 bytes
    /// each), the two transaction commitments (32 bytes each), the request index (4 bytes), the
    /// recipient key commitment and the two digests (32 bytes each), all little-endian.
    pub fn derive_ephemeral_secret(
        &self,
        account_id: AccountId,
        initial_account_commitment: Word,
        input_notes_commitment: Word,
        request_idx: u32,
        recipient: &PublicKey,
        context_digest: Word,
        plaintext_digest: Word,
    ) -> SecretKey {
        let rng_seed = Blake3_256::hash_iter(
            [
                Self::DERIVATION_DOMAIN,
                &self.0,
                &account_id.prefix().as_u64().to_le_bytes(),
                &account_id.suffix().as_canonical_u64().to_le_bytes(),
                &initial_account_commitment.as_bytes(),
                &input_notes_commitment.as_bytes(),
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
    use crate::testing::account_id::{ACCOUNT_ID_PRIVATE_SENDER, ACCOUNT_ID_SENDER};

    /// The inputs of [`IesSealSeed::derive_ephemeral_secret`].
    #[derive(Clone)]
    struct Inputs {
        seed: IesSealSeed,
        account_id: AccountId,
        initial_account_commitment: Word,
        input_notes_commitment: Word,
        request_idx: u32,
        recipient: PublicKey,
        context_digest: Word,
        plaintext_digest: Word,
    }

    impl Inputs {
        fn ephemeral_key(&self) -> PublicKey {
            self.seed
                .derive_ephemeral_secret(
                    self.account_id,
                    self.initial_account_commitment,
                    self.input_notes_commitment,
                    self.request_idx,
                    &self.recipient,
                    self.context_digest,
                    self.plaintext_digest,
                )
                .public_key()
        }
    }

    #[test]
    fn ephemeral_secret_depends_on_every_input() {
        let digest = |value: u32| Word::from([value; 4]);
        let recipient = |seed: u8| SecretKey::from_bytes(&[seed; 40]).unwrap().public_key();
        let inputs = Inputs {
            seed: IesSealSeed::new([1; 32]),
            account_id: AccountId::try_from(ACCOUNT_ID_SENDER).unwrap(),
            initial_account_commitment: digest(1),
            input_notes_commitment: digest(2),
            request_idx: 0,
            recipient: recipient(2),
            context_digest: digest(3),
            plaintext_digest: digest(4),
        };
        let expected = inputs.ephemeral_key();
        assert_eq!(inputs.clone().ephemeral_key(), expected);

        let changes: [fn(&mut Inputs); 8] = [
            |inputs| inputs.seed = IesSealSeed::new([5; 32]),
            |inputs| inputs.account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap(),
            |inputs| inputs.initial_account_commitment = Word::from([6_u32; 4]),
            |inputs| inputs.input_notes_commitment = Word::from([6_u32; 4]),
            |inputs| inputs.request_idx = 1,
            |inputs| inputs.recipient = SecretKey::from_bytes(&[3; 40]).unwrap().public_key(),
            |inputs| inputs.context_digest = inputs.plaintext_digest,
            |inputs| inputs.plaintext_digest = inputs.context_digest,
        ];
        for change in changes {
            let mut changed = inputs.clone();
            change(&mut changed);
            assert_ne!(changed.ephemeral_key(), expected);
        }
    }
}
