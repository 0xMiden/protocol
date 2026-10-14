use alloc::borrow::ToOwned;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::str::FromStr;

use rand::{CryptoRng, Rng};

use crate::crypto::dsa::{ecdsa_k256_keccak, falcon512_eidos};
use crate::errors::{AuthSchemeError, BoundSignatureError};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word};

// AUTH SCHEME
// ================================================================================================

/// Identifier of signature schemes use for transaction authentication
const FALCON512_EIDOS: u8 = 2;
const ECDSA_K256_KECCAK: u8 = 1;

const FALCON512_EIDOS_STR: &str = "Falcon512Eidos";
const ECDSA_K256_KECCAK_STR: &str = "EcdsaK256Keccak";

/// Defines standard authentication schemes (i.e., signature schemes) available in the Miden
/// protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum AuthScheme {
    /// A deterministic Falcon512 signature scheme.
    ///
    /// This version differs from the reference Falcon512 implementation in its use of the Eidos
    /// hash function in its hash-to-point algorithm to make signatures very efficient to verify
    /// inside Miden VM.
    Falcon512Eidos = FALCON512_EIDOS,

    /// ECDSA signature scheme over secp256k1 curve using Keccak to hash the messages when signing.
    ///
    /// Verification uses a deferred precompile. The transaction proof carries the public key and
    /// signature in its precompile witness for verification during batch proving, so both are
    /// visible to recipients of the transaction proof. The VM binds the public key to the account
    /// commitment.
    EcdsaK256Keccak = ECDSA_K256_KECCAK,
}

impl AuthScheme {
    /// Returns a numerical value of this auth scheme.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl core::fmt::Display for AuthScheme {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Falcon512Eidos => f.write_str(FALCON512_EIDOS_STR),
            Self::EcdsaK256Keccak => f.write_str(ECDSA_K256_KECCAK_STR),
        }
    }
}

impl TryFrom<u8> for AuthScheme {
    type Error = AuthSchemeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            FALCON512_EIDOS => Ok(Self::Falcon512Eidos),
            ECDSA_K256_KECCAK => Ok(Self::EcdsaK256Keccak),
            value => Err(AuthSchemeError::InvalidAuthSchemeIdentifier(value.to_string())),
        }
    }
}

impl FromStr for AuthScheme {
    type Err = AuthSchemeError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            FALCON512_EIDOS_STR => Ok(AuthScheme::Falcon512Eidos),
            ECDSA_K256_KECCAK_STR => Ok(AuthScheme::EcdsaK256Keccak),
            other => Err(AuthSchemeError::InvalidAuthSchemeIdentifier(other.to_owned())),
        }
    }
}

impl Serializable for AuthScheme {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(*self as u8);
    }

    fn get_size_hint(&self) -> usize {
        // auth scheme is encoded as a single byte
        size_of::<u8>()
    }
}

impl Deserializable for AuthScheme {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            FALCON512_EIDOS => Ok(Self::Falcon512Eidos),
            ECDSA_K256_KECCAK => Ok(Self::EcdsaK256Keccak),
            value => Err(DeserializationError::InvalidValue(format!(
                "auth scheme identifier `{value}` is not valid"
            ))),
        }
    }
}

// AUTH SECRET KEY
// ================================================================================================

/// Secret keys of the standard [`AuthScheme`]s available in the Miden protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum AuthSecretKey {
    Falcon512Eidos(falcon512_eidos::SecretKey) = FALCON512_EIDOS,
    EcdsaK256Keccak(ecdsa_k256_keccak::SigningKey) = ECDSA_K256_KECCAK,
}

impl AuthSecretKey {
    /// Generates a Falcon512Eidos secret key from OS-provided randomness.
    #[cfg(feature = "std")]
    pub fn new_falcon512_eidos() -> Self {
        Self::Falcon512Eidos(falcon512_eidos::SecretKey::new())
    }

    /// Generates a Falcon512Eidos secret key using the provided cryptographic random number
    /// generator.
    pub fn new_falcon512_eidos_with_rng<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::Falcon512Eidos(falcon512_eidos::SecretKey::with_rng::<R>(rng))
    }

    /// Generates an EcdsaK256Keccak secret key from the OS-provided randomness.
    #[cfg(feature = "std")]
    pub fn new_ecdsa_k256_keccak() -> Self {
        Self::EcdsaK256Keccak(ecdsa_k256_keccak::SigningKey::new())
    }

    /// Generates an EcdsaK256Keccak secret key using the provided random number generator.
    pub fn new_ecdsa_k256_keccak_with_rng<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::EcdsaK256Keccak(ecdsa_k256_keccak::SigningKey::with_rng::<R>(rng))
    }

    /// Generates a new secret key for the specified authentication scheme using the provided
    /// random number generator.
    ///
    /// Returns an error if the specified authentication scheme is not supported.
    pub fn with_scheme_and_rng<R: Rng + CryptoRng>(
        scheme: AuthScheme,
        rng: &mut R,
    ) -> Result<Self, AuthSchemeError> {
        match scheme {
            AuthScheme::Falcon512Eidos => Ok(Self::new_falcon512_eidos_with_rng(rng)),
            AuthScheme::EcdsaK256Keccak => Ok(Self::new_ecdsa_k256_keccak_with_rng(rng)),
        }
    }

    /// Generates a new secret key for the specified authentication scheme from the
    /// OS-provided randomness.
    ///
    /// Returns an error if the specified authentication scheme is not supported.
    #[cfg(feature = "std")]
    pub fn with_scheme(scheme: AuthScheme) -> Result<Self, AuthSchemeError> {
        match scheme {
            AuthScheme::Falcon512Eidos => Ok(Self::new_falcon512_eidos()),
            AuthScheme::EcdsaK256Keccak => Ok(Self::new_ecdsa_k256_keccak()),
        }
    }

    /// Returns the authentication scheme of this secret key.
    pub fn auth_scheme(&self) -> AuthScheme {
        match self {
            AuthSecretKey::Falcon512Eidos(_) => AuthScheme::Falcon512Eidos,
            AuthSecretKey::EcdsaK256Keccak(_) => AuthScheme::EcdsaK256Keccak,
        }
    }

    /// Returns a public key associated with this secret key.
    pub fn public_key(&self) -> PublicKey {
        match self {
            AuthSecretKey::Falcon512Eidos(key) => PublicKey::Falcon512Eidos(key.public_key()),
            AuthSecretKey::EcdsaK256Keccak(key) => PublicKey::EcdsaK256Keccak(key.public_key()),
        }
    }

    /// Signs the provided message with this secret key.
    pub fn sign(&self, message: Word) -> Signature {
        match self {
            AuthSecretKey::Falcon512Eidos(key) => Signature::Falcon512Eidos(key.sign(message)),
            AuthSecretKey::EcdsaK256Keccak(key) => Signature::EcdsaK256Keccak(key.sign(message)),
        }
    }
}

impl Serializable for AuthSecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.auth_scheme().write_into(target);
        match self {
            AuthSecretKey::Falcon512Eidos(key) => key.write_into(target),
            AuthSecretKey::EcdsaK256Keccak(key) => key.write_into(target),
        }
    }
}

impl Deserializable for AuthSecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read::<AuthScheme>()? {
            AuthScheme::Falcon512Eidos => {
                let secret_key = falcon512_eidos::SecretKey::read_from(source)?;
                Ok(AuthSecretKey::Falcon512Eidos(secret_key))
            },
            AuthScheme::EcdsaK256Keccak => {
                let secret_key = ecdsa_k256_keccak::SigningKey::read_from(source)?;
                Ok(AuthSecretKey::EcdsaK256Keccak(secret_key))
            },
        }
    }
}

// PUBLIC KEY
// ================================================================================================

/// Commitment to a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKeyCommitment(Word);

impl core::fmt::Display for PublicKeyCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<falcon512_eidos::PublicKey> for PublicKeyCommitment {
    fn from(value: falcon512_eidos::PublicKey) -> Self {
        Self(value.to_commitment())
    }
}

impl From<ecdsa_k256_keccak::PublicKey> for PublicKeyCommitment {
    fn from(value: ecdsa_k256_keccak::PublicKey) -> Self {
        Self(value.to_commitment())
    }
}

impl From<PublicKeyCommitment> for Word {
    fn from(value: PublicKeyCommitment) -> Self {
        value.0
    }
}

impl From<Word> for PublicKeyCommitment {
    fn from(value: Word) -> Self {
        Self(value)
    }
}

// SIGNATURE KEY
// ================================================================================================

/// Identifies a signature by the commitment to the signer's public key and the signed message.
///
/// The message is part of the key because ECDSA signatures need it to recover the public key when
/// they are encoded for the VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignatureKey {
    pub_key_commitment: PublicKeyCommitment,
    message: Word,
}

impl SignatureKey {
    /// Returns a new [`SignatureKey`] for the given public key commitment and message.
    pub fn new(pub_key_commitment: PublicKeyCommitment, message: Word) -> Self {
        Self { pub_key_commitment, message }
    }

    /// Returns the commitment to the signer's public key.
    pub fn pub_key_commitment(&self) -> PublicKeyCommitment {
        self.pub_key_commitment
    }

    /// Returns the signed message.
    pub fn message(&self) -> Word {
        self.message
    }

    /// Returns the advice map key under which the transaction kernel looks up the encoded
    /// signature.
    pub fn to_advice_map_key(&self) -> Word {
        Hasher::hash_double_word(&[self.pub_key_commitment.into(), self.message])
    }
}

/// Public keys of the standard authentication schemes available in the Miden protocol.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum PublicKey {
    Falcon512Eidos(falcon512_eidos::PublicKey),
    EcdsaK256Keccak(ecdsa_k256_keccak::PublicKey),
}

impl PublicKey {
    /// Returns the authentication scheme of this public key.
    pub fn auth_scheme(&self) -> AuthScheme {
        match self {
            PublicKey::Falcon512Eidos(_) => AuthScheme::Falcon512Eidos,
            PublicKey::EcdsaK256Keccak(_) => AuthScheme::EcdsaK256Keccak,
        }
    }

    /// Returns a commitment to this public key.
    pub fn to_commitment(&self) -> PublicKeyCommitment {
        match self {
            PublicKey::Falcon512Eidos(key) => key.to_commitment().into(),
            PublicKey::EcdsaK256Keccak(key) => key.to_commitment().into(),
        }
    }

    /// Verifies the provided signature against the provided message and this public key.
    pub fn verify(&self, message: Word, signature: Signature) -> bool {
        match (self, signature) {
            (PublicKey::Falcon512Eidos(key), Signature::Falcon512Eidos(sig)) => {
                key.verify(message, &sig)
            },
            (PublicKey::EcdsaK256Keccak(key), Signature::EcdsaK256Keccak(sig)) => {
                key.verify(message, &sig)
            },
            _ => false,
        }
    }
}

impl Serializable for PublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.auth_scheme().write_into(target);
        match self {
            PublicKey::Falcon512Eidos(pub_key) => pub_key.write_into(target),
            PublicKey::EcdsaK256Keccak(pub_key) => pub_key.write_into(target),
        }
    }
}

impl Deserializable for PublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read::<AuthScheme>()? {
            AuthScheme::Falcon512Eidos => {
                let pub_key = falcon512_eidos::PublicKey::read_from(source)?;
                Ok(PublicKey::Falcon512Eidos(pub_key))
            },
            AuthScheme::EcdsaK256Keccak => {
                let pub_key = ecdsa_k256_keccak::PublicKey::read_from(source)?;
                Ok(PublicKey::EcdsaK256Keccak(pub_key))
            },
        }
    }
}

// SIGNATURE
// ================================================================================================

/// Represents a signature object ready for native verification.
///
/// To use this signature within the Miden VM, bind it to the [`SignatureKey`] it signs with
/// [`BoundSignature`], which can encode it for the advice provider.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Signature {
    Falcon512Eidos(falcon512_eidos::Signature) = FALCON512_EIDOS,
    EcdsaK256Keccak(ecdsa_k256_keccak::Signature) = ECDSA_K256_KECCAK,
}

impl Signature {
    /// The maximum number of field elements that [`BoundSignature::to_encoded_signature`] can
    /// return for any variant.
    ///
    /// This lets consumers reject an encoded signature of an impossible length before allocating
    /// for it. The largest encoding is the one of [`Signature::Falcon512Eidos`].
    pub const MAX_NUM_ENCODED_SIGNATURE_FELTS: usize = 2058;

    /// Returns the authentication scheme of this signature.
    pub fn auth_scheme(&self) -> AuthScheme {
        match self {
            Signature::Falcon512Eidos(_) => AuthScheme::Falcon512Eidos,
            Signature::EcdsaK256Keccak(_) => AuthScheme::EcdsaK256Keccak,
        }
    }

    /// Returns the commitment to the public key of the signer of `message`.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key of an ECDSA signature cannot be recovered from the
    /// signature and `message`.
    fn signer_commitment(&self, message: Word) -> Result<PublicKeyCommitment, BoundSignatureError> {
        match self {
            Signature::Falcon512Eidos(sig) => Ok(sig.public_key().to_commitment().into()),
            Signature::EcdsaK256Keccak(sig) => {
                let pub_key =
                    ecdsa_k256_keccak::PublicKey::recover_from(message, sig).map_err(|source| {
                        BoundSignatureError::EcdsaPublicKeyRecoveryFailed { message, source }
                    })?;
                Ok(pub_key.into())
            },
        }
    }
}

impl From<falcon512_eidos::Signature> for Signature {
    fn from(signature: falcon512_eidos::Signature) -> Self {
        Signature::Falcon512Eidos(signature)
    }
}

impl Serializable for Signature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.auth_scheme().write_into(target);
        match self {
            Signature::Falcon512Eidos(signature) => signature.write_into(target),
            Signature::EcdsaK256Keccak(signature) => signature.write_into(target),
        }
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read::<AuthScheme>()? {
            AuthScheme::Falcon512Eidos => {
                let signature = falcon512_eidos::Signature::read_from(source)?;
                Ok(Signature::Falcon512Eidos(signature))
            },
            AuthScheme::EcdsaK256Keccak => {
                let signature = ecdsa_k256_keccak::Signature::read_from(source)?;
                Ok(Signature::EcdsaK256Keccak(signature))
            },
        }
    }
}

// BOUND SIGNATURE
// ================================================================================================

/// A [`Signature`] bound to the [`SignatureKey`] it signs.
///
/// The public key of the signer matches the public key commitment of the key, so the signature can
/// always be encoded for the VM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundSignature {
    key: SignatureKey,
    signature: Signature,
}

impl BoundSignature {
    /// Returns a new [`BoundSignature`] that binds `signature` to `key`.
    ///
    /// This does not check that the signature is valid since that is an expensive computation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the public key of an ECDSA signature cannot be recovered from the signature and message.
    /// - the commitment to the public key of the signer does not match the commitment of `key`.
    pub fn new(key: SignatureKey, signature: Signature) -> Result<Self, BoundSignatureError> {
        let actual = signature.signer_commitment(key.message())?;
        if actual != key.pub_key_commitment() {
            return Err(BoundSignatureError::PublicKeyCommitmentMismatch {
                expected: key.pub_key_commitment(),
                actual,
            });
        }

        Ok(Self { key, signature })
    }

    /// Returns the key this signature is bound to.
    pub fn key(&self) -> SignatureKey {
        self.key
    }

    /// Returns the signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Converts this signature to a sequence of field elements in the format expected by the
    /// native verification procedure in the VM.
    ///
    /// The returned vector contains at most [`Signature::MAX_NUM_ENCODED_SIGNATURE_FELTS`]
    /// elements.
    pub fn to_encoded_signature(&self) -> Vec<Felt> {
        match &self.signature {
            Signature::Falcon512Eidos(sig) => {
                miden_core_lib::dsa::falcon512_eidos::encode_signature(sig.public_key(), sig)
            },
            Signature::EcdsaK256Keccak(sig) => {
                let pub_key = ecdsa_k256_keccak::PublicKey::recover_from(self.key.message(), sig)
                    .expect("constructor should have checked that the public key is recoverable");
                miden_core_lib::dsa::ecdsa_k256_keccak::encode_signature(&pub_key, sig)
            },
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rstest::rstest;

    use super::*;

    /// The encoding of every [`Signature`] variant must fit within
    /// [`Signature::MAX_NUM_ENCODED_SIGNATURE_FELTS`], which consumers rely on to bound the
    /// untrusted encoded signatures they accept.
    #[rstest]
    #[case::falcon512_eidos(AuthScheme::Falcon512Eidos, 2058)]
    #[case::ecdsa_k256_keccak(AuthScheme::EcdsaK256Keccak, 32)]
    fn encoded_signature_does_not_exceed_max_num_felts(
        #[case] auth_scheme: AuthScheme,
        #[case] expected_num_felts: usize,
    ) -> anyhow::Result<()> {
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        let secret_key = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng)?;
        let message = Word::from([1u32, 2, 3, 4]);
        let key = SignatureKey::new(secret_key.public_key().to_commitment(), message);
        let signature = BoundSignature::new(key, secret_key.sign(message))?;

        let encoded_signature = signature.to_encoded_signature();
        assert_eq!(encoded_signature.len(), expected_num_felts);
        assert!(encoded_signature.len() <= Signature::MAX_NUM_ENCODED_SIGNATURE_FELTS);

        // Match exhaustively on `Signature` so adding a variant breaks compilation as a reminder
        // to add a case above and to re-check the maximum.
        match signature.signature() {
            Signature::Falcon512Eidos(_) | Signature::EcdsaK256Keccak(_) => {},
        }

        Ok(())
    }

    /// An ECDSA signature from which no public key can be recovered cannot be bound.
    #[test]
    fn binding_unrecoverable_ecdsa_signature_fails() -> anyhow::Result<()> {
        let ecdsa_signature =
            ecdsa_k256_keccak::Signature::from_sec1_bytes_and_recovery_id([0; 64], 0)?;
        let key = SignatureKey::new(
            PublicKeyCommitment::from(Word::empty()),
            Word::from([1u32, 2, 3, 4]),
        );

        assert_matches!(
            BoundSignature::new(key, Signature::EcdsaK256Keccak(ecdsa_signature)),
            Err(BoundSignatureError::EcdsaPublicKeyRecoveryFailed { .. })
        );

        Ok(())
    }

    /// A signature cannot be bound to a key with the commitment of a different public key.
    #[rstest]
    #[case::falcon512_eidos(AuthScheme::Falcon512Eidos)]
    #[case::ecdsa_k256_keccak(AuthScheme::EcdsaK256Keccak)]
    fn binding_signature_to_other_pub_key_commitment_fails(
        #[case] auth_scheme: AuthScheme,
    ) -> anyhow::Result<()> {
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        let secret_key = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng)?;
        let message = Word::from([1u32, 2, 3, 4]);
        let other_commitment = PublicKeyCommitment::from(Word::from([5u32, 6, 7, 8]));
        let key = SignatureKey::new(other_commitment, message);

        assert_matches!(
            BoundSignature::new(key, secret_key.sign(message)),
            Err(BoundSignatureError::PublicKeyCommitmentMismatch { expected, actual })
                if expected == other_commitment
                    && actual == secret_key.public_key().to_commitment()
        );

        Ok(())
    }
}
