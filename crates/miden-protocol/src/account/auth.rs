use alloc::borrow::ToOwned;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::str::FromStr;

use rand::{CryptoRng, Rng};

use crate::crypto::dsa::{ecdsa_k256_keccak, falcon512_poseidon2};
use crate::errors::AuthSchemeError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Word};

// AUTH SCHEME
// ================================================================================================

/// Identifier of signature schemes use for transaction authentication
const FALCON512_POSEIDON2: u8 = 2;
const ECDSA_K256_KECCAK: u8 = 1;

const FALCON512_POSEIDON2_STR: &str = "Falcon512Poseidon2";
const ECDSA_K256_KECCAK_STR: &str = "EcdsaK256Keccak";

/// Defines standard authentication schemes (i.e., signature schemes) available in the Miden
/// protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum AuthScheme {
    /// A deterministic Falcon512 signature scheme.
    ///
    /// This version differs from the reference Falcon512 implementation in its use of the poseidon2
    /// hash function in its hash-to-point algorithm to make signatures very efficient to verify
    /// inside Miden VM.
    Falcon512Poseidon2 = FALCON512_POSEIDON2,

    /// ECDSA signature scheme over secp256k1 curve using Keccak to hash the messages when signing.
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
            Self::Falcon512Poseidon2 => f.write_str(FALCON512_POSEIDON2_STR),
            Self::EcdsaK256Keccak => f.write_str(ECDSA_K256_KECCAK_STR),
        }
    }
}

impl TryFrom<u8> for AuthScheme {
    type Error = AuthSchemeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            FALCON512_POSEIDON2 => Ok(Self::Falcon512Poseidon2),
            ECDSA_K256_KECCAK => Ok(Self::EcdsaK256Keccak),
            value => Err(AuthSchemeError::InvalidAuthSchemeIdentifier(value.to_string())),
        }
    }
}

impl FromStr for AuthScheme {
    type Err = AuthSchemeError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            FALCON512_POSEIDON2_STR => Ok(AuthScheme::Falcon512Poseidon2),
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
            FALCON512_POSEIDON2 => Ok(Self::Falcon512Poseidon2),
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
    Falcon512Poseidon2(falcon512_poseidon2::SecretKey) = FALCON512_POSEIDON2,
    EcdsaK256Keccak(ecdsa_k256_keccak::SecretKey) = ECDSA_K256_KECCAK,
}

impl AuthSecretKey {
    /// Generates an Falcon512Poseidon2 secret key from the OS-provided randomness.
    #[cfg(feature = "std")]
    pub fn new_falcon512_poseidon2() -> Self {
        Self::Falcon512Poseidon2(falcon512_poseidon2::SecretKey::new())
    }

    /// Generates an Falcon512Poseidon2 secrete key using the provided random number generator.
    pub fn new_falcon512_poseidon2_with_rng<R: Rng>(rng: &mut R) -> Self {
        Self::Falcon512Poseidon2(falcon512_poseidon2::SecretKey::with_rng(rng))
    }

    /// Generates an EcdsaK256Keccak secret key from the OS-provided randomness.
    #[cfg(feature = "std")]
    pub fn new_ecdsa_k256_keccak() -> Self {
        Self::EcdsaK256Keccak(ecdsa_k256_keccak::SecretKey::new())
    }

    /// Generates an EcdsaK256Keccak secret key using the provided random number generator.
    pub fn new_ecdsa_k256_keccak_with_rng<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::EcdsaK256Keccak(ecdsa_k256_keccak::SecretKey::with_rng(rng))
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
            AuthScheme::Falcon512Poseidon2 => Ok(Self::new_falcon512_poseidon2_with_rng(rng)),
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
            AuthScheme::Falcon512Poseidon2 => Ok(Self::new_falcon512_poseidon2()),
            AuthScheme::EcdsaK256Keccak => Ok(Self::new_ecdsa_k256_keccak()),
        }
    }

    /// Returns the authentication scheme of this secret key.
    pub fn auth_scheme(&self) -> AuthScheme {
        match self {
            AuthSecretKey::Falcon512Poseidon2(_) => AuthScheme::Falcon512Poseidon2,
            AuthSecretKey::EcdsaK256Keccak(_) => AuthScheme::EcdsaK256Keccak,
        }
    }

    /// Returns a public key associated with this secret key.
    pub fn public_key(&self) -> PublicKey {
        match self {
            AuthSecretKey::Falcon512Poseidon2(key) => {
                PublicKey::Falcon512Poseidon2(key.public_key())
            },
            AuthSecretKey::EcdsaK256Keccak(key) => PublicKey::EcdsaK256Keccak(key.public_key()),
        }
    }

    /// Signs the provided message with this secret key.
    pub fn sign(&self, message: Word) -> Signature {
        match self {
            AuthSecretKey::Falcon512Poseidon2(key) => {
                Signature::Falcon512Poseidon2(key.sign(message))
            },
            AuthSecretKey::EcdsaK256Keccak(key) => Signature::EcdsaK256Keccak(key.sign(message)),
        }
    }
}

impl Serializable for AuthSecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.auth_scheme().write_into(target);
        match self {
            AuthSecretKey::Falcon512Poseidon2(key) => key.write_into(target),
            AuthSecretKey::EcdsaK256Keccak(key) => key.write_into(target),
        }
    }
}

impl Deserializable for AuthSecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read::<AuthScheme>()? {
            AuthScheme::Falcon512Poseidon2 => {
                let secret_key = falcon512_poseidon2::SecretKey::read_from(source)?;
                Ok(AuthSecretKey::Falcon512Poseidon2(secret_key))
            },
            AuthScheme::EcdsaK256Keccak => {
                let secret_key = ecdsa_k256_keccak::SecretKey::read_from(source)?;
                Ok(AuthSecretKey::EcdsaK256Keccak(secret_key))
            },
        }
    }
}

// PUBLIC KEY
// ================================================================================================

/// Commitment to a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicKeyCommitment(Word);

impl core::fmt::Display for PublicKeyCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<falcon512_poseidon2::PublicKey> for PublicKeyCommitment {
    fn from(value: falcon512_poseidon2::PublicKey) -> Self {
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

/// Public keys of the standard authentication schemes available in the Miden protocol.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum PublicKey {
    Falcon512Poseidon2(falcon512_poseidon2::PublicKey),
    EcdsaK256Keccak(ecdsa_k256_keccak::PublicKey),
}

impl PublicKey {
    /// Returns the authentication scheme of this public key.
    pub fn auth_scheme(&self) -> AuthScheme {
        match self {
            PublicKey::Falcon512Poseidon2(_) => AuthScheme::Falcon512Poseidon2,
            PublicKey::EcdsaK256Keccak(_) => AuthScheme::EcdsaK256Keccak,
        }
    }

    /// Returns a commitment to this public key.
    pub fn to_commitment(&self) -> PublicKeyCommitment {
        match self {
            PublicKey::Falcon512Poseidon2(key) => key.to_commitment().into(),
            PublicKey::EcdsaK256Keccak(key) => key.to_commitment().into(),
        }
    }

    /// Verifies the provided signature against the provided message and this public key.
    pub fn verify(&self, message: Word, signature: Signature) -> bool {
        match (self, signature) {
            (PublicKey::Falcon512Poseidon2(key), Signature::Falcon512Poseidon2(sig)) => {
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
            PublicKey::Falcon512Poseidon2(pub_key) => pub_key.write_into(target),
            PublicKey::EcdsaK256Keccak(pub_key) => pub_key.write_into(target),
        }
    }
}

impl Deserializable for PublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read::<AuthScheme>()? {
            AuthScheme::Falcon512Poseidon2 => {
                let pub_key = falcon512_poseidon2::PublicKey::read_from(source)?;
                Ok(PublicKey::Falcon512Poseidon2(pub_key))
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
/// In order to use this signature within the Miden VM, a preparation step may be necessary to
/// convert the native signature into a vector of field elements that can be loaded into the advice
/// provider. To prepare the signature, use the provided `to_prepared_signature` method:
/// ```rust,no_run
/// use miden_protocol::account::auth::Signature;
/// use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
/// use miden_protocol::{Felt, Word};
///
/// let secret_key = SecretKey::new();
/// let message = Word::default();
/// let signature: Signature = secret_key.sign(message).into();
/// let prepared_signature: Vec<Felt> = signature.to_prepared_signature(message);
/// ```
#[derive(Clone, Debug)]
#[repr(u8)]
pub enum Signature {
    Falcon512Poseidon2(falcon512_poseidon2::Signature) = FALCON512_POSEIDON2,
    EcdsaK256Keccak(ecdsa_k256_keccak::Signature) = ECDSA_K256_KECCAK,
}

impl Signature {
    /// Returns the authentication scheme of this signature.
    pub fn auth_scheme(&self) -> AuthScheme {
        match self {
            Signature::Falcon512Poseidon2(_) => AuthScheme::Falcon512Poseidon2,
            Signature::EcdsaK256Keccak(_) => AuthScheme::EcdsaK256Keccak,
        }
    }

    /// Converts this signature to a sequence of field elements in the format expected by the
    /// native verification procedure in the VM.
    ///
    /// The order of elements in the returned vector is reversed because it is expected that the
    /// data will be pushed into the advice stack
    pub fn to_prepared_signature(&self, msg: Word) -> Vec<Felt> {
        // TODO: the `expect()` should be changed to an error; but that will be a part of a bigger
        // refactoring
        match self {
            Signature::Falcon512Poseidon2(sig) => {
                miden_core_lib::dsa::falcon512_poseidon2::encode_signature(sig.public_key(), sig)
            },
            Signature::EcdsaK256Keccak(sig) => {
                let pk = ecdsa_k256_keccak::PublicKey::recover_from(msg, sig)
                    .expect("inferring public key from signature and message should succeed");
                miden_core_lib::dsa::ecdsa_k256_keccak::encode_signature(&pk, sig)
            },
        }
    }
}

impl From<falcon512_poseidon2::Signature> for Signature {
    fn from(signature: falcon512_poseidon2::Signature) -> Self {
        Signature::Falcon512Poseidon2(signature)
    }
}

impl Serializable for Signature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.auth_scheme().write_into(target);
        match self {
            Signature::Falcon512Poseidon2(signature) => signature.write_into(target),
            Signature::EcdsaK256Keccak(signature) => signature.write_into(target),
        }
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read::<AuthScheme>()? {
            AuthScheme::Falcon512Poseidon2 => {
                let signature = falcon512_poseidon2::Signature::read_from(source)?;
                Ok(Signature::Falcon512Poseidon2(signature))
            },
            AuthScheme::EcdsaK256Keccak => {
                let signature = ecdsa_k256_keccak::Signature::read_from(source)?;
                Ok(Signature::EcdsaK256Keccak(signature))
            },
        }
    }
}
