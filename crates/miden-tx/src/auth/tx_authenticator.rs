use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::FutureMaybeSend;
use miden_protocol::account::auth::{AuthSecretKey, PublicKey, PublicKeyCommitment, Signature};
use miden_protocol::crypto::SequentialCommit;
use miden_protocol::transaction::TransactionSummary;
use miden_protocol::{Felt, Hasher, Word};

use crate::errors::AuthenticationError;
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// SIGNATURE DATA
// ================================================================================================

/// Data types on which a signature can be requested.
///
/// It supports three modes:
/// - `TransactionSummary`: Structured transaction summary, recommended for authenticating
///   transactions.
/// - `Arbitrary`: Arbitrary payload provided by the application. It is up to the authenticator to
///   display it appropriately.
/// - `Blind`: The underlying data is not meant to be displayed in a human-readable format. It must
///   be a cryptographic commitment to some data.
#[derive(Debug, Clone)]
pub enum SigningInputs {
    TransactionSummary(Box<TransactionSummary>),
    Arbitrary(Vec<Felt>),
    Blind(Word),
}

impl SequentialCommit for SigningInputs {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        match self {
            SigningInputs::TransactionSummary(tx_summary) => tx_summary.as_ref().to_elements(),
            SigningInputs::Arbitrary(elements) => elements.clone(),
            SigningInputs::Blind(word) => word.as_elements().to_vec(),
        }
    }

    fn to_commitment(&self) -> Self::Commitment {
        match self {
            // `TransactionSummary` knows how to derive a commitment to itself.
            SigningInputs::TransactionSummary(tx_summary) => tx_summary.as_ref().to_commitment(),
            // use the default implementation.
            SigningInputs::Arbitrary(elements) => Hasher::hash_elements(elements),
            // `Blind` is assumed to already be a commitment.
            SigningInputs::Blind(word) => *word,
        }
    }
}

/// Convenience methods for [SigningInputs].
impl SigningInputs {
    /// Computes the commitment to [SigningInputs].
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Returns a representation of the [SigningInputs] as a sequence of field elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for SigningInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            SigningInputs::TransactionSummary(tx_summary) => {
                target.write_u8(0);
                tx_summary.as_ref().write_into(target);
            },
            SigningInputs::Arbitrary(elements) => {
                target.write_u8(1);
                elements.write_into(target);
            },
            SigningInputs::Blind(word) => {
                target.write_u8(2);
                word.write_into(target);
            },
        }
    }
}

impl Deserializable for SigningInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let discriminant = source.read_u8()?;
        match discriminant {
            0 => {
                let tx_summary: TransactionSummary = source.read()?;
                Ok(SigningInputs::TransactionSummary(Box::new(tx_summary)))
            },
            1 => {
                let elements: Vec<Felt> = source.read()?;
                Ok(SigningInputs::Arbitrary(elements))
            },
            2 => {
                let word: Word = source.read()?;
                Ok(SigningInputs::Blind(word))
            },
            other => Err(DeserializationError::InvalidValue(format!(
                "invalid SigningInputs variant: {other}"
            ))),
        }
    }
}

// TRANSACTION AUTHENTICATOR
// ================================================================================================

/// Defines an authenticator for transactions.
///
/// The main purpose of the authenticator is to generate signatures for a given message against
/// a key managed by the authenticator. That is, the authenticator maintains a set of public-
/// private key pairs, and can be requested to generate signatures against any of the managed keys.
///
/// The public keys are defined by [PublicKeyCommitment]'s which are the hashes of the actual
/// public keys.
pub trait TransactionAuthenticator {
    /// Retrieves a signature for a specific message as a list of [Felt].
    ///
    /// The request is initiated by the VM as a consequence of the SigToStack advice
    /// injector.
    ///
    /// - `pub_key_commitment`: the hash of the public key used for signature generation.
    /// - `signing_inputs`: description of the message to be singed. The inputs could contain
    ///   arbitrary data or a [TransactionSummary] which would describe the changes made to the
    ///   account up to the point of calling `get_signature()`. This allows the authenticator to
    ///   review any alterations to the account prior to signing. It should not be directly used in
    ///   the signature computation.
    fn get_signature(
        &self,
        pub_key_commitment: PublicKeyCommitment,
        signing_inputs: &SigningInputs,
    ) -> impl FutureMaybeSend<Result<Signature, AuthenticationError>>;

    /// Retrieves a public key for a specific public key commitment.
    fn get_public_key(
        &self,
        pub_key_commitment: PublicKeyCommitment,
    ) -> impl FutureMaybeSend<Option<Arc<PublicKey>>>;
}

/// A placeholder type for the generic trait bound of `TransactionAuthenticator<'_,'_,_,T>`
/// when we do not want to provide one, but must provide the `T` in `Option<T>`.
///
/// Note: Asserts when `get_signature` is called.
#[derive(Debug, Clone, Copy)]
pub struct UnreachableAuth {
    // ensure the type cannot be instantiated
    _protect: core::marker::PhantomData<u8>,
}

impl TransactionAuthenticator for UnreachableAuth {
    #[allow(clippy::manual_async_fn)]
    fn get_signature(
        &self,
        _pub_key_commitment: PublicKeyCommitment,
        _signing_inputs: &SigningInputs,
    ) -> impl FutureMaybeSend<Result<Signature, AuthenticationError>> {
        async { unreachable!("Type `UnreachableAuth` must not be instantiated") }
    }

    fn get_public_key(
        &self,
        _pub_key_commitment: PublicKeyCommitment,
    ) -> impl FutureMaybeSend<Option<Arc<PublicKey>>> {
        async { unreachable!("Type `UnreachableAuth` must not be instantiated") }
    }
}

// BASIC AUTHENTICATOR
// ================================================================================================

/// Represents a signer for [AuthSecretKey] keys.
#[derive(Clone, Debug)]
pub struct BasicAuthenticator {
    /// pub_key |-> (secret_key, public_key) mapping
    keys: BTreeMap<PublicKeyCommitment, (AuthSecretKey, Arc<PublicKey>)>,
}

impl BasicAuthenticator {
    pub fn new(keys: &[AuthSecretKey]) -> Self {
        let mut key_map = BTreeMap::new();
        for secret_key in keys {
            let pub_key = secret_key.public_key();
            key_map.insert(pub_key.to_commitment(), (secret_key.clone(), pub_key.into()));
        }

        BasicAuthenticator { keys: key_map }
    }

    pub fn from_key_pairs(keys: &[(AuthSecretKey, PublicKey)]) -> Self {
        let mut key_map = BTreeMap::new();
        for (secret_key, public_key) in keys {
            key_map.insert(
                public_key.to_commitment(),
                (secret_key.clone(), public_key.clone().into()),
            );
        }

        BasicAuthenticator { keys: key_map }
    }

    /// Returns a reference to the keys map.
    ///
    /// Map keys represent the public key commitments, and values represent the (secret_key,
    /// public_key) pair that the authenticator would use to sign messages.
    pub fn keys(&self) -> &BTreeMap<PublicKeyCommitment, (AuthSecretKey, Arc<PublicKey>)> {
        &self.keys
    }
}

impl TransactionAuthenticator for BasicAuthenticator {
    /// Gets a signature over a message, given a public key commitment.
    ///
    /// The key should be included in the `keys` map and should be a variant of [AuthSecretKey].
    ///
    /// # Errors
    /// If the public key is not contained in the `keys` map,
    /// [`AuthenticationError::UnknownPublicKey`] is returned.
    fn get_signature(
        &self,
        pub_key_commitment: PublicKeyCommitment,
        signing_inputs: &SigningInputs,
    ) -> impl FutureMaybeSend<Result<Signature, AuthenticationError>> {
        let message = signing_inputs.to_commitment();

        async move {
            match self.keys.get(&pub_key_commitment) {
                Some((auth_key, _)) => Ok(auth_key.sign(message)),
                None => Err(AuthenticationError::UnknownPublicKey(pub_key_commitment)),
            }
        }
    }

    /// Returns the public key associated with the given public key commitment.
    ///
    /// If the public key commitment is not contained in the `keys` map, `None` is returned.
    fn get_public_key(
        &self,
        pub_key_commitment: PublicKeyCommitment,
    ) -> impl FutureMaybeSend<Option<Arc<PublicKey>>> {
        async move { self.keys.get(&pub_key_commitment).map(|(_, pub_key)| pub_key.clone()) }
    }
}

// EMPTY AUTHENTICATOR
// ================================================================================================

impl TransactionAuthenticator for () {
    #[allow(clippy::manual_async_fn)]
    fn get_signature(
        &self,
        _pub_key_commitment: PublicKeyCommitment,
        _signing_inputs: &SigningInputs,
    ) -> impl FutureMaybeSend<Result<Signature, AuthenticationError>> {
        async {
            Err(AuthenticationError::RejectedSignature(
                "default authenticator cannot provide signatures".to_string(),
            ))
        }
    }

    fn get_public_key(
        &self,
        _pub_key_commitment: PublicKeyCommitment,
    ) -> impl FutureMaybeSend<Option<Arc<PublicKey>>> {
        async { None }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use miden_protocol::account::auth::AuthSecretKey;
    use miden_protocol::utils::{Deserializable, Serializable};
    use miden_protocol::{Felt, Word};

    use super::SigningInputs;

    #[test]
    fn serialize_auth_key() {
        let auth_key = AuthSecretKey::new_falcon512_rpo();
        let serialized = auth_key.to_bytes();
        let deserialized = AuthSecretKey::read_from_bytes(&serialized).unwrap();

        assert_eq!(auth_key, deserialized);
    }

    #[test]
    fn serialize_deserialize_signing_inputs_arbitrary() {
        let elements = vec![
            Felt::new(0),
            Felt::new(1),
            Felt::new(2),
            Felt::new(3),
            Felt::new(4),
            Felt::new(5),
            Felt::new(6),
            Felt::new(7),
        ];
        let inputs = SigningInputs::Arbitrary(elements.clone());
        let bytes = inputs.to_bytes();
        let decoded = SigningInputs::read_from_bytes(&bytes).unwrap();

        match decoded {
            SigningInputs::Arbitrary(decoded_elements) => {
                assert_eq!(decoded_elements, elements);
            },
            _ => panic!("expected Arbitrary variant"),
        }
    }

    #[test]
    fn serialize_deserialize_signing_inputs_blind() {
        let word = Word::from([Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]);
        let inputs = SigningInputs::Blind(word);
        let bytes = inputs.to_bytes();
        let decoded = SigningInputs::read_from_bytes(&bytes).unwrap();

        match decoded {
            SigningInputs::Blind(w) => {
                assert_eq!(w, word);
            },
            _ => panic!("expected Blind variant"),
        }
    }
}
