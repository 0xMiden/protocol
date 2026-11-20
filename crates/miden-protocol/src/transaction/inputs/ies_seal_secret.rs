use core::fmt;

use crate::crypto::ecdh::ecgfp5::{AgreementAdvice, PublicKey, SecretKey};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// IES SEAL SECRET
// ================================================================================================

/// The ephemeral secret a transaction host drew to encrypt to a recipient with the EcGFp5/Eidos
/// integrated encryption scheme.
///
/// Replaying the same secret for the same `seal` request reproduces the same envelope, which
/// re-execution and proving rely on. Anyone holding the transaction inputs can decrypt the
/// envelope, so the secret is as sensitive as the plaintext. It must only be replayed into the
/// transaction it was drawn for: using it for a different plaintext reuses the encryption key and
/// nonce.
pub struct IesSealSecret {
    recipient: PublicKey,
    ephemeral_secret: SecretKey,
}

impl IesSealSecret {
    /// Returns a new [`IesSealSecret`] binding `ephemeral_secret` to `recipient`.
    pub fn new(recipient: PublicKey, ephemeral_secret: SecretKey) -> Self {
        Self { recipient, ephemeral_secret }
    }

    /// Returns the public key of the recipient.
    pub fn recipient(&self) -> PublicKey {
        self.recipient
    }

    /// Returns the ephemeral secret key.
    pub fn ephemeral_secret(&self) -> &SecretKey {
        &self.ephemeral_secret
    }

    /// Returns the key agreement advice for encrypting to the recipient with this secret.
    pub fn advise(&self) -> AgreementAdvice {
        self.recipient.advise(&self.ephemeral_secret)
    }
}

impl Clone for IesSealSecret {
    fn clone(&self) -> Self {
        let ephemeral_secret = SecretKey::from_bytes(&self.ephemeral_secret.to_bytes())
            .expect("the encoding of a secret key should decode to that key");
        Self::new(self.recipient, ephemeral_secret)
    }
}

impl PartialEq for IesSealSecret {
    fn eq(&self, other: &Self) -> bool {
        self.recipient == other.recipient
            && *self.ephemeral_secret.to_bytes() == *other.ephemeral_secret.to_bytes()
    }
}

impl Eq for IesSealSecret {}

impl fmt::Debug for IesSealSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IesSealSecret")
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

impl Serializable for IesSealSecret {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.recipient.write_into(target);
        self.ephemeral_secret.write_into(target);
    }
}

impl Deserializable for IesSealSecret {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let recipient = PublicKey::read_from(source)?;
        let ephemeral_secret = SecretKey::read_from(source)?;

        Ok(Self::new(recipient, ephemeral_secret))
    }
}
