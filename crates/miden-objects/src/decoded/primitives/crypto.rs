use crate::{Verify, proto};

#[cfg(test)]
mod tests;

/// A canonically deserialized byte payload, with no verification of its application use.
#[derive(Debug)]
pub struct Canonical<T>(T);

impl<T> Canonical<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: miden_protocol::utils::serde::Deserializable + miden_protocol::utils::serde::Serializable>
    TryFrom<alloc::vec::Vec<u8>> for Canonical<T>
{
    type Error = miden_protocol::utils::serde::DeserializationError;
    fn try_from(bytes: alloc::vec::Vec<u8>) -> Result<Self, Self::Error> {
        let value = T::read_from_bytes(&bytes)?;
        if value.to_bytes() != bytes {
            return Err(Self::Error::InvalidValue(alloc::string::String::from(
                "non-canonical encoding or trailing bytes",
            )));
        }
        Ok(Self(value))
    }
}

pub use proto::primitives::DecodedPublicKey as PublicKey;

/// Returns the canonical public key; ownership and authorization are not established here.
impl Verify for PublicKey {
    type Verified = miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let proto::primitives::public_key::DecodedKey::EcdsaK256Keccak(key) = self.key;
        Ok(key.into_inner())
    }
}

pub use proto::primitives::DecodedSignature as Signature;

/// Returns the canonical signature; authenticity requires a public key and signed message.
impl Verify for Signature {
    type Verified = miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let proto::primitives::signature::DecodedSignature::EcdsaK256Keccak(signature) =
            self.signature;
        Ok(signature.into_inner())
    }
}
