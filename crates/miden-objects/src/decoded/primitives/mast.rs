use crate::{Verify, proto};

#[cfg(test)]
mod tests;

/// A parsed MAST payload whose structure and node hashes have not yet been verified.
#[derive(Debug)]
pub struct UntrustedMastForest(miden_protocol::assembly::mast::UntrustedMastForest);

impl TryFrom<alloc::vec::Vec<u8>> for UntrustedMastForest {
    type Error = miden_protocol::utils::serde::DeserializationError;

    fn try_from(bytes: alloc::vec::Vec<u8>) -> Result<Self, Self::Error> {
        miden_protocol::assembly::mast::UntrustedMastForest::read_from_bytes(&bytes).map(Self)
    }
}

pub use proto::primitives::DecodedMastForest as MastForest;

impl Verify for MastForest {
    type Verified = miden_protocol::MastForest;
    type Error = miden_protocol::assembly::mast::MastForestError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        self.encoded.0.validate()
    }
}
