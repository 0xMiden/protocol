use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

/// Represents a proof of a block in the chain.
///
/// NOTE: Block proving is not yet implemented. This is a placeholder struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockProof {}

impl BlockProof {
    /// Creates a dummy `BlockProof` for testing purposes only.
    #[cfg(any(test, feature = "testing"))]
    pub fn new_dummy() -> Self {
        Self {}
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for BlockProof {
    fn write_into<W: ByteWriter>(&self, _target: &mut W) {
        // TODO: Implement serialization for BlockProof when fields exist.
    }
}

impl Deserializable for BlockProof {
    fn read_from<R: ByteReader>(_source: &mut R) -> Result<Self, DeserializationError> {
        // TODO: Implement deserialization for BlockProof when fields exist.
        let block = Self {};

        Ok(block)
    }
}
