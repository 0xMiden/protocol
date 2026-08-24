use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::vm::ExecutionProof;

/// Represents a proof of a block in the chain.
///
/// Currently, this only carries a skeleton proof which does not attest to anything meaningful. See
/// [`BlockKernel`](crate::block::BlockKernel) for the kernel program the proof is generated over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockProof {
    proof: ExecutionProof,
}

impl BlockProof {
    /// Creates a new [`BlockProof`] from the provided execution proof.
    pub fn new(proof: ExecutionProof) -> Self {
        Self { proof }
    }

    /// Returns the execution proof attached to this block.
    pub fn proof(&self) -> &ExecutionProof {
        &self.proof
    }

    /// Creates a dummy `BlockProof` for testing purposes only.
    #[cfg(any(test, feature = "testing"))]
    pub fn new_dummy() -> Self {
        Self::new(ExecutionProof::new_dummy())
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for BlockProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.proof.write_into(target);
    }
}

impl Deserializable for BlockProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self::new(ExecutionProof::read_from(source)?))
    }
}
