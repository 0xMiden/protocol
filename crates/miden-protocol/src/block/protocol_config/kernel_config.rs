use alloc::string::ToString;
use alloc::vec::Vec;

use miden_verifier::KernelDescriptor;

use super::ProtocolConfigError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word};

// KERNEL CONFIG
// ================================================================================================

/// The configuration of one of the protocol's kernels.
///
/// A kernel is identified by the root of its executable procedure together with the set of
/// procedures it exposes through its API. Both are needed by other kernels: the batch kernel
/// verifies transaction proofs against the transaction kernel's `main_proc`, while the exposed
/// procedure roots are what users may invoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelConfig {
    /// The root of the executable kernel procedure.
    main_proc: Word,

    /// The roots of the procedures exposed by the kernel API.
    kernel_procs: Vec<Word>,
}

impl KernelConfig {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of procedures that can be exported from a kernel.
    pub const MAX_NUM_KERNEL_PROCEDURES: usize = KernelDescriptor::MAX_NUM_PROCEDURES;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`KernelConfig`] from the provided inputs.
    ///
    /// # Errors
    ///
    /// Returns an error if `kernel_procs` contains more than
    /// [`Self::MAX_NUM_KERNEL_PROCEDURES`] procedure roots.
    pub fn new(main_proc: Word, kernel_procs: Vec<Word>) -> Result<Self, ProtocolConfigError> {
        if kernel_procs.len() > Self::MAX_NUM_KERNEL_PROCEDURES {
            return Err(ProtocolConfigError::TooManyKernelProcedures { count: kernel_procs.len() });
        }

        Ok(Self { main_proc, kernel_procs })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the executable kernel procedure.
    pub fn main_proc(&self) -> Word {
        self.main_proc
    }

    /// Returns the roots of the procedures exposed by the kernel API.
    pub fn kernel_procs(&self) -> &[Word] {
        &self.kernel_procs
    }

    /// Returns the roots of the procedures exposed by the kernel API.
    pub fn num_kernel_procs(&self) -> u8 {
        u8::try_from(self.kernel_procs.len())
            .expect("constructor should validate num procs fits in u8")
    }

    /// Returns the sequential hash of the exposed kernel procedure roots.
    pub fn kernel_procs_elements(&self) -> &[Felt] {
        Word::words_as_elements(&self.kernel_procs)
    }

    /// Returns the sequential hash of the exposed kernel procedure roots.
    pub fn kernel_procs_commitment(&self) -> Word {
        Hasher::hash_elements(self.kernel_procs_elements())
    }

    /// Returns a commitment to this kernel configuration.
    pub fn to_commitment(&self) -> Word {
        Hasher::merge(&[self.main_proc, self.kernel_procs_commitment()])
    }

    /// Returns the preimage of [`KernelConfig::to_commitment`] as a sequence of field elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        let kernel_procs_commitment = self.kernel_procs_commitment();
        [self.main_proc.as_elements(), kernel_procs_commitment.as_elements()].concat()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for KernelConfig {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let num_kernel_procs = self.num_kernel_procs();
        let Self { main_proc, kernel_procs } = self;

        main_proc.write_into(target);
        num_kernel_procs.write_into(target);
        target.write_many(kernel_procs);
    }
}

impl Deserializable for KernelConfig {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let main_proc = source.read()?;
        let num_kernel_procs: u8 = source.read()?;
        let kernel_procs = source
            .read_many_iter(num_kernel_procs as usize)?
            .collect::<Result<Vec<Word>, _>>()?;

        Self::new(main_proc, kernel_procs)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use assert_matches::assert_matches;
    use miden_crypto::rand::test_utils::rand_value;

    use super::*;

    #[test]
    fn new_rejects_too_many_procedures() {
        let procs = vec![Word::empty(); KernelConfig::MAX_NUM_KERNEL_PROCEDURES + 1];

        let error = KernelConfig::new(Word::empty(), procs).unwrap_err();
        assert_matches!(error, ProtocolConfigError::TooManyKernelProcedures { count } => {
            assert_eq!(count, KernelConfig::MAX_NUM_KERNEL_PROCEDURES + 1);
        });
    }

    #[test]
    fn serde_round_trip() -> anyhow::Result<()> {
        let config = KernelConfig::new(rand_value::<Word>(), vec![rand_value::<Word>(); 3])?;

        let deserialized = KernelConfig::read_from_bytes(&config.to_bytes())?;
        assert_eq!(config, deserialized);

        Ok(())
    }
}
