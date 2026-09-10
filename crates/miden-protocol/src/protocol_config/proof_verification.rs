use alloc::string::ToString;
use alloc::vec::Vec;

use super::ProtocolConfigError;
use crate::crypto::SequentialCommit;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Word, ZERO};

// PROOF VERIFICATION CONFIG
// ================================================================================================

/// The parameters that define which proofs the protocol accepts.
///
/// The verifier roots implicitly define which versions of the VM can be used to produce a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofVerificationConfig {
    /// The root of the procedure that verifies proofs produced by the VM. The batch kernel uses it
    /// to verify transaction proofs and the block kernel uses it to verify batch proofs.
    vm_verifier_root: Word,

    /// The root of the procedure that verifies precompile VM proofs.
    precompile_verifier_root: Word,

    /// The policy deciding whether a given proof is secure enough to be accepted.
    security_policy: ProofSecurityPolicy,
}

impl ProofVerificationConfig {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`ProofVerificationConfig`] from the provided inputs.
    pub fn new(
        vm_verifier_root: Word,
        precompile_verifier_root: Word,
        security_policy: ProofSecurityPolicy,
    ) -> Self {
        Self {
            vm_verifier_root,
            precompile_verifier_root,
            security_policy,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the VM proof verification procedure.
    pub fn vm_verifier_root(&self) -> Word {
        self.vm_verifier_root
    }

    /// Returns the root of the precompile proof verification procedure.
    pub fn precompile_verifier_root(&self) -> Word {
        self.precompile_verifier_root
    }

    /// Returns the [`ProofSecurityPolicy`] of this configuration.
    pub fn security_policy(&self) -> &ProofSecurityPolicy {
        &self.security_policy
    }

    /// Returns a commitment to this configuration.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Returns the preimage of [`ProofVerificationConfig::to_commitment`] as a sequence of field
    /// elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }
}

impl SequentialCommit for ProofVerificationConfig {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        [
            self.vm_verifier_root.as_elements(),
            self.precompile_verifier_root.as_elements(),
            &self.security_policy.to_elements(),
        ]
        .concat()
    }
}

impl Serializable for ProofVerificationConfig {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self {
            vm_verifier_root,
            precompile_verifier_root,
            security_policy,
        } = self;

        vm_verifier_root.write_into(target);
        precompile_verifier_root.write_into(target);
        security_policy.write_into(target);
    }
}

impl Deserializable for ProofVerificationConfig {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let vm_verifier_root = source.read()?;
        let precompile_verifier_root = source.read()?;
        let security_policy = source.read()?;

        Ok(Self::new(vm_verifier_root, precompile_verifier_root, security_policy))
    }
}

// PROOF SECURITY POLICY
// ================================================================================================

/// The policy that decides whether a proof is secure enough for the protocol to accept it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofSecurityPolicy {
    /// The root of the procedure which computes the security level of a proof in bits from its
    /// proof parameters.
    security_estimator_root: Word,

    /// The minimum security in bits that a proof must reach to be accepted.
    minimum_bits: u8,
}

impl ProofSecurityPolicy {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`ProofSecurityPolicy`] from the provided inputs.
    ///
    /// # Errors
    ///
    /// Returns an error if `minimum_bits` is zero.
    pub fn new(
        security_estimator_root: Word,
        minimum_bits: u8,
    ) -> Result<Self, ProtocolConfigError> {
        if minimum_bits == 0 {
            return Err(ProtocolConfigError::MinimumSecurityBitsMustBeNonZero);
        }

        Ok(Self { security_estimator_root, minimum_bits })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the proof security estimator procedure.
    pub fn security_estimator_root(&self) -> Word {
        self.security_estimator_root
    }

    /// Returns the minimum security in bits that a proof must reach to be accepted.
    pub fn minimum_bits(&self) -> u8 {
        self.minimum_bits
    }

    /// Returns this policy as a sequence of field elements, contributed to the preimage of
    /// [`ProofVerificationConfig::to_commitment`].
    pub fn to_elements(&self) -> Vec<Felt> {
        [
            self.security_estimator_root.as_elements(),
            &[Felt::from(self.minimum_bits), ZERO, ZERO, ZERO],
        ]
        .concat()
    }
}

impl Serializable for ProofSecurityPolicy {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { security_estimator_root, minimum_bits } = self;

        security_estimator_root.write_into(target);
        minimum_bits.write_into(target);
    }
}

impl Deserializable for ProofSecurityPolicy {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let security_estimator_root = source.read()?;
        let minimum_bits = source.read()?;

        Self::new(security_estimator_root, minimum_bits)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_crypto::rand::test_utils::rand_value;

    use super::*;

    fn config() -> ProofVerificationConfig {
        let policy = ProofSecurityPolicy::new(rand_value::<Word>(), 96).unwrap();
        ProofVerificationConfig::new(rand_value::<Word>(), rand_value::<Word>(), policy)
    }

    #[test]
    fn to_elements_is_pipeable() {
        // The kernel pipes the protocol config into memory, which requires the element count of
        // every nested preimage to be a multiple of the hasher's rate width.
        assert_eq!(config().to_elements().len(), 16);
    }

    #[test]
    fn new_rejects_zero_minimum_bits() {
        let error = ProofSecurityPolicy::new(Word::empty(), 0).unwrap_err();
        assert_matches!(error, ProtocolConfigError::MinimumSecurityBitsMustBeNonZero);
    }

    #[test]
    fn serde_round_trip() -> anyhow::Result<()> {
        let config = config();

        let deserialized = ProofVerificationConfig::read_from_bytes(&config.to_bytes())?;
        assert_eq!(config, deserialized);

        Ok(())
    }
}
