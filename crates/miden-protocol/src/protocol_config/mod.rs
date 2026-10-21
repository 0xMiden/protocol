use alloc::string::ToString;
use alloc::vec::Vec;

use crate::asset::AssetId;
use crate::batch::BatchKernel;
use crate::constants::MIN_PROOF_SECURITY_LEVEL;
use crate::crypto::SequentialCommit;
use crate::errors::ProtocolConfigError;
use crate::transaction::TransactionKernel;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Word};

mod kernel_config;
pub use kernel_config::KernelConfig;

mod next_protocol_config;
pub use next_protocol_config::NextProtocolConfig;

mod proof_verification;
pub use proof_verification::{ProofSecurityPolicy, ProofVerificationConfig};

// PROTOCOL CONFIG
// ================================================================================================

/// The configuration parameters of the protocol that are expected to change rarely over the
/// lifetime of a chain.
///
/// A [`BlockHeader`](crate::block::BlockHeader) holds only the commitment to this config, so that
/// rarely changing data does not take up space in every block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolConfig {
    /// The ID of the asset that fees are paid in.
    fee_asset_id: AssetId,

    /// The configuration of the transaction kernel.
    tx_kernel: KernelConfig,

    /// The configuration of the batch kernel.
    batch_kernel: KernelConfig,

    /// The configuration of the block kernel.
    block_kernel: KernelConfig,

    /// The parameters defining which proofs the protocol accepts.
    proof_verification: ProofVerificationConfig,
}

impl ProtocolConfig {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The minimum proof security in bits, as a `u8`.
    const MINIMUM_SECURITY_BITS: u8 = {
        assert!(MIN_PROOF_SECURITY_LEVEL <= u8::MAX as u32);
        MIN_PROOF_SECURITY_LEVEL as u8
    };

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`ProtocolConfig`] from the provided inputs.
    ///
    /// # Errors
    ///
    /// Returns an error if `fee_asset_id` is not a fungible asset ID.
    pub fn new(
        fee_asset_id: AssetId,
        tx_kernel: KernelConfig,
        batch_kernel: KernelConfig,
        block_kernel: KernelConfig,
        proof_verification: ProofVerificationConfig,
    ) -> Result<Self, ProtocolConfigError> {
        if !fee_asset_id.composition().is_fungible() {
            return Err(ProtocolConfigError::FeeAssetMustBeFungible(fee_asset_id.composition()));
        }

        Ok(Self {
            fee_asset_id,
            tx_kernel,
            batch_kernel,
            block_kernel,
            proof_verification,
        })
    }

    /// Creates the [`ProtocolConfig`] described by the currently linked kernels.
    ///
    /// TODO(#3644): The batch kernel, the block kernel and the proof verification roots are
    /// placeholders until those parts of the protocol exist.
    ///
    /// # Errors
    ///
    /// Returns an error if `fee_asset_id` is not a fungible asset ID.
    pub fn current(fee_asset_id: AssetId) -> Result<Self, ProtocolConfigError> {
        let tx_kernel = KernelConfig::new(
            TransactionKernel::main().hash(),
            TransactionKernel::PROCEDURES.to_vec(),
        )?;
        let batch_kernel = KernelConfig::new(BatchKernel::main().hash(), Vec::new())?;
        let block_kernel = KernelConfig::new(Word::empty(), Vec::new())?;

        // Placeholders.
        let security_policy = ProofSecurityPolicy::new(Word::empty(), Self::MINIMUM_SECURITY_BITS)?;
        let proof_verification =
            ProofVerificationConfig::new(Word::empty(), Word::empty(), security_policy);

        Self::new(fee_asset_id, tx_kernel, batch_kernel, block_kernel, proof_verification)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the ID of the asset that fees are paid in.
    pub fn fee_asset_id(&self) -> AssetId {
        self.fee_asset_id
    }

    /// Returns the configuration of the transaction kernel.
    pub fn tx_kernel(&self) -> &KernelConfig {
        &self.tx_kernel
    }

    /// Returns the configuration of the batch kernel.
    pub fn batch_kernel(&self) -> &KernelConfig {
        &self.batch_kernel
    }

    /// Returns the configuration of the block kernel.
    pub fn block_kernel(&self) -> &KernelConfig {
        &self.block_kernel
    }

    /// Returns the parameters defining which proofs the protocol accepts.
    pub fn proof_verification(&self) -> &ProofVerificationConfig {
        &self.proof_verification
    }

    /// Returns the commitment to this configuration, which is what a block header commits to.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Returns the preimage of [`ProtocolConfig::to_commitment`] as a sequence of field elements.
    ///
    /// The element layout is:
    ///
    /// ```text
    /// [
    ///     FEE_ASSET_ID,
    ///     TX_KERNEL_CONFIG_COMMITMENT,
    ///     BATCH_KERNEL_CONFIG_COMMITMENT,
    ///     BLOCK_KERNEL_CONFIG_COMMITMENT,
    ///     PROOF_VERIFICATION_CONFIG_COMMITMENT,
    ///     EMPTY_WORD,
    /// ]
    /// ```
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }
}

impl SequentialCommit for ProtocolConfig {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        let fee_asset_id = self.fee_asset_id.to_word();
        let tx_kernel = self.tx_kernel.to_commitment();
        let batch_kernel = self.batch_kernel.to_commitment();
        let block_kernel = self.block_kernel.to_commitment();
        let proof_verification = self.proof_verification.to_commitment();

        [
            fee_asset_id.as_elements(),
            tx_kernel.as_elements(),
            batch_kernel.as_elements(),
            block_kernel.as_elements(),
            proof_verification.as_elements(),
            Word::empty().as_elements(),
        ]
        .concat()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for ProtocolConfig {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self {
            fee_asset_id,
            tx_kernel,
            batch_kernel,
            block_kernel,
            proof_verification,
        } = self;

        fee_asset_id.write_into(target);
        tx_kernel.write_into(target);
        batch_kernel.write_into(target);
        block_kernel.write_into(target);
        proof_verification.write_into(target);
    }
}

impl Deserializable for ProtocolConfig {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let fee_asset_id = source.read()?;
        let tx_kernel = source.read()?;
        let batch_kernel = source.read()?;
        let block_kernel = source.read()?;
        let proof_verification = source.read()?;

        Self::new(fee_asset_id, tx_kernel, batch_kernel, block_kernel, proof_verification)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::account::AccountId;
    use crate::asset::{AssetClass, AssetComposition};
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    };

    fn fee_asset_id() -> AssetId {
        let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("test faucet ID should be valid");
        AssetId::new_fungible(faucet_id)
    }

    #[test]
    fn to_elements_is_pipeable() {
        // The kernel pipes the preimage into memory, which requires the element count to be a
        // multiple of the hasher's rate width.
        let config = ProtocolConfig::current(fee_asset_id()).unwrap();

        assert_eq!(config.to_elements().len(), 24);
    }

    #[test]
    fn current_commits_to_the_linked_tx_kernel() {
        let config = ProtocolConfig::current(fee_asset_id()).unwrap();

        assert_eq!(config.tx_kernel().main_proc(), TransactionKernel::main().hash());
        assert_eq!(config.tx_kernel().kernel_procs(), TransactionKernel::PROCEDURES);
    }

    #[test]
    fn new_rejects_non_fungible_fee_asset() {
        let faucet_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET)
            .expect("test faucet ID should be valid");
        let fee_asset_id =
            AssetId::new(AssetClass::default(), faucet_id, AssetComposition::None).unwrap();

        let error = ProtocolConfig::new(
            fee_asset_id,
            KernelConfig::dummy(),
            KernelConfig::dummy(),
            KernelConfig::dummy(),
            ProofVerificationConfig::new(
                Word::empty(),
                Word::empty(),
                ProofSecurityPolicy::new(Word::empty(), 96).unwrap(),
            ),
        )
        .unwrap_err();

        assert_matches!(error, ProtocolConfigError::FeeAssetMustBeFungible(AssetComposition::None));
    }

    #[test]
    fn serde_round_trip() -> anyhow::Result<()> {
        let config = ProtocolConfig::current(fee_asset_id())?;

        let deserialized = ProtocolConfig::read_from_bytes(&config.to_bytes())
            .map_err(|err| anyhow::anyhow!("{err}"))?;

        assert_eq!(config, deserialized);
        Ok(())
    }
}
