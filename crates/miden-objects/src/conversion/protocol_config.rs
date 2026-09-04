use miden_protocol::Word;
use miden_protocol::asset::AssetId;
use miden_protocol::protocol_config::{
    KernelConfig,
    ProofSecurityPolicy,
    ProofVerificationConfig,
    ProtocolConfig,
};

use crate::{ConversionError, proto};

impl From<KernelConfig> for proto::protocol_config::KernelConfig {
    fn from(config: KernelConfig) -> Self {
        (&config).into()
    }
}

impl From<&ProofSecurityPolicy> for proto::protocol_config::ProofSecurityPolicy {
    fn from(policy: &ProofSecurityPolicy) -> Self {
        Self {
            security_estimator_root: Some(policy.security_estimator_root().into()),
            minimum_bits: u32::from(policy.minimum_bits()),
        }
    }
}

impl From<ProofSecurityPolicy> for proto::protocol_config::ProofSecurityPolicy {
    fn from(policy: ProofSecurityPolicy) -> Self {
        (&policy).into()
    }
}

impl From<&ProofVerificationConfig> for proto::protocol_config::ProofVerificationConfig {
    fn from(config: &ProofVerificationConfig) -> Self {
        Self {
            vm_verifier_root: Some(config.vm_verifier_root().into()),
            precompile_verifier_root: Some(config.precompile_verifier_root().into()),
            security_policy: Some(config.security_policy().into()),
        }
    }
}

impl From<ProofVerificationConfig> for proto::protocol_config::ProofVerificationConfig {
    fn from(config: ProofVerificationConfig) -> Self {
        (&config).into()
    }
}

impl TryFrom<proto::primitives::Word> for AssetId {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Word) -> Result<Self, Self::Error> {
        let word = Word::try_from(value)?;
        Self::try_from(word).map_err(ConversionError::new)
    }
}

impl From<&ProtocolConfig> for proto::protocol_config::ProtocolConfig {
    fn from(config: &ProtocolConfig) -> Self {
        Self {
            fee_asset_id: Some(Word::from(config.fee_asset_id()).into()),
            tx_kernel: Some(config.tx_kernel().into()),
            batch_kernel: Some(config.batch_kernel().into()),
            block_kernel: Some(config.block_kernel().into()),
            proof_verification: Some(config.proof_verification().into()),
        }
    }
}

impl From<ProtocolConfig> for proto::protocol_config::ProtocolConfig {
    fn from(config: ProtocolConfig) -> Self {
        (&config).into()
    }
}
