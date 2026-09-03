use alloc::format;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::asset::AssetId;
use miden_protocol::protocol_config::{
    KernelConfig,
    ProofSecurityPolicy,
    ProofVerificationConfig,
    ProtocolConfig,
};

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

impl TryFrom<proto::protocol_config::KernelConfig> for KernelConfig {
    type Error = ConversionError;

    fn try_from(message: proto::protocol_config::KernelConfig) -> Result<Self, Self::Error> {
        let decoder = message.decoder();
        let main_proc = required!(decoder, message.main_proc)?;
        let kernel_procs = message
            .kernel_procs
            .into_iter()
            .enumerate()
            .map(|(index, root)| Word::try_from(root).context(format!("kernel_procs[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;

        KernelConfig::new(main_proc, kernel_procs).map_err(ConversionError::new)
    }
}

impl From<&KernelConfig> for proto::protocol_config::KernelConfig {
    fn from(config: &KernelConfig) -> Self {
        Self {
            main_proc: Some(config.main_proc().into()),
            kernel_procs: config.kernel_procs().iter().copied().map(Into::into).collect(),
        }
    }
}

impl From<KernelConfig> for proto::protocol_config::KernelConfig {
    fn from(config: KernelConfig) -> Self {
        (&config).into()
    }
}

impl TryFrom<proto::protocol_config::ProofSecurityPolicy> for ProofSecurityPolicy {
    type Error = ConversionError;

    fn try_from(message: proto::protocol_config::ProofSecurityPolicy) -> Result<Self, Self::Error> {
        let decoder = message.decoder();
        let security_estimator_root = required!(decoder, message.security_estimator_root)?;
        let minimum_bits = u8::try_from(message.minimum_bits).context("minimum_bits")?;

        ProofSecurityPolicy::new(security_estimator_root, minimum_bits)
            .map_err(ConversionError::new)
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

impl TryFrom<proto::protocol_config::ProofVerificationConfig> for ProofVerificationConfig {
    type Error = ConversionError;

    fn try_from(
        message: proto::protocol_config::ProofVerificationConfig,
    ) -> Result<Self, Self::Error> {
        let decoder = message.decoder();
        let vm_verifier_root = required!(decoder, message.vm_verifier_root)?;
        let precompile_verifier_root = required!(decoder, message.precompile_verifier_root)?;
        let security_policy = required!(decoder, message.security_policy)?;

        Ok(ProofVerificationConfig::new(
            vm_verifier_root,
            precompile_verifier_root,
            security_policy,
        ))
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

impl TryFrom<proto::protocol_config::ProtocolConfig> for ProtocolConfig {
    type Error = ConversionError;

    fn try_from(message: proto::protocol_config::ProtocolConfig) -> Result<Self, Self::Error> {
        let decoder = message.decoder();
        let fee_asset_id: Word = required!(decoder, message.fee_asset_id)?;
        let fee_asset_id = AssetId::try_from(fee_asset_id).context("fee_asset_id")?;
        let tx_kernel = required!(decoder, message.tx_kernel)?;
        let batch_kernel = required!(decoder, message.batch_kernel)?;
        let block_kernel = required!(decoder, message.block_kernel)?;
        let proof_verification = required!(decoder, message.proof_verification)?;

        ProtocolConfig::new(fee_asset_id, tx_kernel, batch_kernel, block_kernel, proof_verification)
            .map_err(ConversionError::new)
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
