use alloc::vec;

use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::asset::AssetId;
use miden_protocol::errors::ProtocolConfigError;
use miden_protocol::protocol_config::KernelConfig;

use crate::decoded::account::test_utils::dummy_account_id;
use crate::decoded::protocol_config::test_utils::dummy_protocol_config;
use crate::test_utils::error_source;
use crate::{ConversionError, DecodeMessage, Verify, proto};

#[test]
fn kernel_verification_is_deferred() {
    let decoded = proto::protocol_config::KernelConfig {
        main_proc: Some(Word::empty().into()),
        kernel_procs: vec![
            Word::empty().into();
            miden_protocol::protocol_config::KernelConfig::MAX_NUM_KERNEL_PROCEDURES
                + 1
        ],
    }
    .decode_fields()
    .unwrap();
    assert!(decoded.verify().is_err());
}

#[test]
fn security_policy_verification_is_deferred() {
    for minimum_bits in [0, u32::MAX] {
        let decoded = proto::protocol_config::ProofSecurityPolicy {
            security_estimator_root: Some(Word::empty().into()),
            minimum_bits,
        }
        .decode_fields()
        .unwrap();
        assert_eq!(decoded.minimum_bits, minimum_bits);
        assert!(decoded.verify().is_err());
    }
}

#[test]
fn proof_verification_config_defers_nested_policy_checks() {
    let decoded = proto::protocol_config::ProofVerificationConfig {
        vm_verifier_root: Some(Word::empty().into()),
        precompile_verifier_root: Some(Word::empty().into()),
        security_policy: Some(proto::protocol_config::ProofSecurityPolicy {
            security_estimator_root: Some(Word::empty().into()),
            minimum_bits: 0,
        }),
    }
    .decode_fields()
    .unwrap();
    assert!(decoded.verify().is_err());
}

#[test]
fn protocol_config_preserves_fee_asset_validation_source() {
    let mut message = proto::protocol_config::ProtocolConfig::from(dummy_protocol_config());
    let non_fungible = AssetId::new(
        miden_protocol::asset::AssetClass::default(),
        dummy_account_id(10),
        miden_protocol::asset::AssetComposition::None,
    )
    .unwrap();
    message.fee_asset_id = Some(Word::from(non_fungible).into());

    let error = message
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<ProtocolConfigError>(&error),
        Some(ProtocolConfigError::FeeAssetMustBeFungible(_))
    );
}

#[test]
fn kernel_config_rejects_oversized_procedure_list() {
    let error = proto::protocol_config::KernelConfig {
        main_proc: Some(Word::empty().into()),
        kernel_procs: vec![Word::empty().into(); KernelConfig::MAX_NUM_KERNEL_PROCEDURES + 1],
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new)
    .unwrap_err();

    assert_matches!(
        error_source::<ProtocolConfigError>(&error),
        Some(ProtocolConfigError::TooManyKernelProcedures { count })
            if *count == KernelConfig::MAX_NUM_KERNEL_PROCEDURES + 1
    );
}

#[test]
fn proof_security_policy_rejects_out_of_range_minimum_bits() {
    let error = proto::protocol_config::ProofSecurityPolicy {
        security_estimator_root: Some(Word::empty().into()),
        minimum_bits: u32::from(u8::MAX) + 1,
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new)
    .unwrap_err();

    assert_matches!(error_source::<core::num::TryFromIntError>(&error), Some(_));
}

#[test]
fn proof_security_policy_preserves_zero_bits_validation_source() {
    let error = proto::protocol_config::ProofSecurityPolicy {
        security_estimator_root: Some(Word::empty().into()),
        minimum_bits: 0,
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new)
    .unwrap_err();

    assert_matches!(
        error_source::<ProtocolConfigError>(&error),
        Some(ProtocolConfigError::MinimumSecurityBitsMustBeNonZero)
    );
}

#[test]
fn protocol_config_decodes_all_fields_before_verification() {
    use crate::{DecodeMessage, Verify};
    let config = dummy_protocol_config();
    let decoded = proto::protocol_config::ProtocolConfig::from(&config).decode_fields().unwrap();
    assert_eq!(decoded.tx_kernel.kernel_procs, config.tx_kernel().kernel_procs());
    assert_eq!(decoded.verify().unwrap(), config);
}
