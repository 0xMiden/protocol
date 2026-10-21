use alloc::vec;

use miden_protocol::Word;
use miden_protocol::asset::AssetId;
use miden_protocol::protocol_config::{
    KernelConfig,
    ProofSecurityPolicy,
    ProofVerificationConfig,
    ProtocolConfig,
};

use crate::decoded::account::test_utils::dummy_account_id;

pub(crate) fn dummy_protocol_config() -> ProtocolConfig {
    ProtocolConfig::new(
        AssetId::new_fungible(dummy_account_id(8)),
        KernelConfig::new(Word::from([1_u32, 0, 0, 0]), vec![Word::from([2_u32, 0, 0, 0])])
            .unwrap(),
        KernelConfig::new(Word::from([3_u32, 0, 0, 0]), vec![]).unwrap(),
        KernelConfig::new(Word::from([4_u32, 0, 0, 0]), vec![]).unwrap(),
        ProofVerificationConfig::new(
            Word::from([5_u32, 0, 0, 0]),
            Word::from([6_u32, 0, 0, 0]),
            ProofSecurityPolicy::new(Word::from([7_u32, 0, 0, 0]), 96).unwrap(),
        ),
    )
    .unwrap()
}
