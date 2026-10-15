use alloc::string::ToString;
use alloc::vec;
use core::error::Error;

use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::block::{BlockBody, BlockNumber};
use miden_protocol::errors::{ProtocolConfigError, ValidatorConfigError};
use miden_protocol::transaction::OrderedTransactionHeaders;

use crate::decoded::blockchain::test_utils::block_header_with_scheduled_upgrade;
use crate::decoded::protocol_config::test_utils::dummy_protocol_config;
use crate::test_utils::error_source;
use crate::{BuildUnchecked, ConversionError, DecodeMessage, DecodeMessageExt, Verify, proto};

#[test]
fn block_number_verifies() {
    assert_eq!(
        proto::blockchain::BlockNumber { block_num: u32::MAX }
            .decode_and_verify()
            .unwrap()
            .as_u32(),
        u32::MAX
    );
}

#[test]
fn fee_parameters_verify() {
    assert_eq!(
        proto::blockchain::FeeParameters { verification_base_fee: 7 }
            .decode_fields()
            .unwrap()
            .verify()
            .unwrap()
            .verification_base_fee(),
        7
    );
}

#[test]
fn signed_blocks_require_a_trusted_parent_for_authentication() {
    use miden_protocol::block::{
        BlockBody,
        BlockHeader,
        SignedBlock,
        SignedBlockError,
        ValidatorConfig,
    };
    use miden_protocol::transaction::OrderedTransactionHeaders;

    use crate::{BuildUnchecked, VerifyWith};

    fn header_for(num: u32, previous: Word, keys: ValidatorConfig) -> BlockHeader {
        let body = BlockBody::new(
            vec![],
            vec![],
            vec![],
            OrderedTransactionHeaders::new_unchecked(vec![]),
        )
        .unwrap();
        BlockHeader::new(
            previous,
            num.into(),
            Word::empty(),
            Word::empty(),
            Word::empty(),
            body.compute_block_note_tree().root(),
            body.transaction_commitment(),
            keys,
            miden_protocol::block::FeeParameters::new(500),
            Word::empty(),
            None,
            0,
        )
    }
    let (parent_signers, parent_keys) = ValidatorConfig::random_with_signers(1);
    let (child_signers, child_keys) = ValidatorConfig::random_with_signers(1);
    let parent = header_for(0, Word::empty(), parent_keys.clone());
    let header = header_for(1, parent.commitment(), child_keys.clone());
    let body =
        BlockBody::new(vec![], vec![], vec![], OrderedTransactionHeaders::new_unchecked(vec![]))
            .unwrap();
    let block = SignedBlock::new(
        header.clone(),
        body.clone(),
        parent_keys.sign_all(&parent_signers, header.commitment()),
    )
    .unwrap();
    let wire: proto::blockchain::SignedBlock = (&block).into();
    assert_eq!(wire.clone().decode_fields().unwrap().verify_with(&parent).unwrap(), block);
    let wrong_parent = header_for(0, Word::empty(), ValidatorConfig::random_with_signers(1).1);
    let error = wire.clone().decode_fields().unwrap().verify_with(&wrong_parent).unwrap_err();
    assert_matches!(
        error_source::<SignedBlockError>(&error),
        Some(SignedBlockError::ParentCommitmentMismatch { .. })
    );
    assert_eq!(wire.clone().decode_fields().unwrap().build_unchecked().unwrap(), block);

    // Correct linkage is insufficient: signatures must use the trusted parent's keys.
    let self_signed = SignedBlock::new(
        header.clone(),
        body,
        child_keys.sign_all(&child_signers, header.commitment()),
    )
    .unwrap();
    let self_signed_wire: proto::blockchain::SignedBlock = (&self_signed).into();
    let error = self_signed_wire
        .clone()
        .decode_fields()
        .unwrap()
        .verify_with(&parent)
        .unwrap_err();
    assert_matches!(
        error_source::<SignedBlockError>(&error),
        Some(SignedBlockError::InvalidSignatureAtPosition { position: 0 })
    );
    assert_eq!(
        self_signed_wire.decode_fields().unwrap().build_unchecked().unwrap(),
        self_signed
    );

    // Both construction paths must retain the header/body consistency checks.
    for corrupt_note_root in [false, true] {
        let mut inconsistent = wire.clone();
        let header = inconsistent.header.as_mut().unwrap();
        let commitment = if corrupt_note_root {
            &mut header.note_root
        } else {
            &mut header.tx_commitment
        };
        *commitment = Some(Word::from([1, 2, 3, 4u32]).into());
        for error in [
            inconsistent.clone().decode_fields().unwrap().build_unchecked().unwrap_err(),
            inconsistent.decode_fields().unwrap().verify_with(&parent).unwrap_err(),
        ] {
            let source = error_source::<SignedBlockError>(&error).unwrap();
            if corrupt_note_root {
                assert_matches!(source, SignedBlockError::NoteRootMismatch { .. });
            } else {
                assert_matches!(source, SignedBlockError::TxCommitmentMismatch { .. });
            }
        }
    }
}

#[test]
fn empty_protobuf_block_body_decodes_to_an_empty_domain_body() {
    let expected =
        BlockBody::new(vec![], vec![], vec![], OrderedTransactionHeaders::new_unchecked(vec![]))
            .unwrap();

    assert_eq!(
        proto::blockchain::BlockBody::default()
            .decode_fields()
            .unwrap()
            .build_unchecked()
            .unwrap(),
        expected
    );
}

#[test]
fn block_header_protobuf_rejects_unspecified_version_after_decoding() {
    let error = proto::blockchain::BlockHeader {
        version: proto::blockchain::BlockVersion::Unspecified as i32,
        ..proto::blockchain::BlockHeader::from(block_header_with_scheduled_upgrade())
    }
    .decode_fields()
    .unwrap()
    .build_unchecked()
    .map_err(ConversionError::new)
    .unwrap_err();

    assert_eq!(error.to_string(), "block header version is unspecified");
}

#[test]
fn block_header_protobuf_rejects_invalid_validator_quorum() {
    let header = block_header_with_scheduled_upgrade();
    let mut message = proto::blockchain::BlockHeader::from(header);
    message.validator_config.as_mut().unwrap().quorum = 0;

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();
    let source = error_source::<ValidatorConfigError>(&error).unwrap();

    assert_matches!(
        source,
        ValidatorConfigError::QuorumMustEqualValidatorCount { quorum: 0, count: 3 }
    );
}

#[test]
fn block_header_protobuf_reports_invalid_validator_key_index() {
    let header = block_header_with_scheduled_upgrade();
    let mut message = proto::blockchain::BlockHeader::from(header);
    message.validator_config.as_mut().unwrap().keys[1].key =
        Some(proto::primitives::public_key::Key::EcdsaK256Keccak(vec![]));

    let error = message.decode_fields().unwrap_err();

    assert!(
        error
            .to_string()
            .starts_with("validator_config.keys[1].key.ecdsa_k256_keccak: ")
    );
    assert!(
        error
            .source()
            .unwrap()
            .is::<miden_protocol::utils::serde::DeserializationError>()
    );
}

#[test]
fn block_header_protobuf_rejects_upgrade_effective_at_genesis() {
    let header = block_header_with_scheduled_upgrade();
    let mut message = proto::blockchain::BlockHeader::from(header);
    message.next_protocol_config.as_mut().unwrap().effective_from =
        Some(BlockNumber::GENESIS.into());

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();
    let source = error_source::<ProtocolConfigError>(&error).unwrap();

    assert!(error.to_string().starts_with("next_protocol_config:"), "{error}");
    assert_matches!(source, ProtocolConfigError::NextConfigEffectiveAtGenesis);
}

#[test]
fn next_protocol_config_defers_effective_block_validation() {
    use crate::{DecodeMessage, Verify};
    let decoded = proto::blockchain::NextProtocolConfig {
        effective_from: Some(proto::blockchain::BlockNumber { block_num: 0 }),
        protocol_config: Some(dummy_protocol_config().to_commitment().into()),
    }
    .decode_fields()
    .unwrap();
    assert!(decoded.verify().is_err());
}

fn partial_blockchain() -> miden_protocol::transaction::PartialBlockchain {
    use miden_protocol::block::BlockHeader;
    use miden_protocol::crypto::merkle::mmr::PartialMmr;

    let headers = [BlockHeader::mock(0, None, None, &[]), BlockHeader::mock(1, None, None, &[])];
    let mut mmr = PartialMmr::default();
    for header in &headers {
        mmr.add(header.commitment(), true).unwrap();
    }
    miden_protocol::transaction::PartialBlockchain::new(mmr, headers).unwrap()
}

#[test]
fn partial_blockchain_round_trip() {
    use prost::Message;

    let expected = partial_blockchain();
    let wire: proto::blockchain::PartialBlockchain = (&expected).into();
    let bytes = wire.encode_to_vec();
    let actual = proto::blockchain::PartialBlockchain::decode(bytes.as_slice())
        .unwrap()
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn partial_blockchain_requires_mmr() {
    let error = proto::blockchain::PartialBlockchain::default().decode_fields().unwrap_err();
    assert_eq!(
        error.to_string(),
        ConversionError::missing_field::<proto::blockchain::PartialBlockchain>("mmr")
            .context("mmr")
            .to_string()
    );
}

#[test]
fn partial_blockchain_rejects_duplicate_or_unordered_headers() {
    for duplicate in [false, true] {
        let mut wire: proto::blockchain::PartialBlockchain = (&partial_blockchain()).into();
        if duplicate {
            wire.block_headers[1] = wire.block_headers[0].clone();
        } else {
            wire.block_headers.swap(0, 1);
        }
        let error = wire.decode_fields().unwrap().build_unchecked().unwrap_err();
        assert_matches!(
            error_source::<super::PartialBlockchainError>(&error),
            Some(super::PartialBlockchainError::HeaderOrder)
        );
    }
}

#[test]
fn partial_blockchain_checks_header_membership() {
    use miden_protocol::errors::PartialBlockchainError;

    let mut wire: proto::blockchain::PartialBlockchain = (&partial_blockchain()).into();
    wire.block_headers[0].account_root = Some(Word::from([42u32, 0, 0, 0]).into());
    let error = wire.decode_fields().unwrap().build_unchecked().unwrap_err();
    assert_matches!(
        error_source::<PartialBlockchainError>(&error),
        Some(PartialBlockchainError::BlockHeaderCommitmentMismatch { block_num, .. })
        if *block_num == BlockNumber::GENESIS
    );
}

#[test]
fn partial_blockchain_verifies_nested_mmr() {
    use crate::decoded::primitives::PartialMmrError;

    let mut wire: proto::blockchain::PartialBlockchain = (&partial_blockchain()).into();
    wire.mmr.as_mut().unwrap().tracked_leaves[1].position = 2;
    let error = wire.decode_fields().unwrap().build_unchecked().unwrap_err();
    assert_matches!(
        error_source::<PartialMmrError>(&error),
        Some(PartialMmrError::Position { position: 2, size: 2 })
    );
}
