use alloc::vec;

use miden_protocol::Word;

use crate::{DecodeMessage, DecodeMessageExt, Verify, proto};

#[test]
fn merkle_path_verifies() {
    let decoded = proto::primitives::MerklePath { siblings: vec![Word::empty().into()] }
        .decode_fields()
        .unwrap();
    assert_eq!(decoded.verify().unwrap().nodes(), &[Word::empty()]);
}

#[test]
fn merkle_path_rejects_more_than_255_siblings_without_panicking() {
    use miden_protocol::crypto::merkle::MerkleError;

    let decoded = proto::primitives::MerklePath {
        siblings: vec![Word::empty().into(); 256],
    }
    .decode_fields()
    .unwrap();
    assert!(matches!(decoded.verify(), Err(MerkleError::DepthTooBig(256))));
}

#[test]
fn merkle_path_oversized_protobuf_reports_depth_error() {
    use assert_matches::assert_matches;
    use miden_protocol::crypto::merkle::MerkleError;

    let wire = proto::primitives::MerklePath {
        siblings: vec![Word::empty().into(); 256],
    };
    let error = wire.decode_and_verify().unwrap_err();
    assert_matches!(
        crate::test_utils::error_source::<MerkleError>(&error),
        Some(MerkleError::DepthTooBig(256))
    );
}

#[test]
fn merkle_path_accepts_maximum_sibling_count() {
    let decoded = proto::primitives::MerklePath {
        siblings: vec![Word::empty().into(); 255],
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.verify().unwrap().depth(), 255);
}

#[test]
fn sparse_path_defers_depth_validation() {
    let decoded = proto::primitives::SparseMerklePath {
        empty_nodes_mask: 0,
        siblings: vec![Word::empty().into(); 65],
    }
    .decode_fields()
    .unwrap();
    assert!(decoded.verify().is_err());
}

#[test]
fn mmr_delta_verifies_forest_size_after_decoding() {
    let decoded = proto::primitives::MmrDelta {
        forest: 3,
        update_data: vec![Word::empty().into()],
    }
    .decode_fields()
    .unwrap();
    let delta = decoded.verify().unwrap();
    assert_eq!(delta.forest.num_leaves(), 3);
    assert_eq!(delta.data, vec![Word::empty()]);
    let invalid = proto::primitives::MmrDelta { forest: u64::MAX, update_data: vec![] }
        .decode_fields()
        .unwrap();
    assert!(invalid.verify().is_err());
}

#[test]
fn tracked_mmr_leaf_verifies() {
    let decoded = proto::primitives::TrackedMmrLeaf {
        position: 2,
        leaf: Some(Word::empty().into()),
        path: vec![],
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.verify().unwrap(), (2, Word::empty(), vec![]));
}

#[test]
fn partial_mmr_rejects_invalid_forest() {
    use assert_matches::assert_matches;
    use miden_protocol::crypto::merkle::mmr::Forest;
    use miden_protocol::utils::serde::DeserializationError;

    let error = proto::primitives::PartialMmr {
        forest: (Forest::MAX_LEAVES as u64) + 1,
        ..Default::default()
    }
    .decode_fields()
    .unwrap()
    .verify()
    .unwrap_err();
    assert_matches!(
        crate::test_utils::error_source::<DeserializationError>(&error),
        Some(DeserializationError::InvalidValue(_))
    );
}

#[test]
fn partial_mmr_rejects_wrong_peak_count() {
    use assert_matches::assert_matches;
    use miden_protocol::crypto::merkle::mmr::MmrError;

    for (forest, peak_count) in [(0, 1), (3, 1), (1, 2)] {
        let error = proto::primitives::PartialMmr {
            forest,
            peaks: vec![Word::empty().into(); peak_count],
            tracked_leaves: vec![],
        }
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap_err();
        assert_matches!(
            crate::test_utils::error_source::<MmrError>(&error),
            Some(MmrError::InvalidPeaks(_))
        );
    }
}

fn tracked_partial_mmr() -> proto::primitives::PartialMmr {
    let mut mmr = miden_protocol::crypto::merkle::mmr::PartialMmr::default();
    for index in 0..7u32 {
        mmr.add(crate::test_utils::dummy_word(index), true).unwrap();
    }
    mmr.into()
}

#[test]
fn partial_mmr_rejects_out_of_range_position() {
    use assert_matches::assert_matches;

    use crate::decoded::primitives::PartialMmrError;

    let mut message = tracked_partial_mmr();
    message.tracked_leaves[6].position = message.forest;
    let error = message.decode_fields().unwrap().verify().unwrap_err();
    assert_matches!(
        crate::test_utils::error_source::<PartialMmrError>(&error),
        Some(PartialMmrError::Position { position: 7, size: 7 })
    );
}

#[test]
fn partial_mmr_rejects_duplicate_or_unordered_leaves() {
    use assert_matches::assert_matches;

    use crate::decoded::primitives::PartialMmrError;

    for duplicate in [false, true] {
        let mut message = tracked_partial_mmr();
        if duplicate {
            message.tracked_leaves[1] = message.tracked_leaves[0].clone();
        } else {
            message.tracked_leaves.swap(0, 1);
        }
        let error = message.decode_fields().unwrap().verify().unwrap_err();
        assert_matches!(
            crate::test_utils::error_source::<PartialMmrError>(&error),
            Some(PartialMmrError::LeafOrder)
        );
    }
}

#[test]
fn partial_mmr_rejects_invalid_inclusion_proof() {
    use assert_matches::assert_matches;
    use miden_protocol::crypto::merkle::mmr::MmrError;

    for corrupt_leaf in [false, true] {
        let mut message = tracked_partial_mmr();
        let tracked = &mut message.tracked_leaves[0];
        let wrong_word = crate::test_utils::dummy_word(42).into();
        if corrupt_leaf {
            tracked.leaf = Some(wrong_word);
        } else {
            tracked.path[0] = wrong_word;
        }
        let error = message.decode_fields().unwrap().verify().unwrap_err();
        assert_matches!(
            crate::test_utils::error_source::<MmrError>(&error),
            Some(MmrError::PeakPathMismatch)
        );
    }
}

#[test]
fn partial_mmr_rejects_path_depth_for_another_peak() {
    use assert_matches::assert_matches;
    use miden_protocol::crypto::merkle::mmr::MmrError;

    for path_depth in [0, 3] {
        let mut message = tracked_partial_mmr();
        message.tracked_leaves[0].path = vec![Word::empty().into(); path_depth];
        let error = message.decode_fields().unwrap().verify().unwrap_err();
        let source = crate::test_utils::error_source::<MmrError>(&error);
        if path_depth == 0 {
            // The depth-zero peak exists, but it contains position 6 rather than position 0.
            assert_matches!(source, Some(MmrError::PositionNotFound(0)));
        } else {
            assert_matches!(source, Some(MmrError::UnknownPeak(3)));
        }
    }
}
