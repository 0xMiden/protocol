use alloc::vec;

use miden_protocol::Word;

use crate::{DecodeMessage, Verify, proto};

#[test]
fn merkle_path_verifies() {
    let decoded = proto::primitives::MerklePath { siblings: vec![Word::empty().into()] }
        .decode_fields()
        .unwrap();
    assert_eq!(decoded.verify().unwrap().nodes(), &[Word::empty()]);
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
