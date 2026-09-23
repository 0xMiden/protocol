use alloc::vec::Vec;

use miden_protocol::utils::serde::Serializable;
use miden_protocol::{MastForest, Word};

use crate::proto;

/// Uses the hash-bearing format, which the untrusted decoder still accepts from a sender that
/// chooses it, because only that format carries node digests to corrupt.
pub(crate) fn corrupt_node_hash(
    forest: &MastForest,
    digest: Word,
) -> proto::primitives::MastForest {
    let mut wire = proto::primitives::MastForest { encoded: forest.to_bytes() };
    let digest = digest.to_bytes();
    let offsets: Vec<_> = wire
        .encoded
        .windows(digest.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == digest).then_some(offset))
        .collect();
    assert_eq!(offsets.len(), 1, "the fixture must contain the node digest exactly once");
    let replacement = Word::from([9_u32, 8, 7, 6]).to_bytes();
    assert_ne!(replacement, digest);
    wire.encoded[offsets[0]..offsets[0] + digest.len()].copy_from_slice(&replacement);
    wire
}
