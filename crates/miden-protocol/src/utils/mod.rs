use alloc::vec;
use alloc::vec::Vec;

use miden_core::mast::MastNode;
pub use miden_core::utils::*;
pub use miden_crypto::utils::{HexParseError, bytes_to_hex_string, hex_to_bytes};
pub use miden_utils_sync as sync;

use crate::assembly::mast::{ExternalNodeBuilder, MastForest, MastNodeId};
use crate::vm::AdviceMap;
use crate::{Felt, Word};

pub mod serde {
    pub use miden_crypto::utils::{
        BudgetedReader,
        ByteReader,
        ByteWriter,
        Deserializable,
        DeserializationError,
        Serializable,
        SliceReader,
    };
}

pub mod strings;

pub(crate) use strings::ShortCapitalString;

/// Returns the [`Word`]s formed by each consecutive [`Word::NUM_ELEMENTS`] elements, or `None` if
/// the number of elements is not a multiple of [`Word::NUM_ELEMENTS`].
pub fn words_from_elements(elements: &[Felt]) -> Option<Vec<Word>> {
    let (words, []) = elements.as_chunks::<{ Word::NUM_ELEMENTS }>() else {
        return None;
    };
    Some(words.iter().copied().map(Word::new).collect())
}

/// Creates a minimal [MastForest] containing only an external node referencing the given digest.
///
/// This is useful for creating lightweight references to procedures without copying entire
/// packages. The external reference will be resolved at runtime, assuming the source package
/// is loaded into the VM's MastForestStore.
pub(crate) fn create_external_node_forest(digest: Word) -> (MastForest, MastNodeId) {
    let mut nodes: IndexVec<MastNodeId, MastNode> = IndexVec::new();
    let node_id = nodes
        .push(ExternalNodeBuilder::new(digest).build().into())
        .expect("adding external node to empty forest should not fail");
    let mast = MastForest::from_raw_parts(nodes, vec![node_id], AdviceMap::default())
        .expect("single external node forest should be well-formed");
    (mast, node_id)
}
