pub use miden_core::utils::*;
pub use miden_crypto::utils::{HexParseError, bytes_to_hex_string, hex_to_bytes};
pub use miden_utils_sync as sync;

use crate::Word;
use crate::assembly::mast::{ExternalNodeBuilder, MastForest, MastForestContributor, MastNodeId};

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

/// Creates a minimal [MastForest] containing only an external node referencing the given digest.
///
/// This is useful for creating lightweight references to procedures without copying entire
/// libraries. The external reference will be resolved at runtime, assuming the source library
/// is loaded into the VM's MastForestStore.
pub(crate) fn create_external_node_forest(digest: Word) -> (MastForest, MastNodeId) {
    let mut mast = MastForest::new();
    let node_id = ExternalNodeBuilder::new(digest)
        .add_to_forest(&mut mast)
        .expect("adding external node to empty forest should not fail");
    mast.make_root(node_id);
    (mast, node_id)
}
