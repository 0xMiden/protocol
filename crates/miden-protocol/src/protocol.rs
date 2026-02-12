use alloc::sync::Arc;

use crate::assembly::Library;
use crate::assembly::mast::MastForest;
use crate::utils::serde::Deserializable;
use crate::utils::sync::LazyLock;

// CONSTANTS
// ================================================================================================

const PROTOCOL_LIB_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/assets/protocol.masl"));

// PROTOCOL LIBRARY
// ================================================================================================

#[derive(Clone)]
pub struct ProtocolLib(Library);

impl ProtocolLib {
    /// Returns a reference to the [`MastForest`] of the inner [`Library`].
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.0.mast_forest()
    }
}

impl AsRef<Library> for ProtocolLib {
    fn as_ref(&self) -> &Library {
        &self.0
    }
}

impl From<ProtocolLib> for Library {
    fn from(value: ProtocolLib) -> Self {
        value.0
    }
}

impl Default for ProtocolLib {
    fn default() -> Self {
        static PROTOCOL_LIB: LazyLock<ProtocolLib> = LazyLock::new(|| {
            let contents = Library::read_from_bytes(PROTOCOL_LIB_BYTES)
                .expect("protocol lib masl should be well-formed");
            ProtocolLib(contents)
        });
        PROTOCOL_LIB.clone()
    }
}

// TESTS
// ================================================================================================

// NOTE: Most protocol-related tests can be found in miden-testing.
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::ProtocolLib;
    use crate::assembly::Path;

    #[test]
    fn test_compile() {
        let path = Path::new("::miden::protocol::active_account::get_id");
        let miden = ProtocolLib::default();
        let exists = miden.0.module_infos().any(|module| {
            module
                .procedures()
                .any(|(_, proc)| module.path().join(&proc.name).as_path() == path)
        });

        assert!(exists);
    }
}
