use alloc::boxed::Box;
use alloc::sync::Arc;

use miden_mast_package::{Package, TargetType, Version};

use crate::assembly::Library;
use crate::assembly::mast::MastForest;
use crate::utils::serde::Deserializable;
use crate::utils::sync::LazyLock;

// CONSTANTS
// ================================================================================================

const PROTOCOL_LIB_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/assets/protocol.masl"));

const PROTOCOL_PACKAGE_NAME: &str = "miden-protocol";

// PROTOCOL LIBRARY
// ================================================================================================

#[derive(Clone)]
pub struct ProtocolLib(Library);

impl ProtocolLib {
    /// Returns a reference to the [`MastForest`] of the inner [`Library`].
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.0.mast_forest()
    }

    /// Wraps this library into a [`Package`] named `PROTOCOL_PACKAGE_NAME`,
    /// versioned with the `miden-protocol` crate's version.
    pub fn into_package(self) -> Box<Package> {
        // The ProtocolLib's version is the same as the crate's as per the miden-protocol's
        // Cargo.toml.
        let version = Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("CARGO_PKG_VERSION must be valid semver");

        Package::from_library(
            PROTOCOL_PACKAGE_NAME.into(),
            version,
            TargetType::Library,
            Arc::new(self.0),
            [],
        )
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
