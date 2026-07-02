use alloc::sync::Arc;

use miden_protocol::assembly::Library;
use miden_protocol::assembly::mast::MastForest;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::vm::Package;

// CONSTANTS
// ================================================================================================

const STANDARDS_PACKAGE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/assets/miden-standards.masp"));

static STANDARDS_PACKAGE: LazyLock<Arc<Package>> = LazyLock::new(|| {
    Arc::new(
        // These bytes are produced by this crate's build script and embedded in the binary.
        Package::read_from_bytes_trusted(STANDARDS_PACKAGE_BYTES)
            .expect("standards lib masp should be well-formed"),
    )
});

// MIDEN STANDARDS LIBRARY
// ================================================================================================

#[derive(Clone)]
pub struct StandardsLib(Arc<Package>);

impl StandardsLib {
    /// Returns a reference to the [`MastForest`] of the inner [`Package`].
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.0.mast_forest()
    }
}

impl AsRef<Library> for StandardsLib {
    fn as_ref(&self) -> &Library {
        self.0.as_ref()
    }
}

impl From<StandardsLib> for Package {
    fn from(value: StandardsLib) -> Self {
        Arc::unwrap_or_clone(value.0)
    }
}

impl Default for StandardsLib {
    fn default() -> Self {
        StandardsLib(STANDARDS_PACKAGE.clone())
    }
}

// TESTS
// ================================================================================================

// NOTE: Most standards-related tests can be found in miden-testing.
#[cfg(all(test, feature = "std"))]
mod tests {
    use miden_protocol::assembly::Path;

    use super::StandardsLib;

    #[test]
    fn test_compile() {
        let path = Path::new("::miden::standards::faucets::fungible::mint_and_send");
        let miden = StandardsLib::default();
        let exists = miden.0.module_infos().any(|module| {
            module
                .procedures()
                .any(|(_, proc)| module.path().join(&proc.name).as_path() == path)
        });

        assert!(exists);
    }
}
