//! The shipped `xreserve` MASM library as a link target, for harnesses only.
//!
//! Deploying and using the faucet never needs this module: an account installs the
//! [`XReserveFaucetExtension`](crate::account::XReserveFaucetExtension) component, whose package
//! re-exports the two account procedures and carries the code they reach. What lives here is the
//! whole `xreserve::*` surface — every internal procedure and constant — so a harness can assemble
//! its own MASM against it. The whole module is behind the `testing` feature, which keeps that link
//! target out of the shipped surface and keeps the gate in one place.

use std::sync::Arc;

use miden_protocol::assembly::mast::MastForest;
use miden_protocol::assembly::Package;
use miden_protocol::utils::sync::LazyLock;

static XRESERVE_PACKAGE: LazyLock<Arc<Package>> = LazyLock::new(|| {
    // These bytes are produced by this crate's build script and embedded in the binary.
    Arc::new(
        Package::read_from_bytes_trusted(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/assets/xreserve.masp"
        )))
        .expect("the shipped xreserve package deserializes"),
    )
});

/// The shipped `xreserve` MASM library.
#[derive(Clone)]
pub struct XReserveLibrary(Arc<Package>);

impl XReserveLibrary {
    /// Returns the underlying [`Arc<Package>`].
    pub fn package(&self) -> Arc<Package> {
        self.0.clone()
    }

    /// Returns a reference to the [`MastForest`] of the inner [`Package`].
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.0.mast_forest()
    }
}

impl AsRef<Package> for XReserveLibrary {
    fn as_ref(&self) -> &Package {
        self.0.as_ref()
    }
}

impl From<XReserveLibrary> for Package {
    fn from(value: XReserveLibrary) -> Self {
        Arc::unwrap_or_clone(value.0)
    }
}

impl Default for XReserveLibrary {
    fn default() -> Self {
        Self(XRESERVE_PACKAGE.clone())
    }
}
