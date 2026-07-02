use alloc::sync::Arc;

use miden_mast_package::debug_info::PackageDebugInfo;
use miden_mast_package::{Package, PackageDebugInfoError};
use miden_processor::LoadedMastForest;

use crate::MastForest;

/// Returns package-owned debug info when it can be decoded from trusted package sections.
pub fn package_debug_info(package: &Package) -> Option<Arc<PackageDebugInfo>> {
    match package.debug_info() {
        Ok(debug_info) => debug_info.map(Arc::new),
        Err(PackageDebugInfoError::UntrustedSections) => None,
        Err(_) => None,
    }
}

/// Builds a loaded MAST forest from a MAST forest and package-owned debug info.
pub fn loaded_mast_forest(
    mast: Arc<MastForest>,
    package_debug_info: Option<Arc<PackageDebugInfo>>,
) -> LoadedMastForest {
    match package_debug_info {
        Some(package_debug_info) => {
            LoadedMastForest::with_package_debug_info(mast, Ok(Some((*package_debug_info).clone())))
        },
        None => LoadedMastForest::new(mast),
    }
}

/// Builds a loaded MAST forest from a package, including package-owned debug info when trusted.
pub fn loaded_mast_forest_from_package(package: &Package) -> LoadedMastForest {
    loaded_mast_forest(package.mast_forest().clone(), package_debug_info(package))
}
