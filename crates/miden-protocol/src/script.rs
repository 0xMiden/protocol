use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;

use miden_core::mast::MastNodeExt;
use miden_mast_package::Package;
use miden_mast_package::debug_info::PackageDebugInfo;
use miden_processor::LoadedMastForest;
use thiserror::Error;

use crate::assembly::Path;
use crate::package::{loaded_mast_forest, package_debug_info};
use crate::utils::create_external_node_forest;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::vm::AdviceMap;
use crate::{MastForest, MastNodeId, Word};

// MAST FOREST SCRIPT ERROR
// ================================================================================================

/// Errors that can occur while resolving a `MastForestScript` from a package.
#[derive(Debug, Error)]
pub enum MastForestScriptError {
    #[error("entrypoint node {0} is not in the provided MAST forest")]
    EntrypointNotInForest(MastNodeId),
    #[error("package does not contain a procedure with '@{0}' attribute")]
    NoProcedureWithAttribute(Box<str>),
    #[error("package contains multiple procedures with '@{0}' attribute")]
    MultipleProceduresWithAttribute(Box<str>),
    #[error("procedure at path '{0}' not found in package")]
    ProcedureNotFound(Box<str>),
    #[error("procedure at path '{0}' does not have the specified attribute")]
    ProcedureMissingAttribute(Box<str>),
    #[error("expected a library package, but the provided package is an executable")]
    ExecutablePackage,
}

// MAST FOREST SCRIPT
// ================================================================================================

/// An executable program backed by a [MastForest] and a designated entrypoint.
///
/// A [MastForestScript] consists of a [MastForest], a reference to the node in the forest at
/// which execution begins (the entrypoint), and optional package-owned debug information. It is the
/// shared core of [`NoteScript`](crate::note::NoteScript) and
/// [`TransactionScript`](crate::transaction::TransactionScript).
#[derive(Debug, Clone)]
pub(crate) struct MastForestScript {
    mast: Arc<MastForest>,
    entrypoint: MastNodeId,
    package_debug_info: Option<Arc<PackageDebugInfo>>,
}

impl MastForestScript {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [MastForestScript] instantiated from the provided components.
    ///
    /// # Errors
    /// Returns an error if the specified entrypoint is not in the provided MAST forest.
    pub fn from_parts(
        mast: Arc<MastForest>,
        entrypoint: MastNodeId,
    ) -> Result<Self, MastForestScriptError> {
        if mast.get_node_by_id(entrypoint).is_none() {
            return Err(MastForestScriptError::EntrypointNotInForest(entrypoint));
        }
        Ok(Self {
            mast,
            entrypoint,
            package_debug_info: None,
        })
    }

    /// Returns a new [MastForestScript] instantiated from the provided package.
    ///
    /// The package must be a library package containing exactly one procedure with the specified
    /// `attribute`, which is used as the entrypoint. Executable packages are rejected: a script's
    /// entrypoint is identified by its attribute, never by the package's program entrypoint.
    pub(crate) fn from_package(
        package: &Package,
        attribute: &str,
    ) -> Result<Self, MastForestScriptError> {
        if package.is_program() {
            return Err(MastForestScriptError::ExecutablePackage);
        }

        let mut entrypoint = None;

        for export in package.manifest.exports() {
            if let Some(proc_export) = export.as_procedure()
                && proc_export.attributes.has(attribute)
            {
                if entrypoint.is_some() {
                    return Err(MastForestScriptError::MultipleProceduresWithAttribute(
                        attribute.into(),
                    ));
                }
                entrypoint = Some(proc_export.node.ok_or_else(|| {
                    MastForestScriptError::NoProcedureWithAttribute(attribute.into())
                })?);
            }
        }

        let entrypoint = entrypoint
            .ok_or_else(|| MastForestScriptError::NoProcedureWithAttribute(attribute.into()))?;

        Ok(Self::from_parts(package.mast_forest().clone(), entrypoint)?
            .with_package_debug_info(package))
    }

    /// Returns a new [MastForestScript] containing only a reference to a procedure in the provided
    /// package.
    ///
    /// The procedure at the specified path must have the given `attribute`.
    ///
    /// Note: This creates a minimal [MastForest] containing only an external node referencing the
    /// procedure's digest, rather than copying the entire package. The actual procedure code is
    /// resolved at runtime via the `MastForestStore`.
    pub(crate) fn from_package_reference(
        package: &Package,
        path: &Path,
        attribute: &str,
    ) -> Result<Self, MastForestScriptError> {
        let export = package
            .manifest
            .exports()
            .find(|e| e.path().as_ref() == path)
            .ok_or_else(|| MastForestScriptError::ProcedureNotFound(path.to_string().into()))?;

        let proc_export = export
            .as_procedure()
            .ok_or_else(|| MastForestScriptError::ProcedureNotFound(path.to_string().into()))?;

        if !proc_export.attributes.has(attribute) {
            return Err(MastForestScriptError::ProcedureMissingAttribute(path.to_string().into()));
        }

        let digest = proc_export.digest;

        let (mast, entrypoint) = create_external_node_forest(digest);

        Ok(Self::from_parts(Arc::new(mast), entrypoint)?.with_package_debug_info(package))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the [MastForest] backing this program.
    pub fn mast(&self) -> Arc<MastForest> {
        self.mast.clone()
    }

    /// Returns the MAST forest and package-owned debug information backing this program.
    pub fn loaded_mast_forest(&self) -> LoadedMastForest {
        loaded_mast_forest(self.mast.clone(), self.package_debug_info.clone())
    }

    /// Returns the digest of the entrypoint node of this program (i.e., its MAST root).
    pub fn digest(&self) -> Word {
        self.mast[self.entrypoint].digest()
    }

    /// Returns the entrypoint node ID of this program.
    pub fn entrypoint(&self) -> MastNodeId {
        self.entrypoint
    }

    /// Removes debug info from this program, if any.
    pub fn clear_debug_info(&mut self) {
        self.package_debug_info = None;
    }

    /// Returns a new [MastForestScript] with the package-owned debug information of the provided
    /// package attached.
    pub fn with_package_debug_info(mut self, package: &Package) -> Self {
        self.package_debug_info = package_debug_info(package);
        self
    }

    /// Returns a new [MastForestScript] with the provided advice map entries merged into the
    /// underlying [MastForest].
    ///
    /// This allows adding advice map entries to an already-compiled program, which is useful when
    /// the entries are determined after compilation.
    pub fn with_advice_map(mut self, advice_map: AdviceMap) -> Self {
        if advice_map.is_empty() {
            return self;
        }

        let mast = (*self.mast).clone().with_advice_map(advice_map);
        self.mast = Arc::new(mast);
        self
    }
}

impl PartialEq for MastForestScript {
    fn eq(&self, other: &Self) -> bool {
        self.mast == other.mast && self.entrypoint == other.entrypoint
    }
}

impl Eq for MastForestScript {}

// SERIALIZATION
// ================================================================================================

impl Serializable for MastForestScript {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.mast.write_into(target);
        target.write_u32(u32::from(self.entrypoint));
    }

    fn get_size_hint(&self) -> usize {
        // TODO: this is a temporary workaround. Replace mast.to_bytes().len() with
        // MastForest::get_size_hint() (or a similar size-hint API) once it becomes
        // available.
        let mast_size = self.mast.to_bytes().len();
        let u32_size = 0u32.get_size_hint();

        mast_size + u32_size
    }
}

impl Deserializable for MastForestScript {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mast = MastForest::read_from(source)?;
        let entrypoint = MastNodeId::from_u32_safe(source.read_u32()?, &mast)?;

        Self::from_parts(Arc::new(mast), entrypoint)
            .map_err(|e| DeserializationError::InvalidValue(e.to_string()))
    }
}
