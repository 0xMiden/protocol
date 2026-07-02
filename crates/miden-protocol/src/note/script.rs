use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Display;
use core::num::TryFromIntError;

use miden_core::mast::{MastNode, MastNodeExt};
use miden_core::utils::IndexVec;
use miden_crypto_derive::WordWrapper;
use miden_mast_package::debug_info::PackageDebugInfo;
use miden_mast_package::{Package, PackageDebugInfoError};
use miden_processor::LoadedMastForest;

use super::Felt;
use crate::assembly::mast::{ExternalNodeBuilder, MastForest, MastNodeId};
use crate::assembly::{Library, Path};
use crate::errors::NoteError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::vm::{AdviceMap, Program};
use crate::{PrettyPrint, Word};

/// The attribute name used to mark the entrypoint procedure in a note script library.
const NOTE_SCRIPT_ATTRIBUTE: &str = "note_script";

// NOTE SCRIPT ROOT
// ================================================================================================

/// The MAST root of a [`NoteScript`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, WordWrapper)]
pub struct NoteScriptRoot(Word);

impl From<NoteScriptRoot> for Word {
    fn from(root: NoteScriptRoot) -> Self {
        root.0
    }
}

impl Display for NoteScriptRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Serializable for NoteScriptRoot {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.0);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl Deserializable for NoteScriptRoot {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let word: Word = source.read()?;
        Ok(Self::from_raw(word))
    }
}

// NOTE SCRIPT
// ================================================================================================

/// An executable program of a note.
///
/// A note's script represents a program which must be executed for a note to be consumed. As such
/// it defines the rules and side effects of consuming a given note.
#[derive(Debug, Clone)]
pub struct NoteScript {
    mast: Arc<MastForest>,
    entrypoint: MastNodeId,
    package_debug_info: Option<Arc<PackageDebugInfo>>,
}

impl NoteScript {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [NoteScript] instantiated from the provided program.
    ///
    /// TODO: since the note script now should be created from `Library`, not `Program`, this
    /// constructor should be removed:
    /// (<https://github.com/0xMiden/protocol/pull/2822#discussion_r3132965577>).
    pub fn new(code: Program) -> Self {
        Self {
            entrypoint: code.entrypoint(),
            mast: code.mast_forest().clone(),
            package_debug_info: None,
        }
    }

    /// Returns a new [NoteScript] deserialized from the provided bytes.
    ///
    /// # Errors
    /// Returns an error if note script deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NoteError> {
        Self::read_from_bytes(bytes).map_err(NoteError::NoteScriptDeserializationError)
    }

    /// Returns a new [NoteScript] instantiated from the provided components.
    ///
    /// # Panics
    /// Panics if the specified entrypoint is not in the provided MAST forest.
    pub fn from_parts(mast: Arc<MastForest>, entrypoint: MastNodeId) -> Self {
        assert!(mast.get_node_by_id(entrypoint).is_some());
        Self {
            mast,
            entrypoint,
            package_debug_info: None,
        }
    }

    /// Returns a new [NoteScript] instantiated from the provided library.
    ///
    /// The library must contain exactly one procedure with the `@note_script` attribute,
    /// which will be used as the entrypoint.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The library does not contain a procedure with the `@note_script` attribute.
    /// - The library contains multiple procedures with the `@note_script` attribute.
    pub fn from_library(library: &Library) -> Result<Self, NoteError> {
        let mut entrypoint = None;

        for export in library.manifest.exports() {
            if let Some(proc_export) = export.as_procedure() {
                // Check for @note_script attribute
                if proc_export.attributes.has(NOTE_SCRIPT_ATTRIBUTE) {
                    if entrypoint.is_some() {
                        return Err(NoteError::NoteScriptMultipleProceduresWithAttribute);
                    }
                    entrypoint = Some(
                        proc_export.node.ok_or(NoteError::NoteScriptNoProcedureWithAttribute)?,
                    );
                }
            }
        }

        let entrypoint = entrypoint.ok_or(NoteError::NoteScriptNoProcedureWithAttribute)?;

        Ok(Self {
            mast: library.mast_forest().clone(),
            entrypoint,
            package_debug_info: decode_package_debug_info(library),
        })
    }

    /// Returns a new [NoteScript] containing only a reference to a procedure in the provided
    /// library.
    ///
    /// This method is useful when a library contains multiple note scripts and you need to
    /// extract a specific one by its fully qualified path (e.g.,
    /// `miden::standards::notes::burn::main`).
    ///
    /// The procedure at the specified path must have the `@note_script` attribute.
    ///
    /// Note: This method creates a minimal [MastForest] containing only an external node
    /// referencing the procedure's digest, rather than copying the entire library. The actual
    /// procedure code will be resolved at runtime via the `MastForestStore`.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The library does not contain a procedure at the specified path.
    /// - The procedure at the specified path does not have the `@note_script` attribute.
    pub fn from_library_reference(library: &Library, path: &Path) -> Result<Self, NoteError> {
        // Find the export matching the path
        let export = library
            .manifest
            .exports()
            .find(|e| e.path().as_ref() == path)
            .ok_or_else(|| NoteError::NoteScriptProcedureNotFound(path.to_string().into()))?;

        // Get the procedure export and verify it has the @note_script attribute
        let proc_export = export
            .as_procedure()
            .ok_or_else(|| NoteError::NoteScriptProcedureNotFound(path.to_string().into()))?;

        if !proc_export.attributes.has(NOTE_SCRIPT_ATTRIBUTE) {
            return Err(NoteError::NoteScriptProcedureMissingAttribute(path.to_string().into()));
        }

        // Get the digest of the procedure from the library
        let digest = proc_export.digest;

        // Create a minimal MastForest with just an external node referencing the digest
        let (mast, entrypoint) = create_external_node_forest(digest);

        Ok(Self {
            mast: Arc::new(mast),
            entrypoint,
            package_debug_info: decode_package_debug_info(library),
        })
    }

    /// Creates an [`NoteScript`] from a [`Package`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The package contains a library which does not contain a procedure with the `@note_script`
    ///   attribute.
    /// - The package contains a library which contains multiple procedures with the `@note_script`
    ///   attribute.
    pub fn from_package(package: &Package) -> Result<Self, NoteError> {
        Ok(NoteScript::from_library(package))?
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the commitment of this note script (i.e., the script's MAST root).
    pub fn root(&self) -> NoteScriptRoot {
        NoteScriptRoot::from_raw(self.mast[self.entrypoint].digest())
    }

    /// Returns a reference to the [MastForest] backing this note script.
    pub fn mast(&self) -> Arc<MastForest> {
        self.mast.clone()
    }

    /// Returns the MAST forest and package-owned debug information backing this note script.
    pub fn loaded_mast_forest(&self) -> LoadedMastForest {
        loaded_mast_forest(self.mast.clone(), self.package_debug_info.clone())
    }

    /// Returns an entrypoint node ID of the current script.
    pub fn entrypoint(&self) -> MastNodeId {
        self.entrypoint
    }

    /// Compacts this script's [`MastForest`], removing duplicate and unreachable nodes while
    /// preserving the script root.
    pub fn compact(&mut self) {
        let root = self.root();
        let mut roots = self.mast.procedure_roots().to_vec();
        if !roots.contains(&self.entrypoint) {
            roots.push(self.entrypoint);
        }
        let mast = MastForest::from_raw_parts(
            IndexVec::try_from(self.mast.nodes().to_vec())
                .expect("note script MAST forest should not exceed the maximum node count"),
            roots,
            self.mast.advice_map().clone(),
        )
        .expect("note script MAST forest should be valid after preserving the entrypoint");
        let (mast, root_map) = mast.compact();
        self.entrypoint = root_map
            .map_root(0, &self.entrypoint)
            .expect("entrypoint should be preserved when compacting a note script MAST forest");
        self.mast = Arc::new(mast);
        self.package_debug_info = None;

        debug_assert_eq!(self.root(), root);
    }

    #[deprecated(note = "use NoteScript::compact instead")]
    pub fn clear_debug_info(&mut self) {
        self.compact();
    }

    /// Returns a new [NoteScript] with the provided advice map entries merged into the
    /// underlying [MastForest].
    ///
    /// This allows adding advice map entries to an already-compiled note script,
    /// which is useful when the entries are determined after script compilation.
    pub fn with_advice_map(self, advice_map: AdviceMap) -> Self {
        if advice_map.is_empty() {
            return self;
        }

        let mast = (*self.mast).clone().with_advice_map(advice_map);
        Self {
            mast: Arc::new(mast),
            entrypoint: self.entrypoint,
            package_debug_info: self.package_debug_info,
        }
    }
}

impl PartialEq for NoteScript {
    fn eq(&self, other: &Self) -> bool {
        self.mast == other.mast && self.entrypoint == other.entrypoint
    }
}

impl Eq for NoteScript {}

// CONVERSIONS INTO NOTE SCRIPT
// ================================================================================================

impl From<&NoteScript> for Vec<Felt> {
    fn from(script: &NoteScript) -> Self {
        let mut bytes = script.mast.to_bytes();
        let len = bytes.len();

        // Pad the data so that it can be encoded with u32
        let missing = if !len.is_multiple_of(4) { 4 - (len % 4) } else { 0 };
        bytes.resize(bytes.len() + missing, 0);

        let final_size = 2 + bytes.len();
        let mut result = Vec::with_capacity(final_size);

        // Push the length, this is used to remove the padding later
        result.push(Felt::from(u32::from(script.entrypoint)));
        result.push(Felt::new_unchecked(len as u64));

        // A Felt can not represent all u64 values, so the data is encoded using u32.
        let mut encoded: &[u8] = &bytes;
        while encoded.len() >= 4 {
            let (data, rest) =
                encoded.split_first_chunk::<4>().expect("The length has been checked");
            let number = u32::from_le_bytes(*data);
            result.push(Felt::from(number));

            encoded = rest;
        }

        result
    }
}

impl From<NoteScript> for Vec<Felt> {
    fn from(value: NoteScript) -> Self {
        (&value).into()
    }
}

impl AsRef<NoteScript> for NoteScript {
    fn as_ref(&self) -> &NoteScript {
        self
    }
}

// CONVERSIONS FROM NOTE SCRIPT
// ================================================================================================

impl TryFrom<&[Felt]> for NoteScript {
    type Error = DeserializationError;

    fn try_from(elements: &[Felt]) -> Result<Self, Self::Error> {
        if elements.len() < 2 {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let entrypoint: u32 = elements[0]
            .as_canonical_u64()
            .try_into()
            .map_err(|err: TryFromIntError| DeserializationError::InvalidValue(err.to_string()))?;
        let len = elements[1].as_canonical_u64();
        let mut data = Vec::with_capacity(elements.len() * 4);

        for &felt in &elements[2..] {
            let element: u32 =
                felt.as_canonical_u64().try_into().map_err(|err: TryFromIntError| {
                    DeserializationError::InvalidValue(err.to_string())
                })?;
            data.extend(element.to_le_bytes())
        }
        data.truncate(len as usize);

        // TODO: Use UntrustedMastForest and check where else we deserialize mast forests.
        let mast = MastForest::read_from_bytes(&data)?;
        let entrypoint = MastNodeId::from_u32_safe(entrypoint, &mast)?;
        Ok(NoteScript::from_parts(Arc::new(mast), entrypoint))
    }
}

impl TryFrom<Vec<Felt>> for NoteScript {
    type Error = DeserializationError;

    fn try_from(value: Vec<Felt>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteScript {
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

impl Deserializable for NoteScript {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mast = MastForest::read_from(source)?;
        let entrypoint = MastNodeId::from_u32_safe(source.read_u32()?, &mast)?;

        Ok(Self::from_parts(Arc::new(mast), entrypoint))
    }
}

// PRETTY-PRINTING
// ================================================================================================

impl PrettyPrint for NoteScript {
    fn render(&self) -> miden_core::prettier::Document {
        use miden_core::prettier::*;
        let entrypoint = self.mast[self.entrypoint].to_pretty_print(&self.mast);

        indent(4, const_text("begin") + nl() + entrypoint.render()) + nl() + const_text("end")
    }
}

impl Display for NoteScript {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.pretty_print(f)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates a minimal [MastForest] containing only an external node referencing the given digest.
///
/// This is useful for creating lightweight references to procedures without copying entire
/// libraries. The external reference will be resolved at runtime, assuming the source library
/// is loaded into the VM's MastForestStore.
fn create_external_node_forest(digest: Word) -> (MastForest, MastNodeId) {
    let mut nodes: miden_core::utils::IndexVec<MastNodeId, MastNode> =
        miden_core::utils::IndexVec::new();
    let node_id = nodes
        .push(ExternalNodeBuilder::new(digest).build().into())
        .expect("adding external node to empty forest should not fail");
    let mast = MastForest::from_raw_parts(nodes, vec![node_id], AdviceMap::default())
        .expect("single external node forest should be well-formed");
    (mast, node_id)
}

fn decode_package_debug_info(package: &Package) -> Option<Arc<PackageDebugInfo>> {
    match package.debug_info() {
        Ok(debug_info) => debug_info.map(Arc::new),
        Err(PackageDebugInfoError::UntrustedSections) => None,
        Err(_) => None,
    }
}

fn loaded_mast_forest(
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use miden_core::mast::{
        BasicBlockNodeBuilder,
        CallNodeBuilder,
        MastForest,
        MastForestContributor,
    };
    use miden_core::operations::Operation;

    use super::{Felt, NoteScript, Vec};
    use crate::testing::assembler::assemble_test_library;
    use crate::testing::note::DEFAULT_NOTE_SCRIPT;

    #[test]
    fn test_note_script_to_from_felt() {
        let script_src = DEFAULT_NOTE_SCRIPT;
        let library =
            assemble_test_library("test-note-script-roundtrip", "test::note_roundtrip", script_src);
        let note_script = NoteScript::from_library(&library).unwrap();

        let encoded: Vec<Felt> = (&note_script).into();
        let decoded: NoteScript = encoded.try_into().unwrap();

        assert_eq!(note_script, decoded);
    }

    #[test]
    fn test_note_script_preserves_package_debug_info() {
        let library = assemble_test_library(
            "test-note-script-debug-info",
            "test::note_debug_info",
            DEFAULT_NOTE_SCRIPT,
        );
        let note_script = NoteScript::from_library(&library).unwrap();

        assert!(note_script.loaded_mast_forest().package_debug_info().unwrap().is_some());
    }

    #[test]
    fn test_note_script_compact_preserves_non_root_entrypoint() {
        let mut forest = MastForest::new();
        let entrypoint = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .unwrap();
        let root = CallNodeBuilder::new(entrypoint).add_to_forest(&mut forest).unwrap();
        forest.make_root(root);

        let mut script = NoteScript::from_parts(Arc::new(forest), entrypoint);
        let script_root = script.root();

        script.compact();

        assert_eq!(script.root(), script_root);
    }

    #[test]
    fn test_note_script_compact_preserves_unrooted_entrypoint() {
        let mut forest = MastForest::new();
        let entrypoint = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .unwrap();

        let mut script = NoteScript::from_parts(Arc::new(forest), entrypoint);
        let script_root = script.root();

        script.compact();

        assert_eq!(script.root(), script_root);
    }

    #[test]
    fn test_note_script_with_advice_map() {
        use miden_core::advice::AdviceMap;

        use crate::Word;

        let library = assemble_test_library(
            "test-note-script-with-advice-map",
            "test::note_with_advice_map",
            DEFAULT_NOTE_SCRIPT,
        );
        let script = NoteScript::from_library(&library).unwrap();

        assert!(script.mast().advice_map().is_empty());

        // Empty advice map should be a no-op
        let original_root = script.root();
        let script = script.with_advice_map(AdviceMap::default());
        assert_eq!(original_root, script.root());

        // Non-empty advice map should add entries
        let key = Word::from([5u32, 6, 7, 8]);
        let value = vec![Felt::new_unchecked(100)];
        let mut advice_map = AdviceMap::default();
        advice_map.insert(key, value.clone());

        let script = script.with_advice_map(advice_map);

        let mast = script.mast();
        let stored = mast.advice_map().get(&key).expect("entry should be present");
        assert_eq!(stored.as_ref(), value.as_slice());
    }
}
