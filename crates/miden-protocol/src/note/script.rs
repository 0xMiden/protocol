use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Display;
use core::num::TryFromIntError;

use miden_core::mast::MastNodeExt;
use miden_crypto_derive::WordWrapper;
use miden_mast_package::Package;
use miden_processor::LoadedMastForest;

use super::Felt;
use crate::assembly::Path;
use crate::assembly::mast::{MastForest, MastNodeId};
use crate::errors::NoteError;
use crate::script::MastForestScript;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::vm::AdviceMap;
use crate::{PrettyPrint, Word};

/// The attribute name used to mark the entrypoint procedure in a note script package.
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
pub struct NoteScript(MastForestScript);

impl NoteScript {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

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
        Self(MastForestScript::from_parts(mast, entrypoint))
    }

    /// Returns a new [NoteScript] instantiated from the provided package.
    ///
    /// The package must contain exactly one procedure with the `@note_script` attribute,
    /// which will be used as the entrypoint.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The package does not contain a procedure with the `@note_script` attribute.
    /// - The package contains multiple procedures with the `@note_script` attribute.
    pub fn from_package(package: &Package) -> Result<Self, NoteError> {
        let script = MastForestScript::from_package(package, NOTE_SCRIPT_ATTRIBUTE)
            .map_err(NoteError::MastForestScript)?;
        Ok(Self(script))
    }

    /// Returns a new [NoteScript] containing only a reference to a procedure in the provided
    /// package.
    ///
    /// This method is useful when a package contains multiple note scripts and you need to
    /// extract a specific one by its fully qualified path (e.g.,
    /// `miden::standards::notes::burn::main`).
    ///
    /// The procedure at the specified path must have the `@note_script` attribute.
    ///
    /// Note: This method creates a minimal [MastForest] containing only an external node
    /// referencing the procedure's digest, rather than copying the entire package. The actual
    /// procedure code will be resolved at runtime via the `MastForestStore`.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The package does not contain a procedure at the specified path.
    /// - The procedure at the specified path does not have the `@note_script` attribute.
    pub fn from_package_reference(package: &Package, path: &Path) -> Result<Self, NoteError> {
        let script = MastForestScript::from_package_reference(package, path, NOTE_SCRIPT_ATTRIBUTE)
            .map_err(NoteError::MastForestScript)?;
        Ok(Self(script))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the commitment of this note script (i.e., the script's MAST root).
    pub fn root(&self) -> NoteScriptRoot {
        NoteScriptRoot::from_raw(self.0.digest())
    }

    /// Returns a reference to the [MastForest] backing this note script.
    pub fn mast(&self) -> Arc<MastForest> {
        self.0.mast()
    }

    /// Returns the MAST forest and package-owned debug information backing this note script.
    pub fn loaded_mast_forest(&self) -> LoadedMastForest {
        self.0.loaded_mast_forest()
    }

    /// Returns an entrypoint node ID of the current script.
    pub fn entrypoint(&self) -> MastNodeId {
        self.0.entrypoint()
    }

    /// Removes debug info from this note script, if any.
    pub fn clear_debug_info(&mut self) {
        self.0.clear_debug_info();
    }

    /// Returns a new [NoteScript] with the provided advice map entries merged into the
    /// underlying [MastForest].
    ///
    /// This allows adding advice map entries to an already-compiled note script,
    /// which is useful when the entries are determined after script compilation.
    pub fn with_advice_map(self, advice_map: AdviceMap) -> Self {
        Self(self.0.with_advice_map(advice_map))
    }
}

impl PartialEq for NoteScript {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for NoteScript {}

// CONVERSIONS INTO NOTE SCRIPT
// ================================================================================================

impl From<&NoteScript> for Vec<Felt> {
    fn from(script: &NoteScript) -> Self {
        let mut bytes = script.0.mast().to_bytes();
        let len = bytes.len();

        // Pad the data so that it can be encoded with u32
        let missing = if !len.is_multiple_of(4) { 4 - (len % 4) } else { 0 };
        bytes.resize(bytes.len() + missing, 0);

        let final_size = 2 + bytes.len();
        let mut result = Vec::with_capacity(final_size);

        // Push the length, this is used to remove the padding later
        result.push(Felt::from(u32::from(script.0.entrypoint())));
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
        self.0.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl Deserializable for NoteScript {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(MastForestScript::read_from(source)?))
    }
}

// PRETTY-PRINTING
// ================================================================================================

impl PrettyPrint for NoteScript {
    fn render(&self) -> miden_core::prettier::Document {
        use miden_core::prettier::*;
        let mast = self.0.mast();
        let entrypoint = mast[self.0.entrypoint()].to_pretty_print(&mast);

        indent(4, const_text("begin") + nl() + entrypoint.render()) + nl() + const_text("end")
    }
}

impl Display for NoteScript {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.pretty_print(f)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use super::{Felt, NoteScript, Vec};
    use crate::testing::assembler::assemble_test_package;
    use crate::testing::note::DEFAULT_NOTE_SCRIPT;

    #[test]
    fn test_note_script_to_from_felt() {
        let script_src = DEFAULT_NOTE_SCRIPT;
        let package =
            assemble_test_package("test-note-script-roundtrip", "test::note_roundtrip", script_src);
        let note_script = NoteScript::from_package(&package).unwrap();

        let encoded: Vec<Felt> = (&note_script).into();
        let decoded: NoteScript = encoded.try_into().unwrap();

        assert_eq!(note_script, decoded);
    }

    #[test]
    fn test_note_script_preserves_package_debug_info() {
        let package = assemble_test_package(
            "test-note-script-debug-info",
            "test::note_debug_info",
            DEFAULT_NOTE_SCRIPT,
        );
        let note_script = NoteScript::from_package(&package).unwrap();

        assert!(note_script.loaded_mast_forest().package_debug_info().unwrap().is_some());
    }

    #[test]
    fn test_note_script_with_advice_map() {
        use miden_core::advice::AdviceMap;

        use crate::Word;

        let package = assemble_test_package(
            "test-note-script-with-advice-map",
            "test::note_with_advice_map",
            DEFAULT_NOTE_SCRIPT,
        );
        let script = NoteScript::from_package(&package).unwrap();

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
