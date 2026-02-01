use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Display;

use miden_processor::MastNodeExt;

use super::Felt;
use crate::assembly::Library;
use crate::assembly::mast::{MastForest, MastNodeId};
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

// NOTE SCRIPT
// ================================================================================================

/// An executable program of a note.
///
/// A note's script represents a program which must be executed for a note to be consumed. As such
/// it defines the rules and side effects of consuming a given note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteScript {
    mast: Arc<MastForest>,
    entrypoint: MastNodeId,
}

impl NoteScript {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [NoteScript] instantiated from the provided program.
    pub fn new(code: Program) -> Self {
        Self {
            entrypoint: code.entrypoint(),
            mast: code.mast_forest().clone(),
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
        Self { mast, entrypoint }
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

        for export in library.exports() {
            if let Some(proc_export) = export.as_procedure() {
                // Check for @note_script attribute
                if proc_export.attributes.has(NOTE_SCRIPT_ATTRIBUTE) {
                    if entrypoint.is_some() {
                        return Err(NoteError::NoteScriptMultipleProceduresWithAttribute);
                    }
                    entrypoint = Some(proc_export.node);
                }
            }
        }

        let entrypoint = entrypoint.ok_or(NoteError::NoteScriptNoProcedureWithAttribute)?;

        Ok(Self {
            mast: library.mast_forest().clone(),
            entrypoint,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the commitment of this note script (i.e., the script's MAST root).
    pub fn root(&self) -> Word {
        self.mast[self.entrypoint].digest()
    }

    /// Returns a reference to the [MastForest] backing this note script.
    pub fn mast(&self) -> Arc<MastForest> {
        self.mast.clone()
    }

    /// Returns an entrypoint node ID of the current script.
    pub fn entrypoint(&self) -> MastNodeId {
        self.entrypoint
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

        let mut mast = (*self.mast).clone();
        mast.advice_map_mut().extend(advice_map);
        Self {
            mast: Arc::new(mast),
            entrypoint: self.entrypoint,
        }
    }
}

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
        result.push(Felt::new(len as u64));

        // A Felt can not represent all u64 values, so the data is encoded using u32.
        let mut encoded: &[u8] = &bytes;
        while encoded.len() >= 4 {
            let (data, rest) =
                encoded.split_first_chunk::<4>().expect("The length has been checked");
            let number = u32::from_le_bytes(*data);
            result.push(Felt::new(number.into()));

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

        let entrypoint: u32 = elements[0].try_into().map_err(DeserializationError::InvalidValue)?;
        let len = elements[1].as_int();
        let mut data = Vec::with_capacity(elements.len() * 4);

        for &felt in &elements[2..] {
            let v: u32 = felt.try_into().map_err(DeserializationError::InvalidValue)?;
            data.extend(v.to_le_bytes())
        }
        data.shrink_to(len as usize);

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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{Felt, NoteScript, Vec};
    use crate::assembly::Assembler;
    use crate::testing::note::DEFAULT_NOTE_CODE;

    #[test]
    fn test_note_script_to_from_felt() {
        let assembler = Assembler::default();
        let tx_script_src = DEFAULT_NOTE_CODE;
        let program = assembler.assemble_program(tx_script_src).unwrap();
        let note_script = NoteScript::new(program);

        let encoded: Vec<Felt> = (&note_script).into();
        let decoded: NoteScript = encoded.try_into().unwrap();

        assert_eq!(note_script, decoded);
    }

    #[test]
    fn test_note_script_with_advice_map() {
        use miden_core::{AdviceMap, Word};

        let assembler = Assembler::default();
        let program = assembler.assemble_program("begin nop end").unwrap();
        let script = NoteScript::new(program);

        assert!(script.mast().advice_map().is_empty());

        // Empty advice map should be a no-op
        let original_root = script.root();
        let script = script.with_advice_map(AdviceMap::default());
        assert_eq!(original_root, script.root());

        // Non-empty advice map should add entries
        let key = Word::from([5u32, 6, 7, 8]);
        let value = vec![Felt::new(100)];
        let mut advice_map = AdviceMap::default();
        advice_map.insert(key, value.clone());

        let script = script.with_advice_map(advice_map);

        let mast = script.mast();
        let stored = mast.advice_map().get(&key).expect("entry should be present");
        assert_eq!(stored.as_ref(), value.as_slice());
    }
}
