use alloc::vec::Vec;

use crate::errors::NoteError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, MAX_INPUTS_PER_NOTE, Word};

// NOTE INPUTS
// ================================================================================================

/// A container for note inputs.
///
/// A note can be associated with up to 1024 input values. Each value is represented by a single
/// field element. Thus, note input values can contain up to ~8 KB of data.
///
/// All inputs associated with a note can be reduced to a single commitment which is computed by
/// hashing the elements directly via the sequential hash (the Poseidon2 hasher tracks the input
/// length via its capacity element).
#[derive(Clone, Debug)]
pub struct NoteInputs {
    values: Vec<Felt>,
    commitment: Word,
}

impl NoteInputs {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns [NoteInputs] instantiated from the provided values.
    ///
    /// # Errors
    /// Returns an error if the number of provided inputs is greater than 1024.
    pub fn new(values: Vec<Felt>) -> Result<Self, NoteError> {
        if values.len() > MAX_INPUTS_PER_NOTE {
            return Err(NoteError::TooManyInputs(values.len()));
        }

        Ok(pad_and_build(values))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a commitment to these inputs.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// Returns the number of input values.
    ///
    /// The returned value is guaranteed to be smaller than or equal to 1024.
    pub fn num_values(&self) -> u16 {
        const _: () = assert!(MAX_INPUTS_PER_NOTE <= u16::MAX as usize);
        debug_assert!(
            self.values.len() <= MAX_INPUTS_PER_NOTE,
            "The constructor should have checked the number of inputs"
        );
        self.values.len() as u16
    }

    /// Returns a reference to the input values.
    pub fn values(&self) -> &[Felt] {
        &self.values
    }

    /// Returns the note's input as a vector of field elements.
    ///
    pub fn to_elements(&self) -> Vec<Felt> {
        self.values.clone()
    }
}

impl Default for NoteInputs {
    fn default() -> Self {
        pad_and_build(vec![])
    }
}

impl PartialEq for NoteInputs {
    fn eq(&self, other: &Self) -> bool {
        let NoteInputs { values: inputs, commitment: _ } = self;
        inputs == &other.values
    }
}

impl Eq for NoteInputs {}

// CONVERSION
// ================================================================================================

impl From<NoteInputs> for Vec<Felt> {
    fn from(value: NoteInputs) -> Self {
        value.values
    }
}

impl TryFrom<Vec<Felt>> for NoteInputs {
    type Error = NoteError;

    fn try_from(value: Vec<Felt>) -> Result<Self, Self::Error> {
        NoteInputs::new(value)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a vector built from the provided inputs (in stack order) and padded to the next
/// multiple of 8.
/// Pad `values` and returns a new `NoteInputs`.
fn pad_and_build(values: Vec<Felt>) -> NoteInputs {
    let commitment = {
        Hasher::hash_elements(&values)
    };

    NoteInputs { values, commitment }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let NoteInputs { values, commitment: _commitment } = self;
        target.write_u16(values.len().try_into().expect("inputs len is not a u16 value"));
        target.write_many(values);
    }
}

impl Deserializable for NoteInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_values = source.read_u16()? as usize;
        let values = source.read_many_iter::<Felt>(num_values)?.collect::<Result<Vec<_>, _>>()?;
        Self::new(values).map_err(|v| DeserializationError::InvalidValue(format!("{v}")))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_crypto::utils::Deserializable;

    use super::{Felt, NoteInputs, Serializable};

    #[test]
    fn test_input_ordering() {
        // inputs are provided in reverse stack order
        let inputs = vec![Felt::new(1), Felt::new(2), Felt::new(3)];
        // we expect the inputs to be padded to length 16 and to remain in reverse stack order.
        let expected_ordering = vec![Felt::new(1), Felt::new(2), Felt::new(3)];

        let note_inputs = NoteInputs::new(inputs).expect("note created should succeed");
        assert_eq!(&expected_ordering, &note_inputs.values);
    }

    #[test]
    fn test_input_serialization() {
        let inputs = vec![Felt::new(1), Felt::new(2), Felt::new(3)];
        let note_inputs = NoteInputs::new(inputs).unwrap();

        let bytes = note_inputs.to_bytes();
        let parsed_note_inputs = NoteInputs::read_from_bytes(&bytes).unwrap();
        assert_eq!(note_inputs, parsed_note_inputs);
    }
}
