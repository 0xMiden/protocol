use miden_core::utils::hash_string_to_word;

use crate::Felt;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// An opaque two-felt transaction log topic.
///
/// Named topics use the first two felts of MASM `word(name)`. Applications define the payload
/// schema for each topic. Incompatible schemas should use distinct names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogTopic([Felt; 2]);

impl LogTopic {
    /// Size of a serialized topic in bytes.
    pub const SERIALIZED_SIZE: usize = 2 * size_of::<u64>();

    /// Creates a topic from its field elements, in metadata order.
    pub const fn new(elements: [Felt; 2]) -> Self {
        Self(elements)
    }

    /// Derives a topic from the first two elements of a MASM `word(name)` constant.
    ///
    /// The name's syntax is not validated.
    pub fn from_name(name: &str) -> Self {
        let word = hash_string_to_word(name);
        Self([word[0], word[1]])
    }

    /// Returns the topic's elements in metadata and serialization order.
    pub const fn as_elements(&self) -> [Felt; 2] {
        self.0
    }
}

impl Serializable for LogTopic {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0[0].write_into(target);
        self.0[1].write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for LogTopic {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self([Felt::read_from(source)?, Felt::read_from(source)?]))
    }

    fn min_serialized_size() -> usize {
        Self::SERIALIZED_SIZE
    }
}
