use miden_core::utils::hash_string_to_word;

use crate::Felt;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// An opaque two felt transaction log topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogTopic {
    suffix: Felt,
    prefix: Felt,
}

impl LogTopic {
    /// Size of a serialized topic in bytes.
    pub const SERIALIZED_SIZE: usize = 2 * size_of::<u64>();

    /// Creates a topic from its field elements, in metadata order.
    pub const fn new([suffix, prefix]: [Felt; 2]) -> Self {
        Self { suffix, prefix }
    }

    /// Derives a topic from the first two elements of a MASM `word(name)` constant.
    pub fn from_name(name: &str) -> Self {
        let word = hash_string_to_word(name);
        Self::new([word[0], word[1]])
    }

    /// Returns the topic's elements in metadata and serialization order.
    pub const fn as_elements(&self) -> [Felt; 2] {
        [self.suffix, self.prefix]
    }
}

impl Serializable for LogTopic {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.suffix.write_into(target);
        self.prefix.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for LogTopic {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self::new([Felt::read_from(source)?, Felt::read_from(source)?]))
    }

    fn min_serialized_size() -> usize {
        Self::SERIALIZED_SIZE
    }
}
