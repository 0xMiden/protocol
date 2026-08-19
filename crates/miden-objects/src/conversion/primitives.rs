use alloc::format;

use miden_protocol::asset::Asset;
use miden_protocol::note::NoteId;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Felt, Word};

use crate::{ConversionError, proto};

const FELT_SERIALIZED_SIZE: usize = size_of::<u64>();
const WORD_SERIALIZED_SIZE: usize = Word::SERIALIZED_SIZE;

fn ensure_exact_length(
    encoded: &[u8],
    expected: usize,
    field: &'static str,
) -> Result<(), ConversionError> {
    if encoded.len() != expected {
        return Err(ConversionError::message(format!(
            "expected exactly {expected} bytes, got {}",
            encoded.len()
        ))
        .context(field));
    }
    Ok(())
}

impl From<Felt> for proto::primitives::Felt {
    fn from(value: Felt) -> Self {
        Self { encoded: value.to_bytes() }
    }
}

impl From<&Felt> for proto::primitives::Felt {
    fn from(value: &Felt) -> Self {
        Self { encoded: value.to_bytes() }
    }
}

impl TryFrom<proto::primitives::Felt> for Felt {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Felt) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&proto::primitives::Felt> for Felt {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::Felt) -> Result<Self, Self::Error> {
        ensure_exact_length(&value.encoded, FELT_SERIALIZED_SIZE, "felt.encoded")?;
        Self::read_from_bytes(&value.encoded)
            .map_err(|error| ConversionError::deserialization("felt.encoded", error))
    }
}

impl From<Word> for proto::primitives::Word {
    fn from(value: Word) -> Self {
        Self { encoded: value.to_bytes() }
    }
}

impl From<&Word> for proto::primitives::Word {
    fn from(value: &Word) -> Self {
        Self { encoded: value.to_bytes() }
    }
}

impl TryFrom<proto::primitives::Word> for Word {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Word) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&proto::primitives::Word> for Word {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::Word) -> Result<Self, Self::Error> {
        ensure_exact_length(&value.encoded, WORD_SERIALIZED_SIZE, "word.encoded")?;
        Self::read_from_bytes(&value.encoded)
            .map_err(|error| ConversionError::deserialization("word.encoded", error))
    }
}

impl From<Word> for proto::primitives::Digest {
    fn from(value: Word) -> Self {
        Self {
            d0: value[0].as_canonical_u64(),
            d1: value[1].as_canonical_u64(),
            d2: value[2].as_canonical_u64(),
            d3: value[3].as_canonical_u64(),
        }
    }
}

impl From<&Word> for proto::primitives::Digest {
    fn from(value: &Word) -> Self {
        (*value).into()
    }
}

impl From<[Felt; 4]> for proto::primitives::Digest {
    fn from(value: [Felt; 4]) -> Self {
        Word::new(value).into()
    }
}

impl TryFrom<proto::primitives::Digest> for Word {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Digest) -> Result<Self, Self::Error> {
        let values = [value.d0, value.d1, value.d2, value.d3];
        if values.iter().any(|value| *value >= Felt::ORDER) {
            return Err(ConversionError::message("value is not in the range 0..MODULUS"));
        }
        Ok(Word::new(values.map(Felt::new_unchecked)))
    }
}

impl TryFrom<&proto::primitives::Digest> for Word {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::Digest) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl From<&NoteId> for proto::primitives::Digest {
    fn from(value: &NoteId) -> Self {
        value.as_word().into()
    }
}

impl From<NoteId> for proto::primitives::Digest {
    fn from(value: NoteId) -> Self {
        (&value).into()
    }
}

impl From<&Asset> for proto::primitives::Asset {
    fn from(value: &Asset) -> Self {
        Self {
            key: Some(value.to_id_word().into()),
            value: Some(value.to_value_word().into()),
        }
    }
}

impl From<Asset> for proto::primitives::Asset {
    fn from(value: Asset) -> Self {
        (&value).into()
    }
}

impl TryFrom<proto::primitives::Asset> for Asset {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Asset) -> Result<Self, Self::Error> {
        let key = value
            .key
            .ok_or_else(|| ConversionError::missing_field::<proto::primitives::Asset>("key"))?
            .try_into()
            .map_err(|error: ConversionError| error.context("key"))?;
        let value = value
            .value
            .ok_or_else(|| ConversionError::missing_field::<proto::primitives::Asset>("value"))?
            .try_into()
            .map_err(|error: ConversionError| error.context("value"))?;
        Asset::from_id_and_value_words(key, value).map_err(ConversionError::new)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;

    #[test]
    fn felt_and_word_roundtrip_and_reject_invalid_lengths() {
        let felt = Felt::new_unchecked(42);
        assert_eq!(Felt::try_from(proto::primitives::Felt::from(felt)).unwrap(), felt);

        let word = Word::new([felt, Felt::ZERO, Felt::ONE, Felt::new_unchecked(7)]);
        assert_eq!(Word::try_from(proto::primitives::Word::from(word)).unwrap(), word);

        let error = Felt::try_from(proto::primitives::Felt { encoded: vec![0; 7] }).unwrap_err();
        assert_eq!(error.to_string(), "felt.encoded: expected exactly 8 bytes, got 7");
    }

    #[test]
    fn digest_rejects_non_canonical_limbs() {
        let digest = proto::primitives::Digest { d0: Felt::ORDER, d1: 0, d2: 0, d3: 0 };
        assert!(Word::try_from(digest).is_err());
    }
}
