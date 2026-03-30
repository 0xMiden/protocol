use core::fmt::Display;
use core::str::FromStr;

use crate::Felt;
use crate::errors::NoteError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// NOTE TYPE
// ================================================================================================

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum NoteType {
    #[default]
    /// Notes with this type have only their hash published to the network.
    Private = Self::PRIVATE,

    /// Notes with this type are fully shared with the network.
    Public = Self::PUBLIC,
}

impl NoteType {
    const PRIVATE: u8 = 0;
    const PUBLIC: u8 = 1;

    /// Returns the note type encoded to a 1-bit flag, where private is 0 and public is 1.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

// CONVERSIONS FROM NOTE TYPE
// ================================================================================================

impl From<NoteType> for Felt {
    fn from(note_type: NoteType) -> Self {
        Felt::from(note_type.as_u8())
    }
}

// CONVERSIONS INTO NOTE TYPE
// ================================================================================================

impl TryFrom<u8> for NoteType {
    type Error = NoteError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::PRIVATE => Ok(NoteType::Private),
            Self::PUBLIC => Ok(NoteType::Public),
            _ => Err(NoteError::UnknownNoteType(format!("0b{value:b}").into())),
        }
    }
}

impl TryFrom<Felt> for NoteType {
    type Error = NoteError;

    fn try_from(value: Felt) -> Result<Self, Self::Error> {
        let byte = value.as_canonical_u64();
        Self::try_from(
            u8::try_from(byte)
                .map_err(|_| NoteError::UnknownNoteType(format!("0b{byte:b}").into()))?,
        )
    }
}

// STRING CONVERSION
// ================================================================================================

impl Display for NoteType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NoteType::Private => write!(f, "private"),
            NoteType::Public => write!(f, "public"),
        }
    }
}

impl FromStr for NoteType {
    type Err = NoteError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "private" => Ok(NoteType::Private),
            "public" => Ok(NoteType::Public),
            _ => Err(NoteError::UnknownNoteType(s.into())),
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteType {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        (*self as u8).write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u8>()
    }
}

impl Deserializable for NoteType {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let discriminant = u8::read_from(source)?;

        let note_type = match discriminant {
            NoteType::PRIVATE => NoteType::Private,
            NoteType::PUBLIC => NoteType::Public,
            discriminant => {
                return Err(DeserializationError::InvalidValue(format!(
                    "discriminant {discriminant} is not a valid NoteType"
                )));
            },
        };

        Ok(note_type)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::alloc::string::ToString;

    #[rstest::rstest]
    #[case::private(NoteType::Private)]
    #[case::public(NoteType::Public)]
    #[test]
    fn test_note_type_roundtrip(#[case] note_type: NoteType) -> anyhow::Result<()> {
        // String roundtrip
        assert_eq!(note_type, note_type.to_string().parse()?);

        // Serialization roundtrip
        assert_eq!(note_type, NoteType::read_from_bytes(&note_type.to_bytes())?);

        // Byte conversion roundtrip
        assert_eq!(note_type, NoteType::try_from(note_type.as_u8())?);

        // Felt conversion roundtrip
        assert_eq!(note_type, NoteType::try_from(Felt::from(note_type))?);

        Ok(())
    }

    #[test]
    fn test_from_str_note_type() {
        for string in ["private", "public"] {
            let parsed_note_type = NoteType::from_str(string).unwrap();
            assert_eq!(parsed_note_type.to_string(), string);
        }

        let public_type_invalid_err = NoteType::from_str("puBlIc").unwrap_err();
        assert_matches!(public_type_invalid_err, NoteError::UnknownNoteType(_));

        let invalid_type = NoteType::from_str("invalid").unwrap_err();
        assert_matches!(invalid_type, NoteError::UnknownNoteType(_));
    }
}
