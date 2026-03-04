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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NoteType {
    /// Notes with this type have only their hash published to the network.
    Private = Self::PRIVATE,

    /// Notes with this type are fully shared with the network.
    Public = Self::PUBLIC,
}

impl NoteType {
    // Keep these masks in sync with `miden-lib/asm/miden/kernels/tx/tx.masm`
    pub const PUBLIC: u8 = 0b01;
    pub const PRIVATE: u8 = 0b10;
}

// CONVERSIONS FROM NOTE TYPE
// ================================================================================================

impl From<NoteType> for Felt {
    fn from(id: NoteType) -> Self {
        Felt::new(id as u64)
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

impl TryFrom<u16> for NoteType {
    type Error = NoteError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::try_from(value as u64)
    }
}

impl TryFrom<u32> for NoteType {
    type Error = NoteError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::try_from(value as u64)
    }
}

impl TryFrom<u64> for NoteType {
    type Error = NoteError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let value: u8 = value
            .try_into()
            .map_err(|_| NoteError::UnknownNoteType(format!("0b{value:b}").into()))?;
        value.try_into()
    }
}

impl TryFrom<Felt> for NoteType {
    type Error = NoteError;

    fn try_from(value: Felt) -> Result<Self, Self::Error> {
        value.as_canonical_u64().try_into()
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

// DISPLAY
// ================================================================================================

impl Display for NoteType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NoteType::Private => write!(f, "private"),
            NoteType::Public => write!(f, "public"),
        }
    }
}

#[test]
fn test_from_str_note_type() {
    use assert_matches::assert_matches;

    use crate::alloc::string::ToString;

    for string in ["private", "public"] {
        let parsed_note_type = NoteType::from_str(string).unwrap();
        assert_eq!(parsed_note_type.to_string(), string);
    }

    let public_type_invalid_err = NoteType::from_str("puBlIc").unwrap_err();
    assert_matches!(public_type_invalid_err, NoteError::UnknownNoteType(_));

    let invalid_type = NoteType::from_str("invalid").unwrap_err();
    assert_matches!(invalid_type, NoteError::UnknownNoteType(_));
}
