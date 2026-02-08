use core::fmt::Display;
use core::str::FromStr;

use miden_core::field::PrimeField64;

use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, NoteError};

// CONSTANTS
// ================================================================================================

// Keep these masks in sync with `miden-lib/asm/miden/kernels/tx/tx.masm`
const PUBLIC: u8 = 0b01;
const PRIVATE: u8 = 0b10;
const ENCRYPTED: u8 = 0b11;

// NOTE TYPE
// ================================================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NoteType {
    /// Notes with this type have only their hash published to the network.
    Private = PRIVATE,

    /// Notes with this type are shared with the network encrypted.
    Encrypted = ENCRYPTED,

    /// Notes with this type are fully shared with the network.
    Public = PUBLIC,
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
            PRIVATE => Ok(NoteType::Private),
            ENCRYPTED => Ok(NoteType::Encrypted),
            PUBLIC => Ok(NoteType::Public),
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
            "encrypted" => Ok(NoteType::Encrypted),
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
}

impl Deserializable for NoteType {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let discriminant = u8::read_from(source)?;

        let note_type = match discriminant {
            PRIVATE => NoteType::Private,
            ENCRYPTED => NoteType::Encrypted,
            PUBLIC => NoteType::Public,
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
            NoteType::Encrypted => write!(f, "encrypted"),
            NoteType::Public => write!(f, "public"),
        }
    }
}

#[test]
fn test_from_str_note_type() {
    use assert_matches::assert_matches;

    use crate::alloc::string::ToString;

    for string in ["private", "public", "encrypted"] {
        let parsed_note_type = NoteType::from_str(string).unwrap();
        assert_eq!(parsed_note_type.to_string(), string);
    }

    let public_type_invalid_err = NoteType::from_str("puBlIc").unwrap_err();
    assert_matches!(public_type_invalid_err, NoteError::UnknownNoteType(_));

    let encrypted_type_invalid = NoteType::from_str("eNcrYptEd").unwrap_err();
    assert_matches!(encrypted_type_invalid, NoteError::UnknownNoteType(_));

    let invalid_type = NoteType::from_str("invalid").unwrap_err();
    assert_matches!(invalid_type, NoteError::UnknownNoteType(_));
}
