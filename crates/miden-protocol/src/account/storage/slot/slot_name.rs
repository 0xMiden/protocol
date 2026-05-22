use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::fmt::Display;
use core::str::FromStr;

use crate::account::name_validation::{self, NameValidationError};
use crate::account::storage::slot::StorageSlotId;
use crate::errors::StorageSlotNameError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// The name of an account storage slot.
///
/// A typical slot name looks like this:
///
/// ```text
/// miden::standards::fungible_faucets::metadata
/// ```
///
/// The double-colon (`::`) serves as a separator and the strings in between the separators are
/// called components.
///
/// It is generally recommended that slot names have at least three components and follow this
/// structure:
///
/// ```text
/// project_name::component_name::slot_name
/// ```
///
/// ## Requirements
///
/// For a string to be a valid slot name it needs to satisfy the following criteria:
/// - Its length must be less than 255.
/// - It needs to have at least 2 components.
/// - Each component must consist of at least one character.
/// - Each component must only consist of the characters `a` to `z`, `A` to `Z`, `0` to `9` or `_`
///   (underscore).
/// - Each component must not start with an underscore.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorageSlotName {
    name: Arc<str>,
    id: StorageSlotId,
}

impl StorageSlotName {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The minimum number of components that a slot name must contain.
    pub(crate) const MIN_NUM_COMPONENTS: usize = name_validation::MIN_NUM_COMPONENTS;

    /// The maximum number of characters in a slot name.
    pub(crate) const MAX_LENGTH: usize = name_validation::MAX_LENGTH;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a new [`StorageSlotName`] from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the slot name is invalid (see the type-level docs for the requirements).
    pub fn new(name: impl Into<Arc<str>>) -> Result<Self, StorageSlotNameError> {
        let name: Arc<str> = name.into();
        Self::validate(&name)?;
        let id = StorageSlotId::from_str(&name);
        Ok(Self { name, id })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the slot name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Returns the slot name as a string slice.
    // allow is_empty to be missing because it would always return false since slot names are
    // enforced to have a length greater than zero, so it does not have much use.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u8 {
        // SAFETY: Slot name validation should enforce length fits into a u8.
        debug_assert!(self.name.len() <= Self::MAX_LENGTH);
        self.name.len() as u8
    }

    /// Returns the [`StorageSlotId`] derived from the slot name.
    pub fn id(&self) -> StorageSlotId {
        self.id
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Validates a slot name against the shared name validation rules.
    const fn validate(name: &str) -> Result<(), StorageSlotNameError> {
        match name_validation::validate(name) {
            Ok(()) => Ok(()),
            Err(NameValidationError::TooShort) => Err(StorageSlotNameError::TooShort),
            Err(NameValidationError::TooLong) => Err(StorageSlotNameError::TooLong),
            Err(NameValidationError::UnexpectedColon) => Err(StorageSlotNameError::UnexpectedColon),
            Err(NameValidationError::UnexpectedUnderscore) => {
                Err(StorageSlotNameError::UnexpectedUnderscore)
            },
            Err(NameValidationError::InvalidCharacter) => {
                Err(StorageSlotNameError::InvalidCharacter)
            },
        }
    }
}

impl Ord for StorageSlotName {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id().cmp(&other.id())
    }
}

impl PartialOrd for StorageSlotName {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for StorageSlotName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for StorageSlotName {
    type Err = StorageSlotNameError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        StorageSlotName::new(string)
    }
}

impl TryFrom<&str> for StorageSlotName {
    type Error = StorageSlotNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for StorageSlotName {
    type Error = StorageSlotNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<StorageSlotName> for String {
    fn from(slot_name: StorageSlotName) -> Self {
        slot_name.name.to_string()
    }
}

impl Serializable for StorageSlotName {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.len());
        target.write_many(self.as_str().as_bytes())
    }

    fn get_size_hint(&self) -> usize {
        // Slot name length + slot name bytes
        1 + self.as_str().len()
    }
}

impl Deserializable for StorageSlotName {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_u8()?;
        let name = source.read_many_iter(len as usize)?.collect::<Result<_, _>>()?;
        String::from_utf8(name)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
            .and_then(|name| {
                Self::new(name).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
            })
    }
}

#[cfg(test)]
mod tests {
    //! Note: Most tests live in crate::account::name_validation.

    use super::*;

    // Serialization tests
    // --------------------------------------------------------------------------------------------

    #[test]
    fn serde_slot_name() -> anyhow::Result<()> {
        let slot_name = StorageSlotName::new("miden::faucet0::fungible_1::b4sic::metadata")?;
        assert_eq!(slot_name, StorageSlotName::read_from_bytes(&slot_name.to_bytes())?);
        Ok(())
    }

    #[test]
    fn serde_max_length_slot_name() -> anyhow::Result<()> {
        let slot_name = StorageSlotName::new(name_validation::tests::get_max_length_name())?;
        assert_eq!(slot_name, StorageSlotName::read_from_bytes(&slot_name.to_bytes())?);
        Ok(())
    }
}
