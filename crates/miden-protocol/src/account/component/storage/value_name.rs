use alloc::string::{String, ToString};
use core::cmp::Ordering;
use core::fmt::{self, Display};
use core::str::FromStr;

use miden_crypto::utils::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use thiserror::Error;

use crate::account::StorageSlotName;
use crate::errors::StorageSlotNameError;

/// A simple wrapper type around a string key that identifies init-provided values.
///
/// A storage value name is a string that identifies values supplied during component
/// instantiation (via [`InitStorageData`](super::InitStorageData)).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "std", derive(::serde::Deserialize, ::serde::Serialize))]
#[cfg_attr(feature = "std", serde(try_from = "String", into = "String"))]
pub struct StorageValueName {
    slot_name: StorageSlotName,
    element_field: Option<String>,
}

impl StorageValueName {
    /// Creates a [`StorageValueName`] for the given storage slot.
    pub fn from_slot_name(slot_name: &StorageSlotName) -> Self {
        StorageValueName {
            slot_name: slot_name.clone(),
            element_field: None,
        }
    }

    /// Adds a field-name suffix to a slot-name key, separated by a period, that identifies a
    /// specific element (e.g., "basic_faucet::metadata.decimals")
    pub fn with_suffix(self, suffix: &str) -> Result<StorageValueName, StorageValueNameError> {
        let mut key = self;

        // `StorageValueName` keys are either `slot` or `slot.field`. Appending to a key that is
        // already suffixed is create an invalid name.
        if key.element_field.is_some() {
            return Err(StorageValueNameError::InvalidCharacter {
                part: key.to_string(),
                character: '.',
            });
        }

        Self::validate_field_segment(suffix)?;
        key.element_field = Some(suffix.to_string());
        Ok(key)
    }

    fn validate_field_segment(segment: &str) -> Result<(), StorageValueNameError> {
        if segment.is_empty() {
            return Err(StorageValueNameError::EmptySuffix);
        }

        if let Some(offending_char) =
            segment.chars().find(|&c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        {
            return Err(StorageValueNameError::InvalidCharacter {
                part: segment.to_string(),
                character: offending_char,
            });
        }

        Ok(())
    }
}

impl PartialEq for StorageValueName {
    fn eq(&self, other: &Self) -> bool {
        self.slot_name.as_str() == other.slot_name.as_str()
            && self.element_field.as_deref() == other.element_field.as_deref()
    }
}

impl Eq for StorageValueName {}

impl PartialOrd for StorageValueName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StorageValueName {
    fn cmp(&self, other: &Self) -> Ordering {
        let slot_cmp = self.slot_name.as_str().cmp(other.slot_name.as_str());
        if slot_cmp != Ordering::Equal {
            return slot_cmp;
        }

        match (self.element_field.as_deref(), other.element_field.as_deref()) {
            (None, None) => Ordering::Equal,

            // "<slot>" is a prefix of "<slot>.<field>", so it sorts first.
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,

            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

impl FromStr for StorageValueName {
    type Err = StorageValueNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(StorageValueNameError::EmptySuffix);
        }

        // `StorageValueName` represents:
        // - a storage slot name (`StorageSlotName`), or
        // - a fully-qualified storage slot field key (`named::slot.field`).
        let (slot, field) = match value.split_once('.') {
            Some((slot, field)) => {
                Self::validate_field_segment(field)?;

                if slot.is_empty() || field.is_empty() {
                    return Err(StorageValueNameError::EmptySuffix);
                }

                (slot, Some(field))
            },
            None => (value, None),
        };

        let slot_name =
            StorageSlotName::new(slot).map_err(StorageValueNameError::InvalidSlotName)?;
        let field = match field {
            Some(field) => {
                Self::validate_field_segment(field)?;
                Some(field.to_string())
            },
            None => None,
        };

        Ok(Self { slot_name, element_field: field })
    }
}

impl TryFrom<String> for StorageValueName {
    type Error = StorageValueNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<StorageValueName> for String {
    fn from(value: StorageValueName) -> Self {
        value.to_string()
    }
}

impl From<&StorageSlotName> for StorageValueName {
    fn from(value: &StorageSlotName) -> Self {
        StorageValueName::from_slot_name(value)
    }
}

impl Display for StorageValueName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.element_field {
            None => f.write_str(self.slot_name.as_str()),
            Some(field) => {
                f.write_str(self.slot_name.as_str())?;
                f.write_str(".")?;
                f.write_str(field)
            },
        }
    }
}

impl Serializable for StorageValueName {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let key = self.to_string();
        target.write(&key);
    }
}

impl Deserializable for StorageValueName {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let key: String = source.read()?;
        key.parse().map_err(|err: StorageValueNameError| {
            DeserializationError::InvalidValue(err.to_string())
        })
    }
}

#[derive(Debug, Error)]
pub enum StorageValueNameError {
    #[error("key segment is empty")]
    EmptySuffix,
    #[error("key segment '{part}' contains invalid character '{character}'")]
    InvalidCharacter { part: String, character: char },
    #[error("invalid storage slot name")]
    InvalidSlotName(#[source] StorageSlotNameError),
}
