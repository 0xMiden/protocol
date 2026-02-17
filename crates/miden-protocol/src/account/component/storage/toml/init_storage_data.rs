use alloc::string::{String, ToString};

use serde::Deserialize;
use thiserror::Error;

use super::super::{
    InitStorageData,
    InitStorageDataError as CoreInitStorageDataError,
    StorageValueName,
    StorageValueNameError,
    WordValue,
};
use super::RawMapEntrySchema;

impl InitStorageData {
    /// Creates an instance of [`InitStorageData`] from a TOML string.
    ///
    /// # Supported formats
    ///
    /// ```toml
    /// # Value entry (string)
    /// "slot::name" = "0x1234"
    ///
    /// # Value entry (4-element word)
    /// "slot::name" = ["0", "0", "0", "100"]
    ///
    /// # Nested table (flattened to slot::name.field)
    /// ["slot::name"]
    /// field = "value"
    ///
    /// # Map entries
    /// "slot::map" = [
    ///     { key = "0x01", value = "0x10" },
    /// ]
    /// ```
    pub fn from_toml(toml_str: &str) -> Result<Self, InitStorageDataError> {
        let table: toml::Table = toml::from_str(toml_str)?;
        let mut data = InitStorageData::default();

        for (key, value) in table {
            let name: StorageValueName =
                key.parse().map_err(InitStorageDataError::InvalidStorageValueName)?;

            match value {
                // ["slot::name"]
                // field = "value"
                toml::Value::Table(nested) => {
                    if nested.is_empty() {
                        return Err(InitStorageDataError::EmptyTable(name.to_string()));
                    }
                    if name.field_name().is_some() {
                        return Err(InitStorageDataError::ExcessiveNesting(name.to_string()));
                    }
                    for (field, field_value) in nested {
                        let field_name =
                            StorageValueName::from_slot_name_with_suffix(name.slot_name(), &field)
                                .map_err(InitStorageDataError::InvalidStorageValueName)?;
                        let word = WordValue::deserialize(field_value).map_err(|_| {
                            InitStorageDataError::InvalidValue(field_name.to_string())
                        })?;
                        data.insert_value(field_name, word)?;
                    }
                },
                // "slot::name" = [{ key = "...", value = "..." }, ...]
                toml::Value::Array(items)
                    if items.iter().all(|v| matches!(v, toml::Value::Table(_))) =>
                {
                    if name.field_name().is_some() {
                        return Err(InitStorageDataError::InvalidMapEntryKey(name.to_string()));
                    }
                    for item in items {
                        // Try deserializing as map entry
                        let entry: RawMapEntrySchema = RawMapEntrySchema::deserialize(item)
                            .map_err(|e| {
                                InitStorageDataError::InvalidMapEntrySchema(e.to_string())
                            })?;

                        data.insert_map_entry(name.slot_name().clone(), entry.key, entry.value)?;
                    }
                },
                // "slot::name" = "value" or "slot::name" = ["a", "b", "c", "d"]
                other => {
                    let word = WordValue::deserialize(other)
                        .map_err(|_| InitStorageDataError::InvalidValue(name.to_string()))?;
                    data.insert_value(name, word)?;
                },
            }
        }

        Ok(data)
    }
}

#[derive(Debug, Error)]
pub enum InitStorageDataError {
    #[error("failed to parse TOML: {0}")]
    InvalidToml(#[from] toml::de::Error),

    #[error("empty table encountered for key `{0}`")]
    EmptyTable(String),

    #[error(transparent)]
    InvalidData(#[from] CoreInitStorageDataError),

    #[error("invalid map entry key `{0}`: map entries must target a slot name")]
    InvalidMapEntryKey(String),

    #[error("excessive nesting for key `{0}`: only one level of table nesting is allowed")]
    ExcessiveNesting(String),

    #[error(
        "invalid input for `{0}`: expected a string, a 4-element string array, or a map entry list"
    )]
    InvalidValue(String),

    #[error("invalid storage value name")]
    InvalidStorageValueName(#[source] StorageValueNameError),

    #[error("invalid map entry: {0}")]
    InvalidMapEntrySchema(String),
}
