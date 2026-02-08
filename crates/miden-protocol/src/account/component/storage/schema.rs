use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_crypto::utils::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

use super::type_registry::{SCHEMA_TYPE_REGISTRY, SchemaRequirement, SchemaTypeId};
use super::{InitStorageData, StorageValueName, WordValue};
use crate::account::storage::is_reserved_slot_name;
use crate::account::{StorageMap, StorageSlot, StorageSlotName};
use crate::errors::AccountComponentTemplateError;
use crate::{Felt, Word, ZERO};

// STORAGE SCHEMA
// ================================================================================================

/// Describes the storage schema of an account component in terms of its named storage slots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountStorageSchema {
    slots: BTreeMap<StorageSlotName, StorageSlotSchema>,
}

impl AccountStorageSchema {
    /// Creates a new [`AccountStorageSchema`].
    ///
    /// # Errors
    /// - If `fields` contains duplicate slot names.
    /// - If `fields` contains the protocol-reserved faucet metadata slot name.
    /// - If any slot schema is invalid.
    /// - If multiple schema fields map to the same init value name.
    pub fn new(
        slots: impl IntoIterator<Item = (StorageSlotName, StorageSlotSchema)>,
    ) -> Result<Self, AccountComponentTemplateError> {
        let mut map = BTreeMap::new();
        for (slot_name, schema) in slots {
            if map.insert(slot_name.clone(), schema).is_some() {
                return Err(AccountComponentTemplateError::DuplicateSlotName(slot_name));
            }
        }

        let schema = Self { slots: map };
        schema.validate()?;
        Ok(schema)
    }

    /// Returns an iterator over `(slot_name, schema)` pairs in slot-id order.
    pub fn iter(&self) -> impl Iterator<Item = (&StorageSlotName, &StorageSlotSchema)> {
        self.slots.iter()
    }

    /// Returns a reference to the underlying slots map.
    pub fn slots(&self) -> &BTreeMap<StorageSlotName, StorageSlotSchema> {
        &self.slots
    }

    /// Builds the initial [`StorageSlot`]s for this schema using the provided initialization data.
    pub fn build_storage_slots(
        &self,
        init_storage_data: &InitStorageData,
    ) -> Result<Vec<StorageSlot>, AccountComponentTemplateError> {
        self.slots
            .iter()
            .map(|(slot_name, schema)| schema.try_build_storage_slot(slot_name, init_storage_data))
            .collect()
    }

    /// Returns init-value requirements for the entire schema.
    ///
    /// The returned map includes both required values (no `default_value`) and optional values
    /// (with `default_value`), and excludes map entries.
    pub fn schema_requirements(
        &self,
    ) -> Result<BTreeMap<StorageValueName, SchemaRequirement>, AccountComponentTemplateError> {
        let mut requirements = BTreeMap::new();
        for (slot_name, schema) in self.slots.iter() {
            schema.collect_init_value_requirements(slot_name, &mut requirements)?;
        }
        Ok(requirements)
    }

    fn validate(&self) -> Result<(), AccountComponentTemplateError> {
        let mut init_values = BTreeMap::new();

        for (slot_name, schema) in self.slots.iter() {
            if is_reserved_slot_name(slot_name) {
                return Err(AccountComponentTemplateError::ReservedSlotName(slot_name.clone()));
            }

            schema.validate(slot_name)?;
            schema.collect_init_value_requirements(slot_name, &mut init_values)?;
        }

        Ok(())
    }
}

impl Serializable for AccountStorageSchema {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(self.slots.len() as u16);
        for (slot_name, schema) in self.slots.iter() {
            target.write(slot_name);
            target.write(schema);
        }
    }
}

impl Deserializable for AccountStorageSchema {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_entries = source.read_u16()? as usize;
        let mut fields = BTreeMap::new();

        for _ in 0..num_entries {
            let slot_name = StorageSlotName::read_from(source)?;
            let schema = StorageSlotSchema::read_from(source)?;

            if fields.insert(slot_name.clone(), schema).is_some() {
                return Err(DeserializationError::InvalidValue(format!(
                    "duplicate slot name in storage schema: {slot_name}",
                )));
            }
        }

        let schema = AccountStorageSchema::new(fields)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
        Ok(schema)
    }
}

// STORAGE SLOT SCHEMA
// ================================================================================================

/// Describes the schema for a storage slot.
/// Can describe either a value slot, or a map slot.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageSlotSchema {
    Value(ValueSlotSchema),
    Map(MapSlotSchema),
}

impl StorageSlotSchema {
    fn collect_init_value_requirements(
        &self,
        slot_name: &StorageSlotName,
        requirements: &mut BTreeMap<StorageValueName, SchemaRequirement>,
    ) -> Result<(), AccountComponentTemplateError> {
        let slot_prefix = StorageValueName::from_slot_name(slot_name);
        match self {
            StorageSlotSchema::Value(slot) => {
                slot.collect_init_value_requirements(slot_prefix, requirements)
            },
            StorageSlotSchema::Map(_) => Ok(()),
        }
    }

    /// Builds a [`StorageSlot`] for the specified `slot_name` using the provided initialization
    /// data.
    pub fn try_build_storage_slot(
        &self,
        slot_name: &StorageSlotName,
        init_storage_data: &InitStorageData,
    ) -> Result<StorageSlot, AccountComponentTemplateError> {
        let slot_prefix = StorageValueName::from_slot_name(slot_name);
        match self {
            StorageSlotSchema::Value(slot) => {
                let word = slot.try_build_word(init_storage_data, slot_prefix)?;
                Ok(StorageSlot::with_value(slot_name.clone(), word))
            },
            StorageSlotSchema::Map(slot) => {
                let storage_map = slot.try_build_map(init_storage_data, slot_prefix)?;
                Ok(StorageSlot::with_map(slot_name.clone(), storage_map))
            },
        }
    }

    pub(crate) fn validate(
        &self,
        slot_name: &StorageSlotName,
    ) -> Result<(), AccountComponentTemplateError> {
        match self {
            StorageSlotSchema::Value(slot) => slot.validate(slot_name)?,
            StorageSlotSchema::Map(slot) => slot.validate()?,
        }

        Ok(())
    }
}

impl Serializable for StorageSlotSchema {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            StorageSlotSchema::Value(slot) => {
                target.write_u8(0u8);
                slot.write_into(target);
            },
            StorageSlotSchema::Map(slot) => {
                target.write_u8(1u8);
                slot.write_into(target);
            },
        }
    }
}

impl Deserializable for StorageSlotSchema {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let variant_tag = source.read_u8()?;
        match variant_tag {
            0 => Ok(StorageSlotSchema::Value(ValueSlotSchema::read_from(source)?)),
            1 => Ok(StorageSlotSchema::Map(MapSlotSchema::read_from(source)?)),
            _ => Err(DeserializationError::InvalidValue(format!(
                "unknown variant tag '{variant_tag}' for StorageSlotSchema"
            ))),
        }
    }
}

// WORDS
// ================================================================================================

/// Defines how a word slot is described within the component's storage schema.
///
/// Each word schema can either describe a whole-word typed value supplied at instantiation time
/// (`Simple`) or a composite word that explicitly defines each felt element (`Composite`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum WordSchema {
    /// A whole-word typed value supplied at instantiation time.
    Simple {
        r#type: SchemaTypeId,
        default_value: Option<Word>,
    },
    /// A composed word that may mix defaults and typed fields.
    Composite { value: [FeltSchema; 4] },
}

impl WordSchema {
    pub fn new_simple(r#type: SchemaTypeId) -> Self {
        WordSchema::Simple { r#type, default_value: None }
    }

    pub fn new_simple_with_default(r#type: SchemaTypeId, default_value: Word) -> Self {
        WordSchema::Simple {
            r#type,
            default_value: Some(default_value),
        }
    }

    pub fn new_value(value: impl Into<[FeltSchema; 4]>) -> Self {
        WordSchema::Composite { value: value.into() }
    }

    pub fn value(&self) -> Option<&[FeltSchema; 4]> {
        match self {
            WordSchema::Composite { value } => Some(value),
            WordSchema::Simple { .. } => None,
        }
    }

    /// Returns the schema type identifier associated with whole-word init-supplied values.
    pub fn word_type(&self) -> SchemaTypeId {
        match self {
            WordSchema::Simple { r#type, .. } => r#type.clone(),
            WordSchema::Composite { .. } => SchemaTypeId::native_word(),
        }
    }

    fn collect_init_value_requirements(
        &self,
        slot_prefix: StorageValueName,
        description: Option<String>,
        requirements: &mut BTreeMap<StorageValueName, SchemaRequirement>,
    ) -> Result<(), AccountComponentTemplateError> {
        match self {
            WordSchema::Simple { r#type, default_value } => {
                if *r#type == SchemaTypeId::void() {
                    return Ok(());
                }

                let default_value = default_value.map(|word| {
                    SCHEMA_TYPE_REGISTRY.display_word(r#type, word).value().to_string()
                });

                if requirements
                    .insert(
                        slot_prefix.clone(),
                        SchemaRequirement {
                            description,
                            r#type: r#type.clone(),
                            default_value,
                        },
                    )
                    .is_some()
                {
                    return Err(AccountComponentTemplateError::DuplicateInitValueName(slot_prefix));
                }

                Ok(())
            },
            WordSchema::Composite { value } => {
                for felt in value.iter() {
                    felt.collect_init_value_requirements(slot_prefix.clone(), requirements)?;
                }
                Ok(())
            },
        }
    }

    /// Validates that the defined word type exists and its inner felts (if any) are valid.
    fn validate(&self) -> Result<(), AccountComponentTemplateError> {
        let type_exists = SCHEMA_TYPE_REGISTRY.contains_word_type(&self.word_type());
        if !type_exists {
            return Err(AccountComponentTemplateError::InvalidType(
                self.word_type().to_string(),
                "Word".into(),
            ));
        }

        if let WordSchema::Simple {
            r#type,
            default_value: Some(default_value),
        } = self
        {
            SCHEMA_TYPE_REGISTRY
                .validate_word_value(r#type, *default_value)
                .map_err(AccountComponentTemplateError::StorageValueParsingError)?;
        }

        if let Some(felts) = self.value() {
            for felt in felts {
                felt.validate()?;
            }
        }

        Ok(())
    }

    pub(crate) fn try_build_word(
        &self,
        init_storage_data: &InitStorageData,
        value_prefix: StorageValueName,
    ) -> Result<Word, AccountComponentTemplateError> {
        match self {
            WordSchema::Simple { r#type, default_value } => {
                let value_name = value_prefix;
                match init_storage_data.get(&value_name) {
                    Some(WordValue::Atomic(raw)) => SCHEMA_TYPE_REGISTRY
                        .try_parse_word(r#type, raw)
                        .map_err(AccountComponentTemplateError::StorageValueParsingError),
                    Some(WordValue::Elements(elements)) => {
                        let felts = elements
                            .iter()
                            .map(|element| {
                                SCHEMA_TYPE_REGISTRY
                                    .try_parse_felt(&SchemaTypeId::native_felt(), element)
                            })
                            .collect::<Result<Vec<Felt>, _>>()
                            .map_err(AccountComponentTemplateError::StorageValueParsingError)?;
                        let felts: [Felt; 4] = felts.try_into().expect("length is 4");
                        let word = Word::from(felts);
                        SCHEMA_TYPE_REGISTRY
                            .validate_word_value(r#type, word)
                            .map_err(AccountComponentTemplateError::StorageValueParsingError)?;
                        Ok(word)
                    },
                    None => {
                        if *r#type == SchemaTypeId::void() {
                            Ok(Word::empty())
                        } else {
                            default_value.as_ref().copied().ok_or_else(|| {
                                AccountComponentTemplateError::InitValueNotProvided(value_name)
                            })
                        }
                    },
                }
            },
            WordSchema::Composite { value } => {
                let mut result = [ZERO; 4];
                for (index, felt_schema) in value.iter().enumerate() {
                    result[index] =
                        felt_schema.try_build_felt(init_storage_data, value_prefix.clone())?;
                }
                Ok(Word::from(result))
            },
        }
    }

    pub(crate) fn validate_word_value(
        &self,
        slot_prefix: &StorageValueName,
        label: &str,
        word: Word,
    ) -> Result<(), AccountComponentTemplateError> {
        match self {
            WordSchema::Simple { r#type, .. } => {
                SCHEMA_TYPE_REGISTRY.validate_word_value(r#type, word).map_err(|err| {
                    AccountComponentTemplateError::InvalidInitStorageValue(
                        slot_prefix.clone(),
                        format!("{label} does not match `{}`: {err}", r#type),
                    )
                })
            },
            WordSchema::Composite { value } => {
                for (index, felt_schema) in value.iter().enumerate() {
                    let felt_type = felt_schema.felt_type();
                    SCHEMA_TYPE_REGISTRY.validate_felt_value(&felt_type, word[index]).map_err(
                        |err| {
                            AccountComponentTemplateError::InvalidInitStorageValue(
                                slot_prefix.clone(),
                                format!("{label}[{index}] does not match `{felt_type}`: {err}"),
                            )
                        },
                    )?;
                }

                Ok(())
            },
        }
    }
}

impl Serializable for WordSchema {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            WordSchema::Simple { r#type, default_value } => {
                target.write_u8(0);
                target.write(r#type);
                target.write(default_value);
            },
            WordSchema::Composite { value } => {
                target.write_u8(1);
                target.write(value);
            },
        }
    }
}

impl Deserializable for WordSchema {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag = source.read_u8()?;
        match tag {
            0 => {
                let r#type = SchemaTypeId::read_from(source)?;
                let default_value = Option::<Word>::read_from(source)?;
                Ok(WordSchema::Simple { r#type, default_value })
            },
            1 => {
                let value = <[FeltSchema; 4]>::read_from(source)?;
                Ok(WordSchema::Composite { value })
            },
            other => Err(DeserializationError::InvalidValue(format!(
                "unknown tag '{other}' for WordSchema"
            ))),
        }
    }
}

impl From<[FeltSchema; 4]> for WordSchema {
    fn from(value: [FeltSchema; 4]) -> Self {
        WordSchema::new_value(value)
    }
}

impl From<[Felt; 4]> for WordSchema {
    fn from(value: [Felt; 4]) -> Self {
        WordSchema::new_simple_with_default(SchemaTypeId::native_word(), Word::from(value))
    }
}

// FELT SCHEMA
// ================================================================================================

/// Supported element schema descriptors for a component's storage entries.
///
/// Each felt element in a composed word slot is typed, can have an optional default value, and can
/// optionally be named to allow overriding at instantiation time.
///
/// To avoid non-overridable constants, unnamed elements are allowed only when `type = "void"`,
/// which always evaluates to `0` and does not require init data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeltSchema {
    name: Option<String>,
    description: Option<String>,
    r#type: SchemaTypeId,
    default_value: Option<Felt>,
}

impl FeltSchema {
    /// Creates a new required typed felt field.
    pub fn new_typed(r#type: SchemaTypeId, name: impl Into<String>) -> Self {
        FeltSchema {
            name: Some(name.into()),
            description: None,
            r#type,
            default_value: None,
        }
    }

    /// Creates a new typed felt field with a default value.
    pub fn new_typed_with_default(
        r#type: SchemaTypeId,
        name: impl Into<String>,
        default_value: Felt,
    ) -> Self {
        FeltSchema {
            name: Some(name.into()),
            description: None,
            r#type,
            default_value: Some(default_value),
        }
    }

    /// Creates an unnamed `void` felt element.
    pub fn new_void() -> Self {
        FeltSchema {
            name: None,
            description: None,
            r#type: SchemaTypeId::void(),
            default_value: None,
        }
    }

    /// Sets the description of the [`FeltSchema`] and returns `self`.
    pub fn with_description(self, description: impl Into<String>) -> Self {
        FeltSchema {
            description: Some(description.into()),
            ..self
        }
    }

    /// Returns the felt type.
    pub fn felt_type(&self) -> SchemaTypeId {
        self.r#type.clone()
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn description(&self) -> Option<&String> {
        self.description.as_ref()
    }

    pub fn default_value(&self) -> Option<Felt> {
        self.default_value
    }

    fn collect_init_value_requirements(
        &self,
        slot_prefix: StorageValueName,
        requirements: &mut BTreeMap<StorageValueName, SchemaRequirement>,
    ) -> Result<(), AccountComponentTemplateError> {
        if self.r#type == SchemaTypeId::void() {
            return Ok(());
        }

        let Some(name) = self.name.as_deref() else {
            return Err(AccountComponentTemplateError::InvalidSchema(
                "non-void felt elements must be named".into(),
            ));
        };
        let value_name = slot_prefix
            .clone()
            .with_suffix(name)
            .map_err(|err| AccountComponentTemplateError::InvalidSchema(err.to_string()))?;

        let default_value = self
            .default_value
            .map(|felt| SCHEMA_TYPE_REGISTRY.display_felt(&self.r#type, felt));

        if requirements
            .insert(
                value_name.clone(),
                SchemaRequirement {
                    description: self.description.clone(),
                    r#type: self.r#type.clone(),
                    default_value,
                },
            )
            .is_some()
        {
            return Err(AccountComponentTemplateError::DuplicateInitValueName(value_name));
        }

        Ok(())
    }

    /// Attempts to convert the [`FeltSchema`] into a [`Felt`].
    ///
    /// If the schema variant is typed, the value is retrieved from `init_storage_data`,
    /// identified by its key. Otherwise, the returned value is just the inner element.
    pub(crate) fn try_build_felt(
        &self,
        init_storage_data: &InitStorageData,
        value_prefix: StorageValueName,
    ) -> Result<Felt, AccountComponentTemplateError> {
        let value_name =
            match self.name.as_deref() {
                Some(name) => Some(value_prefix.with_suffix(name).map_err(|err| {
                    AccountComponentTemplateError::InvalidSchema(err.to_string())
                })?),
                None => None,
            };

        if let Some(value_name) = value_name.clone() {
            match init_storage_data.get(&value_name) {
                Some(WordValue::Atomic(raw)) => {
                    let felt = SCHEMA_TYPE_REGISTRY
                        .try_parse_felt(&self.r#type, raw)
                        .map_err(AccountComponentTemplateError::StorageValueParsingError)?;
                    return Ok(felt);
                },
                Some(WordValue::Elements(_)) => {
                    return Err(AccountComponentTemplateError::InvalidInitStorageValue(
                        value_name,
                        "expected an atomic value, got a 4-element array".into(),
                    ));
                },
                None => {},
            }
        }

        if self.r#type == SchemaTypeId::void() {
            return Ok(ZERO);
        }

        if let Some(default_value) = self.default_value {
            return Ok(default_value);
        }

        let Some(value_name) = value_name else {
            return Err(AccountComponentTemplateError::InvalidSchema(
                "non-void felt elements must be named".into(),
            ));
        };

        Err(AccountComponentTemplateError::InitValueNotProvided(value_name))
    }

    /// Validates that the defined felt type exists.
    fn validate(&self) -> Result<(), AccountComponentTemplateError> {
        let type_exists = SCHEMA_TYPE_REGISTRY.contains_felt_type(&self.felt_type());
        if !type_exists {
            return Err(AccountComponentTemplateError::InvalidType(
                self.felt_type().to_string(),
                "Felt".into(),
            ));
        }

        if self.r#type == SchemaTypeId::void() {
            if self.name.is_some() {
                return Err(AccountComponentTemplateError::InvalidSchema(
                    "void felt elements must be unnamed".into(),
                ));
            }
            if self.default_value.is_some() {
                return Err(AccountComponentTemplateError::InvalidSchema(
                    "void felt elements cannot define `default-value`".into(),
                ));
            }
            return Ok(());
        }

        if self.name.is_none() {
            return Err(AccountComponentTemplateError::InvalidSchema(
                "non-void felt elements must be named".into(),
            ));
        }

        if let Some(value) = self.default_value {
            SCHEMA_TYPE_REGISTRY
                .validate_felt_value(&self.felt_type(), value)
                .map_err(AccountComponentTemplateError::StorageValueParsingError)?;
        }
        Ok(())
    }
}

impl Serializable for FeltSchema {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.name);
        target.write(&self.description);
        target.write(&self.r#type);
        target.write(self.default_value);
    }
}

impl Deserializable for FeltSchema {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name = Option::<String>::read_from(source)?;
        let description = Option::<String>::read_from(source)?;
        let r#type = SchemaTypeId::read_from(source)?;
        let default_value = Option::<Felt>::read_from(source)?;
        Ok(FeltSchema { name, description, r#type, default_value })
    }
}

/// Describes the schema for a storage value slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueSlotSchema {
    description: Option<String>,
    word: WordSchema,
}

impl ValueSlotSchema {
    pub fn new(description: Option<String>, word: WordSchema) -> Self {
        Self { description, word }
    }

    pub fn description(&self) -> Option<&String> {
        self.description.as_ref()
    }

    pub fn word(&self) -> &WordSchema {
        &self.word
    }

    fn collect_init_value_requirements(
        &self,
        slot_prefix: StorageValueName,
        requirements: &mut BTreeMap<StorageValueName, SchemaRequirement>,
    ) -> Result<(), AccountComponentTemplateError> {
        self.word.collect_init_value_requirements(
            slot_prefix,
            self.description.clone(),
            requirements,
        )
    }

    pub fn try_build_word(
        &self,
        init_storage_data: &InitStorageData,
        value_prefix: StorageValueName,
    ) -> Result<Word, AccountComponentTemplateError> {
        self.word.try_build_word(init_storage_data, value_prefix)
    }

    pub(crate) fn validate(
        &self,
        _slot_name: &StorageSlotName,
    ) -> Result<(), AccountComponentTemplateError> {
        self.word.validate()?;
        Ok(())
    }
}

impl Serializable for ValueSlotSchema {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.description);
        target.write(&self.word);
    }
}

impl Deserializable for ValueSlotSchema {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let description = Option::<String>::read_from(source)?;
        let word = WordSchema::read_from(source)?;
        Ok(ValueSlotSchema::new(description, word))
    }
}

/// Describes the schema for a storage map slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSlotSchema {
    description: Option<String>,
    default_values: Option<BTreeMap<Word, Word>>,
    key_schema: WordSchema,
    value_schema: WordSchema,
}

impl MapSlotSchema {
    pub fn new(
        description: Option<String>,
        default_values: Option<BTreeMap<Word, Word>>,
        key_schema: WordSchema,
        value_schema: WordSchema,
    ) -> Self {
        Self {
            description,
            default_values,
            key_schema,
            value_schema,
        }
    }

    pub fn description(&self) -> Option<&String> {
        self.description.as_ref()
    }

    pub fn try_build_map(
        &self,
        init_storage_data: &InitStorageData,
        slot_prefix: StorageValueName,
    ) -> Result<StorageMap, AccountComponentTemplateError> {
        let mut entries = self.default_values.clone().unwrap_or_default();

        if init_storage_data.get(&slot_prefix).is_some()
            && init_storage_data.map_entries(&slot_prefix).is_none()
        {
            return Err(AccountComponentTemplateError::InvalidInitStorageValue(
                slot_prefix,
                "expected a map, got a value".into(),
            ));
        }

        if let Some(init_entries) = init_storage_data.map_entries(&slot_prefix) {
            let mut parsed_entries = Vec::with_capacity(init_entries.len());
            for (index, (raw_key, raw_value)) in init_entries.iter().enumerate() {
                let key_label = format!("map entry[{index}].key");
                let value_label = format!("map entry[{index}].value");

                let key = parse_word_value_with_schema(
                    &self.key_schema,
                    raw_key,
                    &slot_prefix,
                    key_label.as_str(),
                )?;
                let value = parse_word_value_with_schema(
                    &self.value_schema,
                    raw_value,
                    &slot_prefix,
                    value_label.as_str(),
                )?;

                parsed_entries.push((key, value));
            }

            // Reject duplicate keys in init-provided entries.
            let _ = StorageMap::with_entries(parsed_entries.iter().copied()).map_err(|err| {
                AccountComponentTemplateError::StorageMapHasDuplicateKeys(Box::new(err))
            })?;

            for (key, value) in parsed_entries.iter() {
                entries.insert(*key, *value);
            }
        }

        if entries.is_empty() {
            return Ok(StorageMap::new());
        }

        StorageMap::with_entries(entries)
            .map_err(|err| AccountComponentTemplateError::StorageMapHasDuplicateKeys(Box::new(err)))
    }

    pub fn key_schema(&self) -> &WordSchema {
        &self.key_schema
    }

    pub fn value_schema(&self) -> &WordSchema {
        &self.value_schema
    }

    pub fn default_values(&self) -> Option<BTreeMap<Word, Word>> {
        self.default_values.clone()
    }

    fn validate(&self) -> Result<(), AccountComponentTemplateError> {
        self.key_schema.validate()?;
        self.value_schema.validate()?;
        Ok(())
    }
}

pub(super) fn parse_word_value_with_schema(
    schema: &WordSchema,
    raw_value: &WordValue,
    slot_prefix: &StorageValueName,
    label: &str,
) -> Result<Word, AccountComponentTemplateError> {
    match schema {
        WordSchema::Simple { r#type, .. } => match raw_value {
            WordValue::Atomic(value) => {
                SCHEMA_TYPE_REGISTRY.try_parse_word(r#type, value).map_err(|err| {
                    AccountComponentTemplateError::InvalidInitStorageValue(
                        slot_prefix.clone(),
                        format!("failed to parse {label} as `{}`: {err}", r#type),
                    )
                })
            },
            WordValue::Elements(elements) => {
                let felts: Vec<Felt> = elements
                    .iter()
                    .map(|element| {
                        SCHEMA_TYPE_REGISTRY.try_parse_felt(&SchemaTypeId::native_felt(), element)
                    })
                    .collect::<Result<_, _>>()
                    .map_err(|err| {
                        AccountComponentTemplateError::InvalidInitStorageValue(
                            slot_prefix.clone(),
                            format!("failed to parse {label} element as `felt`: {err}"),
                        )
                    })?;
                let felts: [Felt; 4] = felts.try_into().expect("length is 4");
                let word = Word::from(felts);
                schema.validate_word_value(slot_prefix, label, word)?;
                Ok(word)
            },
        },
        WordSchema::Composite { value } => match raw_value {
            WordValue::Elements(elements) => {
                let mut felts = [ZERO; 4];
                for index in 0..4 {
                    let felt_type = value[index].felt_type();
                    felts[index] = SCHEMA_TYPE_REGISTRY
                        .try_parse_felt(&felt_type, &elements[index])
                        .map_err(|err| {
                            AccountComponentTemplateError::InvalidInitStorageValue(
                                slot_prefix.clone(),
                                format!("failed to parse {label}[{index}] as `{felt_type}`: {err}"),
                            )
                        })?;
                }

                Ok(Word::from(felts))
            },
            WordValue::Atomic(value) => {
                Err(AccountComponentTemplateError::InvalidInitStorageValue(
                    slot_prefix.clone(),
                    format!(
                        "{label} must be an array of 4 elements for a composite schema, got atomic `{value}`"
                    ),
                ))
            },
        },
    }
}

impl Serializable for MapSlotSchema {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.description);
        target.write(&self.default_values);
        target.write(&self.key_schema);
        target.write(&self.value_schema);
    }
}

impl Deserializable for MapSlotSchema {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let description = Option::<String>::read_from(source)?;
        let default_values = Option::<BTreeMap<Word, Word>>::read_from(source)?;
        let key_schema = WordSchema::read_from(source)?;
        let value_schema = WordSchema::read_from(source)?;
        Ok(MapSlotSchema::new(description, default_values, key_schema, value_schema))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use super::*;

    #[test]
    fn map_slot_schema_default_values_returns_map() {
        let word_schema = WordSchema::new_simple(SchemaTypeId::native_word());
        let mut default_values = BTreeMap::new();
        default_values.insert(
            Word::from([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]),
            Word::from([Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13)]),
        );
        let slot = MapSlotSchema::new(
            Some("static map".into()),
            Some(default_values),
            word_schema.clone(),
            word_schema,
        );

        let mut expected = BTreeMap::new();
        expected.insert(
            Word::from([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]),
            Word::from([Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13)]),
        );

        assert_eq!(slot.default_values(), Some(expected));
    }

    #[test]
    fn value_slot_schema_exposes_felt_schema_types() {
        let felt_values = [
            FeltSchema::new_typed(SchemaTypeId::u8(), "a"),
            FeltSchema::new_typed(SchemaTypeId::u16(), "b"),
            FeltSchema::new_typed(SchemaTypeId::u32(), "c"),
            FeltSchema::new_typed(SchemaTypeId::new("felt").unwrap(), "d"),
        ];

        let slot = ValueSlotSchema::new(None, WordSchema::new_value(felt_values));
        let WordSchema::Composite { value } = slot.word() else {
            panic!("expected composite word schema");
        };

        assert_eq!(value[0].felt_type(), SchemaTypeId::u8());
        assert_eq!(value[1].felt_type(), SchemaTypeId::u16());
        assert_eq!(value[2].felt_type(), SchemaTypeId::u32());
        assert_eq!(value[3].felt_type(), SchemaTypeId::new("felt").unwrap());
    }

    #[test]
    fn map_slot_schema_key_and_value_types() {
        let key_schema = WordSchema::new_simple(SchemaTypeId::new("sampling::Key").unwrap());

        let value_schema = WordSchema::new_value([
            FeltSchema::new_typed(SchemaTypeId::native_felt(), "a"),
            FeltSchema::new_typed(SchemaTypeId::native_felt(), "b"),
            FeltSchema::new_typed(SchemaTypeId::native_felt(), "c"),
            FeltSchema::new_typed(SchemaTypeId::native_felt(), "d"),
        ]);

        let slot = MapSlotSchema::new(None, None, key_schema, value_schema);

        assert_eq!(
            slot.key_schema(),
            &WordSchema::new_simple(SchemaTypeId::new("sampling::Key").unwrap())
        );

        let WordSchema::Composite { value } = slot.value_schema() else {
            panic!("expected composite word schema for map values");
        };
        for felt in value.iter() {
            assert_eq!(felt.felt_type(), SchemaTypeId::native_felt());
        }
    }

    #[test]
    fn value_slot_schema_accepts_typed_word_init_value() {
        let slot = ValueSlotSchema::new(None, WordSchema::new_simple(SchemaTypeId::native_word()));
        let slot_prefix: StorageValueName = "demo::slot".parse().unwrap();

        let expected = Word::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
        let init_data =
            InitStorageData::new([(slot_prefix.clone(), expected.to_string().into())], []);

        let built = slot.try_build_word(&init_data, slot_prefix).unwrap();
        assert_eq!(built, expected);
    }

    #[test]
    fn value_slot_schema_accepts_felt_typed_word_init_value() {
        let slot = ValueSlotSchema::new(None, WordSchema::new_simple(SchemaTypeId::u8()));
        let slot_prefix: StorageValueName = "demo::u8_word".parse().unwrap();

        let init_data = InitStorageData::new([(slot_prefix.clone(), "6".into())], []);

        let built = slot.try_build_word(&init_data, slot_prefix).unwrap();
        assert_eq!(built, Word::from([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(6)]));
    }

    #[test]
    fn value_slot_schema_accepts_typed_felt_init_value_in_composed_word() {
        let word = WordSchema::new_value([
            FeltSchema::new_typed(SchemaTypeId::u8(), "a"),
            FeltSchema::new_typed_with_default(SchemaTypeId::native_felt(), "b", Felt::new(2)),
            FeltSchema::new_typed_with_default(SchemaTypeId::native_felt(), "c", Felt::new(3)),
            FeltSchema::new_typed_with_default(SchemaTypeId::native_felt(), "d", Felt::new(4)),
        ]);
        let slot = ValueSlotSchema::new(None, word);

        let init_data = InitStorageData::new([("demo::slot.a".parse().unwrap(), "1".into())], []);

        let built = slot.try_build_word(&init_data, "demo::slot".parse().unwrap()).unwrap();
        assert_eq!(built, Word::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]));
    }

    #[test]
    fn map_slot_schema_accepts_typed_map_init_value() {
        let word_schema = WordSchema::new_simple(SchemaTypeId::native_word());
        let slot = MapSlotSchema::new(None, None, word_schema.clone(), word_schema);
        let slot_prefix: StorageValueName = "demo::map".parse().unwrap();

        let entries = vec![(
            WordValue::Elements(["1".into(), "0".into(), "0".into(), "0".into()]),
            WordValue::Elements(["10".into(), "11".into(), "12".into(), "13".into()]),
        )];
        let init_data = InitStorageData::new([], [(slot_prefix.clone(), entries.clone())]);

        let built = slot.try_build_map(&init_data, slot_prefix).unwrap();
        let expected = StorageMap::with_entries([(
            Word::from([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]),
            Word::from([Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13)]),
        )])
        .unwrap();
        assert_eq!(built, expected);
    }

    #[test]
    fn map_slot_schema_missing_init_value_defaults_to_empty_map() {
        let word_schema = WordSchema::new_simple(SchemaTypeId::native_word());
        let slot = MapSlotSchema::new(None, None, word_schema.clone(), word_schema);
        let built = slot
            .try_build_map(&InitStorageData::default(), "demo::map".parse().unwrap())
            .unwrap();
        assert_eq!(built, StorageMap::new());
    }
}
