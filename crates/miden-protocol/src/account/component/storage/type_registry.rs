use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use core::error::Error;
use core::fmt::{self, Display};

use miden_core::utils::{ByteReader, ByteWriter, Deserializable, Serializable};
use miden_core::{Felt, FieldElement, Word};
use miden_crypto::dsa::{ecdsa_k256_keccak, falcon512_rpo};
use miden_processor::DeserializationError;
use thiserror::Error;

use crate::asset::TokenSymbol;
use crate::utils::sync::LazyLock;

/// A global registry for schema type converters.
///
/// It is used during component instantiation to convert init-provided values (typically provided
/// as strings) into their respective storage values.
pub static SCHEMA_TYPE_REGISTRY: LazyLock<SchemaTypeRegistry> = LazyLock::new(|| {
    let mut registry = SchemaTypeRegistry::new();
    registry.register_felt_type::<Void>();
    registry.register_felt_type::<u8>();
    registry.register_felt_type::<u16>();
    registry.register_felt_type::<u32>();
    registry.register_felt_type::<Felt>();
    registry.register_felt_type::<TokenSymbol>();
    registry.register_word_type::<Word>();
    registry.register_word_type::<falcon512_rpo::PublicKey>();
    registry.register_word_type::<ecdsa_k256_keccak::PublicKey>();
    registry
});

// SCHEMA TYPE ERROR
// ================================================================================================

/// Errors that can occur when parsing or converting schema types.
///
/// This enum covers various failure cases including parsing errors, conversion errors,
/// unsupported conversions, and cases where a required type is not found in the registry.
#[derive(Debug, Error)]
pub enum SchemaTypeError {
    #[error("conversion error: {0}")]
    ConversionError(String),
    #[error("felt type ` {0}` not found in the type registry")]
    FeltTypeNotFound(SchemaTypeId),
    #[error("invalid type name `{0}`: {1}")]
    InvalidTypeName(String, String),
    #[error("failed to parse input `{input}` as `{schema_type}`")]
    ParseError {
        input: String,
        schema_type: SchemaTypeId,
        source: Box<dyn Error + Send + Sync + 'static>,
    },
    #[error("word type ` {0}` not found in the type registry")]
    WordTypeNotFound(SchemaTypeId),
}

impl SchemaTypeError {
    /// Creates a [`SchemaTypeError::ParseError`].
    pub fn parse(
        input: impl Into<String>,
        schema_type: SchemaTypeId,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        SchemaTypeError::ParseError {
            input: input.into(),
            schema_type,
            source: Box::new(source),
        }
    }
}

// SCHEMA TYPE
// ================================================================================================

/// A newtype wrapper around a `String`, representing a schema type identifier.
///
/// A valid schema identifier is a name in the style of Rust namespaces, composed of one or more
/// non-empty segments separated by `::`. Each segment can contain only ASCII alphanumerics or `_`.
///
/// Some examples:
/// - `u32`
/// - `felt`
/// - `miden::standards::auth::falcon512_rpo::pub_key`
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
#[cfg_attr(feature = "std", derive(::serde::Deserialize, ::serde::Serialize))]
#[cfg_attr(feature = "std", serde(transparent))]
pub struct SchemaTypeId(String);

impl SchemaTypeId {
    /// Creates a new [`SchemaTypeId`] from a `String`.
    ///
    /// The name must follow a Rust-style namespace format, consisting of one or more segments
    /// (non-empty, and alphanumerical) separated by double-colon (`::`) delimiters.
    ///
    /// # Errors
    ///
    /// - If the identifier is empty.
    /// - If any segment is empty or contains something other than alphanumerical
    ///   characters/underscores.
    pub fn new(s: impl Into<String>) -> Result<Self, SchemaTypeError> {
        let s = s.into();
        if s.is_empty() {
            return Err(SchemaTypeError::InvalidTypeName(
                s.clone(),
                "schema type identifier is empty".to_string(),
            ));
        }
        for segment in s.split("::") {
            if segment.is_empty() {
                return Err(SchemaTypeError::InvalidTypeName(
                    s.clone(),
                    "empty segment in schema type identifier".to_string(),
                ));
            }
            if !segment.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(SchemaTypeError::InvalidTypeName(
                    s.clone(),
                    format!("segment '{segment}' contains invalid characters"),
                ));
            }
        }
        Ok(Self(s))
    }

    /// Returns the schema type identifier for the `void` type.
    ///
    /// The `void` type always parses to `0` and is intended to model reserved or padding felts.
    pub fn void() -> SchemaTypeId {
        SchemaTypeId::new("void").expect("type is well formed")
    }

    /// Returns the schema type identifier for the native [`Felt`] type.
    pub fn native_felt() -> SchemaTypeId {
        SchemaTypeId::new("felt").expect("type is well formed")
    }

    /// Returns the schema type identifier for the native [`Word`] type.
    pub fn native_word() -> SchemaTypeId {
        SchemaTypeId::new("word").expect("type is well formed")
    }

    /// Returns the schema type identifier for the native `u8` type.
    pub fn u8() -> SchemaTypeId {
        SchemaTypeId::new("u8").expect("type is well formed")
    }

    /// Returns the schema type identifier for the native `u16` type.
    pub fn u16() -> SchemaTypeId {
        SchemaTypeId::new("u16").expect("type is well formed")
    }

    /// Returns the schema type identifier for the native `u32` type.
    pub fn u32() -> SchemaTypeId {
        SchemaTypeId::new("u32").expect("type is well formed")
    }

    /// Returns a reference to the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for SchemaTypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serializable for SchemaTypeId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.0.clone())
    }
}

impl Deserializable for SchemaTypeId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let id: String = source.read()?;

        SchemaTypeId::new(id).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// SCHEMA REQUIREMENT
// ================================================================================================

/// Describes the expected type and additional metadata for an init-provided storage value.
///
/// A schema requirement specifies the expected type identifier for an init value, along with
/// optional description and default value metadata.
///
/// The `default_value` (when present) is the canonical string representation for this type, and
/// can be used directly in [`InitStorageData`](super::InitStorageData).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaRequirement {
    /// The expected type identifier.
    pub r#type: SchemaTypeId,
    /// An optional description providing additional context.
    pub description: Option<String>,
    /// An optional default value, which can be overridden at component instantiation time.
    pub default_value: Option<String>,
}

// SCHEMA TYPE TRAITS
// ================================================================================================

/// Trait for converting a string into a single `Felt`.
pub trait FeltType: Send + Sync {
    /// Returns the type identifier.
    fn type_name() -> SchemaTypeId
    where
        Self: Sized;

    /// Parses the input string into a `Felt`.
    fn parse_str(input: &str) -> Result<Felt, SchemaTypeError>
    where
        Self: Sized;

    /// Displays a `Felt` in a canonical string representation for this type.
    fn display_felt(value: Felt) -> Result<String, SchemaTypeError>
    where
        Self: Sized;
}

/// Trait for converting a string into a single `Word`.
pub trait WordType: Send + Sync {
    /// Returns the type identifier.
    fn type_name() -> SchemaTypeId
    where
        Self: Sized;

    /// Parses the input string into a `Word`.
    fn parse_str(input: &str) -> Result<Word, SchemaTypeError>
    where
        Self: Sized;

    /// Displays a `Word` in a canonical string representation for this type.
    fn display_word(value: Word) -> Result<String, SchemaTypeError>
    where
        Self: Sized;
}

impl<T> WordType for T
where
    T: FeltType,
{
    fn type_name() -> SchemaTypeId {
        <T as FeltType>::type_name()
    }

    fn parse_str(input: &str) -> Result<Word, SchemaTypeError> {
        let felt = <T as FeltType>::parse_str(input)?;
        Ok(Word::from([Felt::new(0), Felt::new(0), Felt::new(0), felt]))
    }

    fn display_word(value: Word) -> Result<String, SchemaTypeError> {
        if value[0] != Felt::new(0) || value[1] != Felt::new(0) || value[2] != Felt::new(0) {
            return Err(SchemaTypeError::ConversionError(format!(
                "expected a word of the form [0, 0, 0, <felt>] for type `{}`",
                Self::type_name()
            )));
        }
        <T as FeltType>::display_felt(value[3])
    }
}

// FELT IMPLS FOR NATIVE TYPES
// ================================================================================================

/// A felt type that represents irrelevant elements in a storage schema definition.
struct Void;

impl FeltType for Void {
    fn type_name() -> SchemaTypeId {
        SchemaTypeId::void()
    }

    fn parse_str(input: &str) -> Result<Felt, SchemaTypeError> {
        let parsed = <Felt as FeltType>::parse_str(input)?;
        if parsed != Felt::new(0) {
            return Err(SchemaTypeError::ConversionError("void values must be zero".to_string()));
        }
        Ok(Felt::new(0))
    }

    fn display_felt(value: Felt) -> Result<String, SchemaTypeError> {
        if value != Felt::new(0) {
            return Err(SchemaTypeError::ConversionError("void values must be zero".to_string()));
        }
        Ok("0".into())
    }
}

impl FeltType for u8 {
    fn type_name() -> SchemaTypeId {
        SchemaTypeId::u8()
    }

    fn parse_str(input: &str) -> Result<Felt, SchemaTypeError> {
        let native: u8 = input.parse().map_err(|err| {
            SchemaTypeError::parse(input.to_string(), <Self as FeltType>::type_name(), err)
        })?;
        Ok(Felt::from(native))
    }

    fn display_felt(value: Felt) -> Result<String, SchemaTypeError> {
        let native = u8::try_from(value.as_int()).map_err(|_| {
            SchemaTypeError::ConversionError(format!("value `{}` is out of range for u8", value))
        })?;
        Ok(native.to_string())
    }
}

impl FeltType for u16 {
    fn type_name() -> SchemaTypeId {
        SchemaTypeId::u16()
    }

    fn parse_str(input: &str) -> Result<Felt, SchemaTypeError> {
        let native: u16 = input.parse().map_err(|err| {
            SchemaTypeError::parse(input.to_string(), <Self as FeltType>::type_name(), err)
        })?;
        Ok(Felt::from(native))
    }

    fn display_felt(value: Felt) -> Result<String, SchemaTypeError> {
        let native = u16::try_from(value.as_int()).map_err(|_| {
            SchemaTypeError::ConversionError(format!("value `{}` is out of range for u16", value))
        })?;
        Ok(native.to_string())
    }
}

impl FeltType for u32 {
    fn type_name() -> SchemaTypeId {
        SchemaTypeId::u32()
    }

    fn parse_str(input: &str) -> Result<Felt, SchemaTypeError> {
        let native: u32 = input.parse().map_err(|err| {
            SchemaTypeError::parse(input.to_string(), <Self as FeltType>::type_name(), err)
        })?;
        Ok(Felt::from(native))
    }

    fn display_felt(value: Felt) -> Result<String, SchemaTypeError> {
        let native = u32::try_from(value.as_int()).map_err(|_| {
            SchemaTypeError::ConversionError(format!("value `{}` is out of range for u32", value))
        })?;
        Ok(native.to_string())
    }
}

impl FeltType for Felt {
    fn type_name() -> SchemaTypeId {
        SchemaTypeId::new("felt").expect("type is well formed")
    }

    fn parse_str(input: &str) -> Result<Felt, SchemaTypeError> {
        let n = if let Some(hex) = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16)
        } else {
            input.parse::<u64>()
        }
        .map_err(|err| {
            SchemaTypeError::parse(input.to_string(), <Self as FeltType>::type_name(), err)
        })?;
        Felt::try_from(n).map_err(|_| SchemaTypeError::ConversionError(input.to_string()))
    }

    fn display_felt(value: Felt) -> Result<String, SchemaTypeError> {
        Ok(format!("0x{:x}", value.as_int()))
    }
}

impl FeltType for TokenSymbol {
    fn type_name() -> SchemaTypeId {
        SchemaTypeId::new("miden::standards::fungible_faucets::metadata::token_symbol")
            .expect("type is well formed")
    }
    fn parse_str(input: &str) -> Result<Felt, SchemaTypeError> {
        let token = TokenSymbol::new(input).map_err(|err| {
            SchemaTypeError::parse(input.to_string(), <Self as FeltType>::type_name(), err)
        })?;
        Ok(Felt::from(token))
    }

    fn display_felt(value: Felt) -> Result<String, SchemaTypeError> {
        let token = TokenSymbol::try_from(value).map_err(|err| {
            SchemaTypeError::ConversionError(format!(
                "invalid token_symbol value `{}`: {err}",
                value.as_int()
            ))
        })?;
        token.to_string().map_err(|err| {
            SchemaTypeError::ConversionError(format!(
                "failed to display token_symbol value `{}`: {err}",
                value.as_int()
            ))
        })
    }
}

// WORD IMPLS FOR NATIVE TYPES
// ================================================================================================

#[derive(Debug, Error)]
#[error("error parsing word: {0}")]
struct WordParseError(String);

/// Pads a hex string to 64 characters (excluding the 0x prefix).
///
/// If the input starts with "0x" and has fewer than 64 hex characters after the prefix,
/// it will be left-padded with zeros. Otherwise, returns the input unchanged.
fn pad_hex_string(input: &str) -> String {
    if input.starts_with("0x") && input.len() < 66 {
        // 66 = "0x" + 64 hex chars
        let hex_part = &input[2..];
        let padding = "0".repeat(64 - hex_part.len());
        format!("0x{}{}", padding, hex_part)
    } else {
        input.to_string()
    }
}

impl WordType for Word {
    fn type_name() -> SchemaTypeId {
        SchemaTypeId::native_word()
    }
    fn parse_str(input: &str) -> Result<Word, SchemaTypeError> {
        Word::parse(input).map_err(|err| {
            SchemaTypeError::parse(
                input.to_string(),
                Self::type_name(),
                WordParseError(err.to_string()),
            )
        })
    }

    fn display_word(value: Word) -> Result<String, SchemaTypeError> {
        Ok(value.to_string())
    }
}

impl WordType for falcon512_rpo::PublicKey {
    fn type_name() -> SchemaTypeId {
        SchemaTypeId::new("miden::standards::auth::falcon512_rpo::pub_key")
            .expect("type is well formed")
    }
    fn parse_str(input: &str) -> Result<Word, SchemaTypeError> {
        let padded_input = pad_hex_string(input);

        Word::try_from(padded_input.as_str()).map_err(|err| {
            SchemaTypeError::parse(
                input.to_string(), // Use original input in error
                Self::type_name(),
                WordParseError(err.to_string()),
            )
        })
    }

    fn display_word(value: Word) -> Result<String, SchemaTypeError> {
        Ok(value.to_string())
    }
}

impl WordType for ecdsa_k256_keccak::PublicKey {
    fn type_name() -> SchemaTypeId {
        SchemaTypeId::new("miden::standards::auth::ecdsa_k256_keccak::pub_key")
            .expect("type is well formed")
    }
    fn parse_str(input: &str) -> Result<Word, SchemaTypeError> {
        let padded_input = pad_hex_string(input);

        Word::try_from(padded_input.as_str()).map_err(|err| {
            SchemaTypeError::parse(
                input.to_string(),
                Self::type_name(),
                WordParseError(err.to_string()),
            )
        })
    }

    fn display_word(value: Word) -> Result<String, SchemaTypeError> {
        Ok(value.to_string())
    }
}

// TYPE ALIASES FOR CONVERTER CLOSURES
// ================================================================================================

/// Type alias for a function that converts a string into a [`Felt`] value.
type FeltFromStrConverter = fn(&str) -> Result<Felt, SchemaTypeError>;

/// Type alias for a function that converts a string into a [`Word`].
type WordFromStrConverter = fn(&str) -> Result<Word, SchemaTypeError>;

/// Type alias for a function that converts a [`Felt`] into a canonical string representation.
type FeltTypeDisplayer = fn(Felt) -> Result<String, SchemaTypeError>;

/// Type alias for a function that converts a [`Word`] into a canonical string representation.
type WordTypeDisplayer = fn(Word) -> Result<String, SchemaTypeError>;

/// Result of a word display conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordDisplay {
    Word(String),
    Felt(String),
    Hex(String),
}

impl WordDisplay {
    pub fn value(&self) -> &str {
        match self {
            WordDisplay::Word(v) => v,
            WordDisplay::Felt(v) => v,
            WordDisplay::Hex(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeKind {
    Word,
    Felt,
}

// SCHEMA TYPE REGISTRY
// ================================================================================================

/// Registry for schema type converters.
///
/// This registry maintains mappings from type identifiers (as strings) to conversion functions for
/// [`Felt`] and [`Word`] types. It is used to dynamically parse init-provided inputs into their
/// corresponding storage values.
#[derive(Clone, Debug, Default)]
pub struct SchemaTypeRegistry {
    felt: BTreeMap<SchemaTypeId, FeltFromStrConverter>,
    word: BTreeMap<SchemaTypeId, WordFromStrConverter>,
    felt_display: BTreeMap<SchemaTypeId, FeltTypeDisplayer>,
    word_display: BTreeMap<SchemaTypeId, WordTypeDisplayer>,
}

impl SchemaTypeRegistry {
    /// Creates a new, empty [`SchemaTypeRegistry`].
    ///
    /// The registry is initially empty and conversion functions can be registered using the
    /// `register_*_type` methods.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a `FeltType` converter, to interpret a string as a [`Felt``].
    pub fn register_felt_type<T: FeltType + 'static>(&mut self) {
        let key = <T as FeltType>::type_name();
        self.felt.insert(key.clone(), T::parse_str);
        self.felt_display.insert(key, T::display_felt);
    }

    /// Registers a `WordType` converter, to interpret a string as a [`Word`].
    pub fn register_word_type<T: WordType + 'static>(&mut self) {
        let key = <T as WordType>::type_name();
        self.word.insert(key.clone(), T::parse_str);
        self.word_display.insert(key, T::display_word);
    }

    /// Attempts to parse a string into a `Felt` using the registered converter for the given type
    /// name.
    ///
    /// # Arguments
    ///
    /// - type_name: A string that acts as the type identifier.
    /// - value: The string input that should be parsed.
    ///
    /// # Errors
    ///
    /// - If the type is not registered or if the conversion fails.
    pub fn try_parse_felt(
        &self,
        type_name: &SchemaTypeId,
        value: &str,
    ) -> Result<Felt, SchemaTypeError> {
        let converter = self
            .felt
            .get(type_name)
            .ok_or(SchemaTypeError::FeltTypeNotFound(type_name.clone()))?;
        converter(value)
    }

    /// Validates that the given [`Felt`] conforms to the specified schema type.
    pub fn validate_felt_value(
        &self,
        type_name: &SchemaTypeId,
        felt: Felt,
    ) -> Result<(), SchemaTypeError> {
        let display = self
            .felt_display
            .get(type_name)
            .ok_or(SchemaTypeError::FeltTypeNotFound(type_name.clone()))?;
        display(felt).map(|_| ())
    }

    // VALUE VALIDATION HELPERS
    // ============================================================================================

    /// Validates that the given [`Word`] conforms to the specified schema type.
    pub fn validate_word_value(
        &self,
        type_name: &SchemaTypeId,
        word: Word,
    ) -> Result<(), SchemaTypeError> {
        match self.type_kind(type_name) {
            TypeKind::Word => Ok(()),
            TypeKind::Felt => {
                // Felt types stored as words must have the form [0, 0, 0, <felt>]
                if word[0] != Felt::ZERO || word[1] != Felt::ZERO || word[2] != Felt::ZERO {
                    return Err(SchemaTypeError::ConversionError(format!(
                        "expected a word of the form [0, 0, 0, <felt>] for type `{type_name}`"
                    )));
                }
                self.validate_felt_value(type_name, word[3])
            },
        }
    }

    /// Converts a [`Felt`] into a canonical string representation for the given schema type.
    ///
    /// This is intended for serializing schemas to TOML (e.g. default values).
    #[allow(dead_code)]
    pub fn display_felt(&self, type_name: &SchemaTypeId, felt: Felt) -> String {
        self.felt_display
            .get(type_name)
            .and_then(|display| display(felt).ok())
            .unwrap_or_else(|| format!("0x{:x}", felt.as_int()))
    }

    /// Converts a [`Word`] into a canonical string representation and reports how it was produced.
    pub fn display_word(&self, type_name: &SchemaTypeId, word: Word) -> WordDisplay {
        if let Some(display) = self.word_display.get(type_name) {
            let value = display(word).unwrap_or_else(|_| word.to_string());
            return WordDisplay::Word(value);
        }

        // Treat any registered felt type as a word type by zero-padding the remaining felts.
        if self.contains_felt_type(type_name) {
            let value = self.display_felt(type_name, word[3]);
            return WordDisplay::Felt(value);
        }

        WordDisplay::Hex(word.to_hex())
    }

    /// Attempts to parse a string into a `Word` using the registered converter for the given type
    /// name.
    ///
    /// # Arguments
    ///
    /// - type_name: A string that acts as the type identifier.
    /// - value: The string input that should be parsed.
    ///
    /// # Errors
    ///
    /// - If the type is not registered or if the conversion fails.
    pub fn try_parse_word(
        &self,
        type_name: &SchemaTypeId,
        value: &str,
    ) -> Result<Word, SchemaTypeError> {
        if let Some(converter) = self.word.get(type_name) {
            return converter(value);
        }

        // Treat any registered felt type as a word type by zero-padding the remaining felts.
        if let Some(converter) = self.felt.get(type_name) {
            let felt = converter(value)?;
            return Ok(Word::from([Felt::new(0), Felt::new(0), Felt::new(0), felt]));
        }

        Err(SchemaTypeError::WordTypeNotFound(type_name.clone()))
    }

    /// Returns `true` if a `FeltType` is registered for the given type.
    pub fn contains_felt_type(&self, type_name: &SchemaTypeId) -> bool {
        self.felt.contains_key(type_name)
    }

    fn type_kind(&self, type_name: &SchemaTypeId) -> TypeKind {
        if self.contains_felt_type(type_name) {
            TypeKind::Felt
        } else {
            TypeKind::Word
        }
    }

    /// Returns `true` if a `WordType` is registered for the given type.
    ///
    /// This also returns `true` for any registered felt type (as those can be embedded into a word
    /// with zero-padding).
    pub fn contains_word_type(&self, type_name: &SchemaTypeId) -> bool {
        self.word.contains_key(type_name) || self.felt.contains_key(type_name)
    }
}
