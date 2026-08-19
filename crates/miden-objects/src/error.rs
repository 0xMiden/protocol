use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::any::type_name;
use core::fmt;

use miden_protocol::utils::serde::DeserializationError;

/// Error produced while converting a Protobuf message into a protocol object.
#[derive(Debug)]
pub struct ConversionError {
    path: Vec<String>,
    source: Box<dyn core::error::Error + Send + Sync>,
}

impl ConversionError {
    pub fn new(source: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self {
            path: Vec::new(),
            source: Box::new(source),
        }
    }

    #[must_use]
    pub fn context(mut self, field: impl Into<String>) -> Self {
        self.path.push(field.into());
        self
    }

    pub fn missing_field<T: prost::Message>(field_name: &'static str) -> Self {
        Self::message(format!("field {}::{field_name} is missing", type_name::<T>()))
    }

    pub fn deserialization(entity: &'static str, source: DeserializationError) -> Self {
        Self::message(format!("failed to deserialize {entity}: {source}"))
    }

    pub fn message(message: impl Into<String>) -> Self {
        Self {
            path: Vec::new(),
            source: Box::new(StringError(message.into())),
        }
    }
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, segment) in self.path.iter().rev().enumerate() {
            if index > 0 {
                f.write_str(".")?;
            }
            f.write_str(segment)?;
        }
        if !self.path.is_empty() {
            f.write_str(": ")?;
        }
        self.source.fmt(f)
    }
}

impl core::error::Error for ConversionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&*self.source)
    }
}

#[derive(Debug)]
struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for StringError {}

pub trait ConversionResultExt<T> {
    fn context(self, field: impl Into<String>) -> Result<T, ConversionError>;
}

impl<T, E: Into<ConversionError>> ConversionResultExt<T> for Result<T, E> {
    fn context(self, field: impl Into<String>) -> Result<T, ConversionError> {
        self.map_err(|error| error.into().context(field))
    }
}

macro_rules! impl_conversion_error_from {
    ($($ty:ty),* $(,)?) => {$(
        impl From<$ty> for ConversionError {
            fn from(error: $ty) -> Self {
                Self::new(error)
            }
        }
    )*};
}

impl_conversion_error_from!(
    core::convert::Infallible,
    core::num::TryFromIntError,
    DeserializationError,
    miden_protocol::crypto::merkle::MerkleError,
    miden_protocol::crypto::merkle::smt::SmtLeafError,
    miden_protocol::crypto::merkle::smt::SmtProofError,
    miden_protocol::errors::AccountError,
    miden_protocol::errors::AssetError,
    miden_protocol::errors::AssetVaultError,
    miden_protocol::errors::NoteError,
    miden_protocol::errors::StorageSlotNameError,
);

impl From<prost::UnknownEnumValue> for ConversionError {
    fn from(error: prost::UnknownEnumValue) -> Self {
        Self::message(error.to_string())
    }
}
