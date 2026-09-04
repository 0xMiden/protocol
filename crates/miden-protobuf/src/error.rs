use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::any::type_name;
use core::error::Error;
use core::fmt;

/// Error produced while converting a Protobuf message into a domain object.
#[derive(Debug)]
pub struct ConversionError {
    path: Vec<String>,
    source: Box<dyn core::error::Error + Send + Sync>,
}

impl ConversionError {
    pub fn new(source: impl Error + Send + Sync + 'static) -> Self {
        let source: Box<dyn Error + Send + Sync> = Box::new(source);
        match source.downcast::<Self>() {
            Ok(error) => *error,
            Err(source) => Self { path: Vec::new(), source },
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

    pub fn deserialization(
        entity: &'static str,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        let message = format!("failed to deserialize {entity}: {source}");
        Self::with_source(message, source)
    }

    pub fn message(message: impl Into<String>) -> Self {
        Self {
            path: Vec::new(),
            source: Box::new(StringError(message.into())),
        }
    }

    pub fn with_source(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self::new(ContextualError {
            message: message.into(),
            source: Box::new(source),
        })
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

impl Error for ConversionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
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

impl Error for StringError {}

#[derive(Debug)]
struct ContextualError {
    message: String,
    source: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for ContextualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ContextualError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.source)
    }
}

pub trait ConversionResultExt<T> {
    fn context(self, field: impl Into<String>) -> Result<T, ConversionError>;
}

impl<T, E> ConversionResultExt<T> for Result<T, E>
where
    E: Error + Send + Sync + 'static,
{
    fn context(self, field: impl Into<String>) -> Result<T, ConversionError> {
        self.map_err(|error| ConversionError::new(error).context(field))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::ConversionError;

    #[test]
    fn wrapping_a_conversion_error_preserves_its_path() {
        let inner = ConversionError::message("invalid value").context("inner");
        let outer = ConversionError::new(inner).context("outer");

        assert_eq!(outer.to_string(), "outer.inner: invalid value");
    }
}
