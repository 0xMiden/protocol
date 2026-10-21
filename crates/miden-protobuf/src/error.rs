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

    /// Reports a oneof extraction mismatch using exact wire variant names.
    ///
    /// The actual variant is added to the field path. No payload is decoded or verified when
    /// the requested variant does not match.
    pub fn wrong_variant(expected: &'static str, actual: &'static str) -> Self {
        Self::message(format!("expected oneof variant `{expected}`, got `{actual}`"))
            .context(actual)
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

    /// Converts this input conversion failure into a gRPC `InvalidArgument` status.
    ///
    /// The message includes the field path and every source-chain level, even when a source's
    /// `Display` omits its own cause. Deeper causes are separated by `\ncaused by: `; a cause may
    /// appear more than once if an outer error already includes it in its display text.
    /// The original error is also retained as the status's local source.
    ///
    /// Available with the optional `tonic` feature, which enables `std` without transport.
    #[cfg(feature = "tonic")]
    pub fn into_status(self) -> tonic::Status {
        use alloc::string::ToString;
        use alloc::sync::Arc;
        use core::fmt::Write;

        let mut message = self.to_string();
        // Display already includes the immediate source; walk the causes it may omit.
        let mut cause = self.source.source();
        while let Some(error) = cause {
            write!(message, "\ncaused by: {error}").expect("writing to a String cannot fail");
            cause = error.source();
        }
        let mut status = tonic::Status::invalid_argument(message);
        status.set_source(Arc::new(self));
        status
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
    /// Adds a field path segment if the result is an error.
    fn context(self, field: impl Into<String>) -> Result<T, ConversionError>;

    /// Computes and adds a field path segment only if the result is an error.
    fn with_context<F, S>(self, field: F) -> Result<T, ConversionError>
    where
        F: FnOnce() -> S,
        S: Into<String>;
}

impl<T, E> ConversionResultExt<T> for Result<T, E>
where
    E: Error + Send + Sync + 'static,
{
    fn context(self, field: impl Into<String>) -> Result<T, ConversionError> {
        self.with_context(|| field)
    }

    fn with_context<F, S>(self, field: F) -> Result<T, ConversionError>
    where
        F: FnOnce() -> S,
        S: Into<String>,
    {
        self.map_err(|error| ConversionError::new(error).context(field()))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use core::error::Error;
    use core::num::TryFromIntError;

    use super::{ConversionError, ConversionResultExt};

    #[test]
    fn with_context_does_not_evaluate_the_closure_on_success() {
        let value = Ok::<_, TryFromIntError>(7)
            .with_context(|| -> &'static str { panic!("context must not be evaluated") })
            .unwrap();

        assert_eq!(value, 7);
    }

    #[test]
    fn with_context_evaluates_once_and_preserves_the_path_and_source() {
        let source = u8::try_from(256_u16).unwrap_err();
        let inner = ConversionError::new(source).context("inner");
        let field = "outer".to_string();
        let mut calls = 0;

        let error = Err::<(), _>(inner)
            .with_context(|| {
                calls += 1;
                field
            })
            .unwrap_err();

        assert_eq!(calls, 1);
        assert_eq!(error.to_string(), alloc::format!("outer.inner: {source}"));
        assert!(error.source().unwrap().is::<TryFromIntError>());
    }

    #[test]
    fn deserialization_errors_preserve_the_source() {
        let source = u8::try_from(256_u16).unwrap_err();
        let error = ConversionError::deserialization("Payload", source);
        assert_eq!(error.to_string(), alloc::format!("failed to deserialize Payload: {source}"));
        assert!(error.source().unwrap().source().unwrap().is::<TryFromIntError>());
    }

    #[test]
    fn wrapping_a_conversion_error_preserves_its_path() {
        let inner = ConversionError::message("invalid value").context("inner");
        let outer = ConversionError::new(inner).context("outer");

        assert_eq!(outer.to_string(), "outer.inner: invalid value");
    }
}
