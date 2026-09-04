use alloc::format;
use alloc::vec::Vec;
use core::error::Error;
use core::marker::PhantomData;

use crate::{ConversionError, ConversionResultExt};

pub fn decode<S, T>(source: S) -> Result<T, ConversionError>
where
    S: DecodeField<T>,
{
    source.decode()
}

/// Converts a generated Protobuf field wrapper into the target type inferred by its constructor.
///
/// Implement [`DecodeRepeated`] on a domain collection to adapt a repeated Protobuf field directly
/// into a type that enforces its own invariants.
pub trait DecodeField<T> {
    fn decode(self) -> Result<T, ConversionError>;
}

pub struct RequiredField<M, S> {
    name: &'static str,
    value: Option<S>,
    message: PhantomData<M>,
}

impl<M, S> RequiredField<M, S> {
    pub const fn new(name: &'static str, value: Option<S>) -> Self {
        Self { name, value, message: PhantomData }
    }
}

impl<M, S, T> DecodeField<T> for RequiredField<M, S>
where
    M: prost::Message,
    S: TryInto<T>,
    S::Error: Error + Send + Sync + 'static,
{
    fn decode(self) -> Result<T, ConversionError> {
        let value = self
            .value
            .ok_or_else(|| ConversionError::missing_field::<M>(self.name))
            .context(self.name)?;
        value.try_into().map_err(ConversionError::new).context(self.name)
    }
}

pub struct OptionalField<S> {
    name: &'static str,
    value: Option<S>,
}

impl<S> OptionalField<S> {
    pub const fn new(name: &'static str, value: Option<S>) -> Self {
        Self { name, value }
    }
}

impl<S, T> DecodeField<Option<T>> for OptionalField<S>
where
    S: TryInto<T>,
    S::Error: Error + Send + Sync + 'static,
{
    fn decode(self) -> Result<Option<T>, ConversionError> {
        self.value
            .map(TryInto::try_into)
            .transpose()
            .map_err(ConversionError::new)
            .context(self.name)
    }
}

/// A repeated Protobuf field together with the field name used for conversion error paths.
pub struct RepeatedField<S> {
    name: &'static str,
    values: Vec<S>,
}

impl<S> RepeatedField<S> {
    /// Wraps the generated values from the named Protobuf field.
    pub const fn new(name: &'static str, values: Vec<S>) -> Self {
        Self { name, values }
    }

    /// Returns the Protobuf field name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Converts every item and includes the failing item index in conversion errors.
    pub fn decode_items<T>(self) -> Result<Vec<T>, ConversionError>
    where
        S: TryInto<T>,
        S::Error: Error + Send + Sync + 'static,
    {
        self.values
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                value
                    .try_into()
                    .map_err(ConversionError::new)
                    .context(format!("{}[{index}]", self.name))
            })
            .collect()
    }
}

/// Converts a repeated Protobuf field directly into a target collection.
///
/// The Protobuf source type is a trait parameter so a crate that owns the generated source type
/// can implement this trait for a foreign domain collection.
pub trait DecodeRepeated<S>: Sized {
    fn decode_repeated(field: RepeatedField<S>) -> Result<Self, ConversionError>;
}

impl<S, T> DecodeRepeated<S> for Vec<T>
where
    S: TryInto<T>,
    S::Error: Error + Send + Sync + 'static,
{
    fn decode_repeated(field: RepeatedField<S>) -> Result<Self, ConversionError> {
        field.decode_items()
    }
}

impl<S, T> DecodeField<T> for RepeatedField<S>
where
    T: DecodeRepeated<S>,
{
    fn decode(self) -> Result<T, ConversionError> {
        T::decode_repeated(self)
    }
}

pub struct ValueField<S> {
    name: &'static str,
    value: S,
}

impl<S> ValueField<S> {
    pub const fn new(name: &'static str, value: S) -> Self {
        Self { name, value }
    }
}

impl<S, T> DecodeField<T> for ValueField<S>
where
    S: TryInto<T>,
    S::Error: Error + Send + Sync + 'static,
{
    fn decode(self) -> Result<T, ConversionError> {
        self.value.try_into().map_err(ConversionError::new).context(self.name)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{DecodeRepeated, OptionalField, RepeatedField, RequiredField, decode};
    use crate::ConversionError;

    #[derive(Clone, PartialEq, prost::Message)]
    struct Message {}

    #[derive(Debug, PartialEq, Eq)]
    struct Numbers(Vec<u16>);

    impl DecodeRepeated<u32> for Numbers {
        fn decode_repeated(field: RepeatedField<u32>) -> Result<Self, ConversionError> {
            let name = field.name();
            let values = field.decode_items()?;
            if values.is_empty() {
                return Err(ConversionError::message("numbers must not be empty").context(name));
            }
            Ok(Numbers(values))
        }
    }

    #[test]
    fn optional_field_converts_present_values() {
        let value: Option<u16> = decode(OptionalField::new("value", Some(7_u32))).unwrap();
        assert_eq!(value, Some(7));
    }

    #[test]
    fn required_field_reports_its_name_when_missing() {
        let error =
            decode::<_, u16>(RequiredField::<Message, _>::new("value", None::<u32>)).unwrap_err();

        assert!(error.to_string().starts_with("value: field "));
        assert!(error.to_string().ends_with("::value is missing"));
    }

    #[test]
    fn repeated_field_reports_the_failing_index() {
        let error = decode::<_, Vec<u16>>(RepeatedField::new(
            "values",
            vec![1_u32, u32::from(u16::MAX) + 1],
        ))
        .unwrap_err();
        assert!(error.to_string().starts_with("values[1]:"));
    }

    #[test]
    fn repeated_field_can_decode_directly_into_a_domain_collection() {
        let numbers: Numbers = decode(RepeatedField::new("numbers", vec![1_u32, 2_u32])).unwrap();
        assert_eq!(numbers, Numbers(vec![1, 2]));
    }
}
