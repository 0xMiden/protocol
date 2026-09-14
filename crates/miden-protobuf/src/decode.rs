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

/// Converts a Protobuf field into the representation selected by its generated decoded record.
/// This handles structural conversion and error paths, not domain construction or verification.
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
        value.try_into().context(self.name)
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
        self.value.map(TryInto::try_into).transpose().context(self.name)
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
}

impl<S, T> DecodeField<Vec<T>> for RepeatedField<S>
where
    S: TryInto<T>,
    S::Error: Error + Send + Sync + 'static,
{
    fn decode(self) -> Result<Vec<T>, ConversionError> {
        self.values
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                value.try_into().with_context(|| format!("{}[{index}]", self.name))
            })
            .collect()
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
        self.value.try_into().context(self.name)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::error::Error;
    use core::num::TryFromIntError;

    use super::{OptionalField, RepeatedField, RequiredField, decode};

    #[derive(Clone, PartialEq, prost::Message)]
    struct Message {}

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
        assert!(error.source().unwrap().is::<TryFromIntError>());
    }

    #[test]
    fn repeated_fields_preserve_order_and_duplicates() {
        let numbers: Vec<u16> = decode(RepeatedField::new("numbers", vec![2_u32, 1, 2])).unwrap();
        assert_eq!(numbers, vec![2, 1, 2]);
    }

    #[test]
    fn empty_repeated_fields_do_not_enforce_domain_invariants() {
        let numbers: Vec<u16> = decode(RepeatedField::new("numbers", Vec::<u32>::new())).unwrap();
        assert!(numbers.is_empty());
    }
}
