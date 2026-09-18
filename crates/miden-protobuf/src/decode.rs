use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt::Debug;
use core::marker::PhantomData;

use crate::{ConversionError, ConversionResultExt};

mod build;
mod map;
mod verify;
pub use verify::DuplicatePolicy;

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

/// A named optional field for decoding or verifying its present value.
///
/// Generated decoded records retain this wrapper and its field name. The value has not been
/// verified; use [`crate::Verify`] or [`Self::into_inner`] for explicit domain construction.
#[derive(Debug)]
pub struct OptionalField<S> {
    name: &'static str,
    value: Option<S>,
}

impl<S> OptionalField<S> {
    pub const fn new(name: &'static str, value: Option<S>) -> Self {
        Self { name, value }
    }

    /// Borrows the present value without verifying it.
    pub const fn as_ref(&self) -> Option<&S> {
        self.value.as_ref()
    }

    /// Extracts the unverified value, discarding the field context for custom processing.
    pub fn into_inner(self) -> Option<S> {
        self.value
    }
}

impl<S, T> DecodeField<Option<T>> for OptionalField<S>
where
    S: TryInto<T>,
    S::Error: Error + Send + Sync + 'static,
{
    fn decode(self) -> Result<Option<T>, ConversionError> {
        self.try_map(TryInto::try_into)
    }
}

/// A named repeated field for decoding or verifying its values.
///
/// [`crate::Verify`] and [`crate::VerifyWith`] preserve order and duplicates. Use the explicit
/// set conversion methods to select a [`DuplicatePolicy`].
/// Generated decoded records retain this wrapper and its field name; its values are unverified.
#[derive(Debug)]
pub struct RepeatedField<S> {
    name: &'static str,
    values: Vec<S>,
}

impl<S> RepeatedField<S> {
    /// Wraps the generated values from the named Protobuf field.
    pub const fn new(name: &'static str, values: Vec<S>) -> Self {
        Self { name, values }
    }

    /// Borrows the values without verifying them.
    pub fn as_slice(&self) -> &[S] {
        &self.values
    }

    /// Extracts the unverified values, discarding the field context for custom processing.
    pub fn into_inner(self) -> Vec<S> {
        self.values
    }
}

impl<S, T> DecodeField<Vec<T>> for RepeatedField<S>
where
    S: TryInto<T>,
    S::Error: Error + Send + Sync + 'static,
{
    fn decode(self) -> Result<Vec<T>, ConversionError> {
        self.try_map(TryInto::try_into)
    }
}

/// A named Protobuf map for decoding or verifying its values, preserving keys and collection type.
///
/// Processing stops at the first error and includes the failing key in the field path, using
/// `Debug` formatting to quote and escape string keys. Hash maps require the `std` feature;
/// their iteration order, and thus the first reported failure, is unspecified.
/// Generated decoded records retain this wrapper and its field name; its values are unverified.
#[derive(Debug)]
pub struct MapField<M> {
    name: &'static str,
    values: M,
}

impl<M> MapField<M> {
    pub const fn new(name: &'static str, values: M) -> Self {
        Self { name, values }
    }

    /// Extracts the unverified map, discarding the field context for custom processing.
    pub fn into_inner(self) -> M {
        self.values
    }
}

impl<M> AsRef<M> for MapField<M> {
    /// Borrows the map without verifying its values.
    fn as_ref(&self) -> &M {
        &self.values
    }
}

impl<K, S, T> DecodeField<BTreeMap<K, T>> for MapField<BTreeMap<K, S>>
where
    K: Ord + Debug,
    S: TryInto<T>,
    S::Error: Error + Send + Sync + 'static,
{
    fn decode(self) -> Result<BTreeMap<K, T>, ConversionError> {
        self.try_map(TryInto::try_into)
    }
}

#[cfg(feature = "std")]
impl<K, S, T> DecodeField<std::collections::HashMap<K, T>>
    for MapField<std::collections::HashMap<K, S>>
where
    K: Eq + core::hash::Hash + Debug,
    S: TryInto<T>,
    S::Error: Error + Send + Sync + 'static,
{
    fn decode(self) -> Result<std::collections::HashMap<K, T>, ConversionError> {
        self.try_map(TryInto::try_into)
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
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::Cell;
    use core::error::Error;
    use core::num::TryFromIntError;

    use super::{MapField, OptionalField, RepeatedField, RequiredField, decode};

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

    #[test]
    fn map_fields_stop_at_the_first_failed_value() {
        struct Counted<'a>(&'a Cell<usize>, u32);

        impl TryFrom<Counted<'_>> for u8 {
            type Error = TryFromIntError;

            fn try_from(value: Counted<'_>) -> Result<Self, Self::Error> {
                value.0.set(value.0.get() + 1);
                value.1.try_into()
            }
        }

        let calls = Cell::new(0);
        let values = BTreeMap::from([
            (1, Counted(&calls, 7)),
            (2, Counted(&calls, 256)),
            (3, Counted(&calls, 8)),
        ]);
        let error = decode::<_, BTreeMap<_, u8>>(MapField::new("values", values)).unwrap_err();
        assert_eq!(calls.get(), 2);
        assert!(error.to_string().starts_with("values[2]:"), "{error}");
        assert!(error.source().unwrap().is::<TryFromIntError>());
    }
}
