use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt::Debug;

use super::{MapField, OptionalField, RepeatedField};
use crate::{ConversionError, ConversionResultExt};

impl<S> OptionalField<S> {
    /// Transforms the present value into an ordinary option using an explicit conversion.
    /// Does not invoke verification automatically.
    pub fn map<T>(self, convert: impl FnOnce(S) -> T) -> Option<T> {
        self.value.map(convert)
    }

    /// Converts the present value, retaining the field name and source on failure.
    /// Returns an ordinary option; does not invoke verification automatically.
    pub fn try_map<T, E>(
        self,
        convert: impl FnOnce(S) -> Result<T, E>,
    ) -> Result<Option<T>, ConversionError>
    where
        E: Error + Send + Sync + 'static,
    {
        self.value.map(convert).transpose().context(self.name)
    }
}

impl<S> RepeatedField<S> {
    /// Transforms values in input order into an ordinary vector, preserving duplicates.
    /// Does not invoke verification automatically or apply collection-wide checks.
    pub fn map<T>(self, convert: impl FnMut(S) -> T) -> Vec<T> {
        self.values.into_iter().map(convert).collect()
    }

    /// Converts values in input order into an ordinary vector, preserving duplicates.
    ///
    /// Stops at the first failure and retains its field name, input index, and source.
    /// Does not invoke verification automatically or apply collection-wide checks.
    pub fn try_map<T, E>(
        self,
        mut convert: impl FnMut(S) -> Result<T, E>,
    ) -> Result<Vec<T>, ConversionError>
    where
        E: Error + Send + Sync + 'static,
    {
        self.values
            .into_iter()
            .enumerate()
            .map(|(index, value)| convert(value).with_context(|| format!("{}[{index}]", self.name)))
            .collect()
    }
}

impl<K: Ord, S> MapField<BTreeMap<K, S>> {
    /// Transforms values into an ordinary map, preserving keys and their order.
    /// Does not invoke verification automatically or apply collection-wide checks.
    pub fn map<T>(self, mut convert: impl FnMut(S) -> T) -> BTreeMap<K, T> {
        self.values.into_iter().map(|(key, value)| (key, convert(value))).collect()
    }

    /// Converts values in key order into an ordinary map, preserving keys.
    ///
    /// Stops at the first failure and retains its field name, key, and source.
    /// Does not invoke verification automatically or apply collection-wide checks.
    pub fn try_map<T, E>(
        self,
        mut convert: impl FnMut(S) -> Result<T, E>,
    ) -> Result<BTreeMap<K, T>, ConversionError>
    where
        K: Debug,
        E: Error + Send + Sync + 'static,
    {
        self.values
            .into_iter()
            .map(|(key, value)| {
                let value = convert(value).with_context(|| format!("{}[{key:?}]", self.name))?;
                Ok((key, value))
            })
            .collect()
    }
}

#[cfg(feature = "std")]
impl<K: Eq + core::hash::Hash, S> MapField<std::collections::HashMap<K, S>> {
    /// Transforms values into an ordinary hash map, preserving keys.
    /// Iteration order is unspecified. Does not invoke verification automatically.
    pub fn map<T>(self, mut convert: impl FnMut(S) -> T) -> std::collections::HashMap<K, T> {
        self.values.into_iter().map(|(key, value)| (key, convert(value))).collect()
    }

    /// Converts values into an ordinary hash map, preserving keys.
    ///
    /// Stops at the first failure and retains its field name, key, and source. Iteration order,
    /// and thus the first reported failure, is unspecified. Does not invoke verification
    /// automatically or apply collection-wide checks.
    pub fn try_map<T, E>(
        self,
        mut convert: impl FnMut(S) -> Result<T, E>,
    ) -> Result<std::collections::HashMap<K, T>, ConversionError>
    where
        K: Debug,
        E: Error + Send + Sync + 'static,
    {
        self.values
            .into_iter()
            .map(|(key, value)| {
                let value = convert(value).with_context(|| format!("{}[{key:?}]", self.name))?;
                Ok((key, value))
            })
            .collect()
    }
}
