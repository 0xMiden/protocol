use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt::Debug;

use super::{MapField, OptionalField, RepeatedField};
use crate::{ConversionError, ConversionResultExt, Verify, VerifyWith};

impl<S: Verify> Verify for OptionalField<S> {
    type Verified = Option<S::Verified>;
    type Error = ConversionError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        self.value.map(Verify::verify).transpose().context(self.name)
    }
}

impl<S: VerifyWith<C>, C> VerifyWith<C> for OptionalField<S> {
    type Verified = Option<S::Verified>;
    type Error = ConversionError;

    fn verify_with(self, context: C) -> Result<Self::Verified, Self::Error> {
        self.value
            .map(|value| value.verify_with(context))
            .transpose()
            .context(self.name)
    }
}

impl<S: Verify> Verify for RepeatedField<S> {
    type Verified = Vec<S::Verified>;
    type Error = ConversionError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        self.values
            .into_iter()
            .enumerate()
            .map(|(index, value)| value.verify().with_context(|| format!("{}[{index}]", self.name)))
            .collect()
    }
}

impl<S: VerifyWith<C>, C: Clone> VerifyWith<C> for RepeatedField<S> {
    type Verified = Vec<S::Verified>;
    type Error = ConversionError;

    fn verify_with(self, context: C) -> Result<Self::Verified, Self::Error> {
        self.values
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                value
                    .verify_with(context.clone())
                    .with_context(|| format!("{}[{index}]", self.name))
            })
            .collect()
    }
}

impl<K: Ord + Debug, S: Verify> Verify for MapField<BTreeMap<K, S>> {
    type Verified = BTreeMap<K, S::Verified>;
    type Error = ConversionError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        self.values
            .into_iter()
            .map(|(key, value)| {
                let value = value.verify().with_context(|| format!("{}[{key:?}]", self.name))?;
                Ok((key, value))
            })
            .collect()
    }
}

impl<K: Ord + Debug, S: VerifyWith<C>, C: Clone> VerifyWith<C> for MapField<BTreeMap<K, S>> {
    type Verified = BTreeMap<K, S::Verified>;
    type Error = ConversionError;

    fn verify_with(self, context: C) -> Result<Self::Verified, Self::Error> {
        self.values
            .into_iter()
            .map(|(key, value)| {
                let value = value
                    .verify_with(context.clone())
                    .with_context(|| format!("{}[{key:?}]", self.name))?;
                Ok((key, value))
            })
            .collect()
    }
}

#[cfg(feature = "std")]
impl<K: Eq + core::hash::Hash + Debug, S: Verify> Verify
    for MapField<std::collections::HashMap<K, S>>
{
    type Verified = std::collections::HashMap<K, S::Verified>;
    type Error = ConversionError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        self.values
            .into_iter()
            .map(|(key, value)| {
                let value = value.verify().with_context(|| format!("{}[{key:?}]", self.name))?;
                Ok((key, value))
            })
            .collect()
    }
}

#[cfg(feature = "std")]
impl<K: Eq + core::hash::Hash + Debug, S: VerifyWith<C>, C: Clone> VerifyWith<C>
    for MapField<std::collections::HashMap<K, S>>
{
    type Verified = std::collections::HashMap<K, S::Verified>;
    type Error = ConversionError;

    fn verify_with(self, context: C) -> Result<Self::Verified, Self::Error> {
        self.values
            .into_iter()
            .map(|(key, value)| {
                let value = value
                    .verify_with(context.clone())
                    .with_context(|| format!("{}[{key:?}]", self.name))?;
                Ok((key, value))
            })
            .collect()
    }
}

/// How to handle equal verified values when converting a repeated field to a set.
///
/// There is no default policy. Equality is determined by the output set's `Ord` or `Eq`/`Hash`
/// implementation, after each input has been verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuplicatePolicy {
    /// Fail at the first duplicate, attaching its input index to the field path.
    Reject,
    /// Keep the first verified value. Later equal values are still verified before discarding.
    KeepFirst,
}

impl<S> RepeatedField<S> {
    /// Verifies values in input order and collects them into a set using an explicit policy.
    ///
    /// Verification failures and rejected duplicates include the field name and input index.
    /// Processing stops immediately on either error. This checks individual values and the
    /// duplicate policy; other collection invariants belong to the containing verifier.
    ///
    /// ```
    /// use miden_protobuf::{DuplicatePolicy, RepeatedField, Verify};
    /// # use std::collections::BTreeSet;
    /// # struct Entry(u32);
    /// # impl Verify for Entry {
    /// #     type Verified = u8;
    /// #     type Error = core::num::TryFromIntError;
    /// #     fn verify(self) -> Result<u8, Self::Error> { self.0.try_into() }
    /// # }
    /// let values = vec![Entry(1), Entry(2), Entry(1)];
    /// let unique =
    ///     RepeatedField::new("entries", values).verify_into_btree_set(DuplicatePolicy::KeepFirst)?;
    /// # assert_eq!(unique, BTreeSet::from([1, 2]));
    /// # Ok::<_, miden_protobuf::ConversionError>(())
    /// ```
    pub fn verify_into_btree_set(
        self,
        duplicates: DuplicatePolicy,
    ) -> Result<BTreeSet<S::Verified>, ConversionError>
    where
        S: Verify,
        S::Verified: Ord,
    {
        let mut values = BTreeSet::new();
        self.verify_set(duplicates, Verify::verify, |value| values.insert(value))?;
        Ok(values)
    }

    /// Contextual version of [`Self::verify_into_btree_set`]. Context is cloned per element;
    /// pass `&context` to share it without cloning its contents.
    pub fn verify_into_btree_set_with<C>(
        self,
        context: C,
        duplicates: DuplicatePolicy,
    ) -> Result<BTreeSet<S::Verified>, ConversionError>
    where
        S: VerifyWith<C>,
        S::Verified: Ord,
        C: Clone,
    {
        let mut values = BTreeSet::new();
        self.verify_set(
            duplicates,
            |value| value.verify_with(context.clone()),
            |value| values.insert(value),
        )?;
        Ok(values)
    }

    /// Verifies values in input order and collects them into a hash set.
    ///
    /// Has the same verification and duplicate semantics as [`Self::verify_into_btree_set`].
    #[cfg(feature = "std")]
    pub fn verify_into_hash_set(
        self,
        duplicates: DuplicatePolicy,
    ) -> Result<std::collections::HashSet<S::Verified>, ConversionError>
    where
        S: Verify,
        S::Verified: Eq + core::hash::Hash,
    {
        let mut values = std::collections::HashSet::new();
        self.verify_set(duplicates, Verify::verify, |value| values.insert(value))?;
        Ok(values)
    }

    /// Contextual version of [`Self::verify_into_hash_set`]. Context is cloned per element;
    /// pass `&context` to share it without cloning its contents.
    #[cfg(feature = "std")]
    pub fn verify_into_hash_set_with<C>(
        self,
        context: C,
        duplicates: DuplicatePolicy,
    ) -> Result<std::collections::HashSet<S::Verified>, ConversionError>
    where
        S: VerifyWith<C>,
        S::Verified: Eq + core::hash::Hash,
        C: Clone,
    {
        let mut values = std::collections::HashSet::new();
        self.verify_set(
            duplicates,
            |value| value.verify_with(context.clone()),
            |value| values.insert(value),
        )?;
        Ok(values)
    }

    fn verify_set<T, E: Error + Send + Sync + 'static>(
        self,
        duplicates: DuplicatePolicy,
        mut verify: impl FnMut(S) -> Result<T, E>,
        mut insert: impl FnMut(T) -> bool,
    ) -> Result<(), ConversionError> {
        for (index, value) in self.values.into_iter().enumerate() {
            let value = verify(value).with_context(|| format!("{}[{index}]", self.name))?;
            if !insert(value) && duplicates == DuplicatePolicy::Reject {
                return Err(ConversionError::message("duplicate verified value")
                    .context(format!("{}[{index}]", self.name)));
            }
        }
        Ok(())
    }
}
