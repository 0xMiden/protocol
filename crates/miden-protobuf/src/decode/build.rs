use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt::Debug;

use super::{MapField, OptionalField, RepeatedField};
use crate::{BuildUnchecked, ConversionError};

/// Builds the present value; the caller must ensure the invariants documented by `S`.
impl<S: BuildUnchecked> BuildUnchecked for OptionalField<S> {
    type Output = Option<S::Output>;
    type Error = ConversionError;

    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        self.try_map(BuildUnchecked::build_unchecked)
    }
}

/// Builds each value in input order, preserving duplicates. The caller must ensure the
/// invariants documented by `S` for every value, as well as any collection-wide invariants.
impl<S: BuildUnchecked> BuildUnchecked for RepeatedField<S> {
    type Output = Vec<S::Output>;
    type Error = ConversionError;

    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        self.try_map(BuildUnchecked::build_unchecked)
    }
}

/// Builds each value in key order, preserving keys. The caller must ensure the invariants
/// documented by `S` for every value, as well as any collection-wide invariants.
impl<K: Ord + Debug, S: BuildUnchecked> BuildUnchecked for MapField<BTreeMap<K, S>> {
    type Output = BTreeMap<K, S::Output>;
    type Error = ConversionError;

    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        self.try_map(BuildUnchecked::build_unchecked)
    }
}

/// Builds each value in unspecified order, preserving keys. The caller must ensure the
/// invariants documented by `S` for every value, as well as any collection-wide invariants.
#[cfg(feature = "std")]
impl<K: Eq + core::hash::Hash + Debug, S: BuildUnchecked> BuildUnchecked
    for MapField<std::collections::HashMap<K, S>>
{
    type Output = std::collections::HashMap<K, S::Output>;
    type Error = ConversionError;

    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        self.try_map(BuildUnchecked::build_unchecked)
    }
}
