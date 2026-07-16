//! A [`DoubleWord`] type used in the Miden protocol and associated utilities.

use alloc::vec::Vec;
use core::hash::{Hash, Hasher};
use core::mem::size_of;
use core::ops::{Deref, DerefMut};

use crate::{Felt, Word, WordError};

// DOUBLE WORD
// ================================================================================================

/// A unit of data consisting of 8 field elements (a "double word").
///
/// Conceptually this is two [`Word`]s: `word_lo` (elements 0..4) followed by `word_hi` (elements
/// 4..8).
///
/// # Examples
///
/// ```
/// use miden_protocol::{DoubleWord, Felt, Word};
///
/// let lo = Word::new([Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
/// let hi = Word::new([Felt::ZERO, Felt::ONE, Felt::ZERO, Felt::ZERO]);
/// let dword = DoubleWord::new(lo, hi);
/// assert_eq!(dword.lo(), lo);
/// assert_eq!(dword.hi(), hi);
/// ```
#[derive(Default, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct DoubleWord {
    word_lo: Word,
    word_hi: Word,
}

// Compile-time assertions to ensure `DoubleWord` has the same layout as `[Felt; 8]`. This is
// relied upon in `as_elements_array`/`as_elements_array_mut`.
const _: () = {
    assert!(DoubleWord::NUM_ELEMENTS == 8, "DoubleWord::NUM_ELEMENTS is assumed to be 8");
    assert!(
        DoubleWord::SERIALIZED_SIZE == 64,
        "DoubleWord::SERIALIZED_SIZE is assumed to be 64"
    );
    assert!(size_of::<DoubleWord>() == DoubleWord::NUM_ELEMENTS * size_of::<Felt>());
    assert!(core::mem::offset_of!(DoubleWord, word_lo) == 0);
    assert!(core::mem::offset_of!(DoubleWord, word_hi) == Word::SERIALIZED_SIZE);
};

impl core::fmt::Debug for DoubleWord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("DoubleWord").field(&self.into_elements()).finish()
    }
}

impl DoubleWord {
    /// The number of field elements in the double word.
    pub const NUM_ELEMENTS: usize = Word::NUM_ELEMENTS * 2;

    /// The serialized size of the double word in bytes.
    pub const SERIALIZED_SIZE: usize = Word::SERIALIZED_SIZE * 2;

    /// Creates a new [`DoubleWord`] from two [`Word`]s.
    pub const fn new(word_lo: Word, word_hi: Word) -> Self {
        Self { word_lo, word_hi }
    }

    /// Returns the low word of this double word.
    pub const fn lo(&self) -> Word {
        self.word_lo
    }

    /// Returns the high word of this double word.
    pub const fn hi(&self) -> Word {
        self.word_hi
    }

    /// Returns the elements of this double word as an array.
    ///
    /// # Examples
    ///
    /// ```
    /// use miden_protocol::{DoubleWord, Felt, Word};
    ///
    /// let lo = Word::new([Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    /// let hi = Word::new([Felt::ZERO, Felt::ONE, Felt::ZERO, Felt::ZERO]);
    /// let dword = DoubleWord::new(lo, hi);
    /// assert_eq!(
    ///     dword.into_elements(),
    ///     [
    ///         Felt::ONE,
    ///         Felt::ZERO,
    ///         Felt::ZERO,
    ///         Felt::ZERO,
    ///         Felt::ZERO,
    ///         Felt::ONE,
    ///         Felt::ZERO,
    ///         Felt::ZERO
    ///     ]
    /// );
    /// ```
    pub fn into_elements(self) -> [Felt; Self::NUM_ELEMENTS] {
        let [a, b, c, d] = self.word_lo.into_elements();
        let [e, f, g, h] = self.word_hi.into_elements();
        [a, b, c, d, e, f, g, h]
    }

    /// Returns the two [`Word`]s of this double word as a tuple in the following format: `(low,
    /// high)`.
    pub fn into_tuple(self) -> (Word, Word) {
        (self.word_lo, self.word_hi)
    }

    /// Returns the elements of this double word as an array reference.
    ///
    /// # Safety
    /// This assumes the two [`Word`] fields of [`DoubleWord`] are laid out contiguously with no
    /// padding, in the same order as `[Felt; 8]`.
    fn as_elements_array(&self) -> &[Felt; Self::NUM_ELEMENTS] {
        unsafe { &*(&self.word_lo as *const Word as *const [Felt; Self::NUM_ELEMENTS]) }
    }

    /// Returns the elements of this double word as a mutable array reference.
    ///
    /// # Safety
    /// This assumes the two [`Word`] fields of [`DoubleWord`] are laid out contiguously with no
    /// padding, in the same order as `[Felt; 8]`.
    fn as_elements_array_mut(&mut self) -> &mut [Felt; Self::NUM_ELEMENTS] {
        unsafe { &mut *(&mut self.word_lo as *mut Word as *mut [Felt; Self::NUM_ELEMENTS]) }
    }

    /// Returns the double word as a slice of field elements.
    pub fn as_elements(&self) -> &[Felt] {
        self.as_elements_array()
    }

    /// Returns the double word as a byte array.
    pub fn as_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut result = [0; Self::SERIALIZED_SIZE];
        result[..Word::SERIALIZED_SIZE].copy_from_slice(&self.word_lo.as_bytes());
        result[Word::SERIALIZED_SIZE..].copy_from_slice(&self.word_hi.as_bytes());
        result
    }

    /// Returns internal elements of this double word as a vector.
    pub fn to_vec(&self) -> Vec<Felt> {
        self.as_elements().to_vec()
    }

    /// Returns a new [`DoubleWord`] consisting of eight ZERO elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use miden_protocol::{DoubleWord, Felt};
    ///
    /// let dword = DoubleWord::empty();
    /// assert!(dword.is_empty());
    /// ```
    pub const fn empty() -> Self {
        Self::new(Word::empty(), Word::empty())
    }

    /// Returns true if the double word consists of eight ZERO elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use miden_protocol::{DoubleWord, Felt, Word};
    ///
    /// let dword = DoubleWord::new(Word::empty(), Word::empty());
    /// assert!(dword.is_empty());
    ///
    /// let lo = Word::new([Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    /// let dword2 = DoubleWord::new(lo, Word::empty());
    /// assert!(!dword2.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.word_lo.is_empty() && self.word_hi.is_empty()
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl Hash for DoubleWord {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.as_bytes());
    }
}

impl Deref for DoubleWord {
    type Target = [Felt; DoubleWord::NUM_ELEMENTS];

    fn deref(&self) -> &Self::Target {
        self.as_elements_array()
    }
}

impl DerefMut for DoubleWord {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_elements_array_mut()
    }
}

impl IntoIterator for DoubleWord {
    type Item = Felt;
    type IntoIter = <[Felt; 8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.into_elements().into_iter()
    }
}

// CONVERSIONS: FROM DOUBLE WORD
// ================================================================================================

impl From<DoubleWord> for [Felt; DoubleWord::NUM_ELEMENTS] {
    fn from(value: DoubleWord) -> Self {
        value.into_elements()
    }
}

impl From<DoubleWord> for Vec<Felt> {
    fn from(value: DoubleWord) -> Self {
        value.to_vec()
    }
}

impl From<DoubleWord> for (Word, Word) {
    fn from(value: DoubleWord) -> Self {
        value.into_tuple()
    }
}

// CONVERSIONS: TO DOUBLE WORD
// ================================================================================================

impl From<[Felt; DoubleWord::NUM_ELEMENTS]> for DoubleWord {
    fn from(value: [Felt; DoubleWord::NUM_ELEMENTS]) -> Self {
        let word_lo = Word::new([value[0], value[1], value[2], value[3]]);
        let word_hi = Word::new([value[4], value[5], value[6], value[7]]);
        Self::new(word_lo, word_hi)
    }
}

impl From<&[Felt; DoubleWord::NUM_ELEMENTS]> for DoubleWord {
    fn from(value: &[Felt; DoubleWord::NUM_ELEMENTS]) -> Self {
        Self::from(*value)
    }
}

impl TryFrom<&[Felt]> for DoubleWord {
    type Error = WordError;

    fn try_from(value: &[Felt]) -> Result<Self, Self::Error> {
        let value: [Felt; DoubleWord::NUM_ELEMENTS] = value.try_into().map_err(|_| {
            WordError::InvalidInputLength("elements", DoubleWord::NUM_ELEMENTS, value.len())
        })?;
        Ok(value.into())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::hash::Hasher;
    use std::collections::hash_map::DefaultHasher;

    use rstest::rstest;

    use super::*;

    fn felt(n: u64) -> Felt {
        Felt::new_unchecked(n)
    }

    fn make_lo() -> Word {
        Word::new([felt(1), felt(2), felt(3), felt(4)])
    }

    fn make_hi() -> Word {
        Word::new([felt(5), felt(6), felt(7), felt(8)])
    }

    fn make_dword() -> DoubleWord {
        DoubleWord::new(make_lo(), make_hi())
    }

    // CONSTRUCTOR AND ACCESSORS
    // ----------------------------------------------------------------------------------------

    #[test]
    fn dword_new_and_accessors() {
        let dword = make_dword();
        assert_eq!(dword.lo(), make_lo());
        assert_eq!(dword.hi(), make_hi());
    }

    #[test]
    fn dword_into_elements_ordering() {
        let dword = make_dword();
        let elements = dword.into_elements();
        assert_eq!(
            elements,
            [felt(1), felt(2), felt(3), felt(4), felt(5), felt(6), felt(7), felt(8)]
        );
    }

    #[test]
    fn dword_as_elements_matches_into_elements() {
        let dword = make_dword();
        let owned = dword.into_elements();
        let borrowed: &[Felt; DoubleWord::NUM_ELEMENTS] = dword.deref();
        assert_eq!(&owned, borrowed);
    }

    #[test]
    fn dword_into_tuple() {
        let dword = make_dword();
        let (lo, hi) = dword.into_tuple();
        assert_eq!(lo, make_lo());
        assert_eq!(hi, make_hi());
    }

    #[test]
    fn dword_as_bytes_layout() {
        let dword = make_dword();
        let bytes = dword.as_bytes();
        assert_eq!(bytes.len(), DoubleWord::SERIALIZED_SIZE);

        let lo_bytes = make_lo().as_bytes();
        let hi_bytes = make_hi().as_bytes();
        let mut expected = [0u8; DoubleWord::SERIALIZED_SIZE];
        expected[..Word::SERIALIZED_SIZE].copy_from_slice(&lo_bytes);
        expected[Word::SERIALIZED_SIZE..].copy_from_slice(&hi_bytes);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn dword_to_vec() {
        let dword = make_dword();
        let v: Vec<Felt> = dword.to_vec();
        assert_eq!(v.len(), DoubleWord::NUM_ELEMENTS);
        assert_eq!(v, dword.into_elements().to_vec());
    }

    // EMPTY / DEFAULT
    // ----------------------------------------------------------------------------------------

    #[test]
    fn dword_empty() {
        let dword = DoubleWord::empty();
        assert_eq!(dword.lo(), Word::empty());
        assert_eq!(dword.hi(), Word::empty());
    }

    #[rstest]
    #[case(true, Word::empty(), Word::empty())]
    #[case(false, make_lo(), Word::empty())]
    #[case(false, Word::empty(), make_hi())]
    #[case(false, make_lo(), make_hi())]
    fn dword_is_empty(#[case] expected: bool, #[case] lo: Word, #[case] hi: Word) {
        assert_eq!(DoubleWord::new(lo, hi).is_empty(), expected);
    }

    #[test]
    fn dword_default_equals_empty() {
        assert_eq!(DoubleWord::default(), DoubleWord::empty());
    }

    // LAYOUT (unsafe pointer correctness)
    // ----------------------------------------------------------------------------------------

    #[test]
    fn dword_elements_array_layout() {
        let dword = make_dword();

        let elements = dword.as_elements();
        assert_eq!(
            elements,
            &[felt(1), felt(2), felt(3), felt(4), felt(5), felt(6), felt(7), felt(8)]
        );

        let lo_ptr = core::ptr::addr_of!(dword.word_lo);
        assert_eq!(elements.as_ptr() as *const Word, lo_ptr);

        let hi_ptr = core::ptr::addr_of!(dword.word_hi);
        assert_eq!(unsafe { elements.as_ptr().add(4) } as *const Word, hi_ptr);
    }

    // DEREF / DEREFMUT
    // ----------------------------------------------------------------------------------------

    #[test]
    fn dword_deref_read() {
        let dword = make_dword();
        assert_eq!(dword[0], felt(1));
        assert_eq!(dword[3], felt(4));
        assert_eq!(dword[4], felt(5));
        assert_eq!(dword[7], felt(8));
    }

    #[test]
    fn dword_deref_mut_write() {
        let mut dword = make_dword();
        dword[0] = felt(99);
        dword[7] = felt(100);
        assert_eq!(dword.lo()[0], felt(99));
        assert_eq!(dword.hi()[3], felt(100));
    }

    #[test]
    fn dword_index_matches_into_elements() {
        let dword = make_dword();
        let elements = dword.into_elements();
        for idx in 0..DoubleWord::NUM_ELEMENTS {
            assert_eq!(dword[idx], elements[idx]);
        }
    }

    #[test]
    fn dword_index_mut_updates_all_elements() {
        let mut dword = make_dword();
        let new_values: [Felt; DoubleWord::NUM_ELEMENTS] =
            [felt(10), felt(20), felt(30), felt(40), felt(50), felt(60), felt(70), felt(80)];
        for idx in 0..DoubleWord::NUM_ELEMENTS {
            dword[idx] = new_values[idx];
        }
        assert_eq!(dword.into_elements(), new_values);
    }

    #[test]
    fn dword_index_mut_range_updates_slice() {
        let mut dword = make_dword();
        let replacement = [felt(90), felt(91)];
        dword[2..4].copy_from_slice(&replacement);
        assert_eq!(dword[2], felt(90));
        assert_eq!(dword[3], felt(91));
    }

    // INTO ITERATOR
    // ----------------------------------------------------------------------------------------

    #[test]
    fn dword_into_iter() {
        let dword = make_dword();
        let collected: Vec<Felt> = dword.into_iter().collect();
        assert_eq!(collected, dword.into_elements().to_vec());
    }

    // HASH
    // ----------------------------------------------------------------------------------------

    #[test]
    fn dword_hash_equal_for_equal_values() {
        let a = make_dword();
        let b = make_dword();

        let hasher = DefaultHasher::new();
        let mut ha = hasher.clone();
        let mut hb = hasher;
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn dword_hash_differs_for_different_values() {
        let a = make_dword();
        let b = DoubleWord::empty();

        let hasher = DefaultHasher::new();
        let mut ha = hasher.clone();
        let mut hb = hasher;
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_ne!(ha.finish(), hb.finish());
    }

    // COPY / CLONE / EQ
    // ----------------------------------------------------------------------------------------

    #[test]
    fn dword_copy_independence() {
        let original = make_dword();
        let copy = original;
        // Both should be equal (Copy semantics).
        assert_eq!(original, copy);
        // Mutating a copy through a rebinding does not affect the original.
        let mut modified = copy;
        modified[0] = felt(999);
        assert_eq!(original[0], felt(1));
        assert_eq!(modified[0], felt(999));
    }

    #[test]
    fn dword_eq_inequality() {
        assert_eq!(make_dword(), make_dword());
        assert_ne!(make_dword(), DoubleWord::empty());
        assert_ne!(DoubleWord::new(make_lo(), make_hi()), DoubleWord::new(make_hi(), make_lo()));
    }

    // DEBUG
    // ----------------------------------------------------------------------------------------

    #[test]
    fn dword_debug_format() {
        let dword = make_dword();
        let debug = alloc::format!("{dword:?}");
        assert!(debug.starts_with("DoubleWord("), "unexpected debug format: {debug}");
    }

    // CONSTANTS
    // ----------------------------------------------------------------------------------------

    #[test]
    fn dword_constants() {
        assert_eq!(DoubleWord::NUM_ELEMENTS, 8);
        assert_eq!(DoubleWord::SERIALIZED_SIZE, 64);
    }

    // CONVERSIONS
    // ----------------------------------------------------------------------------------------

    #[test]
    fn dword_felt_array_roundtrip() {
        let elements: [Felt; DoubleWord::NUM_ELEMENTS] =
            [felt(10), felt(20), felt(30), felt(40), felt(50), felt(60), felt(70), felt(80)];
        let dword = DoubleWord::from(elements);
        let round_trip: [Felt; DoubleWord::NUM_ELEMENTS] = dword.into();
        assert_eq!(elements, round_trip);
    }

    #[test]
    fn dword_from_ref_felt_array() {
        let elements: [Felt; DoubleWord::NUM_ELEMENTS] =
            [felt(10), felt(20), felt(30), felt(40), felt(50), felt(60), felt(70), felt(80)];
        let from_owned = DoubleWord::from(elements);
        let from_ref = DoubleWord::from(&elements);
        assert_eq!(from_owned, from_ref);
    }

    #[test]
    fn dword_word_tuple_roundtrip() {
        let dword = make_dword();
        let tuple: (Word, Word) = dword.into();
        let round_trip = DoubleWord::new(tuple.0, tuple.1);
        assert_eq!(make_dword(), round_trip);
    }

    #[test]
    fn dword_from_double_word_to_vec() {
        let dword = make_dword();
        let v: Vec<Felt> = dword.into();
        assert_eq!(v, dword.into_elements().to_vec());
    }

    #[test]
    fn dword_from_double_word_to_array() {
        let dword = make_dword();
        let arr: [Felt; DoubleWord::NUM_ELEMENTS] = dword.into();
        assert_eq!(arr, dword.into_elements());
    }

    #[test]
    fn dword_try_from_felt_slice_correct_length() {
        let elements: Vec<Felt> = (1..=8).map(felt).collect();
        let dword = DoubleWord::try_from(elements.as_slice()).unwrap();
        assert_eq!(
            dword.into_elements(),
            [felt(1), felt(2), felt(3), felt(4), felt(5), felt(6), felt(7), felt(8)]
        );
    }

    #[rstest]
    #[case::empty(&[])]
    #[case::too_few_4(&[felt(1); 4])]
    #[case::too_few_7(&[felt(1); 7])]
    #[case::too_many_9(&[felt(1); 9])]
    #[case::too_many_16(&[felt(1); 16])]
    fn dword_try_from_felt_slice_wrong_length(#[case] slice: &[Felt]) {
        let result = DoubleWord::try_from(slice);
        assert!(result.is_err());
    }
}
