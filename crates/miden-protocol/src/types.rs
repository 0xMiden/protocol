//! A [`DoubleWord`] type used in the Miden protocol and associated utilities.

use alloc::vec::Vec;
use core::mem::size_of;

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
#[derive(Default, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct DoubleWord {
    word_lo: Word,
    word_hi: Word,
}

// Compile-time assertions to ensure `DoubleWord` has the same layout as `[Felt; 8]`. This is
// relied upon in `as_elements_array`.
const _: () = {
    assert!(DoubleWord::NUM_ELEMENTS == 8, "DoubleWord::NUM_ELEMENTS is assumed to be 8");
    assert!(size_of::<DoubleWord>() == DoubleWord::NUM_ELEMENTS * size_of::<Felt>());
    assert!(core::mem::offset_of!(DoubleWord, word_lo) == 0);
    assert!(core::mem::offset_of!(DoubleWord, word_hi) == Word::SERIALIZED_SIZE);
};

impl core::fmt::Debug for DoubleWord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("DoubleWord").field(self.as_elements_array()).finish()
    }
}

impl DoubleWord {
    /// The number of field elements in the double word.
    pub const NUM_ELEMENTS: usize = Word::NUM_ELEMENTS * 2;

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

    /// Returns the double word as a slice of field elements.
    pub fn as_elements(&self) -> &[Felt] {
        self.as_elements_array()
    }

    /// Returns internal elements of this double word as a vector.
    pub fn to_vec(&self) -> Vec<Felt> {
        self.as_elements().to_vec()
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl IntoIterator for DoubleWord {
    type Item = Felt;
    type IntoIter = <[Felt; 8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        <[Felt; DoubleWord::NUM_ELEMENTS]>::from(self).into_iter()
    }
}

// CONVERSIONS: FROM DOUBLE WORD
// ================================================================================================

impl From<DoubleWord> for [Felt; DoubleWord::NUM_ELEMENTS] {
    fn from(value: DoubleWord) -> Self {
        let [a, b, c, d] = value.word_lo.into_elements();
        let [e, f, g, h] = value.word_hi.into_elements();
        [a, b, c, d, e, f, g, h]
    }
}

// CONVERSIONS: TO DOUBLE WORD
// ================================================================================================

impl TryFrom<&[Felt]> for DoubleWord {
    type Error = WordError;

    fn try_from(value: &[Felt]) -> Result<Self, Self::Error> {
        let [a, b, c, d, e, f, g, h]: [Felt; DoubleWord::NUM_ELEMENTS] =
            value.try_into().map_err(|_| {
                WordError::InvalidInputLength("elements", DoubleWord::NUM_ELEMENTS, value.len())
            })?;
        Ok(Self::new(Word::new([a, b, c, d]), Word::new([e, f, g, h])))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

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

    #[test]
    fn dword_element_ordering() {
        let dword = make_dword();
        let expected = [felt(1), felt(2), felt(3), felt(4), felt(5), felt(6), felt(7), felt(8)];

        assert_eq!(dword.as_elements(), &expected);
        assert_eq!(<[Felt; DoubleWord::NUM_ELEMENTS]>::from(dword), expected);
        assert_eq!(dword.into_iter().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn dword_elements_array_layout() {
        let dword = make_dword();
        let elements = dword.as_elements();

        let lo_ptr = core::ptr::addr_of!(dword.word_lo);
        assert_eq!(elements.as_ptr() as *const Word, lo_ptr);

        let hi_ptr = core::ptr::addr_of!(dword.word_hi);
        assert_eq!(unsafe { elements.as_ptr().add(4) } as *const Word, hi_ptr);
    }

    #[test]
    fn dword_try_from_felt_slice_correct_length() {
        let elements: Vec<Felt> = (1..=8).map(felt).collect();
        let dword = DoubleWord::try_from(elements.as_slice()).unwrap();
        assert_eq!(dword, make_dword());
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
