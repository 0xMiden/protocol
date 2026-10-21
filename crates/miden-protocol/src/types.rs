//! A [`DoubleWord`] type used in the Miden protocol and associated utilities.

use alloc::vec::Vec;

use crate::{Felt, Word, WordError};

// DOUBLE WORD
// ================================================================================================

/// A unit of data consisting of 8 field elements (a "double word").
///
/// Conceptually this is two [`Word`]s: the low word (elements 0..4) followed by the high word
/// (elements 4..8).
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
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash)]
pub struct DoubleWord([Felt; DoubleWord::NUM_ELEMENTS]);

impl DoubleWord {
    /// The number of field elements in the double word.
    pub const NUM_ELEMENTS: usize = Word::NUM_ELEMENTS * 2;

    /// Creates a new [`DoubleWord`] from two [`Word`]s.
    pub const fn new(word_lo: Word, word_hi: Word) -> Self {
        let [a, b, c, d] = word_lo.into_elements();
        let [e, f, g, h] = word_hi.into_elements();
        Self([a, b, c, d, e, f, g, h])
    }

    /// Returns the low word of this double word.
    pub const fn lo(&self) -> Word {
        let [a, b, c, d, ..] = self.0;
        Word::new([a, b, c, d])
    }

    /// Returns the high word of this double word.
    pub const fn hi(&self) -> Word {
        let [.., e, f, g, h] = self.0;
        Word::new([e, f, g, h])
    }

    /// Returns the two [`Word`]s of this double word as a tuple in the following format: `(low,
    /// high)`.
    pub fn into_tuple(self) -> (Word, Word) {
        (self.lo(), self.hi())
    }

    /// Returns the double word as a slice of field elements.
    pub fn as_elements(&self) -> &[Felt] {
        &self.0
    }

    /// Returns internal elements of this double word as a vector.
    pub fn to_vec(&self) -> Vec<Felt> {
        self.0.to_vec()
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl IntoIterator for DoubleWord {
    type Item = Felt;
    type IntoIter = <[Felt; 8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// CONVERSIONS: FROM DOUBLE WORD
// ================================================================================================

impl From<DoubleWord> for [Felt; DoubleWord::NUM_ELEMENTS] {
    fn from(value: DoubleWord) -> Self {
        value.0
    }
}

// CONVERSIONS: TO DOUBLE WORD
// ================================================================================================

impl TryFrom<&[Felt]> for DoubleWord {
    type Error = WordError;

    fn try_from(value: &[Felt]) -> Result<Self, Self::Error> {
        value.try_into().map(Self).map_err(|_| {
            WordError::InvalidInputLength("elements", DoubleWord::NUM_ELEMENTS, value.len())
        })
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
    fn dword_try_from_felt_slice_correct_length() {
        let elements: Vec<Felt> = (1..=8).map(felt).collect();
        let dword = DoubleWord::try_from(elements.as_slice()).unwrap();
        assert_eq!(dword.lo(), make_lo());
        assert_eq!(dword.hi(), make_hi());
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
