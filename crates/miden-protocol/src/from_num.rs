use miden_assembly_syntax::PrimeField64;
use miden_core::field::QuotientMap;

use crate::Felt;

/// Infallible conversion from a numeric type into a [`Felt`].
///
/// Implemented for integer types whose full range fits within the field modulus (u8, u16, u32).
pub trait FromNum<Num> {
    /// Converts the provided number into a [`Felt`].
    fn from_num(num: Num) -> Felt;
}

/// Fallible conversion from a numeric type into a [`Felt`].
///
/// Implemented for integer types that may exceed the field modulus (u64).
pub trait TryFromNum<Num> {
    type Error;

    /// Tries to convert the provided number into a [`Felt`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided number is equal or larger than the field's modulus.
    fn try_from_num(num: Num) -> Result<Felt, Self::Error>;
}

impl FromNum<u8> for Felt {
    fn from_num(num: u8) -> Felt {
        Felt::new(u64::from(num))
    }
}

impl FromNum<u16> for Felt {
    fn from_num(num: u16) -> Felt {
        Felt::new(u64::from(num))
    }
}

impl FromNum<u32> for Felt {
    fn from_num(num: u32) -> Felt {
        Felt::new(u64::from(num))
    }
}

impl TryFromNum<u64> for Felt {
    type Error = FeltError;

    fn try_from_num(num: u64) -> Result<Felt, Self::Error> {
        Felt::from_canonical_checked(num).ok_or(FeltError::NumberOutOfRange(num))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FeltError {
    #[error("{0} is outside the felt modulus {modulus}", modulus = Felt::ORDER_U64)]
    NumberOutOfRange(u64),
}
