use alloc::string::ToString;
use core::fmt;
use core::ops::{Add, Sub};

use super::super::errors::AssetError;
use super::super::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// ASSET AMOUNT
// ================================================================================================

/// A validated fungible asset amount.
///
/// Wraps a `u64` that is guaranteed to be at most [`AssetAmount::MAX`]. This type is used in
/// [`FungibleAsset`](super::FungibleAsset) to ensure the amount is always valid.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetAmount(u64);

impl AssetAmount {
    /// The maximum value an asset amount can represent.
    ///
    /// Equal to 2^63 - 2^31. This was chosen so that the amount fits as both a positive and
    /// negative value in a field element.
    pub const MAX: u64 = 2u64.pow(63) - 2u64.pow(31);

    /// Returns a new `AssetAmount` if `amount` does not exceed [`Self::MAX`].
    ///
    /// # Errors
    ///
    /// Returns an error if `amount` is greater than [`Self::MAX`].
    pub fn new(amount: u64) -> Result<Self, AssetError> {
        if amount > Self::MAX {
            return Err(AssetError::FungibleAssetAmountTooBig(amount));
        }
        Ok(Self(amount))
    }
}

impl Add for AssetAmount {
    type Output = Result<Self, AssetError>;

    fn add(self, other: Self) -> Self::Output {
        let raw = u64::from(self)
            .checked_add(u64::from(other))
            .expect("even MAX + MAX should not overflow u64");
        Self::new(raw)
    }
}

impl Sub for AssetAmount {
    type Output = Result<Self, AssetError>;

    fn sub(self, other: Self) -> Self::Output {
        let raw = u64::from(self).checked_sub(u64::from(other)).ok_or(
            AssetError::FungibleAssetAmountNotSufficient {
                minuend: u64::from(self),
                subtrahend: u64::from(other),
            },
        )?;
        Ok(Self(raw))
    }
}

// CONVERSIONS
// ================================================================================================

impl From<u8> for AssetAmount {
    fn from(value: u8) -> Self {
        Self(value as u64)
    }
}

impl From<u16> for AssetAmount {
    fn from(value: u16) -> Self {
        Self(value as u64)
    }
}

impl From<u32> for AssetAmount {
    fn from(value: u32) -> Self {
        Self(value as u64)
    }
}

impl TryFrom<u64> for AssetAmount {
    type Error = AssetError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<AssetAmount> for u64 {
    fn from(amount: AssetAmount) -> Self {
        amount.0
    }
}

// DISPLAY
// ================================================================================================

impl fmt::Display for AssetAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AssetAmount {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.0);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl Deserializable for AssetAmount {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let amount: u64 = source.read()?;
        Self::new(amount).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_amounts() {
        let val: u64 = AssetAmount::new(0).unwrap().into();
        assert_eq!(val, 0);
        let val: u64 = AssetAmount::new(1000).unwrap().into();
        assert_eq!(val, 1000);
        let val: u64 = AssetAmount::new(AssetAmount::MAX).unwrap().into();
        assert_eq!(val, AssetAmount::MAX);
    }

    #[test]
    fn exceeds_max() {
        assert!(AssetAmount::new(AssetAmount::MAX + 1).is_err());
        assert!(AssetAmount::new(u64::MAX).is_err());
    }

    #[test]
    fn from_small_types() {
        let a: AssetAmount = 42u8.into();
        let val: u64 = a.into();
        assert_eq!(val, 42);

        let b: AssetAmount = 1000u16.into();
        let val: u64 = b.into();
        assert_eq!(val, 1000);

        let c: AssetAmount = 100_000u32.into();
        let val: u64 = c.into();
        assert_eq!(val, 100_000);
    }

    #[test]
    fn try_from_u64() {
        assert!(AssetAmount::try_from(0u64).is_ok());
        assert!(AssetAmount::try_from(AssetAmount::MAX).is_ok());
        assert!(AssetAmount::try_from(AssetAmount::MAX + 1).is_err());
    }

    #[test]
    fn display() {
        assert_eq!(AssetAmount::new(12345).unwrap().to_string(), "12345");
    }

    #[test]
    fn into_u64() {
        let amount = AssetAmount::new(500).unwrap();
        let raw: u64 = amount.into();
        assert_eq!(raw, 500);
    }

    #[test]
    fn add_amounts() {
        let a = AssetAmount::new(100).unwrap();
        let b = AssetAmount::new(200).unwrap();
        let val: u64 = (a + b).unwrap().into();
        assert_eq!(val, 300);
    }

    #[test]
    fn add_overflow() {
        let max = AssetAmount::new(AssetAmount::MAX).unwrap();
        let one = AssetAmount::new(1).unwrap();
        assert!((max + one).is_err());
    }

    #[test]
    fn sub_amounts() {
        let a = AssetAmount::new(300).unwrap();
        let b = AssetAmount::new(100).unwrap();
        let val: u64 = (a - b).unwrap().into();
        assert_eq!(val, 200);
    }

    #[test]
    fn sub_underflow() {
        let a = AssetAmount::new(50).unwrap();
        let b = AssetAmount::new(100).unwrap();
        assert!((a - b).is_err());
    }
}
