use alloc::string::ToString;
use core::fmt;

use super::AssetError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// ASSET AMOUNT
// ================================================================================================

/// A validated amount for a [`super::FungibleAsset`].
///
/// The inner value is guaranteed to be at most [`AssetAmount::MAX`].
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetAmount(u64);

impl AssetAmount {
    /// The maximum amount a fungible asset can represent.
    ///
    /// This number was chosen so that it can be represented as a positive and negative number in a
    /// field element. See `account_delta.masm` for more details on how this number was chosen.
    pub const MAX: Self = Self(2u64.pow(63) - 2u64.pow(31));

    /// An amount of zero.
    pub const ZERO: Self = Self(0);

    /// Creates a new [`AssetAmount`] after validating that `amount` does not exceed
    /// [`Self::MAX`].
    ///
    /// # Errors
    ///
    /// Returns [`AssetError::FungibleAssetAmountTooBig`] if `amount` exceeds [`Self::MAX`].
    pub fn new(amount: u64) -> Result<Self, AssetError> {
        if amount > Self::MAX.0 {
            return Err(AssetError::FungibleAssetAmountTooBig(amount));
        }
        Ok(Self(amount))
    }

    /// Returns the inner `u64` value.
    pub const fn inner(&self) -> u64 {
        self.0
    }

    /// Creates a new [`AssetAmount`] without validating bounds.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `amount <= AssetAmount::MAX`.
    pub(crate) const fn new_unchecked(amount: u64) -> Self {
        Self(amount)
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl From<u8> for AssetAmount {
    fn from(amount: u8) -> Self {
        Self(amount as u64)
    }
}

impl From<u16> for AssetAmount {
    fn from(amount: u16) -> Self {
        Self(amount as u64)
    }
}

impl From<u32> for AssetAmount {
    fn from(amount: u32) -> Self {
        Self(amount as u64)
    }
}

impl TryFrom<u64> for AssetAmount {
    type Error = AssetError;

    fn try_from(amount: u64) -> Result<Self, Self::Error> {
        Self::new(amount)
    }
}

impl From<AssetAmount> for u64 {
    fn from(amount: AssetAmount) -> Self {
        amount.0
    }
}

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
    fn asset_amount_max_value() {
        let max = AssetAmount::MAX;
        assert_eq!(max.inner(), 2u64.pow(63) - 2u64.pow(31));
    }

    #[test]
    fn asset_amount_new_valid() {
        assert!(AssetAmount::new(0).is_ok());
        assert!(AssetAmount::new(100).is_ok());
        assert!(AssetAmount::new(AssetAmount::MAX.inner()).is_ok());
    }

    #[test]
    fn asset_amount_new_exceeds_max() {
        assert!(AssetAmount::new(AssetAmount::MAX.inner() + 1).is_err());
        assert!(AssetAmount::new(u64::MAX).is_err());
    }

    #[test]
    fn asset_amount_from_small_types() {
        let a: AssetAmount = 42u8.into();
        assert_eq!(a.inner(), 42);

        let b: AssetAmount = 1000u16.into();
        assert_eq!(b.inner(), 1000);

        let c: AssetAmount = 1_000_000u32.into();
        assert_eq!(c.inner(), 1_000_000);
    }

    #[test]
    fn asset_amount_try_from_u64() {
        assert!(AssetAmount::try_from(100u64).is_ok());
        assert!(AssetAmount::try_from(AssetAmount::MAX.inner() + 1).is_err());
    }

    #[test]
    fn asset_amount_into_u64() {
        let amount = AssetAmount::new(42).unwrap();
        let val: u64 = amount.into();
        assert_eq!(val, 42);
    }

    #[test]
    fn asset_amount_display() {
        let amount = AssetAmount::new(12345).unwrap();
        assert_eq!(format!("{amount}"), "12345");
    }

    #[test]
    fn asset_amount_ordering() {
        let a = AssetAmount::new(10).unwrap();
        let b = AssetAmount::new(20).unwrap();
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, AssetAmount::new(10).unwrap());
    }

    #[test]
    fn asset_amount_default_is_zero() {
        assert_eq!(AssetAmount::default(), AssetAmount::ZERO);
        assert_eq!(AssetAmount::default().inner(), 0);
    }

    #[test]
    fn asset_amount_serde_roundtrip() {
        let amount = AssetAmount::new(999).unwrap();
        let bytes = amount.to_bytes();
        let restored = AssetAmount::read_from_bytes(&bytes).unwrap();
        assert_eq!(amount, restored);
    }
}
