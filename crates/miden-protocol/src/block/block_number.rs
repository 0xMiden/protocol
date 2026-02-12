use core::fmt;
use core::ops::Add;

use crate::Felt;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// BLOCK NUMBER
// ================================================================================================

/// A convenience wrapper around a `u32` representing the number of a block.
///
/// Each block has a unique number and block numbers increase monotonically by `1`.
#[derive(Debug, Default, Eq, PartialEq, Copy, Clone, PartialOrd, Ord, Hash)]
pub struct BlockNumber(u32);

impl BlockNumber {
    /// The length of an epoch expressed as a power of two. `2^(EPOCH_LENGTH_EXPONENT)` is the
    /// number of blocks in an epoch.
    ///
    /// The epoch of a block can be obtained by shifting the block number to the right by this
    /// exponent.
    pub const EPOCH_LENGTH_EXPONENT: u8 = 16;

    /// The block height of the genesis block.
    pub const GENESIS: Self = Self(0);

    /// The maximum block number.
    pub const MAX: Self = Self(u32::MAX);

    /// Returns the previous block number
    pub fn parent(self) -> Option<BlockNumber> {
        self.checked_sub(1)
    }

    /// Returns the next block number
    pub fn child(self) -> BlockNumber {
        self + 1
    }

    /// Creates the [`BlockNumber`] corresponding to the epoch block for the provided `epoch`.
    pub const fn from_epoch(epoch: u16) -> BlockNumber {
        BlockNumber((epoch as u32) << BlockNumber::EPOCH_LENGTH_EXPONENT)
    }

    /// Returns the epoch to which this block number belongs.
    pub const fn block_epoch(&self) -> u16 {
        (self.0 >> BlockNumber::EPOCH_LENGTH_EXPONENT) as u16
    }

    /// Returns the block number as a `u32`.
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Returns the block number as a `u64`.
    pub fn as_u64(&self) -> u64 {
        self.0 as u64
    }

    /// Returns the block number as a `usize`.
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    /// Checked integer subtraction. Computes `self - rhs`, returning `None` if underflow occurred.
    pub fn checked_sub(&self, rhs: u32) -> Option<Self> {
        self.0.checked_sub(rhs).map(Self)
    }
}

impl Add<u32> for BlockNumber {
    type Output = Self;

    fn add(self, other: u32) -> Self::Output {
        BlockNumber(self.0 + other)
    }
}

impl Serializable for BlockNumber {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.0);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u32>()
    }
}

impl Deserializable for BlockNumber {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read::<u32>().map(BlockNumber::from)
    }
}

impl From<BlockNumber> for Felt {
    fn from(value: BlockNumber) -> Self {
        Felt::from(value.as_u32())
    }
}

impl From<u32> for BlockNumber {
    fn from(value: u32) -> Self {
        BlockNumber(value)
    }
}

impl fmt::Display for BlockNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
