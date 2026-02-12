use alloc::collections::BTreeSet;

use miden_core::utils::{ByteReader, ByteWriter, Deserializable, Serializable};
use miden_crypto::merkle::mmr::{Forest, Mmr, MmrError, MmrPeaks, MmrProof, PartialMmr};
use miden_processor::DeserializationError;

use crate::Word;
use crate::block::BlockNumber;

/// The [Merkle Mountain Range](Mmr) defining the Miden blockchain.
///
/// The values of the leaves in the MMR are the commitments of blocks, i.e.
/// [`BlockHeader::commitment`](crate::block::BlockHeader::commitment).
///
/// Each new block updates the blockchain by adding **the previous block's commitment** to the MMR.
/// This means the chain commitment found in block 10's header commits to all blocks 0..=9, but not
/// 10 itself. This results from the fact that block 10 cannot compute its own block commitment
/// and thus cannot add itself to the chain. Hence, the blockchain is lagging behind by one block.
///
/// Some APIs take a _checkpoint_ which is equivalent to the concept of _forest_ of the underlying
/// MMR. As an example, if the blockchain has 20 blocks in total, and the checkpoint is 10, then
/// the API works in the context of the chain at the time it had 10 blocks, i.e. it contains blocks
/// 0..=9. This is useful, for example, to retrieve proofs that are valid when verified against the
/// chain commitment of block 10.
///
/// The maximum number of supported blocks is [`u32::MAX`]. This is not validated however.
#[derive(Debug, Clone)]
pub struct Blockchain {
    mmr: Mmr,
}

impl Blockchain {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new, empty blockchain.
    pub fn new() -> Self {
        Self { mmr: Mmr::new() }
    }

    /// Construct a new blockchain from an [`Mmr`] without validation.
    pub fn from_mmr_unchecked(mmr: Mmr) -> Self {
        Self { mmr }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of blocks in the chain.
    pub fn num_blocks(&self) -> u32 {
        // SAFETY: The chain should never contain more than u32::MAX blocks, so a non-panicking cast
        // should be fine.
        self.mmr.forest().num_leaves() as u32
    }

    /// Returns the tip of the chain, i.e. the number of the latest block in the chain, unless the
    /// chain is empty.
    pub fn chain_tip(&self) -> Option<BlockNumber> {
        if self.num_blocks() == 0 {
            return None;
        }

        Some(BlockNumber::from(self.num_blocks() - 1))
    }

    /// Returns the chain commitment.
    pub fn commitment(&self) -> Word {
        self.peaks().hash_peaks()
    }

    /// Returns the current peaks of the MMR.
    pub fn peaks(&self) -> MmrPeaks {
        self.mmr.peaks()
    }

    /// Returns the peaks of the chain at the state of the given block.
    ///
    /// Note that this represents the state of the chain where the block at the given number **is
    /// not yet** in the chain. For example, if the given block number is 5, then the returned peaks
    /// represent the chain whose latest block is 4. See the type-level documentation for why this
    /// is the case.
    ///
    /// # Errors
    ///
    /// Returns an error if the specified `block` exceeds the number of blocks in the chain.
    pub fn peaks_at(&self, checkpoint: BlockNumber) -> Result<MmrPeaks, MmrError> {
        self.mmr.peaks_at(Forest::new(checkpoint.as_usize()))
    }

    /// Returns an [`MmrProof`] for the `block` with the given number.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The specified block number does not exist in the chain.
    pub fn open(&self, block: BlockNumber) -> Result<MmrProof, MmrError> {
        self.mmr.open(block.as_usize())
    }

    /// Returns an [`MmrProof`] for the `block` with the given number at the state of the given
    /// `checkpoint`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The specified block number does not exist in the chain.
    /// - The specified checkpoint number exceeds the number of blocks in the chain.
    pub fn open_at(
        &self,
        block: BlockNumber,
        checkpoint: BlockNumber,
    ) -> Result<MmrProof, MmrError> {
        self.mmr.open_at(block.as_usize(), Forest::new(checkpoint.as_usize()))
    }

    /// Returns a reference to the underlying [`Mmr`].
    pub fn as_mmr(&self) -> &Mmr {
        &self.mmr
    }

    /// Creates a [`PartialMmr`] at the state of the given block. This means the hashed peaks of the
    /// returned partial MMR will match the checkpoint's chain commitment. This MMR will include
    /// authentication paths for all blocks in the provided `blocks` set.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the specified `latest_block_number` exceeds the number of blocks in the chain.
    /// - any block in `blocks` is not in the state of the chain specified by `latest_block_number`.
    pub fn partial_mmr_from_blocks(
        &self,
        blocks: &BTreeSet<BlockNumber>,
        checkpoint: BlockNumber,
    ) -> Result<PartialMmr, MmrError> {
        // Using latest block as the target state means we take the state of the MMR one before
        // the latest block.
        let peaks = self.peaks_at(checkpoint)?;

        // Track the merkle paths of the requested blocks in the partial MMR.
        let mut partial_mmr = PartialMmr::from_peaks(peaks);
        for block_num in blocks.iter() {
            let leaf = self.mmr.get(block_num.as_usize())?;
            let path = self.open_at(*block_num, checkpoint)?.merkle_path;

            // SAFETY: We should be able to fill the partial MMR with data from the partial
            // blockchain without errors, otherwise it indicates the blockchain is
            // invalid.
            partial_mmr
                .track(block_num.as_usize(), leaf, &path)
                .expect("filling partial mmr with data from mmr should succeed");
        }

        Ok(partial_mmr)
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds a block commitment to the MMR.
    ///
    /// The caller must ensure that this commitent is the one for the next block in the chain.
    pub fn push(&mut self, block_commitment: Word) {
        self.mmr.add(block_commitment);
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Blockchain {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.mmr.write_into(target);
    }
}

impl Deserializable for Blockchain {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let chain = Mmr::read_from(source)?;
        Ok(Self::from_mmr_unchecked(chain))
    }
}
