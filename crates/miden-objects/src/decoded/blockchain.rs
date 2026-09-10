//! Domain construction for decoded blockchain messages.
use miden_protobuf::unwrap_infallible;
pub use proto::blockchain::DecodedTrackedMmrLeaf as TrackedMmrLeaf;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_utils;

impl Verify for TrackedMmrLeaf {
    type Verified = (u64, miden_protocol::Word, alloc::vec::Vec<miden_protocol::Word>);
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((self.position, self.leaf, self.path))
    }
}

pub use proto::blockchain::DecodedBlockNumber as BlockNumber;

impl Verify for BlockNumber {
    type Verified = miden_protocol::block::BlockNumber;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(self.block_num.into())
    }
}

pub use proto::blockchain::DecodedFeeParameters as FeeParameters;

impl Verify for FeeParameters {
    type Verified = miden_protocol::block::FeeParameters;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(self.verification_base_fee))
    }
}

pub use proto::blockchain::DecodedNextProtocolConfig as NextProtocolConfig;

impl Verify for NextProtocolConfig {
    type Verified = miden_protocol::protocol_config::NextProtocolConfig;
    type Error = miden_protocol::errors::ProtocolConfigError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let effective_from = unwrap_infallible(self.effective_from.verify());
        Self::Verified::new(effective_from, self.protocol_config)
    }
}

pub use proto::blockchain::DecodedValidatorConfig as ValidatorConfig;

impl Verify for ValidatorConfig {
    type Verified = miden_protocol::block::ValidatorConfig;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let keys = self.keys.into_iter().map(|key| unwrap_infallible(key.verify())).collect();
        Ok(Self::Verified::new(keys, self.quorum.try_into()?)?)
    }
}

pub use proto::blockchain::DecodedBlockHeader as BlockHeader;

/// Builds a header without validating its parent linkage, signatures, or protocol transition.
impl crate::BuildUnchecked for BlockHeader {
    type Output = miden_protocol::block::BlockHeader;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        if self.version != proto::blockchain::BlockVersion::V1 {
            return Err(BlockHeaderError::UnspecifiedVersion.into());
        }
        Ok(Self::Output::new(
            self.prev_block_commitment,
            unwrap_infallible(self.block_num.verify()),
            self.chain_commitment,
            self.account_root,
            self.nullifier_root,
            self.note_root,
            self.tx_commitment,
            self.validator_config.verify()?,
            unwrap_infallible(self.fee_parameters.verify()),
            self.protocol_config_commitment,
            self.next_protocol_config.map(Verify::verify).transpose()?,
            self.timestamp,
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlockHeaderError {
    #[error("block header version is unspecified")]
    UnspecifiedVersion,
}

pub use proto::blockchain::DecodedPartialBlockchain as PartialBlockchain;

/// Checks MMR reconstruction and header membership, but not header parent linkage or a trusted
/// root.
impl crate::BuildUnchecked for PartialBlockchain {
    type Output = miden_protocol::transaction::PartialBlockchain;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        use miden_protocol::crypto::merkle::MerklePath;
        use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks, PartialMmr};

        let size = usize::try_from(self.forest)?;
        let peaks = MmrPeaks::new(Forest::new(size)?, self.peaks)?;
        let mut mmr = PartialMmr::from_peaks(peaks);
        let mut previous = None;
        for tracked in self.tracked_leaves {
            let position = usize::try_from(tracked.position)?;
            if position >= size {
                return Err(PartialBlockchainError::Position { position, size }.into());
            }
            if previous.is_some_and(|previous| position <= previous) {
                return Err(PartialBlockchainError::LeafOrder.into());
            }
            previous = Some(position);
            mmr.track(position, tracked.leaf, &MerklePath::new(tracked.path))?;
        }
        let mut previous = None;
        let mut headers = alloc::vec::Vec::new();
        for header in self.block_headers {
            let header = header.build_unchecked()?;
            if previous.is_some_and(|previous| header.block_num() <= previous) {
                return Err(PartialBlockchainError::HeaderOrder.into());
            }
            previous = Some(header.block_num());
            headers.push(header);
        }
        Ok(Self::Output::new(mmr, headers)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PartialBlockchainError {
    #[error("tracked leaf position {position} is outside forest of size {size}")]
    Position { position: usize, size: usize },
    #[error("tracked leaf positions must be unique and strictly increasing")]
    LeafOrder,
    #[error("block headers must be unique and ordered by ascending block number")]
    HeaderOrder,
}

pub use proto::blockchain::DecodedBlockAccountUpdate as BlockAccountUpdate;

impl Verify for BlockAccountUpdate {
    type Verified = miden_protocol::block::BlockAccountUpdate;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(
            self.account_id.verify()?,
            self.final_state_commitment,
            self.details.verify()?,
        )?)
    }
}

pub use proto::blockchain::DecodedIndexedOutputNote as IndexedOutputNote;

impl Verify for IndexedOutputNote {
    type Verified = (usize, miden_protocol::transaction::OutputNote);
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((self.note_index_in_batch.try_into()?, self.note.verify()?))
    }
}

pub use proto::blockchain::DecodedOutputNoteBatch as OutputNoteBatch;

impl Verify for OutputNoteBatch {
    type Verified = miden_protocol::block::OutputNoteBatch;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        self.notes.into_iter().map(Verify::verify).collect()
    }
}

pub use proto::blockchain::DecodedBlockBody as BlockBody;

/// Checks body invariants, but trusts transaction ordering and unchecked input-note commitments.
impl crate::BuildUnchecked for BlockBody {
    type Output = miden_protocol::block::BlockBody;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        let updates = self
            .updated_accounts
            .into_iter()
            .map(Verify::verify)
            .collect::<Result<_, _>>()?;
        let notes = self
            .output_note_batches
            .into_iter()
            .map(Verify::verify)
            .collect::<Result<_, _>>()?;
        let nullifiers = self
            .created_nullifiers
            .into_iter()
            .map(miden_protocol::note::Nullifier::from_raw)
            .collect();
        let transactions = self
            .transactions
            .into_iter()
            .map(crate::BuildUnchecked::build_unchecked)
            .collect::<Result<_, _>>()?;
        Ok(Self::Output::new(
            updates,
            notes,
            nullifiers,
            miden_protocol::transaction::OrderedTransactionHeaders::new_unchecked(transactions),
        )?)
    }
}

pub use proto::blockchain::DecodedSignedBlock as SignedBlock;

/// Checks header/body consistency but does not authenticate against a trusted parent.
impl crate::BuildUnchecked for SignedBlock {
    type Output = miden_protocol::block::SignedBlock;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        self.build(None)
    }
}

impl SignedBlock {
    fn build(
        self,
        parent: Option<&miden_protocol::block::BlockHeader>,
    ) -> Result<miden_protocol::block::SignedBlock, VerificationError> {
        use crate::BuildUnchecked;

        let header = self.header.build_unchecked()?;
        let body = self.body.build_unchecked()?;
        let signatures = self
            .signatures
            .into_iter()
            .map(|signature| unwrap_infallible(signature.verify()))
            .collect();
        let signatures = miden_protocol::block::BlockSignatures::new(signatures)
            .map_err(VerificationError::new)?;
        let block = miden_protocol::block::SignedBlock::new_unchecked(header, body, signatures);
        block.validate(parent)?;
        Ok(block)
    }
}

/// Authenticates the block against an already-trusted parent, in addition to self-consistency.
/// This does not re-execute transactions or validate the account/nullifier state transition.
impl crate::VerifyWith<&miden_protocol::block::BlockHeader> for SignedBlock {
    type Verified = miden_protocol::block::SignedBlock;
    type Error = VerificationError;
    fn verify_with(
        self,
        parent: &miden_protocol::block::BlockHeader,
    ) -> Result<Self::Verified, Self::Error> {
        self.build(Some(parent))
    }
}
