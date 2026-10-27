use miden_protocol::batch::ProvenBatch;
use miden_protocol::block::BlockBody;
use miden_protocol::transaction::{
    OrderedTransactionHeaders,
    PublicTransactionLogBundle as VerifiedBundle,
    TransactionLogBundleLimits,
    TransactionLogError,
    TransactionLogs,
};
use prost::Message;
use prost::encoding::{DecodeContext, WireType, check_wire_type, decode_key, skip_field};
pub use proto::transaction::DecodedPublicTransactionLogBundle as PublicTransactionLogBundle;

use crate::decoded::VerificationError;
use crate::{DecodeMessage, Verify, VerifyWith, proto};

#[derive(Debug, thiserror::Error)]
enum LogBundleDecodeError {
    #[error("duplicate bundle commitment")]
    DuplicateCommitment,
    #[error("truncated log bundle frame")]
    TruncatedFrame,
}

impl PublicTransactionLogBundle {
    fn verify_headers(
        self,
        headers: &OrderedTransactionHeaders,
        limits: TransactionLogBundleLimits,
    ) -> Result<VerifiedBundle, VerificationError> {
        limits.check(headers.as_slice().len().max(self.entries.as_slice().len()), 0, 0)?;
        if self.transactions_commitment != headers.commitment() {
            return Err(TransactionLogError::BundleCommitmentMismatch.into());
        }
        let (mut num_logs, mut num_words) = (0, 0);
        let entries = self.entries.try_map(|entry| -> Result<_, VerificationError> {
            num_logs += entry.logs.logs.as_slice().len();
            num_words += entry
                .logs
                .logs
                .as_slice()
                .iter()
                .map(|log| log.content.as_slice().len())
                .sum::<usize>();
            limits.check(headers.as_slice().len(), num_logs, num_words)?;
            Ok((
                miden_protobuf::unwrap_infallible(entry.transaction_id.verify()),
                entry.logs.verify()?,
            ))
        })?;
        Ok(VerifiedBundle::new(entries, headers)?)
    }
}

/// Checks complete public log availability against an already authenticated batch's headers.
/// Does not verify the batch's proof. For untrusted bytes, use the bounded decoder below.
impl VerifyWith<&ProvenBatch> for PublicTransactionLogBundle {
    type Verified = VerifiedBundle;
    type Error = VerificationError;

    fn verify_with(self, batch: &ProvenBatch) -> Result<VerifiedBundle, VerificationError> {
        self.verify_headers(batch.transactions(), TransactionLogBundleLimits::BATCH)
    }
}

/// Checks complete public log availability against an already authenticated block's headers.
/// Does not authenticate the block. For untrusted bytes, use the bounded decoder below.
impl VerifyWith<&BlockBody> for PublicTransactionLogBundle {
    type Verified = VerifiedBundle;
    type Error = VerificationError;

    fn verify_with(self, body: &BlockBody) -> Result<VerifiedBundle, VerificationError> {
        self.verify_headers(body.transactions(), TransactionLogBundleLimits::BLOCK)
    }
}

impl proto::transaction::PublicTransactionLogBundle {
    /// Maximum encoded batch log bundle size, including framing and unknown fields (4 MiB).
    pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
    /// Maximum encoded block log bundle size, including framing and unknown fields (32 MiB).
    pub const MAX_BLOCK_BYTES: usize = 32 * 1024 * 1024;

    /// Decodes untrusted bytes and checks the complete bundle against a batch.
    ///
    /// Bounds bytes before parsing, entries before allocation, and aggregate logs/content before
    /// retaining each entry. Each entry frame is capped at 16 KiB before Prost allocates its
    /// fields.
    pub fn decode_for_batch(
        bytes: &[u8],
        batch: &ProvenBatch,
    ) -> Result<VerifiedBundle, VerificationError> {
        TransactionLogBundleLimits::BATCH.check(batch.transactions().as_slice().len(), 0, 0)?;
        Self::decode_bounded(bytes, TransactionLogBundleLimits::BATCH, Self::MAX_BATCH_BYTES)?
            .decode_fields()?
            .verify_with(batch)
    }

    /// Decodes untrusted bytes and checks the complete bundle against a block body.
    /// The block itself must be authenticated separately. See [`Self::decode_for_batch`] for
    /// bounds.
    pub fn decode_for_block(
        bytes: &[u8],
        body: &BlockBody,
    ) -> Result<VerifiedBundle, VerificationError> {
        TransactionLogBundleLimits::BLOCK.check(body.transactions().as_slice().len(), 0, 0)?;
        Self::decode_bounded(bytes, TransactionLogBundleLimits::BLOCK, Self::MAX_BLOCK_BYTES)?
            .decode_fields()?
            .verify_with(body)
    }

    fn decode_bounded(
        mut bytes: &[u8],
        limits: TransactionLogBundleLimits,
        max_bytes: usize,
    ) -> Result<Self, VerificationError> {
        if bytes.len() > max_bytes {
            return Err(TransactionLogError::BundleLimitExceeded.into());
        }
        let mut bundle = Self::default();
        let mut remaining = limits;
        while !bytes.is_empty() {
            let (tag, wire_type) = decode_key(&mut bytes).map_err(VerificationError::new)?;
            match tag {
                1 => bundle.read_commitment(&mut bytes, wire_type)?,
                2 => bundle.entries.push(read_entry(&mut bytes, wire_type, &mut remaining)?),
                _ => skip_field(wire_type, tag, &mut bytes, DecodeContext::default())
                    .map_err(VerificationError::new)?,
            }
        }
        Ok(bundle)
    }

    fn read_commitment(
        &mut self,
        bytes: &mut &[u8],
        wire_type: WireType,
    ) -> Result<(), VerificationError> {
        if self.transactions_commitment.is_some() {
            return Err(VerificationError::new(LogBundleDecodeError::DuplicateCommitment));
        }
        let frame = read_frame(bytes, wire_type, 64)?;
        self.transactions_commitment =
            Some(proto::primitives::Word::decode(frame).map_err(VerificationError::new)?);
        Ok(())
    }
}

fn read_entry(
    bytes: &mut &[u8],
    wire_type: WireType,
    remaining: &mut TransactionLogBundleLimits,
) -> Result<proto::transaction::PublicTransactionLogEntry, VerificationError> {
    // Reserve the entry before reading its frame or allocating its fields.
    remaining.transactions = remaining
        .transactions
        .checked_sub(1)
        .ok_or(TransactionLogError::BundleLimitExceeded)?;
    // A canonical entry with 64 log records and 64 content words fits in 16 KiB.
    let frame = read_frame(bytes, wire_type, 16 * 1024)?;
    let entry = proto::transaction::PublicTransactionLogEntry::decode(frame)
        .map_err(VerificationError::new)?;
    let (logs, words) = entry_log_counts(&entry)?;
    remaining.logs = remaining
        .logs
        .checked_sub(logs)
        .ok_or(TransactionLogError::BundleLimitExceeded)?;
    remaining.content_words = remaining
        .content_words
        .checked_sub(words)
        .ok_or(TransactionLogError::BundleLimitExceeded)?;
    Ok(entry)
}

fn entry_log_counts(
    entry: &proto::transaction::PublicTransactionLogEntry,
) -> Result<(usize, usize), TransactionLogError> {
    let Some(logs) = &entry.logs else {
        // Missing required fields are rejected by decode_fields after bounded wire decoding.
        return Ok((0, 0));
    };
    let count = logs.logs.len();
    if count > TransactionLogs::MAX_COUNT {
        return Err(TransactionLogError::TooManyLogs(count));
    }
    let words = logs.logs.iter().map(|log| log.content.len()).sum::<usize>();
    if words > TransactionLogs::MAX_NUM_WORDS {
        return Err(TransactionLogError::TooManyTotalContentWords(words));
    }
    Ok((count, words))
}

fn read_frame<'a>(
    bytes: &mut &'a [u8],
    wire_type: WireType,
    max_bytes: usize,
) -> Result<&'a [u8], VerificationError> {
    check_wire_type(WireType::LengthDelimited, wire_type).map_err(VerificationError::new)?;
    let len = prost::decode_length_delimiter(&mut *bytes).map_err(VerificationError::new)?;
    if len > max_bytes {
        return Err(TransactionLogError::BundleLimitExceeded.into());
    }
    if len > bytes.len() {
        return Err(VerificationError::new(LogBundleDecodeError::TruncatedFrame));
    }
    let (frame, rest) = bytes.split_at(len);
    *bytes = rest;
    Ok(frame)
}

#[cfg(test)]
mod tests;
