use miden_protocol::transaction::{
    OrderedTransactionHeaders,
    PublicTransactionLogs as VerifiedLogs,
    TransactionId,
    TransactionLogs,
};
pub use proto::transaction::DecodedPublicTransactionLogs as PublicTransactionLogs;

use crate::decoded::VerificationError;
use crate::{Verify, VerifyWith, proto};

/// Checks completeness, visibility and payload commitments against the owner's transaction headers.
/// This does not authenticate those headers; the enclosing owner enforces its aggregate limits.
impl VerifyWith<&OrderedTransactionHeaders> for PublicTransactionLogs {
    type Verified = VerifiedLogs;
    type Error = VerificationError;

    fn verify_with(
        self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<Self::Verified, Self::Error> {
        Ok(VerifiedLogs::new(self.verify_entries()?, headers)?)
    }
}

/// Checks a block's public logs against its transaction headers in batch order.
impl VerifyWith<&[OrderedTransactionHeaders]> for PublicTransactionLogs {
    type Verified = VerifiedLogs;
    type Error = VerificationError;

    fn verify_with(
        self,
        batches: &[OrderedTransactionHeaders],
    ) -> Result<Self::Verified, Self::Error> {
        Ok(VerifiedLogs::new_for_block(self.verify_entries()?, batches)?)
    }
}

impl PublicTransactionLogs {
    fn verify_entries(
        self,
    ) -> Result<alloc::vec::Vec<(TransactionId, TransactionLogs)>, VerificationError> {
        self.entries.try_map(|entry| -> Result<_, VerificationError> {
            Ok((
                miden_protobuf::unwrap_infallible(entry.transaction_id.verify()),
                entry.logs.verify()?,
            ))
        })
    }
}

use miden_protocol::transaction::{
    PublicLogLimits,
    TransactionLog,
    TransactionLogError,
    TransactionLogs,
};
use prost::Message;
use prost::encoding::{DecodeContext, WireType, check_wire_type, decode_key, skip_field};

// Canonical protobuf field numbers from batch.proto, block.proto and transaction.proto.
const BATCH_HEADERS_TAG: u32 = 7;
const BATCH_LOGS_TAG: u32 = 9;
const BLOCK_HEADERS_TAG: u32 = 4;
const BLOCK_LOGS_TAG: u32 = 5;
const SIGNED_BODY_TAG: u32 = 2;
const LOG_ENTRIES_TAG: u32 = 1;
const ENTRY_LOGS_TAG: u32 = 2;
const LOG_RECORDS_TAG: u32 = 1;
const LOG_CONTENT_TAG: u32 = 3;

const MAX_BATCH_LOG_BYTES: usize = 4 * 1024 * 1024;
const MAX_BLOCK_LOG_BYTES: usize = 32 * 1024 * 1024;
const MAX_LOG_ENTRY_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
enum PublicLogDecodeError {
    #[error("duplicate field {0}")]
    DuplicateField(&'static str),
    #[error("truncated embedded log frame")]
    TruncatedFrame,
    #[error("missing field {0}")]
    MissingField(&'static str),
}

impl proto::transaction::ProvenBatch {
    /// Decodes bytes after checking embedded public-log allocation budgets.
    ///
    /// Counts all transaction headers, bounds the encoded log field to 4 MiB (including framing
    /// and unknown fields), and caps each entry frame at 16 KiB before Prost allocates it.
    /// Callers must still decode fields, build the domain object, and authenticate the batch.
    /// This does not bound proof/note fields; transports must also impose message-size limits.
    ///
    /// # Errors
    /// Rejects malformed framing, missing/duplicate log fields, or excessive log resource counts.
    pub fn decode_bounded(bytes: &[u8]) -> Result<Self, VerificationError> {
        preflight_owner(
            bytes,
            BATCH_HEADERS_TAG,
            BATCH_LOGS_TAG,
            PublicLogLimits::BATCH,
            MAX_BATCH_LOG_BYTES,
        )?;
        Self::decode(bytes).map_err(VerificationError::new)
    }
}

impl proto::blockchain::BlockBody {
    /// Decodes bytes after checking embedded public-log allocation budgets.
    ///
    /// The encoded log field is capped at 32 MiB, including framing and unknown fields. Each entry
    /// is capped at 16 KiB. Other fields require transport limits. This does not validate domain
    /// invariants or authenticate the block; use the normal decoded construction/verification path.
    ///
    /// # Errors
    /// Rejects malformed framing, missing/duplicate log fields, or excessive log resource counts.
    pub fn decode_bounded(bytes: &[u8]) -> Result<Self, VerificationError> {
        preflight_owner(
            bytes,
            BLOCK_HEADERS_TAG,
            BLOCK_LOGS_TAG,
            PublicLogLimits::BLOCK,
            MAX_BLOCK_LOG_BYTES,
        )?;
        Self::decode(bytes).map_err(VerificationError::new)
    }
}

impl proto::blockchain::SignedBlock {
    /// Decodes a signed block after checking its nested body's log allocation budgets.
    ///
    /// This is the envelope equivalent of [`proto::blockchain::BlockBody::decode_bounded`].
    /// It does not verify signatures or authenticate the chain. Generated Prost/gRPC decoding
    /// alone does not perform this preflight and still needs transport message-size limits.
    ///
    /// # Errors
    /// Rejects missing/duplicate bodies and all nested log framing and resource violations.
    pub fn decode_bounded(bytes: &[u8]) -> Result<Self, VerificationError> {
        let mut remaining = bytes;
        let mut seen_body = false;
        while !remaining.is_empty() {
            let (tag, wire) = decode_key(&mut remaining).map_err(VerificationError::new)?;
            if tag == SIGNED_BODY_TAG {
                once(&mut seen_body, "body")?;
                let body = read_frame(&mut remaining, wire)?;
                preflight_owner(
                    body,
                    BLOCK_HEADERS_TAG,
                    BLOCK_LOGS_TAG,
                    PublicLogLimits::BLOCK,
                    MAX_BLOCK_LOG_BYTES,
                )?;
            } else {
                skip(&mut remaining, tag, wire)?;
            }
        }
        if !seen_body {
            return Err(VerificationError::new(PublicLogDecodeError::MissingField("body")));
        }
        Self::decode(bytes).map_err(VerificationError::new)
    }
}

/// Preflight only borrows byte slices: no untrusted records are allocated before the entire
/// enclosing message has passed. Header and entry budgets are independent of protobuf field order.
fn preflight_owner(
    mut bytes: &[u8],
    header_tag: u32,
    logs_tag: u32,
    limits: PublicLogLimits,
    max_bytes: usize,
) -> Result<(), VerificationError> {
    let mut headers_left = limits.transactions();
    let mut seen_logs = false;
    while !bytes.is_empty() {
        let before = bytes.len();
        let (tag, wire) = decode_key(&mut bytes).map_err(VerificationError::new)?;
        if tag == header_tag {
            charge(&mut headers_left)?;
            read_frame(&mut bytes, wire)?;
        } else if tag == logs_tag {
            once(&mut seen_logs, "public_logs")?;
            let logs = read_frame(&mut bytes, wire)?;
            // The difference includes the owner field's tag and length delimiter.
            if before - bytes.len() > max_bytes {
                return Err(TransactionLogError::PublicLogsLimitExceeded.into());
            }
            preflight_logs(logs, limits)?;
        } else {
            skip(&mut bytes, tag, wire)?;
        }
    }
    if !seen_logs {
        return Err(VerificationError::new(PublicLogDecodeError::MissingField("public_logs")));
    }
    Ok(())
}

fn preflight_logs(mut bytes: &[u8], limits: PublicLogLimits) -> Result<(), VerificationError> {
    let mut entries_left = limits.transactions();
    let mut logs_left = limits.logs();
    let mut words_left = limits.content_words();
    while !bytes.is_empty() {
        let (tag, wire) = decode_key(&mut bytes).map_err(VerificationError::new)?;
        if tag == LOG_ENTRIES_TAG {
            charge(&mut entries_left)?;
            let entry = read_frame(&mut bytes, wire)?;
            if entry.len() > MAX_LOG_ENTRY_BYTES {
                return Err(TransactionLogError::PublicLogsLimitExceeded.into());
            }
            preflight_entry(entry, &mut logs_left, &mut words_left)?;
        } else {
            skip(&mut bytes, tag, wire)?;
        }
    }
    Ok(())
}

fn preflight_entry(
    mut bytes: &[u8],
    logs_left: &mut usize,
    words_left: &mut usize,
) -> Result<(), VerificationError> {
    let mut seen_logs = false;
    while !bytes.is_empty() {
        let (tag, wire) = decode_key(&mut bytes).map_err(VerificationError::new)?;
        if tag == ENTRY_LOGS_TAG {
            once(&mut seen_logs, "entry.logs")?;
            preflight_records(read_frame(&mut bytes, wire)?, logs_left, words_left)?;
        } else {
            skip(&mut bytes, tag, wire)?;
        }
    }
    // Required entry fields are checked later by decode_fields, before domain construction.
    Ok(())
}

fn preflight_records(
    mut bytes: &[u8],
    logs_left: &mut usize,
    words_left: &mut usize,
) -> Result<(), VerificationError> {
    let mut tx_logs_left = TransactionLogs::MAX_COUNT;
    let mut tx_words_left = TransactionLogs::MAX_NUM_WORDS;
    while !bytes.is_empty() {
        let (tag, wire) = decode_key(&mut bytes).map_err(VerificationError::new)?;
        if tag == LOG_RECORDS_TAG {
            tx_logs_left = tx_logs_left
                .checked_sub(1)
                .ok_or(TransactionLogError::TooManyLogs(TransactionLogs::MAX_COUNT + 1))?;
            charge(logs_left)?;
            preflight_record(read_frame(&mut bytes, wire)?, &mut tx_words_left, words_left)?;
        } else {
            skip(&mut bytes, tag, wire)?;
        }
    }
    Ok(())
}

fn preflight_record(
    mut bytes: &[u8],
    tx_words_left: &mut usize,
    words_left: &mut usize,
) -> Result<(), VerificationError> {
    let mut log_words_left = TransactionLog::MAX_NUM_WORDS;
    while !bytes.is_empty() {
        let (tag, wire) = decode_key(&mut bytes).map_err(VerificationError::new)?;
        if tag == LOG_CONTENT_TAG {
            log_words_left = log_words_left.checked_sub(1).ok_or(
                TransactionLogError::TooManyContentWords(TransactionLog::MAX_NUM_WORDS + 1),
            )?;
            *tx_words_left = tx_words_left.checked_sub(1).ok_or(
                TransactionLogError::TooManyTotalContentWords(TransactionLogs::MAX_NUM_WORDS + 1),
            )?;
            charge(words_left)?;
            read_frame(&mut bytes, wire)?;
        } else {
            skip(&mut bytes, tag, wire)?;
        }
    }
    Ok(())
}

fn charge(remaining: &mut usize) -> Result<(), TransactionLogError> {
    *remaining = remaining.checked_sub(1).ok_or(TransactionLogError::PublicLogsLimitExceeded)?;
    Ok(())
}

fn once(seen: &mut bool, field: &'static str) -> Result<(), VerificationError> {
    if *seen {
        return Err(VerificationError::new(PublicLogDecodeError::DuplicateField(field)));
    }
    *seen = true;
    Ok(())
}

fn read_frame<'a>(bytes: &mut &'a [u8], wire: WireType) -> Result<&'a [u8], VerificationError> {
    check_wire_type(WireType::LengthDelimited, wire).map_err(VerificationError::new)?;
    let len = prost::decode_length_delimiter(&mut *bytes).map_err(VerificationError::new)?;
    if len > bytes.len() {
        return Err(VerificationError::new(PublicLogDecodeError::TruncatedFrame));
    }
    let (frame, rest) = bytes.split_at(len);
    *bytes = rest;
    Ok(frame)
}

fn skip(bytes: &mut &[u8], tag: u32, wire: WireType) -> Result<(), VerificationError> {
    skip_field(wire, tag, bytes, DecodeContext::default()).map_err(VerificationError::new)
}

#[cfg(test)]
mod tests;
