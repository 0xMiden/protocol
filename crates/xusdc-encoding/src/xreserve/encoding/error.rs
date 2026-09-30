//! The error type every encoding routine returns.
//!
//! One enum covers the whole encoding surface so a caller handles failures from the amount reducer,
//! the intent parser, and the codecs uniformly.

use core::fmt;

use miden_protocol::utils::serde::DeserializationError;
use miden_standards::interop::eth::EthAmountError;

use super::deposit_intent::DepositIntentField;
use super::domain::CircleDomain;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingError {
    LimbOutOfField,
    /// A u32-LE-packed felt limb exceeds `u32::MAX` (the `packed_felts_to_bytes32` guard on the
    /// burn-note item decode, distinct from `LimbOutOfField`'s 8-byte/felt `>= p` Word-packing check).
    LimbNotU32,
    /// A deposit amount too wide to reduce to an asset amount at all: the quotient does not fit a
    /// `u64`. Every uint256 above 2^128 lands here, whatever the scale exponent.
    AmountTooLarge,
    /// The reduced amount fits a `u64` but exceeds `AssetAmount::MAX`.
    AmountOverCap,
    ScaleExpTooLarge,
    BadMagic,
    BadVersion,
    ZeroField {
        field: DepositIntentField,
    },
    TruncatedHeader,
    LengthMismatch,
    HookDataTooLarge,
    /// A field the mint note must carry as a single `AssetAmount` felt holds a wire value outside
    /// that range, so the note cannot express it. The faucet rebuilds the signed message from what
    /// the note carries, so an unrepresentable field makes the deposit unmintable rather than
    /// merely rejected on-chain.
    FieldNotAssetAmount {
        field: DepositIntentField,
    },
    /// The intent's `remoteToken` is not this faucet's account id.
    RemoteTokenMismatch,
    /// The intent's `remoteDomain` is not the domain the consuming faucet has configured. The
    /// faucet writes its own configured domain into the message it rebuilds, so a divergent one
    /// changes the digest and the attestation stops verifying.
    RemoteDomainMismatch {
        expected: CircleDomain,
        actual: CircleDomain,
    },
    AccountIdOutOfRange,
    NonCanonicalAccountId,
    BurnItemsMalformed,
    JsonSchema(String),
    BinaryMagic,
    BinaryLength,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimbOutOfField => write!(f, "a u64 limb is not a valid field element"),
            Self::LimbNotU32 => write!(f, "packed felt exceeds u32 range"),
            Self::AmountTooLarge => write!(f, "post-scale quotient does not fit a u64"),
            Self::AmountOverCap => {
                write!(f, "post-scale quotient exceeds the asset amount maximum")
            }
            Self::ScaleExpTooLarge => write!(f, "scale exponent exceeds 18"),
            Self::BadMagic => write!(f, "deposit intent magic mismatch"),
            Self::BadVersion => write!(f, "deposit intent version mismatch"),
            Self::ZeroField { field } => write!(f, "deposit intent field {field:?} is zero"),
            Self::TruncatedHeader => write!(f, "deposit intent header is shorter than 240 bytes"),
            Self::LengthMismatch => write!(f, "deposit intent length relation violated"),
            Self::HookDataTooLarge => write!(f, "hook data exceeds the note storage felt bound"),
            Self::FieldNotAssetAmount { field } => {
                write!(
                    f,
                    "deposit intent field {field:?} is not a valid asset amount"
                )
            }
            Self::RemoteTokenMismatch => {
                write!(
                    f,
                    "deposit intent remote token is not the faucet account id"
                )
            }
            Self::RemoteDomainMismatch { expected, actual } => {
                write!(
                    f,
                    "deposit intent remote domain {actual} is not the faucet's configured domain {expected}"
                )
            }
            Self::AccountIdOutOfRange => {
                // The right-aligned (Agglayer-mirroring) layout: the account id region is the
                // 16 bytes `bytes[16..32]` (prefix u64 BE + suffix u64 BE) behind a 16-byte zero
                // pad — the message names the 16-byte region of the shipped layout.
                write!(f, "bytes set outside the 16-byte account id region")
            }
            Self::NonCanonicalAccountId => {
                write!(f, "bytes do not decode to a canonical account id")
            }
            Self::BurnItemsMalformed => write!(f, "burn note items have the wrong length or shape"),
            Self::JsonSchema(msg) => write!(f, "circle json does not match the schema: {msg}"),
            Self::BinaryMagic => write!(f, "circle binary decoder magic mismatch"),
            Self::BinaryLength => write!(f, "circle binary length reconciliation failed"),
        }
    }
}

impl core::error::Error for EncodingError {}

impl From<EncodingError> for DeserializationError {
    /// Carries the reason across the protocol's deserialization boundary. The specific variant is
    /// preserved by the typed entry points (`TryFrom<&[u8]>`), which is where callers that branch
    /// on the failure read it; this spelling exists so the codecs can implement the standard
    /// [`Deserializable`](miden_protocol::utils::serde::Deserializable) trait.
    fn from(error: EncodingError) -> Self {
        Self::InvalidValue(error.to_string())
    }
}

impl From<EthAmountError> for EncodingError {
    /// Re-spells the standards reducer's failures in this crate's error vocabulary, so a caller
    /// of the encoding surface still handles one error type.
    fn from(error: EthAmountError) -> Self {
        match error {
            EthAmountError::ScaleTooLarge => Self::ScaleExpTooLarge,
            // both spellings of "wider than an asset amount can ever be": a quotient past the u64
            // range, and a uint256 that overflowed before any scaling
            EthAmountError::ScaledValueDoesNotFitU64 | EthAmountError::Overflow => {
                Self::AmountTooLarge
            }
            EthAmountError::ScaledValueExceedsMaxFungibleAmount => Self::AmountOverCap,
        }
    }
}
