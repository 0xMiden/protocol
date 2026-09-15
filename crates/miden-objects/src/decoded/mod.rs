//! Schema-shaped records with manually implemented domain construction.
//!
//! Explicitly choose the construction capability, either after decoding fields or through
//! [`crate::DecodeMessageExt`]. For example, building a block header does not authenticate it
//! against its parent:
//!
//! ```
//! use miden_objects::{ConversionError, DecodeMessageExt, proto};
//! use miden_protocol::block::BlockHeader;
//!
//! # fn build(message: proto::blockchain::BlockHeader)
//! #     -> Result<BlockHeader, ConversionError> {
//! let header = message.decode_and_build_unchecked()?;
//! # Ok(header)
//! # }
//! ```
//!
//! Generated records deliberately do not provide direct protobuf-to-domain conversions, even
//! when construction is checked or infallible. This keeps the trust decision explicit.
//!
//! ```compile_fail,E0277
//! use miden_objects::proto;
//! use miden_protocol::block::BlockHeader;
//! let _: BlockHeader = proto::blockchain::BlockHeader::default().try_into().unwrap();
//! ```
//!
//! Borrowing a message must not bypass that decision either:
//!
//! ```compile_fail,E0277
//! use miden_objects::proto;
//! use miden_protocol::block::BlockHeader;
//! let message = proto::blockchain::BlockHeader::default();
//! let _: BlockHeader = (&message).try_into().unwrap();
//! ```
//!
//! ```compile_fail,E0277
//! use miden_objects::proto;
//! use miden_protocol::account::AccountId;
//! let _: AccountId = proto::account::AccountId::default().try_into().unwrap();
//! ```
//!
//! ```compile_fail,E0277
//! use miden_objects::proto;
//! use miden_protocol::block::BlockNumber;
//! let _: BlockNumber = proto::blockchain::BlockNumber::default().into();
//! ```
//!
//! A parsed MAST forest is not trusted until its structure and node hashes are verified:
//!
//! ```compile_fail,E0277
//! use miden_objects::proto;
//! use miden_protocol::MastForest;
//! let _: MastForest = proto::primitives::MastForest::default().try_into().unwrap();
//! ```
//!
//! ```compile_fail,E0277
//! use miden_objects::proto;
//! use miden_protocol::MastForest;
//! let message = proto::primitives::MastForest::default();
//! let _: MastForest = (&message).try_into().unwrap();
//! ```

mod error;
pub use error::VerificationError;

pub mod protocol_config;

pub mod primitives;

pub mod account;

pub mod asset;

pub mod transaction;

pub mod blockchain;

pub mod note;
