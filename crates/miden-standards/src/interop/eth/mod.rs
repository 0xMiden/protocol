//! Types for interoperating with EVM chains: Ethereum addresses, uint256 amounts, and the
//! encoding of Miden account IDs into the Ethereum address format.
//!
//! These are the Rust counterparts of the MASM procedures in
//! `miden::standards::assets::asset_amount` and `miden::standards::interop::eth`.

pub mod address;
pub mod amount;
pub mod embedded_account_id;

pub use address::{AddressConversionError, EthAddress};
pub use amount::{EthAmount, EthAmountError};
pub use embedded_account_id::EthEmbeddedAccountId;
