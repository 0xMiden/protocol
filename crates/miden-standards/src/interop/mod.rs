//! Types for interoperating with EVM chains: Ethereum addresses, uint256 amounts, and the
//! encoding of Miden account IDs into the Ethereum address format.
//!
//! These are the Rust counterparts of the MASM procedures in `miden::standards::assets::conversion`
//! and `miden::standards::interop::eth_address`.

pub mod amount;
pub mod eth_address;
pub mod eth_embedded_account_id;

pub use amount::{EthAmount, EthAmountError};
pub use eth_address::{AddressConversionError, EthAddress};
pub use eth_embedded_account_id::EthEmbeddedAccountId;
