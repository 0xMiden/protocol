#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

mod mock_chain;
pub use mock_chain::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    MockChainNote,
    MockTransactionInput,
};

mod tx_context;
#[cfg(test)]
pub(crate) use tx_context::TestTransactionBuilder;
#[allow(deprecated)]
pub use tx_context::TransactionContextBuilder;
pub use tx_context::{ExecError, MockTransaction, MockTransactionBuilder};

pub mod asserts;

pub mod executor;

mod mock_host;

pub mod utils;

#[cfg(test)]
mod assertion;

#[cfg(test)]
mod kernel_tests;

#[cfg(test)]
mod standards;
