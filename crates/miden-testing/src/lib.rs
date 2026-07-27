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

mod mock_transaction;
#[cfg(test)]
pub(crate) use mock_transaction::TestTransactionBuilder;
pub use mock_transaction::{ExecError, MockTransaction, MockTransactionBuilder};

pub mod asserts;

#[cfg(test)]
mod executor;

#[cfg(test)]
mod mock_host;

pub mod utils;

#[cfg(test)]
mod assertion;

#[cfg(test)]
mod kernel_tests;

#[cfg(test)]
mod standards;
