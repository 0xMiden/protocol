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
    TxContextInput,
};

mod tx_context;
pub use tx_context::{ExecError, TransactionContext, TransactionContextBuilder};

pub mod executor;

mod mock_host;

pub mod utils;

#[cfg(test)]
mod kernel_tests;

#[cfg(test)]
mod standards;
