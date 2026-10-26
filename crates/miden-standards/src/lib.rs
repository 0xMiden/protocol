#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod account;
pub mod code_builder;
mod domain_registry;
pub mod errors;
pub mod interop;
pub mod note;
mod standards_lib;
pub mod tx_script;
pub mod utils;

pub use domain_registry::StandardsDomainRegistry;
pub use standards_lib::StandardsLib;

#[cfg(any(feature = "testing", test))]
pub mod testing;
