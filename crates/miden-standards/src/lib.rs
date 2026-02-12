#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod auth_scheme;
pub use auth_scheme::AuthScheme;

pub mod account;
pub mod code_builder;
pub mod errors;
pub mod note;
mod standards_lib;

pub use standards_lib::StandardsLib;

#[cfg(any(feature = "testing", test))]
pub mod testing;
