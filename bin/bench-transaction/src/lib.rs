#![cfg_attr(not(feature = "concurrent"), no_std)]

#[cfg(feature = "concurrent")]
pub mod context_setups;
