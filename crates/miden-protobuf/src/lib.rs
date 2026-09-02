//! Shared runtime, derive, and Prost build support for Protobuf-to-domain conversions.

#![no_std]

extern crate alloc;

#[cfg(feature = "build")]
extern crate std;

#[cfg(feature = "build")]
pub mod build;
mod decode;
mod error;

pub use decode::{
    DecodeField,
    DecodeRepeated,
    OptionalField,
    RepeatedField,
    RequiredField,
    ValueField,
    decode,
};
pub use error::{ConversionError, ConversionResultExt};
#[cfg(feature = "derive")]
pub use miden_protobuf_derive::ProtoDecode;
pub use prost;

#[doc(hidden)]
pub mod __private {
    pub use crate::{
        ConversionError,
        DecodeField,
        OptionalField,
        RepeatedField,
        RequiredField,
        ValueField,
        decode,
    };
}
