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

/// Configures Prost messages to derive `ProtoDecode`.
#[cfg(feature = "build")]
#[macro_export]
macro_rules! configure_proto_decodes {
    (
        prost: $prost:expr,
        descriptors: $descriptors:expr,
        $(
            $message_name:literal => {
                target: $target:ty,
                $($settings:tt)*
            }
        ),+ $(,)?
    ) => {
        $crate::build::configure_proto_decodes(
            $prost,
            $descriptors,
            [
                $(
                    $crate::__proto_decode_config!(
                        $message_name,
                        $target,
                        $($settings)*
                    )
                ),+
            ],
        )
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __proto_decode_config {
    (
        $message_name:literal,
        $target:ty,
        constructor: $constructor:expr $(,)?
    ) => {
        $crate::build::ProtoDecodeConfig::constructor(
            $message_name,
            ::core::stringify!($target),
            &[],
            ::core::stringify!($constructor),
        )
    };
    (
        $message_name:literal,
        $target:ty,
        try_constructor: $constructor:expr $(,)?
    ) => {
        $crate::build::ProtoDecodeConfig::try_constructor(
            $message_name,
            ::core::stringify!($target),
            &[],
            ::core::stringify!($constructor),
        )
    };
    (
        $message_name:literal,
        $target:ty,
        validate: {
            $($validated_field:ident: $validator:path),+ $(,)?
        },
        constructor: $constructor:expr $(,)?
    ) => {
        $crate::build::ProtoDecodeConfig::constructor(
            $message_name,
            ::core::stringify!($target),
            &[
                $(
                    (
                        ::core::stringify!($validated_field),
                        ::core::stringify!($validator),
                    ),
                )+
            ],
            ::core::stringify!($constructor),
        )
    };
    (
        $message_name:literal,
        $target:ty,
        validate: {
            $($validated_field:ident: $validator:path),+ $(,)?
        },
        try_constructor: $constructor:expr $(,)?
    ) => {
        $crate::build::ProtoDecodeConfig::try_constructor(
            $message_name,
            ::core::stringify!($target),
            &[
                $(
                    (
                        ::core::stringify!($validated_field),
                        ::core::stringify!($validator),
                    ),
                )+
            ],
            ::core::stringify!($constructor),
        )
    };
}
