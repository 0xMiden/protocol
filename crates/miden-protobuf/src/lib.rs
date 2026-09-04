//! Shared runtime, derive, and Prost build support for conversions between Protobuf and domain
//! types.

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
pub use miden_protobuf_derive::{ProtoDecode, ProtoEncode};
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

/// Configures Prost messages to derive `ProtoDecode` and, when requested, `ProtoEncode`.
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
        $($settings:tt)*
    ) => {
        $crate::__proto_decode_config!(
            @parse
            $message_name,
            $target,
            [],
            [],
            [],
            [],
            [];
            $($settings)*
        )
    };
    (
        @parse
        $message_name:literal,
        $target:ty,
        [$($validators:expr,)*],
        [$($field_decoders:expr,)*],
        [$($field_encoders:expr,)*],
        [$($enumerations:expr,)*],
        [$($oneofs:expr,)*];
        validate: {
            $($field:ident: $validator:path),+ $(,)?
        },
        $($remaining:tt)*
    ) => {
        $crate::__proto_decode_config!(
            @parse
            $message_name,
            $target,
            [
                $($validators,)*
                $((::core::stringify!($field), ::core::stringify!($validator)),)+
            ],
            [$($field_decoders,)*],
            [$($field_encoders,)*],
            [$($enumerations,)*],
            [$($oneofs,)*];
            $($remaining)*
        )
    };
    (
        @parse
        $message_name:literal,
        $target:ty,
        [$($validators:expr,)*],
        [$($field_decoders:expr,)*],
        [$($field_encoders:expr,)*],
        [$($enumerations:expr,)*],
        [$($oneofs:expr,)*];
        decode: {
            $($field:ident: $decoder:path),+ $(,)?
        },
        $($remaining:tt)*
    ) => {
        $crate::__proto_decode_config!(
            @parse
            $message_name,
            $target,
            [$($validators,)*],
            [
                $($field_decoders,)*
                $((::core::stringify!($field), ::core::stringify!($decoder)),)+
            ],
            [$($field_encoders,)*],
            [$($enumerations,)*],
            [$($oneofs,)*];
            $($remaining)*
        )
    };
    (
        @parse
        $message_name:literal,
        $target:ty,
        [$($validators:expr,)*],
        [$($field_decoders:expr,)*],
        [$($field_encoders:expr,)*],
        [$($enumerations:expr,)*],
        [$($oneofs:expr,)*];
        encode: {
            $($field:ident: $accessor:path),+ $(,)?
        },
        $($remaining:tt)*
    ) => {
        $crate::__proto_decode_config!(
            @parse
            $message_name,
            $target,
            [$($validators,)*],
            [$($field_decoders,)*],
            [
                $($field_encoders,)*
                $((::core::stringify!($field), ::core::stringify!($accessor)),)+
            ],
            [$($enumerations,)*],
            [$($oneofs,)*];
            $($remaining)*
        )
    };
    (
        @parse
        $message_name:literal,
        $target:ty,
        [$($validators:expr,)*],
        [$($field_decoders:expr,)*],
        [$($field_encoders:expr,)*],
        [$($enumerations:expr,)*],
        [$($oneofs:expr,)*];
        enumeration: {
            $(
                $field:ident: {
                    $(
                        $variant:ident: $variant_kind:ident $(($variant_value:expr))?
                    ),+ $(,)?
                }
            ),+ $(,)?
        },
        $($remaining:tt)*
    ) => {
        $crate::__proto_decode_config!(
            @parse
            $message_name,
            $target,
            [$($validators,)*],
            [$($field_decoders,)*],
            [$($field_encoders,)*],
            [
                $($enumerations,)*
                $(
                    $crate::build::ProtoDecodeEnumerationConfig::new(
                        ::core::stringify!($field),
                        &[
                            $(
                                $crate::__proto_decode_enumeration_variant!(
                                    $variant,
                                    $variant_kind $(($variant_value))?
                                ),
                            )+
                        ],
                    ),
                )+
            ],
            [$($oneofs,)*];
            $($remaining)*
        )
    };
    (
        @parse
        $message_name:literal,
        $target:ty,
        [$($validators:expr,)*],
        [$($field_decoders:expr,)*],
        [$($field_encoders:expr,)*],
        [$($enumerations:expr,)*],
        [$($oneofs:expr,)*];
        oneof: {
            $(
                $field:ident: {
                    $(
                        $variant:ident: $variant_action:ident(
                            $variant_value:expr
                        )
                    ),+ $(,)?
                }
            ),+ $(,)?
        },
        $($remaining:tt)*
    ) => {
        $crate::__proto_decode_config!(
            @parse
            $message_name,
            $target,
            [$($validators,)*],
            [$($field_decoders,)*],
            [$($field_encoders,)*],
            [$($enumerations,)*],
            [
                $($oneofs,)*
                $(
                    $crate::build::ProtoDecodeOneofConfig::new(
                        ::core::stringify!($field),
                        &[
                            $(
                                $crate::__proto_decode_oneof_variant!(
                                    $variant,
                                    $variant_action($variant_value)
                                ),
                            )+
                        ],
                    ),
                )+
            ];
            $($remaining)*
        )
    };
    (
        @parse
        $message_name:literal,
        $target:ty,
        [$($validators:expr,)*],
        [$($field_decoders:expr,)*],
        [$($field_encoders:expr,)*],
        [$($enumerations:expr,)*],
        [$($oneofs:expr,)*];
        constructor: $constructor:expr $(,)?
    ) => {
        $crate::build::ProtoDecodeConfig::constructor(
            $message_name,
            ::core::stringify!($target),
            &[$($validators,)*],
            ::core::stringify!($constructor),
        )
        .with_field_decoders(&[$($field_decoders,)*])
        .with_field_encoders(&[$($field_encoders,)*])
        .with_enumerations(&[$($enumerations,)*])
        .with_oneofs(&[$($oneofs,)*])
    };
    (
        @parse
        $message_name:literal,
        $target:ty,
        [$($validators:expr,)*],
        [$($field_decoders:expr,)*],
        [$($field_encoders:expr,)*],
        [$($enumerations:expr,)*],
        [$($oneofs:expr,)*];
        try_constructor: $constructor:expr $(,)?
    ) => {
        $crate::build::ProtoDecodeConfig::try_constructor(
            $message_name,
            ::core::stringify!($target),
            &[$($validators,)*],
            ::core::stringify!($constructor),
        )
        .with_field_decoders(&[$($field_decoders,)*])
        .with_field_encoders(&[$($field_encoders,)*])
        .with_enumerations(&[$($enumerations,)*])
        .with_oneofs(&[$($oneofs,)*])
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __proto_decode_enumeration_variant {
    ($variant:ident,map($target:expr)) => {
        $crate::build::ProtoDecodeEnumerationVariantConfig::map(
            ::core::stringify!($variant),
            ::core::stringify!($target),
        )
    };
    ($variant:ident,accept) => {
        $crate::build::ProtoDecodeEnumerationVariantConfig::accept(::core::stringify!($variant))
    };
    ($variant:ident,reject($message:expr)) => {
        $crate::build::ProtoDecodeEnumerationVariantConfig::reject(
            ::core::stringify!($variant),
            ::core::stringify!($message),
        )
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __proto_decode_oneof_variant {
    ($variant:ident,constructor($constructor:expr)) => {
        $crate::build::ProtoDecodeOneofVariantConfig::constructor(
            ::core::stringify!($variant),
            ::core::stringify!($constructor),
        )
    };
    ($variant:ident,try_constructor($constructor:expr)) => {
        $crate::build::ProtoDecodeOneofVariantConfig::try_constructor(
            ::core::stringify!($variant),
            ::core::stringify!($constructor),
        )
    };
    ($variant:ident,constant($value:expr)) => {
        $crate::build::ProtoDecodeOneofVariantConfig::constant(
            ::core::stringify!($variant),
            ::core::stringify!($value),
        )
    };
}
