//! Generated structural Protobuf decoding and opt-in domain construction.
#![no_std]
extern crate alloc;
#[cfg(feature = "build")]
extern crate std;
#[cfg(feature = "build")]
pub mod build;
mod decode;
mod error;
mod message;
pub use decode::{DecodeField, OptionalField, RepeatedField, RequiredField, ValueField, decode};
pub use error::{ConversionError, ConversionResultExt};
pub use message::{BuildUnchecked, DecodeMessage, Decoded, Verify, VerifyWith, unwrap_infallible};
#[cfg(feature = "derive")]
pub use miden_protobuf_derive::{ProtoDecodeFields, ProtoDecodeValue};
pub use prost;
#[doc(hidden)]
pub mod __private {
    pub use alloc::vec::Vec;

    pub use crate::{
        ConversionError,
        DecodeMessage,
        OptionalField,
        RepeatedField,
        RequiredField,
        ValueField,
        decode,
    };
}

#[cfg(all(test, feature = "derive"))]
mod value_tests {
    use alloc::string::ToString;
    use core::error::Error;
    use core::num::TryFromIntError;

    use crate::{ConversionError, ProtoDecodeValue};

    #[derive(Clone, PartialEq, prost::Message, ProtoDecodeValue)]
    struct Value {
        #[prost(uint32, tag = "1")]
        r#type: u32,
    }

    #[test]
    fn borrowed_payload_reports_its_field_and_preserves_the_source() {
        let value = Value { r#type: 42 };
        assert_eq!(value.decode_value(|value| u8::try_from(*value)).unwrap(), 42);
        let value = Value { r#type: 256 };
        let error = value.decode_value(|value| u8::try_from(*value)).unwrap_err();
        assert!(error.to_string().starts_with("type: "), "{error}");
        assert!(error.source().unwrap().is::<TryFromIntError>());
    }

    #[test]
    fn payload_conversion_errors_are_not_nested_or_duplicated() {
        let error = Value::default()
            .decode_value::<(), _>(|_| {
                Err(ConversionError::message("invalid payload").context("inner"))
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "type.inner: invalid payload");
    }
}
