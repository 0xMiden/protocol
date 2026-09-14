use core::error::Error;
use core::num::TryFromIntError;

use miden_protobuf::{
    BuildUnchecked,
    ConversionError,
    ConversionResultExt,
    DecodeMessage,
    DecodeMessageExt,
    Verify,
    VerifyWith,
};

// Handwritten decoding keeps these tests available without the derive feature.
struct Message(u64);
struct Record(u32);

impl DecodeMessage for Message {
    type Decoded = Record;
}

impl TryFrom<Message> for Record {
    type Error = ConversionError;

    fn try_from(message: Message) -> Result<Self, Self::Error> {
        u32::try_from(message.0).map(Self).context("value")
    }
}

impl Verify for Record {
    type Verified = u8;
    type Error = TryFromIntError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        self.0.try_into()
    }
}

impl VerifyWith<&u32> for Record {
    type Verified = u8;
    type Error = ConversionError;

    fn verify_with(self, offset: &u32) -> Result<Self::Verified, Self::Error> {
        u8::try_from(self.0 + offset).context("adjusted_value")
    }
}

impl BuildUnchecked for Record {
    type Output = u16;
    type Error = TryFromIntError;

    // Skip the u8 domain constraint, retaining the u16 construction constraint.
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        self.0.try_into()
    }
}

#[test]
fn decoding_errors_report_the_stage_and_preserve_the_field_path_and_source() {
    let source = u32::try_from(u64::MAX).unwrap_err();
    for error in [
        Message(u64::MAX).decode_and_verify().unwrap_err(),
        Message(u64::MAX).decode_and_verify_with(&0).unwrap_err(),
        Message(u64::MAX).decode_and_build_unchecked().unwrap_err(),
    ] {
        assert_eq!(error.to_string(), format!("failed to decode: value: {source}"));
        let original = error.source().unwrap().source().unwrap();
        assert!(original.is::<ConversionError>());
        assert_eq!(original.to_string(), format!("value: {source}"));
        assert!(original.source().unwrap().is::<TryFromIntError>());
    }
}

#[test]
fn construction_errors_report_the_stage_and_preserve_typed_sources_and_existing_context() {
    let source = u8::try_from(256_u32).unwrap_err();
    for (error, stage, original_message) in [
        (Message(256).decode_and_verify().unwrap_err(), "verify", source.to_string()),
        (
            Message(255).decode_and_verify_with(&1).unwrap_err(),
            "verify",
            format!("adjusted_value: {source}"),
        ),
        (
            Message(u32::MAX.into()).decode_and_build_unchecked().unwrap_err(),
            "build unchecked",
            source.to_string(),
        ),
    ] {
        assert_eq!(error.to_string(), format!("failed to {stage}: {original_message}"));
        let original = error.source().unwrap().source().unwrap();
        assert_eq!(original.to_string(), original_message);
        if let Some(conversion) = original.downcast_ref::<ConversionError>() {
            assert!(conversion.source().unwrap().is::<TryFromIntError>());
        } else {
            assert!(original.is::<TryFromIntError>());
        }
    }
}
