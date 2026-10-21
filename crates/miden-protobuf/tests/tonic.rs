#![cfg(feature = "tonic")]

use core::error::Error;
use core::fmt;

use miden_protobuf::ConversionError;

#[derive(Debug)]
struct RootCause;

impl fmt::Display for RootCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid attestation signature")
    }
}

impl Error for RootCause {}

#[derive(Debug)]
struct HiddenCause(RootCause);

impl fmt::Display for HiddenCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("verification failed")
    }
}

impl Error for HiddenCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

#[test]
fn status_preserves_field_paths_and_causes_omitted_by_display() {
    let error = ConversionError::with_source("invalid payload", HiddenCause(RootCause))
        .context("attestations[1]")
        .context("request");
    assert_eq!(error.to_string(), "request.attestations[1]: invalid payload");

    let status = error.into_status();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        status.message(),
        "request.attestations[1]: invalid payload\ncaused by: verification failed\ncaused by: invalid attestation signature"
    );
    let original = status.source().unwrap().downcast_ref::<ConversionError>().unwrap();
    assert!(original.source().unwrap().source().unwrap().source().unwrap().is::<RootCause>());
}

#[test]
fn simple_status_messages_do_not_duplicate_the_immediate_source() {
    for (error, expected) in [
        (ConversionError::message("invalid request"), "invalid request"),
        (
            ConversionError::message("missing value").context("value"),
            "value: missing value",
        ),
    ] {
        let status = error.into_status();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(status.message(), expected);
    }
}

#[test]
fn nested_conversion_paths_survive_intermediate_errors() {
    let inner = ConversionError::new(RootCause).context("signature");
    let status = ConversionError::with_source("failed to verify", inner)
        .context("request")
        .into_status();
    assert_eq!(
        status.message(),
        "request: failed to verify\ncaused by: signature: invalid attestation signature\ncaused by: invalid attestation signature"
    );
}
