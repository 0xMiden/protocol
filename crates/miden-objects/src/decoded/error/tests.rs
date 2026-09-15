use alloc::string::ToString;
use core::error::Error;

use miden_protocol::errors::AccountIdError;

use super::VerificationError;

#[test]
fn nested_verification_preserves_the_concrete_source_without_wrappers() {
    let error = AccountIdError::UnknownAccountIdVersion(0);
    let message = error.to_string();
    let error = VerificationError::new(VerificationError::from(error));

    assert_eq!(error.to_string(), message);
    assert!(matches!(
        error.source().unwrap().downcast_ref::<AccountIdError>(),
        Some(AccountIdError::UnknownAccountIdVersion(0))
    ));
}

#[test]
fn collection_errors_preserve_context_and_domain_sources() {
    let domain = AccountIdError::UnknownAccountIdVersion(0);
    let message = domain.to_string();
    let contextual = miden_protobuf::ConversionError::new(VerificationError::from(domain))
        .context("accounts[1]");
    let error = VerificationError::from(contextual);

    assert_eq!(error.to_string(), alloc::format!("accounts[1]: {message}"));
    assert!(error.source().unwrap().is::<miden_protobuf::ConversionError>());
    assert!(matches!(
        crate::test_utils::error_source::<AccountIdError>(&error),
        Some(AccountIdError::UnknownAccountIdVersion(0))
    ));
}
