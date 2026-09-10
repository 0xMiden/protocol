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
