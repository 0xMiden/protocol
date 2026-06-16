use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::errors::AccountError;

// APPROVER
// ================================================================================================

/// A signer that can approve transactions, identified by its public key commitment and the
/// signature scheme used to verify its signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approver {
    pub_key: PublicKeyCommitment,
    auth_scheme: AuthScheme,
}

impl Approver {
    /// Creates a new [`Approver`] from the given public key commitment and signature scheme.
    pub fn new(pub_key: PublicKeyCommitment, auth_scheme: AuthScheme) -> Self {
        Self { pub_key, auth_scheme }
    }

    /// Returns the public key commitment of this approver.
    pub fn pub_key(&self) -> PublicKeyCommitment {
        self.pub_key
    }

    /// Returns the signature scheme of this approver.
    pub fn auth_scheme(&self) -> AuthScheme {
        self.auth_scheme
    }
}

impl From<(PublicKeyCommitment, AuthScheme)> for Approver {
    fn from((pub_key, auth_scheme): (PublicKeyCommitment, AuthScheme)) -> Self {
        Self::new(pub_key, auth_scheme)
    }
}

// APPROVER SET
// ================================================================================================

/// A set of [`Approver`]s together with the threshold of signatures required to approve a
/// transaction by default.
///
/// The set is guaranteed to be valid by construction: the threshold is non-zero and at most the
/// number of approvers, and no public key commitment appears more than once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverSet {
    approvers: Vec<Approver>,
    threshold: NonZeroU32,
}

impl ApproverSet {
    /// Creates a new [`ApproverSet`] from the given approvers and default threshold.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `threshold` is zero,
    /// - `threshold` is greater than the number of approvers, or
    /// - two approvers share the same public key commitment.
    pub fn new(approvers: Vec<Approver>, threshold: u32) -> Result<Self, AccountError> {
        let threshold = NonZeroU32::new(threshold)
            .ok_or_else(|| AccountError::other("threshold must be at least 1"))?;

        if threshold.get() > approvers.len() as u32 {
            return Err(AccountError::other(
                "threshold cannot be greater than number of approvers",
            ));
        }

        let unique_approvers: BTreeSet<_> = approvers.iter().map(Approver::pub_key).collect();
        if unique_approvers.len() != approvers.len() {
            return Err(AccountError::other("duplicate approver public keys are not allowed"));
        }

        Ok(Self { approvers, threshold })
    }

    /// Returns the approvers in this set.
    pub fn approvers(&self) -> &[Approver] {
        &self.approvers
    }

    /// Returns the default threshold of signatures required to approve a transaction.
    pub fn threshold(&self) -> NonZeroU32 {
        self.threshold
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_protocol::Word;
    use miden_protocol::account::auth::AuthScheme;

    use super::*;

    fn approver(seed: u32) -> Approver {
        Approver::new(PublicKeyCommitment::from(Word::from([seed; 4])), AuthScheme::EcdsaK256Keccak)
    }

    #[test]
    fn rejects_zero_threshold() {
        let err = ApproverSet::new(vec![approver(1)], 0).unwrap_err();
        assert!(err.to_string().contains("threshold must be at least 1"));
    }

    #[test]
    fn rejects_threshold_above_approver_count() {
        let err = ApproverSet::new(vec![approver(1)], 2).unwrap_err();
        assert!(err.to_string().contains("threshold cannot be greater than number of approvers"));
    }

    #[test]
    fn rejects_duplicate_approvers() {
        let err = ApproverSet::new(vec![approver(1), approver(1)], 2).unwrap_err();
        assert!(err.to_string().contains("duplicate approver public keys are not allowed"));
    }

    #[test]
    fn accepts_valid_set() {
        let set = ApproverSet::new(vec![approver(1), approver(2)], 2).unwrap();
        assert_eq!(set.approvers().len(), 2);
        assert_eq!(set.threshold().get(), 2);
    }
}
