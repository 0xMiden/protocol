use alloc::collections::BTreeSet;
use alloc::format;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use miden_protocol::account::auth::{AuthScheme, PublicKey, PublicKeyCommitment};
use miden_protocol::errors::AccountError;

// APPROVER
// ================================================================================================

/// A signer that can approve transactions, identified by its public key commitment and the
/// signature scheme used to verify its signatures.
///
/// Note: an approver using [`AuthScheme::EcdsaK256Keccak`] discloses its public key and signature
/// at proving time and therefore does not provide public-key privacy, regardless of the component
/// it is used in (single-sig, multisig, or guarded multisig). See
/// [`AuthScheme::EcdsaK256Keccak`] for details, and prefer [`AuthScheme::Falcon512Poseidon2`] if
/// signer-key privacy is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approver {
    pub_key: PublicKeyCommitment,
    auth_scheme: AuthScheme,
}

impl Approver {
    /// Creates a new [`Approver`] from the given public key commitment and signature scheme.
    ///
    /// # Security
    ///
    /// The `pub_key` commitment must have been derived under `auth_scheme`. This is not checked
    /// here: a commitment is a bare digest that carries no record of the scheme that produced it,
    /// and this constructor accepts a raw commitment (e.g. one rebuilt from stored account state)
    /// without the originating key, so it cannot re-derive or verify the scheme. Pairing a
    /// commitment with the wrong scheme is a self-inflicted misconfiguration: authentication
    /// dispatches on the stored scheme alone and hashes the provided key under that scheme's hash
    /// function, so a mismatched commitment can never be reproduced and the account becomes
    /// permanently unauthenticatable.
    ///
    /// To keep the two consistent by construction, derive the approver from a [`PublicKey`] via the
    /// [`From<&PublicKey>`](Approver::from) conversion, or use the typed constructors on
    /// [`AuthSingleSig`](crate::account::auth::AuthSingleSig).
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

impl From<&PublicKey> for Approver {
    fn from(pub_key: &PublicKey) -> Self {
        Self::new(pub_key.to_commitment(), pub_key.auth_scheme())
    }
}

// APPROVER SET
// ================================================================================================

/// A set of [`Approver`]s together with the threshold of signatures required to approve a
/// transaction by default.
///
/// The set is guaranteed to be valid by construction: the threshold is non-zero and at most the
/// number of approvers, the number of approvers is at most [`ApproverSet::MAX_APPROVERS`], and no
/// public key commitment appears more than once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverSet {
    approvers: Vec<Approver>,
    threshold: NonZeroU32,
}

impl ApproverSet {
    /// The maximum number of approvers a set may contain.
    ///
    /// Authentication cost is linear in the size of the approver set - `verify_signatures` iterates
    /// over every approver regardless of how many signatures the transaction actually requires -
    /// and `update_signers_and_threshold` is quadratic in it because it re-checks key uniqueness.
    /// Every transaction on the account pays that cost, so without a bound an approver set can be
    /// configured whose first `auth_tx` exceeds provable cycle limits, permanently locking the
    /// account's assets.
    ///
    /// Must be kept in sync with `MAX_NUM_APPROVERS` in
    /// `asm/standards/auth/multisig.masm`, which enforces the same bound on the on-chain
    /// `update_signers_and_threshold` path.
    pub const MAX_APPROVERS: u32 = 64;

    /// Creates a new [`ApproverSet`] from the given approvers and default threshold.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `threshold` is zero,
    /// - the number of approvers exceeds [`Self::MAX_APPROVERS`],
    /// - `threshold` is greater than the number of approvers, or
    /// - two approvers share the same public key commitment.
    pub fn new(approvers: Vec<Approver>, threshold: u32) -> Result<Self, AccountError> {
        let threshold = NonZeroU32::new(threshold)
            .ok_or_else(|| AccountError::other("threshold must be at least 1"))?;

        if approvers.len() as u64 > u64::from(Self::MAX_APPROVERS) {
            return Err(AccountError::other(format!(
                "number of approvers cannot be greater than {}",
                Self::MAX_APPROVERS
            )));
        }

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
    fn rejects_approver_count_above_max() {
        let approvers: Vec<_> = (0..=ApproverSet::MAX_APPROVERS).map(approver).collect();
        let err = ApproverSet::new(approvers, 1).unwrap_err();
        assert!(err.to_string().contains("number of approvers cannot be greater than 64"));
    }

    #[test]
    fn accepts_approver_count_at_max() {
        let approvers: Vec<_> = (0..ApproverSet::MAX_APPROVERS).map(approver).collect();
        let set = ApproverSet::new(approvers, ApproverSet::MAX_APPROVERS).unwrap();
        assert_eq!(set.approvers().len(), ApproverSet::MAX_APPROVERS as usize);
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
