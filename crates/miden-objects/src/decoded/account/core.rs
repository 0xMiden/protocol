pub use proto::account::{DecodedAccountId as AccountId, DecodedAccountIdV1 as AccountIdV1};

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for AccountId {
    type Verified = miden_protocol::account::AccountId;
    type Error = miden_protocol::errors::AccountIdError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        match self.version {
            proto::account::account_id::DecodedVersion::V1(id) => {
                Ok(Self::Verified::V1(id.verify()?))
            },
        }
    }
}

impl Verify for AccountIdV1 {
    type Verified = miden_protocol::account::AccountIdV1;
    type Error = miden_protocol::errors::AccountIdError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Self::Verified::try_from_elements(self.suffix, self.prefix)
    }
}

pub use proto::account::DecodedAccountCode as AccountCode;

impl Verify for AccountCode {
    type Verified = miden_protocol::account::AccountCode;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let roots = self
            .procedure_roots
            .into_iter()
            .map(miden_protocol::account::AccountProcedureRoot::from_raw)
            .collect();
        Ok(Self::Verified::from_parts(alloc::sync::Arc::new(self.mast.verify()?), roots)?)
    }
}

pub use proto::account::DecodedAccountWitness as AccountWitness;

impl Verify for AccountWitness {
    type Verified = miden_protocol::block::account_tree::AccountWitness;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(
            self.witness_id.verify()?,
            self.commitment,
            self.path.verify()?,
        )?)
    }
}

pub use proto::account::DecodedAccountHeader as AccountHeader;

impl Verify for AccountHeader {
    type Verified = miden_protocol::account::AccountHeader;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        match self.version {
            proto::account::AccountVersion::V1 => {},
            proto::account::AccountVersion::Unspecified => {
                return Err(AccountHeaderError::UnspecifiedVersion.into());
            },
        }
        Ok(Self::Verified::new(
            self.account_id.verify()?,
            self.nonce.try_into().map_err(AccountHeaderError::Nonce)?,
            self.vault_root,
            self.storage_commitment,
            self.code_commitment,
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountHeaderError {
    #[error("account header version is unspecified")]
    UnspecifiedVersion,
    #[error("invalid account nonce: {0}")]
    Nonce(#[source] <miden_protocol::Felt as TryFrom<u64>>::Error),
}
