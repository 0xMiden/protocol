use miden_protocol::account::AssetDelta;
use miden_protocol::account::delta::AssetDeltaOperation;
pub use proto::account::{
    DecodedAccountDelta as AccountDelta,
    DecodedAccountVaultDelta as AccountVaultDelta,
};

use crate::decoded::VerificationError;
use crate::{Verify, proto};

impl Verify for AccountVaultDelta {
    type Verified = miden_protocol::account::AccountVaultDelta;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let added = self
            .added
            .verify()?
            .into_iter()
            .map(|asset| AssetDelta::new(AssetDeltaOperation::Add, asset));
        let removed = self
            .removed
            .verify()?
            .into_iter()
            .map(|asset| AssetDelta::new(AssetDeltaOperation::Remove, asset));
        Ok(Self::Verified::new(added.chain(removed))?)
    }
}

impl Verify for AccountDelta {
    type Verified = miden_protocol::account::AccountDelta;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        if self.version != proto::account::AccountDeltaVersion::V1 {
            return Err(AccountDeltaError::UnspecifiedVersion.into());
        }
        Ok(Self::Verified::new(
            self.account_id.verify()?,
            self.storage.verify()?,
            self.vault.verify()?,
            self.code.verify()?,
            self.nonce_delta,
        )?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountDeltaError {
    #[error("account delta version is unspecified")]
    UnspecifiedVersion,
}
