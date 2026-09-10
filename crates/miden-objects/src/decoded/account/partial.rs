pub use proto::account::DecodedPartialStorageMap as PartialStorageMap;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for PartialStorageMap {
    type Verified = miden_protocol::account::PartialStorageMap;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::try_from_parts(
            self.smt.verify()?,
            self.keys.into_iter().map(miden_protocol::account::StorageMapKey::from_raw),
        )?)
    }
}

pub use proto::account::DecodedPartialStorage as PartialStorage;

impl Verify for PartialStorage {
    type Verified = miden_protocol::account::PartialStorage;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let mut roots = alloc::collections::BTreeSet::new();
        let mut maps = alloc::vec::Vec::new();
        for map in self.maps {
            let map = map.verify()?;
            if !roots.insert(map.root()) {
                return Err(PartialStorageError::DuplicateRoot(map.root()).into());
            }
            maps.push(map);
        }
        Ok(Self::Verified::new(self.header.verify()?, maps)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PartialStorageError {
    #[error("duplicate partial storage map root {0}")]
    DuplicateRoot(miden_protocol::Word),
}

pub use proto::account::DecodedPartialVault as PartialVault;

impl Verify for PartialVault {
    type Verified = miden_protocol::asset::PartialVault;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let ids = self
            .asset_ids
            .into_iter()
            .map(miden_protocol::asset::AssetId::try_from)
            .collect::<Result<alloc::vec::Vec<_>, _>>()?;
        Ok(Self::Verified::try_from_parts(self.smt.verify()?, ids)?)
    }
}

pub use proto::account::DecodedPartialAccount as PartialAccount;

impl Verify for PartialAccount {
    type Verified = miden_protocol::account::PartialAccount;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(
            self.account_id.verify()?,
            self.nonce,
            self.code.verify()?,
            self.storage.verify()?,
            self.vault.verify()?,
            self.seed,
        )?)
    }
}
