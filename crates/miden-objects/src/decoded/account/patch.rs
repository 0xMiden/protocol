use miden_protobuf::unwrap_infallible;
pub use proto::account::DecodedAccountVaultPatchEntry as AccountVaultPatchEntry;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for AccountVaultPatchEntry {
    type Verified = (miden_protocol::asset::AssetId, miden_protocol::Word);
    type Error = miden_protocol::errors::AssetError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((self.asset_id.try_into()?, self.value))
    }
}

pub use proto::account::DecodedAccountVaultPatch as AccountVaultPatch;

impl Verify for AccountVaultPatch {
    type Verified = miden_protocol::account::AccountVaultPatch;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let mut entries = alloc::collections::BTreeMap::new();
        for entry in self.entries {
            let (id, value) = entry.verify()?;
            if entries.insert(id, value).is_some() {
                return Err(VaultPatchError::DuplicateAssetId(id).into());
            }
        }
        Ok(Self::Verified::new(entries)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultPatchError {
    #[error("duplicate vault asset ID {0}")]
    DuplicateAssetId(miden_protocol::asset::AssetId),
}

pub use proto::account::DecodedPrivateAccountUpdate as PrivateAccountUpdate;

impl Verify for PrivateAccountUpdate {
    type Verified = miden_protocol::account::AccountUpdateDetails;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::Private)
    }
}

pub use proto::account::DecodedStorageMapPatchEntries as StorageMapPatchEntries;

impl Verify for StorageMapPatchEntries {
    type Verified = miden_protocol::account::StorageMapPatchEntries;
    type Error = StorageMapPatchError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let mut entries = alloc::collections::BTreeMap::new();
        for entry in self.entries {
            let (key, value) = unwrap_infallible(entry.verify());
            if entries.insert(key, value).is_some() {
                return Err(StorageMapPatchError::DuplicateKey(key));
            }
        }
        Ok(Self::Verified::from_raw(entries))
    }
}

pub use proto::account::DecodedStorageMapPatch as StorageMapPatch;

impl Verify for StorageMapPatch {
    type Verified = miden_protocol::account::StorageMapPatch;
    type Error = StorageMapPatchError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use proto::account::storage_map_patch::DecodedOperation;
        match self.operation {
            DecodedOperation::Create(entries) => {
                Ok(Self::Verified::Create { entries: entries.verify()? })
            },
            DecodedOperation::Update(entries) => {
                let entries = entries.verify()?;
                if entries.is_empty() {
                    return Err(StorageMapPatchError::EmptyUpdate);
                }
                Ok(Self::Verified::Update { entries })
            },
            DecodedOperation::Remove(()) => Ok(Self::Verified::Remove),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageMapPatchError {
    #[error("entries must be non-empty for an update operation")]
    EmptyUpdate,
    #[error("duplicate storage map key {0:?}")]
    DuplicateKey(miden_protocol::account::StorageMapKey),
}

pub use proto::account::DecodedStorageValuePatch as StorageValuePatch;

impl Verify for StorageValuePatch {
    type Verified = miden_protocol::account::StorageValuePatch;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use proto::account::storage_value_patch::DecodedOperation;
        Ok(match self.operation {
            DecodedOperation::Create(value) => Self::Verified::Create { value },
            DecodedOperation::Update(value) => Self::Verified::Update { value },
            DecodedOperation::Remove(()) => Self::Verified::Remove,
        })
    }
}

pub use proto::account::DecodedStorageSlotPatch as StorageSlotPatch;

impl Verify for StorageSlotPatch {
    type Verified = (
        miden_protocol::account::StorageSlotName,
        miden_protocol::account::StorageSlotPatch,
    );
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use miden_protocol::account::{StorageSlotName, StorageSlotPatch};
        use proto::account::storage_slot_patch::DecodedPatch;
        let name = StorageSlotName::new(self.slot_name)?;
        let patch = match self.patch {
            DecodedPatch::Value(value) => {
                StorageSlotPatch::Value(unwrap_infallible(value.verify()))
            },
            DecodedPatch::Map(map) => StorageSlotPatch::Map(map.verify()?),
        };
        Ok((name, patch))
    }
}

pub use proto::account::DecodedAccountStoragePatch as AccountStoragePatch;

impl Verify for AccountStoragePatch {
    type Verified = miden_protocol::account::AccountStoragePatch;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let slots = self
            .slots
            .into_iter()
            .map(Verify::verify)
            .collect::<Result<alloc::vec::Vec<_>, _>>()?;
        Ok(Self::Verified::from_entries(slots)?)
    }
}

pub use proto::account::DecodedAccountPatch as AccountPatch;

impl Verify for AccountPatch {
    type Verified = miden_protocol::account::AccountPatch;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        if self.version != proto::account::AccountPatchVersion::V1 {
            return Err(AccountPatchError::UnspecifiedVersion.into());
        }
        Ok(Self::Verified::new(
            self.account_id.verify()?,
            self.storage.verify()?,
            self.vault.verify()?,
            self.code.map(Verify::verify).transpose()?,
            self.final_nonce,
        )?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountPatchError {
    #[error("account patch version is unspecified")]
    UnspecifiedVersion,
}

pub use proto::account::DecodedAccountUpdateDetails as AccountUpdateDetails;

impl Verify for AccountUpdateDetails {
    type Verified = miden_protocol::account::AccountUpdateDetails;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use proto::account::account_update_details::DecodedUpdate;
        match self.update {
            DecodedUpdate::Private(value) => Ok(unwrap_infallible(value.verify())),
            DecodedUpdate::Public(patch) => Ok(Self::Verified::Public(patch.verify()?)),
        }
    }
}
