use alloc::string::ToString;

use miden_protocol::Word;
use miden_protocol::account::{
    AccountHeader,
    AccountId,
    AccountIdV1,
    AccountStorageHeader,
    PartialAccount,
    PartialStorage,
    PartialStorageMap,
    StorageSlotId,
    StorageSlotType,
};
use miden_protocol::asset::PartialVault;
use miden_protocol::block::account_tree::AccountWitness;

use crate::proto;

#[cfg(test)]
mod tests;

impl From<&AccountIdV1> for proto::account::AccountIdV1 {
    fn from(account_id: &AccountIdV1) -> Self {
        Self {
            suffix: Some(account_id.suffix().into()),
            prefix: Some(account_id.prefix().as_felt().into()),
        }
    }
}

impl From<AccountIdV1> for proto::account::AccountIdV1 {
    fn from(account_id: AccountIdV1) -> Self {
        (&account_id).into()
    }
}

impl From<&AccountId> for proto::account::AccountId {
    fn from(account_id: &AccountId) -> Self {
        let version = match account_id {
            AccountId::V1(id) => proto::account::account_id::Version::V1(id.into()),
        };
        Self { version: Some(version) }
    }
}

impl From<AccountId> for proto::account::AccountId {
    fn from(account_id: AccountId) -> Self {
        (&account_id).into()
    }
}

// STORAGE SLOT ID
// ================================================================================================

impl From<StorageSlotId> for proto::account::StorageSlotId {
    fn from(id: StorageSlotId) -> Self {
        Self {
            suffix: Some(id.suffix().into()),
            prefix: Some(id.prefix().into()),
        }
    }
}

impl From<&StorageSlotId> for proto::account::StorageSlotId {
    fn from(id: &StorageSlotId) -> Self {
        (*id).into()
    }
}

impl From<&AccountStorageHeader> for proto::account::AccountStorageHeader {
    fn from(account_storage_header: &AccountStorageHeader) -> Self {
        use proto::account::account_storage_header::storage_slot::Content;

        Self {
            slots: account_storage_header
                .slots()
                .map(|slot| {
                    let content = match slot.slot_type() {
                        StorageSlotType::Value => Content::Value(slot.value().into()),
                        StorageSlotType::Map => Content::MapRoot(slot.value().into()),
                    };
                    proto::account::account_storage_header::StorageSlot {
                        slot_name: slot.name().to_string(),
                        content: Some(content),
                    }
                })
                .collect(),
        }
    }
}

impl From<AccountStorageHeader> for proto::account::AccountStorageHeader {
    fn from(account_storage_header: AccountStorageHeader) -> Self {
        (&account_storage_header).into()
    }
}

// PARTIAL STORAGE MAP
// ================================================================================================

impl From<&PartialStorageMap> for proto::account::PartialStorageMap {
    fn from(map: &PartialStorageMap) -> Self {
        Self {
            smt: Some(map.partial_smt().clone().into()),
            keys: map.entries().map(|(key, _)| Word::from(*key).into()).collect(),
        }
    }
}

impl From<PartialStorageMap> for proto::account::PartialStorageMap {
    fn from(map: PartialStorageMap) -> Self {
        (&map).into()
    }
}

// PARTIAL STORAGE
// ================================================================================================

impl From<&PartialStorage> for proto::account::PartialStorage {
    fn from(storage: &PartialStorage) -> Self {
        Self {
            header: Some(storage.header().into()),
            maps: storage.maps().map(Into::into).collect(),
        }
    }
}

impl From<PartialStorage> for proto::account::PartialStorage {
    fn from(storage: PartialStorage) -> Self {
        (&storage).into()
    }
}

// PARTIAL VAULT
// ================================================================================================

impl From<&PartialVault> for proto::account::PartialVault {
    fn from(vault: &PartialVault) -> Self {
        Self {
            smt: Some(vault.partial_smt().clone().into()),
            asset_ids: vault.asset_ids().map(|id| Word::from(id).into()).collect(),
        }
    }
}

impl From<PartialVault> for proto::account::PartialVault {
    fn from(vault: PartialVault) -> Self {
        (&vault).into()
    }
}

// PARTIAL ACCOUNT
// ================================================================================================

impl From<&PartialAccount> for proto::account::PartialAccount {
    fn from(account: &PartialAccount) -> Self {
        Self {
            account_id: Some(account.id().into()),
            nonce: Some(account.nonce().into()),
            code: Some(account.code().into()),
            storage: Some(account.storage().into()),
            vault: Some(account.vault().into()),
            seed: account.seed().map(Into::into),
        }
    }
}

impl From<PartialAccount> for proto::account::PartialAccount {
    fn from(account: PartialAccount) -> Self {
        (&account).into()
    }
}

impl From<&AccountHeader> for proto::account::AccountHeader {
    fn from(account_header: &AccountHeader) -> Self {
        Self {
            version: proto::account::AccountVersion::V1 as i32,
            account_id: Some(account_header.id().into()),
            vault_root: Some(account_header.vault_root().into()),
            storage_commitment: Some(account_header.storage_commitment().into()),
            code_commitment: Some(account_header.code_commitment().into()),
            nonce: account_header.nonce().as_canonical_u64(),
        }
    }
}

impl From<AccountHeader> for proto::account::AccountHeader {
    fn from(account_header: AccountHeader) -> Self {
        (&account_header).into()
    }
}

impl From<&AccountWitness> for proto::account::AccountWitness {
    fn from(witness: &AccountWitness) -> Self {
        Self {
            witness_id: Some(witness.id().into()),
            commitment: Some(witness.state_commitment().into()),
            path: Some(witness.path().clone().into()),
        }
    }
}

impl From<AccountWitness> for proto::account::AccountWitness {
    fn from(witness: AccountWitness) -> Self {
        (&witness).into()
    }
}
