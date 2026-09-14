use alloc::borrow::ToOwned;

use miden_protocol::Word;
use miden_protocol::account::{
    AccountCode,
    AccountPatch,
    AccountStoragePatch,
    AccountUpdateDetails,
    AccountVaultPatch,
    StorageMapPatch,
    StorageMapPatchEntries,
    StorageSlotPatch,
    StorageValuePatch,
};

use crate::proto;

#[cfg(test)]
mod tests;

// ACCOUNT CODE
// ================================================================================================

impl From<&AccountCode> for proto::account::AccountCode {
    fn from(code: &AccountCode) -> Self {
        Self {
            mast: Some(code.mast().as_ref().into()),
            procedure_roots: code.procedure_roots().map(Into::into).collect(),
        }
    }
}

impl From<AccountCode> for proto::account::AccountCode {
    fn from(code: AccountCode) -> Self {
        Self::from(&code)
    }
}

// STORAGE PATCHES
// ================================================================================================

impl From<&StorageValuePatch> for proto::account::StorageValuePatch {
    fn from(patch: &StorageValuePatch) -> Self {
        use proto::account::storage_value_patch::Operation;

        let operation = match patch {
            StorageValuePatch::Create { value } => Operation::Create(value.into()),
            StorageValuePatch::Update { value } => Operation::Update(value.into()),
            StorageValuePatch::Remove => Operation::Remove(()),
        };
        Self { operation: Some(operation) }
    }
}

impl From<&StorageMapPatch> for proto::account::StorageMapPatch {
    fn from(patch: &StorageMapPatch) -> Self {
        use proto::account::storage_map_patch::Operation;

        let operation = match patch {
            StorageMapPatch::Create { entries } => Operation::Create(entries.into()),
            StorageMapPatch::Update { entries } => Operation::Update(entries.into()),
            StorageMapPatch::Remove => Operation::Remove(()),
        };
        Self { operation: Some(operation) }
    }
}

impl From<&StorageMapPatchEntries> for proto::account::StorageMapPatchEntries {
    fn from(entries: &StorageMapPatchEntries) -> Self {
        Self {
            entries: entries
                .as_map()
                .iter()
                .map(|(key, value)| proto::account::StorageMapEntry {
                    key: Some(Word::from(*key).into()),
                    value: Some(value.into()),
                })
                .collect(),
        }
    }
}

impl From<&AccountStoragePatch> for proto::account::AccountStoragePatch {
    fn from(patch: &AccountStoragePatch) -> Self {
        Self {
            slots: patch
                .slots()
                .map(|(slot_name, slot_patch)| {
                    use proto::account::storage_slot_patch::Patch;

                    let patch = match slot_patch {
                        StorageSlotPatch::Value(value) => Patch::Value(value.into()),
                        StorageSlotPatch::Map(map) => Patch::Map(map.into()),
                    };
                    proto::account::StorageSlotPatch {
                        slot_name: slot_name.as_str().to_owned(),
                        patch: Some(patch),
                    }
                })
                .collect(),
        }
    }
}

// VAULT AND ACCOUNT PATCHES
// ================================================================================================

impl From<&AccountVaultPatch> for proto::account::AccountVaultPatch {
    fn from(patch: &AccountVaultPatch) -> Self {
        Self {
            entries: patch
                .iter()
                .map(|(asset_id, value)| proto::account::AccountVaultPatchEntry {
                    asset_id: Some(asset_id.to_word().into()),
                    value: Some((*value).into()),
                })
                .collect(),
        }
    }
}

impl From<&AccountPatch> for proto::account::AccountPatch {
    fn from(patch: &AccountPatch) -> Self {
        Self {
            version: proto::account::AccountPatchVersion::V1 as i32,
            account_id: Some(patch.id().into()),
            storage: Some(patch.storage().into()),
            vault: Some(patch.vault().into()),
            code: patch.code().map(Into::into),
            final_nonce: patch.final_nonce().map(Into::into),
        }
    }
}

impl From<AccountPatch> for proto::account::AccountPatch {
    fn from(patch: AccountPatch) -> Self {
        Self::from(&patch)
    }
}

impl From<&AccountUpdateDetails> for proto::account::AccountUpdateDetails {
    fn from(details: &AccountUpdateDetails) -> Self {
        use proto::account::account_update_details::Update;

        let update = match details {
            AccountUpdateDetails::Private => {
                Update::Private(proto::account::PrivateAccountUpdate {})
            },
            AccountUpdateDetails::Public(patch) => Update::Public(patch.into()),
        };
        Self { update: Some(update) }
    }
}

impl From<AccountUpdateDetails> for proto::account::AccountUpdateDetails {
    fn from(details: AccountUpdateDetails) -> Self {
        Self::from(&details)
    }
}
