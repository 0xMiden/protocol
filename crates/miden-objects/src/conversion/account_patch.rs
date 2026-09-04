use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::{
    AccountCode,
    AccountPatch,
    AccountProcedureRoot,
    AccountStoragePatch,
    AccountUpdateDetails,
    AccountVaultPatch,
    StorageMapKey,
    StorageMapPatch,
    StorageMapPatchEntries,
    StoragePatchOperation,
    StorageSlotName,
    StorageSlotPatch,
    StorageValuePatch,
};
use miden_protocol::asset::AssetId;

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

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

impl TryFrom<proto::primitives::Word> for AccountProcedureRoot {
    type Error = ConversionError;

    fn try_from(root: proto::primitives::Word) -> Result<Self, Self::Error> {
        Word::try_from(root).map(Self::from_raw)
    }
}

pub(crate) fn decode_account_code(
    mast: miden_protocol::MastForest,
    procedure_roots: Vec<AccountProcedureRoot>,
) -> Result<AccountCode, ConversionError> {
    AccountCode::from_parts(Arc::new(mast), procedure_roots).map_err(ConversionError::new)
}

// STORAGE PATCHES
// ================================================================================================

const fn encode_storage_operation(operation: StoragePatchOperation) -> i32 {
    match operation {
        StoragePatchOperation::Create => proto::account::StoragePatchOperation::Create as i32,
        StoragePatchOperation::Update => proto::account::StoragePatchOperation::Update as i32,
        StoragePatchOperation::Remove => proto::account::StoragePatchOperation::Remove as i32,
    }
}

fn decode_storage_operation(operation: i32) -> Result<StoragePatchOperation, ConversionError> {
    match proto::account::StoragePatchOperation::try_from(operation) {
        Ok(proto::account::StoragePatchOperation::Create) => Ok(StoragePatchOperation::Create),
        Ok(proto::account::StoragePatchOperation::Update) => Ok(StoragePatchOperation::Update),
        Ok(proto::account::StoragePatchOperation::Remove) => Ok(StoragePatchOperation::Remove),
        Ok(proto::account::StoragePatchOperation::Unspecified) => {
            Err(ConversionError::message("storage patch operation is unspecified"))
        },
        Err(_) => {
            Err(ConversionError::message(format!("unknown storage patch operation {operation}")))
        },
    }
}

impl From<&StorageValuePatch> for proto::account::StorageValuePatch {
    fn from(patch: &StorageValuePatch) -> Self {
        use proto::account::storage_value_patch::Patch;

        let patch = match patch {
            StorageValuePatch::Create { value } => Patch::Create((*value).into()),
            StorageValuePatch::Update { value } => Patch::Update((*value).into()),
            StorageValuePatch::Remove => Patch::Remove(()),
        };
        Self { patch: Some(patch) }
    }
}

pub(crate) fn decode_storage_value_patch_create(value: Word) -> StorageValuePatch {
    StorageValuePatch::Create { value }
}

pub(crate) fn decode_storage_value_patch_update(value: Word) -> StorageValuePatch {
    StorageValuePatch::Update { value }
}

impl From<&StorageMapPatch> for proto::account::StorageMapPatch {
    fn from(patch: &StorageMapPatch) -> Self {
        let entries = patch
            .entries()
            .into_iter()
            .flat_map(StorageMapPatchEntries::as_map)
            .map(|(key, value)| proto::account::StorageMapEntry {
                key: Some(Word::from(*key).into()),
                value: Some((*value).into()),
            })
            .collect();

        Self {
            operation: encode_storage_operation(patch.patch_op()),
            entries,
        }
    }
}

impl TryFrom<proto::account::StorageMapPatch> for StorageMapPatch {
    type Error = ConversionError;

    fn try_from(patch: proto::account::StorageMapPatch) -> Result<Self, Self::Error> {
        let operation = decode_storage_operation(patch.operation).context("operation")?;
        if operation.is_remove() {
            if !patch.entries.is_empty() {
                return Err(ConversionError::message(
                    "entries must be empty for a remove operation",
                )
                .context("entries"));
            }
            return Ok(StorageMapPatch::Remove);
        }

        let mut entries = BTreeMap::new();
        for (index, entry) in patch.entries.into_iter().enumerate() {
            let decoder = entry.decoder();
            let entry_context = format!("entries[{index}]");
            let key = StorageMapKey::from_raw(
                required!(decoder, entry.key).context(entry_context.clone())?,
            );
            let value = required!(decoder, entry.value).context(entry_context.clone())?;
            if entries.insert(key, value).is_some() {
                return Err(ConversionError::message("duplicate storage map key")
                    .context(format!("{entry_context}.key")));
            }
        }

        let entries = StorageMapPatchEntries::from_raw(entries);
        match operation {
            StoragePatchOperation::Create => Ok(StorageMapPatch::Create { entries }),
            StoragePatchOperation::Update if entries.is_empty() => {
                Err(ConversionError::message("entries must be non-empty for an update operation")
                    .context("entries"))
            },
            StoragePatchOperation::Update => Ok(StorageMapPatch::Update { entries }),
            StoragePatchOperation::Remove => unreachable!("remove handled above"),
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

pub(crate) fn decode_storage_slot_name(
    slot_name: alloc::string::String,
) -> Result<StorageSlotName, ConversionError> {
    StorageSlotName::new(slot_name).map_err(ConversionError::new)
}

pub(crate) fn decode_account_storage_patch(
    slots: Vec<(StorageSlotName, StorageSlotPatch)>,
) -> Result<AccountStoragePatch, ConversionError> {
    AccountStoragePatch::from_entries(slots)
        .map_err(ConversionError::new)
        .context("slots")
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

pub(crate) fn decode_account_vault_patch(
    decoded_entries: Vec<(AssetId, Word)>,
) -> Result<AccountVaultPatch, ConversionError> {
    let mut entries = BTreeMap::new();
    for (index, (asset_id, value)) in decoded_entries.into_iter().enumerate() {
        if entries.insert(asset_id, value).is_some() {
            return Err(ConversionError::message("duplicate vault asset ID")
                .context(format!("entries[{index}].asset_id")));
        }
    }

    AccountVaultPatch::new(entries).map_err(ConversionError::new).context("entries")
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

pub(crate) fn decode_private_account_update(
    _update: proto::account::PrivateAccountUpdate,
) -> AccountUpdateDetails {
    AccountUpdateDetails::Private
}
