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
    StorageSlotName,
    StorageSlotPatch,
    StorageValuePatch,
};
use miden_protocol::asset::AssetId;

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
        use proto::account::storage_map_patch::{Entries, Patch};

        let encode_entries = |entries: &StorageMapPatchEntries| Entries {
            entries: entries
                .as_map()
                .iter()
                .map(|(key, value)| proto::account::StorageMapEntry {
                    key: Some(Word::from(*key).into()),
                    value: Some((*value).into()),
                })
                .collect(),
        };
        let patch = match patch {
            StorageMapPatch::Create { entries } => Patch::Create(encode_entries(entries)),
            StorageMapPatch::Update { entries } => Patch::Update(encode_entries(entries)),
            StorageMapPatch::Remove => Patch::Remove(()),
        };
        Self { patch: Some(patch) }
    }
}

pub(crate) fn decode_storage_map_patch_entries(
    decoded_entries: Vec<(StorageMapKey, Word)>,
) -> Result<StorageMapPatchEntries, ConversionError> {
    let mut entries = BTreeMap::new();
    for (index, (key, value)) in decoded_entries.into_iter().enumerate() {
        let entry_context = format!("entries[{index}]");
        if entries.insert(key, value).is_some() {
            return Err(ConversionError::message("duplicate storage map key")
                .context(format!("{entry_context}.key")));
        }
    }

    Ok(StorageMapPatchEntries::from_raw(entries))
}

pub(crate) fn decode_storage_map_patch_create(entries: StorageMapPatchEntries) -> StorageMapPatch {
    StorageMapPatch::Create { entries }
}

pub(crate) fn decode_storage_map_patch_update(
    entries: StorageMapPatchEntries,
) -> Result<StorageMapPatch, ConversionError> {
    if entries.is_empty() {
        return Err(ConversionError::message(
            "entries must be non-empty for an update operation",
        )
        .context("entries"));
    }

    Ok(StorageMapPatch::Update { entries })
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
