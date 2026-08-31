use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use miden_protocol::account::{
    AccountCode,
    AccountHeader,
    AccountId,
    AccountStorageHeader,
    PartialAccount,
    PartialStorage,
    PartialStorageMap,
    StorageSlotHeader,
    StorageSlotId,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::asset::{AssetId, PartialVault};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::crypto::merkle::smt::PartialSmt;
use miden_protocol::{Felt, Word};

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

impl TryFrom<proto::account::AccountId> for AccountId {
    type Error = ConversionError;

    fn try_from(message: proto::account::AccountId) -> Result<Self, Self::Error> {
        let bytes: [u8; AccountId::SERIALIZED_SIZE] =
            message.id.as_slice().try_into().map_err(ConversionError::new)?;

        AccountId::try_from(bytes).map_err(ConversionError::new)
    }
}

impl From<&AccountId> for proto::account::AccountId {
    fn from(account_id: &AccountId) -> Self {
        let id: [u8; AccountId::SERIALIZED_SIZE] = (*account_id).into();
        Self { id: id.into() }
    }
}

impl From<AccountId> for proto::account::AccountId {
    fn from(account_id: AccountId) -> Self {
        (&account_id).into()
    }
}

// STORAGE SLOT ID
// ================================================================================================

impl TryFrom<proto::account::StorageSlotId> for StorageSlotId {
    type Error = ConversionError;

    fn try_from(message: proto::account::StorageSlotId) -> Result<Self, Self::Error> {
        let decoder = message.decoder();
        let suffix = required!(decoder, message.suffix)?;
        let prefix = required!(decoder, message.prefix)?;
        Ok(Self::new(suffix, prefix))
    }
}

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

/// Decodes a protobuf storage slot type into its domain representation.
///
/// Protobuf reserves discriminant 0 for an unspecified value, while the domain
/// enum uses discriminants 0 and 1 for `Value` and `Map`, respectively.
fn decode_storage_slot_type(slot_type: i32) -> Result<StorageSlotType, ConversionError> {
    match proto::account::StorageSlotType::try_from(slot_type) {
        Ok(proto::account::StorageSlotType::Value) => Ok(StorageSlotType::Value),
        Ok(proto::account::StorageSlotType::Map) => Ok(StorageSlotType::Map),
        Ok(proto::account::StorageSlotType::Unspecified) => {
            Err(ConversionError::message("storage slot type is unspecified"))
        },
        Err(error) => Err(ConversionError::with_source(
            format!("unknown storage slot type {slot_type}"),
            error,
        )),
    }
}

/// Encodes a domain storage slot type using its protobuf representation.
fn encode_storage_slot_type(slot_type: StorageSlotType) -> i32 {
    match slot_type {
        StorageSlotType::Value => proto::account::StorageSlotType::Value as i32,
        StorageSlotType::Map => proto::account::StorageSlotType::Map as i32,
    }
}

impl TryFrom<proto::account::AccountStorageHeader> for AccountStorageHeader {
    type Error = ConversionError;

    fn try_from(message: proto::account::AccountStorageHeader) -> Result<Self, Self::Error> {
        let slots = message
            .slots
            .into_iter()
            .map(|slot| {
                let decoder = slot.decoder();
                let name = StorageSlotName::new(slot.slot_name)?;
                let slot_type = decode_storage_slot_type(slot.slot_type).context("slot_type")?;
                let commitment = required!(decoder, slot.commitment)?;
                Ok(StorageSlotHeader::new(name, slot_type, commitment))
            })
            .collect::<Result<Vec<_>, ConversionError>>()
            .context("slots")?;
        AccountStorageHeader::new(slots).map_err(ConversionError::new)
    }
}

impl From<&AccountStorageHeader> for proto::account::AccountStorageHeader {
    fn from(account_storage_header: &AccountStorageHeader) -> Self {
        Self {
            slots: account_storage_header
                .slots()
                .map(|slot| proto::account::account_storage_header::StorageSlot {
                    slot_name: slot.name().to_string(),
                    slot_type: encode_storage_slot_type(slot.slot_type()),
                    commitment: Some(slot.value().into()),
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

fn decode_account_version(version: i32) -> Result<(), ConversionError> {
    match proto::account::AccountVersion::try_from(version) {
        Ok(proto::account::AccountVersion::V1) => Ok(()),
        Ok(proto::account::AccountVersion::Unspecified) => {
            Err(ConversionError::message("account header version is unspecified"))
        },
        Err(error) => Err(ConversionError::with_source(
            format!("unknown account header version {version}"),
            error,
        )),
    }
}

// PARTIAL STORAGE MAP
// ================================================================================================

impl TryFrom<proto::account::PartialStorageMap> for PartialStorageMap {
    type Error = ConversionError;

    fn try_from(message: proto::account::PartialStorageMap) -> Result<Self, Self::Error> {
        let decoder = message.decoder();
        let smt: PartialSmt = required!(decoder, message.smt)?;
        let keys = message
            .keys
            .into_iter()
            .enumerate()
            .map(|(index, key)| {
                Word::try_from(key)
                    .map(miden_protocol::account::StorageMapKey::from_raw)
                    .context(format!("keys[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        PartialStorageMap::try_from_parts(smt, keys).map_err(ConversionError::new)
    }
}

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

impl TryFrom<proto::account::PartialStorage> for PartialStorage {
    type Error = ConversionError;

    fn try_from(message: proto::account::PartialStorage) -> Result<Self, Self::Error> {
        let decoder = message.decoder();
        let header = required!(decoder, message.header)?;
        let mut roots = BTreeSet::new();
        let maps = message
            .maps
            .into_iter()
            .enumerate()
            .map(|(index, map)| {
                let map = PartialStorageMap::try_from(map).context(format!("maps[{index}]"))?;
                if !roots.insert(map.root()) {
                    return Err(ConversionError::message("duplicate partial storage map root")
                        .context(format!("maps[{index}]")));
                }
                Ok(map)
            })
            .collect::<Result<Vec<_>, _>>()?;

        PartialStorage::new(header, maps).map_err(ConversionError::new)
    }
}

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

impl TryFrom<proto::account::PartialVault> for PartialVault {
    type Error = ConversionError;

    fn try_from(message: proto::account::PartialVault) -> Result<Self, Self::Error> {
        let decoder = message.decoder();
        let smt: PartialSmt = required!(decoder, message.smt)?;
        let asset_ids = message
            .asset_ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| {
                Word::try_from(id)
                    .context(format!("asset_ids[{index}]"))
                    .and_then(|id| AssetId::try_from(id).context(format!("asset_ids[{index}]")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        PartialVault::try_from_parts(smt, asset_ids).map_err(ConversionError::new)
    }
}

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

impl TryFrom<proto::account::PartialAccount> for PartialAccount {
    type Error = ConversionError;

    fn try_from(message: proto::account::PartialAccount) -> Result<Self, Self::Error> {
        let decoder = message.decoder();
        let account_id = required!(decoder, message.account_id)?;
        let nonce = required!(decoder, message.nonce)?;
        let code: AccountCode = required!(decoder, message.code)?;
        let storage = required!(decoder, message.storage)?;
        let vault = required!(decoder, message.vault)?;
        let seed = message.seed.map(Word::try_from).transpose().context("seed")?;

        PartialAccount::new(account_id, nonce, code, storage, vault, seed)
            .map_err(ConversionError::new)
    }
}

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

impl TryFrom<proto::account::AccountHeader> for AccountHeader {
    type Error = ConversionError;

    fn try_from(message: proto::account::AccountHeader) -> Result<Self, Self::Error> {
        decode_account_version(message.version).context("version")?;

        let decoder = message.decoder();
        let account_id = required!(decoder, message.account_id)?;
        let vault_root = required!(decoder, message.vault_root)?;
        let storage_commitment = required!(decoder, message.storage_commitment)?;
        let code_commitment = required!(decoder, message.code_commitment)?;
        let nonce = Felt::try_from(message.nonce).map_err(ConversionError::new).context("nonce")?;
        Ok(AccountHeader::new(
            account_id,
            nonce,
            vault_root,
            storage_commitment,
            code_commitment,
        ))
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

impl TryFrom<proto::account::AccountWitness> for AccountWitness {
    type Error = ConversionError;

    fn try_from(message: proto::account::AccountWitness) -> Result<Self, Self::Error> {
        let decoder = message.decoder();
        let witness_id = required!(decoder, message.witness_id)?;
        let commitment = required!(decoder, message.commitment)?;
        let path = required!(decoder, message.path)?;

        AccountWitness::new(witness_id, commitment, path).map_err(ConversionError::new)
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
