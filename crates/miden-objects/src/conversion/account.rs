use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use miden_protocol::account::{
    AccountHeader,
    AccountId,
    AccountStorageHeader,
    PartialAccount,
    PartialStorage,
    PartialStorageMap,
    StorageMapKey,
    StorageSlotHeader,
    StorageSlotId,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::asset::{AssetId, PartialVault};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::{Felt, Word};

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

pub(crate) fn decode_account_id(id: Vec<u8>) -> Result<AccountId, ConversionError> {
    let bytes: [u8; AccountId::SERIALIZED_SIZE] =
        id.as_slice().try_into().map_err(ConversionError::new)?;
    AccountId::try_from(bytes).map_err(ConversionError::new)
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

impl TryFrom<proto::account::account_storage_header::StorageSlot> for StorageSlotHeader {
    type Error = ConversionError;

    fn try_from(
        slot: proto::account::account_storage_header::StorageSlot,
    ) -> Result<Self, Self::Error> {
        let decoder = slot.decoder();
        let name = StorageSlotName::new(slot.slot_name)
            .map_err(ConversionError::new)
            .context("slot_name")?;
        let slot_type = decode_storage_slot_type(slot.slot_type).context("slot_type")?;
        let commitment = required!(decoder, slot.commitment)?;
        Ok(Self::new(name, slot_type, commitment))
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

pub(crate) fn decode_account_version(version: i32) -> Result<(), ConversionError> {
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

pub(crate) fn decode_account_header(
    account_id: AccountId,
    vault_root: Word,
    storage_commitment: Word,
    code_commitment: Word,
    nonce: u64,
) -> Result<AccountHeader, ConversionError> {
    let nonce = Felt::try_from(nonce).map_err(ConversionError::new).context("nonce")?;
    Ok(AccountHeader::new(
        account_id,
        nonce,
        vault_root,
        storage_commitment,
        code_commitment,
    ))
}

// PARTIAL STORAGE MAP
// ================================================================================================

impl TryFrom<proto::primitives::Word> for StorageMapKey {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Word) -> Result<Self, Self::Error> {
        Word::try_from(value).map(Self::from_raw)
    }
}

pub(crate) fn decode_partial_storage_map(
    smt: miden_protocol::crypto::merkle::smt::PartialSmt,
    keys: Vec<StorageMapKey>,
) -> Result<PartialStorageMap, ConversionError> {
    PartialStorageMap::try_from_parts(smt, keys).map_err(ConversionError::new)
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

pub(crate) fn decode_partial_storage(
    header: AccountStorageHeader,
    maps: Vec<PartialStorageMap>,
) -> Result<PartialStorage, ConversionError> {
    let mut roots = BTreeSet::new();
    for (index, map) in maps.iter().enumerate() {
        if !roots.insert(map.root()) {
            return Err(ConversionError::message("duplicate partial storage map root")
                .context(format!("maps[{index}]")));
        }
    }

    PartialStorage::new(header, maps).map_err(ConversionError::new)
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

pub(crate) fn decode_partial_vault(
    smt: miden_protocol::crypto::merkle::smt::PartialSmt,
    asset_ids: Vec<AssetId>,
) -> Result<PartialVault, ConversionError> {
    PartialVault::try_from_parts(smt, asset_ids).map_err(ConversionError::new)
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
