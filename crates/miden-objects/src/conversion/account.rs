use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use miden_protocol::Felt;
use miden_protocol::account::{
    AccountHeader,
    AccountId,
    AccountStorageHeader,
    StorageSlotHeader,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::utils::serde::{Deserializable, DeserializationError, Serializable};

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

impl TryFrom<proto::account::AccountId> for AccountId {
    type Error = ConversionError;

    fn try_from(value: proto::account::AccountId) -> Result<Self, Self::Error> {
        AccountId::read_from_bytes(&value.id)
            .map_err(|error| ConversionError::deserialization("AccountId", error))
    }
}

impl From<&AccountId> for proto::account::AccountId {
    fn from(value: &AccountId) -> Self {
        Self { id: value.to_bytes() }
    }
}

impl From<AccountId> for proto::account::AccountId {
    fn from(value: AccountId) -> Self {
        (&value).into()
    }
}

impl TryFrom<proto::account::AccountStorageHeader> for AccountStorageHeader {
    type Error = ConversionError;

    fn try_from(value: proto::account::AccountStorageHeader) -> Result<Self, Self::Error> {
        let slots = value
            .slots
            .into_iter()
            .map(|slot| {
                let decoder = slot.decoder();
                let name = StorageSlotName::new(slot.slot_name)?;
                let slot_type = match slot.slot_type {
                    0 => StorageSlotType::Value,
                    1 => StorageSlotType::Map,
                    _ => {
                        return Err(ConversionError::message(
                            "storage slot type discriminant out of range",
                        ));
                    },
                };
                let value = required!(decoder, slot.commitment)?;
                Ok(StorageSlotHeader::new(name, slot_type, value))
            })
            .collect::<Result<Vec<_>, ConversionError>>()
            .context("slots")?;
        AccountStorageHeader::new(slots).map_err(ConversionError::new)
    }
}

impl From<&AccountStorageHeader> for proto::account::AccountStorageHeader {
    fn from(value: &AccountStorageHeader) -> Self {
        Self {
            slots: value
                .slots()
                .map(|slot| proto::account::account_storage_header::StorageSlot {
                    slot_name: slot.name().to_string(),
                    slot_type: match slot.slot_type() {
                        StorageSlotType::Value => 0,
                        StorageSlotType::Map => 1,
                    },
                    commitment: Some(slot.value().into()),
                })
                .collect(),
        }
    }
}

impl From<AccountStorageHeader> for proto::account::AccountStorageHeader {
    fn from(value: AccountStorageHeader) -> Self {
        (&value).into()
    }
}

impl TryFrom<proto::account::AccountHeader> for AccountHeader {
    type Error = ConversionError;

    fn try_from(value: proto::account::AccountHeader) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let account_id = required!(decoder, value.account_id)?;
        let vault_root = required!(decoder, value.vault_root)?;
        let storage_commitment = required!(decoder, value.storage_commitment)?;
        let code_commitment = required!(decoder, value.code_commitment)?;
        let nonce = Felt::try_from(value.nonce)
            .map_err(|error| ConversionError::message(format!("{error}")))
            .context("nonce")?;
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
    fn from(value: &AccountHeader) -> Self {
        Self {
            account_id: Some(value.id().into()),
            vault_root: Some(value.vault_root().into()),
            storage_commitment: Some(value.storage_commitment().into()),
            code_commitment: Some(value.code_commitment().into()),
            nonce: value.nonce().as_canonical_u64(),
        }
    }
}

impl From<AccountHeader> for proto::account::AccountHeader {
    fn from(value: AccountHeader) -> Self {
        (&value).into()
    }
}

impl TryFrom<proto::account::AccountWitness> for AccountWitness {
    type Error = ConversionError;

    fn try_from(value: proto::account::AccountWitness) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let witness_id = required!(decoder, value.witness_id)?;
        let commitment = required!(decoder, value.commitment)?;
        let path = required!(decoder, value.path)?;
        AccountWitness::new(witness_id, commitment, path).map_err(|error| {
            ConversionError::deserialization(
                "AccountWitness",
                DeserializationError::InvalidValue(error.to_string()),
            )
        })
    }
}

impl From<&AccountWitness> for proto::account::AccountWitness {
    fn from(value: &AccountWitness) -> Self {
        Self {
            account_id: Some(value.id().into()),
            witness_id: Some(value.id().into()),
            commitment: Some(value.state_commitment().into()),
            path: Some(value.path().clone().into()),
        }
    }
}

impl From<AccountWitness> for proto::account::AccountWitness {
    fn from(value: AccountWitness) -> Self {
        (&value).into()
    }
}
