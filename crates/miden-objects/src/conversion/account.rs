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
