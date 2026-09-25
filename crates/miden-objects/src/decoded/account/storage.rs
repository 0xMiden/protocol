pub use proto::account::DecodedStorageSlotId as StorageSlotId;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for StorageSlotId {
    type Verified = miden_protocol::account::StorageSlotId;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(self.suffix, self.prefix))
    }
}

pub use proto::account::DecodedStorageMapEntry as StorageMapEntry;

impl Verify for StorageMapEntry {
    type Verified = (miden_protocol::account::StorageMapKey, miden_protocol::Word);
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((miden_protocol::account::StorageMapKey::from_raw(self.key), self.value))
    }
}

pub use proto::account::account_storage_header::DecodedStorageSlot as AccountStorageHeaderStorageSlot;

impl Verify for AccountStorageHeaderStorageSlot {
    type Verified = miden_protocol::account::StorageSlotHeader;
    type Error = miden_protocol::errors::StorageSlotNameError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use miden_protocol::account::StorageSlotType;
        use proto::account::account_storage_header::storage_slot::DecodedContent;

        let name = miden_protocol::account::StorageSlotName::new(self.slot_name)?;
        let (slot_type, value) = match self.content {
            DecodedContent::Value(value) => (StorageSlotType::Value, value),
            DecodedContent::MapRoot(root) => (StorageSlotType::Map, root),
        };
        Ok(Self::Verified::new(name, slot_type, value))
    }
}

pub use proto::account::DecodedAccountStorageHeader as AccountStorageHeader;

impl Verify for AccountStorageHeader {
    type Verified = miden_protocol::account::AccountStorageHeader;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let slots = self.slots.verify()?;
        Ok(Self::Verified::new(slots)?)
    }
}

pub use proto::account::DecodedStorageMap as StorageMap;

impl Verify for StorageMap {
    type Verified = miden_protocol::account::StorageMap;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let entries = self.entries.verify_infallible();
        // The storage map constructor drops an entry with an empty value. Reject it here for a
        // clear error.
        if let Some((key, _)) = entries.iter().find(|(_, value)| value.is_empty()) {
            return Err(StorageMapEntryError::EmptyValue(*key).into());
        }
        Ok(Self::Verified::with_entries(entries)?)
    }
}

/// An invariant of a single map entry, distinct from the domain's `StorageMapError`.
#[derive(Debug, thiserror::Error)]
pub enum StorageMapEntryError {
    #[error("storage map entry {0} has an empty value")]
    EmptyValue(miden_protocol::account::StorageMapKey),
}

pub use proto::account::DecodedStorageSlot as StorageSlot;

impl Verify for StorageSlot {
    type Verified = miden_protocol::account::StorageSlot;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use miden_protocol::account::StorageSlotContent;
        use proto::account::storage_slot::DecodedStorageSlotContent;

        let name = miden_protocol::account::StorageSlotName::new(self.slot_name)?;
        let content = match self.storage_slot_content {
            DecodedStorageSlotContent::Value(value) => StorageSlotContent::Value(value),
            DecodedStorageSlotContent::Map(map) => StorageSlotContent::Map(map.verify()?),
        };
        Ok(Self::Verified::new(name, content))
    }
}

pub use proto::account::DecodedAccountStorage as AccountStorage;

impl Verify for AccountStorage {
    type Verified = miden_protocol::account::AccountStorage;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        // Check the slot count before verifying the slots, so an oversized message is rejected
        // without first building a tree for each of its map slots.
        let num_slots = self.slots.as_slice().len();
        if num_slots > Self::Verified::MAX_NUM_STORAGE_SLOTS {
            return Err(miden_protocol::errors::AccountError::StorageTooManySlots(
                num_slots as u64,
            )
            .into());
        }
        Ok(Self::Verified::new(self.slots.verify()?)?)
    }
}
