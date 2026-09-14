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
        let slots = self.slots.into_iter().map(Verify::verify).collect::<Result<_, _>>()?;
        Ok(Self::Verified::new(slots)?)
    }
}
