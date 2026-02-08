use alloc::string::ToString;
use alloc::vec::Vec;

use super::map::EMPTY_STORAGE_MAP_ROOT;
use super::{AccountStorage, Felt, StorageSlotType, Word};
use crate::account::{StorageSlot, StorageSlotId, StorageSlotName};
use crate::crypto::SequentialCommit;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{AccountError, ZERO};

// ACCOUNT STORAGE HEADER
// ================================================================================================

/// The header of an [`AccountStorage`], storing only the slot name, slot type and value of each
/// storage slot.
///
/// The stored value differs based on the slot type:
/// - [`StorageSlotType::Value`]: The value of the slot itself.
/// - [`StorageSlotType::Map`]: The root of the SMT that represents the storage map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStorageHeader {
    slots: Vec<StorageSlotHeader>,
}

impl AccountStorageHeader {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new instance of account storage header initialized with the provided slots.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of provided slots is greater than [`AccountStorage::MAX_NUM_STORAGE_SLOTS`].
    /// - The slots are not sorted by [`StorageSlotId`].
    /// - There are multiple storage slots with the same [`StorageSlotName`].
    pub fn new(slots: Vec<StorageSlotHeader>) -> Result<Self, AccountError> {
        if slots.len() > AccountStorage::MAX_NUM_STORAGE_SLOTS {
            return Err(AccountError::StorageTooManySlots(slots.len() as u64));
        }

        if !slots.is_sorted_by_key(|slot| slot.id()) {
            return Err(AccountError::UnsortedStorageSlots);
        }

        // Check for slot name uniqueness by checking each neighboring slot's IDs. This is
        // sufficient because the slots are sorted.
        for slots in slots.windows(2) {
            if slots[0].id() == slots[1].id() {
                return Err(AccountError::DuplicateStorageSlotName(slots[0].name().clone()));
            }
        }

        Ok(Self { slots })
    }

    /// Returns a new instance of account storage header initialized with the provided slot tuples.
    ///
    /// This is a convenience method that converts tuples to [`StorageSlotHeader`]s.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of provided slots is greater than [`AccountStorage::MAX_NUM_STORAGE_SLOTS`].
    /// - The slots are not sorted by [`StorageSlotId`].
    #[cfg(any(feature = "testing", test))]
    pub fn from_tuples(
        slots: Vec<(StorageSlotName, StorageSlotType, Word)>,
    ) -> Result<Self, AccountError> {
        let slots = slots
            .into_iter()
            .map(|(name, slot_type, value)| StorageSlotHeader::new(name, slot_type, value))
            .collect();

        Self::new(slots)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the storage header slots.
    pub fn slots(&self) -> impl Iterator<Item = &StorageSlotHeader> {
        self.slots.iter()
    }

    /// Returns an iterator over the storage header map slots.
    pub fn map_slot_roots(&self) -> impl Iterator<Item = Word> + '_ {
        self.slots.iter().filter_map(|slot| match slot.slot_type() {
            StorageSlotType::Value => None,
            StorageSlotType::Map => Some(slot.value()),
        })
    }

    /// Returns the number of slots contained in the storage header.
    pub fn num_slots(&self) -> u8 {
        // SAFETY: The constructors of this type ensure this value fits in a u8.
        self.slots.len() as u8
    }

    /// Returns the storage slot header for the slot with the given name.
    ///
    /// Returns `None` if a slot with the provided name does not exist.
    pub fn find_slot_header_by_name(
        &self,
        slot_name: &StorageSlotName,
    ) -> Option<&StorageSlotHeader> {
        self.find_slot_header_by_id(slot_name.id())
    }

    /// Returns the storage slot header for the slot with the given ID.
    ///
    /// Returns `None` if a slot with the provided slot ID does not exist.
    pub fn find_slot_header_by_id(&self, slot_id: StorageSlotId) -> Option<&StorageSlotHeader> {
        self.slots.iter().find(|slot| slot.id() == slot_id)
    }

    /// Indicates whether the slot with the given `name` is a map slot.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a slot with the provided name does not exist.
    pub fn is_map_slot(&self, name: &StorageSlotName) -> Result<bool, AccountError> {
        match self
            .find_slot_header_by_name(name)
            .ok_or(AccountError::StorageSlotNameNotFound { slot_name: name.clone() })?
            .slot_type()
        {
            StorageSlotType::Map => Ok(true),
            StorageSlotType::Value => Ok(false),
        }
    }

    /// Converts storage slots of this account storage header into a vector of field elements.
    ///
    /// This is done by first converting each storage slot into exactly 8 elements as follows:
    ///
    /// ```text
    /// [[0, slot_type, slot_id_suffix, slot_id_prefix], SLOT_VALUE]
    /// ```
    ///
    /// And then concatenating the resulting elements into a single vector.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Returns the commitment to the [`AccountStorage`] this header represents.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }
}

impl From<&AccountStorage> for AccountStorageHeader {
    fn from(value: &AccountStorage) -> Self {
        value.to_header()
    }
}

// SEQUENTIAL COMMIT
// ================================================================================================

impl SequentialCommit for AccountStorageHeader {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        self.slots().flat_map(|slot| slot.to_elements()).collect()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountStorageHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let len = self.slots.len() as u8;
        target.write_u8(len);
        target.write_many(self.slots())
    }
}

impl Deserializable for AccountStorageHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_u8()?;
        let slots: Vec<StorageSlotHeader> = source
            .read_many_iter::<StorageSlotHeader>(len as usize)?
            .collect::<Result<_, _>>()?;
        Self::new(slots).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// STORAGE SLOT HEADER
// ================================================================================================

/// The header of a [`StorageSlot`], storing only the slot name (or ID), slot type and value of the
/// slot.
///
/// The stored value differs based on the slot type:
/// - [`StorageSlotType::Value`]: The value of the slot itself.
/// - [`StorageSlotType::Map`]: The root of the SMT that represents the storage map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSlotHeader {
    name: StorageSlotName,
    r#type: StorageSlotType,
    value: Word,
}

impl StorageSlotHeader {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new instance of storage slot header.
    pub fn new(name: StorageSlotName, r#type: StorageSlotType, value: Word) -> Self {
        Self { name, r#type, value }
    }

    /// Returns a new instance of storage slot header with an empty value slot.
    pub fn with_empty_value(name: StorageSlotName) -> StorageSlotHeader {
        StorageSlotHeader::new(name, StorageSlotType::Value, Word::default())
    }

    /// Returns a new instance of storage slot header with an empty map slot.
    pub fn with_empty_map(name: StorageSlotName) -> StorageSlotHeader {
        StorageSlotHeader::new(name, StorageSlotType::Map, EMPTY_STORAGE_MAP_ROOT)
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the slot name.
    pub fn name(&self) -> &StorageSlotName {
        &self.name
    }

    /// Returns the slot ID.
    pub fn id(&self) -> StorageSlotId {
        self.name.id()
    }

    /// Returns the slot type.
    pub fn slot_type(&self) -> StorageSlotType {
        self.r#type
    }

    /// Returns the slot value.
    pub fn value(&self) -> Word {
        self.value
    }

    /// Returns this storage slot header as field elements.
    ///
    /// This is done by converting this storage slot into 8 field elements as follows:
    /// ```text
    /// [[0, slot_type, slot_id_suffix, slot_id_prefix], SLOT_VALUE]
    /// ```
    pub(crate) fn to_elements(&self) -> [Felt; StorageSlot::NUM_ELEMENTS] {
        let id = self.id();
        let mut elements = [ZERO; StorageSlot::NUM_ELEMENTS];
        elements[0..4].copy_from_slice(&[ZERO, self.r#type.as_felt(), id.suffix(), id.prefix()]);
        elements[4..8].copy_from_slice(self.value.as_elements());
        elements
    }
}

impl From<&StorageSlot> for StorageSlotHeader {
    fn from(slot: &StorageSlot) -> Self {
        StorageSlotHeader::new(slot.name().clone(), slot.slot_type(), slot.value())
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for StorageSlotHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.name.write_into(target);
        self.r#type.write_into(target);
        self.value.write_into(target);
    }
}

impl Deserializable for StorageSlotHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name = StorageSlotName::read_from(source)?;
        let slot_type = StorageSlotType::read_from(source)?;
        let value = Word::read_from(source)?;
        Ok(Self::new(name, slot_type, value))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::Felt;
    use miden_crypto::utils::{Deserializable, Serializable};

    use super::AccountStorageHeader;
    use crate::Word;
    use crate::account::{AccountStorage, StorageSlotType};
    use crate::testing::storage::{MOCK_MAP_SLOT, MOCK_VALUE_SLOT0, MOCK_VALUE_SLOT1};

    #[test]
    fn test_from_account_storage() {
        let storage_map = AccountStorage::mock_map();

        // create new storage header from AccountStorage
        let mut slots = vec![
            (MOCK_VALUE_SLOT0.clone(), StorageSlotType::Value, Word::from([1, 2, 3, 4u32])),
            (
                MOCK_VALUE_SLOT1.clone(),
                StorageSlotType::Value,
                Word::from([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]),
            ),
            (MOCK_MAP_SLOT.clone(), StorageSlotType::Map, storage_map.root()),
        ];
        slots.sort_unstable_by_key(|(slot_name, ..)| slot_name.id());

        let expected_header = AccountStorageHeader::from_tuples(slots).unwrap();
        let account_storage = AccountStorage::mock();

        assert_eq!(expected_header, AccountStorageHeader::from(&account_storage))
    }

    #[test]
    fn test_serde_account_storage_header() {
        // create new storage header
        let storage = AccountStorage::mock();
        let storage_header = AccountStorageHeader::from(&storage);

        // serde storage header
        let bytes = storage_header.to_bytes();
        let deserialized = AccountStorageHeader::read_from_bytes(&bytes).unwrap();

        // assert deserialized == storage header
        assert_eq!(storage_header, deserialized);
    }
}
