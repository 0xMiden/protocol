use crate::Word;
use crate::account::storage::slot::StorageSlotId;
use crate::account::{StorageMap, StorageSlotContent, StorageSlotName, StorageSlotType};

/// An individual storage slot in [`AccountStorage`](crate::account::AccountStorage).
///
/// This consists of a [`StorageSlotName`] that uniquely identifies the slot and its
/// [`StorageSlotContent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSlot {
    /// The name of the storage slot.
    name: StorageSlotName,
    /// The content of the storage slot.
    content: StorageSlotContent,
}

impl StorageSlot {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of field elements that represent a [`StorageSlot`] in kernel memory.
    pub const NUM_ELEMENTS: usize = 8;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`StorageSlot`] with the given [`StorageSlotName`] and
    /// [`StorageSlotContent`].
    pub fn new(name: StorageSlotName, content: StorageSlotContent) -> Self {
        Self { name, content }
    }

    /// Creates a new [`StorageSlot`] with the given [`StorageSlotName`] and the `value`
    /// wrapped into a [`StorageSlotContent::Value`].
    pub fn with_value(name: StorageSlotName, value: Word) -> Self {
        Self::new(name, StorageSlotContent::Value(value))
    }

    /// Creates a new [`StorageSlot`] with the given [`StorageSlotName`] and
    /// [`StorageSlotContent::empty_value`].
    pub fn with_empty_value(name: StorageSlotName) -> Self {
        Self::new(name, StorageSlotContent::empty_value())
    }

    /// Creates a new [`StorageSlot`] with the given [`StorageSlotName`] and the `map` wrapped
    /// into a [`StorageSlotContent::Map`]
    pub fn with_map(name: StorageSlotName, map: StorageMap) -> Self {
        Self::new(name, StorageSlotContent::Map(map))
    }

    /// Creates a new [`StorageSlot`] with the given [`StorageSlotName`] and
    /// [`StorageSlotContent::empty_map`].
    pub fn with_empty_map(name: StorageSlotName) -> Self {
        Self::new(name, StorageSlotContent::empty_map())
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] by which the [`StorageSlot`] is identified.
    pub fn name(&self) -> &StorageSlotName {
        &self.name
    }

    /// Returns the [`StorageSlotId`] by which the [`StorageSlot`] is identified.
    pub fn id(&self) -> StorageSlotId {
        self.name.id()
    }

    /// Returns this storage slot value as a [Word]
    ///
    /// Returns:
    /// - For [`StorageSlotContent::Value`] the value.
    /// - For [`StorageSlotContent::Map`] the root of the [StorageMap].
    pub fn value(&self) -> Word {
        self.content().value()
    }

    /// Returns a reference to the [`StorageSlotContent`] contained in this [`StorageSlot`].
    pub fn content(&self) -> &StorageSlotContent {
        &self.content
    }

    /// Returns the [`StorageSlotType`] of this [`StorageSlot`].
    pub fn slot_type(&self) -> StorageSlotType {
        self.content.slot_type()
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Returns a mutable reference to the [`StorageSlotContent`] contained in this
    /// [`StorageSlot`].
    pub fn content_mut(&mut self) -> &mut StorageSlotContent {
        &mut self.content
    }

    /// Consumes self and returns the underlying parts.
    pub fn into_parts(self) -> (StorageSlotName, StorageSlotContent) {
        (self.name, self.content)
    }
}

impl Ord for StorageSlot {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.name().cmp(&other.name)
    }
}

impl PartialOrd for StorageSlot {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// SERIALIZATION
// ================================================================================================

impl crate::utils::serde::Serializable for StorageSlot {
    fn write_into<W: crate::utils::serde::ByteWriter>(&self, target: &mut W) {
        target.write(&self.name);
        target.write(&self.content);
    }

    fn get_size_hint(&self) -> usize {
        self.name.get_size_hint() + self.content().get_size_hint()
    }
}

impl crate::utils::serde::Deserializable for StorageSlot {
    fn read_from<R: miden_core::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, crate::utils::serde::DeserializationError> {
        let name: StorageSlotName = source.read()?;
        let content: StorageSlotContent = source.read()?;

        Ok(Self::new(name, content))
    }
}
