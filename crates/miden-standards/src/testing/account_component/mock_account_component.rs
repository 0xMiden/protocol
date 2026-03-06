use alloc::vec::Vec;

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountCode,
    AccountComponent,
    AccountStorage,
    AccountType,
    StorageSlot,
};

use crate::testing::mock_account_code::MockAccountCodeExt;

// MOCK ACCOUNT COMPONENT
// ================================================================================================

/// A mock account component for use in tests.
///
/// It uses the [`MockAccountCodeExt::mock_account_library`][account_lib] and allows for an
/// arbitrary number of storage slots (within the overall limit) so anything can be set for testing
/// purposes.
///
/// This component supports all [`AccountType`](miden_protocol::account::AccountType)s for testing
/// purposes.
///
/// [account_lib]: crate::testing::mock_account_code::MockAccountCodeExt::mock_account_library
pub struct MockAccountComponent {
    storage_slots: Vec<StorageSlot>,
}

impl MockAccountComponent {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a [`MockAccountComponent`] with empty storage.
    pub fn with_empty_slots() -> Self {
        Self::new(vec![])
    }

    /// Constructs a [`MockAccountComponent`] with the provided storage slots.
    ///
    /// # Panics
    ///
    /// Panics if the number of slots exceeds [`AccountStorage::MAX_NUM_STORAGE_SLOTS`].
    pub fn with_slots(storage_slots: Vec<StorageSlot>) -> Self {
        Self::new(storage_slots)
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    fn new(storage_slots: Vec<StorageSlot>) -> Self {
        debug_assert!(
            storage_slots.len() <= AccountStorage::MAX_NUM_STORAGE_SLOTS,
            "too many storage slots passed to MockAccountComponent"
        );

        Self { storage_slots }
    }
}

impl From<MockAccountComponent> for AccountComponent {
    fn from(mock_component: MockAccountComponent) -> Self {
        let metadata =
            AccountComponentMetadata::new("miden::testing::mock_account", AccountType::all())
                .with_description("Mock account component for testing");

        AccountComponent::new(
            AccountCode::mock_account_library(),
            mock_component.storage_slots,
            metadata,
        )
        .expect(
            "mock account component should satisfy the requirements of a valid account component",
        )
    }
}
