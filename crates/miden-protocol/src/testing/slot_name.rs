use crate::account::StorageSlotName;

impl StorageSlotName {
    /// Returns a new slot name with the format `"miden::test::slot::{index}"`.
    pub fn mock(index: usize) -> Self {
        Self::new(format!("miden::test::slot::{index}")).expect("storage slot name should be valid")
    }
}
