use crate::account::component::AccountComponentMetadata;

impl AccountComponentMetadata {
    /// Creates a mock [`AccountComponentMetadata`] with the given name.
    pub fn mock(name: &str) -> Self {
        AccountComponentMetadata::new(name)
    }
}
