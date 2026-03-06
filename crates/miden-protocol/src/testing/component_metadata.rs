use crate::account::AccountType;
use crate::account::component::AccountComponentMetadata;

impl AccountComponentMetadata {
    /// Creates a mock [`AccountComponentMetadata`] with the given name that supports all account
    /// types.
    pub fn mock(name: &str) -> Self {
        AccountComponentMetadata::new(name, AccountType::all())
    }
}
