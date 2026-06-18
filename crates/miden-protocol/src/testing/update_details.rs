use crate::account::{AccountPatch, AccountUpdateDetails};

impl AccountUpdateDetails {
    /// Returns the [`AccountPatch`] contained in this update.
    ///
    /// # Panics
    ///
    /// Panics if the update is not [`AccountUpdateDetails::Public`].
    #[track_caller]
    pub fn unwrap_public(&self) -> &AccountPatch {
        match self {
            AccountUpdateDetails::Private => panic!("expected public, got private"),
            AccountUpdateDetails::Public(patch) => patch,
        }
    }
}
