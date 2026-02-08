use miden_assembly::Library;
use miden_core::mast::MastForest;

// ACCOUNT COMPONENT CODE
// ================================================================================================

/// A [`Library`] that has been assembled for use as component code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountComponentCode(Library);

impl AccountComponentCode {
    /// Returns a reference to the underlying [`Library`]
    pub fn as_library(&self) -> &Library {
        &self.0
    }

    /// Returns a reference to the code's [`MastForest`]
    pub fn mast_forest(&self) -> &MastForest {
        self.0.mast_forest().as_ref()
    }

    /// Consumes `self` and returns the underlying [`Library`]
    pub fn into_library(self) -> Library {
        self.0
    }
}

impl AsRef<Library> for AccountComponentCode {
    fn as_ref(&self) -> &Library {
        self.as_library()
    }
}

// CONVERSIONS
// ================================================================================================

impl From<Library> for AccountComponentCode {
    fn from(value: Library) -> Self {
        Self(value)
    }
}

impl From<AccountComponentCode> for Library {
    fn from(value: AccountComponentCode) -> Self {
        value.into_library()
    }
}
