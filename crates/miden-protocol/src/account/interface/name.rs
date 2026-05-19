use alloc::borrow::Cow;
use alloc::string::String;
use core::fmt::Display;
use core::str::FromStr;

use crate::account::name_validation::{self, NameValidationError};
use crate::errors::AccountComponentNameError;

/// The canonical name of an account component.
///
/// Names follow the same syntax as [`StorageSlotName`](crate::account::StorageSlotName):
/// `::`-separated components consisting of ASCII alphanumeric characters or underscores, with at
/// least two components and no leading underscore on any component. See the type-level docs of
/// [`StorageSlotName`](crate::account::StorageSlotName) for the full grammar.
///
/// The name is stored as a `Cow<'static, str>` so that hard-coded component names (e.g. the
/// `NAME` constant on each standard component) can be turned into typed names via
/// [`AccountComponentName::from_static_str`] without any runtime allocation, while runtime names
/// (parsed strings, etc.) can still be constructed via [`AccountComponentName::new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountComponentName(Cow<'static, str>);

impl AccountComponentName {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs an [`AccountComponentName`] from a `&'static str` at compile time.
    ///
    /// # Panics
    ///
    /// Panics if `name` does not satisfy the validity rules described in the type-level
    /// documentation of [`AccountComponentName`].
    pub const fn from_static_str(name: &'static str) -> Self {
        match name_validation::validate(name) {
            Ok(()) => Self(Cow::Borrowed(name)),
            Err(_) => panic!("invalid AccountComponentName: see the type-level documentation"),
        }
    }

    /// Constructs an [`AccountComponentName`] from any value convertible into a
    /// `Cow<'static, str>`.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is not a valid component name (see the type-level docs).
    pub fn new(name: impl Into<Cow<'static, str>>) -> Result<Self, AccountComponentNameError> {
        let name = name.into();
        name_validation::validate(&name).map_err(AccountComponentNameError::from_internal)?;
        Ok(Self(name))
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the component name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AccountComponentNameError {
    /// Maps each [`NameValidationError`] variant to its corresponding
    /// [`AccountComponentNameError`] variant.
    pub(crate) fn from_internal(error: NameValidationError) -> Self {
        match error {
            NameValidationError::TooShort => Self::TooShort,
            NameValidationError::TooLong => Self::TooLong,
            NameValidationError::UnexpectedColon => Self::UnexpectedColon,
            NameValidationError::UnexpectedUnderscore => Self::UnexpectedUnderscore,
            NameValidationError::InvalidCharacter => Self::InvalidCharacter,
        }
    }
}

impl Display for AccountComponentName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AccountComponentName {
    type Err = AccountComponentNameError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Self::new(String::from(string))
    }
}

impl TryFrom<&str> for AccountComponentName {
    type Error = AccountComponentNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for AccountComponentName {
    type Error = AccountComponentNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<AccountComponentName> for String {
    fn from(name: AccountComponentName) -> Self {
        name.0.into_owned()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    //! Note: Most tests live in crate::account::name_validation.

    use super::*;

    #[test]
    #[should_panic(expected = "invalid AccountComponentName")]
    fn from_static_str_panics_on_invalid_input() {
        AccountComponentName::from_static_str("not_two_components");
    }
}
