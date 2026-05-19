//! Shared validation rules used by both [`StorageSlotName`](super::StorageSlotName) and
//! [`AccountComponentName`](crate::account::AccountComponentName).
//!
//! Both names share the same syntax: `1..=255` total bytes, `::`-separated components, each
//! component consisting of ASCII alphanumeric characters or underscores and not starting with an
//! underscore.
//!
//! Public callers should use the validation methods on the public types (which map this internal
//! error into their respective public error types). This module is `pub(crate)` to keep the
//! mapping exhaustive and the public surface clean.

/// Errors that can be produced by the shared name validator.
///
/// This type is intentionally internal: each public name type maps it exhaustively into its own
/// error enum so the public error surface stays type-specific.
#[derive(Debug)]
pub(crate) enum NameValidationError {
    TooShort,
    TooLong,
    UnexpectedColon,
    UnexpectedUnderscore,
    InvalidCharacter,
}

/// The minimum number of `::`-separated components a name must contain.
pub(crate) const MIN_NUM_COMPONENTS: usize = 2;

/// The maximum number of bytes a name may contain.
pub(crate) const MAX_LENGTH: usize = u8::MAX as usize;

/// validates a name against the shared rules.
///
/// We must check validity against the raw bytes of the UTF-8 string because typical character APIs
/// are not available in a const context. We can do this because any byte in a UTF-8 string that is
/// an ASCII character never represents anything other than such a character, even though UTF-8 can
/// contain multi-byte sequences:
///
/// > UTF-8, the object of this memo, has a one-octet encoding unit. It uses all bits of an
/// > octet, but has the quality of preserving the full US-ASCII range: US-ASCII characters
/// > are encoded in one octet having the normal US-ASCII value, and any octet with such a value
/// > can only stand for a US-ASCII character, and nothing else.
/// > <https://www.rfc-editor.org/rfc/rfc3629>
pub(crate) const fn validate(name: &str) -> Result<(), NameValidationError> {
    let bytes = name.as_bytes();
    let mut idx = 0;
    let mut num_components = 0;

    if bytes.is_empty() {
        return Err(NameValidationError::TooShort);
    }

    if bytes.len() > MAX_LENGTH {
        return Err(NameValidationError::TooLong);
    }

    // Names must not start with a colon or underscore.
    // SAFETY: We just checked that we're not dealing with an empty slice.
    if bytes[0] == b':' {
        return Err(NameValidationError::UnexpectedColon);
    } else if bytes[0] == b'_' {
        return Err(NameValidationError::UnexpectedUnderscore);
    }

    while idx < bytes.len() {
        let byte = bytes[idx];

        let is_colon = byte == b':';

        if is_colon {
            // A colon must always be followed by another colon. In other words, we
            // expect a double colon.
            if (idx + 1) < bytes.len() {
                if bytes[idx + 1] != b':' {
                    return Err(NameValidationError::UnexpectedColon);
                }
            } else {
                return Err(NameValidationError::UnexpectedColon);
            }

            // A component cannot end with a colon, so this allows us to validate the start of a
            // component: It must not start with a colon or an underscore.
            if (idx + 2) < bytes.len() {
                if bytes[idx + 2] == b':' {
                    return Err(NameValidationError::UnexpectedColon);
                } else if bytes[idx + 2] == b'_' {
                    return Err(NameValidationError::UnexpectedUnderscore);
                }
            } else {
                return Err(NameValidationError::UnexpectedColon);
            }

            // Advance past the double colon.
            idx += 2;

            // A double colon completes a name component.
            num_components += 1;
        } else if is_valid_char(byte) {
            idx += 1;
        } else {
            return Err(NameValidationError::InvalidCharacter);
        }
    }

    // The last component is not counted as part of the loop because no double colon follows.
    num_components += 1;

    if num_components < MIN_NUM_COMPONENTS {
        return Err(NameValidationError::TooShort);
    }

    Ok(())
}

const fn is_valid_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

// TESTS
// ================================================================================================

#[cfg(test)]
pub(super) mod tests {
    use alloc::string::String;
    use std::borrow::ToOwned;
    use std::string::ToString;

    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::account::{AccountComponentName, StorageSlotName};

    // A string containing all allowed characters of a slot name.
    const FULL_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789";

    // Invalid colon or underscore tests
    // --------------------------------------------------------------------------------------------

    #[test]
    fn slot_name_fails_on_invalid_colon_placement() {
        // Single colon.
        assert_matches!(validate(":").unwrap_err(), NameValidationError::UnexpectedColon);
        assert_matches!(validate("0::1:").unwrap_err(), NameValidationError::UnexpectedColon);
        assert_matches!(validate(":0::1").unwrap_err(), NameValidationError::UnexpectedColon);
        assert_matches!(validate("0::1:2").unwrap_err(), NameValidationError::UnexpectedColon);

        // Double colon (placed invalidly).
        assert_matches!(validate("::").unwrap_err(), NameValidationError::UnexpectedColon);
        assert_matches!(validate("1::2::").unwrap_err(), NameValidationError::UnexpectedColon);
        assert_matches!(validate("::1::2").unwrap_err(), NameValidationError::UnexpectedColon);

        // Triple colon.
        assert_matches!(validate(":::").unwrap_err(), NameValidationError::UnexpectedColon);
        assert_matches!(validate("1::2:::").unwrap_err(), NameValidationError::UnexpectedColon);
        assert_matches!(validate(":::1::2").unwrap_err(), NameValidationError::UnexpectedColon);
        assert_matches!(validate("1::2:::3").unwrap_err(), NameValidationError::UnexpectedColon);
    }

    #[test]
    fn slot_name_fails_on_invalid_underscore_placement() {
        assert_matches!(
            validate("_one::two").unwrap_err(),
            NameValidationError::UnexpectedUnderscore
        );
        assert_matches!(
            validate("one::_two").unwrap_err(),
            NameValidationError::UnexpectedUnderscore
        );
    }

    // Length validation tests
    // --------------------------------------------------------------------------------------------

    #[test]
    fn slot_name_fails_on_empty_string() {
        assert_matches!(validate("").unwrap_err(), NameValidationError::TooShort);
    }

    #[test]
    fn slot_name_fails_on_single_component() {
        assert_matches!(validate("single_component").unwrap_err(), NameValidationError::TooShort);
    }

    #[test]
    fn slot_name_fails_on_string_whose_length_exceeds_max_length() {
        let mut string = get_max_length_name();
        string.push('a');
        assert_matches!(validate(&string).unwrap_err(), NameValidationError::TooLong);
    }

    // Alphabet validation tests
    // --------------------------------------------------------------------------------------------

    #[test]
    fn slot_name_allows_ascii_alphanumeric_and_underscore() {
        let name = format!("{FULL_ALPHABET}::second");
        validate(&name).unwrap();
    }

    #[test]
    fn slot_name_fails_on_invalid_character() {
        assert_matches!(
            validate("na#me::second").unwrap_err(),
            NameValidationError::InvalidCharacter
        );
        assert_matches!(
            validate("first_entry::secönd").unwrap_err(),
            NameValidationError::InvalidCharacter
        );
        assert_matches!(
            validate("first::sec::th!rd").unwrap_err(),
            NameValidationError::InvalidCharacter
        );
    }

    // Valid slot name tests
    // --------------------------------------------------------------------------------------------

    #[test]
    fn slot_name_with_min_components_is_valid() {
        validate("miden::component").unwrap()
    }

    #[test]
    fn slot_name_with_many_components_is_valid() {
        validate("miden::faucet0::fungible_1::b4sic::metadata").unwrap();
    }

    #[test]
    fn slot_name_with_max_length_is_valid() {
        validate(&get_max_length_name()).unwrap();
    }

    // Shared validation parity
    // --------------------------------------------------------------------------------------------

    /// Confirms that both `StorageSlotName::new` and `AccountComponentName::new` reject the same
    /// inputs through the shared validator. Guards against the extraction silently dropping a
    /// check.
    #[rstest]
    #[case("")]
    #[case("single")]
    #[case(":leading_colon::ok")]
    #[case("_leading_underscore::ok")]
    #[case("ok::_leading_underscore")]
    #[case("ok::bad#char")]
    #[case("triple:::colon::ok")]
    fn shared_validation_parity(#[case] name: &str) {
        assert!(StorageSlotName::new(name.to_string()).is_err());
        assert!(AccountComponentName::new(name.to_string()).is_err());
    }

    // Test helpers
    // --------------------------------------------------------------------------------------------

    pub(crate) fn get_max_length_name() -> String {
        const MIDEN_STR: &str = "miden::";
        let remainder = ['a'; MAX_LENGTH - MIDEN_STR.len()];
        let mut string = MIDEN_STR.to_owned();
        string.extend(remainder);
        assert_eq!(string.len(), MAX_LENGTH);
        string
    }
}
