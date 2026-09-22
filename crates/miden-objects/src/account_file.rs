//! The account file format.

use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::path::Path;

use miden_protocol::account::Account;
use miden_protocol::account::auth::AuthSecretKey;

use crate::{ConversionError, DecodeMessageExt, proto};

#[cfg(test)]
mod tests;

/// The marker that starts every account file.
const MAGIC: [u8; 4] = *b"acct";

// ACCOUNT FILE
// ================================================================================================

/// A complete description of an account together with the secret keys that authenticate it.
///
/// The file is a single unit that carries everything a client needs to act as the account, so it
/// is the usual way to move an account between clients.
///
/// # Warning
///
/// The encoded file contains secret key material in the clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountFile {
    account: Account,
    auth_secret_keys: Vec<AuthSecretKey>,
}

impl AccountFile {
    /// Returns a new [`AccountFile`] with the provided account and secret keys.
    ///
    /// A stored key does not have to belong to the account's authentication component, so there is
    /// nothing to validate between the two.
    pub fn new(account: Account, auth_secret_keys: Vec<AuthSecretKey>) -> Self {
        Self { account, auth_secret_keys }
    }

    /// Returns the account of this file.
    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Returns the secret keys of this file.
    pub fn auth_secret_keys(&self) -> &[AuthSecretKey] {
        &self.auth_secret_keys
    }

    /// Consumes this file and returns its account and secret keys.
    pub fn into_parts(self) -> (Account, Vec<AuthSecretKey>) {
        (self.account, self.auth_secret_keys)
    }

    // SERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Returns the encoded file: MAGIC bytes, then the Protobuf message.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::from(MAGIC);
        prost::Message::encode(&proto::account_file::AccountFile::from(self), &mut bytes)
            .expect("a Vec never runs out of capacity");
        bytes
    }

    /// Decodes an [`AccountFile`] from the provided bytes.
    ///
    /// The encoded account carries every storage map entry and every vault asset, so the size of
    /// the file is unbounded. A caller that decodes untrusted bytes must cap their length first.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not start with the MAGIC bytes, or if the message that
    /// follows is not a valid account file.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, AccountFileError> {
        let (magic, payload) =
            bytes.split_at_checked(MAGIC.len()).ok_or(AccountFileError::InvalidMagic)?;
        if magic != MAGIC {
            return Err(AccountFileError::InvalidMagic);
        }

        <proto::account_file::AccountFile as prost::Message>::decode(payload)
            .map_err(|error| AccountFileError::Decode(ConversionError::new(error)))?
            .decode_and_verify()
            .map_err(AccountFileError::Decode)
    }

    /// Writes the encoded file to the provided path.
    #[cfg(feature = "std")]
    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), AccountFileError> {
        std::fs::write(path, self.to_bytes()).map_err(AccountFileError::Io)
    }

    /// Reads an [`AccountFile`] from the provided path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, or if [`Self::try_from_bytes`] rejects its
    /// contents.
    #[cfg(feature = "std")]
    pub fn read(path: impl AsRef<Path>) -> Result<Self, AccountFileError> {
        let bytes = std::fs::read(path).map_err(AccountFileError::Io)?;
        Self::try_from_bytes(&bytes)
    }
}

// ACCOUNT FILE ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AccountFileError {
    #[error("invalid account file marker")]
    InvalidMagic,
    #[error("failed to decode the account file")]
    Decode(#[source] ConversionError),
    #[cfg(feature = "std")]
    #[error("failed to read or write the account file")]
    Io(#[source] std::io::Error),
}
