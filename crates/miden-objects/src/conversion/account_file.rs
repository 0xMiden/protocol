use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::utils::serde::Serializable;

use crate::account_file::AccountFile;
use crate::proto;

#[cfg(test)]
mod tests;

// AUTH SECRET KEY
// ================================================================================================

impl From<&AuthSecretKey> for proto::account_file::AuthSecretKey {
    fn from(secret_key: &AuthSecretKey) -> Self {
        use proto::account_file::auth_secret_key::Key;

        let key = match secret_key {
            AuthSecretKey::Falcon512Poseidon2(key) => Key::Falcon512Poseidon2(key.to_bytes()),
            AuthSecretKey::EcdsaK256Keccak(key) => Key::EcdsaK256Keccak(key.to_bytes()),
            // `AuthSecretKey` is `non_exhaustive`, but it should evolve together with this crate.
            _ => unreachable!(
                "every auth secret key scheme should have a corresponding protobuf variant"
            ),
        };
        Self { key: Some(key) }
    }
}

impl From<AuthSecretKey> for proto::account_file::AuthSecretKey {
    fn from(secret_key: AuthSecretKey) -> Self {
        Self::from(&secret_key)
    }
}

// ACCOUNT FILE
// ================================================================================================

impl From<&AccountFile> for proto::account_file::AccountFile {
    fn from(file: &AccountFile) -> Self {
        let version = proto::account_file::account_file::Version::V1(file.into());
        Self { version: Some(version) }
    }
}

impl From<AccountFile> for proto::account_file::AccountFile {
    fn from(file: AccountFile) -> Self {
        Self::from(&file)
    }
}

impl From<&AccountFile> for proto::account_file::AccountFileV1 {
    fn from(file: &AccountFile) -> Self {
        Self {
            account: Some(file.account().into()),
            auth_secret_keys: file.auth_secret_keys().iter().map(Into::into).collect(),
        }
    }
}
