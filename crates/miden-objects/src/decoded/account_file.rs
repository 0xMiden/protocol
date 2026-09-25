//! Domain construction for decoded account file messages.

pub use proto::account_file::DecodedAuthSecretKey as AuthSecretKey;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

/// Returns the canonical secret key; it is not checked against any account.
impl Verify for AuthSecretKey {
    type Verified = miden_protocol::account::auth::AuthSecretKey;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use proto::account_file::auth_secret_key::DecodedKey;

        Ok(match self.key {
            DecodedKey::Falcon512Poseidon2(key) => {
                Self::Verified::Falcon512Poseidon2(key.into_inner())
            },
            DecodedKey::EcdsaK256Keccak(key) => Self::Verified::EcdsaK256Keccak(key.into_inner()),
        })
    }
}

pub use proto::account_file::DecodedAccountFile as AccountFile;

impl Verify for AccountFile {
    type Verified = crate::account_file::AccountFile;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        match self.version {
            proto::account_file::account_file::DecodedVersion::V1(file) => file.verify(),
        }
    }
}

pub use proto::account_file::DecodedAccountFileV1 as AccountFileV1;

impl Verify for AccountFileV1 {
    type Verified = crate::account_file::AccountFile;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(
            self.account.verify()?,
            self.auth_secret_keys.verify_infallible(),
        ))
    }
}
