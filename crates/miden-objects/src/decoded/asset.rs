//! Domain construction for decoded asset messages.
use miden_protobuf::unwrap_infallible;
pub use proto::asset::DecodedAssetClass as AssetClass;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for AssetClass {
    type Verified = miden_protocol::asset::AssetClass;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(self.suffix, self.prefix))
    }
}

pub use proto::asset::DecodedAssetId as AssetId;

impl Verify for AssetId {
    type Verified = miden_protocol::asset::AssetId;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use miden_protocol::asset::AssetComposition;
        use proto::asset::asset_id::DecodedComposition;

        match self.version {
            proto::asset::AssetVersion::V1 => {},
            proto::asset::AssetVersion::Unspecified => {
                return Err(AssetIdError::UnspecifiedVersion.into());
            },
        }
        let faucet_id = self.faucet_id.verify()?;
        match self.composition {
            DecodedComposition::Fungible(()) => Ok(Self::Verified::new_fungible(faucet_id)),
            DecodedComposition::NonFungible(asset_class) => Ok(Self::Verified::new(
                unwrap_infallible(asset_class.verify()),
                faucet_id,
                AssetComposition::None,
            )?),
            DecodedComposition::Custom(asset_class) => Ok(Self::Verified::new(
                unwrap_infallible(asset_class.verify()),
                faucet_id,
                AssetComposition::Custom,
            )?),
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum AssetIdError {
    #[error("asset id version is unspecified")]
    UnspecifiedVersion,
}

pub use proto::asset::DecodedAsset as Asset;

impl Verify for Asset {
    type Verified = miden_protocol::asset::Asset;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(self.asset_id.verify()?, self.value)?)
    }
}

pub use proto::asset::DecodedAssetVault as AssetVault;

impl Verify for AssetVault {
    type Verified = miden_protocol::asset::AssetVault;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let assets = self.assets.verify()?;
        // The asset vault constructor skips an empty asset value. Reject it here for a
        // clear error.
        if let Some(asset) = assets.iter().find(|asset| asset.to_value_word().is_empty()) {
            return Err(AssetVaultEntryError::EmptyValue(asset.id()).into());
        }
        Ok(Self::Verified::new(&assets)?)
    }
}

/// An invariant of a single vault entry, distinct from the domain's `AssetVaultError`.
#[derive(Debug, thiserror::Error)]
pub enum AssetVaultEntryError {
    #[error("asset {0} has an empty value word")]
    EmptyValue(miden_protocol::asset::AssetId),
}
