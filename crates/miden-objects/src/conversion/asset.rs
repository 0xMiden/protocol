use alloc::format;

use miden_protocol::asset::{Asset, AssetClass, AssetComposition, AssetId};

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

impl From<&AssetClass> for proto::asset::AssetClass {
    fn from(asset_class: &AssetClass) -> Self {
        Self {
            suffix: Some(asset_class.suffix().into()),
            prefix: Some(asset_class.prefix().into()),
        }
    }
}

impl From<AssetClass> for proto::asset::AssetClass {
    fn from(asset_class: AssetClass) -> Self {
        Self::from(&asset_class)
    }
}

fn decode_asset_composition(composition: i32) -> Result<AssetComposition, ConversionError> {
    match proto::asset::AssetComposition::try_from(composition) {
        Ok(proto::asset::AssetComposition::None) => Ok(AssetComposition::None),
        Ok(proto::asset::AssetComposition::Fungible) => Ok(AssetComposition::Fungible),
        Ok(proto::asset::AssetComposition::Custom) => Ok(AssetComposition::Custom),
        Ok(proto::asset::AssetComposition::Unspecified) => {
            Err(ConversionError::message("asset composition is unspecified"))
        },
        Err(error) => Err(ConversionError::with_source(
            format!("unknown asset composition {composition}"),
            error,
        )),
    }
}

fn decode_asset_version(version: i32) -> Result<(), ConversionError> {
    match proto::asset::AssetVersion::try_from(version) {
        Ok(proto::asset::AssetVersion::V1) => Ok(()),
        Ok(proto::asset::AssetVersion::Unspecified) => {
            Err(ConversionError::message("asset id version is unspecified"))
        },
        Err(error) => Err(ConversionError::with_source(
            format!("unknown asset id version {version}"),
            error,
        )),
    }
}

fn encode_asset_composition(composition: AssetComposition) -> i32 {
    match composition {
        AssetComposition::None => proto::asset::AssetComposition::None as i32,
        AssetComposition::Fungible => proto::asset::AssetComposition::Fungible as i32,
        AssetComposition::Custom => proto::asset::AssetComposition::Custom as i32,
    }
}

impl From<&AssetId> for proto::asset::AssetId {
    fn from(asset_id: &AssetId) -> Self {
        Self {
            version: proto::asset::AssetVersion::V1 as i32,
            asset_class: Some(asset_id.asset_class().into()),
            composition: encode_asset_composition(asset_id.composition()),
            faucet_id: Some(asset_id.faucet_id().into()),
        }
    }
}

impl From<AssetId> for proto::asset::AssetId {
    fn from(asset_id: AssetId) -> Self {
        Self::from(&asset_id)
    }
}

impl TryFrom<proto::asset::AssetId> for AssetId {
    type Error = ConversionError;

    fn try_from(message: proto::asset::AssetId) -> Result<Self, Self::Error> {
        decode_asset_version(message.version).context("version")?;

        let decoder = message.decoder();
        let asset_class = required!(decoder, message.asset_class)?;
        let composition = decode_asset_composition(message.composition).context("composition")?;
        let faucet_id = required!(decoder, message.faucet_id)?;

        Self::new(asset_class, faucet_id, composition).map_err(ConversionError::new)
    }
}

impl From<&Asset> for proto::asset::Asset {
    fn from(asset: &Asset) -> Self {
        Self {
            asset_id: Some(asset.id().into()),
            value: Some(asset.to_value_word().into()),
        }
    }
}

impl From<Asset> for proto::asset::Asset {
    fn from(asset: Asset) -> Self {
        Self::from(&asset)
    }
}

impl TryFrom<proto::asset::Asset> for Asset {
    type Error = ConversionError;

    fn try_from(message: proto::asset::Asset) -> Result<Self, Self::Error> {
        let decoder = message.decoder();
        let asset_id = required!(decoder, message.asset_id)?;
        let value = required!(decoder, message.value)?;

        Self::new(asset_id, value).map_err(ConversionError::new)
    }
}
