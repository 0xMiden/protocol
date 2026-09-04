use miden_protocol::asset::{Asset, AssetClass, AssetComposition, AssetId};

use crate::proto;

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
