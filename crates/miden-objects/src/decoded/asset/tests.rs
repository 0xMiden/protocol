use alloc::string::ToString;
use core::error::Error;

use assert_matches::assert_matches;
use miden_protocol::asset::{AssetComposition as ProtocolAssetComposition, FungibleAsset};
use miden_protocol::errors::AssetError;
use miden_protocol::{Felt, Word};

use crate::{ConversionError, DecodeMessage, Verify, proto};

#[test]
fn asset_class_verifies() {
    let decoded = proto::asset::AssetClass {
        suffix: Some(miden_protocol::Felt::ONE.into()),
        prefix: Some(miden_protocol::Felt::ZERO.into()),
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.verify().unwrap().suffix(), miden_protocol::Felt::ONE);
}

#[test]
fn asset_id_composition_payloads_preserve_the_asset_class() {
    use miden_protocol::asset::{AssetClass, AssetComposition, AssetId, FungibleAsset};
    use proto::asset::asset_id::DecodedComposition;

    let faucet_id = FungibleAsset::mock_issuer();
    let nonzero_class =
        AssetClass::new(miden_protocol::Felt::ONE, miden_protocol::Felt::from(2_u32));
    for id in [
        AssetId::new_fungible(faucet_id),
        AssetId::new(AssetClass::default(), faucet_id, AssetComposition::None).unwrap(),
        AssetId::new(nonzero_class, faucet_id, AssetComposition::None).unwrap(),
    ] {
        let decoded = proto::asset::AssetId::from(id).decode_fields().unwrap();
        assert_eq!(decoded.version, proto::asset::AssetVersion::V1);
        match &decoded.composition {
            DecodedComposition::Fungible(()) => assert!(id.asset_class().is_empty()),
            DecodedComposition::NonFungible(class) => {
                assert_eq!(class.suffix, id.asset_class().suffix());
                assert_eq!(class.prefix, id.asset_class().prefix());
            },
            DecodedComposition::Custom(_) => panic!("unexpected custom composition"),
        }
        assert_eq!(decoded.verify().unwrap(), id);
    }
}

#[test]
fn structured_asset_conversion_rejects_custom_composition_after_decoding() {
    let asset_class = proto::asset::AssetClass {
        suffix: Some(Felt::ZERO.into()),
        prefix: Some(Felt::ZERO.into()),
    };
    let faucet_id = Some(FungibleAsset::mock_issuer().into());

    let custom = proto::asset::AssetId {
        version: proto::asset::AssetVersion::V1 as i32,
        composition: Some(proto::asset::asset_id::Composition::Custom(asset_class)),
        faucet_id,
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new)
    .unwrap_err();
    assert_matches!(
        custom
            .source()
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<AssetError>()),
        Some(AssetError::UnsupportedAssetComposition(ProtocolAssetComposition::Custom))
    );
}

#[test]
fn structured_asset_conversion_rejects_invalid_fungible_values() {
    let error = proto::asset::Asset {
        asset_id: Some(proto::asset::AssetId {
            version: proto::asset::AssetVersion::V1 as i32,
            composition: Some(proto::asset::asset_id::Composition::Fungible(())),
            faucet_id: Some(FungibleAsset::mock_issuer().into()),
        }),
        value: Some(Word::from([1_u32, 1, 0, 0]).into()),
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new)
    .unwrap_err();

    assert_matches!(
        error
            .source()
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<AssetError>()),
        Some(AssetError::FungibleAssetValueMostSignificantElementsMustBeZero(_))
    );
}

#[test]
fn asset_id_protobuf_rejects_unspecified_version_after_decoding() {
    let error = proto::asset::AssetId {
        version: proto::asset::AssetVersion::Unspecified as i32,
        composition: Some(proto::asset::asset_id::Composition::Fungible(())),
        faucet_id: Some(FungibleAsset::mock_issuer().into()),
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new)
    .unwrap_err();

    assert_eq!(error.to_string(), "asset id version is unspecified");
}
