use assert_matches::assert_matches;
use miden_protocol::asset::{FungibleAsset, NonFungibleAsset};
use prost::Message;

use crate::{DecodeMessage, Verify, proto};

#[test]
fn fungible_asset_roundtrips_through_structured_protobuf() {
    let asset = FungibleAsset::mock(42);

    let encoded = proto::asset::Asset::from(asset);

    assert_eq!(
        encoded.asset_id.as_ref().unwrap().version,
        proto::asset::AssetVersion::V1 as i32
    );
    assert_matches!(
        encoded.asset_id.as_ref().unwrap().composition,
        Some(proto::asset::asset_id::Composition::Fungible(()))
    );
    let encoded = proto::asset::Asset::decode(encoded.encode_to_vec().as_slice()).unwrap();
    assert_eq!(encoded.decode_fields().unwrap().verify().unwrap(), asset);
}

#[test]
fn non_fungible_asset_roundtrips_through_structured_protobuf() {
    let asset = NonFungibleAsset::mock(&[1, 2, 3]);

    let encoded = proto::asset::Asset::from(asset);

    assert_matches!(
        encoded.asset_id.as_ref().unwrap().composition,
        Some(proto::asset::asset_id::Composition::NonFungible(_))
    );
    let encoded = proto::asset::Asset::decode(encoded.encode_to_vec().as_slice()).unwrap();
    assert_eq!(encoded.decode_fields().unwrap().verify().unwrap(), asset);
}
