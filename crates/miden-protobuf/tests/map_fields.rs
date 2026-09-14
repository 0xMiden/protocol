use core::error::Error;
use core::num::TryFromIntError;
use std::collections::BTreeMap;

use miden_protobuf::{ConversionResultExt, MapField, OptionalField, RepeatedField};

#[test]
fn explicit_maps_preserve_shape_without_requiring_verification() {
    // These scalar values have no Verify implementation. Their meaning belongs to the caller.
    assert!(OptionalField::new("optional", None::<u32>).map(|_| panic!("absent")).is_none());
    let suffix = String::from(" ms");
    let optional = OptionalField::new("optional", Some(7)).map(move |n| (n, suffix));
    assert_eq!(optional, Some((7, String::from(" ms"))));
    let mut visits = Vec::new();
    let repeated = RepeatedField::new("values", vec![2, 1, 2]).map(|n| {
        visits.push(n);
        n + 1
    });
    assert_eq!(visits, [2, 1, 2]);
    assert_eq!(repeated, [3, 2, 3]);
    let map = MapField::new("map", BTreeMap::from([(-5, 7), (3, 2)])).map(|n| n + 1);
    assert_eq!(map, BTreeMap::from([(-5, 8), (3, 3)]));
}

#[test]
fn fallible_maps_retain_presence_paths_and_original_sources() {
    let absent = OptionalField::new("optional", None::<u32>)
        .try_map(|_| -> Result<u8, TryFromIntError> { panic!("absent") })
        .unwrap();
    assert_eq!(absent, None);
    assert_eq!(
        OptionalField::new("optional", Some(7_u32)).try_map(u8::try_from).unwrap(),
        Some(7)
    );
    let error = OptionalField::new("optional", Some(256_u32))
        .try_map(|n| u8::try_from(n).context("value"))
        .unwrap_err();
    assert!(error.to_string().starts_with("optional.value:"), "{error}");
    assert!(error.source().unwrap().is::<TryFromIntError>());

    let mut visits = Vec::new();
    let error = RepeatedField::new("asset_ids", vec![7_u32, 256, 8])
        .try_map(|n| {
            visits.push(n);
            u8::try_from(n)
        })
        .unwrap_err();
    assert_eq!(visits, [7, 256]);
    assert!(error.to_string().starts_with("asset_ids[1]:"), "{error}");
    assert!(error.source().unwrap().is::<TryFromIntError>());
}

#[test]
fn fallible_map_values_preserve_keys_and_stop_at_the_first_error() {
    let valid = MapField::new("map", BTreeMap::from([(-3, 7_u32)]))
        .try_map(u8::try_from)
        .unwrap();
    assert_eq!(valid, BTreeMap::from([(-3, 7_u8)]));
    let mut visits = Vec::new();
    let key = "b.\"[limits]\n";
    let error = MapField::new("map", BTreeMap::from([("a", 7_u32), (key, 256), ("c", 8)]))
        .try_map(|n| {
            visits.push(n);
            u8::try_from(n).context("value")
        })
        .unwrap_err();
    assert_eq!(visits, [7, 256]);
    assert!(error.to_string().starts_with(&format!("map[{key:?}].value:")), "{error}");
    assert!(error.source().unwrap().is::<TryFromIntError>());
}

#[cfg(feature = "std")]
#[test]
fn hash_map_transformations_preserve_keys_and_error_sources() {
    use std::collections::HashMap;

    let mapped = MapField::new("map", HashMap::from([("rpc", 7)])).map(|n| n + 1);
    assert_eq!(mapped, HashMap::from([("rpc", 8)]));
    let mapped = MapField::new("map", HashMap::from([("rpc", 7_u32)]))
        .try_map(u8::try_from)
        .unwrap();
    assert_eq!(mapped, HashMap::from([("rpc", 7_u8)]));
    let mut calls = 0;
    let error = MapField::new("map", HashMap::from([("rpc", 256_u32), ("sync", 256)]))
        .try_map(|n| {
            calls += 1;
            u8::try_from(n)
        })
        .unwrap_err();
    assert_eq!(calls, 1);
    assert!(
        error.to_string().starts_with("map[\"rpc\"]:")
            || error.to_string().starts_with("map[\"sync\"]:"),
        "{error}"
    );
    assert!(error.source().unwrap().is::<TryFromIntError>());
}
