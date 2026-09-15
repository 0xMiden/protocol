use core::cell::Cell;
use core::error::Error;
use core::num::TryFromIntError;
use std::collections::BTreeMap;

use miden_protobuf::{BuildUnchecked, MapField, OptionalField, RepeatedField};

// Deliberately has no Verify implementation: construction must remain a separate capability.
struct Unchecked<'a> {
    value: u32,
    calls: &'a Cell<usize>,
}

impl BuildUnchecked for Unchecked<'_> {
    type Output = u8;
    type Error = TryFromIntError;

    fn build_unchecked(self) -> Result<u8, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        self.value.try_into()
    }
}

#[test]
fn unchecked_collection_builds_preserve_presence_order_duplicates_and_keys() {
    let calls = Cell::new(0);
    let entry = |value| Unchecked { value, calls: &calls };
    assert!(
        OptionalField::new("optional", None::<Unchecked<'_>>)
            .build_unchecked()
            .unwrap()
            .is_none()
    );
    assert!(
        RepeatedField::new("values", Vec::<Unchecked<'_>>::new())
            .build_unchecked()
            .unwrap()
            .is_empty()
    );
    assert_eq!(calls.get(), 0);
    assert_eq!(
        OptionalField::new("optional", Some(entry(7))).build_unchecked().unwrap(),
        Some(7)
    );
    let values = RepeatedField::new("values", vec![entry(3), entry(1), entry(3)])
        .build_unchecked()
        .unwrap();
    assert_eq!(values, [3, 1, 3]);
    let map = MapField::new("map", BTreeMap::from([(-5, entry(7)), (3, entry(8))]))
        .build_unchecked()
        .unwrap();
    assert_eq!(map, BTreeMap::from([(-5, 7), (3, 8)]));
    assert_eq!(calls.get(), 6);
}

#[test]
fn unchecked_collection_builds_compose_paths_and_stop_at_the_first_failure() {
    let calls = Cell::new(0);
    let entry = |value| Unchecked { value, calls: &calls };
    let key = "rpc.\"[limits]\n";
    let values = vec![
        MapField::new("limits", BTreeMap::from([("a", entry(7))])),
        MapField::new("limits", BTreeMap::from([(key, entry(256))])),
        MapField::new("limits", BTreeMap::from([("a", entry(8))])),
    ];
    let error = OptionalField::new("request", Some(RepeatedField::new("groups", values)))
        .build_unchecked()
        .unwrap_err();
    assert_eq!(calls.get(), 2);
    assert!(
        error.to_string().starts_with(&format!("request.groups[1].limits[{key:?}]:")),
        "{error}"
    );
    assert!(error.source().unwrap().is::<TryFromIntError>());
}

#[cfg(feature = "std")]
#[test]
fn unchecked_hash_map_builds_preserve_keys_and_error_context() {
    use std::collections::HashMap;

    let calls = Cell::new(0);
    let entry = |value| Unchecked { value, calls: &calls };
    let map = MapField::new("map", HashMap::from([("rpc", entry(7))]))
        .build_unchecked()
        .unwrap();
    assert_eq!(map, HashMap::from([("rpc", 7)]));
    let error = MapField::new("map", HashMap::from([("rpc", entry(256))]))
        .build_unchecked()
        .unwrap_err();
    assert!(error.to_string().starts_with("map[\"rpc\"]:"), "{error}");
    assert!(error.source().unwrap().is::<TryFromIntError>());
}
