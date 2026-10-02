use core::cell::Cell;
use core::convert::Infallible;
use core::error::Error;
use core::num::TryFromIntError;
use std::collections::{BTreeMap, BTreeSet};

use miden_protobuf::{
    ConversionError,
    ConversionResultExt,
    DuplicatePolicy,
    MapField,
    OptionalField,
    RepeatedField,
    Verify,
    VerifyWith,
};

struct Entry(u32);

impl Verify for Entry {
    type Verified = u8;
    type Error = TryFromIntError;

    fn verify(self) -> Result<u8, Self::Error> {
        self.0.try_into()
    }
}

struct InfallibleEntry(u8);

impl Verify for InfallibleEntry {
    type Verified = u32;
    type Error = Infallible;

    fn verify(self) -> Result<u32, Infallible> {
        Ok(u32::from(self.0) + 1)
    }
}

#[test]
fn infallible_verification_composes_without_introducing_errors() {
    let optional: Option<u32> =
        OptionalField::new("optional", Some(InfallibleEntry(3))).verify_infallible();
    assert_eq!(optional, Some(4));
    assert!(
        OptionalField::new("optional", None::<InfallibleEntry>)
            .verify_infallible()
            .is_none()
    );
    let values: Vec<u32> = RepeatedField::new(
        "values",
        vec![InfallibleEntry(2), InfallibleEntry(1), InfallibleEntry(2)],
    )
    .verify_infallible();
    assert_eq!(values, [3, 2, 3]);
    assert!(
        RepeatedField::new("values", Vec::<InfallibleEntry>::new())
            .verify_infallible()
            .is_empty()
    );
    let map: BTreeMap<i32, u32> =
        MapField::new("map", BTreeMap::from([(-5, InfallibleEntry(7))])).verify_infallible();
    assert_eq!(map, BTreeMap::from([(-5, 8)]));

    #[cfg(feature = "std")]
    {
        use std::collections::HashMap;
        let map: HashMap<&str, u32> =
            MapField::new("map", HashMap::from([("rpc", InfallibleEntry(7))])).verify_infallible();
        assert_eq!(map, HashMap::from([("rpc", 8)]));
    }
}

// Deliberately not Clone: collections can share a borrowed context.
struct Context {
    offset: u32,
    calls: Cell<usize>,
}

impl VerifyWith<&Context> for Entry {
    type Verified = u8;
    type Error = ConversionError;

    fn verify_with(self, context: &Context) -> Result<u8, Self::Error> {
        context.calls.set(context.calls.get() + 1);
        u8::try_from(self.0 + context.offset).context("value")
    }
}

impl VerifyWith<Context> for Entry {
    type Verified = u8;
    type Error = ConversionError;

    fn verify_with(self, context: Context) -> Result<u8, Self::Error> {
        self.verify_with(&context)
    }
}

#[test]
fn verification_preserves_optional_presence_order_duplicates_and_keys() {
    assert_eq!(OptionalField::new("optional", None::<Entry>).verify().unwrap(), None);
    assert_eq!(OptionalField::new("optional", Some(Entry(7))).verify().unwrap(), Some(7));
    let values = RepeatedField::new("values", vec![Entry(3), Entry(1), Entry(3)])
        .verify()
        .unwrap();
    assert_eq!(values, [3, 1, 3]);
    assert!(RepeatedField::new("values", Vec::<Entry>::new()).verify().unwrap().is_empty());
    let map = MapField::new("map", BTreeMap::from([(-5, Entry(7)), (2, Entry(8))]))
        .verify()
        .unwrap();
    assert_eq!(map, BTreeMap::from([(-5, 7), (2, 8)]));
    assert!(MapField::new("map", BTreeMap::<i32, Entry>::new()).verify().unwrap().is_empty());
}

#[test]
fn collection_helpers_compose_paths_and_preserve_typed_sources() {
    let key = "rpc.\"[limits]\n";
    let groups = vec![
        MapField::new("limits", BTreeMap::new()),
        MapField::new("limits", BTreeMap::from([(key, Entry(256))])),
    ];
    let error = OptionalField::new("request", Some(RepeatedField::new("groups", groups)))
        .verify()
        .unwrap_err();
    assert!(
        error.to_string().starts_with(&format!("request.groups[1].limits[{key:?}]:")),
        "{error}"
    );
    assert!(error.source().unwrap().is::<TryFromIntError>());

    let context = Context { offset: 1, calls: Cell::new(0) };
    let error = MapField::new("map", BTreeMap::from([(false, Entry(255))]))
        .verify_with(&context)
        .unwrap_err();
    assert!(error.to_string().starts_with("map[false].value:"), "{error}");
    assert!(error.source().unwrap().is::<TryFromIntError>());
}

#[test]
fn contextual_verification_shares_context_and_handles_empty_collections() {
    let context = Context { offset: 1, calls: Cell::new(0) };
    assert!(
        OptionalField::new("optional", None::<Entry>)
            .verify_with(&context)
            .unwrap()
            .is_none()
    );
    assert!(
        RepeatedField::new("values", Vec::<Entry>::new())
            .verify_with(&context)
            .unwrap()
            .is_empty()
    );
    assert!(
        MapField::new("map", BTreeMap::<i32, Entry>::new())
            .verify_with(&context)
            .unwrap()
            .is_empty()
    );
    assert_eq!(context.calls.get(), 0);

    let values = RepeatedField::new("values", vec![Entry(2), Entry(1)])
        .verify_with(&context)
        .unwrap();
    assert_eq!(values, [3, 2]);
    let map = MapField::new("map", BTreeMap::from([(-5, Entry(7))]))
        .verify_with(&context)
        .unwrap();
    assert_eq!(map, BTreeMap::from([(-5, 8)]));
    assert_eq!(context.calls.get(), 3);
    // Optional values can consume a context without any Clone bound.
    assert_eq!(
        OptionalField::new("optional", Some(Entry(3))).verify_with(context).unwrap(),
        Some(4)
    );
}

#[test]
fn contextual_verification_stops_at_the_first_error() {
    let context = Context { offset: 0, calls: Cell::new(0) };
    let error = RepeatedField::new("values", vec![Entry(1), Entry(256), Entry(2)])
        .verify_with(&context)
        .unwrap_err();
    assert!(error.to_string().starts_with("values[1].value:"), "{error}");
    assert_eq!(context.calls.get(), 2);
    context.calls.set(0);
    let error =
        MapField::new("map", BTreeMap::from([(0, Entry(1)), (1, Entry(256)), (2, Entry(2))]))
            .verify_with(&context)
            .unwrap_err();
    assert!(error.to_string().starts_with("map[1].value:"), "{error}");
    assert_eq!(context.calls.get(), 2);
}

struct Candidate<'a> {
    value: u8,
    valid: bool,
    calls: &'a Cell<usize>,
}

impl Verify for Candidate<'_> {
    type Verified = u8;
    type Error = ConversionError;

    fn verify(self) -> Result<u8, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        if !self.valid {
            return Err(ConversionError::message("invalid candidate").context("value"));
        }
        Ok(self.value)
    }
}

#[test]
fn set_policies_apply_to_verified_values_and_stop_on_rejected_duplicates() {
    let calls = Cell::new(0);
    let entries = || {
        vec![
            Candidate { value: 1, valid: true, calls: &calls },
            Candidate { value: 1, valid: true, calls: &calls },
            Candidate { value: 2, valid: true, calls: &calls },
        ]
    };
    let error = RepeatedField::new("entries", entries())
        .verify_into_btree_set(DuplicatePolicy::Reject)
        .unwrap_err();
    assert_eq!(error.to_string(), "entries[1]: duplicate verified value");
    assert_eq!(calls.get(), 2);

    calls.set(0);
    let set = RepeatedField::new("entries", entries())
        .verify_into_btree_set(DuplicatePolicy::KeepFirst)
        .unwrap();
    assert_eq!(set, BTreeSet::from([1, 2]));
    assert_eq!(calls.get(), 3);
    let error = RepeatedField::new(
        "entries",
        vec![
            Candidate { value: 1, valid: true, calls: &calls },
            Candidate { value: 1, valid: false, calls: &calls },
        ],
    )
    .verify_into_btree_set(DuplicatePolicy::KeepFirst)
    .unwrap_err();
    assert_eq!(error.to_string(), "entries[1].value: invalid candidate");
}

#[test]
fn contextual_set_verification_preserves_error_paths_and_policy() {
    let context = Context { offset: 1, calls: Cell::new(0) };
    let set = RepeatedField::new("values", vec![Entry(2), Entry(1), Entry(2)])
        .verify_into_btree_set_with(&context, DuplicatePolicy::KeepFirst)
        .unwrap();
    assert_eq!(set, BTreeSet::from([2, 3]));
    assert_eq!(context.calls.get(), 3);
    let error = RepeatedField::new("values", vec![Entry(1), Entry(1), Entry(255)])
        .verify_into_btree_set_with(&context, DuplicatePolicy::Reject)
        .unwrap_err();
    assert_eq!(error.to_string(), "values[1]: duplicate verified value");
    assert_eq!(context.calls.get(), 5);
    let error = RepeatedField::new("values", vec![Entry(1), Entry(255)])
        .verify_into_btree_set_with(&context, DuplicatePolicy::KeepFirst)
        .unwrap_err();
    assert!(error.to_string().starts_with("values[1].value:"), "{error}");
    assert!(error.source().unwrap().is::<TryFromIntError>());
}

#[cfg(feature = "std")]
#[test]
fn hash_collections_preserve_keys_sources_and_set_policy() {
    use std::collections::{HashMap, HashSet};

    let context = Context { offset: 1, calls: Cell::new(0) };
    let map = MapField::new("map", HashMap::from([("rpc", Entry(7))])).verify().unwrap();
    assert_eq!(map, HashMap::from([("rpc", 7)]));
    let map = MapField::new("map", HashMap::from([(true, Entry(7))]))
        .verify_with(&context)
        .unwrap();
    assert_eq!(map, HashMap::from([(true, 8)]));
    let error = MapField::new("map", HashMap::from([("rpc", Entry(256))])).verify().unwrap_err();
    assert!(error.to_string().starts_with("map[\"rpc\"]:"), "{error}");
    assert!(error.source().unwrap().is::<TryFromIntError>());
    context.calls.set(0);
    let error = MapField::new("map", HashMap::from([(1, Entry(255)), (2, Entry(255))]))
        .verify_with(&context)
        .unwrap_err();
    assert!(error.to_string().contains("].value:"), "{error}");
    assert!(error.source().unwrap().is::<TryFromIntError>());
    assert_eq!(context.calls.get(), 1);

    for policy in [DuplicatePolicy::Reject, DuplicatePolicy::KeepFirst] {
        let result =
            RepeatedField::new("values", vec![Entry(1), Entry(1)]).verify_into_hash_set(policy);
        let contextual = RepeatedField::new("values", vec![Entry(1), Entry(1)])
            .verify_into_hash_set_with(&context, policy);
        match policy {
            DuplicatePolicy::Reject => {
                assert_eq!(result.unwrap_err().to_string(), "values[1]: duplicate verified value");
                assert_eq!(
                    contextual.unwrap_err().to_string(),
                    "values[1]: duplicate verified value"
                );
            },
            DuplicatePolicy::KeepFirst => {
                assert_eq!(result.unwrap(), HashSet::from([1]));
                assert_eq!(contextual.unwrap(), HashSet::from([2]));
            },
        }
    }
}
