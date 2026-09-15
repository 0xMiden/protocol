#![no_std]
extern crate alloc;

include!(concat!(env!("OUT_DIR"), "/example.rs"));

#[derive(Clone, PartialEq, prost::Message, wire_codec::ProtoDecodeValue)]
pub struct Value {
    #[prost(uint32, tag = "1")]
    pub value: u32,
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use alloc::vec;

    use wire_codec::DecodeMessage;

    use super::*;

    fn valid() -> Container {
        let child = Child { leaf: Some(Leaf {}) };
        Container {
            implicit: Some(child.clone()),
            explicit: None,
            children: vec![],
            selection: Some(container::Selection::ChoiceValue(child)),
        }
    }

    #[test]
    fn records_and_oneofs_decode() {
        let decoded = valid().decode_fields().unwrap();
        assert!(decoded.explicit.as_ref().is_none());
        assert!(matches!(decoded.selection, container::DecodedSelection::ChoiceValue(_)));
    }

    #[test]
    fn generated_oneof_accessors_extract_decoded_payloads_without_std() {
        use container::Selection;
        use container::detail_request::StorageRequest;
        use recursive_choice::Kind;

        let wire = Selection::ChoiceValue(Child { leaf: Some(Leaf {}) });
        let _: DecodedChild = wire.clone().into_choice_value().unwrap();
        let _: DecodedChild = wire.decode_fields().unwrap().into_choice_value().unwrap();
        assert_eq!(StorageRequest::Slot(7).into_slot().unwrap(), 7);
        let error = StorageRequest::All(Child::default()).into_slot().unwrap_err();
        assert_eq!(error.to_string(), "all: expected oneof variant `slot`, got `all`");
        let error = StorageRequest::All(Child::default()).into_all().unwrap_err();
        assert!(error.to_string().starts_with("all.leaf:"), "{error}");
        let error = StorageRequest::Slot(7).decode_fields().unwrap().into_all().unwrap_err();
        assert_eq!(error.to_string(), "slot: expected oneof variant `all`, got `slot`");

        let wire = Kind::Branch(Box::new(RecursiveChoice { kind: Some(Kind::Leaf(Leaf {})) }));
        let branch: Box<DecodedRecursiveChoice> = wire.into_branch().unwrap();
        let _: DecodedLeaf = branch.kind.into_leaf().unwrap();
    }

    #[test]
    fn prost_generated_recursive_boxes_decode_without_std() {
        use recursive_choice::{DecodedKind, Kind};

        let wire = Recursive {
            leaf: Some(Leaf {}),
            next: Some(Box::new(Recursive { leaf: Some(Leaf {}), next: None })),
        };
        let decoded = wire.clone().decode_fields().unwrap();
        let next: Box<DecodedRecursive> = decoded.next.into_inner().unwrap();
        assert!(next.next.as_ref().is_none());
        let mut invalid = wire;
        invalid.next.as_mut().unwrap().leaf = None;
        let error = invalid.decode_fields().unwrap_err();
        assert!(error.to_string().starts_with("next.leaf:"), "{error}");

        let wire = RecursiveChoice {
            kind: Some(Kind::Branch(Box::new(RecursiveChoice { kind: Some(Kind::Leaf(Leaf {})) }))),
        };
        let decoded = wire.decode_fields().unwrap();
        let DecodedKind::Branch(branch) = decoded.kind else {
            panic!("wrong variant")
        };
        let nested: Box<DecodedRecursiveChoice> = branch;
        assert!(matches!(nested.kind, DecodedKind::Leaf(_)));
        let error = RecursiveChoice {
            kind: Some(Kind::Branch(Box::new(RecursiveChoice { kind: None }))),
        }
        .decode_fields()
        .unwrap_err();
        assert!(error.to_string().starts_with("kind.branch.kind:"), "{error}");
    }

    #[test]
    fn configured_optional_oneofs_preserve_absence_and_decode_present_payloads() {
        use container::DetailRequest;
        use container::detail_request::{DecodedStorageRequest, StorageRequest};
        use prost::Message;

        for storage_request in [
            None,
            Some(StorageRequest::All(Child { leaf: Some(Leaf {}) })),
            Some(StorageRequest::Slot(0)),
        ] {
            let wire = DetailRequest { storage_request: storage_request.clone() };
            let decoded = DetailRequest::decode(wire.encode_to_vec().as_slice())
                .unwrap()
                .decode_fields()
                .unwrap();
            match (storage_request, decoded.storage_request.into_inner()) {
                (None, None)
                | (Some(StorageRequest::All(_)), Some(DecodedStorageRequest::All(_)))
                | (Some(StorageRequest::Slot(0)), Some(DecodedStorageRequest::Slot(0))) => {},
                _ => panic!("oneof presence or payload changed"),
            }
        }

        let error = DetailRequest {
            storage_request: Some(StorageRequest::All(Child::default())),
        }
        .decode_fields()
        .unwrap_err();
        assert!(error.to_string().starts_with("storage_request.all.leaf:"), "{error}");

        let mut required = valid();
        required.selection = None;
        let error = required.decode_fields().unwrap_err();
        assert!(error.to_string().starts_with("selection:"), "{error}");
    }

    #[test]
    fn required_optional_repeated_and_oneof_paths_are_generated() {
        for (field, path) in [
            ("implicit", "implicit"),
            ("explicit", "explicit.leaf"),
            ("selection", "selection.choice_value.leaf"),
            ("children", "children[1].leaf"),
        ] {
            let mut message = valid();
            match field {
                "implicit" => message.implicit = None,
                "explicit" => message.explicit = Some(Child::default()),
                "selection" => {
                    message.selection = Some(container::Selection::ChoiceValue(Child::default()))
                },
                "children" => {
                    message.children = vec![Child { leaf: Some(Leaf {}) }, Child::default()]
                },
                _ => unreachable!(),
            }
            let error = message.decode_fields().unwrap_err();
            assert_eq!(error.to_string().split(": ").next(), Some(path));
        }
    }

    #[test]
    fn payload_helpers_report_field_errors() {
        let error = Value { value: 256 }.decode_value(|value| u8::try_from(*value)).unwrap_err();
        assert!(error.to_string().starts_with("value: "));
    }

    #[test]
    fn generated_maps_decode_values_and_preserve_nested_keys() {
        use prost::Message;

        let wire = MappedGroups {
            values: [(
                "rpc".into(),
                MappedChildren {
                    values: [("limits".into(), Child { leaf: Some(Leaf {}) })].into(),
                },
            )]
            .into(),
        };
        let decoded = MappedGroups::decode(wire.encode_to_vec().as_slice())
            .unwrap()
            .decode_fields()
            .unwrap();
        let _: &BTreeMap<_, DecodedMappedChildren> = decoded.values.as_ref();
        let _: &BTreeMap<_, DecodedChild> = decoded.values.as_ref()["rpc"].values.as_ref();
        assert_eq!(decoded.values.as_ref()["rpc"].values.as_ref().len(), 1);
        assert!(MappedGroups::default().decode_fields().unwrap().values.as_ref().is_empty());
        let scalars = MappedScalars { values: [("limit".into(), 10)].into() };
        assert_eq!(scalars.clone().decode_fields().unwrap().values.into_inner(), scalars.values);
        let enums = MappedEnums { values: [("kind".into(), 0)].into() }.decode_fields().unwrap();
        assert_eq!(enums.values.as_ref()["kind"], Kind::Unspecified);

        let invalid = MappedGroups {
            values: [(
                "rpc".into(),
                MappedChildren {
                    values: [("limits".into(), Child::default())].into(),
                },
            )]
            .into(),
        };
        let error = invalid.decode_fields().unwrap_err();
        assert!(
            error.to_string().starts_with("values[\"rpc\"].values[\"limits\"].leaf:"),
            "{error}"
        );
    }
}
