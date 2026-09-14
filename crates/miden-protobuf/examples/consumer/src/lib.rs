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
        assert!(decoded.explicit.is_none());
        assert!(matches!(decoded.selection, container::DecodedSelection::ChoiceValue(_)));
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
            match (storage_request, decoded.storage_request) {
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
        let _: &BTreeMap<_, DecodedMappedChildren> = &decoded.values;
        let _: &BTreeMap<_, DecodedChild> = &decoded.values["rpc"].values;
        assert_eq!(decoded.values["rpc"].values.len(), 1);
        assert!(MappedGroups::default().decode_fields().unwrap().values.is_empty());
        let scalars = MappedScalars { values: [("limit".into(), 10)].into() };
        assert_eq!(scalars.clone().decode_fields().unwrap().values, scalars.values);
        let enums = MappedEnums { values: [("kind".into(), 0)].into() }.decode_fields().unwrap();
        assert_eq!(enums.values["kind"], Kind::Unspecified);

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
