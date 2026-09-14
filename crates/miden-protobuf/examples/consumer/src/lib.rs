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
}
