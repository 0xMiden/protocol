use alloc::string::String;
use alloc::vec::Vec;

use super::super::type_registry::{SCHEMA_TYPE_REGISTRY, SchemaTypeId};
use super::super::{StorageValueName, WordValue};
use super::{FeltSchema, WordSchema};
use crate::errors::AccountComponentTemplateError;
use crate::{Felt, FieldElement, Word};

// HELPER FUNCTIONS
// ================================================================================================

pub(crate) fn parse_storage_value_with_schema(
    schema: &WordSchema,
    raw_value: &WordValue,
    slot_prefix: &StorageValueName,
) -> Result<Word, AccountComponentTemplateError> {
    let word = match (schema, raw_value) {
        (_, WordValue::FullyTyped(word)) => *word,
        (WordSchema::Simple { r#type, .. }, raw_value) => {
            parse_simple_word_value(r#type, raw_value, slot_prefix)?
        },
        (WordSchema::Composite { value }, WordValue::Elements(elements)) => {
            parse_composite_elements(value, elements, slot_prefix)?
        },
        (WordSchema::Composite { .. }, WordValue::Atomic(value)) => SCHEMA_TYPE_REGISTRY
            .try_parse_word(&SchemaTypeId::native_word(), value)
            .map_err(|err| {
                AccountComponentTemplateError::InvalidInitStorageValue(
                    slot_prefix.clone(),
                    format!("failed to parse value as `word`: {err}"),
                )
            })?,
    };

    schema.validate_word_value(slot_prefix, "value", word)?;
    Ok(word)
}

fn parse_simple_word_value(
    schema_type: &SchemaTypeId,
    raw_value: &WordValue,
    slot_prefix: &StorageValueName,
) -> Result<Word, AccountComponentTemplateError> {
    match raw_value {
        WordValue::Atomic(value) => {
            SCHEMA_TYPE_REGISTRY.try_parse_word(schema_type, value).map_err(|err| {
                AccountComponentTemplateError::InvalidInitStorageValue(
                    slot_prefix.clone(),
                    format!("failed to parse value as `{}`: {err}", schema_type),
                )
            })
        },
        WordValue::Elements(elements) => {
            let felts: Vec<Felt> = elements
                .iter()
                .map(|element| {
                    SCHEMA_TYPE_REGISTRY.try_parse_felt(&SchemaTypeId::native_felt(), element)
                })
                .collect::<Result<_, _>>()
                .map_err(|err| {
                    AccountComponentTemplateError::InvalidInitStorageValue(
                        slot_prefix.clone(),
                        format!("failed to parse value element as `felt`: {err}"),
                    )
                })?;
            let felts: [Felt; 4] = felts.try_into().expect("length is 4");
            Ok(Word::from(felts))
        },
        WordValue::FullyTyped(word) => Ok(*word),
    }
}

fn parse_composite_elements(
    schema: &[FeltSchema; 4],
    elements: &[String; 4],
    slot_prefix: &StorageValueName,
) -> Result<Word, AccountComponentTemplateError> {
    let mut felts = [Felt::ZERO; 4];
    for (index, felt_schema) in schema.iter().enumerate() {
        let felt_type = felt_schema.felt_type();
        felts[index] =
            SCHEMA_TYPE_REGISTRY
                .try_parse_felt(&felt_type, &elements[index])
                .map_err(|err| {
                    AccountComponentTemplateError::InvalidInitStorageValue(
                        slot_prefix.clone(),
                        format!("failed to parse value[{index}] as `{felt_type}`: {err}"),
                    )
                })?;
    }
    Ok(Word::from(felts))
}
