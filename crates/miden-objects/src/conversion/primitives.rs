use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;

use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::merkle::InnerNodeInfo;
use miden_protocol::crypto::merkle::store::MerkleStore;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::vm::{AdviceInputs, AdviceMap, AdviceStack, ExecutionProof};
use miden_protocol::{Felt, MastForest, Word};

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

const WORD_SERIALIZED_SIZE: usize = Word::SERIALIZED_SIZE;

fn ensure_exact_length(
    encoded: &[u8],
    expected: usize,
    field: &'static str,
) -> Result<(), ConversionError> {
    if encoded.len() != expected {
        return Err(ConversionError::message(format!(
            "expected exactly {expected} bytes, got {}",
            encoded.len()
        ))
        .context(field));
    }
    Ok(())
}

// FELT
// ================================================================================================

impl From<Felt> for proto::primitives::Felt {
    fn from(value: Felt) -> Self {
        Self { value: value.as_canonical_u64() }
    }
}

impl From<&Felt> for proto::primitives::Felt {
    fn from(value: &Felt) -> Self {
        Self { value: value.as_canonical_u64() }
    }
}

impl TryFrom<proto::primitives::Felt> for Felt {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Felt) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&proto::primitives::Felt> for Felt {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::Felt) -> Result<Self, Self::Error> {
        Self::try_from(value.value).map_err(ConversionError::new).context("felt.value")
    }
}

// WORD
// ================================================================================================

impl From<Word> for proto::primitives::Word {
    fn from(value: Word) -> Self {
        Self { encoded: value.to_bytes() }
    }
}

impl From<&Word> for proto::primitives::Word {
    fn from(value: &Word) -> Self {
        Self { encoded: value.to_bytes() }
    }
}

impl TryFrom<proto::primitives::Word> for Word {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Word) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&proto::primitives::Word> for Word {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::Word) -> Result<Self, Self::Error> {
        ensure_exact_length(&value.encoded, WORD_SERIALIZED_SIZE, "word.encoded")?;
        Self::read_from_bytes(&value.encoded)
            .map_err(|error| ConversionError::deserialization("word.encoded", error))
    }
}

// EXECUTION PROOF
// ================================================================================================

impl From<&ExecutionProof> for proto::primitives::ExecutionProof {
    fn from(value: &ExecutionProof) -> Self {
        Self { encoded: value.to_bytes() }
    }
}

impl From<ExecutionProof> for proto::primitives::ExecutionProof {
    fn from(value: ExecutionProof) -> Self {
        (&value).into()
    }
}

impl TryFrom<proto::primitives::ExecutionProof> for ExecutionProof {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::ExecutionProof) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&proto::primitives::ExecutionProof> for ExecutionProof {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::ExecutionProof) -> Result<Self, Self::Error> {
        Self::read_from_bytes(&value.encoded)
            .map_err(|error| ConversionError::deserialization("ExecutionProof", error))
            .map_err(|error| error.context("encoded"))
    }
}

// MAST FOREST
// ================================================================================================

impl From<&MastForest> for proto::primitives::MastForest {
    fn from(value: &MastForest) -> Self {
        Self { encoded: value.to_bytes() }
    }
}

impl From<MastForest> for proto::primitives::MastForest {
    fn from(value: MastForest) -> Self {
        (&value).into()
    }
}

impl TryFrom<proto::primitives::MastForest> for MastForest {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::MastForest) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&proto::primitives::MastForest> for MastForest {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::MastForest) -> Result<Self, Self::Error> {
        Self::read_from_bytes(&value.encoded)
            .map_err(|error| ConversionError::deserialization("MastForest", error))
            .map_err(|error| error.context("encoded"))
    }
}

// ADVICE INPUTS
// ================================================================================================

impl From<&AdviceStack> for proto::primitives::AdviceStack {
    fn from(value: &AdviceStack) -> Self {
        Self {
            values: value.iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<proto::primitives::AdviceStack> for AdviceStack {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::AdviceStack) -> Result<Self, Self::Error> {
        value
            .values
            .into_iter()
            .enumerate()
            .map(|(index, value)| Felt::try_from(value).context(format!("values[{index}]")))
            .collect::<Result<AdviceStack, _>>()
    }
}

impl From<&AdviceMap> for proto::primitives::AdviceMap {
    fn from(value: &AdviceMap) -> Self {
        Self {
            entries: value
                .iter()
                .map(|(key, values)| proto::primitives::AdviceMapEntry {
                    key: Some(key.into()),
                    values: values.iter().map(Into::into).collect(),
                })
                .collect(),
        }
    }
}

impl TryFrom<proto::primitives::AdviceMap> for AdviceMap {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::AdviceMap) -> Result<Self, Self::Error> {
        let mut entries = BTreeMap::new();
        for (index, entry) in value.entries.into_iter().enumerate() {
            let decoder = entry.decoder();
            let entry_context = format!("entries[{index}]");
            let key = required!(decoder, entry.key).context(&entry_context)?;
            let values = entry
                .values
                .into_iter()
                .enumerate()
                .map(|(value_index, value)| {
                    Felt::try_from(value).context(format!("{entry_context}.values[{value_index}]"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if entries.insert(key, values).is_some() {
                return Err(ConversionError::message("duplicate advice map key")
                    .context(format!("{entry_context}.key")));
            }
        }

        Ok(entries.into())
    }
}

impl From<&MerkleStore> for proto::primitives::MerkleStore {
    fn from(value: &MerkleStore) -> Self {
        let default_nodes = MerkleStore::new()
            .inner_nodes()
            .map(|node| (node.value, (node.left, node.right)))
            .collect::<BTreeMap<_, _>>();
        let mut nodes = value
            .inner_nodes()
            .filter(|node| default_nodes.get(&node.value) != Some(&(node.left, node.right)))
            .collect::<Vec<_>>();
        nodes.sort_by_key(|node| node.value);

        Self {
            nodes: nodes
                .into_iter()
                .map(|node| proto::primitives::MerkleStoreNode {
                    value: Some(node.value.into()),
                    left: Some(node.left.into()),
                    right: Some(node.right.into()),
                })
                .collect(),
        }
    }
}

impl TryFrom<proto::primitives::MerkleStore> for MerkleStore {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::MerkleStore) -> Result<Self, Self::Error> {
        let mut nodes = BTreeMap::new();
        for (index, node) in value.nodes.into_iter().enumerate() {
            let decoder = node.decoder();
            let node_context = format!("nodes[{index}]");
            let parent = required!(decoder, node.value).context(&node_context)?;
            let left = required!(decoder, node.left).context(&node_context)?;
            let right = required!(decoder, node.right).context(&node_context)?;
            if nodes.insert(parent, (left, right)).is_some() {
                return Err(ConversionError::message("duplicate Merkle store parent")
                    .context(format!("{node_context}.value")));
            }
        }

        let mut store = MerkleStore::new();
        store.extend(nodes.into_iter().map(|(value, (left, right))| InnerNodeInfo {
            value,
            left,
            right,
        }));
        Ok(store)
    }
}

impl From<&AdviceInputs> for proto::primitives::AdviceInputs {
    fn from(value: &AdviceInputs) -> Self {
        Self {
            advice_stack: Some((&value.advice_stack()).into()),
            advice_map: Some((&value.map).into()),
            merkle_store: Some((&value.store).into()),
        }
    }
}

impl TryFrom<proto::primitives::AdviceInputs> for AdviceInputs {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::AdviceInputs) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let advice_stack = required!(decoder, value.advice_stack)?;
        let advice_map: AdviceMap = required!(decoder, value.advice_map)?;
        let merkle_store: MerkleStore = required!(decoder, value.merkle_store)?;

        let mut advice_inputs = AdviceInputs::default()
            .with_advice_stack(advice_stack)
            .with_merkle_store(merkle_store);
        advice_inputs.map = advice_map;
        Ok(advice_inputs)
    }
}

// PUBLIC KEY
// ================================================================================================

fn decode_public_key_variant(variant: i32) -> Result<(), ConversionError> {
    match proto::primitives::PublicKeyVariant::try_from(variant) {
        Ok(proto::primitives::PublicKeyVariant::EcdsaK256Keccak) => Ok(()),
        Ok(proto::primitives::PublicKeyVariant::Unspecified) => {
            Err(ConversionError::message("public key variant is unspecified"))
        },
        Err(error) => Err(ConversionError::with_source(
            format!("unknown public key variant {variant}"),
            error,
        )),
    }
}

impl From<&PublicKey> for proto::primitives::PublicKey {
    fn from(value: &PublicKey) -> Self {
        Self {
            variant: proto::primitives::PublicKeyVariant::EcdsaK256Keccak as i32,
            encoded: value.to_bytes(),
        }
    }
}

impl From<PublicKey> for proto::primitives::PublicKey {
    fn from(value: PublicKey) -> Self {
        (&value).into()
    }
}

impl TryFrom<proto::primitives::PublicKey> for PublicKey {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::PublicKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&proto::primitives::PublicKey> for PublicKey {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::PublicKey) -> Result<Self, Self::Error> {
        decode_public_key_variant(value.variant).context("variant")?;
        Self::read_from_bytes(&value.encoded)
            .map_err(|error| ConversionError::deserialization("PublicKey", error))
            .map_err(|error| error.context("encoded"))
    }
}

// SIGNATURE
// ================================================================================================

fn decode_signature_variant(variant: i32) -> Result<(), ConversionError> {
    match proto::primitives::SignatureVariant::try_from(variant) {
        Ok(proto::primitives::SignatureVariant::EcdsaK256Keccak) => Ok(()),
        Ok(proto::primitives::SignatureVariant::Unspecified) => {
            Err(ConversionError::message("signature variant is unspecified"))
        },
        Err(error) => Err(ConversionError::with_source(
            format!("unknown signature variant {variant}"),
            error,
        )),
    }
}

impl From<&Signature> for proto::primitives::Signature {
    fn from(value: &Signature) -> Self {
        Self {
            variant: proto::primitives::SignatureVariant::EcdsaK256Keccak as i32,
            encoded: value.to_bytes(),
        }
    }
}

impl From<Signature> for proto::primitives::Signature {
    fn from(value: Signature) -> Self {
        (&value).into()
    }
}

impl TryFrom<proto::primitives::Signature> for Signature {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Signature) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&proto::primitives::Signature> for Signature {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::Signature) -> Result<Self, Self::Error> {
        decode_signature_variant(value.variant).context("variant")?;
        Self::read_from_bytes(&value.encoded)
            .map_err(|error| ConversionError::deserialization("Signature", error))
            .map_err(|error| error.context("encoded"))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;
    use core::error::Error;

    use miden_protocol::testing::dummy_execution_proof;
    use miden_protocol::testing::random_secret_key::random_secret_key;
    use miden_protocol::utils::serde::DeserializationError;

    use super::*;

    #[test]
    fn felt_roundtrips_zero_and_rejects_the_field_order() {
        for felt in [Felt::ZERO, Felt::from(42_u32)] {
            let encoded = proto::primitives::Felt::from(felt);
            assert_eq!(encoded.value, felt.as_canonical_u64());
            assert_eq!(Felt::try_from(encoded).unwrap(), felt);
        }

        let error = Felt::try_from(proto::primitives::Felt { value: Felt::ORDER }).unwrap_err();
        assert!(matches!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<<Felt as TryFrom<u64>>::Error>()),
            Some(source) if source.as_u64() == Felt::ORDER
        ));
    }

    #[test]
    fn word_roundtrips_and_rejects_invalid_lengths() {
        let felt = Felt::from(42_u32);

        let word = Word::new([felt, Felt::ZERO, Felt::ONE, Felt::new_unchecked(7)]);
        assert_eq!(Word::try_from(proto::primitives::Word::from(word)).unwrap(), word);

        let error = Word::try_from(proto::primitives::Word { encoded: vec![0; 31] }).unwrap_err();
        assert_eq!(error.to_string(), "word.encoded: expected exactly 32 bytes, got 31");
    }

    #[test]
    fn public_key_and_signature_roundtrip_with_ecdsa_k256_keccak_variants() {
        let signing_key = random_secret_key();
        let public_key = signing_key.public_key();
        let signature = signing_key.sign(Word::empty());

        let encoded_public_key = proto::primitives::PublicKey::from(&public_key);
        assert_eq!(
            encoded_public_key.variant,
            proto::primitives::PublicKeyVariant::EcdsaK256Keccak as i32
        );
        assert_eq!(PublicKey::try_from(encoded_public_key).unwrap(), public_key);

        let encoded_signature = proto::primitives::Signature::from(&signature);
        assert_eq!(
            encoded_signature.variant,
            proto::primitives::SignatureVariant::EcdsaK256Keccak as i32
        );
        assert_eq!(Signature::try_from(encoded_signature).unwrap(), signature);
    }

    #[test]
    fn public_key_and_signature_reject_malformed_encodings() {
        let public_key_error = PublicKey::try_from(proto::primitives::PublicKey {
            variant: proto::primitives::PublicKeyVariant::EcdsaK256Keccak as i32,
            encoded: vec![],
        })
        .unwrap_err();
        assert!(matches!(
            public_key_error
                .source()
                .and_then(Error::source)
                .and_then(|source| source.downcast_ref::<DeserializationError>()),
            Some(DeserializationError::UnexpectedEOF)
        ));

        let signature_error = Signature::try_from(proto::primitives::Signature {
            variant: proto::primitives::SignatureVariant::EcdsaK256Keccak as i32,
            encoded: vec![],
        })
        .unwrap_err();
        assert!(matches!(
            signature_error
                .source()
                .and_then(Error::source)
                .and_then(|source| source.downcast_ref::<DeserializationError>()),
            Some(DeserializationError::UnexpectedEOF)
        ));
    }

    #[test]
    fn public_key_and_signature_reject_unspecified_variants_before_decoding_bytes() {
        let public_key_error =
            PublicKey::try_from(proto::primitives::PublicKey { variant: 0, encoded: vec![] })
                .unwrap_err();
        assert_eq!(public_key_error.to_string(), "variant: public key variant is unspecified");

        let signature_error =
            Signature::try_from(proto::primitives::Signature { variant: 0, encoded: vec![] })
                .unwrap_err();
        assert_eq!(signature_error.to_string(), "variant: signature variant is unspecified");
    }

    #[test]
    fn public_key_and_signature_reject_unknown_variants_before_decoding_bytes() {
        let public_key_error = PublicKey::try_from(proto::primitives::PublicKey {
            variant: i32::MAX,
            encoded: vec![],
        })
        .unwrap_err();
        assert_eq!(public_key_error.to_string(), "variant: unknown public key variant 2147483647");

        let signature_error = Signature::try_from(proto::primitives::Signature {
            variant: i32::MAX,
            encoded: vec![],
        })
        .unwrap_err();
        assert_eq!(signature_error.to_string(), "variant: unknown signature variant 2147483647");
    }

    #[test]
    fn execution_proof_roundtrips() {
        let proof = dummy_execution_proof();
        let encoded = proto::primitives::ExecutionProof::from(&proof);
        assert_eq!(ExecutionProof::try_from(encoded).unwrap(), proof);
    }

    #[test]
    fn mast_forest_roundtrips() {
        let mast = MastForest::new();
        let encoded = proto::primitives::MastForest::from(&mast);
        assert_eq!(MastForest::try_from(encoded).unwrap(), mast);
    }
}
