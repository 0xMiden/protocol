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

pub(crate) fn decode_advice_stack(values: Vec<Felt>) -> AdviceStack {
    values.into_iter().collect()
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

pub(crate) fn decode_advice_map(
    decoded_entries: Vec<(Word, Vec<Felt>)>,
) -> Result<AdviceMap, ConversionError> {
    let mut entries = BTreeMap::new();
    for (index, (key, values)) in decoded_entries.into_iter().enumerate() {
        if entries.insert(key, values).is_some() {
            return Err(ConversionError::message("duplicate advice map key")
                .context(format!("entries[{index}].key")));
        }
    }

    Ok(entries.into())
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

impl TryFrom<proto::primitives::MerkleStoreNode> for InnerNodeInfo {
    type Error = ConversionError;

    fn try_from(node: proto::primitives::MerkleStoreNode) -> Result<Self, Self::Error> {
        let decoder = node.decoder();
        let value = required!(decoder, node.value)?;
        let left = required!(decoder, node.left)?;
        let right = required!(decoder, node.right)?;
        Ok(Self { value, left, right })
    }
}

pub(crate) fn decode_merkle_store(
    decoded_nodes: Vec<InnerNodeInfo>,
) -> Result<MerkleStore, ConversionError> {
    let mut nodes = BTreeMap::new();
    for (index, node) in decoded_nodes.into_iter().enumerate() {
        if nodes.insert(node.value, (node.left, node.right)).is_some() {
            return Err(ConversionError::message("duplicate Merkle store parent")
                .context(format!("nodes[{index}].value")));
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

impl From<&AdviceInputs> for proto::primitives::AdviceInputs {
    fn from(value: &AdviceInputs) -> Self {
        Self {
            advice_stack: Some((&value.stack()).into()),
            advice_map: Some(value.map().into()),
            merkle_store: Some(value.store().into()),
        }
    }
}

// PUBLIC KEY
// ================================================================================================

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

pub(crate) fn decode_public_key(encoded: Vec<u8>) -> Result<PublicKey, ConversionError> {
    PublicKey::read_from_bytes(&encoded)
        .map_err(|error| ConversionError::deserialization("PublicKey", error))
}

impl TryFrom<&proto::primitives::PublicKey> for PublicKey {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::PublicKey) -> Result<Self, Self::Error> {
        value.clone().try_into()
    }
}

// SIGNATURE
// ================================================================================================

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

pub(crate) fn decode_signature(encoded: Vec<u8>) -> Result<Signature, ConversionError> {
    Signature::read_from_bytes(&encoded)
        .map_err(|error| ConversionError::deserialization("Signature", error))
}

impl TryFrom<&proto::primitives::Signature> for Signature {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::Signature) -> Result<Self, Self::Error> {
        value.clone().try_into()
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;
    use core::error::Error;

    use assert_matches::assert_matches;
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
        assert_matches!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<<Felt as TryFrom<u64>>::Error>()),
            Some(source) if source.as_u64() == Felt::ORDER
        );
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
        assert_matches!(
            public_key_error
                .source()
                .and_then(Error::source)
                .and_then(|source| source.downcast_ref::<DeserializationError>()),
            Some(DeserializationError::UnexpectedEOF)
        );

        let signature_error = Signature::try_from(proto::primitives::Signature {
            variant: proto::primitives::SignatureVariant::EcdsaK256Keccak as i32,
            encoded: vec![],
        })
        .unwrap_err();
        assert_matches!(
            signature_error
                .source()
                .and_then(Error::source)
                .and_then(|source| source.downcast_ref::<DeserializationError>()),
            Some(DeserializationError::UnexpectedEOF)
        );
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
        assert_eq!(public_key_error.to_string(), "variant: unknown enumeration value 2147483647");

        let signature_error = Signature::try_from(proto::primitives::Signature {
            variant: i32::MAX,
            encoded: vec![],
        })
        .unwrap_err();
        assert_eq!(signature_error.to_string(), "variant: unknown enumeration value 2147483647");
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
