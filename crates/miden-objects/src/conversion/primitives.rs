use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;

use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::crypto::merkle::store::MerkleStore;
use miden_protocol::utils::serde::{Deserializable, DeserializationError, Serializable};
use miden_protocol::vm::{AdviceInputs, AdviceMap, AdviceStack, ExecutionProof};
use miden_protocol::{Felt, MastForest, Word};

use crate::{ConversionError, proto};

#[cfg(test)]
mod tests;

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
        value.decode_value(|value| Self::try_from(*value))
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
        value.decode_value(|encoded| {
            if encoded.len() != Word::SERIALIZED_SIZE {
                return Err(DeserializationError::InvalidValue(format!(
                    "expected exactly {} bytes, got {}",
                    Word::SERIALIZED_SIZE,
                    encoded.len()
                )));
            }
            Self::read_from_bytes(encoded)
        })
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
        value.decode_value(|encoded| Self::read_from_bytes(encoded))
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

// ADVICE INPUTS
// ================================================================================================

impl From<&AdviceStack> for proto::primitives::AdviceStack {
    fn from(value: &AdviceStack) -> Self {
        Self {
            values: value.iter().map(Into::into).collect(),
        }
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
            key: Some(proto::primitives::public_key::Key::EcdsaK256Keccak(value.to_bytes())),
        }
    }
}

impl From<PublicKey> for proto::primitives::PublicKey {
    fn from(value: PublicKey) -> Self {
        (&value).into()
    }
}

// SIGNATURE
// ================================================================================================

impl From<&Signature> for proto::primitives::Signature {
    fn from(value: &Signature) -> Self {
        Self {
            signature: Some(proto::primitives::signature::Signature::EcdsaK256Keccak(
                value.to_bytes(),
            )),
        }
    }
}

impl From<Signature> for proto::primitives::Signature {
    fn from(value: Signature) -> Self {
        (&value).into()
    }
}

// Canonical representation adapter; domain interpretation is left to the containing record.
impl crate::DecodeMessage for proto::primitives::Word {
    type Decoded = miden_protocol::Word;
}

// Canonical representation adapter; domain interpretation is left to the containing record.
impl crate::DecodeMessage for proto::primitives::Felt {
    type Decoded = miden_protocol::Felt;
}

// Canonical representation adapter; domain interpretation is left to the containing record.
impl crate::DecodeMessage for proto::primitives::ExecutionProof {
    type Decoded = miden_protocol::vm::ExecutionProof;
}
