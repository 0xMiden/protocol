use alloc::format;

use miden_protocol::asset::Asset;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::vm::ExecutionProof;
use miden_protocol::{Felt, MastForest, Word};

use crate::{ConversionError, proto};

const FELT_SERIALIZED_SIZE: usize = size_of::<u64>();
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

impl From<Felt> for proto::primitives::Felt {
    fn from(value: Felt) -> Self {
        Self { encoded: value.to_bytes() }
    }
}

impl From<&Felt> for proto::primitives::Felt {
    fn from(value: &Felt) -> Self {
        Self { encoded: value.to_bytes() }
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
        ensure_exact_length(&value.encoded, FELT_SERIALIZED_SIZE, "felt.encoded")?;
        Self::read_from_bytes(&value.encoded)
            .map_err(|error| ConversionError::deserialization("felt.encoded", error))
    }
}

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

impl From<&PublicKey> for proto::primitives::PublicKey {
    fn from(value: &PublicKey) -> Self {
        Self { encoded: value.to_bytes() }
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
        Self::read_from_bytes(&value.encoded)
            .map_err(|error| ConversionError::deserialization("PublicKey", error))
            .map_err(|error| error.context("encoded"))
    }
}

impl From<&Signature> for proto::primitives::Signature {
    fn from(value: &Signature) -> Self {
        Self { encoded: value.to_bytes() }
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
        Self::read_from_bytes(&value.encoded)
            .map_err(|error| ConversionError::deserialization("Signature", error))
            .map_err(|error| error.context("encoded"))
    }
}

impl From<&Asset> for proto::primitives::Asset {
    fn from(value: &Asset) -> Self {
        Self {
            key: Some(value.to_id_word().into()),
            value: Some(value.to_value_word().into()),
        }
    }
}

impl From<Asset> for proto::primitives::Asset {
    fn from(value: Asset) -> Self {
        (&value).into()
    }
}

impl TryFrom<proto::primitives::Asset> for Asset {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Asset) -> Result<Self, Self::Error> {
        let key = value
            .key
            .ok_or_else(|| ConversionError::missing_field::<proto::primitives::Asset>("key"))?
            .try_into()
            .map_err(|error: ConversionError| error.context("key"))?;
        let value = value
            .value
            .ok_or_else(|| ConversionError::missing_field::<proto::primitives::Asset>("value"))?
            .try_into()
            .map_err(|error: ConversionError| error.context("value"))?;
        Asset::from_id_and_value_words(key, value).map_err(ConversionError::new)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;

    #[test]
    fn felt_and_word_roundtrip_and_reject_invalid_lengths() {
        let felt = Felt::new_unchecked(42);
        assert_eq!(Felt::try_from(proto::primitives::Felt::from(felt)).unwrap(), felt);

        let word = Word::new([felt, Felt::ZERO, Felt::ONE, Felt::new_unchecked(7)]);
        assert_eq!(Word::try_from(proto::primitives::Word::from(word)).unwrap(), word);

        let error = Felt::try_from(proto::primitives::Felt { encoded: vec![0; 7] }).unwrap_err();
        assert_eq!(error.to_string(), "felt.encoded: expected exactly 8 bytes, got 7");
    }

    #[test]
    fn execution_proof_roundtrips() {
        let proof = ExecutionProof::new_dummy();
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
