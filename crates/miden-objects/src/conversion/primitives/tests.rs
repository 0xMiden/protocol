use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::error::Error;

use assert_matches::assert_matches;
use miden_protocol::crypto::merkle::InnerNodeInfo;
use miden_protocol::crypto::merkle::store::MerkleStore;
use miden_protocol::testing::dummy_execution_proof;
use miden_protocol::testing::random_secret_key::random_secret_key;
use miden_protocol::utils::serde::{DeserializationError, Serializable};
use miden_protocol::vm::{AdviceInputs, ExecutionProof};
use miden_protocol::{Felt, MastForest, Word};

use crate::test_utils::dummy_word;
use crate::{DecodeMessage, Verify, proto};

#[test]
fn word_atomic_decode() {
    assert_eq!(
        proto::primitives::Word::from(Word::empty()).decode_fields().unwrap(),
        Word::empty()
    );
}

#[test]
fn felt_atomic_decode() {
    assert!(
        proto::primitives::Felt { value: miden_protocol::Felt::ORDER }
            .decode_fields()
            .is_err()
    );
}

#[test]
fn execution_proof_atomic_decode() {
    let proof = miden_protocol::testing::dummy_execution_proof();
    assert_eq!(proto::primitives::ExecutionProof::from(&proof).decode_fields().unwrap(), proof);
}

#[test]
fn advice_inputs_roundtrip_preserves_stack_order_and_normalizes_map_order() {
    let mut store = MerkleStore::new();
    store.extend([InnerNodeInfo {
        value: dummy_word(9),
        left: dummy_word(10),
        right: dummy_word(11),
    }]);
    let advice_inputs = AdviceInputs::default()
        .with_stack({
            let mut stack = AdviceInputs::default().stack();
            stack.append_elements([Felt::from(1_u32), Felt::from(2_u32)]);
            stack
        })
        .with_map([
            (dummy_word(7), vec![Felt::from(3_u32)]),
            (dummy_word(5), vec![Felt::from(4_u32)]),
        ])
        .with_merkle_store(store);

    let message = proto::primitives::AdviceInputs::from(&advice_inputs);

    assert_eq!(
        message.advice_stack.as_ref().unwrap().values,
        vec![Felt::from(1_u32).into(), Felt::from(2_u32).into()]
    );
    assert_eq!(
        message
            .advice_map
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .map(|entry| Word::try_from(entry.key.clone().unwrap()).unwrap())
            .collect::<Vec<_>>(),
        vec![dummy_word(5), dummy_word(7)]
    );
    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), advice_inputs);
}

#[test]
fn merkle_store_omits_identical_defaults_and_retains_default_parent_overrides() {
    let default_store = MerkleStore::new();
    let default_node = default_store.inner_nodes().next().unwrap();
    let mut store = MerkleStore::new();
    let override_node = InnerNodeInfo {
        value: default_node.value,
        left: dummy_word(12),
        right: default_node.right,
    };
    let custom_node = InnerNodeInfo {
        value: dummy_word(9),
        left: dummy_word(10),
        right: dummy_word(11),
    };
    store.extend([override_node.clone(), custom_node.clone()]);

    let default_message = proto::primitives::MerkleStore::from(&default_store);
    let override_message = proto::primitives::MerkleStore::from(&store);

    assert!(default_message.nodes.is_empty());
    assert_eq!(override_message.nodes.len(), 2);
    assert!(
        Word::try_from(override_message.nodes[0].value.clone().unwrap()).unwrap()
            < Word::try_from(override_message.nodes[1].value.clone().unwrap()).unwrap()
    );
    assert_eq!(default_message.decode_fields().unwrap().verify().unwrap(), default_store);
    assert_eq!(override_message.decode_fields().unwrap().verify().unwrap(), store);
}

#[test]
fn invalid_word_lengths_and_contents_use_the_same_generated_path() {
    for encoded in [vec![0; 31], vec![0; 33], vec![255; 32]] {
        let word = proto::primitives::Word { encoded };
        let borrowed_error = Word::try_from(&word).unwrap_err();
        let error = word.clone().decode_fields().unwrap_err();
        assert_eq!(borrowed_error.to_string(), error.to_string());
        assert!(error.to_string().starts_with("encoded: "), "{error}");
        assert!(error.source().unwrap().is::<DeserializationError>());
    }
}

#[test]
fn felt_paths_include_only_schema_fields() {
    let felt = proto::primitives::Felt { value: Felt::ORDER };
    let borrowed_error = Felt::try_from(&felt).unwrap_err();
    let error = felt.decode_fields().unwrap_err();
    assert_eq!(borrowed_error.to_string(), error.to_string());
    assert!(error.to_string().starts_with("value: "), "{error}");
    assert!(error.source().unwrap().is::<<Felt as TryFrom<u64>>::Error>());
}

#[test]
fn proof_paths_preserve_the_deserialization_source() {
    use miden_protocol::vm::ExecutionProof;

    let proof = proto::primitives::ExecutionProof { encoded: vec![] };
    let borrowed_error = ExecutionProof::try_from(&proof).unwrap_err();
    let error = proof.decode_fields().unwrap_err();
    assert_eq!(borrowed_error.to_string(), error.to_string());
    assert!(error.to_string().starts_with("encoded: "), "{error}");
    assert!(error.source().unwrap().is::<DeserializationError>());
}

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
    assert!(error.to_string().starts_with("encoded: "), "{error}");
    assert!(error.to_string().contains("expected exactly 32 bytes, got 31"), "{error}");
}

#[test]
fn public_key_and_signature_roundtrip_with_ecdsa_k256_keccak_variants() {
    let signing_key = random_secret_key();
    let public_key = signing_key.public_key();
    let signature = signing_key.sign(Word::empty());

    let encoded_public_key = proto::primitives::PublicKey::from(&public_key);
    assert_eq!(encoded_public_key.decode_fields().unwrap().verify().unwrap(), public_key);

    let encoded_signature = proto::primitives::Signature::from(&signature);
    assert_eq!(encoded_signature.decode_fields().unwrap().verify().unwrap(), signature);
}

#[test]
fn execution_proof_roundtrips() {
    let proof = dummy_execution_proof();
    let encoded = proto::primitives::ExecutionProof::from(&proof);
    assert_eq!(ExecutionProof::try_from(encoded).unwrap(), proof);
}

#[test]
fn execution_proof_rejects_unversioned_wire_bytes() {
    let proof = dummy_execution_proof();
    let compatibility = proof.compatibility();
    let compatibility_len = 1
        + compatibility.vm_verifier_roots().to_vec().to_bytes().len()
        + compatibility.pvm_verifier_roots().to_vec().to_bytes().len();
    let unversioned = proof.to_bytes()[compatibility_len..].to_vec();

    let error =
        ExecutionProof::try_from(proto::primitives::ExecutionProof { encoded: unversioned })
            .unwrap_err();

    assert!(error.to_string().starts_with("encoded:"));
}

#[test]
fn mast_forest_roundtrips() {
    let mast = MastForest::new();
    let encoded = proto::primitives::MastForest::from(&mast);
    assert_eq!(encoded.decode_fields().unwrap().verify().unwrap(), mast);
}
