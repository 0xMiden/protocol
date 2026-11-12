use alloc::vec::Vec;

use miden_core::program::proof_request_key;
use miden_core_lib::PVM_PROOF_REQUEST_EVENT_NAME;
use miden_processor::ProcessorState;
use miden_processor::advice::AdviceMutation;
use miden_protocol::transaction::TransactionEventId;
use miden_protocol::vm::{AdviceInputs, EventName};
use miden_protocol::{CoreLibrary, Felt, Word};

use crate::{PrecompileHandling, TransactionKernelError};

pub(crate) static PROOF_REQUEST_EVENT_NAME: EventName = PVM_PROOF_REQUEST_EVENT_NAME;

pub(crate) fn is_proof_request(process: &ProcessorState) -> bool {
    process.get_stack_item(0) == PROOF_REQUEST_EVENT_NAME.to_event_id().as_felt()
}

pub(crate) fn is_handling_request(process: &ProcessorState) -> bool {
    process.get_stack_item(0) == TransactionEventId::EpiloguePrecompileHandling.event_id().as_felt()
}

/// Supplies the selected mode as untrusted advice. The kernel validates its encoding and applies
/// the corresponding branch; proof acceptance remains the verifier's responsibility.
pub(crate) fn handle_handling_request(
    process: &ProcessorState,
    handling: PrecompileHandling,
) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
    if !process.ctx().is_root() {
        return Err(TransactionKernelError::other(
            "precompile handling requests must originate in the transaction kernel context",
        ));
    }
    Ok(vec![AdviceMutation::extend_advice_stack_with([Felt::from(handling as u8)])])
}

/// Supplies an untrusted PVM proof package for the root selected by the epilogue.
///
/// Preloaded packages are reused. Execution retains newly generated packages, including their
/// Merkle nodes, so proving can replay them. A prover given inputs directly may also generate a
/// missing package. The epilogue verifies the supplied proof and its security before clearing.
pub(crate) fn handle_proof_request(
    process: &ProcessorState,
    save_generated: Option<&mut AdviceInputs>,
) -> Result<Vec<AdviceMutation>, TransactionKernelError> {
    if !process.ctx().is_root() {
        return Err(TransactionKernelError::other(
            "precompile proof requests must originate in the transaction kernel context",
        ));
    }
    let verifier_root = process.get_stack_word(1);
    if verifier_root != CoreLibrary::default().pvm_recursive_verifier_root() {
        return Err(TransactionKernelError::other(
            "precompile proof request does not use the linked PVM verifier",
        ));
    }
    let root = process.get_stack_word(5);
    if process
        .advice_provider()
        .map()
        .contains_key(&proof_request_key(verifier_root, root))
    {
        return Ok(Vec::new());
    }

    let advice = generate_proof_package(process, verifier_root, root)?;
    if let Some(saved) = save_generated {
        saved.extend(advice.clone());
    }
    let (_, map, store) = advice.into_parts();
    Ok(vec![
        AdviceMutation::extend_map(map),
        AdviceMutation::extend_merkle_store(store.inner_nodes()),
    ])
}

#[cfg(feature = "std")]
fn generate_proof_package(
    process: &ProcessorState,
    verifier_root: Word,
    root: Word,
) -> Result<AdviceInputs, TransactionKernelError> {
    use miden_precompiles_stark::recursive::PvmRecursiveVerifierInputs;
    use miden_processor::PrecompileWitness;
    use miden_protocol::utils::serde::Deserializable;
    use miden_prover::{HashFunction, Prover};

    let values = process.advice_provider().map().get(&root).ok_or_else(|| {
        TransactionKernelError::other(
            "the epilogue did not export the requested precompile witness",
        )
    })?;
    let bytes =
        decode_exported_witness(values, process.execution_options().max_advice_size_bytes())?;
    let witness = PrecompileWitness::read_from_bytes(&bytes).map_err(|source| {
        TransactionKernelError::other_with_source("invalid exported precompile witness", source)
    })?;
    let proof = Prover::new()
        .with_hash_fn(HashFunction::Eidos)
        .with_verification_precompile_limits(
            process.execution_options().verification_precompile_limits().clone(),
        )
        .prove_precompiles(vec![witness])
        .map_err(|source| {
            TransactionKernelError::other_with_source("local precompile proving failed", source)
        })?;
    let package =
        PvmRecursiveVerifierInputs::for_request(verifier_root, &proof).map_err(|source| {
            TransactionKernelError::other_with_source(
                "failed to prepare precompile verifier advice",
                source,
            )
        })?;
    if package.claim_commitment() != root {
        return Err(TransactionKernelError::other("precompile proof has an unexpected root"));
    }
    Ok(package.into_parts().0)
}

#[cfg(not(feature = "std"))]
fn generate_proof_package(
    _process: &ProcessorState,
    _verifier_root: Word,
    _root: Word,
) -> Result<AdviceInputs, TransactionKernelError> {
    Err(TransactionKernelError::other(
        "local precompile proof generation requires std; supply a proof package in transaction advice",
    ))
}

/// Decodes the system export's `[byte_length, packed_u32_le_bytes...]` value.
#[cfg(feature = "std")]
fn decode_exported_witness(
    values: &[miden_protocol::Felt],
    max_bytes: usize,
) -> Result<Vec<u8>, TransactionKernelError> {
    let malformed = || TransactionKernelError::other("malformed exported precompile witness bytes");
    let (length, packed) = values.split_first().ok_or_else(malformed)?;
    let length = usize::try_from(length.as_canonical_u64()).map_err(|_| malformed())?;
    if length > max_bytes || packed.len() != length.checked_add(3).ok_or_else(malformed)? / 4 {
        return Err(malformed());
    }

    let mut bytes = Vec::with_capacity(length);
    for value in packed {
        let limb = u32::try_from(value.as_canonical_u64()).map_err(|_| malformed())?;
        let limb_bytes = limb.to_le_bytes();
        let used = (length - bytes.len()).min(limb_bytes.len());
        if limb_bytes[used..].iter().any(|&byte| byte != 0) {
            return Err(malformed());
        }
        bytes.extend_from_slice(&limb_bytes[..used]);
    }
    Ok(bytes)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use alloc::vec::Vec;

    use miden_protocol::Felt;

    use super::decode_exported_witness;

    #[test]
    fn exported_witness_bytes_require_exact_length_limbs_and_padding() {
        let cases = [
            (vec![], 8, None),
            (vec![0], 8, Some(vec![])),
            (vec![1, 0x42], 8, Some(vec![0x42])),
            (vec![5, 0x04030201, 0x05], 8, Some(vec![1, 2, 3, 4, 5])),
            (vec![5, 0x04030201], 8, None),
            (vec![4, 0x04030201, 0], 8, None),
            (vec![4, 1_u64 << 32], 8, None),
            (vec![1, 0x0142], 8, None),
            (vec![5, 0x04030201, 0x05], 4, None),
            (vec![1_u64 << 62], 8, None),
        ];
        for (values, max_bytes, expected) in cases {
            let values =
                values.into_iter().map(|value| Felt::new(value).unwrap()).collect::<Vec<_>>();
            let decoded = decode_exported_witness(&values, max_bytes);
            match expected {
                Some(expected) => assert_eq!(decoded.unwrap(), expected),
                None => assert!(decoded.is_err(), "accepted malformed export: {values:?}"),
            }
        }
    }
}
