use alloc::borrow::ToOwned;
use alloc::string::String;

use miden_core::program::proof_request_key;
use miden_processor::ExecutionError;
use miden_processor::operation::OperationError;
use miden_protocol::errors::tx_kernel::{
    ERR_EPILOGUE_INSUFFICIENT_PRECOMPILE_PROOF_SECURITY,
    ERR_EPILOGUE_INVALID_PRECOMPILE_HANDLING,
};
use miden_protocol::transaction::memory::MINIMUM_PROOF_SECURITY_BITS_PTR;
use miden_protocol::vm::AdviceInputs;
use miden_protocol::{CoreLibrary, Felt, Word};

use super::ExecutionOutputExt;
use crate::{Auth, MockChain, assert_execution_error};

// Unused root-context memory, outside the authenticated configuration and account sections.
const SETTLED_ROOT_PTR: u32 = 2300;

/// The host's deferred response leaves the same root and witness available for later proving.
/// Non-boolean responses must fail before any proof request or clearing.
#[tokio::test]
async fn epilogue_validates_precompile_handling_and_preserves_deferred_work() -> anyhow::Result<()>
{
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let chain = builder.build()?;
    let transaction = chain.build_transaction(account.id()).build()?;
    let code = settlement_program(1, "exec.epilogue::finalize_transaction");

    let output = transaction
        .execute_code_with_precompile_handling_response(&code, Felt::ZERO)
        .await?;
    let deferred_root = output.get_kernel_mem_word(SETTLED_ROOT_PTR);
    assert_ne!(deferred_root, Word::empty());
    assert_eq!(output.precompile_root, deferred_root);
    assert!(output.precompile_witness.is_some());
    assert!(!output.advice.map().contains_key(&proof_request_key(
        CoreLibrary::default().pvm_recursive_verifier_root(),
        deferred_root,
    )));

    assert_execution_error!(
        transaction
            .execute_code_with_precompile_handling_response(&code, Felt::from(2u32))
            .await,
        ERR_EPILOGUE_INVALID_PRECOMPILE_HANDLING,
    );
    // Responses outside the u32 range fail at the preceding `u32assert` with the same code.
    assert_execution_error!(
        transaction
            .execute_code_with_precompile_handling_response(
                &code,
                Felt::new(1u64 << 32).unwrap(),
            )
            .await,
        matches ExecutionError::OperationError {
            err: OperationError::U32AssertionFailed { err_code, .. },
            ..
        } if err_code == ERR_EPILOGUE_INVALID_PRECOMPILE_HANDLING.code()
    );

    Ok(())
}

/// Reuse one valid PVM package to ensure rejection happens in the kernel, even when the host
/// supplies a proof under the requested key without checking its statement or security policy.
#[tokio::test]
async fn cached_precompile_proof_must_match_root_and_security_policy() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let chain = builder.build()?;
    let mut transaction = chain.build_transaction(account.id()).build()?;
    let initial_args = transaction.tx_args().clone();

    let output = transaction
        .execute_code(&settlement_program(1, "exec.epilogue::finalize_transaction"))
        .await?;
    let settled_root = output.get_kernel_mem_word(SETTLED_ROOT_PTR);
    assert_ne!(settled_root, Word::empty());
    assert_eq!(output.precompile_root, Word::empty());
    assert!(output.precompile_witness.is_none());

    let verifier_root = CoreLibrary::default().pvm_recursive_verifier_root();
    let request_key = proof_request_key(verifier_root, settled_root);
    let (_, map, store) = output.advice.into_parts();
    let stream = map
        .get(&request_key)
        .expect("settlement must retain its proof package")
        .to_vec();
    let cached = AdviceInputs::from(map).with_merkle_store(store);

    // Logging the same assertion twice produces a different accumulator root. This native
    // execution exports that root without settling it or generating another PVM proof.
    let other = transaction.execute_code(&settlement_program(2, "")).await?;
    let other_root = other.precompile_root;
    assert_ne!(other_root, settled_root);
    assert_ne!(other_root, Word::empty());

    enum Rejection {
        DifferentRoot,
        CorruptedProof,
        InsufficientSecurity,
    }

    for case in [
        Rejection::DifferentRoot,
        Rejection::CorruptedProof,
        Rejection::InsufficientSecurity,
    ] {
        let mut args = initial_args.clone();
        args.extend_advice_inputs(cached.clone());
        let (repetitions, tail) = match case {
            Rejection::DifferentRoot => {
                args.extend_advice_map([(
                    proof_request_key(verifier_root, other_root),
                    stream.clone(),
                )]);
                (2, "exec.epilogue::finalize_transaction".to_owned())
            },
            Rejection::CorruptedProof => {
                let mut corrupted = stream.clone();
                corrupted[0] += Felt::ONE;
                args.extend_advice_map([(request_key, corrupted)]);
                (1, "exec.epilogue::finalize_transaction".to_owned())
            },
            Rejection::InsufficientSecurity => {
                // A trusted test program changes only the acceptance threshold after the
                // prologue. The valid proof must fail the epilogue's security assertion.
                (
                    1,
                    format!(
                        "push.255 mem_store.{MINIMUM_PROOF_SECURITY_BITS_PTR}
                     exec.epilogue::finalize_transaction"
                    ),
                )
            },
        };
        transaction.set_tx_args(args);
        let error = transaction
            .execute_code(&settlement_program(repetitions, &tail))
            .await
            .expect_err("invalid cached settlement must fail in the kernel");
        match case {
            Rejection::InsufficientSecurity => assert!(
                ERR_EPILOGUE_INSUFFICIENT_PRECOMPILE_PROOF_SECURITY
                    .matches_execution_error(error.as_execution_error()),
                "unexpected security-policy error: {error}",
            ),
            Rejection::DifferentRoot | Rejection::CorruptedProof => assert!(
                matches!(
                    error.as_execution_error(),
                    ExecutionError::OperationError { .. } | ExecutionError::AdviceError { .. }
                ),
                "invalid cached proof must reach MASM verification: {error}",
            ),
        }
    }

    Ok(())
}

fn settlement_program(repetitions: u32, tail: &str) -> String {
    format!(
        "use miden::tx_kernel_core::prologue
         use miden::tx_kernel_core::epilogue
         use miden::core::precompiles::u256
         use miden::core::sys
         begin
             exec.prologue::prepare_transaction
             repeat.{repetitions}
                 exec.u256::push_one_digest
                 dupw exec.u256::add
                 exec.u256::push_two_digest
                 exec.u256::assert_eq
             end
             adv.push_deferred_root padw adv_loadw
             mem_storew_le.{SETTLED_ROOT_PTR} dropw
             {tail}
             exec.sys::truncate_stack
         end"
    )
}
