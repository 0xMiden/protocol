use std::iter;
use std::sync::Arc;

use miden_core::program::proof_request_key;
use miden_protocol::batch::ProposedBatch;
use miden_protocol::errors::{ProposedBatchError, TransactionVerifierError};
use miden_protocol::transaction::{TransactionKernel, TransactionVerifier};
use miden_protocol::vm::PrecompileStatus;
use miden_protocol::{CoreLibrary, MIN_PROOF_SECURITY_LEVEL, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};
use miden_tx::{LocalTransactionProver, PrecompileHandling, TransactionExecutor};
use miden_verifier::{ExecutionClaim, Verifier};
use rstest::rstest;

/// Execution and proving select their modes independently. Recursive is also the prover's
/// default when its inputs came from deferred execution; strict protocol acceptance stays closed.
#[rstest]
#[case::deferred(PrecompileHandling::Deferred, Some(PrecompileHandling::Deferred), true)]
#[case::deferred_to_default_recursive(PrecompileHandling::Deferred, None, true)]
#[case::recursive_to_deferred(
    PrecompileHandling::Recursive,
    Some(PrecompileHandling::Deferred),
    true
)]
#[case::no_work(PrecompileHandling::Deferred, Some(PrecompileHandling::Deferred), false)]
#[tokio::test]
async fn host_precompile_modes_preserve_effects_and_acceptance_policy(
    #[case] execution_mode: PrecompileHandling,
    #[case] proving_mode: Option<PrecompileHandling>,
    #[case] has_work: bool,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let auth = if has_work { Auth::basic_ecdsa() } else { Auth::IncrNonce };
    let account = builder.add_existing_wallet(auth)?;
    let chain = builder.build()?;
    let transaction = chain.build_transaction(account.id()).build()?;

    let mut executor = TransactionExecutor::new(&transaction)
        .with_precompile_handling(execution_mode)
        .with_program_executor::<miden_processor::FastProcessor>();
    if let Some(authenticator) = transaction.authenticator() {
        executor = executor.with_authenticator(authenticator);
    }
    let executed = executor
        .execute_transaction(
            account.id(),
            transaction.tx_inputs().ref_block(),
            transaction.input_notes().clone(),
            transaction.tx_args().clone(),
        )
        .await?;
    let expected_id = executed.id();
    let saved_advice = executed.tx_args().advice_inputs().clone();
    let (stack_inputs, _) = TransactionKernel::prepare_inputs(executed.tx_inputs());
    let (_, outputs, ..) = executed.clone().into_parts();
    let claim = ExecutionClaim::from_program_info(
        TransactionKernel::program_info(),
        stack_inputs,
        outputs.to_stack_outputs(),
    );

    let prover = LocalTransactionProver::default();
    let prover = match proving_mode {
        Some(mode) => prover.with_precompile_handling(mode),
        None => prover,
    };
    let proven = prover.prove(executed)?;
    assert_eq!(proven.id(), expected_id);
    let outcome = Verifier::new()
        .with_min_conjectured_security_level_per_stark(MIN_PROOF_SECURITY_LEVEL)
        .verify(&claim, proven.proof())?;
    let deferred = has_work && proving_mode == Some(PrecompileHandling::Deferred);
    if deferred {
        assert!(matches!(proven.proof().precompile(), PrecompileStatus::Deferred(_)));
        let root = proven.proof().vm().precompile_root;
        assert_ne!(root, Word::empty());
        assert_eq!(outcome.outstanding_precompile_root(), Some(root));
        let key = proof_request_key(CoreLibrary::default().pvm_recursive_verifier_root(), root);
        assert_eq!(
            saved_advice.map().contains_key(&key),
            execution_mode == PrecompileHandling::Recursive,
            "only recursive execution should have generated a cached precompile proof",
        );
        assert!(matches!(
            TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&proven),
            Err(TransactionVerifierError::TransactionProofContainsPrecompiles)
        ));
    } else {
        assert!(matches!(proven.proof().precompile(), PrecompileStatus::Empty));
        assert_eq!(proven.proof().vm().precompile_root, Word::empty());
        assert!(outcome.is_complete());
        assert!(
            TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL)
                .verify(&proven)?
                .is_complete()
        );
    }

    let (reference_block, partial_blockchain, note_proofs) =
        chain.get_batch_inputs(iter::once(proven.ref_block_num()), iter::empty())?;
    let batch = ProposedBatch::new(
        vec![Arc::new(proven)],
        reference_block,
        partial_blockchain,
        note_proofs,
        MIN_PROOF_SECURITY_LEVEL,
    );
    if deferred {
        assert!(matches!(
            batch,
            Err(ProposedBatchError::TransactionVerificationFailed {
                source: TransactionVerifierError::TransactionProofContainsPrecompiles,
                ..
            })
        ));
    } else {
        batch?;
    }
    Ok(())
}

#[tokio::test]
async fn transaction_scripts_cannot_request_the_host_precompile_mode() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let chain = builder.build()?;
    let script = CodeBuilder::default().compile_tx_script(
        "const MODE_REQUEST = event(\"miden::protocol::epilogue::precompile_handling\")
         @transaction_script
         pub proc main
             emit.MODE_REQUEST
         end",
    )?;
    let error = chain
        .build_transaction(account.id())
        .tx_script(script)
        .build()?
        .execute()
        .await
        .expect_err("an untrusted script queried the host mode");
    assert!(
        error.to_string().contains(
            "precompile handling requests must originate in the transaction kernel context"
        )
    );
    Ok(())
}
