use miden_assembly::Assembler;
use miden_processor::{DefaultHost, FastProcessor};
use miden_protocol::errors::ProofVerificationError;
use miden_protocol::vm::StackInputs;
use miden_protocol::{PROTOCOL_PROOF_HASH, verify_execution_proof};
use miden_tx::Prover;

#[test]
fn prove_and_check_execution_security_floor() {
    let program = Assembler::default()
        .assemble_program("floor", "begin push.1 drop end")
        .unwrap()
        .try_into_program()
        .unwrap();
    let witness = FastProcessor::new(StackInputs::default())
        .execute_for_proving_sync(&program, &mut DefaultHost::default())
        .unwrap();
    let claim = witness.claim();
    let proof = Prover::new().with_hash_fn(PROTOCOL_PROOF_HASH).prove_full(witness).unwrap();

    let actual = verify_execution_proof(&claim, &proof, 0)
        .unwrap()
        .vm_security_parameters()
        .conjectured_security_level();
    assert!(verify_execution_proof(&claim, &proof, actual).is_ok());
    assert!(matches!(
        verify_execution_proof(&claim, &proof, actual + 1),
        Err(ProofVerificationError::InsufficientSecurityLevel { actual: reported, required })
            if reported == actual && required == actual + 1
    ));
}
