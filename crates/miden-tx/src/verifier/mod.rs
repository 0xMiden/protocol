use miden_protocol::CoreLibrary;
use miden_protocol::transaction::{ProvenTransaction, TransactionKernel};
use miden_protocol::vm::ProgramInfo;
use miden_verifier::verify_with_precompiles;

use super::TransactionVerifierError;

// TRANSACTION VERIFIER
// ================================================================================================

/// The [TransactionVerifier] is used to verify  [ProvenTransaction]s.
///
/// The [TransactionVerifier] contains a [ProgramInfo] object which is associated with the
/// transaction kernel program.  The `proof_security_level` specifies the minimum security
/// level that the transaction proof must have in order to be considered valid.
pub struct TransactionVerifier {
    tx_program_info: ProgramInfo,
    proof_security_level: u32,
}

impl TransactionVerifier {
    /// Returns a new [TransactionVerifier] instantiated with the specified security level.
    pub fn new(proof_security_level: u32) -> Self {
        let tx_program_info = TransactionKernel::program_info();
        Self { tx_program_info, proof_security_level }
    }

    /// Verifies the provided [`ProvenTransaction`] against the transaction kernel.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Transaction verification fails.
    /// - The security level of the verified proof is insufficient.
    pub fn verify(&self, transaction: &ProvenTransaction) -> Result<(), TransactionVerifierError> {
        // build stack inputs and outputs
        let stack_inputs = TransactionKernel::build_input_stack(
            transaction.account_id(),
            transaction.account_update().initial_state_commitment(),
            transaction.input_notes().commitment(),
            transaction.ref_block_commitment(),
            transaction.ref_block_num(),
        );
        let stack_outputs = TransactionKernel::build_output_stack(
            transaction.account_update().final_state_commitment(),
            transaction.account_update().account_delta_commitment(),
            transaction.output_notes().commitment(),
            transaction.fee(),
            transaction.expiration_block_num(),
        );

        // verify transaction proof
        let precompile_verifiers = CoreLibrary::default().verifier_registry();
        let proof_security_level = verify_with_precompiles(
            self.tx_program_info.clone(),
            stack_inputs,
            stack_outputs,
            transaction.proof().clone(),
            &precompile_verifiers,
        )
        .map_err(TransactionVerifierError::TransactionVerificationFailed)?
        .0;

        // check security level
        if proof_security_level < self.proof_security_level {
            return Err(TransactionVerifierError::InsufficientProofSecurityLevel {
                actual: proof_security_level,
                expected_minimum: self.proof_security_level,
            });
        }

        Ok(())
    }
}
