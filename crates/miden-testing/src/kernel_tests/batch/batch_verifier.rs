use anyhow::Context;
use assert_matches::assert_matches;
use miden_batch::{BatchExecutor, BatchVerifier, BatchVerifierError, LocalBatchProver};

use super::proposed_batch::setup_chain;
use super::test_batch_kernel::two_tx_batch;

// BATCH VERIFIER TESTS
// ================================================================================================

/// A batch proven by the batch kernel verifies against the kernel program, and requiring a higher
/// security level than the proof provides is rejected.
#[test]
fn batch_verifier_accepts_freshly_proven_batch() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let executed = BatchExecutor::new().execute(batch).context("batch execution failed")?;
    let proven = LocalBatchProver::new().prove(executed).context("batch proving failed")?;

    let security_level = proven.proof_security_level();

    // Requiring exactly the security level the proof provides must succeed.
    BatchVerifier::new(security_level)
        .verify(&proven)
        .context("verifying the proven batch should succeed")?;

    // Requiring even one more bit than the proof provides must fail.
    let err = BatchVerifier::new(security_level + 1).verify(&proven).unwrap_err();
    assert_matches!(err, BatchVerifierError::InsufficientProofSecurityLevel { .. });

    Ok(())
}

/// The dummy proof carried by `prove_dummy` is not a valid batch-kernel proof and must be rejected.
#[test]
fn batch_verifier_rejects_dummy_proof() -> anyhow::Result<()> {
    let mut setup = setup_chain();
    let batch = two_tx_batch(&mut setup)?;

    let proven = LocalBatchProver::new().prove_dummy(batch)?;

    let err = BatchVerifier::new(0).verify(&proven).unwrap_err();
    assert_matches!(err, BatchVerifierError::BatchVerificationFailed(_));

    Ok(())
}
