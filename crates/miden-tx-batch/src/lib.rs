#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod batch_executor;
pub use batch_executor::BatchExecutor;

mod errors;
pub use errors::BatchVerifierError;

mod executed_batch;
pub use executed_batch::ExecutedBatch;

mod local_batch_prover;
pub use local_batch_prover::LocalBatchProver;

mod verifier;
pub use verifier::BatchVerifier;
