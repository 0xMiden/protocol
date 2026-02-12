use crate::transaction::ExecutedTransaction;

impl ExecutedTransaction {
    /// A Rust implementation of the compute_fee epilogue procedure.
    pub fn compute_fee(&self) -> u64 {
        // Round up the number of cycles to the next power of two and take log2 of it.
        let verification_cycles = self.measurements().trace_length().ilog2();
        let fee_amount =
            self.block_header().fee_parameters().verification_base_fee() * verification_cycles;
        fee_amount as u64
    }
}
