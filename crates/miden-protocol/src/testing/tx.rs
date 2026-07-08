use crate::asset::AssetAmount;
use crate::block::FeeParameters;
use crate::note::NoteId;
use crate::transaction::ExecutedTransaction;

impl ExecutedTransaction {
    /// A Rust implementation of the compute_fee procedure.
    pub fn compute_fee(&self) -> AssetAmount {
        TransactionFee::new(
            u32::try_from(self.measurements().trace_length())
                .expect("total number of cycles should fit in u32"),
        )
        .compute_fee(self.tx_inputs().block_header().fee_parameters())
    }

    /// Returns `true` if the transaction consumes the note with the given ID.
    pub fn consumes_note(&self, note_id: &NoteId) -> bool {
        self.input_notes().iter().any(|n| n.id() == *note_id)
    }
}

/// Contains the inputs used to compute a transaction's fee.
pub struct TransactionFee {
    verification_cycles: u32,
}

impl TransactionFee {
    pub fn new(tx_trace_length: u32) -> Self {
        // Round up the number of cycles to the next power of two and take log2 of it.
        let verification_cycles = tx_trace_length.ilog2();

        Self { verification_cycles }
    }

    /// A Rust implementation of the compute_fee procedure.
    pub fn compute_fee(&self, fee_parameters: &FeeParameters) -> AssetAmount {
        let fee_amount = fee_parameters.verification_base_fee() * self.verification_cycles;

        AssetAmount::from(fee_amount)
    }
}
