use crate::asset::AssetAmount;
use crate::note::NoteId;
use crate::transaction::{ExecutedTransaction, TransactionFee};

impl ExecutedTransaction {
    /// A Rust implementation of the compute_fee procedure.
    pub fn compute_fee(&self) -> AssetAmount {
        TransactionFee::new(
            u32::try_from(self.measurements().total_cycles())
                .expect("total number of cycles should fit in u32"),
        )
        .expect("an executed transaction has a non-zero cycle count")
        .compute_fee(self.tx_inputs().block_header().fee_parameters())
    }

    /// Returns `true` if the transaction consumes the note with the given ID.
    pub fn consumes_note(&self, note_id: &NoteId) -> bool {
        self.input_notes().iter().any(|n| n.id() == *note_id)
    }
}
