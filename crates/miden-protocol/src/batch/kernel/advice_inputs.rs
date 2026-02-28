//! Batch Kernel Advice Inputs
//!
//! This module is responsible for preparing the advice inputs for the batch kernel.
//! The advice inputs contain all the preimages needed for unhashing, as well as
//! the transaction proofs for recursive verification.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::block::BlockHeader;
use crate::transaction::ProvenTransaction;
use crate::vm::AdviceInputs;
use crate::{Felt, ZERO};

// BATCH ADVICE INPUTS
// ================================================================================================

/// Holds the advice inputs required by the batch kernel.
///
/// The advice inputs include:
/// - Block header preimage (for unhashing BLOCK_HASH)
/// - Transaction list preimage (for unhashing TRANSACTIONS_COMMITMENT)
/// - Transaction ID preimages (for unhashing each TX_ID)
/// - Transaction proofs (for recursive verification)
/// - Input/output note data
#[derive(Debug, Clone)]
pub struct BatchAdviceInputs {
    inner: AdviceInputs,
}

impl BatchAdviceInputs {
    /// Creates a new [BatchAdviceInputs] from a block header and list of transactions.
    ///
    /// This method extracts all the data needed by the batch kernel and organizes it
    /// into the advice stack and advice map.
    pub fn new(block_header: &BlockHeader, transactions: &[Arc<ProvenTransaction>]) -> Self {
        let mut advice_stack: Vec<Felt> = Vec::new();
        let advice_map = alloc::collections::BTreeMap::new();

        // Build advice stack in the order MASM will pop it
        // (element 0 = top of advice stack = first popped)

        // Block header data
        advice_stack.push(Felt::from(block_header.block_num()));
        advice_stack.extend(block_header.chain_commitment());

        // Transaction count
        advice_stack.push(Felt::new(transactions.len() as u64));

        // Transaction list data (TX_ID, account_id for each tx)
        for tx in transactions {
            advice_stack.extend(tx.id().as_elements());
            advice_stack.push(tx.account_id().prefix().as_felt());
            advice_stack.push(tx.account_id().suffix());
        }

        // Transaction preimages
        for tx in transactions {
            let account_update = tx.account_update();
            advice_stack.extend(account_update.initial_state_commitment());
            advice_stack.extend(account_update.final_state_commitment());
            advice_stack.extend(tx.input_notes().commitment());
            advice_stack.extend(tx.output_notes().commitment());
            advice_stack.push(Felt::from(tx.expiration_block_num()));
        }

        // Input notes data
        for tx in transactions {
            let input_notes = tx.input_notes();
            advice_stack.push(Felt::new(input_notes.num_notes() as u64));

            for note in input_notes.iter() {
                advice_stack.extend(note.nullifier().as_elements());
                // TODO: For unauthenticated notes, use hash(note_id, note_metadata) instead of
                // zeros
                advice_stack.extend([ZERO; 4]);
            }
        }

        Self {
            inner: AdviceInputs::default().with_stack(advice_stack).with_map(advice_map),
        }
    }

    /// Returns the inner [AdviceInputs].
    pub fn into_inner(self) -> AdviceInputs {
        self.inner
    }

    /// Returns a reference to the inner [AdviceInputs].
    pub fn inner(&self) -> &AdviceInputs {
        &self.inner
    }
}

impl From<BatchAdviceInputs> for AdviceInputs {
    fn from(inputs: BatchAdviceInputs) -> Self {
        inputs.inner
    }
}
