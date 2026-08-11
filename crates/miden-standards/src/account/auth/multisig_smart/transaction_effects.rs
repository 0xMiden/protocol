use miden_protocol::transaction::TransactionSummary;
use miden_protocol::{Hasher, WORD_SIZE, Word, ZERO};

/// A commitment to a transaction's *effects* - what the transaction does - independent of its
/// execution context (the reference block and the expiration block delta).
///
/// It is [`TransactionSummary::to_commitment`] with the reference block commitment and the
/// expiration block delta zeroed out. The reference block and expiration legitimately differ
/// between the moment a transaction is planned and the (later, different-block) moment it runs, so
/// binding them would make the commitment change across blocks. Everything that identifies the
/// transaction's effects - the account delta, the input/output notes, and the user parameters -
/// stays bound.
///
/// The delayed-execution flow keys a proposal on this commitment so that the proposer and the
/// account's authentication procedure - which recomputes it at execution time, against a later
/// reference block - derive the same value.
///
/// This intentionally lives in the multisig-smart code rather than next to [`TransactionSummary`]:
/// it must never be used as the message that authorizes a transaction, because it does not bind the
/// reference block or the expiration delta (doing so would reintroduce the binding gap that binding
/// them into the tx summary closed). Execution is still authorized by signatures over the full
/// tx-summary commitment. It must stay in sync with `hash_tx_effects_commitment` in the standard
/// auth library (`crates/miden-standards/asm/standards/auth/mod.masm`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionEffects {
    commitment: Word,
}

impl TransactionEffects {
    /// Start index of the reference block commitment word in the tx-summary preimage (word 3).
    const BLOCK_COMMITMENT_START: usize = 3 * WORD_SIZE;
    /// Index of the expiration block delta element in the tx-summary preimage (first element of the
    /// params-head word).
    const EXPIRATION_DELTA_IDX: usize = 4 * WORD_SIZE;

    /// Computes the transaction effects commitment of the given [`TransactionSummary`].
    pub fn from_summary(summary: &TransactionSummary) -> Self {
        let mut elements = summary.to_elements();
        debug_assert_eq!(
            elements.len(),
            TransactionSummary::NUM_ELEMENTS,
            "tx summary preimage layout changed; update the zeroed indices below",
        );

        // Zero the reference block commitment (word 3) and the expiration block delta, matching
        // `hash_tx_effects_commitment` in the standard auth library.
        elements[Self::BLOCK_COMMITMENT_START..Self::EXPIRATION_DELTA_IDX].fill(ZERO);
        elements[Self::EXPIRATION_DELTA_IDX] = ZERO;

        Self {
            commitment: Hasher::hash_elements(&elements),
        }
    }

    /// Returns the transaction effects commitment.
    pub fn commitment(&self) -> Word {
        self.commitment
    }
}
