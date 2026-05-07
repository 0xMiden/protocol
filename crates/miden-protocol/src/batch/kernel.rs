use alloc::vec::Vec;

use miden_core::program::Kernel;

use crate::batch::{BatchId, ProposedBatch};
use crate::block::BlockNumber;
use crate::errors::BatchOutputError;
use crate::transaction::{ToInputNoteCommitments, TransactionId};
use crate::utils::serde::Deserializable;
use crate::utils::sync::LazyLock;
use crate::vm::{AdviceInputs, Program, ProgramInfo, StackInputs, StackOutputs};
use crate::{Felt, Word};

// CONSTANTS
// ================================================================================================

static KERNEL_MAIN: LazyLock<Program> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/kernels/batch_kernel.masb"));
    Program::read_from_bytes(bytes).expect("failed to deserialize batch kernel runtime")
});

// Output stack indices, kept in sync with the lay-out at the end of `main.masm::main`. These are
// felt offsets, not word indices: `get_word(N)` returns the four felts at positions `N..N+4`.
const INPUT_NOTES_COMMITMENT_WORD_IDX: usize = 0;
const OUTPUT_NOTES_COMMITMENT_WORD_IDX: usize = 4;
const BATCH_EXPIRATION_BLOCK_NUM_ELEMENT_IDX: usize = 8;
// The word containing `batch_expiration_block_num` plus three padding zeros.
const EXPIRATION_PAD_WORD_FELT_IDX: usize = 8;
const EXPIRATION_PAD_WORD_INNER_OFFSET: usize = 1;
// The trailing word at felt indices 12..16 must be all zero.
const TRAILING_PAD_WORD_FELT_IDX: usize = 12;

// BATCH KERNEL
// ================================================================================================

/// The batch kernel program: an executable Miden program that proves a batch of transactions.
///
/// The kernel takes `[BLOCK_HASH, TRANSACTIONS_COMMITMENT]` as public inputs and emits
/// `[INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, batch_expiration_block_num]`.
/// See [`crate::batch::ProposedBatch`] / `asm/kernels/batch/main.masm` for the verification
/// chain and the list of TODOs the minimal kernel intentionally elides.
pub struct BatchKernel;

impl BatchKernel {
    // KERNEL SOURCE CODE
    // --------------------------------------------------------------------------------------------

    /// Returns the executable batch kernel program loaded from the build's `OUT_DIR`.
    pub fn main() -> Program {
        KERNEL_MAIN.clone()
    }

    /// Returns [`ProgramInfo`] for the batch kernel program.
    ///
    /// The batch kernel does not expose syscalls, so the associated [`Kernel`] is empty.
    pub fn program_info() -> ProgramInfo {
        ProgramInfo::new(Self::main().hash(), Kernel::default())
    }

    // INPUT BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Transforms the provided [`ProposedBatch`] into the stack and advice inputs needed to
    /// execute the batch kernel.
    pub fn prepare_inputs(proposed_batch: &ProposedBatch) -> (StackInputs, AdviceInputs) {
        let block_hash = proposed_batch.reference_block_header().commitment();
        let transactions_commitment = proposed_batch.id().as_word();

        let stack_inputs = Self::build_input_stack(block_hash, transactions_commitment);
        let advice_inputs = Self::build_advice_inputs(proposed_batch);

        (stack_inputs, advice_inputs)
    }

    /// Returns the stack with the public inputs required by the batch kernel.
    ///
    /// The initial stack is defined as:
    ///
    /// ```text
    /// [BLOCK_HASH, TRANSACTIONS_COMMITMENT]
    /// ```
    ///
    /// Where:
    /// - `BLOCK_HASH` is the commitment of the batch's reference block.
    /// - `TRANSACTIONS_COMMITMENT` is the value [`BatchId`] computes — a sequential hash of
    ///   `(transaction_id || account_id_prefix || account_id_suffix || 0 || 0)` over all
    ///   transactions in the batch.
    ///
    /// Note: `main.masm` immediately performs a `swapw`, so by the time `prologue::prepare_batch`
    /// runs the kernel-side stack is `[TRANSACTIONS_COMMITMENT, BLOCK_HASH, pad(8)]`. Any
    /// refactor that drops the leading `swapw` must update this builder to match.
    pub fn build_input_stack(block_hash: Word, transactions_commitment: Word) -> StackInputs {
        let mut inputs: Vec<Felt> = Vec::with_capacity(8);
        inputs.extend_from_slice(block_hash.as_elements());
        inputs.extend_from_slice(transactions_commitment.as_elements());

        StackInputs::new(&inputs).expect("number of stack inputs should be <= 16")
    }

    /// Builds the stack with the expected batch kernel outputs.
    ///
    /// The output stack is defined as:
    ///
    /// ```text
    /// [INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, batch_expiration_block_num]
    /// ```
    pub fn build_output_stack(
        input_notes_commitment: Word,
        output_notes_commitment: Word,
        batch_expiration_block_num: BlockNumber,
    ) -> StackOutputs {
        let mut outputs: Vec<Felt> = Vec::with_capacity(9);
        outputs.extend_from_slice(input_notes_commitment.as_elements());
        outputs.extend_from_slice(output_notes_commitment.as_elements());
        outputs.push(Felt::from(batch_expiration_block_num));

        StackOutputs::new(&outputs).expect("number of stack outputs should be <= 16")
    }

    /// Extracts batch output data from the provided stack outputs.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The padding cells (positions 9..16) are not all zero.
    /// - `batch_expiration_block_num` does not fit into a `u32`.
    pub fn parse_output_stack(
        stack: &StackOutputs,
    ) -> Result<(Word, Word, BlockNumber), BatchOutputError> {
        let input_notes_commitment = stack
            .get_word(INPUT_NOTES_COMMITMENT_WORD_IDX)
            .expect("input_notes_commitment word missing");
        let output_notes_commitment = stack
            .get_word(OUTPUT_NOTES_COMMITMENT_WORD_IDX)
            .expect("output_notes_commitment word missing");

        let expiration_felt = stack
            .get_element(BATCH_EXPIRATION_BLOCK_NUM_ELEMENT_IDX)
            .expect("batch_expiration_block_num missing");

        // The word at felt indices 8..12 contains [batch_expiration_block_num, 0, 0, 0]. Indices
        // 9..12 of the output stack must be zero.
        let pad_word = stack
            .get_word(EXPIRATION_PAD_WORD_FELT_IDX)
            .expect("expiration pad word missing");
        if pad_word.as_elements()[EXPIRATION_PAD_WORD_INNER_OFFSET..]
            != Word::empty().as_elements()[1..]
        {
            return Err(BatchOutputError::OutputStackInvalid(
                "batch_expiration_block_num must be followed by zero padding".into(),
            ));
        }

        // Felts 12..16 (the trailing word) must also be zero.
        let trailing_word =
            stack.get_word(TRAILING_PAD_WORD_FELT_IDX).expect("trailing word missing");
        if trailing_word != Word::empty() {
            return Err(BatchOutputError::OutputStackInvalid(
                "trailing output stack cells must be zero".into(),
            ));
        }

        let batch_expiration_block_num = u32::try_from(expiration_felt.as_canonical_u64())
            .map_err(|_| BatchOutputError::ExpirationBlockNumberTooLarge(expiration_felt))?
            .into();

        Ok((input_notes_commitment, output_notes_commitment, batch_expiration_block_num))
    }

    // ADVICE BUILDER
    // --------------------------------------------------------------------------------------------

    /// Builds the advice inputs (map + stack) consumed by the batch kernel.
    ///
    /// See `asm/kernels/batch/main.masm` for the layered map structure.
    fn build_advice_inputs(proposed_batch: &ProposedBatch) -> AdviceInputs {
        let mut advice_inputs = AdviceInputs::default();

        // Layer 1: TRANSACTIONS_COMMITMENT |-> [(tx_id, account_id_pair) tuples].
        let layer1_data = BatchId::hash_input_elements(
            proposed_batch.transactions().iter().map(|tx| (tx.id(), tx.account_id())),
        );
        advice_inputs.map.extend([(proposed_batch.id().as_word(), layer1_data)]);

        for tx in proposed_batch.transactions().iter() {
            // Layer 2: tx_id |-> [INIT, FINAL, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT,
            //                     FEE_ASSET].
            let header_data = TransactionId::input_elements(
                tx.account_update().initial_state_commitment(),
                tx.account_update().final_state_commitment(),
                tx.input_notes().commitment(),
                tx.output_notes().commitment(),
                tx.fee(),
            );
            advice_inputs.map.extend([(tx.id().as_word(), header_data.to_vec())]);

            // Layer 3: per-tx INPUT_NOTES_COMMITMENT |-> [(NULLIFIER, EMPTY_OR_COMMITMENT) tuples].
            let input_notes_commitment = tx.input_notes().commitment();
            if input_notes_commitment != Word::empty() {
                let mut data: Vec<Felt> =
                    Vec::with_capacity(usize::from(tx.input_notes().num_notes()) * 8);
                for note_commit in tx.input_notes().iter() {
                    data.extend_from_slice(note_commit.nullifier().as_word().as_elements());
                    let commit_or_zero = note_commit.note_commitment().unwrap_or(Word::empty());
                    data.extend_from_slice(commit_or_zero.as_elements());
                }
                advice_inputs.map.extend([(input_notes_commitment, data)]);
            }

            // Layer 3': per-tx OUTPUT_NOTES_COMMITMENT |-> [(NOTE_ID, METADATA_COMMITMENT) tuples].
            let output_notes_commitment = tx.output_notes().commitment();
            if output_notes_commitment != Word::empty() {
                let mut data: Vec<Felt> = Vec::with_capacity(tx.output_notes().num_notes() * 8);
                for note in tx.output_notes().iter() {
                    data.extend_from_slice(note.id().as_word().as_elements());
                    data.extend_from_slice(note.metadata().to_commitment().as_elements());
                }
                advice_inputs.map.extend([(output_notes_commitment, data)]);
            }
        }

        // Advice stack: per-tx expiration_block_num in transaction order.
        // The advice stack is FIFO from the prover's perspective — first pushed = first popped.
        for tx in proposed_batch.transactions().iter() {
            advice_inputs.stack.push(Felt::from(tx.expiration_block_num()));
        }

        advice_inputs
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use anyhow::Context;
    use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor};

    use super::*;
    use crate::Hasher;
    use crate::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
    use crate::asset::FungibleAsset;
    use crate::note::{NoteId, Nullifier};

    /// One synthetic transaction's worth of input data the kernel will read out of the advice
    /// provider during a test run.
    struct SynthTransaction {
        account_id: AccountId,
        initial_state: Word,
        final_state: Word,
        // (NULLIFIER, EMPTY_OR_NOTE_COMMITMENT) tuples — verbatim what the per-tx
        // INPUT_NOTES_COMMITMENT hashes.
        input_notes: Vec<(Nullifier, Word)>,
        // (NOTE_ID, METADATA_COMMITMENT) tuples — verbatim what the per-tx
        // OUTPUT_NOTES_COMMITMENT hashes.
        output_notes: Vec<(NoteId, Word)>,
        fee: FungibleAsset,
        expiration: BlockNumber,
    }

    impl SynthTransaction {
        fn input_notes_commitment(&self) -> Word {
            input_notes_commitment(&self.input_notes)
        }

        fn output_notes_commitment(&self) -> Word {
            output_notes_commitment(&self.output_notes)
        }

        fn tx_id(&self) -> TransactionId {
            TransactionId::from_raw(Hasher::hash_elements(&TransactionId::input_elements(
                self.initial_state,
                self.final_state,
                self.input_notes_commitment(),
                self.output_notes_commitment(),
                self.fee,
            )))
        }

        fn input_notes_advice(&self) -> Vec<Felt> {
            let mut data = Vec::with_capacity(self.input_notes.len() * 8);
            for (nullifier, commit) in &self.input_notes {
                data.extend_from_slice(nullifier.as_word().as_elements());
                data.extend_from_slice(commit.as_elements());
            }
            data
        }

        fn output_notes_advice(&self) -> Vec<Felt> {
            let mut data = Vec::with_capacity(self.output_notes.len() * 8);
            for (note_id, metadata) in &self.output_notes {
                data.extend_from_slice(note_id.as_word().as_elements());
                data.extend_from_slice(metadata.as_elements());
            }
            data
        }
    }

    fn input_notes_commitment(notes: &[(Nullifier, Word)]) -> Word {
        if notes.is_empty() {
            return Word::empty();
        }
        let mut elements = Vec::with_capacity(notes.len() * 8);
        for (nullifier, commit) in notes {
            elements.extend_from_slice(nullifier.as_word().as_elements());
            elements.extend_from_slice(commit.as_elements());
        }
        Hasher::hash_elements(&elements)
    }

    fn output_notes_commitment(notes: &[(NoteId, Word)]) -> Word {
        if notes.is_empty() {
            return Word::empty();
        }
        let mut elements = Vec::with_capacity(notes.len() * 8);
        for (note_id, metadata) in notes {
            elements.extend_from_slice(note_id.as_word().as_elements());
            elements.extend_from_slice(metadata.as_elements());
        }
        Hasher::hash_elements(&elements)
    }

    fn batch_input_notes_commitment(txs: &[SynthTransaction]) -> Word {
        let combined: Vec<_> = txs.iter().flat_map(|tx| tx.input_notes.clone()).collect();
        input_notes_commitment(&combined)
    }

    fn batch_output_notes_commitment(txs: &[SynthTransaction]) -> Word {
        let combined: Vec<_> = txs.iter().flat_map(|tx| tx.output_notes.clone()).collect();
        output_notes_commitment(&combined)
    }

    fn batch_expiration(txs: &[SynthTransaction]) -> BlockNumber {
        txs.iter().map(|tx| tx.expiration).min().expect("non-empty")
    }

    fn transactions_commitment(txs: &[SynthTransaction]) -> Word {
        Hasher::hash_elements(&BatchId::hash_input_elements(
            txs.iter().map(|tx| (tx.tx_id(), tx.account_id)),
        ))
    }

    fn build_advice_inputs(txs: &[SynthTransaction]) -> AdviceInputs {
        let mut advice_inputs = AdviceInputs::default();

        // Layer 1: TRANSACTIONS_COMMITMENT |-> [(tx_id, account_id_pair) tuples].
        let layer1 = BatchId::hash_input_elements(txs.iter().map(|tx| (tx.tx_id(), tx.account_id)));
        advice_inputs.map.extend([(transactions_commitment(txs), layer1)]);

        for tx in txs {
            let header = TransactionId::input_elements(
                tx.initial_state,
                tx.final_state,
                tx.input_notes_commitment(),
                tx.output_notes_commitment(),
                tx.fee,
            );
            advice_inputs.map.extend([(tx.tx_id().as_word(), header.to_vec())]);

            let input_notes_commitment = tx.input_notes_commitment();
            if input_notes_commitment != Word::empty() {
                advice_inputs.map.extend([(input_notes_commitment, tx.input_notes_advice())]);
            }

            let output_notes_commitment = tx.output_notes_commitment();
            if output_notes_commitment != Word::empty() {
                advice_inputs.map.extend([(output_notes_commitment, tx.output_notes_advice())]);
            }

            advice_inputs.stack.push(Felt::from(tx.expiration));
        }

        advice_inputs
    }

    fn dummy_account_id(n: u8) -> AccountId {
        AccountId::dummy(
            [n; 15],
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Private,
        )
    }

    fn synth_batch() -> Vec<SynthTransaction> {
        // Transaction 0: 2 input notes, 1 output note.
        let tx0 = SynthTransaction {
            account_id: dummy_account_id(1),
            initial_state: [10u32; 4].into(),
            final_state: [11u32; 4].into(),
            input_notes: vec![
                (Nullifier::dummy(101), [21u32; 4].into()),
                (Nullifier::dummy(102), Word::empty()),
            ],
            output_notes: vec![(NoteId::from_raw([31u32; 4].into()), [32u32; 4].into())],
            fee: FungibleAsset::mock(100).unwrap_fungible(),
            expiration: BlockNumber::from(1234u32),
        };

        // Transaction 1: 1 input note, 2 output notes, smaller expiration.
        let tx1 = SynthTransaction {
            account_id: dummy_account_id(2),
            initial_state: [40u32; 4].into(),
            final_state: [41u32; 4].into(),
            input_notes: vec![(Nullifier::dummy(201), [51u32; 4].into())],
            output_notes: vec![
                (NoteId::from_raw([61u32; 4].into()), [62u32; 4].into()),
                (NoteId::from_raw([63u32; 4].into()), [64u32; 4].into()),
            ],
            fee: FungibleAsset::mock(200).unwrap_fungible(),
            expiration: BlockNumber::from(800u32),
        };

        vec![tx0, tx1]
    }

    fn run_kernel(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
    ) -> Result<StackOutputs, miden_processor::ExecutionError> {
        use miden_core_lib::CoreLibrary;

        let mut host = DefaultHost::default();
        let core_lib = CoreLibrary::default();
        host.load_library(core_lib.mast_forest())
            .expect("failed to load core library into the test host");

        let processor = FastProcessor::new_with_options(
            stack_inputs,
            advice_inputs,
            ExecutionOptions::default(),
        )
        .with_debugging(true);
        let output = processor.execute_sync(&BatchKernel::main(), &mut host)?;
        Ok(output.stack)
    }

    #[test]
    fn batch_kernel_happy_path() -> anyhow::Result<()> {
        let txs = synth_batch();
        let block_hash = Word::from([99u32; 4]);
        let stack_inputs =
            BatchKernel::build_input_stack(block_hash, transactions_commitment(&txs));
        let advice_inputs = build_advice_inputs(&txs);

        let stack_outputs =
            run_kernel(stack_inputs, advice_inputs).context("kernel execution failed")?;
        let (input_notes_comm, output_notes_comm, expiration) =
            BatchKernel::parse_output_stack(&stack_outputs).context("parse output failed")?;

        assert_eq!(input_notes_comm, batch_input_notes_commitment(&txs));
        assert_eq!(output_notes_comm, batch_output_notes_commitment(&txs));
        assert_eq!(expiration, batch_expiration(&txs));
        Ok(())
    }

    #[test]
    fn batch_kernel_rejects_wrong_transactions_commitment() {
        let txs = synth_batch();
        let block_hash = Word::from([99u32; 4]);
        // Use a TRANSACTIONS_COMMITMENT the advice map does not provide.
        let bogus_commitment = Word::from([12345u32; 4]);
        let stack_inputs = BatchKernel::build_input_stack(block_hash, bogus_commitment);
        let advice_inputs = build_advice_inputs(&txs);

        let err = run_kernel(stack_inputs, advice_inputs).expect_err("kernel must abort");
        // The advice-map lookup for the bogus commitment will produce no value, which surfaces as
        // an `AdviceMapKeyNotFound` (or similar) error from `adv.push_mapvaln`. We don't depend on
        // the exact error variant; failing is enough.
        let msg = err.to_string();
        assert!(
            msg.contains("advice map") || msg.contains("not found") || msg.contains("missing"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn batch_kernel_rejects_tampered_layer_2() -> anyhow::Result<()> {
        let txs = synth_batch();
        let block_hash = Word::from([99u32; 4]);
        let stack_inputs =
            BatchKernel::build_input_stack(block_hash, transactions_commitment(&txs));
        let mut advice_inputs = build_advice_inputs(&txs);

        // Flip a bit in the Layer 2 entry for tx0 — the entry's hash will no longer equal tx0's
        // tx_id and the kernel must abort with ERR_BATCH_TRANSACTION_HEADER_MISMATCH.
        let tx0_id_word = txs[0].tx_id().as_word();
        let entry = advice_inputs.map.get(&tx0_id_word).expect("tx0 layer 2 entry");
        let mut tampered: Vec<Felt> = entry.iter().copied().collect();
        tampered[0] += Felt::new(1);
        advice_inputs.map.extend([(tx0_id_word, tampered)]);

        let err = run_kernel(stack_inputs, advice_inputs).expect_err("kernel must abort");
        let msg = err.to_string();
        assert!(
            msg.contains("transaction header data piped from the advice map"),
            "unexpected error: {msg}",
        );
        Ok(())
    }

    #[test]
    fn batch_kernel_rejects_tampered_input_notes() -> anyhow::Result<()> {
        let txs = synth_batch();
        let block_hash = Word::from([99u32; 4]);
        let stack_inputs =
            BatchKernel::build_input_stack(block_hash, transactions_commitment(&txs));
        let mut advice_inputs = build_advice_inputs(&txs);

        // Flip a felt of the input-notes data for tx0.
        let key = txs[0].input_notes_commitment();
        let entry = advice_inputs.map.get(&key).expect("layer 3 entry");
        let mut tampered: Vec<Felt> = entry.iter().copied().collect();
        tampered[0] += Felt::new(1);
        advice_inputs.map.extend([(key, tampered)]);

        let err = run_kernel(stack_inputs, advice_inputs).expect_err("kernel must abort");
        let msg = err.to_string();
        assert!(
            msg.contains("per-transaction input notes data piped"),
            "unexpected error: {msg}",
        );
        Ok(())
    }

    #[test]
    fn batch_kernel_rejects_tampered_output_notes() -> anyhow::Result<()> {
        let txs = synth_batch();
        let block_hash = Word::from([99u32; 4]);
        let stack_inputs =
            BatchKernel::build_input_stack(block_hash, transactions_commitment(&txs));
        let mut advice_inputs = build_advice_inputs(&txs);

        let key = txs[0].output_notes_commitment();
        let entry = advice_inputs.map.get(&key).expect("layer 3' entry");
        let mut tampered: Vec<Felt> = entry.iter().copied().collect();
        tampered[0] += Felt::new(1);
        advice_inputs.map.extend([(key, tampered)]);

        let err = run_kernel(stack_inputs, advice_inputs).expect_err("kernel must abort");
        let msg = err.to_string();
        assert!(
            msg.contains("per-transaction output notes data piped"),
            "unexpected error: {msg}",
        );
        Ok(())
    }
}
