use std::eprintln;
use std::vec::Vec;

use miden_core::field::PrimeField64;
use miden_protocol::account::AccountId;
use miden_protocol::batch::ProvenBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId};
use miden_protocol::transaction::{ExecutedTransaction, ProvenTransaction, TransactionScript};
use miden_standards::code_builder::CodeBuilder;
use miden_processor::ExecutionError;
use miden_tx::{LocalTransactionProver, TransactionExecutorError};

use crate::{MockChain, TxContextInput};

// MOCK CHAIN BUILDER EXTENSION
// ================================================================================================

/// Provides convenience methods for testing.
pub trait MockChainBlockExt {
    async fn create_authenticated_notes_tx(
        &self,
        input: impl Into<TxContextInput> + Send,
        notes: impl IntoIterator<Item = NoteId> + Send,
    ) -> anyhow::Result<ExecutedTransaction>;

    async fn create_authenticated_notes_proven_tx(
        &self,
        input: impl Into<TxContextInput> + Send,
        notes: impl IntoIterator<Item = NoteId> + Send,
    ) -> anyhow::Result<ProvenTransaction>;

    async fn create_unauthenticated_notes_proven_tx(
        &self,
        account_id: AccountId,
        notes: &[Note],
    ) -> anyhow::Result<ProvenTransaction>;

    async fn create_expiring_proven_tx(
        &self,
        input: impl Into<TxContextInput> + Send,
        expiration_block: BlockNumber,
    ) -> anyhow::Result<ProvenTransaction>;

    fn create_batch(&self, txs: Vec<ProvenTransaction>) -> anyhow::Result<ProvenBatch>;
}

impl MockChainBlockExt for MockChain {
    async fn create_authenticated_notes_tx(
        &self,
        input: impl Into<TxContextInput> + Send,
        notes: impl IntoIterator<Item = NoteId> + Send,
    ) -> anyhow::Result<ExecutedTransaction> {
        let notes = notes.into_iter().collect::<Vec<_>>();
        let tx_context = self.build_tx_context(input, &notes, &[])?.build()?;

        if std::env::var("MIDEN_DEBUG_INPUT_NOTE_DATA").is_ok() {
            use miden_protocol::transaction::TransactionKernel;

            let tx_inputs = tx_context.tx_inputs();
            let (_stack, advice_inputs) = TransactionKernel::prepare_inputs(tx_inputs);
            let input_notes_commitment = tx_inputs.input_notes().commitment();
            if let Some(values) = advice_inputs
                .as_advice_inputs()
                .map
                .get(&input_notes_commitment)
            {
                let len = values.len();
                let tail_start = len.saturating_sub(16);
                let tail = &values[tail_start..];
                eprintln!(
                    "debug input_notes map: len={len} tail={:?}",
                    tail.iter().map(|v| v.as_canonical_u64()).collect::<Vec<_>>()
                );
                let script_root = tx_inputs
                    .tx_args()
                    .tx_script()
                    .map(|script| script.root().map(|v| v.as_canonical_u64()));
                let script_args = tx_inputs.tx_args().tx_script_args().map(|v| v.as_canonical_u64());
                let auth_args = tx_inputs.tx_args().auth_args().map(|v| v.as_canonical_u64());
                eprintln!(
                    "debug tx_script_root={script_root:?} tx_script_args={script_args:?} auth_args={auth_args:?}"
                );
            } else {
                eprintln!(
                    "debug input_notes map: missing entry for commitment {}",
                    input_notes_commitment.to_hex()
                );
            }
        }

        match tx_context.execute().await {
            Ok(executed_tx) => Ok(executed_tx),
            Err(err) => {
                if std::env::var("MIDEN_DEBUG_ADVICE_CLK").is_ok() {
                    if let TransactionExecutorError::TransactionProgramExecutionFailed(
                        ExecutionError::AdviceError { err, .. },
                    ) = &err
                    {
                        eprintln!("advice error (debug): {err:?}");
                    }
                }
                Err(err.into())
            },
        }
    }

    async fn create_authenticated_notes_proven_tx(
        &self,
        input: impl Into<TxContextInput> + Send,
        notes: impl IntoIterator<Item = NoteId> + Send,
    ) -> anyhow::Result<ProvenTransaction> {
        let executed_tx = self.create_authenticated_notes_tx(input, notes).await?;
        LocalTransactionProver::default().prove_dummy(executed_tx).map_err(From::from)
    }

    async fn create_unauthenticated_notes_proven_tx(
        &self,
        account_id: AccountId,
        notes: &[Note],
    ) -> anyhow::Result<ProvenTransaction> {
        let tx_context = self.build_tx_context(account_id, &[], notes)?.build()?;
        let executed_tx = tx_context.execute().await?;
        LocalTransactionProver::default().prove_dummy(executed_tx).map_err(From::from)
    }

    async fn create_expiring_proven_tx(
        &self,
        input: impl Into<TxContextInput> + Send,
        expiration_block: BlockNumber,
    ) -> anyhow::Result<ProvenTransaction> {
        let expiration_delta = expiration_block
            .checked_sub(self.latest_block_header().block_num().as_u32())
            .unwrap();

        let tx_context = self
            .build_tx_context(input, &[], &[])?
            .tx_script(update_expiration_tx_script(expiration_delta.as_u32() as u16))
            .build()?;
        let executed_tx = tx_context.execute().await?;
        LocalTransactionProver::default().prove_dummy(executed_tx).map_err(From::from)
    }

    fn create_batch(&self, txs: Vec<ProvenTransaction>) -> anyhow::Result<ProvenBatch> {
        self.propose_transaction_batch(txs)
            .map(|batch| self.prove_transaction_batch(batch).unwrap())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn update_expiration_tx_script(expiration_delta: u16) -> TransactionScript {
    let code = format!(
        "
        use miden::protocol::tx

        begin
            push.{expiration_delta}
            exec.tx::update_expiration_block_delta
        end
        "
    );

    CodeBuilder::default().compile_tx_script(code).unwrap()
}
