use std::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::batch::ProvenBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId};
use miden_protocol::transaction::{ExecutedTransaction, ProvenTransaction, TransactionScript};
use miden_standards::code_builder::CodeBuilder;
use miden_tx::LocalTransactionProver;

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
        tx_context.execute().await.map_err(From::from)
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
