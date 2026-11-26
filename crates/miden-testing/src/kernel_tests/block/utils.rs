use std::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::batch::ProvenBatch;
use miden_protocol::block::BlockNumber;
use miden_protocol::block::code_tree::CodePatch;
use miden_protocol::note::{Note, NoteId};
use miden_protocol::testing::assembler::assemble_test_package;
use miden_protocol::transaction::{ExecutedTransaction, ProvenTransaction, TransactionScript};
use miden_standards::code_builder::CodeBuilder;
use miden_tx::LocalTransactionProver;

use crate::kernel_tests::batch::proven_tx_builder::MockProvenTxBuilder;
use crate::{MockChain, MockTransactionInput, MockTransactionNoteInput};

// MOCK CHAIN BUILDER EXTENSION
// ================================================================================================

/// Provides convenience methods for testing.
pub trait MockChainBlockExt {
    async fn create_authenticated_notes_tx(
        &self,
        input: impl Into<MockTransactionInput> + Send,
        notes: impl IntoIterator<Item = impl Into<MockTransactionNoteInput>> + Send,
    ) -> anyhow::Result<ExecutedTransaction>;

    async fn create_authenticated_notes_proven_tx(
        &self,
        input: impl Into<MockTransactionInput> + Send,
        notes: impl IntoIterator<Item = NoteId> + Send,
    ) -> anyhow::Result<ProvenTransaction>;

    async fn create_unauthenticated_notes_proven_tx(
        &self,
        account_id: AccountId,
        notes: &[Note],
    ) -> anyhow::Result<ProvenTransaction>;

    async fn create_expiring_proven_tx(
        &self,
        input: impl Into<MockTransactionInput> + Send,
        expiration_block: BlockNumber,
    ) -> anyhow::Result<ProvenTransaction>;

    fn create_batch(&self, txs: Vec<ProvenTransaction>) -> anyhow::Result<ProvenBatch>;
}

impl MockChainBlockExt for MockChain {
    async fn create_authenticated_notes_tx(
        &self,
        input: impl Into<MockTransactionInput> + Send,
        notes: impl IntoIterator<Item = impl Into<MockTransactionNoteInput>> + Send,
    ) -> anyhow::Result<ExecutedTransaction> {
        let mock_tx = self.build_transaction(input).authenticated_input_notes(notes).build()?;
        mock_tx.execute().await.map_err(From::from)
    }

    async fn create_authenticated_notes_proven_tx(
        &self,
        input: impl Into<MockTransactionInput> + Send,
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
        let mock_tx = self
            .build_transaction(account_id)
            .unauthenticated_input_notes(notes.iter().cloned())
            .build()?;
        let executed_tx = mock_tx.execute().await?;
        LocalTransactionProver::default().prove_dummy(executed_tx).map_err(From::from)
    }

    async fn create_expiring_proven_tx(
        &self,
        input: impl Into<MockTransactionInput> + Send,
        expiration_block: BlockNumber,
    ) -> anyhow::Result<ProvenTransaction> {
        let expiration_delta = expiration_block
            .checked_sub(self.latest_block_header().block_num().as_u32())
            .unwrap();

        let mock_tx = self
            .build_transaction(input)
            .tx_script(update_expiration_tx_script(expiration_delta.as_u32() as u16))
            .build()?;
        let executed_tx = mock_tx.execute().await?;
        LocalTransactionProver::default().prove_dummy(executed_tx).map_err(From::from)
    }

    fn create_batch(&self, txs: Vec<ProvenTransaction>) -> anyhow::Result<ProvenBatch> {
        self.propose_transaction_batch(txs)
            .map(|batch| self.prove_transaction_batch(batch).unwrap())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a code patch that shares the procedure `foo` with [`CodePatch::mock`].
pub fn code_patch_sharing_mock_code() -> anyhow::Result<CodePatch> {
    let mast = assemble_test_package(
        "test-shared-code-patch",
        "test::shared_code_patch",
        "
        pub proc foo
            push.1 drop
        end

        pub proc baz
            push.3 drop
        end
        ",
    )
    .mast_forest()
    .clone();

    Ok(CodePatch::new(mast)?)
}

/// Returns a batch with a mock transaction against the account that carries the code patch.
pub fn create_code_patch_batch(
    chain: &MockChain,
    account: &Account,
    code_patch: CodePatch,
) -> anyhow::Result<ProvenBatch> {
    let transaction = MockProvenTxBuilder::with_account(
        account.id(),
        account.to_commitment(),
        Word::from([1, 2, 3, 4u32]),
    )
    .reference_block(&chain.latest_block_header())
    .code_patch(code_patch)
    .build()?;

    chain.create_batch(vec![transaction])
}

fn update_expiration_tx_script(expiration_delta: u16) -> TransactionScript {
    let code = format!(
        "
        use miden::protocol::tx

        @transaction_script
        pub proc main
            push.{expiration_delta}
            exec.tx::update_expiration_block_delta
        end
        "
    );

    CodeBuilder::default().compile_tx_script(code).unwrap()
}
