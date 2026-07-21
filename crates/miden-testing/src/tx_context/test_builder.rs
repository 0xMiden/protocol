// TEST TRANSACTION BUILDER
// ================================================================================================

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::advice::AdviceInputs;
use miden_processor::{Felt, Word};
use miden_protocol::EMPTY_WORD;
use miden_protocol::account::Account;
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::assembly::debuginfo::SourceManagerSync;
use miden_protocol::note::{Note, NoteId, NoteScript, NoteScriptRoot};
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::{RawOutputNote, TransactionScript};
use miden_standards::testing::account_component::IncrNonceAuthComponent;
use miden_standards::testing::mock_account::MockAccountExt;

use super::MockTransaction;
use crate::MockChain;

// TEST TRANSACTION BUILDER
// ================================================================================================

/// A crate-internal builder that makes a [MockTransaction] for tests.
///
/// Use it when a test just needs some valid chain data to run against and does not care about the
/// exact state of a [`crate::MockChain`]. It makes a simple [`crate::MockChain`] inside and builds
/// the transaction against it through [`crate::MockChain::build_transaction`].
#[derive(Clone)]
pub(crate) struct TestTransactionBuilder {
    source_manager: Arc<dyn SourceManagerSync>,
    account: Account,
    advice_inputs: AdviceInputs,
    expected_output_notes: Vec<RawOutputNote>,
    input_notes: Vec<Note>,
    tx_script: Option<TransactionScript>,
    tx_script_args: Word,
    auth_args: Word,
    note_scripts: BTreeMap<NoteScriptRoot, NoteScript>,
    is_lazy_loading_enabled: bool,
}

impl TestTransactionBuilder {
    pub(crate) fn new(account: Account) -> Self {
        Self {
            source_manager: Arc::new(DefaultSourceManager::default()),
            account,
            advice_inputs: Default::default(),
            expected_output_notes: Vec::new(),
            input_notes: Vec::new(),
            tx_script: None,
            tx_script_args: EMPTY_WORD,
            auth_args: EMPTY_WORD,
            note_scripts: BTreeMap::new(),
            is_lazy_loading_enabled: true,
        }
    }

    /// Initializes a [TestTransactionBuilder] with a mock account.
    ///
    /// The wallet:
    ///
    /// - Includes a series of mocked assets ([miden_protocol::asset::AssetVault::mock()]).
    /// - Has a nonce of `1` (so it does not imply seed validation).
    /// - Has an ID of [`ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE`].
    /// - Has an account code based on an
    ///   [miden_standards::testing::account_component::MockAccountComponent].
    pub(crate) fn with_existing_mock_account() -> Self {
        Self::new(Account::mock(
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
            [IncrNonceAuthComponent],
        ))
    }

    /// Same as [`Self::with_existing_mock_account`] but with a
    /// [`miden_protocol::testing::noop_auth_component::NoopAuthComponent`].
    pub(crate) fn with_noop_auth_account() -> Self {
        Self::new(Account::mock(
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
            [NoopAuthComponent],
        ))
    }

    /// Initializes a [TestTransactionBuilder] with a mocked fungible faucet.
    pub(crate) fn with_fungible_faucet(acct_id: u128) -> Self {
        Self::new(Account::mock_fungible_faucet(acct_id))
    }

    /// Initializes a [TestTransactionBuilder] with a mocked non-fungible faucet.
    pub(crate) fn with_non_fungible_faucet(acct_id: u128) -> Self {
        Self::new(Account::mock_non_fungible_faucet(acct_id))
    }

    /// Inserts a single key-value pair into the advice inputs map.
    ///
    /// To add multiple entries, call this repeatedly.
    pub(crate) fn extend_advice_map(mut self, key: Word, value: Vec<Felt>) -> Self {
        self.advice_inputs.map.insert(key, value);
        self
    }

    /// Adds a single input note that the transaction consumes.
    pub(crate) fn input_note(mut self, input_note: Note) -> Self {
        self.input_notes.push(input_note);
        self
    }

    /// Adds multiple input notes that the transaction consumes.
    ///
    /// This is the iterator equivalent of [`Self::input_note`].
    pub(crate) fn input_notes(mut self, input_notes: Vec<Note>) -> Self {
        self.input_notes.extend(input_notes);
        self
    }

    /// Set the desired transaction script.
    pub(crate) fn tx_script(mut self, tx_script: TransactionScript) -> Self {
        self.tx_script = Some(tx_script);
        self
    }

    /// Set the transaction script arguments.
    pub(crate) fn tx_script_args(mut self, tx_script_args: Word) -> Self {
        self.tx_script_args = tx_script_args;
        self
    }

    /// Set the desired auth arguments.
    pub(crate) fn auth_args(mut self, auth_args: Word) -> Self {
        self.auth_args = auth_args;
        self
    }

    /// Disables lazy loading.
    ///
    /// Only affects [`MockTransaction::execute_code`] and causes the host to _not_ handle lazy
    /// loading events.
    pub(crate) fn disable_lazy_loading(mut self) -> Self {
        self.is_lazy_loading_enabled = false;
        self
    }

    /// Adds a single expected output note that the transaction produces.
    pub(crate) fn expected_output_note(mut self, output_note: RawOutputNote) -> Self {
        self.expected_output_notes.push(output_note);
        self
    }

    /// Adds multiple expected output notes that the transaction produces.
    ///
    /// This is the iterator equivalent of [`Self::expected_output_note`].
    pub(crate) fn expected_output_notes(mut self, output_notes: Vec<RawOutputNote>) -> Self {
        self.expected_output_notes.extend(output_notes);
        self
    }

    /// Sets the [`SourceManagerSync`] on the [`MockTransaction`] that will be built.
    pub(crate) fn with_source_manager(
        mut self,
        source_manager: Arc<dyn SourceManagerSync>,
    ) -> Self {
        self.source_manager = source_manager;
        self
    }

    /// Add a note script to the context for testing.
    pub(crate) fn add_note_script(mut self, script: NoteScript) -> Self {
        self.note_scripts.insert(script.root(), script);
        self
    }

    /// Builds the [MockTransaction].
    ///
    /// An ad-hoc [`crate::MockChain`] is created to generate valid block data for the requested
    /// input notes, and the transaction is then built against it through
    /// [`crate::MockChain::build_transaction`]. The account is passed by value so that it is used
    /// directly without requiring it to be committed to the chain. The rest of the configuration
    /// (advice inputs, transaction script, expected output notes, ...) is forwarded to the
    /// [`crate::MockTransactionBuilder`] before the [MockTransaction] is assembled.
    pub(crate) fn build(self) -> anyhow::Result<MockTransaction> {
        // Spin up an ad-hoc mock chain that commits the requested input notes, so that valid block
        // data (block headers and the chain's Merkle Mountain Range) can be generated for them.
        let mut chain_builder = MockChain::builder();

        let input_note_ids: Vec<NoteId> = self.input_notes.iter().map(Note::id).collect();
        for input_note in self.input_notes {
            chain_builder.add_output_note(RawOutputNote::Full(input_note));
        }

        let mut mock_chain = chain_builder.build()?;
        mock_chain.prove_next_block().context("failed to prove first block")?;
        mock_chain.prove_next_block().context("failed to prove second block")?;

        // Build the transaction against the ad-hoc chain through the public chain-coupled builder.
        // The committed input notes are resolved as authenticated input notes by their ID.
        let mut builder = mock_chain
            .build_transaction(self.account)
            .authenticated_input_notes(input_note_ids)
            .extend_advice_inputs(self.advice_inputs)
            .tx_script_args(self.tx_script_args)
            .auth_args(self.auth_args)
            .expected_output_notes(self.expected_output_notes)
            .with_source_manager(self.source_manager);

        if let Some(tx_script) = self.tx_script {
            builder = builder.tx_script(tx_script);
        }
        if !self.is_lazy_loading_enabled {
            builder = builder.disable_lazy_loading();
        }
        for script in self.note_scripts.into_values() {
            builder = builder.add_note_script(script);
        }

        builder.build()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;

    use super::TestTransactionBuilder;
    use crate::utils::create_public_p2any_note;

    #[tokio::test]
    async fn test_transaction_builder_builds_and_executes() -> anyhow::Result<()> {
        let executed =
            TestTransactionBuilder::with_existing_mock_account().build()?.execute().await?;

        // No input notes were provided, so the executed transaction consumes none.
        assert_eq!(executed.input_notes().num_notes(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_transaction_builder_resolves_input_notes() -> anyhow::Result<()> {
        let input_note = create_public_p2any_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            [FungibleAsset::mock(100)],
        );

        let executed = TestTransactionBuilder::with_existing_mock_account()
            .input_note(input_note.clone())
            .build()?
            .execute()
            .await?;

        // The ad-hoc chain should have resolved the provided input note.
        assert_eq!(executed.input_notes().num_notes(), 1);
        assert_eq!(executed.input_notes().get_note(0).id(), input_note.id());

        Ok(())
    }
}
