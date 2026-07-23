// MOCK TRANSACTION BUILDER
// ================================================================================================

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::advice::AdviceInputs;
use miden_processor::{Felt, Word};
use miden_protocol::EMPTY_WORD;
use miden_protocol::account::auth::{PublicKeyCommitment, Signature};
use miden_protocol::account::{Account, AccountId};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::assembly::debuginfo::SourceManagerSync;
use miden_protocol::block::BlockNumber;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::note::{Note, NoteId, NoteScript, NoteScriptRoot};
use miden_protocol::transaction::{RawOutputNote, TransactionArgs, TransactionScript};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_tx::TransactionMastStore;
use miden_tx::auth::BasicAuthenticator;

use super::MockTransaction;
use crate::MockChain;
use crate::mock_chain::MockTransactionInput;

// MOCK TRANSACTION BUILDER
// ================================================================================================

/// A builder for a [`MockTransaction`] that is coupled to a concrete [`MockChain`].
///
/// It is the public entry point for executing a transaction against a chain and is created through
/// [`MockChain::build_transaction`]. Input notes are added explicitly through
/// [`Self::authenticated_input_note`] and [`Self::unauthenticated_input_note`]. The transaction
/// inputs are only resolved against the chain in [`Self::build`], once all input notes are known,
/// by calling [`MockChain::get_transaction_inputs`].
///
/// # Examples
///
/// ```
/// # use anyhow::Result;
/// # use miden_protocol::{asset::FungibleAsset, note::NoteType};
/// # use miden_testing::{Auth, MockChain};
/// #
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<()> {
/// let mut builder = MockChain::builder();
/// let sender = builder.add_existing_mock_account(Auth::IncrNonce)?;
/// let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
/// let note = builder.add_p2id_note(
///     sender.id(),
///     account.id(),
///     &[FungibleAsset::mock(100)],
///     NoteType::Public,
/// )?;
/// let chain = builder.build()?;
///
/// let executed = chain
///     .build_transaction(account.id())
///     .authenticated_input_note(note.id())
///     .build()?
///     .execute()
///     .await?;
///
/// assert_eq!(executed.input_notes().num_notes(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct MockTransactionBuilder<'chain> {
    chain: &'chain MockChain,
    input: MockTransactionInput,
    reference_block: Option<BlockNumber>,
    authenticated_notes: Vec<NoteId>,
    unauthenticated_notes: Vec<Note>,
    authenticator: Option<BasicAuthenticator>,
    advice_inputs: AdviceInputs,
    foreign_account_inputs: BTreeMap<AccountId, (Account, AccountWitness)>,
    expected_output_notes: Vec<Note>,
    tx_script: Option<TransactionScript>,
    tx_script_args: Word,
    auth_args: Word,
    note_args: BTreeMap<NoteId, Word>,
    signatures: Vec<(PublicKeyCommitment, Word, Signature)>,
    note_scripts: BTreeMap<NoteScriptRoot, NoteScript>,
    source_manager: Option<Arc<dyn SourceManagerSync>>,
    is_lazy_loading_enabled: bool,
}

impl<'chain> MockTransactionBuilder<'chain> {
    /// Creates a new [`MockTransactionBuilder`] against the provided chain.
    ///
    /// Use [`MockChain::build_transaction`] instead of calling this directly.
    pub(crate) fn new(chain: &'chain MockChain, input: impl Into<MockTransactionInput>) -> Self {
        let input = input.into();
        // Resolve the chain's authenticator for the account up front. The chain is borrowed
        // immutably for the builder's lifetime, so this default cannot change before `build`; an
        // explicit `authenticator` call may still override it.
        let authenticator = chain.account_authenticator(input.id());

        Self {
            chain,
            input,
            reference_block: None,
            authenticated_notes: Vec::new(),
            unauthenticated_notes: Vec::new(),
            authenticator,
            advice_inputs: AdviceInputs::default(),
            foreign_account_inputs: BTreeMap::new(),
            expected_output_notes: Vec::new(),
            tx_script: None,
            tx_script_args: EMPTY_WORD,
            auth_args: EMPTY_WORD,
            note_args: BTreeMap::new(),
            signatures: Vec::new(),
            note_scripts: BTreeMap::new(),
            source_manager: None,
            is_lazy_loading_enabled: true,
        }
    }

    /// Adds an authenticated input note that the transaction consumes.
    ///
    /// The note must already be committed to the chain so that its inclusion proof can be resolved
    /// in [`Self::build`].
    pub fn authenticated_input_note(mut self, note_id: NoteId) -> Self {
        self.authenticated_notes.push(note_id);
        self
    }

    /// Adds multiple authenticated input notes that the transaction consumes.
    ///
    /// This is the iterator equivalent of [`Self::authenticated_input_note`].
    pub fn authenticated_input_notes(mut self, note_ids: impl IntoIterator<Item = NoteId>) -> Self {
        self.authenticated_notes.extend(note_ids);
        self
    }

    /// Adds an unauthenticated input note that the transaction consumes.
    ///
    /// Contrary to [`Self::authenticated_input_note`], the note does not need to be committed to
    /// the chain.
    pub fn unauthenticated_input_note(mut self, note: Note) -> Self {
        self.unauthenticated_notes.push(note);
        self
    }

    /// Adds multiple unauthenticated input notes that the transaction consumes.
    ///
    /// This is the iterator equivalent of [`Self::unauthenticated_input_note`].
    pub fn unauthenticated_input_notes(mut self, notes: impl IntoIterator<Item = Note>) -> Self {
        self.unauthenticated_notes.extend(notes);
        self
    }

    /// Sets the block the transaction executes against.
    ///
    /// By default the transaction is built against the chain's latest block. Use this to execute
    /// against an earlier block instead, e.g. to test block-height-dependent script logic such as
    /// timelocks or note expiration. All input notes must have been created at or before this
    /// block.
    pub fn reference_block(mut self, reference_block: impl Into<BlockNumber>) -> Self {
        self.reference_block = Some(reference_block.into());
        self
    }

    /// Set the authenticator for the transaction (if needed).
    pub fn authenticator(mut self, authenticator: Option<BasicAuthenticator>) -> Self {
        self.authenticator = authenticator;
        self
    }

    /// Extends the advice inputs with the provided [`AdviceInputs`] instance.
    pub fn extend_advice_inputs(mut self, advice_inputs: AdviceInputs) -> Self {
        self.advice_inputs.extend(advice_inputs);
        self
    }

    /// Inserts a single key-value pair into the advice inputs map.
    ///
    /// To add multiple entries, call this repeatedly or use [`Self::extend_advice_inputs`].
    pub fn extend_advice_map(mut self, key: Word, value: Vec<Felt>) -> Self {
        self.advice_inputs.map.insert(key, value);
        self
    }

    /// Sets foreign account inputs that are used by the transaction.
    pub fn foreign_accounts(
        mut self,
        inputs: impl IntoIterator<Item = (Account, AccountWitness)>,
    ) -> Self {
        self.foreign_account_inputs.extend(
            inputs.into_iter().map(|(account, witness)| (account.id(), (account, witness))),
        );
        self
    }

    /// Sets the desired transaction script.
    pub fn tx_script(mut self, tx_script: TransactionScript) -> Self {
        self.tx_script = Some(tx_script);
        self
    }

    /// Sets the transaction script arguments.
    pub fn tx_script_args(mut self, tx_script_args: Word) -> Self {
        self.tx_script_args = tx_script_args;
        self
    }

    /// Sets the transaction script, script arguments, and advice map entries required to execute
    /// the provided [`SendNotesTransactionScript`].
    pub fn send_notes_script(mut self, script: &SendNotesTransactionScript) -> Self {
        for (key, value) in script.advice_entries() {
            self.advice_inputs.map.insert(*key, value.clone());
        }
        self.tx_script(script.tx_script().clone())
            .tx_script_args(script.tx_script_args())
    }

    /// Sets the desired auth arguments.
    pub fn auth_args(mut self, auth_args: Word) -> Self {
        self.auth_args = auth_args;
        self
    }

    /// Extends the note arguments map with the provided one.
    pub fn extend_note_args(mut self, note_args: BTreeMap<NoteId, Word>) -> Self {
        self.note_args.extend(note_args);
        self
    }

    /// Adds a single expected output note.
    ///
    /// A [`RawOutputNote::Partial`] note is ignored, since it does not carry the recipient details
    /// required to reconstruct the note.
    pub fn expected_output_note(mut self, output_note: RawOutputNote) -> Self {
        if let RawOutputNote::Full(note) = output_note {
            self.expected_output_notes.push(note);
        }
        self
    }

    /// Extends the expected output notes.
    ///
    /// This is the iterator equivalent of [`Self::expected_output_note`].
    pub fn expected_output_notes(mut self, output_notes: Vec<RawOutputNote>) -> Self {
        let output_notes = output_notes.into_iter().filter_map(|note| match note {
            RawOutputNote::Full(note) => Some(note),
            RawOutputNote::Partial(_) => None,
        });
        self.expected_output_notes.extend(output_notes);
        self
    }

    /// Adds a new signature for the message and the public key.
    pub fn add_signature(
        mut self,
        pub_key: PublicKeyCommitment,
        message: Word,
        signature: Signature,
    ) -> Self {
        self.signatures.push((pub_key, message, signature));
        self
    }

    /// Adds a note script to the context for testing.
    pub fn add_note_script(mut self, script: NoteScript) -> Self {
        self.note_scripts.insert(script.root(), script);
        self
    }

    /// Sets the [`SourceManagerSync`] on the [`MockTransaction`] that will be built.
    ///
    /// This source manager should contain the sources of all involved scripts and account code in
    /// order to provide better error messages if an error occurs.
    pub fn with_source_manager(mut self, source_manager: Arc<dyn SourceManagerSync>) -> Self {
        self.source_manager = Some(source_manager);
        self
    }

    /// Disables lazy loading.
    ///
    /// Only affects [`MockTransaction::execute_code`] and causes the host to _not_ handle lazy
    /// loading events.
    pub fn disable_lazy_loading(mut self) -> Self {
        self.is_lazy_loading_enabled = false;
        self
    }

    /// Builds the [`MockTransaction`].
    ///
    /// The configured account and input notes are resolved into [`TransactionInputs`] against the
    /// [`Self::reference_block`] (defaulting to the chain's latest block) through
    /// [`MockChain::get_transaction_inputs`], and the remaining configuration is assembled into the
    /// [`MockTransaction`].
    ///
    /// [`TransactionInputs`]: miden_protocol::transaction::TransactionInputs
    pub fn build(self) -> anyhow::Result<MockTransaction> {
        let account = self.chain.resolve_tx_account(self.input)?;

        let mut tx_inputs = match self.reference_block {
            Some(reference_block) => {
                let latest_block = self.chain.latest_block_header().block_num();
                anyhow::ensure!(
                    reference_block <= latest_block,
                    "reference block {reference_block} is out of range (latest {latest_block})",
                );

                self.chain.get_transaction_inputs_at(
                    reference_block,
                    &account,
                    &self.authenticated_notes,
                    &self.unauthenticated_notes,
                )
            },
            None => self.chain.get_transaction_inputs(
                &account,
                &self.authenticated_notes,
                &self.unauthenticated_notes,
            ),
        }
        .context("failed to resolve transaction inputs from mock chain")?;

        let mut tx_args = TransactionArgs::default().with_note_args(self.note_args);
        if let Some(tx_script) = self.tx_script {
            tx_args = tx_args.with_tx_script_and_args(tx_script, self.tx_script_args);
        }
        tx_args = tx_args.with_auth_args(self.auth_args);
        tx_args.extend_advice_inputs(self.advice_inputs);
        tx_args.extend_output_note_recipients(&self.expected_output_notes);
        for (public_key_commitment, message, signature) in self.signatures {
            tx_args.add_signature(public_key_commitment, message, signature);
        }
        tx_inputs.set_tx_args(tx_args);

        let mast_store = TransactionMastStore::new();
        mast_store.load_account_code(tx_inputs.account().code());
        for (account, _) in self.foreign_account_inputs.values() {
            mast_store.insert(account.code().mast());
        }

        let source_manager =
            self.source_manager.unwrap_or_else(|| Arc::new(DefaultSourceManager::default()));

        Ok(MockTransaction {
            account,
            expected_output_notes: self.expected_output_notes,
            foreign_account_inputs: self.foreign_account_inputs,
            tx_inputs,
            mast_store,
            authenticator: self.authenticator,
            source_manager,
            note_scripts: self.note_scripts,
            is_lazy_loading_enabled: self.is_lazy_loading_enabled,
        })
    }
}
