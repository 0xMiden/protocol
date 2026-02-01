use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use anyhow::Context;
use miden_block_prover::LocalBlockProver;
use miden_processor::DeserializationError;
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
use miden_protocol::account::auth::{AuthSecretKey, PublicKey};
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{Account, AccountId, PartialAccount};
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::block::account_tree::{AccountTree, AccountWitness};
use miden_protocol::block::nullifier_tree::{NullifierTree, NullifierWitness};
use miden_protocol::block::{
    BlockHeader,
    BlockInputs,
    BlockNumber,
    Blockchain,
    ProposedBlock,
    ProvenBlock,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::note::{Note, NoteHeader, NoteId, NoteInclusionProof, Nullifier};
use miden_protocol::transaction::{
    ExecutedTransaction,
    InputNote,
    InputNotes,
    OutputNote,
    PartialBlockchain,
    ProvenTransaction,
    TransactionInputs,
};
use miden_tx::LocalTransactionProver;
use miden_tx::auth::BasicAuthenticator;
use miden_tx::utils::{ByteReader, Deserializable, Serializable};
use miden_tx_batch_prover::LocalBatchProver;
use winterfell::ByteWriter;

use super::note::MockChainNote;
use crate::{MockChainBuilder, TransactionContextBuilder};

// MOCK CHAIN
// ================================================================================================

/// The [`MockChain`] simulates a simplified blockchain environment for testing purposes.
///
/// The typical usage of a mock chain is:
/// - Creating it using a [`MockChainBuilder`], which allows adding accounts and notes to the
///   genesis state.
/// - Creating transactions against the chain state and executing them.
/// - Adding executed or proven transactions to the set of pending transactions (the "mempool"),
///   e.g. using [`MockChain::add_pending_executed_transaction`].
/// - Proving a block, which adds all pending transactions to the chain state, e.g. using
///   [`MockChain::prove_next_block`].
///
/// The mock chain uses the batch and block provers underneath to process pending transactions, so
/// the generated blocks are realistic and indistinguishable from a real node. The only caveat is
/// that no real ZK proofs are generated or validated as part of transaction, batch or block
/// building.
///
/// # Examples
///
/// ## Executing a simple transaction
/// ```
/// # use anyhow::Result;
/// # use miden_protocol::{
/// #    asset::{Asset, FungibleAsset},
/// #    note::NoteType,
/// # };
/// # use miden_testing::{Auth, MockChain};
/// #
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<()> {
/// // Build a genesis state for a mock chain using a MockChainBuilder.
/// // --------------------------------------------------------------------------------------------
///
/// let mut builder = MockChain::builder();
///
/// // Add a recipient wallet.
/// let receiver = builder.add_existing_wallet(Auth::BasicAuth)?;
///
/// // Add a wallet with assets.
/// let sender = builder.add_existing_wallet(Auth::IncrNonce)?;
///
/// let fungible_asset = FungibleAsset::mock(10).unwrap_fungible();
/// // Add a P2ID note with a fungible asset to the chain.
/// let note = builder.add_p2id_note(
///     sender.id(),
///     receiver.id(),
///     &[Asset::Fungible(fungible_asset)],
///     NoteType::Public,
/// )?;
///
/// let mut mock_chain: MockChain = builder.build()?;
///
/// // Create a transaction against the receiver account consuming the note.
/// // --------------------------------------------------------------------------------------------
///
/// let transaction = mock_chain
///     .build_tx_context(receiver.id(), &[note.id()], &[])?
///     .build()?
///     .execute()
///     .await?;
///
/// // Add the transaction to the chain state.
/// // --------------------------------------------------------------------------------------------
///
/// // Add the transaction to the mock chain's "mempool" of pending transactions.
/// mock_chain.add_pending_executed_transaction(&transaction)?;
///
/// // Prove the next block to include the transaction in the chain state.
/// mock_chain.prove_next_block()?;
///
/// // The receiver account should now have the asset in its account vault.
/// assert_eq!(
///     mock_chain
///         .committed_account(receiver.id())?
///         .vault()
///         .get_balance(fungible_asset.faucet_id())?,
///     fungible_asset.amount()
/// );
/// # Ok(())
/// # }
/// ```
///
/// ## Create mock objects and build a transaction context
///
/// ```
/// # use anyhow::Result;
/// # use miden_protocol::{Felt, asset::{Asset, FungibleAsset}, note::NoteType};
/// # use miden_testing::{Auth, MockChain, TransactionContextBuilder};
/// #
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<()> {
/// let mut builder = MockChain::builder();
///
/// let faucet = builder.create_new_faucet(Auth::BasicAuth, "USDT", 100_000)?;
/// let asset = Asset::from(FungibleAsset::new(faucet.id(), 10)?);
///
/// let sender = builder.create_new_wallet(Auth::BasicAuth)?;
/// let target = builder.create_new_wallet(Auth::BasicAuth)?;
///
/// let note = builder.add_p2id_note(faucet.id(), target.id(), &[asset], NoteType::Public)?;
///
/// let mock_chain = builder.build()?;
///
/// // The target account is a new account so we move it into the build_tx_context, since the
/// // chain's committed accounts do not yet contain it.
/// let tx_context = mock_chain.build_tx_context(target, &[note.id()], &[])?.build()?;
/// let executed_transaction = tx_context.execute().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct MockChain {
    /// An append-only structure used to represent the history of blocks produced for this chain.
    chain: Blockchain,

    /// History of produced blocks.
    blocks: Vec<ProvenBlock>,

    /// Tree containing all nullifiers.
    nullifier_tree: NullifierTree,

    /// Tree containing the state commitments of all accounts.
    account_tree: AccountTree,

    /// Transactions that have been submitted to the chain but have not yet been included in a
    /// block.
    pending_transactions: Vec<ProvenTransaction>,

    /// NoteID |-> MockChainNote mapping to simplify note retrieval.
    committed_notes: BTreeMap<NoteId, MockChainNote>,

    /// AccountId |-> Account mapping to simplify transaction creation. Latest known account
    /// state is maintained for each account here.
    ///
    /// The map always holds the most recent *public* state known for every account. For private
    /// accounts, however, transactions do not emit the post-transaction state, so their entries
    /// remain at the last observed state.
    committed_accounts: BTreeMap<AccountId, Account>,

    /// AccountId |-> AccountAuthenticator mapping to store the authenticator for accounts to
    /// simplify transaction creation.
    account_authenticators: BTreeMap<AccountId, AccountAuthenticator>,

    /// Validator secret key used for signing blocks.
    validator_secret_key: SecretKey,
}

impl MockChain {
    // CONSTANTS
    // ----------------------------------------------------------------------------------------

    /// The timestamp of the genesis block of the chain. Chosen as an easily readable number.
    pub const TIMESTAMP_START_SECS: u32 = 1700000000;

    /// The number of seconds by which a block's timestamp increases over the previous block's
    /// timestamp, unless overwritten when calling [`Self::prove_next_block_at`].
    pub const TIMESTAMP_STEP_SECS: u32 = 10;

    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------

    /// Creates a new `MockChain` with an empty genesis block.
    pub fn new() -> Self {
        Self::builder().build().expect("empty chain should be valid")
    }

    /// Returns a new, empty [`MockChainBuilder`].
    pub fn builder() -> MockChainBuilder {
        MockChainBuilder::new()
    }

    /// Creates a new `MockChain` with the provided genesis block and account tree.
    pub(super) fn from_genesis_block(
        genesis_block: ProvenBlock,
        account_tree: AccountTree,
        account_authenticators: BTreeMap<AccountId, AccountAuthenticator>,
        secret_key: SecretKey,
    ) -> anyhow::Result<Self> {
        let mut chain = MockChain {
            chain: Blockchain::default(),
            blocks: vec![],
            nullifier_tree: NullifierTree::default(),
            account_tree,
            pending_transactions: Vec::new(),
            committed_notes: BTreeMap::new(),
            committed_accounts: BTreeMap::new(),
            account_authenticators,
            validator_secret_key: secret_key,
        };

        // We do not have to apply the tree changes, because the account tree is already initialized
        // and the nullifier tree is empty at genesis.
        chain
            .apply_block(genesis_block)
            .context("failed to build account from builder")?;

        debug_assert_eq!(chain.blocks.len(), 1);
        debug_assert_eq!(chain.committed_accounts.len(), chain.account_tree.num_accounts());

        Ok(chain)
    }

    // PUBLIC ACCESSORS
    // ----------------------------------------------------------------------------------------

    /// Returns a reference to the current [`Blockchain`].
    pub fn blockchain(&self) -> &Blockchain {
        &self.chain
    }

    /// Returns a [`PartialBlockchain`] instantiated from the current [`Blockchain`] and with
    /// authentication paths for all all blocks in the chain.
    pub fn latest_partial_blockchain(&self) -> PartialBlockchain {
        // We have to exclude the latest block because we need to fetch the state of the chain at
        // that latest block, which does not include itself.
        let block_headers =
            self.blocks.iter().map(|b| b.header()).take(self.blocks.len() - 1).cloned();

        PartialBlockchain::from_blockchain(&self.chain, block_headers)
            .expect("blockchain should be valid by construction")
    }

    /// Creates a new [`PartialBlockchain`] with all reference blocks in the given iterator except
    /// for the latest block header in the chain and returns that latest block header.
    ///
    /// The intended use for the latest block header is to become the reference block of a new
    /// transaction batch or block.
    pub fn latest_selective_partial_blockchain(
        &self,
        reference_blocks: impl IntoIterator<Item = BlockNumber>,
    ) -> anyhow::Result<(BlockHeader, PartialBlockchain)> {
        let latest_block_header = self.latest_block_header();

        self.selective_partial_blockchain(latest_block_header.block_num(), reference_blocks)
    }

    /// Creates a new [`PartialBlockchain`] with all reference blocks in the given iterator except
    /// for the reference block header in the chain and returns that reference block header.
    ///
    /// The intended use for the reference block header is to become the reference block of a new
    /// transaction batch or block.
    pub fn selective_partial_blockchain(
        &self,
        reference_block: BlockNumber,
        reference_blocks: impl IntoIterator<Item = BlockNumber>,
    ) -> anyhow::Result<(BlockHeader, PartialBlockchain)> {
        let reference_block_header = self.block_header(reference_block.as_usize());
        // Deduplicate block numbers so each header will be included just once. This is required so
        // PartialBlockchain::from_blockchain does not panic.
        let reference_blocks: BTreeSet<_> = reference_blocks.into_iter().collect();

        // Include all block headers except the reference block itself.
        let mut block_headers = Vec::new();

        for block_ref_num in &reference_blocks {
            let block_index = block_ref_num.as_usize();
            let block = self
                .blocks
                .get(block_index)
                .ok_or_else(|| anyhow::anyhow!("block {} not found in chain", block_ref_num))?;
            let block_header = block.header().clone();
            // Exclude the reference block header.
            if block_header.commitment() != reference_block_header.commitment() {
                block_headers.push(block_header);
            }
        }

        let partial_blockchain =
            PartialBlockchain::from_blockchain_at(&self.chain, reference_block, block_headers)?;

        Ok((reference_block_header, partial_blockchain))
    }

    /// Returns a map of [`AccountWitness`]es for the requested account IDs from the current
    /// [`AccountTree`] in the chain.
    pub fn account_witnesses(
        &self,
        account_ids: impl IntoIterator<Item = AccountId>,
    ) -> BTreeMap<AccountId, AccountWitness> {
        let mut account_witnesses = BTreeMap::new();

        for account_id in account_ids {
            let witness = self.account_tree.open(account_id);
            account_witnesses.insert(account_id, witness);
        }

        account_witnesses
    }

    /// Returns a map of [`NullifierWitness`]es for the requested nullifiers from the current
    /// [`NullifierTree`] in the chain.
    pub fn nullifier_witnesses(
        &self,
        nullifiers: impl IntoIterator<Item = Nullifier>,
    ) -> BTreeMap<Nullifier, NullifierWitness> {
        let mut nullifier_proofs = BTreeMap::new();

        for nullifier in nullifiers {
            let witness = self.nullifier_tree.open(&nullifier);
            nullifier_proofs.insert(nullifier, witness);
        }

        nullifier_proofs
    }

    /// Returns all note inclusion proofs for the requested note IDs, **if they are available for
    /// consumption**. Therefore, not all of the requested notes will be guaranteed to have an entry
    /// in the returned map.
    pub fn unauthenticated_note_proofs(
        &self,
        notes: impl IntoIterator<Item = NoteId>,
    ) -> BTreeMap<NoteId, NoteInclusionProof> {
        let mut proofs = BTreeMap::default();
        for note in notes {
            if let Some(input_note) = self.committed_notes.get(&note) {
                proofs.insert(note, input_note.inclusion_proof().clone());
            }
        }

        proofs
    }

    /// Returns the genesis [`BlockHeader`] of the chain.
    pub fn genesis_block_header(&self) -> BlockHeader {
        self.block_header(BlockNumber::GENESIS.as_usize())
    }

    /// Returns the latest [`BlockHeader`] in the chain.
    pub fn latest_block_header(&self) -> BlockHeader {
        let chain_tip =
            self.chain.chain_tip().expect("chain should contain at least the genesis block");
        self.blocks[chain_tip.as_usize()].header().clone()
    }

    /// Returns the latest [`ProvenBlock`] in the chain.
    pub fn latest_block(&self) -> ProvenBlock {
        let chain_tip =
            self.chain.chain_tip().expect("chain should contain at least the genesis block");
        self.blocks[chain_tip.as_usize()].clone()
    }

    /// Returns the [`BlockHeader`] with the specified `block_number`.
    ///
    /// # Panics
    ///
    /// - If the block number does not exist in the chain.
    pub fn block_header(&self, block_number: usize) -> BlockHeader {
        self.blocks[block_number].header().clone()
    }

    /// Returns a reference to slice of all created proven blocks.
    pub fn proven_blocks(&self) -> &[ProvenBlock] {
        &self.blocks
    }

    /// Returns the [`AccountId`] of the faucet whose assets are accepted for fee payments in the
    /// transaction kernel, or in other words, the native asset of the blockchain.
    ///
    /// This value is taken from the genesis block because it is assumed not to change throughout
    /// the chain's lifecycle.
    pub fn native_asset_id(&self) -> AccountId {
        self.genesis_block_header().fee_parameters().native_asset_id()
    }

    /// Returns a reference to the nullifier tree.
    pub fn nullifier_tree(&self) -> &NullifierTree {
        &self.nullifier_tree
    }

    /// Returns the map of note IDs to committed notes.
    ///
    /// These notes are committed for authenticated consumption.
    pub fn committed_notes(&self) -> &BTreeMap<NoteId, MockChainNote> {
        &self.committed_notes
    }

    /// Returns an [`InputNote`] for the given note ID. If the note does not exist or is not
    /// public, `None` is returned.
    pub fn get_public_note(&self, note_id: &NoteId) -> Option<InputNote> {
        let note = self.committed_notes.get(note_id)?;
        note.clone().try_into().ok()
    }

    /// Returns a reference to the account identified by the given account ID.
    ///
    /// The account is retrieved with the latest state known to the [`MockChain`].
    pub fn committed_account(&self, account_id: AccountId) -> anyhow::Result<&Account> {
        self.committed_accounts
            .get(&account_id)
            .with_context(|| format!("account {account_id} not found in committed accounts"))
    }

    /// Returns a reference to the [`AccountTree`] of the chain.
    pub fn account_tree(&self) -> &AccountTree {
        &self.account_tree
    }

    // BATCH APIS
    // ----------------------------------------------------------------------------------------

    /// Proposes a new transaction batch from the provided transactions and returns it.
    ///
    /// This method does not modify the chain state.
    pub fn propose_transaction_batch<I>(
        &self,
        txs: impl IntoIterator<Item = ProvenTransaction, IntoIter = I>,
    ) -> anyhow::Result<ProposedBatch>
    where
        I: Iterator<Item = ProvenTransaction> + Clone,
    {
        let transactions: Vec<_> = txs.into_iter().map(alloc::sync::Arc::new).collect();

        let (batch_reference_block, partial_blockchain, unauthenticated_note_proofs) = self
            .get_batch_inputs(
                transactions.iter().map(|tx| tx.ref_block_num()),
                transactions
                    .iter()
                    .flat_map(|tx| tx.unauthenticated_notes().map(NoteHeader::id)),
            )?;

        Ok(ProposedBatch::new(
            transactions,
            batch_reference_block,
            partial_blockchain,
            unauthenticated_note_proofs,
        )?)
    }

    /// Mock-proves a proposed transaction batch from the provided [`ProposedBatch`] and returns it.
    ///
    /// This method does not modify the chain state.
    pub fn prove_transaction_batch(
        &self,
        proposed_batch: ProposedBatch,
    ) -> anyhow::Result<ProvenBatch> {
        let batch_prover = LocalBatchProver::new(0);
        Ok(batch_prover.prove_dummy(proposed_batch)?)
    }

    // BLOCK APIS
    // ----------------------------------------------------------------------------------------

    /// Proposes a new block from the provided batches with the given timestamp and returns it.
    ///
    /// This method does not modify the chain state.
    pub fn propose_block_at<I>(
        &self,
        batches: impl IntoIterator<Item = ProvenBatch, IntoIter = I>,
        timestamp: u32,
    ) -> anyhow::Result<ProposedBlock>
    where
        I: Iterator<Item = ProvenBatch> + Clone,
    {
        let batches: Vec<_> = batches.into_iter().collect();

        let block_inputs = self
            .get_block_inputs(batches.iter())
            .context("could not retrieve block inputs")?;

        let proposed_block = ProposedBlock::new_at(block_inputs, batches, timestamp)
            .context("failed to create proposed block")?;

        Ok(proposed_block)
    }

    /// Proposes a new block from the provided batches and returns it.
    ///
    /// This method does not modify the chain state.
    pub fn propose_block<I>(
        &self,
        batches: impl IntoIterator<Item = ProvenBatch, IntoIter = I>,
    ) -> anyhow::Result<ProposedBlock>
    where
        I: Iterator<Item = ProvenBatch> + Clone,
    {
        // We can't access system time because we are in a no-std environment, so we use the
        // minimally correct next timestamp.
        let timestamp = self.latest_block_header().timestamp() + 1;

        self.propose_block_at(batches, timestamp)
    }

    // TRANSACTION APIS
    // ----------------------------------------------------------------------------------------

    /// Initializes a [`TransactionContextBuilder`] for executing against a specific block number.
    ///
    /// Depending on the provided `input`, the builder is initialized differently:
    /// - [`TxContextInput::AccountId`]: Initialize the builder with [`TransactionInputs`] fetched
    ///   from the chain for the public account identified by the ID.
    /// - [`TxContextInput::Account`]: Initialize the builder with [`TransactionInputs`] where the
    ///   account is passed as-is to the inputs.
    ///
    /// In all cases, if the chain contains authenticator for the account, they are added to the
    /// builder.
    ///
    /// [`TxContextInput::Account`] can be used to build a chain of transactions against the same
    /// account that build on top of each other. For example, transaction A modifies an account
    /// from state 0 to 1, and transaction B modifies it from state 1 to 2.
    pub fn build_tx_context_at(
        &self,
        reference_block: impl Into<BlockNumber>,
        input: impl Into<TxContextInput>,
        note_ids: &[NoteId],
        unauthenticated_notes: &[Note],
    ) -> anyhow::Result<TransactionContextBuilder> {
        let input = input.into();
        let reference_block = reference_block.into();

        let authenticator = self.account_authenticators.get(&input.id());
        let authenticator =
            authenticator.and_then(|authenticator| authenticator.authenticator().cloned());

        anyhow::ensure!(
            reference_block.as_usize() < self.blocks.len(),
            "reference block {reference_block} is out of range (latest {})",
            self.latest_block_header().block_num()
        );

        let account = match input {
            TxContextInput::AccountId(account_id) => {
                if account_id.is_private() {
                    return Err(anyhow::anyhow!(
                        "transaction contexts for private accounts should be created with TxContextInput::Account"
                    ));
                }

                self.committed_accounts
                    .get(&account_id)
                    .with_context(|| {
                        format!("account {account_id} not found in committed accounts")
                    })?
                    .clone()
            },
            TxContextInput::Account(account) => account,
        };

        let tx_inputs = self
            .get_transaction_inputs_at(reference_block, &account, note_ids, unauthenticated_notes)
            .context("failed to gather transaction inputs")?;

        let tx_context_builder = TransactionContextBuilder::new(account)
            .authenticator(authenticator)
            .tx_inputs(tx_inputs);

        Ok(tx_context_builder)
    }

    /// Initializes a [`TransactionContextBuilder`] for executing against the last block header.
    ///
    /// This is a wrapper around [`Self::build_tx_context_at`] which uses the latest block as the
    /// reference block. See that function's docs for details.
    pub fn build_tx_context(
        &self,
        input: impl Into<TxContextInput>,
        note_ids: &[NoteId],
        unauthenticated_notes: &[Note],
    ) -> anyhow::Result<TransactionContextBuilder> {
        let reference_block = self.latest_block_header().block_num();
        self.build_tx_context_at(reference_block, input, note_ids, unauthenticated_notes)
    }

    // INPUTS APIS
    // ----------------------------------------------------------------------------------------

    /// Returns a valid [`TransactionInputs`] for the specified entities, executing against
    /// a specific block number.
    pub fn get_transaction_inputs_at(
        &self,
        reference_block: BlockNumber,
        account: impl Into<PartialAccount>,
        notes: &[NoteId],
        unauthenticated_notes: &[Note],
    ) -> anyhow::Result<TransactionInputs> {
        let ref_block = self.block_header(reference_block.as_usize());

        let mut input_notes = vec![];
        let mut block_headers_map: BTreeMap<BlockNumber, BlockHeader> = BTreeMap::new();
        for note in notes {
            let input_note: InputNote = self
                .committed_notes
                .get(note)
                .with_context(|| format!("note with id {note} not found"))?
                .clone()
                .try_into()
                .with_context(|| {
                    format!("failed to convert mock chain note with id {note} into input note")
                })?;

            let note_block_num = input_note
                .location()
                .with_context(|| format!("note location not available: {note}"))?
                .block_num();

            if note_block_num > ref_block.block_num() {
                anyhow::bail!(
                    "note with ID {note} was created in block {note_block_num} which is larger than the reference block number {}",
                    ref_block.block_num()
                )
            }

            if note_block_num != ref_block.block_num() {
                let block_header = self
                    .blocks
                    .get(note_block_num.as_usize())
                    .with_context(|| format!("block {note_block_num} not found in chain"))?
                    .header()
                    .clone();
                block_headers_map.insert(note_block_num, block_header);
            }

            input_notes.push(input_note);
        }

        for note in unauthenticated_notes {
            input_notes.push(InputNote::Unauthenticated { note: note.clone() })
        }

        let block_headers = block_headers_map.values();
        let (_, partial_blockchain) = self.selective_partial_blockchain(
            reference_block,
            block_headers.map(BlockHeader::block_num),
        )?;

        let input_notes = InputNotes::new(input_notes)?;

        Ok(TransactionInputs::new(
            account.into(),
            ref_block.clone(),
            partial_blockchain,
            input_notes,
        )?)
    }

    /// Returns a valid [`TransactionInputs`] for the specified entities.
    pub fn get_transaction_inputs(
        &self,
        account: impl Into<PartialAccount>,
        notes: &[NoteId],
        unauthenticated_notes: &[Note],
    ) -> anyhow::Result<TransactionInputs> {
        let latest_block_num = self.latest_block_header().block_num();
        self.get_transaction_inputs_at(latest_block_num, account, notes, unauthenticated_notes)
    }

    /// Returns inputs for a transaction batch for all the reference blocks of the provided
    /// transactions.
    pub fn get_batch_inputs(
        &self,
        tx_reference_blocks: impl IntoIterator<Item = BlockNumber>,
        unauthenticated_notes: impl Iterator<Item = NoteId>,
    ) -> anyhow::Result<(BlockHeader, PartialBlockchain, BTreeMap<NoteId, NoteInclusionProof>)>
    {
        // Fetch note proofs for notes that exist in the chain.
        let unauthenticated_note_proofs = self.unauthenticated_note_proofs(unauthenticated_notes);

        // We also need to fetch block inclusion proofs for any of the blocks that contain
        // unauthenticated notes for which we want to prove inclusion.
        let required_blocks = tx_reference_blocks.into_iter().chain(
            unauthenticated_note_proofs
                .values()
                .map(|note_proof| note_proof.location().block_num()),
        );

        let (batch_reference_block, partial_block_chain) =
            self.latest_selective_partial_blockchain(required_blocks)?;

        Ok((batch_reference_block, partial_block_chain, unauthenticated_note_proofs))
    }

    /// Gets foreign account inputs to execute FPI transactions.
    ///
    /// Used in tests to get foreign account inputs for FPI calls.
    pub fn get_foreign_account_inputs(
        &self,
        account_id: AccountId,
    ) -> anyhow::Result<(Account, AccountWitness)> {
        let account = self.committed_account(account_id)?.clone();

        let account_witness = self.account_tree().open(account_id);
        assert_eq!(account_witness.state_commitment(), account.commitment());

        Ok((account, account_witness))
    }

    /// Gets the inputs for a block for the provided batches.
    pub fn get_block_inputs<'batch, I>(
        &self,
        batch_iter: impl IntoIterator<Item = &'batch ProvenBatch, IntoIter = I>,
    ) -> anyhow::Result<BlockInputs>
    where
        I: Iterator<Item = &'batch ProvenBatch> + Clone,
    {
        let batch_iterator = batch_iter.into_iter();

        let unauthenticated_note_proofs =
            self.unauthenticated_note_proofs(batch_iterator.clone().flat_map(|batch| {
                batch.input_notes().iter().filter_map(|note| note.header().map(NoteHeader::id))
            }));

        let (block_reference_block, partial_blockchain) = self
            .latest_selective_partial_blockchain(
                batch_iterator.clone().map(ProvenBatch::reference_block_num).chain(
                    unauthenticated_note_proofs.values().map(|proof| proof.location().block_num()),
                ),
            )?;

        let account_witnesses =
            self.account_witnesses(batch_iterator.clone().flat_map(ProvenBatch::updated_accounts));

        let nullifier_proofs =
            self.nullifier_witnesses(batch_iterator.flat_map(ProvenBatch::created_nullifiers));

        Ok(BlockInputs::new(
            block_reference_block,
            partial_blockchain,
            account_witnesses,
            nullifier_proofs,
            unauthenticated_note_proofs,
        ))
    }

    // PUBLIC MUTATORS
    // ----------------------------------------------------------------------------------------

    /// Proves the next block in the mock chain.
    ///
    /// This will commit all the currently pending transactions into the chain state.
    pub fn prove_next_block(&mut self) -> anyhow::Result<ProvenBlock> {
        self.prove_and_apply_block(None)
    }

    /// Proves the next block in the mock chain at the given timestamp.
    ///
    /// This will commit all the currently pending transactions into the chain state.
    pub fn prove_next_block_at(&mut self, timestamp: u32) -> anyhow::Result<ProvenBlock> {
        self.prove_and_apply_block(Some(timestamp))
    }

    /// Proves new blocks until the block with the given target block number has been created.
    ///
    /// For example, if the latest block is `5` and this function is called with `10`, then blocks
    /// `6..=10` will be created and block 10 will be returned.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - the given block number is smaller or equal to the number of the latest block in the chain.
    pub fn prove_until_block(
        &mut self,
        target_block_num: impl Into<BlockNumber>,
    ) -> anyhow::Result<ProvenBlock> {
        let target_block_num = target_block_num.into();
        let latest_block_num = self.latest_block_header().block_num();
        assert!(
            target_block_num > latest_block_num,
            "target block number must be greater than the number of the latest block in the chain"
        );

        let mut last_block = None;
        for _ in latest_block_num.as_usize()..target_block_num.as_usize() {
            last_block = Some(self.prove_next_block()?);
        }

        Ok(last_block.expect("at least one block should have been created"))
    }

    // PUBLIC MUTATORS (PENDING APIS)
    // ----------------------------------------------------------------------------------------

    /// Adds the given [`ExecutedTransaction`] to the list of pending transactions.
    ///
    /// A block has to be created to apply the transaction effects to the chain state, e.g. using
    /// [`MockChain::prove_next_block`].
    pub fn add_pending_executed_transaction(
        &mut self,
        transaction: &ExecutedTransaction,
    ) -> anyhow::Result<()> {
        // Transform the executed tx into a proven tx with a dummy proof.
        let proven_tx = LocalTransactionProver::default()
            .prove_dummy(transaction.clone())
            .context("failed to dummy-prove executed transaction into proven transaction")?;

        self.pending_transactions.push(proven_tx);

        Ok(())
    }

    /// Adds the given [`ProvenTransaction`] to the list of pending transactions.
    ///
    /// A block has to be created to apply the transaction effects to the chain state, e.g. using
    /// [`MockChain::prove_next_block`].
    pub fn add_pending_proven_transaction(&mut self, transaction: ProvenTransaction) {
        self.pending_transactions.push(transaction);
    }

    // PRIVATE HELPERS
    // ----------------------------------------------------------------------------------------

    /// Applies the given block to the chain state, which means:
    ///
    /// - Insert account and nullifiers into the respective trees.
    /// - Updated accounts from the block are updated in the committed accounts.
    /// - Created notes are inserted into the committed notes.
    /// - Consumed notes are removed from the committed notes.
    /// - The block is appended to the [`BlockChain`] and the list of proven blocks.
    fn apply_block(&mut self, proven_block: ProvenBlock) -> anyhow::Result<()> {
        for account_update in proven_block.body().updated_accounts() {
            self.account_tree
                .insert(account_update.account_id(), account_update.final_state_commitment())
                .context("failed to insert account update into account tree")?;
        }

        for nullifier in proven_block.body().created_nullifiers() {
            self.nullifier_tree
                .mark_spent(*nullifier, proven_block.header().block_num())
                .context("failed to mark block nullifier as spent")?;

            // TODO: Remove from self.committed_notes. This is not critical to have for now. It is
            // not straightforward, because committed_notes are indexed by note IDs rather than
            // nullifiers, so we'll have to create a second index to do this.
        }

        for account_update in proven_block.body().updated_accounts() {
            match account_update.details() {
                AccountUpdateDetails::Delta(account_delta) => {
                    if account_delta.is_full_state() {
                        let account = Account::try_from(account_delta)
                            .context("failed to convert full state delta into full account")?;
                        self.committed_accounts.insert(account.id(), account.clone());
                    } else {
                        let committed_account = self
                            .committed_accounts
                            .get_mut(&account_update.account_id())
                            .ok_or_else(|| {
                                anyhow::anyhow!("account delta in block for non-existent account")
                            })?;
                        committed_account
                            .apply_delta(account_delta)
                            .context("failed to apply account delta")?;
                    }
                },
                // No state to keep for private accounts other than the commitment on the account
                // tree
                AccountUpdateDetails::Private => {},
            }
        }

        let notes_tree = proven_block.body().compute_block_note_tree();
        for (block_note_index, created_note) in proven_block.body().output_notes() {
            let note_path = notes_tree.open(block_note_index);
            let note_inclusion_proof = NoteInclusionProof::new(
                proven_block.header().block_num(),
                block_note_index.leaf_index_value(),
                note_path,
            )
            .context("failed to create inclusion proof for output note")?;

            if let OutputNote::Full(note) = created_note {
                self.committed_notes
                    .insert(note.id(), MockChainNote::Public(note.clone(), note_inclusion_proof));
            } else {
                self.committed_notes.insert(
                    created_note.id(),
                    MockChainNote::Private(
                        created_note.id(),
                        created_note.metadata().clone(),
                        note_inclusion_proof,
                    ),
                );
            }
        }

        debug_assert_eq!(
            self.chain.commitment(),
            proven_block.header().chain_commitment(),
            "current mock chain commitment and new block's chain commitment should match"
        );
        debug_assert_eq!(
            BlockNumber::from(self.chain.as_mmr().forest().num_leaves() as u32),
            proven_block.header().block_num(),
            "current mock chain length and new block's number should match"
        );

        self.chain.push(proven_block.header().commitment());
        self.blocks.push(proven_block);

        Ok(())
    }

    fn pending_transactions_to_batches(&mut self) -> anyhow::Result<Vec<ProvenBatch>> {
        // Batches must contain at least one transaction, so if there are no pending transactions,
        // return early.
        if self.pending_transactions.is_empty() {
            return Ok(vec![]);
        }

        let pending_transactions = core::mem::take(&mut self.pending_transactions);

        // TODO: Distribute the transactions into multiple batches if the transactions would not fit
        // into a single batch (according to max input notes, max output notes and max accounts).
        let proposed_batch = self.propose_transaction_batch(pending_transactions)?;
        let proven_batch = self.prove_transaction_batch(proposed_batch)?;

        Ok(vec![proven_batch])
    }

    /// Creates a new block in the mock chain.
    ///
    /// Block building is divided into two steps:
    ///
    /// 1. Build batches from pending transactions and a block from those batches. This results in a
    ///    block.
    /// 2. Insert all the account updates, nullifiers and notes from the block into the chain state.
    ///
    /// If a `timestamp` is provided, it will be set on the block.
    fn prove_and_apply_block(&mut self, timestamp: Option<u32>) -> anyhow::Result<ProvenBlock> {
        // Create batches from pending transactions.
        // ----------------------------------------------------------------------------------------

        let batches = self.pending_transactions_to_batches()?;

        // Create block.
        // ----------------------------------------------------------------------------------------

        let block_timestamp =
            timestamp.unwrap_or(self.latest_block_header().timestamp() + Self::TIMESTAMP_STEP_SECS);

        let proposed_block = self
            .propose_block_at(batches.clone(), block_timestamp)
            .context("failed to create proposed block")?;
        let proven_block = self.prove_block(proposed_block.clone())?;

        // Apply block.
        // ----------------------------------------------------------------------------------------

        self.apply_block(proven_block.clone()).context("failed to apply block")?;

        Ok(proven_block)
    }

    /// Proves proposed block alongside a corresponding list of batches.
    pub fn prove_block(&self, proposed_block: ProposedBlock) -> anyhow::Result<ProvenBlock> {
        let (header, body) = proposed_block.clone().into_header_and_body()?;
        let inputs = self.get_block_inputs(proposed_block.batches().as_slice())?;
        let block_proof = LocalBlockProver::new(MIN_PROOF_SECURITY_LEVEL).prove_dummy(
            proposed_block.batches().clone(),
            header.clone(),
            inputs,
        )?;
        let signature = self.validator_secret_key.sign(header.commitment());
        Ok(ProvenBlock::new_unchecked(header, body, signature, block_proof))
    }
}

impl Default for MockChain {
    fn default() -> Self {
        MockChain::new()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for MockChain {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.chain.write_into(target);
        self.blocks.write_into(target);
        self.nullifier_tree.write_into(target);
        self.account_tree.write_into(target);
        self.pending_transactions.write_into(target);
        self.committed_accounts.write_into(target);
        self.committed_notes.write_into(target);
        self.account_authenticators.write_into(target);
        self.validator_secret_key.write_into(target);
    }
}

impl Deserializable for MockChain {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let chain = Blockchain::read_from(source)?;
        let blocks = Vec::<ProvenBlock>::read_from(source)?;
        let nullifier_tree = NullifierTree::read_from(source)?;
        let account_tree = AccountTree::read_from(source)?;
        let pending_transactions = Vec::<ProvenTransaction>::read_from(source)?;
        let committed_accounts = BTreeMap::<AccountId, Account>::read_from(source)?;
        let committed_notes = BTreeMap::<NoteId, MockChainNote>::read_from(source)?;
        let account_authenticators =
            BTreeMap::<AccountId, AccountAuthenticator>::read_from(source)?;
        let secret_key = SecretKey::read_from(source)?;

        Ok(Self {
            chain,
            blocks,
            nullifier_tree,
            account_tree,
            pending_transactions,
            committed_notes,
            committed_accounts,
            account_authenticators,
            validator_secret_key: secret_key,
        })
    }
}

// ACCOUNT STATE
// ================================================================================================

/// Helper type for increased readability at call-sites. Indicates whether to build a new (nonce =
/// ZERO) or existing account (nonce = ONE).
pub enum AccountState {
    New,
    Exists,
}

// ACCOUNT AUTHENTICATOR
// ================================================================================================

/// A wrapper around the authenticator of an account.
#[derive(Debug, Clone)]
pub(super) struct AccountAuthenticator {
    authenticator: Option<BasicAuthenticator>,
}

impl AccountAuthenticator {
    pub fn new(authenticator: Option<BasicAuthenticator>) -> Self {
        Self { authenticator }
    }

    pub fn authenticator(&self) -> Option<&BasicAuthenticator> {
        self.authenticator.as_ref()
    }
}

impl PartialEq for AccountAuthenticator {
    fn eq(&self, other: &Self) -> bool {
        match (&self.authenticator, &other.authenticator) {
            (Some(a), Some(b)) => {
                a.keys().keys().zip(b.keys().keys()).all(|(a_key, b_key)| a_key == b_key)
            },
            (None, None) => true,
            _ => false,
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountAuthenticator {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.authenticator
            .as_ref()
            .map(|auth| {
                auth.keys()
                    .values()
                    .map(|(secret_key, public_key)| (secret_key, public_key.as_ref().clone()))
                    .collect::<Vec<_>>()
            })
            .write_into(target);
    }
}

impl Deserializable for AccountAuthenticator {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let authenticator = Option::<Vec<(AuthSecretKey, PublicKey)>>::read_from(source)?;

        let authenticator = authenticator.map(|keys| BasicAuthenticator::from_key_pairs(&keys));

        Ok(Self { authenticator })
    }
}

// TX CONTEXT INPUT
// ================================================================================================

/// Helper type to abstract over the inputs to [`MockChain::build_tx_context`]. See that method's
/// docs for details.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum TxContextInput {
    AccountId(AccountId),
    Account(Account),
}

impl TxContextInput {
    /// Returns the account ID that this input references.
    fn id(&self) -> AccountId {
        match self {
            TxContextInput::AccountId(account_id) => *account_id,
            TxContextInput::Account(account) => account.id(),
        }
    }
}

impl From<AccountId> for TxContextInput {
    fn from(account: AccountId) -> Self {
        Self::AccountId(account)
    }
}

impl From<Account> for TxContextInput {
    fn from(account: Account) -> Self {
        Self::Account(account)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountBuilder, AccountStorageMode};
    use miden_protocol::asset::{Asset, FungibleAsset};
    use miden_protocol::note::NoteType;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_SENDER,
    };
    use miden_standards::account::wallets::BasicWallet;

    use super::*;
    use crate::Auth;

    #[test]
    fn prove_until_block() -> anyhow::Result<()> {
        let mut chain = MockChain::new();
        let block = chain.prove_until_block(5)?;
        assert_eq!(block.header().block_num(), 5u32.into());
        assert_eq!(chain.proven_blocks().len(), 6);

        Ok(())
    }

    #[tokio::test]
    async fn private_account_state_update() -> anyhow::Result<()> {
        let faucet_id = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
        let account_builder = AccountBuilder::new([4; 32])
            .storage_mode(AccountStorageMode::Private)
            .with_component(BasicWallet);

        let mut builder = MockChain::builder();
        let account = builder.add_account_from_builder(
            Auth::BasicAuth,
            account_builder,
            AccountState::New,
        )?;

        let account_id = account.id();
        assert_eq!(account.nonce().as_int(), 0);

        let note_1 = builder.add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[Asset::Fungible(FungibleAsset::new(faucet_id, 1000u64).unwrap())],
            NoteType::Private,
        )?;

        let mut mock_chain = builder.build()?;
        mock_chain.prove_next_block()?;

        let tx = mock_chain
            .build_tx_context(TxContextInput::Account(account), &[], &[note_1])?
            .build()?
            .execute()
            .await?;

        mock_chain.add_pending_executed_transaction(&tx)?;
        mock_chain.prove_next_block()?;

        assert!(tx.final_account().nonce().as_int() > 0);
        assert_eq!(
            tx.final_account().commitment(),
            mock_chain.account_tree.open(account_id).state_commitment()
        );

        Ok(())
    }

    #[tokio::test]
    async fn mock_chain_serialization() {
        let mut builder = MockChain::builder();

        let mut notes = vec![];
        for i in 0..10 {
            let account = builder
                .add_account_from_builder(
                    Auth::BasicAuth,
                    AccountBuilder::new([i; 32]).with_component(BasicWallet),
                    AccountState::New,
                )
                .unwrap();
            let note = builder
                .add_p2id_note(
                    ACCOUNT_ID_SENDER.try_into().unwrap(),
                    account.id(),
                    &[Asset::Fungible(
                        FungibleAsset::new(
                            ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into().unwrap(),
                            1000u64,
                        )
                        .unwrap(),
                    )],
                    NoteType::Private,
                )
                .unwrap();
            notes.push((account, note));
        }

        let mut chain = builder.build().unwrap();
        for (account, note) in notes {
            let tx = chain
                .build_tx_context(TxContextInput::Account(account), &[], &[note])
                .unwrap()
                .build()
                .unwrap()
                .execute()
                .await
                .unwrap();
            chain.add_pending_executed_transaction(&tx).unwrap();
            chain.prove_next_block().unwrap();
        }

        let bytes = chain.to_bytes();

        let deserialized = MockChain::read_from_bytes(&bytes).unwrap();

        assert_eq!(chain.chain.as_mmr().peaks(), deserialized.chain.as_mmr().peaks());
        assert_eq!(chain.blocks, deserialized.blocks);
        assert_eq!(chain.nullifier_tree, deserialized.nullifier_tree);
        assert_eq!(chain.account_tree, deserialized.account_tree);
        assert_eq!(chain.pending_transactions, deserialized.pending_transactions);
        assert_eq!(chain.committed_accounts, deserialized.committed_accounts);
        assert_eq!(chain.committed_notes, deserialized.committed_notes);
        assert_eq!(chain.account_authenticators, deserialized.account_authenticators);
    }

    #[test]
    fn mock_chain_block_signature() -> anyhow::Result<()> {
        let mut builder = MockChain::builder();
        builder.add_existing_mock_account(Auth::IncrNonce)?;
        let mut chain = builder.build()?;

        // Verify the genesis block signature.
        let genesis_block = chain.latest_block();
        assert!(
            genesis_block.signature().verify(
                genesis_block.header().commitment(),
                genesis_block.header().validator_key()
            )
        );

        // Add another block.
        chain.prove_next_block()?;

        // Verify the next block signature.
        let next_block = chain.latest_block();
        assert!(
            next_block
                .signature()
                .verify(next_block.header().commitment(), next_block.header().validator_key())
        );

        // Public keys should be carried through from the genesis header to the next.
        assert_eq!(next_block.header().validator_key(), next_block.header().validator_key());

        Ok(())
    }
}
