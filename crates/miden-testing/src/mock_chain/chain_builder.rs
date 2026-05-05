use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use anyhow::Context;

// CONSTANTS
// ================================================================================================

/// Default number of decimals for faucets created in tests.
const DEFAULT_FAUCET_DECIMALS: u8 = 10;

// IMPORTS
// ================================================================================================

use itertools::Itertools;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountDelta,
    AccountId,
    AccountStorageMode,
    AccountType,
    StorageSlot,
};
use miden_protocol::asset::{Asset, FungibleAsset, TokenSymbol};
use miden_protocol::block::account_tree::AccountTree;
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{
    BlockAccountUpdate,
    BlockBody,
    BlockHeader,
    BlockNoteTree,
    BlockNumber,
    BlockProof,
    Blockchain,
    FeeParameters,
    OutputNoteBatch,
    ProvenBlock,
};
use miden_protocol::crypto::merkle::smt::Smt;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteAttachment, NoteDetails, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::testing::random_secret_key::random_secret_key;
use miden_protocol::transaction::{OrderedTransactionHeaders, RawOutputNote, TransactionKernel};
use miden_protocol::{MAX_OUTPUT_NOTES_PER_BATCH, Word};
use miden_standards::account::access::Ownable2Step;
use miden_standards::account::faucets::{BasicFungibleFaucet, NetworkFungibleFaucet};
use miden_standards::account::metadata::{
    FungibleTokenMetadata,
    FungibleTokenMetadataBuilder,
    TokenName,
};
use miden_standards::account::policies::{
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyAuthority,
    TokenPolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::{P2idNote, P2ideNote, P2ideNoteStorage, SwapNote};
use miden_standards::testing::account_component::MockAccountComponent;
use rand::Rng;

use crate::mock_chain::chain::AccountAuthenticator;
use crate::utils::{create_p2any_note, create_spawn_note};
use crate::{AccountState, Auth, MockChain};

/// A builder for a [`MockChain`]'s genesis block.
///
/// ## Example
///
/// ```
/// # use anyhow::Result;
/// # use miden_protocol::{
/// #    asset::{Asset, FungibleAsset},
/// #    note::NoteType,
/// # };
/// # use miden_testing::{Auth, MockChain};
/// #
/// # fn main() -> Result<()> {
/// let mut builder = MockChain::builder();
/// let existing_wallet =
///     builder.add_existing_wallet_with_assets(Auth::IncrNonce, [FungibleAsset::mock(500)])?;
/// let new_wallet = builder.create_new_wallet(Auth::IncrNonce)?;
///
/// let existing_note = builder.add_p2id_note(
///     existing_wallet.id(),
///     new_wallet.id(),
///     &[FungibleAsset::mock(100)],
///     NoteType::Private,
/// )?;
/// let chain = builder.build()?;
///
/// // The existing wallet and note should be part of the chain state.
/// assert!(chain.committed_account(existing_wallet.id()).is_ok());
/// assert!(chain.committed_notes().get(&existing_note.id()).is_some());
///
/// // The new wallet should *not* be part of the chain state - it must be created in
/// // a transaction first.
/// assert!(chain.committed_account(new_wallet.id()).is_err());
///
/// # Ok(())
/// # }
/// ```
///
/// Note the distinction between `add_` and `create_` APIs. Any `add_` APIs will add something to
/// the genesis chain state while `create_` APIs do not mutate the genesis state. The latter are
/// simply convenient for creating accounts or notes that will be created by transactions.
///
/// See also the [`MockChain`] docs for examples on using the mock chain.
#[derive(Debug, Clone)]
pub struct MockChainBuilder {
    accounts: BTreeMap<AccountId, Account>,
    account_authenticators: BTreeMap<AccountId, AccountAuthenticator>,
    notes: Vec<RawOutputNote>,
    rng: RandomCoin,
    // Fee parameters.
    fee_faucet_id: AccountId,
    verification_base_fee: u32,
}

impl MockChainBuilder {
    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------

    /// Initializes a new mock chain builder with an empty state.
    ///
    /// By default, the `fee_faucet_id` is set to [`ACCOUNT_ID_FEE_FAUCET`] and can be
    /// overwritten using [`Self::fee_faucet_id`].
    ///
    /// The `verification_base_fee` is initialized to 0 which means no fees are required by default.
    pub fn new() -> Self {
        let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into().expect("account ID should be valid");

        Self {
            accounts: BTreeMap::new(),
            account_authenticators: BTreeMap::new(),
            notes: Vec::new(),
            rng: RandomCoin::new(Default::default()),
            fee_faucet_id,
            verification_base_fee: 0,
        }
    }

    /// Initializes a new mock chain builder with the provided accounts.
    ///
    /// This method only adds the accounts and cannot not register any authenticators for them.
    /// Calling [`MockChain::build_tx_context`] on accounts added in this way will not work if the
    /// account needs an authenticator.
    ///
    /// Due to these limitations, prefer using other methods to add accounts to the chain, e.g.
    /// [`MockChainBuilder::add_account_from_builder`].
    pub fn with_accounts(accounts: impl IntoIterator<Item = Account>) -> anyhow::Result<Self> {
        let mut builder = Self::new();

        for account in accounts {
            builder.add_account(account)?;
        }

        Ok(builder)
    }

    // BUILDER METHODS
    // ----------------------------------------------------------------------------------------

    /// Sets the fee faucet ID of the chain.
    ///
    /// This must be a fungible faucet [`AccountId`] and is the asset in which fees will be accepted
    /// by the transaction kernel.
    pub fn fee_faucet_id(mut self, fee_faucet_id: AccountId) -> Self {
        self.fee_faucet_id = fee_faucet_id;
        self
    }

    /// Sets the `verification_base_fee` of the chain.
    ///
    /// See [`FeeParameters`] for more details.
    pub fn verification_base_fee(mut self, verification_base_fee: u32) -> Self {
        self.verification_base_fee = verification_base_fee;
        self
    }

    /// Consumes the builder, creates the genesis block of the chain and returns the [`MockChain`].
    pub fn build(self) -> anyhow::Result<MockChain> {
        // Create the genesis block, consisting of the provided accounts and notes.
        let block_account_updates: Vec<BlockAccountUpdate> = self
            .accounts
            .into_values()
            .map(|account| {
                let account_id = account.id();
                let account_commitment = account.to_commitment();
                let account_delta = AccountDelta::try_from(account)
                    .expect("chain builder should only store existing accounts without seeds");
                let update_details = AccountUpdateDetails::Delta(account_delta);

                BlockAccountUpdate::new(account_id, account_commitment, update_details)
            })
            .collect();

        let account_tree = AccountTree::with_entries(
            block_account_updates
                .iter()
                .map(|account| (account.account_id(), account.final_state_commitment())),
        )
        .context("failed to create genesis account tree")?;

        // Extract full notes before shrinking for later use in MockChain
        let full_notes: Vec<Note> = self
            .notes
            .iter()
            .filter_map(|note| match note {
                RawOutputNote::Full(n) => Some(n.clone()),
                _ => None,
            })
            .collect();

        let proven_notes: Vec<_> = self
            .notes
            .into_iter()
            .map(|note| note.into_output_note().expect("genesis note should be valid"))
            .collect();
        let note_chunks = proven_notes.into_iter().chunks(MAX_OUTPUT_NOTES_PER_BATCH);
        let output_note_batches: Vec<OutputNoteBatch> = note_chunks
            .into_iter()
            .map(|batch_notes| batch_notes.into_iter().enumerate().collect::<Vec<_>>())
            .collect();

        let created_nullifiers = Vec::new();
        let transactions = OrderedTransactionHeaders::new_unchecked(Vec::new());

        let note_tree = BlockNoteTree::from_note_batches(&output_note_batches)
            .context("failed to create block note tree")?;

        let version = 0;
        let prev_block_commitment = Word::empty();
        let block_num = BlockNumber::from(0u32);
        let chain_commitment = Blockchain::new().commitment();
        let account_root = account_tree.root();
        let nullifier_root = NullifierTree::<Smt>::default().root();
        let note_root = note_tree.root();
        let tx_commitment = transactions.commitment();
        let tx_kernel_commitment = TransactionKernel.to_commitment();
        let timestamp = MockChain::TIMESTAMP_START_SECS;
        let fee_parameters = FeeParameters::new(self.fee_faucet_id, self.verification_base_fee)
            .context("failed to construct fee parameters")?;
        let validator_secret_key = random_secret_key();
        let validator_public_key = validator_secret_key.public_key();

        let header = BlockHeader::new(
            version,
            prev_block_commitment,
            block_num,
            chain_commitment,
            account_root,
            nullifier_root,
            note_root,
            tx_commitment,
            tx_kernel_commitment,
            validator_public_key,
            fee_parameters,
            timestamp,
        );

        let body = BlockBody::new_unchecked(
            block_account_updates,
            output_note_batches,
            created_nullifiers,
            transactions,
        );

        let signature = validator_secret_key.sign(header.commitment());
        let block_proof = BlockProof::new_dummy();
        let genesis_block = ProvenBlock::new_unchecked(header, body, signature, block_proof);

        MockChain::from_genesis_block(
            genesis_block,
            account_tree,
            self.account_authenticators,
            validator_secret_key,
            full_notes,
        )
    }

    // ACCOUNT METHODS
    // ----------------------------------------------------------------------------------------

    /// Creates a new public [`BasicWallet`] account and registers the authenticator (if any) for
    /// it.
    ///
    /// This does not add the account to the chain state, but it can still be used to call
    /// [`MockChain::build_tx_context`] to automatically add the authenticator.
    pub fn create_new_wallet(&mut self, auth_method: Auth) -> anyhow::Result<Account> {
        let account_builder = AccountBuilder::new(self.rng.random())
            .storage_mode(AccountStorageMode::Public)
            .with_component(BasicWallet);

        self.add_account_from_builder(auth_method, account_builder, AccountState::New)
    }

    /// Adds an existing public [`BasicWallet`] account to the initial chain state and registers the
    /// authenticator (if any).
    pub fn add_existing_wallet(&mut self, auth_method: Auth) -> anyhow::Result<Account> {
        self.add_existing_wallet_with_assets(auth_method, [])
    }

    /// Adds an existing public [`BasicWallet`] account to the initial chain state and registers the
    /// authenticator (if any).
    pub fn add_existing_wallet_with_assets(
        &mut self,
        auth_method: Auth,
        assets: impl IntoIterator<Item = Asset>,
    ) -> anyhow::Result<Account> {
        let account_builder = Account::builder(self.rng.random())
            .storage_mode(AccountStorageMode::Public)
            .with_component(BasicWallet)
            .with_assets(assets);

        self.add_account_from_builder(auth_method, account_builder, AccountState::Exists)
    }

    /// Creates a new public [`BasicFungibleFaucet`] account and registers the authenticator (if
    /// any) for it.
    ///
    /// This does not add the account to the chain state, but it can still be used to call
    /// [`MockChain::build_tx_context`] to automatically add the authenticator.
    pub fn create_new_faucet(
        &mut self,
        auth_method: Auth,
        token_symbol: &str,
        max_supply: u64,
    ) -> anyhow::Result<Account> {
        let name = TokenName::new(token_symbol)?;
        let token_symbol = TokenSymbol::new(token_symbol)
            .with_context(|| format!("invalid token symbol: {token_symbol}"))?;
        let metadata = FungibleTokenMetadataBuilder::new(
            name,
            token_symbol,
            DEFAULT_FAUCET_DECIMALS,
            max_supply,
        )
        .build()
        .context("failed to create FungibleTokenMetadata")?;

        let account_builder = AccountBuilder::new(self.rng.random())
            .storage_mode(AccountStorageMode::Public)
            .account_type(AccountType::FungibleFaucet)
            .with_components(TokenPolicyManager::new(
                PolicyAuthority::AuthControlled,
                MintPolicyConfig::AllowAll,
                BurnPolicyConfig::AllowAll,
            ))
            .with_component(metadata)
            .with_component(BasicFungibleFaucet);

        self.add_account_from_builder(auth_method, account_builder, AccountState::New)
    }

    /// Adds an existing [`BasicFungibleFaucet`] account to the initial chain state and
    /// registers the authenticator.
    ///
    /// Basic fungible faucets always use `AccountStorageMode::Public` and require authentication.
    pub fn add_existing_basic_faucet(
        &mut self,
        auth_method: Auth,
        token_symbol: &str,
        max_supply: u64,
        token_supply: Option<u64>,
    ) -> anyhow::Result<Account> {
        let token_supply = token_supply.unwrap_or(0);
        let name = TokenName::new(token_symbol)?;
        let token_symbol =
            TokenSymbol::new(token_symbol).context("failed to create token symbol")?;
        let metadata = FungibleTokenMetadataBuilder::new(
            name,
            token_symbol,
            DEFAULT_FAUCET_DECIMALS,
            max_supply,
        )
        .token_supply(token_supply)
        .build()
        .context("failed to create fungible token metadata")?;

        let account_builder = AccountBuilder::new(self.rng.random())
            .storage_mode(AccountStorageMode::Public)
            .with_component(metadata)
            .with_component(BasicFungibleFaucet)
            .with_components(TokenPolicyManager::new(
                PolicyAuthority::AuthControlled,
                MintPolicyConfig::AllowAll,
                BurnPolicyConfig::AllowAll,
            ))
            .account_type(AccountType::FungibleFaucet);

        self.add_account_from_builder(auth_method, account_builder, AccountState::Exists)
    }

    /// Adds an existing [`NetworkFungibleFaucet`] account to the initial chain state.
    ///
    /// Network fungible faucets always use `AccountStorageMode::Network` and `Auth::NoAuth`.
    ///
    /// `mint_policy` selects the initial active mint policy on the faucet. The installed
    /// [`TokenPolicyManager`] is always owner-controlled.
    pub fn add_existing_network_faucet(
        &mut self,
        token_symbol: &str,
        max_supply: u64,
        owner_account_id: AccountId,
        token_supply: Option<u64>,
        mint_policy: MintPolicyConfig,
    ) -> anyhow::Result<Account> {
        let token_supply = token_supply.unwrap_or(0);
        let name = TokenName::new(token_symbol)?;
        let token_symbol =
            TokenSymbol::new(token_symbol).context("failed to create token symbol")?;

        let metadata = FungibleTokenMetadataBuilder::new(
            name,
            token_symbol,
            DEFAULT_FAUCET_DECIMALS,
            max_supply,
        )
        .token_supply(token_supply)
        .build()
        .context("failed to create fungible token metadata")?;

        let account_builder = AccountBuilder::new(self.rng.random())
            .storage_mode(AccountStorageMode::Network)
            .with_component(metadata)
            .with_component(NetworkFungibleFaucet)
            .with_component(Ownable2Step::new(owner_account_id))
            .with_components(TokenPolicyManager::new(
                PolicyAuthority::OwnerControlled,
                mint_policy,
                BurnPolicyConfig::AllowAll,
            ))
            .account_type(AccountType::FungibleFaucet);

        // Network faucets always use IncrNonce auth (no authentication)
        self.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
    }

    /// Adds an existing network fungible faucet account with the given metadata component
    /// (for testing metadata::fungible procedures: owner can update description / logo_uri /
    /// external_link / max supply when mutable).
    pub fn add_existing_network_faucet_with_metadata(
        &mut self,
        owner_account_id: AccountId,
        metadata: FungibleTokenMetadata,
    ) -> anyhow::Result<Account> {
        let account_builder = AccountBuilder::new(self.rng.random())
            .storage_mode(AccountStorageMode::Network)
            .with_component(metadata)
            .with_component(NetworkFungibleFaucet)
            .with_component(Ownable2Step::new(owner_account_id))
            .with_components(TokenPolicyManager::new(
                PolicyAuthority::OwnerControlled,
                MintPolicyConfig::OwnerOnly,
                BurnPolicyConfig::AllowAll,
            ))
            .account_type(AccountType::FungibleFaucet);

        self.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
    }

    /// Creates a new public account with an [`MockAccountComponent`] and registers the
    /// authenticator (if any).
    pub fn create_new_mock_account(&mut self, auth_method: Auth) -> anyhow::Result<Account> {
        let account_builder = Account::builder(self.rng.random())
            .storage_mode(AccountStorageMode::Public)
            .with_component(MockAccountComponent::with_empty_slots());

        self.add_account_from_builder(auth_method, account_builder, AccountState::New)
    }

    /// Adds an existing public account with an [`MockAccountComponent`] to the initial chain state
    /// and registers the authenticator (if any).
    pub fn add_existing_mock_account(&mut self, auth_method: Auth) -> anyhow::Result<Account> {
        self.add_existing_mock_account_with_storage_and_assets(auth_method, [], [])
    }

    /// Adds an existing public account with an [`MockAccountComponent`] to the initial chain state
    /// and registers the authenticator (if any).
    pub fn add_existing_mock_account_with_storage(
        &mut self,
        auth_method: Auth,
        slots: impl IntoIterator<Item = StorageSlot>,
    ) -> anyhow::Result<Account> {
        self.add_existing_mock_account_with_storage_and_assets(auth_method, slots, [])
    }

    /// Adds an existing public account with an [`MockAccountComponent`] to the initial chain state
    /// and registers the authenticator (if any).
    pub fn add_existing_mock_account_with_assets(
        &mut self,
        auth_method: Auth,
        assets: impl IntoIterator<Item = Asset>,
    ) -> anyhow::Result<Account> {
        self.add_existing_mock_account_with_storage_and_assets(auth_method, [], assets)
    }

    /// Adds an existing public account with an [`MockAccountComponent`] to the initial chain state
    /// and registers the authenticator (if any).
    pub fn add_existing_mock_account_with_storage_and_assets(
        &mut self,
        auth_method: Auth,
        slots: impl IntoIterator<Item = StorageSlot>,
        assets: impl IntoIterator<Item = Asset>,
    ) -> anyhow::Result<Account> {
        let account_builder = Account::builder(self.rng.random())
            .storage_mode(AccountStorageMode::Public)
            .with_component(MockAccountComponent::with_slots(slots.into_iter().collect()))
            .with_assets(assets);

        self.add_account_from_builder(auth_method, account_builder, AccountState::Exists)
    }

    /// Builds the provided [`AccountBuilder`] with the provided auth method and registers the
    /// authenticator (if any).
    ///
    /// - If [`AccountState::Exists`] is given the account is built as an existing account and added
    ///   to the initial chain state. It can then be used in a transaction without having to
    ///   validate its seed.
    /// - If [`AccountState::New`] is given the account is built as a new account and is **not**
    ///   added to the chain. Its authenticator is registered (if present). Its first transaction
    ///   will be its creation transaction. [`MockChain::build_tx_context`] can be called with the
    ///   account to automatically add the authenticator.
    pub fn add_account_from_builder(
        &mut self,
        auth_method: Auth,
        mut account_builder: AccountBuilder,
        account_state: AccountState,
    ) -> anyhow::Result<Account> {
        let (auth_component, authenticator) = auth_method.build_component();
        account_builder = account_builder.with_auth_component(auth_component);

        let account = if let AccountState::New = account_state {
            account_builder.build().context("failed to build account from builder")?
        } else {
            account_builder
                .build_existing()
                .context("failed to build account from builder")?
        };

        self.account_authenticators
            .insert(account.id(), AccountAuthenticator::new(authenticator));

        if let AccountState::Exists = account_state {
            self.accounts.insert(account.id(), account.clone());
        }

        Ok(account)
    }
    pub fn add_existing_account_from_components(
        &mut self,
        auth: Auth,
        components: impl IntoIterator<Item = AccountComponent>,
    ) -> anyhow::Result<Account> {
        let mut account_builder =
            Account::builder(rand::rng().random()).storage_mode(AccountStorageMode::Public);

        for component in components {
            account_builder = account_builder.with_component(component);
        }

        self.add_account_from_builder(auth, account_builder, AccountState::Exists)
    }

    /// Adds the provided account to the list of genesis accounts.
    ///
    /// This method only adds the account and does not store its account authenticator for it.
    /// Calling [`MockChain::build_tx_context`] on accounts added in this way will not work if
    /// the account needs an authenticator.
    ///
    /// Due to these limitations, prefer using other methods to add accounts to the chain, e.g.
    /// [`MockChainBuilder::add_account_from_builder`].
    pub fn add_account(&mut self, account: Account) -> anyhow::Result<()> {
        self.accounts.insert(account.id(), account);

        // This returns a Result to be conservative in case we need to return an error in the future
        // and do not want to break this API.
        Ok(())
    }

    // NOTE ADD METHODS
    // ----------------------------------------------------------------------------------------

    /// Adds the provided note to the initial chain state.
    pub fn add_output_note(&mut self, note: impl Into<RawOutputNote>) {
        self.notes.push(note.into());
    }

    /// Creates a new P2ANY note from the provided parameters and adds it to the list of
    /// genesis notes.
    ///
    /// This note is similar to a P2ID note but can be consumed by any account.
    pub fn add_p2any_note(
        &mut self,
        sender_account_id: AccountId,
        note_type: NoteType,
        assets: impl IntoIterator<Item = Asset>,
    ) -> anyhow::Result<Note> {
        let note = create_p2any_note(sender_account_id, note_type, assets, &mut self.rng);
        self.add_output_note(RawOutputNote::Full(note.clone()));

        Ok(note)
    }

    /// Creates a new P2ID note from the provided parameters and adds it to the list of genesis
    /// notes.
    ///
    /// In the created [`MockChain`], the note will be immediately spendable by `target_account_id`
    /// and carries no additional reclaim or timelock conditions.
    pub fn add_p2id_note(
        &mut self,
        sender_account_id: AccountId,
        target_account_id: AccountId,
        asset: &[Asset],
        note_type: NoteType,
    ) -> Result<Note, NoteError> {
        let note = P2idNote::create(
            sender_account_id,
            target_account_id,
            asset.to_vec(),
            note_type,
            NoteAttachment::default(),
            &mut self.rng,
        )?;
        self.add_output_note(RawOutputNote::Full(note.clone()));

        Ok(note)
    }

    /// Adds a P2IDE note (pay‑to‑ID‑extended) to the list of genesis notes.
    ///
    /// A P2IDE note can include an optional `timelock_height` and/or an optional
    /// `reclaim_height` after which the `sender_account_id` may reclaim the
    /// funds.
    pub fn add_p2ide_note(
        &mut self,
        sender_account_id: AccountId,
        target_account_id: AccountId,
        asset: &[Asset],
        note_type: NoteType,
        reclaim_height: Option<BlockNumber>,
        timelock_height: Option<BlockNumber>,
    ) -> Result<Note, NoteError> {
        let storage = P2ideNoteStorage::new(target_account_id, reclaim_height, timelock_height);

        let note = P2ideNote::create(
            sender_account_id,
            storage,
            asset.to_vec(),
            note_type,
            Default::default(),
            &mut self.rng,
        )?;

        self.add_output_note(RawOutputNote::Full(note.clone()));

        Ok(note)
    }

    /// Adds a public SWAP note to the list of genesis notes.
    pub fn add_swap_note(
        &mut self,
        sender: AccountId,
        offered_asset: Asset,
        requested_asset: Asset,
        payback_note_type: NoteType,
    ) -> anyhow::Result<(Note, NoteDetails)> {
        let (swap_note, payback_note) = SwapNote::create(
            sender,
            offered_asset,
            requested_asset,
            NoteType::Public,
            NoteAttachment::default(),
            payback_note_type,
            &mut self.rng,
        )?;

        self.add_output_note(RawOutputNote::Full(swap_note.clone()));

        Ok((swap_note, payback_note))
    }

    /// Adds a public `SPAWN` note to the list of genesis notes.
    ///
    /// A `SPAWN` note contains a note script that creates all `output_notes` that get passed as a
    /// parameter.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the sender account ID of the provided output notes is not consistent or does not match the
    ///   transaction's sender.
    pub fn add_spawn_note<'note, I>(
        &mut self,
        output_notes: impl IntoIterator<Item = &'note Note, IntoIter = I>,
    ) -> anyhow::Result<Note>
    where
        I: ExactSizeIterator<Item = &'note Note>,
    {
        let note = create_spawn_note(output_notes)?;
        self.add_output_note(RawOutputNote::Full(note.clone()));

        Ok(note)
    }

    /// Creates a new P2ID note with the provided amount of the fee asset of the chain.
    ///
    /// The fee faucet ID of the asset can be set using [`Self::fee_faucet_id`]. By default it
    /// is [`ACCOUNT_ID_FEE_FAUCET`].
    ///
    /// In the created [`MockChain`], the note will be immediately spendable by `target_account_id`.
    pub fn add_p2id_note_with_fee(
        &mut self,
        target_account_id: AccountId,
        amount: u64,
    ) -> anyhow::Result<Note> {
        let fee_asset = self.fee_asset(amount)?;
        let note = self.add_p2id_note(
            self.fee_faucet_id,
            target_account_id,
            &[Asset::from(fee_asset)],
            NoteType::Public,
        )?;

        Ok(note)
    }

    // HELPER FUNCTIONS
    // ----------------------------------------------------------------------------------------

    /// Returns a mutable reference to the builder's RNG.
    ///
    /// This can be used when creating accounts or notes and randomness is required.
    pub fn rng_mut(&mut self) -> &mut RandomCoin {
        &mut self.rng
    }

    /// Constructs a fungible asset based on the fee faucet ID and the provided amount.
    fn fee_asset(&self, amount: u64) -> anyhow::Result<FungibleAsset> {
        FungibleAsset::new(self.fee_faucet_id, amount).context("failed to create fee asset")
    }
}

impl Default for MockChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}
