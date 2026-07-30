//! Benchmark scenarios where a network account carrying the required management components
//! consumes a standard action note.
//!
//! Each scenario mirrors the account fixture of the corresponding note test suite in
//! `crates/miden-testing/tests/scripts/`, changing only what the canonical network-account
//! transaction requires: the account authenticates with `Auth::NetworkAccount` (allowlisting
//! exactly the consumed note's script root), its vault holds the native fee asset, and the chain
//! charges the network verification base fee so the auth procedure pays a TX_FEE note.
//!
//! Every scenario benchmarks one representative action selector (documented per builder). The
//! other selectors of the same note run the identical dispatch path with different storage
//! accesses, so their costs are expected to stay within the same fee bracket.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use miden_protocol::Word;
use miden_protocol::account::{
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountType,
    AssetCallbackFlag,
    RoleSymbol,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{Note, NoteScriptRoot};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::pausable::{Pausable, PausableManager};
use miden_standards::account::access::{AccessControl, Authority, Ownable2Step};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::faucets::{Description, FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    AllowlistManager,
    BlocklistManager,
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::{
    AllowlistConfig,
    AllowlistConfigNote,
    BlocklistConfig,
    BlocklistConfigNote,
    FaucetPolicyAction,
    FaucetPolicyActionNote,
    FungibleFaucetConfig,
    FungibleFaucetConfigNote,
    NetworkAccountConfig,
    NetworkAccountConfigNote,
    OwnerAction,
    OwnerActionNote,
    PauseAction,
    PauseActionNote,
    RbacAction,
    RbacActionNote,
};
use miden_testing::{AccountState, Auth, MockTransaction};

// FAUCET POLICY ACTION NOTE SETUP
// ================================================================================================

/// Returns the transaction context for a network faucet consuming a FAUCET_POLICY_ACTION note.
///
/// The faucet carries a `TokenPolicyManager` with an `owner_only` mint and burn policy registered
/// as allowed alternatives to the active `allow_all` policies, gated by the owner wallet via
/// `Authority::OwnerControlled` (mirrors `create_faucet_with_policies` in the
/// `faucet_policy_action` test suite). The benchmarked action is `SetMintPolicy`, switching the
/// active mint policy to the allowed `owner_only` alternative.
pub fn tx_consume_faucet_policy_action_note_network() -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    // the owner wallet authorized to send policy actions
    let owner = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .allowed_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::allow_all())
        .allowed_burn_policy(BurnPolicy::owner_only())
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build();

    let account_builder = AccountBuilder::new([43; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner.id()))
        .with_component(Authority::OwnerControlled)
        .with_asset_callbacks(AssetCallbackFlag::from(token_policy_manager.has_transfer_policy()))
        .with_components(token_policy_manager)
        .with_assets([super::fee_funding_asset()?]);
    let account = builder.add_account_from_builder(
        super::network_auth([FaucetPolicyActionNote::script_root()])?,
        account_builder,
        AccountState::Exists,
    )?;

    let note: Note = FaucetPolicyActionNote::builder()
        .sender(owner.id())
        .account(account.id())
        .action(FaucetPolicyAction::SetMintPolicy {
            policy_root: MintPolicy::owner_only().root(),
        })
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()
}

// FUNGIBLE FAUCET CONFIG NOTE SETUP
// ================================================================================================

/// Returns the transaction context for a network faucet consuming a FUNGIBLE_FAUCET_CONFIG note.
///
/// The faucet carries the token metadata with every mutability flag set, gated by the owner wallet
/// via `Authority::OwnerControlled` (mirrors `create_faucet` in the `faucet_metadata` test suite).
/// The benchmarked action is `SetDescription`, the most expensive selector: it commits to the
/// 7-Word payload and republishes it in the advice map before the call, which the `SetMaxSupply`
/// selector does not do.
pub fn tx_consume_fungible_faucet_config_note_network() -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    // the owner wallet authorized to send metadata config notes
    let owner = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .is_description_mutable(true)
        .is_logo_uri_mutable(true)
        .is_external_link_mutable(true)
        .is_max_supply_mutable(true)
        .build()?;

    let account_builder = AccountBuilder::new([43; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner.id()))
        .with_component(Authority::OwnerControlled)
        .with_component(Pausable::unpaused())
        .with_assets([super::fee_funding_asset()?]);
    let account = builder.add_account_from_builder(
        super::network_auth([FungibleFaucetConfigNote::script_root()])?,
        account_builder,
        AccountState::Exists,
    )?;

    let note: Note = FungibleFaucetConfigNote::builder()
        .sender(owner.id())
        .target(account.id())
        .config(FungibleFaucetConfig::SetDescription {
            description: Description::new("benchmarked token description")?,
        })
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()
}

// LIST CONFIG NOTE SETUP
// ================================================================================================

/// Returns the transaction context for a network faucet consuming an ALLOWLIST_CONFIG note.
///
/// The benchmarked action is `AllowAccount`, adding an account to the initially empty allowlist.
/// See [`tx_consume_list_config_note_network`] for the account fixture.
pub fn tx_consume_allowlist_config_note_network() -> Result<MockTransaction> {
    tx_consume_list_config_note_network(ListKind::Allowlist)
}

/// Returns the transaction context for a network faucet consuming a BLOCKLIST_CONFIG note.
///
/// The benchmarked action is `BlockAccount`, adding an account to the initially empty blocklist.
/// See [`tx_consume_list_config_note_network`] for the account fixture.
pub fn tx_consume_blocklist_config_note_network() -> Result<MockTransaction> {
    tx_consume_list_config_note_network(ListKind::Blocklist)
}

/// The two transfer-list kinds. The pieces differing between the ALLOWLIST_CONFIG and
/// BLOCKLIST_CONFIG scenarios (transfer policy, list manager component, and consumed note) are
/// all derived from this discriminant via the methods below, keeping the per-list choices in one
/// place.
#[derive(Clone, Copy)]
enum ListKind {
    Allowlist,
    Blocklist,
}

impl ListKind {
    /// The list's empty basic transfer policy.
    fn transfer_policy(self) -> TransferPolicy {
        match self {
            ListKind::Allowlist => TransferPolicy::empty_basic_allowlist(),
            ListKind::Blocklist => TransferPolicy::empty_basic_blocklist(),
        }
    }

    /// The list's manager admin component.
    fn manager(self) -> AccountComponent {
        match self {
            ListKind::Allowlist => AllowlistManager.into(),
            ListKind::Blocklist => BlocklistManager.into(),
        }
    }

    /// The list's config note script root.
    fn script_root(self) -> NoteScriptRoot {
        match self {
            ListKind::Allowlist => AllowlistConfigNote::script_root(),
            ListKind::Blocklist => BlocklistConfigNote::script_root(),
        }
    }

    /// The list's config note carrying the benchmarked action: adding `listed` to the initially
    /// empty list.
    fn build_note(
        self,
        sender: AccountId,
        target: AccountId,
        listed: AccountId,
        rng: &mut impl FeltRng,
    ) -> Result<Note> {
        let note = match self {
            ListKind::Allowlist => AllowlistConfigNote::builder()
                .sender(sender)
                .target(target)
                .config(AllowlistConfig::AllowAccount { account: listed })
                .generate_serial_number(rng)
                .build()?
                .into(),
            ListKind::Blocklist => BlocklistConfigNote::builder()
                .sender(sender)
                .target(target)
                .config(BlocklistConfig::BlockAccount { account: listed })
                .generate_serial_number(rng)
                .build()?
                .into(),
        };
        Ok(note)
    }
}

/// Returns the transaction context for a network faucet consuming a transfer-list config note.
///
/// Shared setup of the ALLOWLIST_CONFIG and BLOCKLIST_CONFIG scenarios: the faucet carries the
/// list's basic transfer policy on send and receive plus the list's manager admin component,
/// gated by the owner wallet via `Authority::OwnerControlled` (mirrors the
/// `add_faucet_with_owner_{allowlist,blocklist}_transfer` fixtures in the respective test
/// suites). The benchmarked action adds an account to the initially empty list.
fn tx_consume_list_config_note_network(list: ListKind) -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    // the owner wallet authorized to send list config notes
    let owner = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(list.transfer_policy())
        .active_receive_policy(list.transfer_policy())
        .build();

    let account_builder = AccountBuilder::new([43; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Ownable2Step::new(owner.id()))
        .with_component(Authority::OwnerControlled)
        .with_asset_callbacks(AssetCallbackFlag::from(token_policy_manager.has_transfer_policy()))
        .with_components(token_policy_manager)
        .with_component(list.manager())
        .with_assets([super::fee_funding_asset()?]);
    let account = builder.add_account_from_builder(
        super::network_auth([list.script_root()])?,
        account_builder,
        AccountState::Exists,
    )?;

    // the account added to the initially empty list by the benchmarked action
    let listed = AccountIdBuilder::new().build_with_seed([3; 32]);
    let note = list.build_note(owner.id(), account.id(), listed, builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()
}

// PAUSE ACTION NOTE SETUP
// ================================================================================================

/// Returns the transaction context for a network pausable account consuming a PAUSE_ACTION note.
///
/// The account carries `PausableManager` gated by the owner wallet via `Authority::OwnerControlled`
/// (installed by `AccessControl::Ownable2Step`), plus the `Pausable` storage component (mirrors
/// `create_pausable_account` in the `pause_action` test suite). The benchmarked action is `Pause`
/// on the initially unpaused account.
pub fn tx_consume_pause_action_note_network() -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    // the owner wallet authorized to send pause actions
    let owner = builder.add_existing_wallet(Auth::IncrNonce)?;

    let account_builder = AccountBuilder::new([43; 32])
        .account_type(AccountType::Public)
        .with_components(AccessControl::Ownable2Step { owner: owner.id() })
        .with_component(Pausable::unpaused())
        .with_component(PausableManager)
        .with_assets([super::fee_funding_asset()?]);
    let account = builder.add_account_from_builder(
        super::network_auth([PauseActionNote::script_root()])?,
        account_builder,
        AccountState::Exists,
    )?;

    let note: Note = PauseActionNote::builder()
        .sender(owner.id())
        .account(account.id())
        .action(PauseAction::Pause)
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()
}

// OWNER ACTION NOTE SETUP
// ================================================================================================

/// Returns the transaction context for a network ownable account consuming an OWNER_ACTION note.
///
/// The account carries the `Ownable2Step` component owned by the owner wallet (mirrors
/// `create_ownable_account` in the `ownable2step` test suite). The benchmarked action is
/// `TransferOwnership`, nominating a new owner.
pub fn tx_consume_owner_action_note_network() -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    // the owner wallet authorized to send owner actions
    let owner = builder.add_existing_wallet(Auth::IncrNonce)?;
    let new_owner = AccountIdBuilder::new().build_with_seed([2; 32]);

    let account_builder = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_component(Ownable2Step::new(owner.id()))
        .with_assets([super::fee_funding_asset()?]);
    let account = builder.add_account_from_builder(
        super::network_auth([OwnerActionNote::script_root()])?,
        account_builder,
        AccountState::Exists,
    )?;

    let note: Note = OwnerActionNote::builder()
        .sender(owner.id())
        .account(account.id())
        .action(OwnerAction::TransferOwnership { new_owner: Some(new_owner) })
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()
}

// RBAC ACTION NOTE SETUP
// ================================================================================================

/// Returns the transaction context for a network RBAC account consuming an RBAC_ACTION note.
///
/// The account carries `AccessControl::Rbac` with the admin wallet seeded as the initial `ADMIN`
/// role member (mirrors `create_rbac_account_with_admin` in the `rbac` test suite). The
/// benchmarked action is `GrantRole`, granting the `MINTER` role to a member account.
pub fn tx_consume_rbac_action_note_network() -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    // the admin wallet authorized to send role administration actions
    let admin = builder.add_existing_wallet(Auth::IncrNonce)?;
    let member = AccountIdBuilder::new().build_with_seed([42; 32]);

    let account_builder = AccountBuilder::new([9; 32])
        .account_type(AccountType::Public)
        .with_components(AccessControl::Rbac {
            admin: admin.id(),
            procedure_roles: BTreeMap::new(),
        })
        .with_assets([super::fee_funding_asset()?]);
    let account = builder.add_account_from_builder(
        super::network_auth([RbacActionNote::script_root()])?,
        account_builder,
        AccountState::Exists,
    )?;

    let note: Note = RbacActionNote::builder()
        .sender(admin.id())
        .account(account.id())
        .action(RbacAction::GrantRole {
            role: RoleSymbol::new("MINTER")?,
            account: member,
        })
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()
}

// NETWORK ACCOUNT CONFIG NOTE SETUP
// ================================================================================================

/// Returns the transaction context in which a network account consumes a NETWORK_ACCOUNT_CONFIG
/// note.
///
/// The account opts into allowlist management: `AuthNetworkAccount` (which auto-allowlists the
/// config-note root) gated by the Ownable2Step owner via `Authority::OwnerControlled` (mirrors
/// `build_owner_controlled_account` in the `network_account` auth test suite). The benchmarked
/// action is `AddAllowedNoteScript`; the other selectors run the identical dispatch path.
pub fn tx_consume_network_account_config_note_network() -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    // the owner authorized to send config notes; only its ID is needed
    let owner = AccountId::builder().account_type(AccountType::Private).build_with_seed([9; 32]);

    let auth_components =
        AuthNetworkAccount::new(BTreeSet::new(), super::fee_policy_manager([], &[])?)?;
    let account = AccountBuilder::new([7; 32])
        .account_type(AccountType::Public)
        .with_components(auth_components)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(BasicWallet)
        .with_assets([super::fee_funding_asset()?])
        .build_existing()?;
    builder.add_account(account.clone())?;

    let note: Note = NetworkAccountConfigNote::builder()
        .sender(owner)
        .account(account.id())
        .action(NetworkAccountConfig::AddAllowedNoteScript {
            script_root: NoteScriptRoot::from_array([1, 2, 3, 4]),
        })
        .serial_number(Word::from([1u32, 0, 0, 0]))
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()
}
