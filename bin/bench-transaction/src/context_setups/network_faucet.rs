//! Benchmark scenarios where a network faucet account consumes a MINT or BURN note.
//!
//! All scenarios run on a chain charging [`super::NETWORK_VERIFICATION_BASE_FEE`], so the faucet's
//! network auth procedure additionally creates a TX_FEE note funded from the native fee asset held
//! in the faucet's vault.

use std::sync::Arc;

use anyhow::Result;
use miden_protocol::Felt;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::{AssetId, FungibleAsset, NonFungibleAsset, TokenSymbol};
use miden_protocol::crypto::merkle::smt::SmtProof;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::vm::AdviceInputs;
use miden_standards::account::access::{AccessControl, Pausable, PausableManager};
use miden_standards::account::faucets::{NonFungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::note::{BurnNote, MintNote, MintNoteStorage, P2idNote};
use miden_testing::{AccountState, Auth, MockChainBuilder, MockTransaction};
use rand::RngExt;

// CONSTANTS
// ================================================================================================

/// Token symbol of the benchmarked faucets.
const TOKEN_SYMBOL: &str = "NET";

/// Maximum supply of the fungible benchmark faucet.
const MAX_SUPPLY: u64 = 1_000;

/// Supply already issued by the fungible benchmark faucet at genesis.
///
/// Must cover [`BURN_AMOUNT`] so the BURN scenario has issued supply to burn.
const TOKEN_SUPPLY: u64 = 100;

/// Amount minted by the fungible MINT scenario.
const MINT_AMOUNT: u64 = 75;

/// Amount burned by the BURN scenario.
const BURN_AMOUNT: u64 = 100;

// FAUCET FIXTURES
// ================================================================================================

/// Returns the deterministic account ID owning the benchmark faucets.
///
/// The owner only ever acts as a note sender (the faucets' mint policy is owner-only), so it does
/// not need to exist as an account on the chain.
fn owner_account_id() -> AccountId {
    AccountId::builder().account_type(AccountType::Private).build_with_seed([1; 32])
}

/// Adds an existing network fungible faucet whose vault holds the native fee asset, so the
/// faucet's auth procedure can pay the transaction fee.
fn add_fee_funded_network_fungible_faucet(
    builder: &mut MockChainBuilder,
    owner_account_id: AccountId,
) -> Result<Account> {
    builder.add_existing_network_faucet_with_assets(
        TOKEN_SYMBOL,
        MAX_SUPPLY,
        owner_account_id,
        Some(TOKEN_SUPPLY),
        MintPolicy::owner_only(),
        [],
        vec![super::fee_funding_asset()?],
    )
}

/// Adds an existing network non-fungible faucet whose vault holds the native fee asset.
///
/// Mirrors the component stack of the network fungible faucet added by
/// [`MockChainBuilder::add_existing_network_faucet`], with the fungible faucet component replaced
/// by [`NonFungibleFaucet`].
fn add_fee_funded_network_non_fungible_faucet(
    builder: &mut MockChainBuilder,
    owner_account_id: AccountId,
) -> Result<Account> {
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new(TOKEN_SYMBOL)?)
        .symbol(TokenSymbol::new(TOKEN_SYMBOL)?)
        .build();

    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build();

    let account_builder = AccountBuilder::new(builder.rng_mut().random())
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_components(AccessControl::Ownable2Step { owner: owner_account_id })
        .with_components(token_policy_manager)
        .with_component(Pausable::unpaused())
        .with_component(PausableManager)
        .with_assets([super::fee_funding_asset()?]);

    builder.add_account_from_builder(
        super::network_auth([MintNote::script_root(), BurnNote::script_root()])?,
        account_builder,
        AccountState::Exists,
    )
}

/// Returns advice inputs carrying the faucet's vault witness for the minted `asset_id`.
///
/// The kernel's `faucet::mint` inserts the minted asset into the input vault for asset
/// preservation. Unlike account-vault accesses, that insertion cannot lazy-load merkle paths, and
/// the transaction executor only pre-fetches witnesses for input note assets — which never cover a
/// freshly minted asset. The witness (an absence proof against the faucet's initial vault root)
/// must therefore be provided upfront. This only matters when the faucet's vault is non-empty
/// (here it holds the fee asset); for an empty vault the merkle store synthesizes the paths from
/// empty subtree roots.
fn minted_asset_witness(faucet: &Account, asset_id: AssetId) -> AdviceInputs {
    let witness = faucet.vault().open(asset_id);

    let mut advice_inputs = AdviceInputs::default();
    advice_inputs.store.extend(witness.authenticated_nodes());

    let smt_proof = SmtProof::from(witness);
    advice_inputs.map.extend([(
        smt_proof.leaf().hash(),
        smt_proof.leaf().to_elements().collect::<Arc<[Felt]>>(),
    )]);

    advice_inputs
}

// MINT NOTE SETUPS
// ================================================================================================

/// Returns the transaction context for a network fungible faucet consuming a MINT note.
///
/// The owner-sent MINT note instructs the fee-funded faucet to mint [`MINT_AMOUNT`] tokens into a
/// public P2ID output note addressed to an existing wallet.
pub fn tx_consume_mint_note_fungible_network() -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    let owner_account_id = owner_account_id();
    let faucet = add_fee_funded_network_fungible_faucet(&mut builder, owner_account_id)?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    // The P2ID output note the faucet mints the asset into.
    let mint_asset = FungibleAsset::new(faucet.id(), MINT_AMOUNT)?;
    let p2id_output_note = Note::from(
        P2idNote::builder()
            .sender(faucet.id())
            .target(target_account.id())
            .asset(mint_asset)
            .note_type(NoteType::Public)
            .serial_number(builder.rng_mut().draw_word())
            .build()?,
    );

    let mint_storage = MintNoteStorage::new_public(
        p2id_output_note.recipient().clone(),
        mint_asset,
        NoteTag::with_account_target(target_account.id()),
    )?;
    let mint_note: Note = MintNote::builder()
        .sender(owner_account_id)
        .mint_storage(mint_storage)
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(mint_note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(faucet.id())
        .authenticated_input_note(mint_note.id())
        .extend_advice_inputs(minted_asset_witness(&faucet, mint_asset.id()))
        .build()
}

/// Returns the transaction context for a network non-fungible faucet consuming a MINT note.
///
/// The owner-sent MINT note instructs the fee-funded faucet to mint an NFT into a public P2ID
/// output note addressed to an existing wallet.
pub fn tx_consume_mint_note_non_fungible_network() -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    let owner_account_id = owner_account_id();
    let faucet = add_fee_funded_network_non_fungible_faucet(&mut builder, owner_account_id)?;
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    // The P2ID output note the faucet mints the NFT into.
    let commitment = NonFungibleFaucet::compute_asset_commitment(
        b"benchmark NFT",
        builder.rng_mut().draw_word(),
    );
    let mint_asset = NonFungibleAsset::from_parts(faucet.id(), commitment);
    let p2id_output_note = Note::from(
        P2idNote::builder()
            .sender(faucet.id())
            .target(target_account.id())
            .asset(mint_asset)
            .note_type(NoteType::Public)
            .serial_number(builder.rng_mut().draw_word())
            .build()?,
    );

    let mint_storage = MintNoteStorage::new_public(
        p2id_output_note.recipient().clone(),
        mint_asset,
        NoteTag::with_account_target(target_account.id()),
    )?;
    let mint_note: Note = MintNote::builder()
        .sender(owner_account_id)
        .mint_storage(mint_storage)
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(mint_note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(faucet.id())
        .authenticated_input_note(mint_note.id())
        .extend_advice_inputs(minted_asset_witness(&faucet, mint_asset.id()))
        .build()
}

// BURN NOTE SETUPS
// ================================================================================================

/// Returns the transaction context for a network fungible faucet consuming a BURN note.
///
/// The BURN note carries [`BURN_AMOUNT`] of the fee-funded faucet's own (previously issued)
/// asset, which the faucet burns.
pub fn tx_consume_burn_note_network() -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    let owner_account_id = owner_account_id();
    let faucet = add_fee_funded_network_fungible_faucet(&mut builder, owner_account_id)?;

    let burn_asset = FungibleAsset::new(faucet.id(), BURN_AMOUNT)?;
    let burn_note: Note = BurnNote::builder()
        .sender(owner_account_id)
        .asset(burn_asset)
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(burn_note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(faucet.id())
        .authenticated_input_note(burn_note.id())
        .build()
}
