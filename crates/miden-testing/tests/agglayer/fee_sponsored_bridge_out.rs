//! End-to-end test of the fee-sponsored double-hop through the real agglayer contracts:
//! B2AGG (bridge, hop 1) spawns BURN (faucet, hop 2). The user funds the entire chain with one
//! sponsorship note; the bridge passes the remainder into a fresh sponsorship for the BURN note.
//!
//! The accounts are wired test-side only: the production agglayer builders stay fee-less.

use std::collections::BTreeSet;

use miden_agglayer::{
    AggLayerBridge,
    AggLayerFaucet,
    B2AggNote,
    ConfigAggBridgeNote,
    ConversionMetadata,
    EthAddress,
    ExitRoot,
    MetadataHash,
};
use miden_crypto::rand::FeltRng;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountId, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset, TokenSymbol};
use miden_protocol::note::{Note, NoteAssets, NoteScriptRoot};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::auth::AuthNetworkAccountWithFees;
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::fees::{FeeManager, FeeScheduleEntry};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::ERR_FEE_MANAGER_INSUFFICIENT_DOWNSTREAM_SPONSORSHIP;
use miden_standards::note::{FeeNote, NetworkAccountTarget, NetworkSponsorshipNote, StandardNote};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::utils::hex_to_bytes;

use super::test_utils::SOLIDITY_MTF_VECTORS;

// The bridge prices B2AGG; the faucet prices BURN. All admin notes are priced free.
const BRIDGE_APP_FEE: u64 = 30;
const BRIDGE_PROTOCOL_FEE: u64 = 12;
const FAUCET_APP_FEE: u64 = 7;
const FAUCET_PROTOCOL_FEE: u64 = 5;
const BRIDGE_TOTAL: u64 = BRIDGE_APP_FEE + BRIDGE_PROTOCOL_FEE;
const FAUCET_TOTAL: u64 = FAUCET_APP_FEE + FAUCET_PROTOCOL_FEE;

fn fee_asset(amount: u64) -> anyhow::Result<Asset> {
    Ok(FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?, amount)?.into())
}

/// Prices every note in `allowed` for free, so the account's whole admin surface stays consumable.
fn free_schedule(allowed: &BTreeSet<NoteScriptRoot>) -> anyhow::Result<FeeManager> {
    let mut fee_manager = FeeManager::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?)?;
    for root in allowed {
        fee_manager = fee_manager.with_fee(*root, FeeScheduleEntry::new(0, 0)?);
    }
    Ok(fee_manager)
}

/// The production bridge composition plus the fee stack: `BasicWallet` (the sponsorship deposit
/// needs `receive_asset`), `Authority` (gates `set_fee`), `FeeManager`, and the combined
/// allowlist + settlement auth.
fn fee_enabled_bridge_account(
    seed: Word,
    admin: AccountId,
    injector: AccountId,
    remover: AccountId,
) -> anyhow::Result<Account> {
    let fee_manager = free_schedule(&AggLayerBridge::allowed_notes())?
        .with_fee(
            B2AggNote::script_root(),
            FeeScheduleEntry::new(BRIDGE_APP_FEE, BRIDGE_PROTOCOL_FEE)?,
        )
        .with_spawn(B2AggNote::script_root(), StandardNote::BURN.script_root());

    Ok(Account::builder(seed.into())
        .account_type(AccountType::Public)
        .with_component(AggLayerBridge::new(admin, injector, remover))
        .with_component(BasicWallet)
        .with_component(Authority::AuthControlled)
        .with_component(fee_manager)
        .with_auth_component(AuthNetworkAccountWithFees::with_allowed_notes(
            AggLayerBridge::allowed_notes(),
        )?)
        .build_existing()?)
}

/// The production faucet composition plus the fee stack. The faucet's existing
/// `Authority::OwnerControlled` (owner = bridge) also gates `set_fee`; no second authority is
/// added.
fn fee_enabled_agglayer_faucet(
    seed: Word,
    symbol: &str,
    decimals: u8,
    token_supply: u64,
    bridge_id: AccountId,
) -> anyhow::Result<Account> {
    let fee_manager = free_schedule(&AggLayerFaucet::allowed_notes())?.with_fee(
        StandardNote::BURN.script_root(),
        FeeScheduleEntry::new(FAUCET_APP_FEE, FAUCET_PROTOCOL_FEE)?,
    );

    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::owner_only())
        .allowed_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build();

    Ok(Account::builder(seed.into())
        .account_type(AccountType::Public)
        .with_component(AggLayerFaucet::new(
            TokenSymbol::new(symbol)?,
            decimals,
            FungibleAsset::MAX_AMOUNT.into(),
            Felt::new(token_supply)?,
        )?)
        .with_component(Ownable2Step::new(bridge_id))
        .with_component(Authority::OwnerControlled)
        .with_components(token_policy_manager)
        .with_component(BasicWallet)
        .with_component(fee_manager)
        .with_auth_component(AuthNetworkAccountWithFees::with_allowed_notes(
            AggLayerFaucet::allowed_notes(),
        )?)
        .build_existing()?)
}

struct Fixture {
    mock_chain: MockChain,
    bridge: Account,
    faucet: Account,
    config_note: Note,
    b2agg_note: Note,
    sponsorship_note: Note,
    bridged_amount: u64,
}

/// Builds the fee-enabled bridge and faucet, the faucet-registering CONFIG note, one B2AGG note
/// (leaf 0 of the Solidity vectors), and a sponsorship carrying `budget`.
fn setup(budget: u64, is_native: bool) -> anyhow::Result<Fixture> {
    let vectors = &*SOLIDITY_MTF_VECTORS;
    let bridged_amount = vectors.amounts[0].parse::<u64>()?;

    let mut builder = MockChain::builder();
    let auth = Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    };
    let bridge_admin = builder.add_existing_wallet(auth.clone())?;
    let ger_injector = builder.add_existing_wallet(auth.clone())?;
    let ger_remover = builder.add_existing_wallet(auth.clone())?;
    let user = builder.add_existing_wallet(auth)?;

    let bridge = fee_enabled_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_injector.id(),
        ger_remover.id(),
    )?;
    builder.add_account(bridge.clone())?;

    let faucet = fee_enabled_agglayer_faucet(
        builder.rng_mut().draw_word(),
        &vectors.token_symbol,
        vectors.token_decimals,
        bridged_amount,
        bridge.id(),
    )?;
    builder.add_account(faucet.clone())?;

    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: faucet.id(),
            origin_token_address: EthAddress::from_hex(&vectors.origin_token_address)
                .expect("valid origin token address"),
            scale: 0,
            origin_network: 64,
            is_native,
            metadata_hash: MetadataHash::from_token_info(
                &vectors.token_name,
                &vectors.token_symbol,
                vectors.token_decimals,
            ),
        },
        bridge_admin.id(),
        bridge.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    let bridge_asset: Asset = FungibleAsset::new(faucet.id(), bridged_amount)?.into();
    let b2agg_note = B2AggNote::create(
        vectors.destination_networks[0],
        EthAddress::from_hex(&vectors.destination_addresses[0]).expect("valid destination"),
        NoteAssets::new(vec![bridge_asset])?,
        bridge.id(),
        user.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(b2agg_note.clone()));

    let sponsorship_note = Note::from(
        NetworkSponsorshipNote::builder()
            .sender(user.id())
            .target_account(bridge.id())?
            .feature_note_id(b2agg_note.id())
            .asset(fee_asset(budget)?)
            .generate_serial_number(builder.rng_mut())
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    Ok(Fixture {
        mock_chain,
        bridge,
        faucet,
        config_note,
        b2agg_note,
        sponsorship_note,
        bridged_amount,
    })
}

/// Registers the faucet by consuming the CONFIG note against the bridge -- free-priced, so no
/// sponsorship travels with it.
async fn register_faucet(f: &mut Fixture) -> anyhow::Result<()> {
    let executed = f
        .mock_chain
        .build_tx_context(f.bridge.id(), &[f.config_note.id()], &[])?
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 0, "a free note settles without a FEE note");

    f.bridge.apply_patch(executed.account_patch())?;
    f.mock_chain.add_pending_executed_transaction(&executed)?;
    f.mock_chain.prove_next_block()?;
    Ok(())
}

/// Finds the output note bearing `root` in `executed`.
fn find_output_note(executed: &ExecutedTransaction, root: NoteScriptRoot) -> Option<&Note> {
    executed.output_notes().iter().find_map(|note| match note {
        RawOutputNote::Full(note) if note.script().root() == root => Some(note),
        _ => None,
    })
}

/// The full fee-sponsored double-hop: B2AGG against the bridge, then BURN against the faucet.
#[tokio::test]
async fn fee_sponsored_bridge_out_double_hop() -> anyhow::Result<()> {
    let vectors = &*SOLIDITY_MTF_VECTORS;
    let mut f = setup(BRIDGE_TOTAL + FAUCET_TOTAL, false)?;
    register_faucet(&mut f).await?;

    // ---- HOP 1: the bridge consumes [sponsorship, B2AGG] -----------------------------------
    let faucet_foreign = f.mock_chain.get_foreign_account_inputs(f.faucet.id())?;
    let hop1 = f
        .mock_chain
        .build_tx_context(f.bridge.clone(), &[f.sponsorship_note.id(), f.b2agg_note.id()], &[])?
        .foreign_accounts(vec![faucet_foreign])
        .add_note_script(NetworkSponsorshipNote::script())
        .add_note_script(FeeNote::script())
        .build()?
        .execute()
        .await?;

    assert_eq!(hop1.output_notes().num_notes(), 3, "expected BURN, child sponsorship and FEE");

    let burn_note = find_output_note(&hop1, StandardNote::BURN.script_root())
        .expect("the bridge spawns the BURN note");
    let bridged: Asset = FungibleAsset::new(f.faucet.id(), f.bridged_amount)?.into();
    assert!(burn_note.assets().iter().any(|asset| asset == &bridged));
    let target = NetworkAccountTarget::try_from(burn_note.attachments())?;
    assert_eq!(target.target_id(), f.faucet.id(), "the BURN note targets the faucet");

    // The child sponsorship carries the remainder -- here exactly the faucet's FPI-quoted price
    // -- and binds the BURN note it pays for.
    let child_sponsorship = find_output_note(&hop1, NetworkSponsorshipNote::script_root())
        .expect("the bridge mints a sponsorship for the BURN note");
    assert_eq!(
        child_sponsorship.assets().iter().next().copied(),
        Some(fee_asset(FAUCET_TOTAL)?),
    );

    let fee_note = find_output_note(&hop1, FeeNote::script_root())
        .expect("the bridge forwards its protocol fee");
    assert_eq!(fee_note.assets().iter().next().copied(), Some(fee_asset(BRIDGE_PROTOCOL_FEE)?));

    f.bridge.apply_patch(hop1.account_patch())?;
    assert_eq!(
        f.bridge.vault().get_balance(fee_asset(0)?.id())?.as_u64(),
        BRIDGE_APP_FEE,
        "the bridge keeps its application fee and fronts nothing",
    );

    // Fees did not perturb the Solidity-compatible exit tree. The LET slots are read directly:
    // the fee-enabled bridge carries extra components, so its code commitment differs from the
    // production bridge and the checked `read_local_exit_root` helper would reject it.
    assert_eq!(AggLayerBridge::read_let_num_leaves(&f.bridge), 1);
    let expected_ler = ExitRoot::new(hex_to_bytes(&vectors.roots[0])?).to_elements();
    let mut ler = f.bridge.storage().get_item(AggLayerBridge::let_root_lo_slot_name())?.to_vec();
    ler.extend(f.bridge.storage().get_item(AggLayerBridge::let_root_hi_slot_name())?.to_vec());
    assert_eq!(ler, expected_ler);

    let (burn_note_id, child_sponsorship_id) = (burn_note.id(), child_sponsorship.id());
    f.mock_chain.add_pending_executed_transaction(&hop1)?;
    f.mock_chain.prove_next_block()?;

    // ---- HOP 2: the faucet consumes [child sponsorship, BURN] ------------------------------
    let hop2 = f
        .mock_chain
        .build_tx_context(f.faucet.clone(), &[child_sponsorship_id, burn_note_id], &[])?
        .add_note_script(NetworkSponsorshipNote::script())
        .add_note_script(FeeNote::script())
        .build()?
        .execute()
        .await?;

    assert_eq!(hop2.output_notes().num_notes(), 1, "hop 2 emits only its FEE note");
    let hop2_fee = find_output_note(&hop2, FeeNote::script_root())
        .expect("the faucet forwards its protocol fee");
    assert_eq!(hop2_fee.assets().iter().next().copied(), Some(fee_asset(FAUCET_PROTOCOL_FEE)?));

    f.faucet.apply_patch(hop2.account_patch())?;
    assert_eq!(
        f.faucet.vault().get_balance(fee_asset(0)?.id())?.as_u64(),
        FAUCET_APP_FEE,
        "the faucet keeps its application fee",
    );
    assert_eq!(
        FungibleFaucet::try_from(f.faucet.storage())?.token_supply(),
        AssetAmount::new(0)?,
        "the bridged amount was burned",
    );

    Ok(())
}

/// A sponsorship covering only the bridge's own fee is rejected: the bridge never fronts the
/// faucet's fee for the BURN note it spawns.
#[tokio::test]
async fn underfunded_downstream_is_rejected() -> anyhow::Result<()> {
    let mut f = setup(BRIDGE_TOTAL, false)?;
    register_faucet(&mut f).await?;

    let faucet_foreign = f.mock_chain.get_foreign_account_inputs(f.faucet.id())?;
    let result = f
        .mock_chain
        .build_tx_context(f.bridge.clone(), &[f.sponsorship_note.id(), f.b2agg_note.id()], &[])?
        .foreign_accounts(vec![faucet_foreign])
        .add_note_script(NetworkSponsorshipNote::script())
        .add_note_script(FeeNote::script())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_INSUFFICIENT_DOWNSTREAM_SPONSORSHIP);

    Ok(())
}

/// A native-asset B2AGG takes the `lock_asset` path and spawns nothing: the declared spawn is a
/// permission, so the transaction settles with the bridge's own fee alone.
#[tokio::test]
async fn native_asset_lock_settles_without_a_spawn() -> anyhow::Result<()> {
    let mut f = setup(BRIDGE_TOTAL, true)?;
    register_faucet(&mut f).await?;

    let hop1 = f
        .mock_chain
        .build_tx_context(f.bridge.clone(), &[f.sponsorship_note.id(), f.b2agg_note.id()], &[])?
        .add_note_script(NetworkSponsorshipNote::script())
        .add_note_script(FeeNote::script())
        .build()?
        .execute()
        .await?;

    assert_eq!(hop1.output_notes().num_notes(), 1, "no BURN note: only the FEE note is emitted");
    let fee_note = find_output_note(&hop1, FeeNote::script_root())
        .expect("the bridge forwards its protocol fee");
    assert_eq!(fee_note.assets().iter().next().copied(), Some(fee_asset(BRIDGE_PROTOCOL_FEE)?));

    f.bridge.apply_patch(hop1.account_patch())?;
    let locked: Asset = FungibleAsset::new(f.faucet.id(), f.bridged_amount)?.into();
    assert_eq!(
        f.bridge.vault().get_balance(locked.id())?.as_u64(),
        f.bridged_amount,
        "the native asset is locked in the bridge vault",
    );
    assert_eq!(AggLayerBridge::read_let_num_leaves(&f.bridge), 1);

    Ok(())
}
