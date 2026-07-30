extern crate alloc;

use miden_agglayer::errors::{
    ERR_PAUSE_AGG_BRIDGE_TARGET_ACCOUNT_MISMATCH,
    ERR_PAUSE_AGG_BRIDGE_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_PAUSE_AGG_BRIDGE_UNKNOWN_SELECTOR,
};
use miden_agglayer::testing::bridge_admin_account_id;
use miden_agglayer::{
    AggLayerBridge,
    B2AggNote,
    ClaimNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    ConversionMetadata,
    DeregisterAggFaucetNote,
    ExitRoot,
    MetadataHash,
    PauseAggBridgeNote,
    RemoveGerNote,
    UpdateGerNote,
};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountId, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{Note, NoteAssets};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::PausableStorage;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED,
    ERR_PAUSABLE_IS_PAUSED,
    ERR_SENDER_LACKS_ROLE,
};
use miden_standards::interop::eth::EthAddress;
use miden_standards::note::{
    NetworkAccountTarget,
    NetworkNoteExt,
    NoteExecutionHint,
    PauseAction,
    PauseActionNote,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};

use super::test_utils::{
    ClaimDataSource,
    MIDEN_NETWORK_ID,
    create_existing_bridge_account_with_roles,
};

// HELPERS
// ================================================================================================

struct BridgeSetup {
    bridge: Account,
    faucet_manager: Account,
    ger_injector: Account,
    ger_remover: Account,
}

/// Creates the three operational-role wallets, builds the bridge account wired to those roles
/// (with the fixed [`bridge_admin_account_id`] as the `ADMIN` member), and registers the bridge
/// account with the builder.
fn setup_bridge(builder: &mut MockChainBuilder) -> anyhow::Result<BridgeSetup> {
    let faucet_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge = create_existing_bridge_account_with_roles(
        builder.rng_mut().draw_word(),
        faucet_manager.id(),
        ger_injector.id(),
        ger_remover.id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge.clone())?;

    Ok(BridgeSetup {
        bridge,
        faucet_manager,
        ger_injector,
        ger_remover,
    })
}

/// Builds a [`PauseAggBridgeNote`] for `action` sent by `sender` and targeting `target`.
fn pause_agg_bridge_note(
    sender: AccountId,
    target: AccountId,
    action: PauseAction,
) -> anyhow::Result<Note> {
    // Vary the rng seed by action so a pause and an unpause note built in the same test get
    // distinct serial numbers.
    let seed = match action {
        PauseAction::Pause => 41u32,
        PauseAction::Unpause => 42u32,
    };
    let mut rng = RandomCoin::new([Felt::from(seed); 4].into());
    let note = PauseAggBridgeNote::create(action, sender, target, &mut rng)?;
    Ok(note)
}

/// Builds an admin-sent [`PauseAggBridgeNote`] for `action` and stages it on the chain so it can
/// later be consumed as an authenticated note.
fn stage_pause_note(
    builder: &mut MockChainBuilder,
    bridge_id: AccountId,
    action: PauseAction,
) -> anyhow::Result<Note> {
    let note = pause_agg_bridge_note(bridge_admin_account_id(), bridge_id, action)?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    Ok(note)
}

/// Consumes a staged note on the bridge and commits the resulting transaction to the chain, so
/// subsequent transactions see the updated bridge state.
async fn consume_and_commit(
    mock_chain: &mut MockChain,
    bridge_id: AccountId,
    note: &Note,
) -> anyhow::Result<()> {
    let executed = mock_chain
        .build_transaction(bridge_id)
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    Ok(())
}

/// Reads the pause state from the committed bridge account.
fn is_bridge_paused(mock_chain: &MockChain, bridge_id: AccountId) -> anyhow::Result<bool> {
    let word = mock_chain
        .committed_account(bridge_id)?
        .storage()
        .get_item(PausableStorage::is_paused_slot())?;
    Ok(word != Word::default())
}

/// Shared skeleton for the "paused bridge rejects <entry point>" tests: sets up the bridge,
/// stages the note produced by `build_note`, pauses the bridge, and asserts that consuming the
/// note fails with `ERR_PAUSABLE_IS_PAUSED`.
async fn assert_note_rejected_while_paused(
    build_note: impl FnOnce(&mut MockChainBuilder, &BridgeSetup) -> anyhow::Result<Note>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let note = build_note(&mut builder, &setup)?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let pause_note = stage_pause_note(&mut builder, setup.bridge.id(), PauseAction::Pause)?;
    let mut mock_chain = builder.build()?;

    consume_and_commit(&mut mock_chain, setup.bridge.id(), &pause_note).await?;

    let result = mock_chain
        .build_transaction(setup.bridge.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_IS_PAUSED);
    Ok(())
}

/// An account ID standing in for a faucet the paused bridge never inspects (the pause guard
/// fires before any registry lookup).
fn dummy_faucet_id() -> AccountId {
    AccountIdBuilder::new().build_with_seed([7; 32])
}

const DUMMY_ETH_ADDRESS: &str = "0x00000000000000000000000000000000000000aa";

// TESTS
// ================================================================================================

/// An ADMIN-sent PAUSE_AGG_BRIDGE note pauses the bridge and a second one unpauses it. This
/// also proves the note passes the bridge's note allowlist and zero-fee schedule, and that it
/// is routable as a network note.
#[tokio::test]
async fn pause_agg_bridge_note_pauses_and_unpauses_bridge() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let pause_note = stage_pause_note(&mut builder, setup.bridge.id(), PauseAction::Pause)?;
    let unpause_note = stage_pause_note(&mut builder, setup.bridge.id(), PauseAction::Unpause)?;
    let mut mock_chain = builder.build()?;

    // The note must be discoverable by network-note routing (it carries a decodable
    // NetworkAccountTarget attachment).
    assert!(pause_note.is_network_note(), "pause note should be a routable network note");

    consume_and_commit(&mut mock_chain, setup.bridge.id(), &pause_note).await?;
    assert!(is_bridge_paused(&mock_chain, setup.bridge.id())?);

    consume_and_commit(&mut mock_chain, setup.bridge.id(), &unpause_note).await?;
    assert!(!is_bridge_paused(&mock_chain, setup.bridge.id())?);

    Ok(())
}

/// A PAUSE_AGG_BRIDGE note from a sender without the ADMIN role is rejected: the pause
/// procedures have no mapped role, so `authority::assert_authorized` falls back to the ADMIN
/// check.
#[tokio::test]
async fn non_admin_pause_reverts() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let mock_chain = builder.build()?;

    // The GER injector holds an operational role but not ADMIN.
    let note =
        pause_agg_bridge_note(setup.ger_injector.id(), setup.bridge.id(), PauseAction::Pause)?;
    let result = mock_chain
        .build_transaction(setup.bridge.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);
    Ok(())
}

/// A non-ADMIN sender cannot unpause a bridge that is actually paused.
#[tokio::test]
async fn non_admin_unpause_of_paused_bridge_reverts() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let pause_note = stage_pause_note(&mut builder, setup.bridge.id(), PauseAction::Pause)?;
    let mut mock_chain = builder.build()?;

    consume_and_commit(&mut mock_chain, setup.bridge.id(), &pause_note).await?;
    assert!(is_bridge_paused(&mock_chain, setup.bridge.id())?);

    let note =
        pause_agg_bridge_note(setup.ger_injector.id(), setup.bridge.id(), PauseAction::Unpause)?;
    let result = mock_chain
        .build_transaction(setup.bridge.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);
    assert!(is_bridge_paused(&mock_chain, setup.bridge.id())?);
    Ok(())
}

/// An admin-sent note whose NetworkAccountTarget attachment points at a different account is
/// rejected by the script's target assertion, so a pause/unpause note intended for one account
/// cannot be redirected onto the bridge.
#[tokio::test]
async fn wrongly_targeted_pause_note_reverts() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let mock_chain = builder.build()?;

    // Admin-sent, but targeting some other (public, network-targetable) account.
    let other_account = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_seed([9; 32]);
    let note = pause_agg_bridge_note(bridge_admin_account_id(), other_account, PauseAction::Pause)?;
    let result = mock_chain
        .build_transaction(setup.bridge.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSE_AGG_BRIDGE_TARGET_ACCOUNT_MISMATCH);
    Ok(())
}

/// The generic standards PAUSE_ACTION note (which carries no target assertion) is not in the
/// bridge's note allowlist, so no untargeted pause path into the bridge remains.
#[tokio::test]
async fn standards_pause_action_note_is_rejected_by_allowlist() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let mock_chain = builder.build()?;

    let mut rng = RandomCoin::new([Felt::from(43u32); 4].into());
    let note: Note = PauseActionNote::builder()
        .sender(bridge_admin_account_id())
        .account(setup.bridge.id())
        .action(PauseAction::Pause)
        .generate_serial_number(&mut rng)
        .build()?
        .into();
    let result = mock_chain
        .build_transaction(setup.bridge.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);
    Ok(())
}

/// A note carrying the PAUSE_AGG_BRIDGE script with malformed storage is rejected by the
/// script's guards: an unknown selector or a wrong storage item count.
#[rstest::rstest]
#[case::unknown_selector(vec![Felt::from(99u32)], ERR_PAUSE_AGG_BRIDGE_UNKNOWN_SELECTOR)]
#[case::wrong_item_count(
    vec![Felt::from(0u32), Felt::from(0u32)],
    ERR_PAUSE_AGG_BRIDGE_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
)]
#[tokio::test]
async fn malformed_pause_note_reverts(
    #[case] storage: alloc::vec::Vec<Felt>,
    #[case] expected_err: miden_protocol::errors::MasmError,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let mock_chain = builder.build()?;

    // Hand-craft the note storage, bypassing the builder, with a valid attachment targeting the
    // bridge so the script's earlier target assertion passes.
    let mut rng = RandomCoin::new([Felt::from(44u32); 4].into());
    let attachment = NetworkAccountTarget::new(setup.bridge.id(), NoteExecutionHint::Always)?;
    let note = NoteBuilder::new(bridge_admin_account_id(), &mut rng)
        .script(PauseAggBridgeNote::script())
        .note_storage(storage)?
        .attachment(attachment)
        .build()?;
    let result = mock_chain
        .build_transaction(setup.bridge.id())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, expected_err);
    Ok(())
}

/// A paused bridge rejects GER injection via UPDATE_GER.
#[tokio::test]
async fn paused_bridge_rejects_update_ger() -> anyhow::Result<()> {
    assert_note_rejected_while_paused(|builder, setup| {
        Ok(UpdateGerNote::create(
            ExitRoot::from([0x11; 32]),
            setup.ger_injector.id(),
            setup.bridge.id(),
            builder.rng_mut(),
        )?)
    })
    .await
}

/// A paused bridge rejects faucet registration via CONFIG_AGG_BRIDGE (`register_faucet` panics
/// before any storage write).
#[tokio::test]
async fn paused_bridge_rejects_register_faucet() -> anyhow::Result<()> {
    assert_note_rejected_while_paused(|builder, setup| {
        Ok(ConfigAggBridgeNote::create(
            ConversionMetadata {
                faucet_account_id: dummy_faucet_id(),
                origin_token_address: EthAddress::from_hex(DUMMY_ETH_ADDRESS)?,
                scale: 0,
                origin_network: 1,
                is_native: false,
                metadata_hash: MetadataHash::from_token_info("Token", "TOK", 8),
            },
            setup.faucet_manager.id(),
            setup.bridge.id(),
            builder.rng_mut(),
        )?)
    })
    .await
}

/// A paused bridge rejects faucet deregistration via DEREGISTER_AGG_FAUCET (the pause guard
/// fires before the is-registered check).
#[tokio::test]
async fn paused_bridge_rejects_deregister_faucet() -> anyhow::Result<()> {
    assert_note_rejected_while_paused(|builder, setup| {
        Ok(DeregisterAggFaucetNote::create(
            dummy_faucet_id(),
            setup.faucet_manager.id(),
            setup.bridge.id(),
            builder.rng_mut(),
        )?)
    })
    .await
}

/// A paused bridge rejects bridging out via B2AGG (the pause guard fires before the faucet
/// registry lookup).
#[tokio::test]
async fn paused_bridge_rejects_bridge_out() -> anyhow::Result<()> {
    assert_note_rejected_while_paused(|builder, setup| {
        let faucet_id = dummy_faucet_id();
        let asset: Asset = FungibleAsset::new(faucet_id, 100)?.into();
        Ok(B2AggNote::create(
            1,
            EthAddress::from_hex(DUMMY_ETH_ADDRESS)?,
            NoteAssets::new(vec![asset])?,
            setup.bridge.id(),
            faucet_id,
            builder.rng_mut(),
        )?)
    })
    .await
}

/// A paused bridge rejects claims via CLAIM (the pause guard fires before proof validation).
#[tokio::test]
async fn paused_bridge_rejects_claim() -> anyhow::Result<()> {
    assert_note_rejected_while_paused(|builder, setup| {
        let (proof_data, leaf_data, _ger, _cgi_chain_hash) = ClaimDataSource::L1ToMiden.get_data();
        let miden_claim_amount = leaf_data
            .amount
            .scale_to_asset_amount(10)
            .expect("test vector amount should scale");
        let storage = ClaimNoteStorage {
            proof_data,
            leaf_data,
            miden_claim_amount,
        };
        Ok(ClaimNote::create(
            storage,
            setup.bridge.id(),
            setup.faucet_manager.id(),
            builder.rng_mut(),
        )?)
    })
    .await
}

/// `remove_ger` is deliberately exempt from the pause: a paused bridge can still revoke a
/// registered GER, the emergency remediation this control exists for.
#[tokio::test]
async fn paused_bridge_allows_remove_ger() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;

    let ger = ExitRoot::from([0x22; 32]);
    let update_note =
        UpdateGerNote::create(ger, setup.ger_injector.id(), setup.bridge.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_note.clone()));
    let remove_note =
        RemoveGerNote::create(ger, setup.ger_remover.id(), setup.bridge.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(remove_note.clone()));
    let pause_note = stage_pause_note(&mut builder, setup.bridge.id(), PauseAction::Pause)?;

    let mut mock_chain = builder.build()?;

    // Register the GER while the bridge is live, then pause.
    consume_and_commit(&mut mock_chain, setup.bridge.id(), &update_note).await?;
    consume_and_commit(&mut mock_chain, setup.bridge.id(), &pause_note).await?;

    // The GER remover can still revoke the GER while the bridge is paused.
    consume_and_commit(&mut mock_chain, setup.bridge.id(), &remove_note).await?;

    let bridge = mock_chain.committed_account(setup.bridge.id())?;
    assert!(is_bridge_paused(&mock_chain, setup.bridge.id())?);
    assert!(
        !AggLayerBridge::is_ger_registered(ger, bridge)?,
        "GER should have been removed while the bridge was paused"
    );

    Ok(())
}

/// Unpausing restores normal operation: a gated procedure that would have aborted while paused
/// succeeds after the unpause.
#[tokio::test]
async fn unpause_restores_operation() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;

    let ger = ExitRoot::from([0x33; 32]);
    let update_note =
        UpdateGerNote::create(ger, setup.ger_injector.id(), setup.bridge.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_note.clone()));
    let pause_note = stage_pause_note(&mut builder, setup.bridge.id(), PauseAction::Pause)?;
    let unpause_note = stage_pause_note(&mut builder, setup.bridge.id(), PauseAction::Unpause)?;

    let mut mock_chain = builder.build()?;

    consume_and_commit(&mut mock_chain, setup.bridge.id(), &pause_note).await?;
    consume_and_commit(&mut mock_chain, setup.bridge.id(), &unpause_note).await?;

    consume_and_commit(&mut mock_chain, setup.bridge.id(), &update_note).await?;

    let bridge = mock_chain.committed_account(setup.bridge.id())?;
    assert!(
        AggLayerBridge::is_ger_registered(ger, bridge)?,
        "GER injection should succeed after unpausing"
    );

    Ok(())
}
