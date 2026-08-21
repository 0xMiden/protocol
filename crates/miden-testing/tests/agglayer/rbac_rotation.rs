//! Tests on-chain rotation of AggLayer account RBAC roles via `RBAC_CONFIG` notes.
//!
//! The generic RBAC component and note-script tests live in `tests/scripts/rbac/`
//! and run against a bare RBAC account. This suite proves the AggLayer account wiring: an
//! `RBAC_CONFIG` note passes the bridge or faucet's [`AuthNetworkAccount`] allowlist and zero-fee
//! schedule, and a rotated role actually changes which senders may invoke role-gated procedures.
//!
//! [`AuthNetworkAccount`]: miden_standards::account::auth::AuthNetworkAccount

extern crate alloc;

use alloc::collections::BTreeSet;

use miden_agglayer::testing::create_existing_agglayer_faucet;
use miden_agglayer::{
    AggLayerBridge,
    B2AggNote,
    ClaimNote,
    ConfigAggBridgeNote,
    DeregisterAggFaucetNote,
    ExitRoot,
    RemoveGerNote,
    UpdateGerNote,
};
use miden_crypto::rand::FeltRng;
use miden_protocol::account::AccountId;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::RoleBasedAccessControl;
use miden_standards::account::auth::NetworkAccount;
use miden_standards::errors::standards::ERR_SENDER_LACKS_ROLE;
use miden_standards::note::{
    ConstantFeePolicyConfigNote,
    FeeSponsorshipNote,
    NetworkAccountConfigNote,
    PauseConfig,
    PauseConfigNote,
    RbacConfig,
    RbacConfigNote,
};
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use super::test_utils::{
    MIDEN_NETWORK_ID,
    bridge_admin_account_id,
    create_existing_bridge_account_with_roles,
    is_bridge_paused,
    setup_bridge,
};
use crate::consume_note;
// The role-membership storage getter is shared with the `rbac` suite, which owns the
// exhaustive tests of the underlying component.
use crate::scripts::rbac::is_role_member;

const GER_BYTES: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];

// HELPERS
// ================================================================================================

/// Builds an `RBAC_CONFIG` note for `config` sent by `sender` and targeted at `account_id`.
fn rbac_config_note(
    sender: AccountId,
    account_id: AccountId,
    config: RbacConfig,
    rng: &mut impl FeltRng,
) -> anyhow::Result<Note> {
    let note = RbacConfigNote::builder()
        .sender(sender)
        .target(account_id)
        .config(config)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

// TESTS
// ================================================================================================

/// The faucet accepts an allowlisted `RBAC_CONFIG` note and applies its role update.
#[tokio::test]
async fn faucet_accepts_rbac_config_note() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let initial_admin = bridge_admin_account_id();
    let new_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        "AGG",
        6,
        Felt::from(1_000u32),
        Felt::ZERO,
        initial_admin,
        initial_admin,
    );
    let faucet_id = faucet.id();
    let admin_role = RoleBasedAccessControl::admin_role();

    let grant = rbac_config_note(
        initial_admin,
        faucet_id,
        RbacConfig::GrantRole {
            role: admin_role.clone(),
            account: new_admin.id(),
        },
        builder.rng_mut(),
    )?;

    builder.add_account(faucet)?;
    builder.add_output_note(RawOutputNote::Full(grant.clone()));
    let mut mock_chain = builder.build()?;

    consume_note(&mut mock_chain, faucet_id, &grant).await?;
    assert!(is_role_member(
        mock_chain.committed_account(faucet_id)?,
        &admin_role,
        new_admin.id(),
    )?);

    Ok(())
}

/// End-to-end rotation of an operational role: the admin grants `GER_INJECTOR` to a fresh
/// account via an `RBAC_CONFIG` note consumed by the bridge, and the new holder's `UPDATE_GER`
/// note then succeeds.
#[tokio::test]
async fn granted_ger_injector_can_update_ger() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let new_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let bridge_id = setup.bridge.id();

    let grant = rbac_config_note(
        bridge_admin_account_id(),
        bridge_id,
        RbacConfig::GrantRole {
            role: AggLayerBridge::ger_injector_role(),
            account: new_injector.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(grant.clone()));

    let ger = ExitRoot::from(GER_BYTES);
    let update_ger_note =
        UpdateGerNote::create(ger, new_injector.id(), bridge_id, builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mut mock_chain = builder.build()?;

    consume_note(&mut mock_chain, bridge_id, &grant).await?;
    assert!(is_role_member(
        mock_chain.committed_account(bridge_id)?,
        &AggLayerBridge::ger_injector_role(),
        new_injector.id()
    )?);

    consume_note(&mut mock_chain, bridge_id, &update_ger_note).await?;
    assert!(AggLayerBridge::is_ger_registered(
        ger,
        mock_chain.committed_account(bridge_id)?
    )?);
    Ok(())
}

/// The admin revokes the seeded `GER_INJECTOR` holder via an `RBAC_CONFIG` note; the revoked
/// account's subsequent `UPDATE_GER` note is rejected by the bridge's role check.
#[tokio::test]
async fn revoked_ger_injector_cannot_update_ger() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let bridge_id = setup.bridge.id();

    let revoke = rbac_config_note(
        bridge_admin_account_id(),
        bridge_id,
        RbacConfig::RevokeRole {
            role: AggLayerBridge::ger_injector_role(),
            account: setup.ger_injector.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(revoke.clone()));

    let ger = ExitRoot::from(GER_BYTES);
    let update_ger_note =
        UpdateGerNote::create(ger, setup.ger_injector.id(), bridge_id, builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mut mock_chain = builder.build()?;

    consume_note(&mut mock_chain, bridge_id, &revoke).await?;
    assert!(!is_role_member(
        mock_chain.committed_account(bridge_id)?,
        &AggLayerBridge::ger_injector_role(),
        setup.ger_injector.id()
    )?);

    let result = mock_chain
        .build_transaction(bridge_id)
        .authenticated_input_note(update_ger_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);
    Ok(())
}

/// A paused bridge still consumes `RBAC_CONFIG` notes: role rotation stays available while
/// bridging is halted.
#[tokio::test]
async fn paused_bridge_allows_role_rotation() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let new_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let bridge_id = setup.bridge.id();

    let pause = AggLayerBridge::pause_note(
        PauseConfig::Pause,
        bridge_admin_account_id(),
        bridge_id,
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(pause.clone()));

    let grant = rbac_config_note(
        bridge_admin_account_id(),
        bridge_id,
        RbacConfig::GrantRole {
            role: AggLayerBridge::ger_injector_role(),
            account: new_injector.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(grant.clone()));

    let mut mock_chain = builder.build()?;

    consume_note(&mut mock_chain, bridge_id, &pause).await?;
    assert!(is_bridge_paused(&mock_chain, bridge_id)?);

    consume_note(&mut mock_chain, bridge_id, &grant).await?;
    assert!(is_role_member(
        mock_chain.committed_account(bridge_id)?,
        &AggLayerBridge::ger_injector_role(),
        new_injector.id()
    )?);
    // the rotation must not have cleared the pause
    assert!(is_bridge_paused(&mock_chain, bridge_id)?);
    Ok(())
}

/// Pins the bridge's input-note allowlist.
#[test]
fn bridge_allowed_notes_pin() {
    let expected = BTreeSet::from([
        ClaimNote::script_root(),
        B2AggNote::script_root(),
        ConfigAggBridgeNote::script_root(),
        DeregisterAggFaucetNote::script_root(),
        UpdateGerNote::script_root(),
        RemoveGerNote::script_root(),
        PauseConfigNote::script_root(),
        RbacConfigNote::script_root(),
        ConstantFeePolicyConfigNote::script_root(),
        NetworkAccountConfigNote::script_root(),
        FeeSponsorshipNote::script_root(),
    ]);
    assert_eq!(AggLayerBridge::allowed_notes(), expected);

    let dummy = bridge_admin_account_id();
    let bridge = create_existing_bridge_account_with_roles(
        Word::default(),
        dummy,
        dummy,
        dummy,
        dummy,
        dummy,
        MIDEN_NETWORK_ID,
    );
    let network_account =
        NetworkAccount::try_from(bridge).expect("bridge should be a network account");
    assert_eq!(network_account.allowed_notes().allowed_script_roots(), &expected);

    // the tx-script allowlist carries only the canonical expiration script
    assert_eq!(
        network_account.allowed_tx_scripts().allowed_script_roots(),
        &BTreeSet::from([ExpirationTransactionScript::script_root()])
    );
}
