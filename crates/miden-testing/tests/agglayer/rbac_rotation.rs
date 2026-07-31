//! Tests on-chain rotation of the AggLayer bridge's RBAC roles via `RBAC_CONFIG` notes.
//!
//! The generic RBAC component and note-script tests live in `tests/scripts/rbac/`
//! and run against a bare RBAC account. This suite proves the bridge-specific wiring: an
//! `RBAC_CONFIG` note passes the bridge's [`AuthNetworkAccount`] allowlist and zero-fee schedule,
//! and a rotated role actually changes which senders may invoke the bridge's role-gated
//! procedures.
//!
//! [`AuthNetworkAccount`]: miden_standards::account::auth::AuthNetworkAccount

extern crate alloc;

use alloc::collections::BTreeSet;

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
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::errors::standards::ERR_SENDER_LACKS_ROLE;
use miden_standards::note::{RbacConfig, RbacConfigNote};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use super::test_utils::setup_bridge;
// The role-membership storage getter is shared with the `rbac` suite, which owns the
// exhaustive tests of the underlying component.
use crate::scripts::rbac::is_role_member;

const GER_BYTES: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];

// HELPERS
// ================================================================================================

/// Builds an `RBAC_CONFIG` note for `config` sent by `sender` and targeted at the bridge.
fn bridge_rbac_config_note(
    sender: AccountId,
    bridge_id: AccountId,
    config: RbacConfig,
    rng: &mut impl FeltRng,
) -> anyhow::Result<Note> {
    let note = RbacConfigNote::builder()
        .sender(sender)
        .account(bridge_id)
        .config(config)
        .generate_serial_number(rng)
        .build()?
        .into();
    Ok(note)
}

/// Executes the (chain-committed) `note` against the bridge, commits the transaction into the
/// next block, and applies the resulting account patch to `bridge_account`.
async fn execute_bridge_note(
    mock_chain: &mut MockChain,
    bridge_account: &mut Account,
    note: &Note,
) -> anyhow::Result<()> {
    let executed = mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    bridge_account.apply_patch(executed.account_patch())?;
    Ok(())
}

// TESTS
// ================================================================================================

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
    let mut bridge_account = setup.bridge_account;

    let grant = bridge_rbac_config_note(
        setup.admin.id(),
        bridge_account.id(),
        RbacConfig::GrantRole {
            role: AggLayerBridge::ger_injector_role(),
            account: new_injector.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(grant.clone()));

    let ger = ExitRoot::from(GER_BYTES);
    let update_ger_note =
        UpdateGerNote::create(ger, new_injector.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mut mock_chain = builder.build()?;

    execute_bridge_note(&mut mock_chain, &mut bridge_account, &grant).await?;
    assert!(is_role_member(
        &bridge_account,
        &AggLayerBridge::ger_injector_role(),
        new_injector.id()
    )?);

    execute_bridge_note(&mut mock_chain, &mut bridge_account, &update_ger_note).await?;
    assert!(AggLayerBridge::is_ger_registered(ger, &bridge_account)?);
    Ok(())
}

/// The admin revokes the seeded `GER_INJECTOR` holder via an `RBAC_CONFIG` note; the revoked
/// account's subsequent `UPDATE_GER` note is rejected by the bridge's role check.
#[tokio::test]
async fn revoked_ger_injector_cannot_update_ger() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let mut bridge_account = setup.bridge_account;

    let revoke = bridge_rbac_config_note(
        setup.admin.id(),
        bridge_account.id(),
        RbacConfig::RevokeRole {
            role: AggLayerBridge::ger_injector_role(),
            account: setup.ger_injector.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(revoke.clone()));

    let ger = ExitRoot::from(GER_BYTES);
    let update_ger_note = UpdateGerNote::create(
        ger,
        setup.ger_injector.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mut mock_chain = builder.build()?;

    execute_bridge_note(&mut mock_chain, &mut bridge_account, &revoke).await?;
    assert!(!is_role_member(
        &bridge_account,
        &AggLayerBridge::ger_injector_role(),
        setup.ger_injector.id()
    )?);

    let result = mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(update_ger_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);
    Ok(())
}

/// Pins the exact contents of the bridge's input-note allowlist so that any drift — adding or
/// removing an accepted note — is a deliberate, reviewed change.
#[test]
fn bridge_allowed_notes_pin() {
    let expected = BTreeSet::from([
        ClaimNote::script_root(),
        B2AggNote::script_root(),
        ConfigAggBridgeNote::script_root(),
        DeregisterAggFaucetNote::script_root(),
        UpdateGerNote::script_root(),
        RemoveGerNote::script_root(),
        RbacConfigNote::script_root(),
    ]);
    assert_eq!(AggLayerBridge::allowed_notes(), expected);
}
