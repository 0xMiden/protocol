//! Tests on-chain rotation of the AggLayer bridge's RBAC roles via `RBAC_ACTION` notes.
//!
//! The generic RBAC component and note-script tests live in `tests/scripts/{rbac,rbac_action}.rs`
//! and run against a bare RBAC account. This suite proves the bridge-specific wiring: an
//! `RBAC_ACTION` note passes the bridge's [`AuthNetworkAccount`] allowlist and zero-fee schedule,
//! its RBAC procedures authorize against the note sender, and a rotated role actually changes
//! which senders may invoke the bridge's role-gated procedures.
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
use miden_standards::account::access::RoleBasedAccessControl;
use miden_standards::errors::standards::{ERR_SENDER_LACKS_ROLE, ERR_SENDER_NOT_ROLE_ADMIN};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint, RbacAction, RbacActionNote};
use miden_testing::{Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};
use rstest::rstest;

use super::test_utils::{MIDEN_NETWORK_ID, create_existing_bridge_account_with_admin_and_roles};
// The role-membership storage getters are shared with the `rbac` suite, which owns the
// exhaustive tests of the underlying component.
use crate::scripts::rbac::{is_role_member, role};

const GER_BYTES: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];

// HELPERS
// ================================================================================================

/// The bridge account together with the wallet IDs of its seeded `ADMIN` member and
/// `GER_INJECTOR` holder.
struct RotationSetup {
    bridge_account: Account,
    admin: AccountId,
    ger_injector: AccountId,
}

/// Creates the admin and operational-role wallets, builds the bridge account wired to them, and
/// registers the bridge account with the builder.
fn setup_bridge(builder: &mut MockChainBuilder) -> anyhow::Result<RotationSetup> {
    let admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let faucet_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account_with_admin_and_roles(
        bridge_seed,
        admin.id(),
        faucet_manager.id(),
        ger_injector.id(),
        ger_remover.id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge_account.clone())?;

    Ok(RotationSetup {
        bridge_account,
        admin: admin.id(),
        ger_injector: ger_injector.id(),
    })
}

/// Builds an `RBAC_ACTION` note for `action` sent by `sender` and targeted at the bridge.
///
/// The [`NetworkAccountTarget`] attachment mirrors the call pattern of the other bridge notes:
/// it routes the note to the bridge for network execution. Unlike those notes' scripts, the
/// `RBAC_ACTION` script does not validate the attachment target — authorization rests entirely
/// on the RBAC procedures' note-sender checks.
fn bridge_rbac_action_note(
    sender: AccountId,
    bridge_id: AccountId,
    action: RbacAction,
    rng: &mut impl FeltRng,
) -> anyhow::Result<Note> {
    let attachment = NetworkAccountTarget::new(bridge_id, NoteExecutionHint::Always)?;
    let note = RbacActionNote::builder()
        .sender(sender)
        .account(bridge_id)
        .action(action)
        .generate_serial_number(rng)
        .attachment(attachment)
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
/// account via an `RBAC_ACTION` note consumed by the bridge, and the new holder's `UPDATE_GER`
/// note then succeeds.
#[tokio::test]
async fn granted_ger_injector_can_update_ger() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let new_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mut bridge_account = setup.bridge_account;

    let grant = bridge_rbac_action_note(
        setup.admin,
        bridge_account.id(),
        RbacAction::GrantRole {
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

/// The admin revokes the seeded `GER_INJECTOR` holder via an `RBAC_ACTION` note; the revoked
/// account's subsequent `UPDATE_GER` note is rejected by the bridge's role check.
#[tokio::test]
async fn revoked_ger_injector_cannot_update_ger() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let mut bridge_account = setup.bridge_account;

    let revoke = bridge_rbac_action_note(
        setup.admin,
        bridge_account.id(),
        RbacAction::RevokeRole {
            role: AggLayerBridge::ger_injector_role(),
            account: setup.ger_injector,
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(revoke.clone()));

    let ger = ExitRoot::from(GER_BYTES);
    let update_ger_note =
        UpdateGerNote::create(ger, setup.ger_injector, bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mut mock_chain = builder.build()?;

    execute_bridge_note(&mut mock_chain, &mut bridge_account, &revoke).await?;
    assert!(!is_role_member(
        &bridge_account,
        &AggLayerBridge::ger_injector_role(),
        setup.ger_injector
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

/// An `RBAC_ACTION` grant note whose sender is not a member of the role's effective admin role
/// (here: an operational-role holder) is rejected by the bridge.
#[tokio::test]
async fn non_admin_sender_cannot_grant_role() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let outsider = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let grant = bridge_rbac_action_note(
        setup.ger_injector,
        setup.bridge_account.id(),
        RbacAction::GrantRole {
            role: AggLayerBridge::ger_injector_role(),
            account: outsider.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(grant.clone()));

    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(setup.bridge_account.id())
        .authenticated_input_note(grant.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ROLE_ADMIN);
    Ok(())
}

/// Rotation of the top-level role: the seeded admin grants `ADMIN` to a new account, and the new
/// admin can then manage operational roles.
#[tokio::test]
async fn granted_admin_can_manage_roles() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let new_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let new_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mut bridge_account = setup.bridge_account;

    let grant_admin = bridge_rbac_action_note(
        setup.admin,
        bridge_account.id(),
        RbacAction::GrantRole {
            role: RoleBasedAccessControl::admin_role(),
            account: new_admin.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(grant_admin.clone()));

    let grant_injector = bridge_rbac_action_note(
        new_admin.id(),
        bridge_account.id(),
        RbacAction::GrantRole {
            role: AggLayerBridge::ger_injector_role(),
            account: new_injector.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(grant_injector.clone()));

    let mut mock_chain = builder.build()?;

    execute_bridge_note(&mut mock_chain, &mut bridge_account, &grant_admin).await?;
    assert!(is_role_member(
        &bridge_account,
        &RoleBasedAccessControl::admin_role(),
        new_admin.id()
    )?);

    execute_bridge_note(&mut mock_chain, &mut bridge_account, &grant_injector).await?;
    assert!(is_role_member(
        &bridge_account,
        &AggLayerBridge::ger_injector_role(),
        new_injector.id()
    )?);
    Ok(())
}

/// Delegating a role's admin via `set_role_admin` is exclusive: after the admin delegates
/// `GER_INJECTOR` management to a dedicated role, that role's member can grant `GER_INJECTOR`
/// while the `ADMIN` member no longer can.
#[tokio::test]
async fn delegated_role_admin_is_exclusive() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let delegate = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let new_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let outsider = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mut bridge_account = setup.bridge_account;
    let injector_admin_role = role("INJ_ADMIN");

    // seed the delegated admin role with a member before delegating, so the role stays manageable
    let grant_delegate = bridge_rbac_action_note(
        setup.admin,
        bridge_account.id(),
        RbacAction::GrantRole {
            role: injector_admin_role.clone(),
            account: delegate.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(grant_delegate.clone()));

    let delegate_admin = bridge_rbac_action_note(
        setup.admin,
        bridge_account.id(),
        RbacAction::SetRoleAdmin {
            role: AggLayerBridge::ger_injector_role(),
            admin_role: Some(injector_admin_role.clone()),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(delegate_admin.clone()));

    let grant_by_delegate = bridge_rbac_action_note(
        delegate.id(),
        bridge_account.id(),
        RbacAction::GrantRole {
            role: AggLayerBridge::ger_injector_role(),
            account: new_injector.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(grant_by_delegate.clone()));

    let grant_by_admin = bridge_rbac_action_note(
        setup.admin,
        bridge_account.id(),
        RbacAction::GrantRole {
            role: AggLayerBridge::ger_injector_role(),
            account: outsider.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(grant_by_admin.clone()));

    let mut mock_chain = builder.build()?;

    execute_bridge_note(&mut mock_chain, &mut bridge_account, &grant_delegate).await?;
    execute_bridge_note(&mut mock_chain, &mut bridge_account, &delegate_admin).await?;

    // the delegated admin role's member now manages GER_INJECTOR...
    execute_bridge_note(&mut mock_chain, &mut bridge_account, &grant_by_delegate).await?;
    assert!(is_role_member(
        &bridge_account,
        &AggLayerBridge::ger_injector_role(),
        new_injector.id()
    )?);

    // ...and the ADMIN member no longer does (delegation is exclusive)
    let result = mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(grant_by_admin.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ROLE_ADMIN);
    Ok(())
}

/// The `RBAC_ACTION` note is not bound to the account it was issued for: a note whose `account`
/// (and thus tag) references a different account is still consumable by the bridge, applying the
/// role change to the bridge's own role graph. Pins the target-binding caveat documented in SPEC
/// section 2.5.
#[tokio::test]
async fn note_targeted_at_another_account_is_consumable_by_bridge() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let other_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let new_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mut bridge_account = setup.bridge_account;

    // note issued "for" other_account: its tag references it, not the bridge, and no
    // NetworkAccountTarget attachment is added (the builder default)
    let grant: Note = RbacActionNote::builder()
        .sender(setup.admin)
        .account(other_account.id())
        .action(RbacAction::GrantRole {
            role: AggLayerBridge::ger_injector_role(),
            account: new_injector.id(),
        })
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(grant.clone()));

    let mut mock_chain = builder.build()?;

    execute_bridge_note(&mut mock_chain, &mut bridge_account, &grant).await?;
    assert!(is_role_member(
        &bridge_account,
        &AggLayerBridge::ger_injector_role(),
        new_injector.id()
    )?);
    Ok(())
}

/// Pins the operational hazard documented in SPEC section 2.5: nothing on-chain prevents the
/// last `ADMIN` member from renouncing (or revoking) its own role, after which no sender can
/// ever manage roles again — role rotation on the bridge is permanently disabled. Admin rotation
/// must therefore grant the successor (and wait for the grant to be committed) before any
/// revocation or renouncement is issued.
#[rstest]
#[case::renounce(true)]
#[case::revoke_self(false)]
#[tokio::test]
async fn removing_last_admin_permanently_disables_role_management(
    #[case] renounce: bool,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let setup = setup_bridge(&mut builder)?;
    let successor = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let mut bridge_account = setup.bridge_account;

    let removal_action = if renounce {
        RbacAction::RenounceRole {
            role: RoleBasedAccessControl::admin_role(),
        }
    } else {
        RbacAction::RevokeRole {
            role: RoleBasedAccessControl::admin_role(),
            account: setup.admin,
        }
    };
    let removal = bridge_rbac_action_note(
        setup.admin,
        bridge_account.id(),
        removal_action,
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(removal.clone()));

    let grant = bridge_rbac_action_note(
        setup.admin,
        bridge_account.id(),
        RbacAction::GrantRole {
            role: RoleBasedAccessControl::admin_role(),
            account: successor.id(),
        },
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(grant.clone()));

    let mut mock_chain = builder.build()?;

    execute_bridge_note(&mut mock_chain, &mut bridge_account, &removal).await?;
    assert!(!is_role_member(
        &bridge_account,
        &RoleBasedAccessControl::admin_role(),
        setup.admin
    )?);

    // the former admin (or anyone else) can no longer grant any role, including ADMIN itself
    let result = mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(grant.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_ROLE_ADMIN);
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
        RbacActionNote::script_root(),
    ]);
    assert_eq!(AggLayerBridge::allowed_notes(), expected);
}
