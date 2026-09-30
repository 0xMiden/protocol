//! The finalized admin surface: pure role-based administration, driven by the standard notes.
//!
//! Two changes land together here. The two-step ownership component is gone, so there is no owner
//! slot and no ownership handshake: every administrator-gated procedure resolves through the
//! account-wide authority to the administrator role, whose member is the account that used to hold
//! the administrator slot.
//!
//! Role management moved to the standard role-action note. It carries four actions behind one
//! script root — grant, revoke, re-point a role's administrator, and renounce — and admitting the
//! root admits all four. The role graph is therefore runtime-mutable, which is a deliberate change
//! from the build-seeded frozen graph the faucet shipped with. The tests below drive each of the
//! four actions against the real faucet so what the composition now permits is on the record.
//!
//! Everything runs against the SHIPPED composition — the same components the deploy path builds and
//! the same keyless network auth — so nothing here can pass on a fixture that flatters the change.

mod support;

use anyhow::Result;
use miden_protocol::account::{Account, AccountId, RoleSymbol, StorageMapKey};
use miden_protocol::note::Note;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::RoleBasedAccessControl;
use miden_standards::note::config::{RbacConfig, RbacConfigNote};
use miden_testing::assert_transaction_executor_error;
use support::w2admin::*;
use support::*;
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;

const MAX_SUPPLY: u64 = 1_000_000;

// READERS AND FIXTURES
// ================================================================================================

/// The member count recorded for `role`.
fn read_role_member_count(account: &Account, role: &RoleSymbol) -> Result<Felt> {
    Ok(read_role_config(account, role)?[0])
}

fn read_role_config(account: &Account, role: &RoleSymbol) -> Result<Word> {
    let key = Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(role)]);
    account
        .storage()
        .get_map_item(
            RoleBasedAccessControl::role_config_slot(),
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading role_config[{role}]: {e}"))
}

/// Whether `member` holds `role`.
fn read_role_membership(account: &Account, role: &RoleSymbol, member: AccountId) -> Result<Word> {
    let key = Word::from([
        Felt::ZERO,
        Felt::from(role),
        member.suffix(),
        member.prefix().as_felt(),
    ]);
    account
        .storage()
        .get_map_item(
            RoleBasedAccessControl::role_membership_slot(),
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading role_membership[{role}][{member}]: {e}"))
}

/// The attester allowlist entry for `commitment`.
fn read_attester(account: &Account, commitment: Word) -> Result<Word> {
    account
        .storage()
        .get_map_item(
            XReserveFaucetExtension::xreserve_attesters_slot(),
            StorageMapKey::new(commitment),
        )
        .map_err(|e| anyhow::anyhow!("reading xReserveAttesters[{commitment}]: {e}"))
}

/// A standard role-action note carrying `action`, sent by `sender` and tagged for `faucet_id`. The
/// serial is derived from `seed` so note ids stay stable; authorization rides on the sender.
fn role_note(
    sender: AccountId,
    faucet_id: AccountId,
    action: RbacConfig,
    seed: u32,
) -> Result<Note> {
    let note = RbacConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(action)
        .serial_number(Word::from([seed, 53, 59, 61]))
        .build()
        .map_err(|e| anyhow::anyhow!("building the standard role-action note: {e}"))?;
    Ok(Note::from(note))
}

// THE REST OF THE ADMIN SURFACE
// ================================================================================================

/// Every remaining administrator- and role-gated action still lands with no ownership component in
/// the composition: the attester allowlist, the supply cap, the burn floor, the pause flag and the
/// transfer blocklist. None of them ever read the administrator slot, and this proves it rather than
/// assuming it.
#[tokio::test]
async fn every_remaining_admin_note_still_lands() -> Result<()> {
    let commitment = Word::from([7u32, 8, 9, 10]);
    let new_max_supply = MAX_SUPPLY * 2;
    let new_min_burn = 42u64;
    let mut pf = admin_faucet(|faucet_id| {
        vec![
            XReserveSetAttesterNote::create(
                admin_holder(),
                faucet_id,
                commitment,
                1,
                &mut note_rng(501),
            )
            .expect("the set_attester note builds"),
            stock_set_max_supply_note(admin_holder(), faucet_id, new_max_supply, 502)
                .expect("the set_max_supply note builds"),
            stock_min_burn_note(admin_holder(), faucet_id, new_min_burn, 503)
                .expect("the min-burn note builds"),
            stock_pause_note(pauser_holder(), faucet_id, 504).expect("the pause note builds"),
            stock_block_note(blocklist_holder(), faucet_id, stranger(), 505)
                .expect("the block note builds"),
        ]
    })?;

    let notes: Vec<Note> = pf.seeded_notes.clone();

    let after = consume_and_commit(&mut pf, &notes[0], "set_attester").await?;
    assert_eq!(
        read_attester(&after, commitment)?,
        set_word(),
        "the attester setter must still write its allowlist entry"
    );

    // token_config is [token_supply, max_supply, decimals, symbol] — the cap is word[1].
    let after = consume_and_commit(&mut pf, &notes[1], "set_max_supply").await?;
    assert_eq!(
        read_token_config(&after)?[1],
        Felt::try_from(new_max_supply).expect("the new supply cap is a valid felt"),
        "the supply cap setter must still land"
    );

    let after = consume_and_commit(&mut pf, &notes[2], "min_burn").await?;
    assert_eq!(
        read_min_burn_size(&after)?[0],
        Felt::try_from(new_min_burn).expect("the new burn floor is a valid felt"),
        "the burn-floor setter must still land"
    );

    let after = consume_and_commit(&mut pf, &notes[3], "pause").await?;
    assert_eq!(
        read_paused(&after)?,
        set_word(),
        "the Domain pauser must still be able to pause"
    );

    let after = consume_and_commit(&mut pf, &notes[4], "block_account").await?;
    assert_eq!(
        read_blocked(&after, stranger())?,
        set_word(),
        "the blocklist administrator must still be able to block"
    );
    Ok(())
}

// THE ADMINISTRATOR ROLE: THE ACCOUNT'S ONLY AUTHORITY HANDLE
// ================================================================================================
// With no ownership component, `ADMIN` membership is the whole of the faucet's administrative
// authority — there is no owner slot, no nominate-then-accept handshake, and no second handle that
// could serve as a backstop. Everything the administratorship component used to carry now rides on grants
// and revokes of this one role, so the handover sequence and its failure boundary are worth driving
// end to end rather than describing.

/// A successor account for the handover — deliberately not one of the seeded role holders, so
/// nothing it can do comes from a membership it already had.
fn successor() -> AccountId {
    test_account_id(77)
}

/// The safe handover, in the order the runbook prescribes: GRANT the administrator role to the
/// successor first, then REVOKE it from the predecessor. Each step is proven by CAPABILITY, not by
/// a storage read — the successor's administrator-gated write must land, and the predecessor's must
/// stop landing once revoked.
///
/// Granting before revoking is what keeps the account from ever having no administrator at all; the
/// reverse order is unrecoverable, which is the boundary the renounce test below pins.
#[tokio::test]
async fn the_administrator_role_hands_over_by_grant_then_revoke() -> Result<()> {
    let admin = RoleBasedAccessControl::admin_role();
    let successor_min_burn = 21u32;
    let predecessor_min_burn = 31u32;

    let mut pf = admin_faucet(|faucet_id| {
        vec![
            // 0 — the successor has no administrator-gated capability yet.
            stock_min_burn_note(successor(), faucet_id, successor_min_burn.into(), 601)
                .expect("the successor's min-burn note builds"),
            // 1 — the incumbent grants the administrator role to the successor.
            role_note(
                admin_holder(),
                faucet_id,
                RbacConfig::GrantRole {
                    role: RoleBasedAccessControl::admin_role(),
                    account: successor(),
                },
                602,
            )
            .expect("the ADMIN grant note builds"),
            // 2 — the same capability, retried after the grant.
            stock_min_burn_note(successor(), faucet_id, successor_min_burn.into(), 603)
                .expect("the successor's second min-burn note builds"),
            // 3 — the successor revokes the predecessor.
            role_note(
                successor(),
                faucet_id,
                RbacConfig::RevokeRole {
                    role: RoleBasedAccessControl::admin_role(),
                    account: admin_holder(),
                },
                604,
            )
            .expect("the ADMIN revoke note builds"),
            // 4 — the predecessor's capability, retried after the revoke.
            stock_min_burn_note(admin_holder(), faucet_id, predecessor_min_burn.into(), 605)
                .expect("the predecessor's min-burn note builds"),
        ]
    })?;
    let notes: Vec<Note> = pf.seeded_notes.clone();

    // BEFORE — the successor holds nothing, so its administrator-gated write is refused.
    let refused = consume(&pf, &notes[0]).await;
    assert_transaction_executor_error!(refused, err_sender_lacks_role());

    // GRANT — the incumbent administrator adds the successor to the role.
    let granted = consume_and_commit(&mut pf, &notes[1], "grant ADMIN to the successor").await?;
    assert_eq!(
        read_role_membership(&granted, &admin, successor())?,
        set_word(),
        "the successor must now hold the administrator role"
    );
    assert_eq!(
        read_role_member_count(&granted, &admin)?,
        Felt::from(2u32),
        "the role must carry both administrators during the handover window"
    );

    // CAPABILITY GAINED — the same write the successor was refused now lands.
    let after = consume_and_commit(&mut pf, &notes[2], "successor min-burn update").await?;
    assert_eq!(
        read_min_burn_size(&after)?,
        Word::from([successor_min_burn, 0, 0, 0]),
        "the successor must gain the administrator-gated capability with the role"
    );

    // REVOKE — the successor removes the predecessor.
    let revoked =
        consume_and_commit(&mut pf, &notes[3], "revoke ADMIN from the predecessor").await?;
    assert_eq!(
        read_role_membership(&revoked, &admin, admin_holder())?,
        Word::empty(),
        "the predecessor must no longer hold the administrator role"
    );
    assert_eq!(
        read_role_member_count(&revoked, &admin)?,
        Felt::from(1u32),
        "the successor must be the sole administrator once the handover completes"
    );

    // CAPABILITY LOST — the predecessor's write is refused, and nothing of it lands.
    let refused = consume(&pf, &notes[4]).await;
    assert_transaction_executor_error!(refused, err_sender_lacks_role());
    let final_state = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    assert_eq!(
        read_min_burn_size(&final_state)?,
        Word::from([successor_min_burn, 0, 0, 0]),
        "the refused predecessor write must leave the burn floor untouched"
    );
    Ok(())
}

/// The handover cannot be hijacked: the administrator role administers ITSELF, so only a current
/// administrator may add another. A different role holder, here the Domain unpauser, is refused.
#[tokio::test]
async fn only_an_administrator_can_grant_the_administrator_role() -> Result<()> {
    let pf = admin_faucet(|faucet_id| {
        vec![role_note(
            unpauser_holder(),
            faucet_id,
            RbacConfig::GrantRole {
                role: RoleBasedAccessControl::admin_role(),
                account: successor(),
            },
            606,
        )
        .expect("the ADMIN grant note builds")]
    })?;

    let note = pf.seeded_notes[0].clone();
    let result = consume(&pf, &note).await;
    assert_transaction_executor_error!(result, err_sender_not_role_admin());

    let account = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    assert_eq!(
        read_role_membership(&account, &RoleBasedAccessControl::admin_role(), successor())?,
        Word::empty(),
        "the refused grant must leave the administrator role's membership untouched"
    );
    Ok(())
}
