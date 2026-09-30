//! The production faucet's admin surface after the standard managers replaced the hand-rolled
//! role-gated wrappers: what the shipped account exposes, what its authority enforces, and what each
//! admin action does on chain.
//!
//! Pausing and blocking used to run through two custom procedures that hard-coded a role symbol in
//! MASM and wrapped the unauthenticated standard primitive. They now run through the standard pause
//! and blocklist managers, gated by the account-wide authority in its role-based mode, driven by the
//! two standard config notes. The role that opens each action is unchanged; only the mechanism
//! moved, from a MASM literal into the account's procedure-role map.
//!
//! This is the effects proof for that swap on the REAL composition — the same components the deploy
//! path ships, under the same keyless network auth.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::{AccountId, StorageMapKey};
use miden_protocol::note::Note;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{
    Authority, Ownable2Step, PausableManager, RoleBasedAccessControl,
};
use miden_standards::account::policies::BlocklistManager;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_standards::note::config::{
    AllowlistConfigNote, BlocklistConfigNote, PauseConfig, PauseConfigNote, RbacConfigNote,
};
use miden_tx::TransactionExecutorError;
use support::w2admin::*;
use support::*;
use xusdc_encoding::account::xreserve::{XReserveAdminAuthority, XReserveStablecoinBuilder};
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;
use xusdc_encoding::note::xreserve_mint::DepositAttestation;
use xusdc_encoding::vectors::{load, MiVector};
use xusdc_encoding::xreserve::encoding::Signature;

// THE MINT FIXTURE — only the pause-halt proof needs a faucet that can actually mint
// ================================================================================================

const MINT_AMOUNT: u64 = 250_000_000;
const MAX_FEE_RAW: u64 = 1;
// the DC-14 rows are the ones whose localToken / localDepositor are address-shaped,
// which the mint transport requires
const BASE_VECTOR: &str = "mi-pos-empty-hookdata";
const REMOTE_TOKEN_BYTE_OFF: usize = 11 * 4;
const NONCE_BYTE_OFF: usize = 51 * 4;

fn mi(id: &str) -> &'static MiVector {
    load()
        .families
        .mi
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("the canonical artifact is missing di vector {id}"))
}

/// The canonical accept payload rebound to this faucet and recipient, with one nonce byte perturbed
/// so each mint consumes a nonce the replay guard has not seen.
fn payload_for(recipient: AccountId, faucet_id: AccountId, nonce_variant: u8) -> Vec<u8> {
    let mut payload = mi(BASE_VECTOR).payload();
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(MINT_AMOUNT));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(MAX_FEE_RAW));
    payload[REMOTE_RECIPIENT_BYTE_OFF..REMOTE_RECIPIENT_BYTE_OFF + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(recipient).to_bytes32());
    payload[REMOTE_TOKEN_BYTE_OFF..REMOTE_TOKEN_BYTE_OFF + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32());
    payload[NONCE_BYTE_OFF] ^= nonce_variant;
    payload
}

/// A production faucet brought up for a real mint: one attester allowlisted through its own admin
/// note, plus whatever the caller wants seeded.
fn mint_faucet(extra_notes: impl Fn(AccountId) -> Vec<Note>) -> Result<ProductionFaucet> {
    setup_production_faucet(0, |recipient, faucet_id| {
        let commitment = gen_attester(1, &payload_for(recipient, faucet_id, 0)).commitment;
        let mut notes = vec![XReserveSetAttesterNote::create(
            admin_holder(),
            faucet_id,
            commitment,
            1,
            &mut note_rng(952),
        )
        .expect("building the set_attester note")];
        notes.extend(extra_notes(faucet_id));
        notes
    })
}

/// Consumes the first `count` seeded notes, committing a block each.
async fn bring_up(pf: &mut ProductionFaucet, count: usize) -> Result<()> {
    for (i, note) in pf.seeded_notes.clone().iter().take(count).enumerate() {
        let tx = pf
            .mock_chain
            .build_transaction(pf.faucet_id)
            .authenticated_input_note(note.id())
            .build()
            .with_context(|| format!("bring-up note {i}: building the transaction"))?
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("bring-up note {i} must succeed: {e}"))?;
        pf.mock_chain.add_pending_executed_transaction(&tx)?;
        pf.mock_chain.prove_next_block()?;
    }
    Ok(())
}

/// Emits an attested mint note from the producer and consumes it on the faucet, returning the
/// verdict so a test can assert the exact trap.
async fn emit_and_consume_mint(
    pf: &mut ProductionFaucet,
    payload: &[u8],
    seed: u64,
) -> Result<std::result::Result<ExecutedTransaction, TransactionExecutorError>> {
    let attester = gen_attester(1, payload);
    let note = mint_note_from_payload(
        pf.producer_id,
        pf.faucet_id,
        payload,
        DepositAttestation::new(Signature::new(attester.sig_bytes), attester.pubkey.clone()),
        &mut note_rng(seed),
    )?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    Ok(pf
        .mock_chain
        .build_transaction(pf.faucet_id)
        .authenticated_input_note(note.id())
        .build()
        .context("building the mint consume transaction")?
        .execute()
        .await)
}

/// The allowlist contains ten roots, including the three standard administration notes.
#[test]
fn the_allowlist_contains_the_ten_expected_roots() {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();

    assert_eq!(
        allowlist.len(),
        PRODUCTION_ALLOWLIST_ROOTS,
        "the note-script allowlist must contain exactly {PRODUCTION_ALLOWLIST_ROOTS} roots"
    );
    assert!(
        allowlist.contains(&PauseConfigNote::script_root()),
        "the standard pause action note must be allowlisted — it is the only pause surface"
    );
    assert!(
        allowlist.contains(&BlocklistConfigNote::script_root()),
        "the standard blocklist config note must be allowlisted — it is the only blocklist surface"
    );
}

/// Role management is the standard role-action note, and the transfer-allowlist note is still not
/// composed. The role note's single root carries re-pointing a role's administrator and
/// self-renouncing alongside grant and revoke — an accepted exposure, driven action by action in
/// `w2admin_surface_finalization.rs`.
#[test]
fn the_role_action_note_is_allowlisted_and_the_transfer_allowlist_note_is_not() {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    assert!(
        allowlist.contains(&RbacConfigNote::script_root()),
        "the standard role-action note must be allowlisted — it is the only role-management surface"
    );
    assert!(
        !allowlist.contains(&AllowlistConfigNote::script_root()),
        "the allowlist config note drives a transfer allowlist the faucet does not have"
    );
}

/// The swap is visible in the callable surface: the four standard manager procedures are present,
/// by name. Membership is the property — the surface's size is a changelog, not a security claim.
#[tokio::test]
async fn the_standard_manager_procedures_are_on_the_callable_surface() -> Result<()> {
    let pf = admin_faucet(|_| Vec::new())?;
    let account = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    let roots = callable_roots(&account);

    for (what, root) in [
        ("pause", PausableManager::pause_root()),
        ("unpause", PausableManager::unpause_root()),
        ("block_account", BlocklistManager::block_account_root()),
        ("unblock_account", BlocklistManager::unblock_account_root()),
    ] {
        assert!(
            roots.contains(&Word::from(root)),
            "the standard manager procedure {what} must be installed on the faucet — the config \
             note calls that exact root"
        );
    }
    Ok(())
}

/// The shipped authority is role-based and carries exactly the five ratified assignments. Read out
/// of the built account's storage, not from the builder that wrote it, so a lossy write would show
/// up here.
#[tokio::test]
async fn the_shipped_authority_carries_the_ratified_role_map() -> Result<()> {
    let pf = admin_faucet(|_| Vec::new())?;
    let account = pf.mock_chain.committed_account(pf.faucet_id)?.clone();

    let authority = Authority::try_from_storage(account.storage())
        .map_err(|e| anyhow::anyhow!("reading the faucet's authority: {e}"))?;
    let Authority::RbacControlled { procedure_roles } = authority else {
        panic!(
            "the faucet's authority must be role-based; owner-controlled would gate the manager \
             procedures on the administrator, which is the identity Circle's model keeps them away from"
        );
    };

    assert_eq!(
        procedure_roles,
        XReserveAdminAuthority::new().procedure_roles().clone(),
        "the role map materialized on the faucet must equal the ratified map exactly"
    );
    assert!(
        !Authority::try_read_frozen(account.storage())
            .map_err(|e| anyhow::anyhow!("reading the frozen flag: {e}"))?,
        "the faucet must not ship with its authority frozen"
    );
    Ok(())
}

/// Two-step ownership is gone: the account carries no owner slot at all, so the administrator role
/// is its single authority handle and there is no second handle that could drift from it.
#[tokio::test]
async fn two_step_ownership_is_no_longer_installed() -> Result<()> {
    let pf = admin_faucet(|_| Vec::new())?;
    let account = pf.mock_chain.committed_account(pf.faucet_id)?.clone();

    assert!(
        Ownable2Step::try_from_storage(account.storage()).is_err(),
        "the faucet must carry no ownership slot — the component was removed"
    );
    Ok(())
}

/// The administrator role resolves to the bootstrap administrator's account, which is what keeps
/// every unmapped procedure — the attester setter, the supply cap, the
/// burn floor, the policy setters — on one identity.
#[tokio::test]
async fn the_administrator_role_is_the_bootstrap_administrator_account() -> Result<()> {
    let pf = admin_faucet(|_| Vec::new())?;
    let account = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    let admin = RoleBasedAccessControl::admin_role();

    let key = Word::from([
        Felt::ZERO,
        Felt::from(&admin),
        admin_holder().suffix(),
        admin_holder().prefix().as_felt(),
    ]);
    let membership = account
        .storage()
        .get_map_item(
            RoleBasedAccessControl::role_membership_slot(),
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading the administrator membership: {e}"))?;

    assert_eq!(
        membership[0],
        Felt::from(1u32),
        "the administrator's account must hold the administrator role, or every unmapped setter would move \
         off its current holder"
    );
    Ok(())
}

/// The pause-role holder pauses the faucet through the standard note.
#[tokio::test]
async fn the_pauser_pauses_the_faucet_through_the_standard_note() -> Result<()> {
    let mut pf = admin_faucet(|id| {
        vec![pause_action_note(pauser_holder(), id, PauseConfig::Pause, 1).expect("pause note")]
    })?;
    let note = pf.seeded_notes[0].clone();
    let before = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    assert_eq!(
        read_paused(&before)?,
        Word::empty(),
        "the faucet starts unpaused"
    );

    let after = consume_and_commit(&mut pf, &note, "a pause from the pause-role holder").await?;
    assert_eq!(
        read_paused(&after)?,
        set_word(),
        "after a pause from the role holder the pause flag must be set"
    );
    Ok(())
}

/// The unpause-role holder clears it again.
#[tokio::test]
async fn the_pauser_unpauses_the_faucet_through_the_standard_note() -> Result<()> {
    let mut pf = admin_faucet(|id| {
        vec![
            pause_action_note(pauser_holder(), id, PauseConfig::Pause, 2).expect("pause note"),
            pause_action_note(unpauser_holder(), id, PauseConfig::Unpause, 3)
                .expect("unpause note"),
        ]
    })?;
    let (pause, unpause) = (pf.seeded_notes[0].clone(), pf.seeded_notes[1].clone());

    let paused = consume_and_commit(&mut pf, &pause, "a pause").await?;
    assert_eq!(read_paused(&paused)?, set_word(), "the pause must land");

    let unpaused = consume_and_commit(&mut pf, &unpause, "an unpause").await?;
    assert_eq!(
        read_paused(&unpaused)?,
        Word::empty(),
        "after an unpause the pause flag must be cleared"
    );
    Ok(())
}

/// The load-bearing effect: a pause driven by the standard note HALTS a real attested mint, and the
/// mint resumes after the unpause. This is what pausing is for, and it is the property the swap
/// most needed to preserve.
#[tokio::test]
async fn a_standard_note_pause_halts_a_real_mint_and_the_unpause_resumes_it() -> Result<()> {
    let mut pf = mint_faucet(|id| {
        vec![
            pause_action_note(pauser_holder(), id, PauseConfig::Pause, 4).expect("pause note"),
            pause_action_note(unpauser_holder(), id, PauseConfig::Unpause, 5)
                .expect("unpause note"),
        ]
    })?;
    let recipient = pf.recipient_id;
    let faucet_id = pf.faucet_id;
    let (pause, unpause) = (pf.seeded_notes[1].clone(), pf.seeded_notes[2].clone());
    bring_up(&mut pf, 1).await?;

    let paused = consume_and_commit(&mut pf, &pause, "a pause").await?;
    assert_eq!(read_paused(&paused)?, set_word(), "the pause must land");

    let halted = emit_and_consume_mint(&mut pf, &payload_for(recipient, faucet_id, 1), 61).await?;
    miden_testing::assert_transaction_executor_error!(halted, err_paused());

    consume_and_commit(&mut pf, &unpause, "an unpause").await?;
    let resumed = emit_and_consume_mint(&mut pf, &payload_for(recipient, faucet_id, 2), 62).await?;
    resumed.map_err(|e| anyhow::anyhow!("the mint must resume after an unpause: {e}"))?;
    Ok(())
}

/// The blocklist-role holder blocks a target through the standard blocklist-config note.
#[tokio::test]
async fn the_blocklist_manager_blocks_a_target_through_the_standard_note() -> Result<()> {
    let target = stranger();
    let mut pf = admin_faucet(|id| {
        vec![stock_block_note(blocklist_holder(), id, target, 11).expect("block note")]
    })?;
    let note = pf.seeded_notes[0].clone();
    let before = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    assert_eq!(
        read_blocked(&before, target)?,
        Word::empty(),
        "the target starts unblocked"
    );

    let after = consume_and_commit(&mut pf, &note, "a block from the blocklist manager").await?;
    assert_eq!(
        read_blocked(&after, target)?,
        set_word(),
        "after a block the target's blocklist entry must be set"
    );
    Ok(())
}

/// And unblocks it again.
#[tokio::test]
async fn the_blocklist_manager_unblocks_a_target_through_the_standard_note() -> Result<()> {
    let target = stranger();
    let mut pf = admin_faucet(|id| {
        vec![
            stock_block_note(blocklist_holder(), id, target, 12).expect("block note"),
            stock_unblock_note(blocklist_holder(), id, target, 13).expect("unblock note"),
        ]
    })?;
    let (block, unblock) = (pf.seeded_notes[0].clone(), pf.seeded_notes[1].clone());

    let blocked = consume_and_commit(&mut pf, &block, "a block").await?;
    assert_eq!(
        read_blocked(&blocked, target)?,
        set_word(),
        "the block must land"
    );

    let unblocked = consume_and_commit(&mut pf, &unblock, "an unblock").await?;
    assert_eq!(
        read_blocked(&unblocked, target)?,
        Word::empty(),
        "after an unblock the target's blocklist entry must be cleared"
    );
    Ok(())
}

/// The administrator has no pause path. That was true before the swap because the standard manager was not
/// installed at all; it is true after the swap because the manager is installed and the role map
/// gates it on the pause role, which the administrator does not hold. Same outcome, different reason — and
/// the reason is exactly what the role map is for.
#[tokio::test]
async fn the_owner_still_has_no_pause_path() -> Result<()> {
    let pf = admin_faucet(|id| {
        vec![pause_action_note(admin_holder(), id, PauseConfig::Pause, 6).expect("pause note")]
    })?;
    let note = pf.seeded_notes[0].clone();

    let result = consume(&pf, &note).await;
    miden_testing::assert_transaction_executor_error!(result, err_sender_lacks_role());

    let account = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    assert_eq!(
        read_paused(&account)?,
        Word::empty(),
        "a rejected pause must leave the faucet unpaused"
    );
    Ok(())
}

/// The administrator has no unpause path either.
#[tokio::test]
async fn the_owner_still_has_no_unpause_path() -> Result<()> {
    let pf = admin_faucet(|id| {
        vec![pause_action_note(admin_holder(), id, PauseConfig::Unpause, 7).expect("unpause note")]
    })?;
    let result = consume(&pf, &pf.seeded_notes[0].clone()).await;
    miden_testing::assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

/// The administrator has no blocklist path. The blocklist belongs to an external administrator holding
/// nothing else, and the administrator — who holds everything else — is kept out of it.
#[tokio::test]
async fn the_owner_still_has_no_blocklist_path() -> Result<()> {
    let pf = admin_faucet(|id| {
        vec![stock_block_note(admin_holder(), id, stranger(), 14).expect("block note")]
    })?;
    let note = pf.seeded_notes[0].clone();

    let result = consume(&pf, &note).await;
    miden_testing::assert_transaction_executor_error!(result, err_sender_lacks_role());

    let account = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    assert_eq!(
        read_blocked(&account, stranger())?,
        Word::empty(),
        "a rejected block must leave the target unblocked"
    );
    Ok(())
}

/// Holding the pause role grants no blocklist capability.
#[tokio::test]
async fn the_pauser_cannot_block() -> Result<()> {
    let pf = admin_faucet(|id| {
        vec![stock_block_note(pauser_holder(), id, stranger(), 15).expect("block note")]
    })?;
    let result = consume(&pf, &pf.seeded_notes[0].clone()).await;
    miden_testing::assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

/// Holding the blocklist role grants no pause capability.
#[tokio::test]
async fn the_blocklist_manager_cannot_pause() -> Result<()> {
    let pf = admin_faucet(|id| {
        vec![pause_action_note(blocklist_holder(), id, PauseConfig::Pause, 8).expect("pause note")]
    })?;
    let result = consume(&pf, &pf.seeded_notes[0].clone()).await;
    miden_testing::assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

/// The unpauser can lift a pause but can neither pause nor block.
#[tokio::test]
async fn the_unpauser_can_neither_pause_nor_block() -> Result<()> {
    let pf = admin_faucet(|id| {
        vec![
            pause_action_note(unpauser_holder(), id, PauseConfig::Pause, 9).expect("pause note"),
            stock_block_note(unpauser_holder(), id, stranger(), 16).expect("block note"),
        ]
    })?;

    let paused = consume(&pf, &pf.seeded_notes[0].clone()).await;
    miden_testing::assert_transaction_executor_error!(paused, err_sender_lacks_role());

    let blocked = consume(&pf, &pf.seeded_notes[1].clone()).await;
    miden_testing::assert_transaction_executor_error!(blocked, err_sender_lacks_role());
    Ok(())
}

/// An account holding no role at all can do neither.
#[tokio::test]
async fn a_stranger_can_neither_pause_nor_block() -> Result<()> {
    let pf = admin_faucet(|id| {
        vec![
            pause_action_note(stranger(), id, PauseConfig::Pause, 10).expect("pause note"),
            stock_block_note(stranger(), id, admin_holder(), 17).expect("block note"),
        ]
    })?;

    let paused = consume(&pf, &pf.seeded_notes[0].clone()).await;
    miden_testing::assert_transaction_executor_error!(paused, err_sender_lacks_role());

    let blocked = consume(&pf, &pf.seeded_notes[1].clone()).await;
    miden_testing::assert_transaction_executor_error!(blocked, err_sender_lacks_role());
    Ok(())
}
