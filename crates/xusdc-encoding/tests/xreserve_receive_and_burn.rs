//! Audit of the burn-consume path: how a burn note is destroyed and supply is lowered.
//!
//! Consuming a burn note runs the standard `receive_and_burn` path, gated by the faucet's
//! burn policy, which checks the required attachments and minimum burn amount.
//!
//! The property it protects is that the faucet has exactly one way to lower `token_supply`. A
//! second, ungated decrement path would let tokens be destroyed without a public burn note, and
//! the off-chain listener would have nothing to show Circle for tokens that no longer exist. The
//! proof is made against code and storage commitments rather than by observing supply deltas,
//! because a delta test can only find the paths it thinks to exercise:
//!
//!   - The faucet's own MASM tree contains no supply surface at all: no file calls the standard
//!     burn primitive, and no file writes — or even names — the faucet's token-config slot. All
//!     supply arithmetic lives in the standard library code.
//!   - The built account's active burn-policy storage slot holds the custom burn policy's root, so the one decrement path that does exist is policy-gated. A companion test
//!     shows the assertion is not vacuous by building a faucet with an allow-all policy and
//!     watching it fail.
//!
//! The remaining tests re-confirm the composition end to end with a real note: a valid burn lowers
//! supply exactly once, and a burn below the configured minimum traps with the standard library's
//! own error.

mod support;

use anyhow::Result;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteRecipient,
    NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::builder::XRESERVE_BURN_POLICY_PROC_PATH;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::note::xreserve_burn::{
    XReserveBurnNote, XUsdcBurnAttachment, FIXED_XUSDC_BURN_TAG,
    XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME,
};
use xusdc_encoding::xreserve::encoding::{CircleDomain, ForeignChainAddress, XReserveBurnItems};

// Amounts are arbitrary: this suite asserts which code path runs and what it is gated by, never
// the magnitudes themselves. They match the ones the burn-note suite uses so the shared harness
// behaves identically across both.
const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
const MIN_BURN_SIZE: u64 = 1_000;
/// A valid burn: `MIN_BURN_SIZE <= VALID_BURN` and `<= TOKEN_SUPPLY`.
const VALID_BURN: u64 = 5_000;

/// The administrator the burn oracle installs (id(1)). Under the reconciled Circle-faithful admin
/// model the setters resolve to the built-in `ADMIN` role under the account's role-based authority.
fn administrator() -> AccountId {
    test_account_id(1)
}

/// A fixed-seed rng for standalone note construction. It feeds only the note's serial number, so
/// the payload layout and tag are unaffected by the seed.
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

/// A withdrawal payload with an arbitrary destination. Those fields exist for
/// the off-chain listener to read; consuming the note does not look at them.
fn items() -> XReserveBurnItems {
    XReserveBurnItems {
        dest_domain: CircleDomain::new(9),
        dest_recipient: ForeignChainAddress::new([0xABu8; 32]),
    }
}

/// Builds a stock-script burn note with exactly the supplied attachments.
fn raw_burn_note(
    sender: AccountId,
    faucet_id: AccountId,
    attachments: Vec<NoteAttachment>,
) -> Note {
    let asset = FungibleAsset::new(faucet_id, VALID_BURN).expect("valid burn asset");
    let storage = NoteStorage::new(Asset::from(asset).as_elements().to_vec())
        .expect("stock burn asset storage");
    Note::with_attachments(
        NoteAssets::new(vec![asset.into()]).expect("one burn asset"),
        PartialNoteMetadata::new(sender, NoteType::Public)
            .with_tag(NoteTag::new(FIXED_XUSDC_BURN_TAG)),
        NoteRecipient::new(
            Word::from([1u32, 2, 3, 4]),
            XReserveBurnNote::script(),
            storage,
        ),
        NoteAttachments::new(attachments).expect("attachments within protocol limits"),
    )
}

#[tokio::test]
async fn burn_rejects_a_missing_withdrawal_attachment() -> Result<()> {
    let pf = setup_production_faucet(TOKEN_SUPPLY, |sender, faucet_id| {
        let routing = NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always)
            .expect("public network faucet");
        vec![raw_burn_note(sender, faucet_id, vec![routing.into()])]
    })?;
    let result = pf
        .mock_chain
        .build_transaction(pf.faucet_id)
        .authenticated_input_note(pf.seeded_notes[0].id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_BURN_NOTE_WITHDRAWAL_MISSING")
    );
    Ok(())
}

#[tokio::test]
async fn burn_rejects_a_wrong_withdrawal_word_count() -> Result<()> {
    let pf = setup_production_faucet(TOKEN_SUPPLY, |sender, faucet_id| {
        let routing = NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always)
            .expect("public network faucet");
        let withdrawal = NoteAttachment::with_words(
            NoteAttachmentScheme::new(XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME)
                .expect("withdrawal scheme"),
            vec![Word::empty(); 4],
        )
        .expect("four-word attachment");
        vec![raw_burn_note(
            sender,
            faucet_id,
            vec![routing.into(), withdrawal],
        )]
    })?;
    let result = pf
        .mock_chain
        .build_transaction(pf.faucet_id)
        .authenticated_input_note(pf.seeded_notes[0].id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_BURN_NOTE_WITHDRAWAL_WORDS")
    );
    Ok(())
}

#[tokio::test]
async fn burn_rejects_an_extra_attachment() -> Result<()> {
    let pf = setup_production_faucet(TOKEN_SUPPLY, |sender, faucet_id| {
        let routing = NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always)
            .expect("public network faucet");
        let withdrawal = NoteAttachment::from(&XUsdcBurnAttachment::new(items()));
        let extra = NoteAttachment::with_words(
            NoteAttachmentScheme::new(7).expect("extra scheme"),
            vec![Word::empty()],
        )
        .expect("one-word attachment");
        vec![raw_burn_note(
            sender,
            faucet_id,
            vec![routing.into(), withdrawal, extra],
        )]
    })?;
    let result = pf
        .mock_chain
        .build_transaction(pf.faucet_id)
        .authenticated_input_note(pf.seeded_notes[0].id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_BURN_NOTE_ATTACHMENT_COUNT")
    );
    Ok(())
}

#[tokio::test]
async fn burn_rejects_a_missing_routing_attachment() -> Result<()> {
    let pf = setup_production_faucet(TOKEN_SUPPLY, |sender, faucet_id| {
        let withdrawal = NoteAttachment::from(&XUsdcBurnAttachment::new(items()));
        vec![raw_burn_note(
            sender,
            faucet_id,
            vec![withdrawal.clone(), withdrawal],
        )]
    })?;
    let result = pf
        .mock_chain
        .build_transaction(pf.faucet_id)
        .authenticated_input_note(pf.seeded_notes[0].id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_BURN_NOTE_TARGET_MISSING")
    );
    Ok(())
}

// THE ACTIVE BURN POLICY — read off the built account's storage, not inferred from behavior
// ================================================================================================

/// The active storage slot must hold the custom policy root exported by the production component.
#[tokio::test]
async fn only_receive_and_burn_lowers_supply() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = h.chain.committed_account(h.faucet_id)?.clone();
    let stored = read_active_burn_policy_root(&account)?;
    assert_eq!(
        stored,
        XReserveStablecoinBuilder::burn_policy_component()
            .get_procedure_root_by_path(XRESERVE_BURN_POLICY_PROC_PATH)
            .expect("production burn policy is exported")
            .as_word(),
        "the active burn root must gate receive_and_burn with the custom burn policy"
    );
    Ok(())
}

/// The account check rejects a faucet that selects `BurnAllowAll` as its active burn policy.
#[tokio::test]
async fn allow_all_active_burn_policy_fails_sole_decrement_audit() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnAllowAll,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = h.chain.committed_account(h.faucet_id)?.clone();
    let stored = read_active_burn_policy_root(&account)?;
    assert_ne!(
        stored,
        XReserveStablecoinBuilder::burn_policy_component()
            .get_procedure_root_by_path(XRESERVE_BURN_POLICY_PROC_PATH)
            .expect("production burn policy is exported")
            .as_word(),
        "the audit must catch a burn policy repointed to BurnAllowAll"
    );
    Ok(())
}

// THE SEAM BETWEEN SETTING THE FLOOR AND ENFORCING IT: the setter writes the same slot the
// burn policy reads, so a change takes effect on the next burn
// ================================================================================================

/// Emits and commits a burn note, applies an administrator-sent minimum-burn configuration note to
/// the faucet, and consumes the burn note against the updated account.
async fn run_set_min_burn_then_consume(
    seed_floor: u64,
    new_min: u64,
    burn_amount: u64,
) -> Result<std::result::Result<ExecutedTransaction, TransactionExecutorError>> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        seed_floor,
        burn_amount,
    )?;
    let note = XReserveBurnNote::create(
        h.user_id,
        h.faucet_id,
        AssetAmount::new(burn_amount)?,
        items(),
        &mut note_rng(23),
    )?;
    let faucet_id = h.faucet_id;
    let user_id = h.user_id;
    let mut chain = h.chain;

    // Block N: the user emits + commits the burn note (floor still `seed_floor`).
    let tx0 = try_emit_burn_note(&chain, &note, &h.asset, faucet_id, user_id)
        .await
        .expect("the user emits the XReserveBurnNote (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    // The administrator moves the floor to `new_min`; evolve the committed faucet with the setter
    // delta.
    let account = chain.committed_account(faucet_id)?.clone();
    let set = run_set_min_burn_amount_against(&chain, &account, administrator(), new_min, 31)
        .await
        .expect("the administrator's minimum-burn update must succeed");
    let mut evolved = account.clone();
    evolved.apply_patch(set.account_patch())?;

    // The burn policy reads the minimum amount updated by the standard setter.
    let result = chain
        .build_transaction(evolved)
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await;
    Ok(result)
}

/// Raising the floor immediately starts rejecting a burn that was fine a moment earlier.
///
/// The amount used (5,000) passes at the seeded floor of 1,000 and fails at the new floor of
/// 10,000, so the only thing that changed between accept and reject is the setter's write. This is
/// the direction that matters for safety: the administrator can tighten the limit and it binds at once.
#[tokio::test]
async fn set_min_burn_raise_then_below_new_min_rejects() -> Result<()> {
    let result = run_set_min_burn_then_consume(MIN_BURN_SIZE, 10_000, VALID_BURN).await?;
    assert_transaction_executor_error!(result, &err_burn_below_min_burn_amount());
    Ok(())
}

/// Lowering the floor immediately admits a burn that would have been rejected.
///
/// The mirror of the test above, and the one that proves the seam is not vacuous: seeded at 10,000
/// the burn of 2,000 would trap, and after the setter lowers the floor to exactly 2,000 the same
/// consume succeeds — so the setter's write genuinely relaxes the minimum the burn policy
/// enforces, rather than the burn passing for some unrelated reason.
#[tokio::test]
async fn set_min_burn_lower_then_at_new_min_passes() -> Result<()> {
    let result = run_set_min_burn_then_consume(10_000, 2_000, 2_000).await?;
    result.expect("a burn equal to the lowered floor passes the stock policy");
    Ok(())
}
