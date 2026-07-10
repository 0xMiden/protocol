//! End-to-end test of a chained (double-hop) network transaction under the sponsorship fee model.
//!
//! Hop 1: an upstream network account consumes a fee-unaware parent note plus its sponsorship. The
//! parent note spawns a downstream feature note. The account's auth procedure then prices that
//! spawned note by asking the downstream account, over FPI, what it charges -- and mints a fresh
//! sponsorship note for it, funded out of the surplus the user provided.
//!
//! Hop 2: the downstream account consumes the spawned feature note plus the sponsorship the
//! upstream account minted for it.
//!
//! The fee budget travels down the chain inside the notes. No network account ever fronts
//! liquidity, and neither feature note knows anything about fees.

use std::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteScriptRoot, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
};
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::Authority;
use miden_standards::account::auth::AuthNetworkAccountWithFees;
use miden_standards::account::fees::{FeeManager, FeeScheduleEntry};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::{
    ERR_FEE_MANAGER_INSUFFICIENT_DOWNSTREAM_SPONSORSHIP,
    ERR_FEE_MANAGER_INSUFFICIENT_SPONSORSHIP,
    ERR_FEE_MANAGER_MULTIPLE_SPAWNING_NOTES,
};
use miden_standards::note::{FeeNote, NetworkSponsorshipNote, P2idNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use rstest::rstest;

// Upstream prices the parent note; downstream prices the spawned P2ID note.
const UPSTREAM_APP_FEE: u64 = 30;
const UPSTREAM_PROTOCOL_FEE: u64 = 12;
const DOWNSTREAM_APP_FEE: u64 = 7;
const DOWNSTREAM_PROTOCOL_FEE: u64 = 5;
const DOWNSTREAM_TOTAL: u64 = DOWNSTREAM_APP_FEE + DOWNSTREAM_PROTOCOL_FEE;

const BUSINESS_AMOUNT: u64 = 777;

fn fee_asset(amount: u64) -> anyhow::Result<Asset> {
    Ok(FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?, amount)?.into())
}

fn business_asset() -> anyhow::Result<Asset> {
    Ok(
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?, BUSINESS_AMOUNT)?
            .into(),
    )
}

/// The parent note's script: sweep the business asset into the consuming account, then spawn a
/// downstream P2ID feature note routed at `downstream`.
///
/// It is entirely fee-unaware. It never mentions a fee, a sponsorship, or a fee manager.
fn parent_note_code(downstream: &Account) -> String {
    format!(
        r#"
        use miden::protocol::output_note
        use miden::standards::attachments::network_account_target
        use miden::standards::notes::p2id
        use miden::standards::wallets::basic as basic_wallet
        use {{NOTE_TYPE_PUBLIC}} from miden::protocol::note
        use {{ALWAYS}} from miden::standards::note::execution_hint

        @note_script
        pub proc main
            dropw
            # => [pad(16)]

            exec.basic_wallet::add_assets_to_account
            # => [pad(16)]

            # spawn the downstream feature note
            push.1.2.3.4
            push.NOTE_TYPE_PUBLIC
            push.0
            push.{prefix} push.{suffix}
            # => [target_id_suffix, target_id_prefix, tag, note_type, SERIAL_NUM, pad(16)]

            exec.p2id::new
            # => [note_idx, pad(16)]

            # route it at the downstream network account
            push.ALWAYS push.{prefix} push.{suffix}
            # => [target_id_suffix, target_id_prefix, exec_hint_tag, note_idx, pad(16)]

            exec.network_account_target::new
            # => [attachment_scheme, NOTE_ATTACHMENT, note_idx, pad(16)]

            exec.output_note::add_word_attachment
            # => [pad(16)]
        end
        "#,
        prefix = downstream.id().prefix().as_felt(),
        suffix = downstream.id().suffix(),
    )
}

/// Builds a fee-managed network account allowlisting `allowed_note` (the sponsorship root is
/// added automatically).
fn fee_managed_account(
    seed: u8,
    fee_manager: FeeManager,
    allowed_note: NoteScriptRoot,
) -> anyhow::Result<Account> {
    let auth = AuthNetworkAccountWithFees::with_allowed_notes(BTreeSet::from([allowed_note]))?;

    Ok(AccountBuilder::new([seed; 32])
        .account_type(AccountType::Public)
        .with_auth_component(auth)
        .with_component(BasicWallet)
        .with_component(Authority::AuthControlled)
        .with_component(fee_manager)
        .build_existing()?)
}

/// A parent note that only sweeps its assets and spawns nothing, despite its root being declared
/// in the upstream account's spawn schedule.
const SWEEP_ONLY_NOTE_CODE: &str = r#"
    use miden::standards::wallets::basic as basic_wallet

    @note_script
    pub proc main
        dropw
        exec.basic_wallet::add_assets_to_account
    end
"#;

/// Builds the whole double-hop fixture with the top-level sponsorship funded with `budget`.
struct Chain {
    mock_chain: MockChain,
    upstream: Account,
    downstream: Account,
    parent_note: Note,
    sponsorship_note: Note,
}

fn setup(budget: u64, parent_spawns: bool, reclaim_delta: u32) -> anyhow::Result<Chain> {
    let fee_faucet = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();

    // The downstream account prices the spawned P2ID note.
    let downstream = fee_managed_account(
        9,
        FeeManager::new(fee_faucet)?.with_fee(
            P2idNote::script_root(),
            FeeScheduleEntry::new(DOWNSTREAM_APP_FEE, DOWNSTREAM_PROTOCOL_FEE)?,
        ),
        P2idNote::script_root(),
    )?;

    // The parent note's script root is only known once its code is compiled, and its code names the
    // downstream account, so the downstream account must exist first.
    let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;
    let parent_code = if parent_spawns {
        parent_note_code(&downstream)
    } else {
        SWEEP_ONLY_NOTE_CODE.into()
    };
    let parent_note = NoteBuilder::new(sponsor.id(), &mut rng)
        .note_type(NoteType::Public)
        .add_assets([business_asset()?])
        .code(parent_code)
        .build()?;
    let parent_root = parent_note.script().root();

    // The upstream account prices the parent note, and declares what it may spawn so that it can
    // price the spawned note against the downstream account.
    let upstream = fee_managed_account(
        8,
        FeeManager::new(fee_faucet)?
            .with_fee(parent_root, FeeScheduleEntry::new(UPSTREAM_APP_FEE, UPSTREAM_PROTOCOL_FEE)?)
            .with_spawn(parent_root, P2idNote::script_root())
            .with_reclaim_delta(reclaim_delta),
        parent_root,
    )?;

    builder.add_account(downstream.clone())?;
    builder.add_account(upstream.clone())?;
    builder.add_output_note(RawOutputNote::Full(parent_note.clone()));

    let sponsorship_note = Note::from(
        NetworkSponsorshipNote::builder()
            .sender(sponsor.id())
            .target_account(upstream.id())?
            .feature_note_id(parent_note.id())
            .asset(fee_asset(budget)?)
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

    Ok(Chain {
        mock_chain: builder.build()?,
        upstream,
        downstream,
        parent_note,
        sponsorship_note,
    })
}

/// A sponsorship whose remainder does not cover the downstream fee is rejected.
///
/// Without this check the upstream account would fund the downstream hop out of its own vault,
/// silently losing the difference on every such transaction. It is also what bounds the payout
/// a hostile downstream account can name through `estimate_note_fee`: an inflated estimate fails
/// the coverage check instead of draining the vault.
#[rstest]
#[case::nothing_left_for_downstream(0)]
#[case::one_unit_short(DOWNSTREAM_TOTAL - 1)]
#[tokio::test]
async fn downstream_fee_must_be_sponsored_up_front(
    #[case] downstream_budget: u64,
) -> anyhow::Result<()> {
    let c = setup(UPSTREAM_APP_FEE + UPSTREAM_PROTOCOL_FEE + downstream_budget, true, 0)?;

    let downstream_foreign = c.mock_chain.get_foreign_account_inputs(c.downstream.id())?;
    let result = c
        .mock_chain
        .build_tx_context(c.upstream.id(), &[c.sponsorship_note.id(), c.parent_note.id()], &[])?
        .foreign_accounts(vec![downstream_foreign])
        .add_note_script(P2idNote::script())
        .add_note_script(NetworkSponsorshipNote::script())
        .add_note_script(FeeNote::script())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_INSUFFICIENT_DOWNSTREAM_SPONSORSHIP);

    Ok(())
}

/// A sponsorship that does not even cover the parent note's own fee is rejected before any
/// downstream consideration.
#[tokio::test]
async fn parent_fee_must_be_sponsored() -> anyhow::Result<()> {
    let c = setup(UPSTREAM_APP_FEE + UPSTREAM_PROTOCOL_FEE - 1, true, 0)?;

    let downstream_foreign = c.mock_chain.get_foreign_account_inputs(c.downstream.id())?;
    let result = c
        .mock_chain
        .build_tx_context(c.upstream.id(), &[c.sponsorship_note.id(), c.parent_note.id()], &[])?
        .foreign_accounts(vec![downstream_foreign])
        .add_note_script(P2idNote::script())
        .add_note_script(NetworkSponsorshipNote::script())
        .add_note_script(FeeNote::script())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_INSUFFICIENT_SPONSORSHIP);

    Ok(())
}

/// A declared spawn is a permission, not an obligation: a parent that spawns nothing settles as a
/// plain feature note, without pricing or funding a downstream hop.
#[tokio::test]
async fn declared_spawn_without_spawned_note_settles_normally() -> anyhow::Result<()> {
    let c = setup(UPSTREAM_APP_FEE + UPSTREAM_PROTOCOL_FEE, false, 0)?;

    let executed = c
        .mock_chain
        .build_tx_context(c.upstream.id(), &[c.sponsorship_note.id(), c.parent_note.id()], &[])?
        .add_note_script(NetworkSponsorshipNote::script())
        .add_note_script(FeeNote::script())
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 1, "only the FEE note is emitted");
    assert_eq!(
        executed.output_notes().get_note(0).assets().iter().next().copied(),
        Some(fee_asset(UPSTREAM_PROTOCOL_FEE)?),
    );

    let mut upstream = c.upstream;
    upstream.apply_patch(executed.account_patch())?;
    assert_eq!(upstream.vault().get_balance(fee_asset(0)?.id())?.as_u64(), UPSTREAM_APP_FEE);

    Ok(())
}

/// The full chained flow, end to end.
///
/// Any surplus beyond the upstream account's own fee travels downstream inside the child
/// sponsorship, rather than staying with the upstream account: this is what lets a chain keep
/// running on one up-front budget.
#[rstest]
#[case::exact_budget(0)]
#[case::surplus_flows_downstream(25)]
#[tokio::test]
async fn double_hop_settles_both_fees(#[case] surplus: u64) -> anyhow::Result<()> {
    // The user funds the whole chain up front: both hops, out of one sponsorship note.
    let total_budget = UPSTREAM_APP_FEE + UPSTREAM_PROTOCOL_FEE + DOWNSTREAM_TOTAL + surplus;
    let c = setup(total_budget, true, 0)?;
    let (mut mock_chain, upstream, downstream) = (c.mock_chain, c.upstream, c.downstream);

    // ---- HOP 1: upstream consumes [sponsorship, parent] ------------------------------------
    let downstream_foreign = mock_chain.get_foreign_account_inputs(downstream.id())?;
    let hop1 = mock_chain
        .build_tx_context(upstream.id(), &[c.sponsorship_note.id(), c.parent_note.id()], &[])?
        .foreign_accounts(vec![downstream_foreign])
        // the public notes this transaction creates must be resolvable by the host
        .add_note_script(P2idNote::script())
        .add_note_script(NetworkSponsorshipNote::script())
        .add_note_script(FeeNote::script())
        .build()?
        .execute()
        .await?;

    // Three output notes: the spawned P2ID, its sponsorship, and the FEE note for the builder.
    assert_eq!(hop1.output_notes().num_notes(), 3, "expected spawned note, sponsorship and FEE");

    // Identify each output note by the script its recipient commits to.
    let find = |root| {
        hop1.output_notes()
            .iter()
            .find(|note| {
                note.recipient()
                    .expect("public output note should expose its recipient")
                    .script()
                    .root()
                    == root
            })
            .expect("expected an output note bearing this script root")
    };

    let spawned_note = find(P2idNote::script_root());
    let child_sponsorship = find(NetworkSponsorshipNote::script_root());
    let hop1_fee_note = find(FeeNote::script_root());

    // The upstream account forwarded exactly its protocol portion to the batch builder.
    assert_eq!(
        hop1_fee_note.assets().iter().next().copied(),
        Some(fee_asset(UPSTREAM_PROTOCOL_FEE)?),
    );

    // The child sponsorship carries the entire remainder of the budget after the upstream fee: at
    // least the downstream account's own price (asked over FPI), plus any surplus.
    assert_eq!(
        child_sponsorship.assets().iter().next().copied(),
        Some(fee_asset(DOWNSTREAM_TOTAL + surplus)?),
    );

    let (spawned_note_id, child_sponsorship_id) = (spawned_note.id(), child_sponsorship.id());

    // Upstream kept its application fee, and nothing more: the downstream budget left in the child
    // sponsorship, and the protocol portion left in the FEE note.
    let mut upstream_after = upstream.clone();
    upstream_after.apply_patch(hop1.account_patch())?;
    assert_eq!(
        upstream_after.vault().get_balance(fee_asset(0)?.id())?.as_u64(),
        UPSTREAM_APP_FEE,
        "no network account fronts liquidity: the fee budget travels inside the notes",
    );

    mock_chain.add_pending_executed_transaction(&hop1)?;
    mock_chain.prove_next_block()?;

    // ---- HOP 2: downstream consumes [child sponsorship, spawned note] ----------------------
    let hop2 = mock_chain
        .build_tx_context(downstream.id(), &[child_sponsorship_id, spawned_note_id], &[])?
        .add_note_script(P2idNote::script())
        .add_note_script(NetworkSponsorshipNote::script())
        .build()?
        .execute()
        .await?;

    assert_eq!(hop2.output_notes().num_notes(), 1, "hop 2 emits only its FEE note");
    let hop2_fee_note = hop2.output_notes().get_note(0);
    assert_eq!(
        hop2_fee_note.assets().iter().next().copied(),
        Some(fee_asset(DOWNSTREAM_PROTOCOL_FEE)?),
    );

    let mut downstream_after = downstream.clone();
    downstream_after.apply_patch(hop2.account_patch())?;
    assert_eq!(
        downstream_after.vault().get_balance(fee_asset(0)?.id())?.as_u64(),
        DOWNSTREAM_APP_FEE + surplus,
        "the downstream account keeps its application fee and the terminal surplus",
    );

    Ok(())
}

/// After the configured delta, the upstream account reclaims a chained sponsorship whose
/// downstream note was never consumed, recovering the budget instead of locking it forever.
#[tokio::test]
async fn upstream_reclaims_chained_sponsorship_after_delta() -> anyhow::Result<()> {
    const RECLAIM_DELTA: u32 = 5;
    let total_budget = UPSTREAM_APP_FEE + UPSTREAM_PROTOCOL_FEE + DOWNSTREAM_TOTAL;
    let c = setup(total_budget, true, RECLAIM_DELTA)?;
    let mut mock_chain = c.mock_chain;

    let downstream_foreign = mock_chain.get_foreign_account_inputs(c.downstream.id())?;
    let hop1 = mock_chain
        .build_tx_context(c.upstream.id(), &[c.sponsorship_note.id(), c.parent_note.id()], &[])?
        .foreign_accounts(vec![downstream_foreign])
        .add_note_script(P2idNote::script())
        .add_note_script(NetworkSponsorshipNote::script())
        .add_note_script(FeeNote::script())
        .build()?
        .execute()
        .await?;

    let child_sponsorship_id = hop1
        .output_notes()
        .iter()
        .find(|note| {
            note.recipient().expect("public note exposes its recipient").script().root()
                == NetworkSponsorshipNote::script_root()
        })
        .expect("hop 1 mints a child sponsorship")
        .id();

    mock_chain.add_pending_executed_transaction(&hop1)?;
    let past_reclaim = mock_chain.latest_block_header().block_num() + RECLAIM_DELTA + 1;
    mock_chain.prove_until_block(past_reclaim)?;

    // The downstream account never consumed the child sponsorship; upstream, its sender, reclaims.
    let reclaim = mock_chain
        .build_tx_context(c.upstream.id(), &[child_sponsorship_id], &[])?
        .add_note_script(NetworkSponsorshipNote::script())
        .build()?
        .execute()
        .await?;

    let mut upstream = c.upstream;
    upstream.apply_patch(hop1.account_patch())?;
    upstream.apply_patch(reclaim.account_patch())?;
    assert_eq!(
        upstream.vault().get_balance(fee_asset(0)?.id())?.as_u64(),
        UPSTREAM_APP_FEE + DOWNSTREAM_TOTAL,
        "the chained budget returns to the upstream account",
    );

    Ok(())
}

/// At most one consumed feature note may declare a spawn: the downstream note is located by
/// attachment rather than script root, so a second spawner could not be matched to its parent.
#[tokio::test]
async fn two_spawning_notes_are_rejected() -> anyhow::Result<()> {
    let fee_faucet = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();

    let downstream = fee_managed_account(
        9,
        FeeManager::new(fee_faucet)?.with_fee(
            P2idNote::script_root(),
            FeeScheduleEntry::new(DOWNSTREAM_APP_FEE, DOWNSTREAM_PROTOCOL_FEE)?,
        ),
        P2idNote::script_root(),
    )?;

    let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mut parents = Vec::new();
    for _ in 0..2 {
        parents.push(
            NoteBuilder::new(sponsor.id(), &mut rng)
                .note_type(NoteType::Public)
                .add_assets([business_asset()?])
                .code(parent_note_code(&downstream))
                .build()?,
        );
    }
    let parent_root = parents[0].script().root();

    let upstream = fee_managed_account(
        8,
        FeeManager::new(fee_faucet)?
            .with_fee(parent_root, FeeScheduleEntry::new(UPSTREAM_APP_FEE, UPSTREAM_PROTOCOL_FEE)?)
            .with_spawn(parent_root, P2idNote::script_root()),
        parent_root,
    )?;

    builder.add_account(downstream.clone())?;
    builder.add_account(upstream.clone())?;

    let mut note_ids = Vec::new();
    for parent in &parents {
        builder.add_output_note(RawOutputNote::Full(parent.clone()));
        let sponsorship = Note::from(
            NetworkSponsorshipNote::builder()
                .sender(sponsor.id())
                .target_account(upstream.id())?
                .feature_note_id(parent.id())
                .asset(fee_asset(UPSTREAM_APP_FEE + UPSTREAM_PROTOCOL_FEE + DOWNSTREAM_TOTAL)?)
                .generate_serial_number(&mut rng)
                .build()?,
        );
        builder.add_output_note(RawOutputNote::Full(sponsorship.clone()));
        note_ids.extend([sponsorship.id(), parent.id()]);
    }

    let mock_chain = builder.build()?;
    let downstream_foreign = mock_chain.get_foreign_account_inputs(downstream.id())?;
    let result = mock_chain
        .build_tx_context(upstream.id(), &note_ids, &[])?
        .foreign_accounts(vec![downstream_foreign])
        .add_note_script(P2idNote::script())
        .add_note_script(NetworkSponsorshipNote::script())
        .add_note_script(FeeNote::script())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_MULTIPLE_SPAWNING_NOTES);

    Ok(())
}
