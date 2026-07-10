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

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
};
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::Authority;
use miden_standards::account::fees::{FeeAuth, FeeManager, FeeScheduleEntry};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::ERR_FEE_MANAGER_INSUFFICIENT_SPONSORSHIP;
use miden_standards::note::{FeeNote, NetworkSponsorshipNote, P2idNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

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

/// Builds a fee-managed network account.
fn fee_managed_account(seed: u8, fee_manager: FeeManager) -> anyhow::Result<Account> {
    Ok(AccountBuilder::new([seed; 32])
        .account_type(AccountType::Public)
        .with_auth_component(FeeAuth)
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

fn setup(budget: u64, parent_spawns: bool) -> anyhow::Result<Chain> {
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
            .with_spawn(parent_root, P2idNote::script_root()),
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

/// A sponsorship that covers only the parent note's own fee is rejected.
///
/// Without this check the upstream account would fund the downstream hop out of its own vault,
/// silently losing the downstream fee on every such transaction. It is also what bounds the payout
/// a hostile downstream account can name through `estimate_note_fee`: an inflated estimate fails
/// the coverage check instead of draining the vault.
#[tokio::test]
async fn downstream_fee_must_be_sponsored_up_front() -> anyhow::Result<()> {
    // Exactly the parent's fee, and not one unit of the downstream's.
    let c = setup(UPSTREAM_APP_FEE + UPSTREAM_PROTOCOL_FEE, true)?;

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
    let c = setup(UPSTREAM_APP_FEE + UPSTREAM_PROTOCOL_FEE, false)?;

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
#[tokio::test]
async fn double_hop_settles_both_fees() -> anyhow::Result<()> {
    // The user funds the whole chain up front: both hops, out of one sponsorship note.
    let total_budget = UPSTREAM_APP_FEE + UPSTREAM_PROTOCOL_FEE + DOWNSTREAM_TOTAL;
    let c = setup(total_budget, true)?;
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

    // The child sponsorship is funded with exactly what the downstream account charges, priced over
    // FPI rather than hardcoded by the upstream account.
    assert_eq!(
        child_sponsorship.assets().iter().next().copied(),
        Some(fee_asset(DOWNSTREAM_TOTAL)?),
        "the child sponsorship should carry the downstream account's own price",
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
        DOWNSTREAM_APP_FEE,
        "the downstream account keeps its application fee",
    );

    Ok(())
}
