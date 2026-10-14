//! Transfer blocklist, the send side: a holder on the faucet's blocklist can create neither a
//! USDCx transfer note nor a USDCx burn note, run against a MockChain.
//!
//! The faucet keeps a list of blocked Miden accounts, its transfer blocklist, which only the
//! holder of the dedicated `BLK_MANAGER` role can change, through the standard blocklist config
//! note. Whenever USDCx moves out of or into an account, the transaction kernel calls back into
//! the faucet, which looks the moving account up in that list and aborts the transaction if the
//! account is listed. OpenZeppelin (finding N-07, issue 0xMiden/miden-usdcx#175) asked for a test
//! showing that a listed account can create neither a transfer note nor a burn note; who may
//! block is covered in `transfer_blocklist_e2e.rs`, and the receive side (a listed account cannot
//! consume an incoming note) in `mint_scale_conformance.rs`. Each case below funds a holder wallet
//! through the real attested mint path on the production faucet, shows the holder can create the
//! note while unlisted, has the `BLK_MANAGER` holder block it, shows the same kind of note can no
//! longer be created and that the holder's balance is untouched, then unblocks the holder and
//! shows the note can be created again. If the "cannot create" step ever passed, a blocked holder
//! could still move or redeem USDCx, which is the freeze the blocklist exists to enforce.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::{Account, AccountId, AssetCallbackFlag, StorageMapKey};
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::policies::BlocklistStorage;
use miden_standards::errors::standards::ERR_ACCOUNT_IS_BLOCKED;
use miden_standards::note::P2idNote;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_usdcx::note::xreserve_admin::XReserveSetAttesterNote;
use miden_usdcx::note::xreserve_burn::XReserveBurnNote;
use miden_usdcx::xreserve::encoding::{ForeignChainAddress, XReserveBurnItems};
use rstest::rstest;
use support::mint_transport::*;
use support::*;

/// The amount each outgoing note carries: 5 USDC in 6-decimal units, a small slice of the
/// `MINT_AMOUNT` (250 USDC) the holder receives through the mint path.
const SEND_AMOUNT: u64 = 5_000_000;

/// The account the production builder seeds as the sole `BLK_MANAGER` member
/// (`test_account_id(4)`, see `production_builder_verdict_with_attesters`).
fn blk_manager() -> AccountId {
    test_account_id(4)
}

/// Another Miden account, the target of the transfer note. Its identity is immaterial: the send
/// policy inspects the account that creates the note, never the one it is addressed to.
fn other_holder() -> AccountId {
    test_account_id(77)
}

/// The two kinds of outgoing note a holder creates with its USDCx.
#[derive(Clone, Copy, Debug)]
enum Outgoing {
    /// The standard pay-to-id note that sends USDCx to another Miden account.
    Transfer,
    /// The USDCx burn note that starts a withdrawal to the source chain.
    Burn,
}

/// The production faucet, a holder wallet funded through the real mint path, and the index of the
/// seeded block and unblock admin notes (both sent by the `BLK_MANAGER` holder and addressed at
/// the holder) inside `pf.seeded_notes`.
struct Fixture {
    pf: ProductionFaucet,
    holder_id: AccountId,
}

/// `pf.seeded_notes[BLOCK_NOTE]` blocks the holder, `pf.seeded_notes[UNBLOCK_NOTE]` unblocks it.
/// Index 0 is the administrator's `set_attester` note the bring-up consumes.
const BLOCK_NOTE: usize = 1;
const UNBLOCK_NOTE: usize = 2;

/// Builds the production faucet (the same `XReserveStablecoinBuilder` composition and network
/// account auth the deployment uses) next to a holder wallet, seeds the attester, block and
/// unblock admin notes at genesis, then funds the holder with `MINT_AMOUNT` USDCx through the
/// real path: an attested mint note is consumed by the faucet, and the holder consumes the
/// resulting pay-to-id note.
async fn funded_fixture() -> Result<Fixture> {
    let mut mc = MockChain::builder();
    // The holder is a standard wallet plus the suite's small note-emitting helper. The kernel
    // only lets an account's own procedures attach data to a note it creates, and the burn note
    // carries its withdrawal payload as such an attachment.
    let holder = add_emitting_wallet(&mut mc, Auth::IncrNonce, [])?;
    let producer = add_emitting_wallet(&mut mc, Auth::IncrNonce, [])?;
    let components = production_builder_verdict_with_attesters(0, TEST_DOMAIN, None, Vec::new())?
        .map_err(|e| anyhow::anyhow!("building the production faucet: {e}"))?
        .build_components()
        .map_err(|e| anyhow::anyhow!("composing the production faucet: {e}"))?;
    let faucet = add_network_faucet_account(&mut mc, components)?;
    let (faucet_id, holder_id) = (faucet.id(), holder.id());
    assert_eq!(
        faucet_id.asset_callback_flag(),
        AssetCallbackFlag::Enabled,
        "the production faucet must have asset callbacks enabled, or no transfer policy would run"
    );

    let payload = payload_for(holder_id, faucet_id, MINT_AMOUNT, 0);
    let seeded_notes = vec![
        XReserveSetAttesterNote::create(
            administrator(),
            faucet_id,
            gen_attester(1, &payload).commitment,
            1,
            &mut note_rng(952),
        )
        .context("building the administrator set_attester note")?,
        stock_block_note(blk_manager(), faucet_id, holder_id, 953)
            .context("building the BLK_MANAGER block note addressed at the holder")?,
        stock_unblock_note(blk_manager(), faucet_id, holder_id, 954)
            .context("building the BLK_MANAGER unblock note addressed at the holder")?,
    ];
    for note in &seeded_notes {
        mc.add_output_note(RawOutputNote::Full(note.clone()));
    }
    let mut pf = ProductionFaucet {
        mock_chain: mc.build().context("building the MockChain")?,
        faucet_id,
        recipient_id: holder_id,
        producer_id: producer.id(),
        seeded_notes,
        build_token_supply: 0,
    };
    // The faucet consumes the set_attester note so the mint below carries an allowlisted
    // attestation.
    bring_up(&mut pf, 1).await?;

    // The real mint path: the producer publishes the attested mint note, the faucet consumes it
    // and mints a pay-to-id note to the holder, and the holder consumes that note. The last step
    // runs the faucet's receive policy on the (still unlisted) holder.
    let mint_note = honest_note(&pf, &payload, 1)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &mint_note).await?;
    let minted = consume_note(&pf.mock_chain, faucet_id, mint_note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the faucet must accept the attested mint note: {e}"))?;
    commit(&mut pf.mock_chain, &minted)?;
    let minted_p2id = minted.output_notes().get_note(0).id();
    let faucet_foreign = pf
        .mock_chain
        .get_foreign_account_inputs(faucet_id)
        .context("faucet foreign-account inputs")?;
    let received = pf
        .mock_chain
        .build_transaction(holder_id)
        .authenticated_input_note(minted_p2id)
        .foreign_accounts([faucet_foreign])
        .build()
        .context("building the holder's consume of the minted note")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("the unlisted holder must receive the minted USDCx: {e}"))?;
    commit(&mut pf.mock_chain, &received)?;
    assert_eq!(
        holder_balance(&pf.mock_chain, holder_id, faucet_id)?,
        MINT_AMOUNT,
        "the holder holds exactly the minted amount before any test step"
    );
    Ok(Fixture { pf, holder_id })
}

/// The holder's committed balance of the faucet's asset.
fn holder_balance(chain: &MockChain, holder_id: AccountId, faucet_id: AccountId) -> Result<u64> {
    Ok(chain
        .committed_account(holder_id)?
        .vault()
        .assets()
        .filter_map(|asset| match asset.as_fungible() {
            Some(fungible) if fungible.faucet_id() == faucet_id => {
                Some(u64::from(fungible.amount()))
            },
            _ => None,
        })
        .sum())
}

/// Whether `account` is on the faucet's blocklist, read from the faucet's committed
/// `blocked_accounts` storage map (the primitive's key is `[0, 0, suffix, prefix]`).
fn is_listed(faucet: &Account, account: AccountId) -> Result<bool> {
    let key = Word::from([Felt::ZERO, Felt::ZERO, account.suffix(), account.prefix().as_felt()]);
    let entry = faucet
        .storage()
        .get_map_item(BlocklistStorage::blocked_accounts_slot(), StorageMapKey::new(key))
        .map_err(|e| anyhow::anyhow!("reading blocked_accounts[{account}]: {e}"))?;
    Ok(entry != Word::empty())
}

/// A fresh outgoing note of the requested kind, carrying `SEND_AMOUNT` of the faucet's asset from
/// the holder, together with the asset the holder's transaction moves into it. `seed` only varies
/// the note's serial number, so every attempt below is a distinct note.
fn outgoing_note(
    kind: Outgoing,
    holder_id: AccountId,
    faucet_id: AccountId,
    seed: u64,
) -> Result<(Note, FungibleAsset)> {
    let asset = FungibleAsset::new(faucet_id, SEND_AMOUNT).context("outgoing asset")?;
    let note = match kind {
        Outgoing::Transfer => P2idNote::builder()
            .sender(holder_id)
            .target(other_holder())
            .asset(asset)
            .generate_serial_number(&mut note_rng(seed))
            .note_type(NoteType::Public)
            .build()
            .context("building the transfer note")?
            .into(),
        Outgoing::Burn => XReserveBurnNote::create(
            holder_id,
            faucet_id,
            AssetAmount::new(SEND_AMOUNT).context("burn amount")?,
            XReserveBurnItems::builder()
                .dest_domain(TEST_SOURCE_DOMAIN)
                .dest_recipient(ForeignChainAddress::new([0xab; 32]))
                .build(),
            &mut note_rng(seed),
        )
        .context("building the burn note")?,
    };
    Ok((note, asset))
}

/// The holder creates `note` in its own transaction and the block is committed. Used for the
/// positive controls, where creation must succeed.
async fn create_and_commit(f: &mut Fixture, note: &Note, asset: &FungibleAsset) -> Result<()> {
    let tx = try_emit_burn_note(&f.pf.mock_chain, note, asset, f.pf.faucet_id, f.holder_id)
        .await
        .map_err(|e| anyhow::anyhow!("the unlisted holder must be able to create the note: {e}"))?;
    commit(&mut f.pf.mock_chain, &tx)?;
    anyhow::ensure!(
        f.pf.mock_chain.is_note_committed(&note.id()),
        "the note the holder created must be committed on chain"
    );
    Ok(())
}

/// A listed holder can create neither a transfer note nor a burn note, and unlisting restores
/// both. One case per note kind; the steps are identical, so a regression in either path names
/// itself.
#[rstest]
#[case::transfer_note(Outgoing::Transfer)]
#[case::burn_note(Outgoing::Burn)]
#[tokio::test]
async fn blocked_holder_cannot_create_the_note(#[case] kind: Outgoing) -> Result<()> {
    let mut f = funded_fixture().await?;
    let (faucet_id, holder_id) = (f.pf.faucet_id, f.holder_id);

    // Positive control: while unlisted, the holder creates the note and it lands on chain. This
    // is what makes the rejection below meaningful, as the only thing that changes between the
    // two attempts is the holder's entry in the blocklist.
    assert!(!is_listed(&committed(&f.pf.mock_chain, faucet_id)?, holder_id)?);
    let (note, asset) = outgoing_note(kind, holder_id, faucet_id, 10)?;
    create_and_commit(&mut f, &note, &asset).await?;
    assert_eq!(
        holder_balance(&f.pf.mock_chain, holder_id, faucet_id)?,
        MINT_AMOUNT - SEND_AMOUNT,
        "the positive control really moved USDCx out of the holder's vault"
    );

    // The BLK_MANAGER holder blocks the holder: the faucet consumes the block note and the block
    // is committed, so the faucet state every later callback reads carries the entry.
    consume_seeded_admin_note(&mut f.pf, BLOCK_NOTE).await?;
    assert!(
        is_listed(&committed(&f.pf.mock_chain, faucet_id)?, holder_id)?,
        "precondition: the block note put the holder on the faucet's blocklist"
    );

    // The step OpenZeppelin asked to see. The failure happens in the holder's own transaction,
    // the one that would create the note, before any note exists: while the kernel moves the
    // asset into the output note it calls the faucet's send policy, which finds the holder in the
    // blocklist and aborts with the policy's own error. Nothing reaches a consumer, because there
    // is nothing to consume.
    let (note, asset) = outgoing_note(kind, holder_id, faucet_id, 11)?;
    let result = try_emit_burn_note(&f.pf.mock_chain, &note, &asset, faucet_id, holder_id).await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_BLOCKED);
    assert!(
        !f.pf.mock_chain.is_note_committed(&note.id()),
        "the rejected attempt must leave no note on chain"
    );
    assert_eq!(
        holder_balance(&f.pf.mock_chain, holder_id, faucet_id)?,
        MINT_AMOUNT - SEND_AMOUNT,
        "the rejected attempt must leave the holder's balance untouched"
    );

    // The BLK_MANAGER holder unblocks the holder, and the same kind of note can be created again.
    consume_seeded_admin_note(&mut f.pf, UNBLOCK_NOTE).await?;
    assert!(
        !is_listed(&committed(&f.pf.mock_chain, faucet_id)?, holder_id)?,
        "precondition: the unblock note removed the holder from the faucet's blocklist"
    );
    let (note, asset) = outgoing_note(kind, holder_id, faucet_id, 12)?;
    create_and_commit(&mut f, &note, &asset).await?;
    assert_eq!(
        holder_balance(&f.pf.mock_chain, holder_id, faucet_id)?,
        MINT_AMOUNT - 2 * SEND_AMOUNT,
        "after the unblock the holder moved USDCx out of its vault again"
    );
    Ok(())
}
