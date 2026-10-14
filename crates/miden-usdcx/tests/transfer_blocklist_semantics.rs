//! A holder on the faucet's transfer blocklist can create neither a USDCx transfer note nor a USDCx
//! burn note.
//!
//! The faucet keeps a list of blocked Miden accounts that only the `BLK_MANAGER` role holder can
//! change, through the standard blocklist config note. Whenever USDCx leaves an account, the
//! transaction kernel calls back into the faucet, which aborts the transaction if that account is
//! listed. OpenZeppelin (finding N-07, issue 0xMiden/miden-usdcx#175) asked for a test that shows
//! this for both kinds of outgoing note. Who may block is covered in `transfer_blocklist_e2e.rs`,
//! the receive side in `mint_scale_conformance.rs`.
//!
//! Each case funds a holder through the real attested mint path on the production faucet, shows
//! the holder can create the note while unlisted, has the `BLK_MANAGER` holder block it, and shows
//! the same kind of note can no longer be created and the holder's balance is untouched.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::{Account, AccountId, StorageMapKey};
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

/// Each outgoing note carries 5 USDC (6 decimals), a slice of the `MINT_AMOUNT` the holder got.
const SEND_AMOUNT: u64 = 5_000_000;

/// Index of the `BLK_MANAGER` block note in `pf.seeded_notes` (index 0 is the set_attester note).
const BLOCK_NOTE: usize = 1;

/// The two kinds of outgoing note a holder creates with its USDCx.
#[derive(Clone, Copy, Debug)]
enum Outgoing {
    /// A pay-to-id note that sends USDCx to another Miden account.
    Transfer,
    /// A USDCx burn note that starts a withdrawal to the source chain.
    Burn,
}

/// Builds the production faucet (the deployment's component set and network-account auth) next to
/// a holder wallet, seeds the attester and block admin notes, then funds the holder with
/// `MINT_AMOUNT` USDCx through the real path: the faucet consumes an attested mint note and the
/// holder consumes the resulting pay-to-id note. The holder is `pf.recipient_id`.
async fn funded_fixture() -> Result<ProductionFaucet> {
    let mut mc = MockChain::builder();
    // A standard wallet plus the suite's small helper that lets the wallet attach data to a note
    // it creates; the burn note carries its withdrawal payload as such an attachment.
    let holder = add_emitting_wallet(&mut mc, Auth::IncrNonce, [])?;
    let producer = add_emitting_wallet(&mut mc, Auth::IncrNonce, [])?;
    let components = production_builder_verdict_with_attesters(0, TEST_DOMAIN, None, Vec::new())?
        .map_err(|e| anyhow::anyhow!("building the production faucet: {e}"))?
        .build_components()
        .map_err(|e| anyhow::anyhow!("composing the production faucet: {e}"))?;
    let faucet = add_network_faucet_account(&mut mc, components)?;
    let (faucet_id, holder_id) = (faucet.id(), holder.id());

    let payload = payload_for(holder_id, faucet_id, MINT_AMOUNT, 0);
    let seeded_notes = vec![
        XReserveSetAttesterNote::create(
            administrator(),
            faucet_id,
            gen_attester(1, &payload).commitment,
            1,
            &mut note_rng(952),
        )
        .context("building the set_attester note")?,
        stock_block_note(test_account_id(4), faucet_id, holder_id, 953)
            .context("building the block note")?,
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
    // The faucet consumes the set_attester note so the mint below carries an allowlisted attester.
    bring_up(&mut pf, 1).await?;

    // The real mint path: the producer publishes the attested mint note, the faucet consumes it and
    // mints a pay-to-id note to the holder, and the holder consumes that note.
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
    assert_eq!(holder_balance(&pf)?, MINT_AMOUNT, "the holder starts with the minted amount");
    Ok(pf)
}

/// The holder's committed balance of the faucet's asset.
fn holder_balance(pf: &ProductionFaucet) -> Result<u64> {
    let asset = FungibleAsset::new(pf.faucet_id, 0).context("faucet asset")?;
    let balance = pf
        .mock_chain
        .committed_account(pf.recipient_id)?
        .vault()
        .get_balance(asset.id())?;
    Ok(u64::from(balance))
}

/// Whether `account` is on the faucet's blocklist, read from the faucet's committed storage.
fn is_listed(faucet: &Account, account: AccountId) -> Result<bool> {
    // The blocklist component keys its map by `[0, 0, suffix, prefix]` of the account id.
    let key = Word::from([Felt::ZERO, Felt::ZERO, account.suffix(), account.prefix().as_felt()]);
    let entry = faucet
        .storage()
        .get_map_item(BlocklistStorage::blocked_accounts_slot(), StorageMapKey::new(key))
        .map_err(|e| anyhow::anyhow!("reading blocked_accounts[{account}]: {e}"))?;
    Ok(entry != Word::empty())
}

/// A fresh outgoing note of the requested kind carrying `SEND_AMOUNT` from the holder, with the
/// asset the holder's transaction moves into it. `seed` only varies the serial number.
fn outgoing_note(
    pf: &ProductionFaucet,
    kind: Outgoing,
    seed: u64,
) -> Result<(Note, FungibleAsset)> {
    let asset = FungibleAsset::new(pf.faucet_id, SEND_AMOUNT).context("outgoing asset")?;
    let note = match kind {
        Outgoing::Transfer => P2idNote::builder()
            .sender(pf.recipient_id)
            .target(test_account_id(77))
            .asset(asset)
            .generate_serial_number(&mut note_rng(seed))
            .note_type(NoteType::Public)
            .build()
            .context("building the transfer note")?
            .into(),
        Outgoing::Burn => XReserveBurnNote::create(
            pf.recipient_id,
            pf.faucet_id,
            AssetAmount::new(SEND_AMOUNT).context("burn amount")?,
            XReserveBurnItems::builder()
                .dest_domain(TEST_SOURCE_DOMAIN)
                .dest_recipient(ForeignChainAddress::new([0xab; 32]))
                .build(),
            &mut note_rng(seed),
        )
        .context("building the burn note")?,
    };
    // Guard against a later edit quietly turning the burn case into a second transfer case: the
    // burn note carries the burn script and two attachments (routing target and withdrawal
    // payload), the transfer note the pay-to-id script and none.
    let (script, attachments) = match kind {
        Outgoing::Transfer => (P2idNote::script_root(), 0),
        Outgoing::Burn => (XReserveBurnNote::script_root(), 2),
    };
    assert_eq!(note.script().root(), script, "the {kind:?} note must carry the {kind:?} script");
    assert_eq!(note.attachments().num_attachments(), attachments, "{kind:?} note attachments");
    Ok((note, asset))
}

/// A listed holder can create neither a transfer note nor a burn note. One case per note kind.
#[rstest]
#[case::transfer_note(Outgoing::Transfer)]
#[case::burn_note(Outgoing::Burn)]
#[tokio::test]
async fn blocked_holder_cannot_create_the_note(#[case] kind: Outgoing) -> Result<()> {
    let mut pf = funded_fixture().await?;
    let (faucet_id, holder_id) = (pf.faucet_id, pf.recipient_id);

    // Positive control: while unlisted, the holder creates the note and it lands on chain. The
    // only thing that changes before the second attempt is the holder's entry in the blocklist.
    assert!(!is_listed(&committed(&pf.mock_chain, faucet_id)?, holder_id)?);
    let (note, asset) = outgoing_note(&pf, kind, 10)?;
    let tx = try_emit_burn_note(&pf.mock_chain, &note, &asset, faucet_id, holder_id)
        .await
        .map_err(|e| anyhow::anyhow!("the unlisted holder must be able to create the note: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;
    assert!(pf.mock_chain.is_note_committed(&note.id()), "the created note is on chain");
    assert_eq!(holder_balance(&pf)?, MINT_AMOUNT - SEND_AMOUNT, "USDCx left the holder's vault");

    // The BLK_MANAGER holder blocks the holder; the faucet consumes the block note in a committed
    // block, so every later callback sees the holder as listed.
    consume_seeded_admin_note(&mut pf, BLOCK_NOTE).await?;
    assert!(
        is_listed(&committed(&pf.mock_chain, faucet_id)?, holder_id)?,
        "precondition: the block note put the holder on the faucet's blocklist"
    );

    // The step OpenZeppelin asked to see. The holder's own transaction fails while the kernel
    // moves the asset into the new note: the faucet's send policy finds the holder in the
    // blocklist and aborts with its own error, so no note ever exists.
    let (note, asset) = outgoing_note(&pf, kind, 11)?;
    let result = try_emit_burn_note(&pf.mock_chain, &note, &asset, faucet_id, holder_id).await;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_BLOCKED);
    assert!(
        !pf.mock_chain.is_note_committed(&note.id()),
        "the rejected attempt left no note"
    );
    assert_eq!(
        holder_balance(&pf)?,
        MINT_AMOUNT - SEND_AMOUNT,
        "the holder's balance is untouched"
    );
    Ok(())
}
