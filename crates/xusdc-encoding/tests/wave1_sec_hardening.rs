//! SECURITY HARDENING — the construction-time guard the min-burn note factory carries.
//!
//! The standard admin procedures validate nothing about the values they write, so the guard lives
//! in the factory that builds the note: it refuses the harmful value before a note exists. The
//! refusal has its exact-error negative plus a positive that proves it is not over-broad (a
//! legitimate in-range min-burn write still succeeds). The refusal is a guard against operator
//! error, not an authorization boundary — what the chain does when someone hand-rolls the
//! standard note past it, and why that state is recoverable, is covered in
//! `w2admin_production_admin_effects.rs`.
//!
//! A min-burn floor below `MIN_BURN_SIZE_FLOOR` is refused (a zero floor admits zero-amount burn
//! notes). Above-range floors are unrepresentable: the factory takes an [`AssetAmount`], whose
//! constructor rejects values over the fungible-asset maximum.
//!
//! The on-chain positive runs through the PRODUCTION note factory on the REAL production faucet
//! composition, so it holds the tripwire serial guard (it shares the mint-transport machinery
//! that flakes under parallel `cargo test`).

mod support;

use anyhow::Result;
use miden_protocol::asset::AssetAmount;
use miden_protocol::{Felt, Word};
use miden_standards::account::policies::MinBurnAmount;
use support::mint_transport::*;
use support::*;
use xusdc_encoding::note::xreserve_admin::{
    XReserveMinBurnAmountNote, XReserveMinBurnAmountNoteError,
};

/// The stock `MinBurnAmount` floor-slot word for a floor `v` (`[v,0,0,0]`), read-back oracle.
fn min_word(v: u64) -> Word {
    Word::from([
        Felt::try_from(v).expect("floor fits the field"),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ])
}

// The min-burn zero-floor refusal
// ================================================================================================

/// A min-burn note carrying a floor of 0 cannot be built: the factory refuses it, so the note never
/// reaches a chain. The stock `set_min_burn_amount` accepts 0, and a zero floor admits zero-amount
/// burn notes — which is what makes this refusal non-vacuous.
#[test]
fn a_min_burn_note_carrying_a_zero_floor_cannot_be_built() {
    let faucet_id = test_faucet_id(1);
    let err = XReserveMinBurnAmountNote::builder()
        .sender(administrator())
        .target(faucet_id)
        .min_burn_amount(AssetAmount::ZERO)
        .generate_serial_number(&mut note_rng(720))
        .build()
        .expect_err("the factory must refuse a zero-floor min-burn note");
    assert!(
        matches!(
            err,
            XReserveMinBurnAmountNoteError::MinBurnAmountTooSmall { min_burn_amount: 0 }
        ),
        "the refusal must be the specific below-floor rejection, not some other note error: {err:?}"
    );
}

/// The refusal is NOT over-broad: an ADMIN-sent write at the floor boundary (`new_min = 1`) still
/// builds, SUCCEEDS on chain, and writes `[1,0,0,0]` into the stock `MinBurnAmount` slot.
#[tokio::test]
async fn set_min_burn_at_the_floor_still_succeeds() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let mut pf = setup_production_faucet(0, |_recipient, faucet_id| {
        vec![stock_min_burn_note(administrator(), faucet_id, 1, 722)
            .expect("building the floor min-burn note")]
    })?;
    let floor_note = pf.seeded_notes[0].clone();

    let tx = consume_note(&pf.mock_chain, pf.faucet_id, floor_note.id())
        .await
        .map_err(|e| anyhow::anyhow!("a min-burn write of 1 must still succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;

    let faucet = committed(&pf.mock_chain, pf.faucet_id)?;
    let floor = faucet
        .storage()
        .get_item(MinBurnAmount::slot_name())
        .map_err(|e| anyhow::anyhow!("reading the stock MinBurnAmount slot: {e}"))?;
    assert_eq!(
        floor,
        min_word(1),
        "a min-burn write of 1 lands [1,0,0,0] in the stock MinBurnAmount slot"
    );
    Ok(())
}
