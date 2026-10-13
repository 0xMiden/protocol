//! The PSWAP fill across its whole input space.
//!
//! Each input is an axis: order size (offered x requested), payback, surplus, minimum fill step
//! and payback visibility. At every point of their cross product the real PSWAP script must either
//! reject with the error an independent model expects, or fill exactly as the model says. On a
//! fill, the order's owner must rebuild the payback and the remainder from the on-chain
//! attachments alone.

use std::collections::BTreeMap;

use anyhow::Context;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word, ZERO};
use miden_standards::errors::standards::{
    ERR_PSWAP_FILL_BELOW_MINIMUM,
    ERR_PSWAP_NOT_VALID_ASSET_AMOUNT,
    ERR_PSWAP_SURPLUS_NOT_BELOW_PAYBACK,
};
use miden_standards::note::{
    P2idNoteRecipient,
    P2idNoteStorage,
    PswapNote,
    PswapNoteAttachment,
    PswapNoteStorage,
    PswapPayback,
};
use miden_testing::{MockChain, assert_transaction_executor_error};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use rstest::rstest;

use super::pswap::{BASIC_AUTH, assert_vault_patch};

/// The largest fungible asset amount.
const MAX: u64 = FungibleAsset::MAX_AMOUNT.as_u64();

/// One whole 18-decimal token.
const E18: u64 = 1_000_000_000_000_000_000;

// THE MODEL
// ================================================================================================

/// Why the script must refuse a point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Refusal {
    /// The payback is not a valid asset amount.
    NotAnAssetAmount,
    /// The surplus leaves no fill.
    SurplusNotBelowPayback,
    /// The fill is below `min(min_fill_step, requested)`.
    FillBelowMinimum,
}

impl Refusal {
    fn error(self) -> MasmError {
        match self {
            Refusal::NotAnAssetAmount => ERR_PSWAP_NOT_VALID_ASSET_AMOUNT,
            Refusal::SurplusNotBelowPayback => ERR_PSWAP_SURPLUS_NOT_BELOW_PAYBACK,
            Refusal::FillBelowMinimum => ERR_PSWAP_FILL_BELOW_MINIMUM,
        }
    }

    /// The error the Rust prediction gives, for points it can be asked about.
    fn rust_message(self) -> &'static str {
        match self {
            Refusal::NotAnAssetAmount => "not a valid asset amount",
            Refusal::SurplusNotBelowPayback => "PSWAP surplus must be below the payback",
            Refusal::FillBelowMinimum => "PSWAP fill amount is below the minimum fill step",
        }
    }
}

/// What a fill must produce, in base units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Filled {
    /// The requested amount the order gives up at its own price.
    fill: u64,
    /// The requested amount the owner receives.
    payback: u64,
    /// The part of the payback above the order's price.
    surplus: u64,
    /// The offered amount the filler receives.
    payout: u64,
    /// The remainder's `(offered, requested)` on a partial fill.
    remainder: Option<(u64, u64)>,
}

/// One order.
#[derive(Clone, Copy, Debug)]
struct Order {
    offered: u64,
    requested: u64,
    min_fill_step: u64,
    private_payback: bool,
}

/// The expected result of filling `order` with note arguments `[0, from_wallet, 0, surplus]`,
/// written from the specification, independently of the script and the Rust crate. The checks
/// run in the script's order.
fn model(order: Order, from_wallet: u64, surplus: u64) -> Result<Filled, Refusal> {
    // No payers select a full fill from the consumer's vault.
    let payback = if from_wallet == 0 { order.requested } else { from_wallet };
    if payback > MAX {
        return Err(Refusal::NotAnAssetAmount);
    }
    if surplus >= payback {
        return Err(Refusal::SurplusNotBelowPayback);
    }
    // Whatever exceeds the requested amount is surplus too.
    let fill = (payback - surplus).min(order.requested);
    if fill < order.min_fill_step.min(order.requested) {
        return Err(Refusal::FillBelowMinimum);
    }
    let payout =
        (u128::from(order.offered) * u128::from(fill) / u128::from(order.requested)) as u64;
    let remainder =
        (fill < order.requested).then(|| (order.offered - payout, order.requested - fill));
    Ok(Filled {
        fill,
        payback,
        surplus: payback - fill,
        payout,
        remainder,
    })
}

/// The payback axis: the default (a full fill), the smallest, a third, one short of the order,
/// the order, one above, about 14% above, the largest amount and one past it.
fn payback_axis(requested: u64) -> Vec<u64> {
    let mut paybacks = vec![
        0,
        1,
        requested / 3,
        requested - 1,
        requested,
        requested + 1,
        requested.saturating_add(requested / 7 + 1),
        MAX,
        MAX + 1,
    ];
    paybacks.sort_unstable();
    paybacks.dedup();
    paybacks
}

/// The surplus axis for a payback of `payback`: none, one unit, about a seventh, all but one
/// unit, all of it and more than it.
fn surplus_axis(payback: u64) -> Vec<u64> {
    let mut surpluses =
        vec![0, 1, payback / 7, payback.saturating_sub(1), payback, payback.saturating_add(1)];
    surpluses.sort_unstable();
    surpluses.dedup();
    surpluses
}

// THE SPACE
// ================================================================================================

/// Order sizes `(offered, requested)`: small coprime ratios both ways, near 1:1, 18-decimal
/// amounts, and the largest amount on either side. Each case crosses every payback, surplus,
/// minimum fill step and payback visibility.
#[rstest]
#[case::one_for_one(1, 1)]
#[case::one_for_seven(1, 7)]
#[case::seven_for_one(7, 1)]
#[case::three_for_ten(3, 10)]
#[case::ten_for_three(10, 3)]
#[case::near_even(1_000, 999)]
#[case::eighteen_decimals(8 * E18, 4 * E18)]
#[case::max_offered(MAX, 3)]
#[case::max_requested(3, MAX)]
#[tokio::test]
async fn pswap_fill_grid(#[case] offered: u64, #[case] requested: u64) -> anyhow::Result<()> {
    let mut outcomes = Outcomes::default();
    for private_payback in [false, true] {
        for min_fill_step in [0, requested.div_ceil(2)] {
            let order = Order {
                offered,
                requested,
                min_fill_step,
                private_payback,
            };
            let space = payback_axis(requested)
                .into_iter()
                .flat_map(|from_wallet| {
                    let payback = if from_wallet == 0 { requested } else { from_wallet };
                    surplus_axis(payback).into_iter().map(move |surplus| (from_wallet, surplus))
                })
                .collect();
            outcomes += check_order(order, space).await?;
        }
    }
    outcomes.assert_covers_every_outcome(requested > 1);
    Ok(())
}

/// Random points, log-uniform in size, across the same axes.
#[rstest]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(4)]
#[tokio::test]
async fn pswap_fill_random(#[case] seed: u64) -> anyhow::Result<()> {
    let mut rng = SmallRng::seed_from_u64(seed);
    let amount = |rng: &mut SmallRng| -> u64 {
        let bits = rng.random_range(0..=62);
        rng.random_range(1..=(1u64 << bits).min(MAX))
    };
    for _ in 0..6 {
        let requested = amount(&mut rng);
        let order = Order {
            offered: amount(&mut rng),
            requested,
            min_fill_step: if rng.random_bool(0.5) { 0 } else { amount(&mut rng) },
            private_payback: rng.random_bool(0.5),
        };
        let space = (0..8)
            .map(|_| {
                let from_wallet = match rng.random_range(0..3) {
                    0 => 0,
                    1 => rng.random_range(1..=requested),
                    _ => amount(&mut rng),
                };
                let payback = if from_wallet == 0 { requested } else { from_wallet };
                let surplus = match rng.random_range(0..3) {
                    0 => 0,
                    1 => rng.random_range(0..=payback),
                    _ => amount(&mut rng),
                };
                (from_wallet, surplus)
            })
            .collect();
        check_order(order, space).await?;
    }
    Ok(())
}

/// Every partial fill of one order, each with its own surplus, rebuilt by the owner round by round
/// from the original order and the attachments alone.
#[tokio::test]
async fn pswap_lineage_rebuilds_from_attachments() -> anyhow::Result<()> {
    let (offered, requested) = (1_000, 900);
    // (payback, surplus): fills of 100, 250, 300 and the last 250, which completes the order.
    let rounds = [(100, 0), (260, 10), (300, 0), (280, 30)];

    let mut builder = MockChain::builder();
    let usdc = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", MAX, Some(offered))?;
    let eth = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", MAX, Some(10_000))?;
    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth.id(), 10_000)?.into()],
    )?;
    let original = PswapNote::builder()
        .sender(alice)
        .storage(
            PswapNoteStorage::builder()
                .min_requested_asset(FungibleAsset::new(eth.id(), requested)?)
                .payback(PswapPayback::public(alice))
                .build(),
        )
        .serial_number(builder.rng_mut().draw_word())
        .note_type(NoteType::Public)
        .offered_asset(FungibleAsset::new(usdc.id(), offered)?)
        .build()?;
    let mut current = original.clone();
    builder.add_output_note(RawOutputNote::Full(original.clone().into()));
    let mut chain = builder.build()?;

    // What the owner knows: the original order and, each round, the on-chain attachments.
    let (mut remaining_offered, mut remaining_requested) = (offered, requested);
    for (round, (payback, surplus)) in rounds.into_iter().enumerate() {
        let depth = u32::try_from(round + 1)?;
        let note: Note = current.clone().into();
        let (payback, surplus) = (AssetAmount::new(payback)?, AssetAmount::new(surplus)?);
        let tx = chain
            .build_transaction(bob.id())
            .authenticated_input_note(note.id())
            .extend_note_args(BTreeMap::from([(
                note.id(),
                PswapNote::create_fill_args(payback, AssetAmount::ZERO, surplus),
            )]))
            .build()?
            .execute()
            .await?;
        let outputs = tx.output_notes();

        let on_chain_payback = outputs.get_note(0);
        let attachment =
            PswapNoteAttachment::try_from(on_chain_payback.attachments().get(0).unwrap())?;
        assert_eq!(attachment.depth(), depth);
        assert_eq!(attachment.surplus(), surplus, "round {depth}: surplus");
        let rebuilt =
            original.public_payback_note(on_chain_payback.metadata().sender(), &attachment)?;
        assert_eq!(rebuilt.id(), on_chain_payback.id(), "round {depth}: payback");
        remaining_requested -= (attachment.amount() - attachment.surplus())?.as_u64();

        let (_, predicted) = current.execute(
            bob.id(),
            Some(FungibleAsset::new(eth.id(), payback.as_u64())?),
            None,
            surplus,
        )?;
        match predicted {
            Some(next) => {
                let on_chain_remainder = outputs.get_note(1);
                let remainder_attachment = PswapNoteAttachment::try_from(
                    on_chain_remainder.attachments().get(0).unwrap(),
                )?;
                remaining_offered -= remainder_attachment.amount().as_u64();
                let rebuilt = original.remainder_note(
                    on_chain_remainder.metadata().sender(),
                    &remainder_attachment,
                    AssetAmount::new(remaining_offered)?,
                    AssetAmount::new(remaining_requested)?,
                )?;
                assert_eq!(
                    rebuilt.details_commitment(),
                    on_chain_remainder.details_commitment(),
                    "round {depth}: remainder"
                );
                current = next;
            },
            None => {
                assert_eq!(remaining_requested, 0, "the last round completes the order");
                assert_eq!(outputs.num_notes(), 1);
            },
        }
        chain.add_pending_executed_transaction(&tx)?;
        chain.prove_next_block()?;
    }
    Ok(())
}

// CHECKING ONE ORDER
// ================================================================================================

/// How many points ended each way.
#[derive(Default)]
struct Outcomes {
    filled_partly: usize,
    filled_fully: usize,
    refused: BTreeMap<Refusal, usize>,
}

impl core::ops::AddAssign for Outcomes {
    fn add_assign(&mut self, other: Self) {
        self.filled_partly += other.filled_partly;
        self.filled_fully += other.filled_fully;
        for (refusal, count) in other.refused {
            *self.refused.entry(refusal).or_default() += count;
        }
    }
}

impl Outcomes {
    /// The grid must reach every outcome, so no region of the space goes untested. An order for
    /// one unit cannot be filled partly.
    fn assert_covers_every_outcome(&self, partial_possible: bool) {
        let summary = format!(
            "{} partial, {} full, refused {:?}",
            self.filled_partly, self.filled_fully, self.refused
        );
        assert_eq!(self.filled_partly > 0, partial_possible, "{summary}");
        assert!(self.filled_fully > 0, "{summary}");
        for refusal in [Refusal::NotAnAssetAmount, Refusal::SurplusNotBelowPayback] {
            assert!(self.refused.contains_key(&refusal), "{refusal:?}: {summary}");
        }
    }
}

/// Builds `order` once and runs every `(from_wallet, surplus)` of `space` against it.
async fn check_order(order: Order, space: Vec<(u64, u64)>) -> anyhow::Result<Outcomes> {
    let mut builder = MockChain::builder();
    let offered_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", MAX, Some(order.offered))?;
    let requested_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", MAX, Some(MAX))?;
    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    // Bob can pay any valid payback.
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(requested_faucet.id(), MAX)?.into()],
    )?;
    let recipient =
        P2idNoteRecipient::new(P2idNoteStorage::new(alice), builder.rng_mut().draw_word());
    let payback = if order.private_payback {
        PswapPayback::private(recipient, NoteTag::new(1234))
    } else {
        PswapPayback::public(alice)
    };
    let pswap = PswapNote::builder()
        .sender(alice)
        .storage(
            PswapNoteStorage::builder()
                .min_requested_asset(FungibleAsset::new(requested_faucet.id(), order.requested)?)
                .payback(payback)
                .min_fill_step(AssetAmount::new(order.min_fill_step)?)
                .build(),
        )
        .serial_number(builder.rng_mut().draw_word())
        .note_type(NoteType::Public)
        .offered_asset(FungibleAsset::new(offered_faucet.id(), order.offered)?)
        .build()?;
    builder.add_output_note(RawOutputNote::Full(pswap.clone().into()));
    let chain = builder.build()?;

    let point = Point {
        chain: &chain,
        pswap: &pswap,
        order,
        filler: bob.id(),
        offered_faucet: offered_faucet.id(),
        requested_faucet: requested_faucet.id(),
        recipient,
    };
    let mut outcomes = Outcomes::default();
    for (from_wallet, surplus) in space {
        let outcome = point
            .check(from_wallet, surplus)
            .await
            .with_context(|| format!("{order:?}, from_wallet {from_wallet}, surplus {surplus}"))?;
        match outcome {
            Ok(Filled { remainder: Some(_), .. }) => outcomes.filled_partly += 1,
            Ok(Filled { remainder: None, .. }) => outcomes.filled_fully += 1,
            Err(refusal) => *outcomes.refused.entry(refusal).or_default() += 1,
        }
    }
    Ok(outcomes)
}

/// One order on its chain, ready to be filled at any point.
struct Point<'a> {
    chain: &'a MockChain,
    pswap: &'a PswapNote,
    order: Order,
    filler: AccountId,
    offered_faucet: AccountId,
    requested_faucet: AccountId,
    recipient: P2idNoteRecipient,
}

impl Point<'_> {
    /// Fills the order with `[0, from_wallet, 0, surplus]` and checks the script against the
    /// model, the Rust prediction and the owner's rebuild. Returns the model's outcome.
    async fn check(
        &self,
        from_wallet: u64,
        surplus: u64,
    ) -> anyhow::Result<Result<Filled, Refusal>> {
        let note: Note = self.pswap.clone().into();
        // Raw felts, so the invalid regions can be written down as well.
        let args = Word::from([ZERO, Felt::try_from(from_wallet)?, ZERO, Felt::try_from(surplus)?]);
        let result = self
            .chain
            .build_transaction(self.filler)
            .authenticated_input_note(note.id())
            .extend_note_args(BTreeMap::from([(note.id(), args)]))
            .build()?
            .execute()
            .await;
        // The Rust prediction takes typed amounts, so it is asked only where they are valid.
        let payback = if from_wallet == 0 {
            self.order.requested
        } else {
            from_wallet
        };
        let predicted =
            match (FungibleAsset::new(self.requested_faucet, payback), AssetAmount::new(surplus)) {
                (Ok(payback), Ok(surplus)) => {
                    Some(self.pswap.execute(self.filler, Some(payback), None, surplus))
                },
                _ => None,
            };

        let filled = match model(self.order, from_wallet, surplus) {
            Err(refusal) => {
                let error = refusal.error();
                assert_transaction_executor_error!(result, error);
                if let Some(predicted) = predicted {
                    let message = predicted.err().map(|error| error.to_string());
                    assert!(
                        message.as_deref().is_some_and(|m| m.contains(refusal.rust_message())),
                        "the Rust prediction must refuse it too: {message:?}"
                    );
                }
                return Ok(Err(refusal));
            },
            Ok(filled) => filled,
        };

        let tx = result.context("the script refused a point the model fills")?;
        let outputs = tx.output_notes();
        assert_eq!(outputs.num_notes(), 1 + usize::from(filled.remainder.is_some()));
        let (predicted_payback, predicted_remainder) =
            predicted.context("a filled point has valid amounts")??;

        // The payback: the model's amount, the Rust prediction and the owner's rebuild.
        let on_chain_payback = outputs.get_note(0);
        assert_eq!(
            on_chain_payback.assets().iter().next().unwrap().unwrap_fungible(),
            FungibleAsset::new(self.requested_faucet, filled.payback)?,
        );
        assert_eq!(predicted_payback.id(), on_chain_payback.id(), "Rust prediction: payback");
        let attachment =
            PswapNoteAttachment::try_from(on_chain_payback.attachments().get(0).unwrap())?;
        assert_eq!(attachment.amount().as_u64(), filled.payback);
        assert_eq!(attachment.surplus().as_u64(), filled.surplus);
        assert_eq!(attachment.depth(), 1);
        let sender = on_chain_payback.metadata().sender();
        let rebuilt_payback = if self.order.private_payback {
            self.pswap.private_payback_note(sender, &attachment, self.recipient)?
        } else {
            self.pswap.public_payback_note(sender, &attachment)?
        };
        assert_eq!(rebuilt_payback.id(), on_chain_payback.id(), "owner rebuild: payback");

        // The remainder on a partial fill: from the remainder's amount and the payback's fill.
        match (filled.remainder, predicted_remainder) {
            (Some((offered_left, requested_left)), Some(predicted)) => {
                let on_chain_remainder = outputs.get_note(1);
                assert_eq!(
                    Note::from(predicted).id(),
                    on_chain_remainder.id(),
                    "Rust prediction: remainder"
                );
                let remainder_attachment = PswapNoteAttachment::try_from(
                    on_chain_remainder.attachments().get(0).unwrap(),
                )?;
                assert_eq!(remainder_attachment.amount().as_u64(), filled.payout);
                assert_eq!(remainder_attachment.surplus(), AssetAmount::ZERO);
                let fill = (attachment.amount() - attachment.surplus())?;
                assert_eq!(fill.as_u64(), filled.fill);
                let rebuilt = self.pswap.remainder_note(
                    on_chain_remainder.metadata().sender(),
                    &remainder_attachment,
                    AssetAmount::new(self.order.offered - remainder_attachment.amount().as_u64())?,
                    AssetAmount::new(self.order.requested - fill.as_u64())?,
                )?;
                assert_eq!(
                    rebuilt.details_commitment(),
                    on_chain_remainder.details_commitment(),
                    "owner rebuild: remainder"
                );
                let rebuilt = PswapNote::try_from(&rebuilt)?;
                assert_eq!(rebuilt.offered_asset().amount().as_u64(), offered_left);
                assert_eq!(rebuilt.storage().min_requested_amount(), requested_left);
            },
            (None, None) => {},
            (model, rust) => {
                anyhow::bail!("remainder: model {model:?}, Rust prediction {}", rust.is_some())
            },
        }

        // The filler paid the whole payback and received the payout.
        let mut vault = vec![FungibleAsset::new(self.requested_faucet, MAX - filled.payback)?];
        if filled.payout > 0 {
            vault.push(FungibleAsset::new(self.offered_faucet, filled.payout)?);
        }
        assert_vault_patch(tx.account_patch().vault(), vault);
        Ok(Ok(filled))
    }
}
