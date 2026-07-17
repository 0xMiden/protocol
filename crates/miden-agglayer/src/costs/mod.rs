//! Benchmarked consumption costs of the agglayer notes.
//!
//! Each constant is the number of VM cycles of the canonical network-account transaction
//! consuming the note - measured by the `bench-transaction` binary. See
//! [`miden_standards::note::costs`] for the full definition of the canonical transaction, the
//! cycle denomination, why the values are estimates rather than guaranteed worst cases, and
//! the [`NotePricer`](miden_standards::note::costs::NotePricer) turning cycle costs into fees.
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when a checked-in value drifts more than 5% from the measured
//! one (small drift from unrelated changes is tolerated - the pricing safety margin dwarfs
//! it).

use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::asset::AssetAmount;
use miden_protocol::note::NoteScriptRoot;
use miden_standards::note::costs::{NoteConsumptionCost, NoteCost, NotePricer, NotePricingError};
use miden_standards::note::{BurnNote, MintNote};

use crate::{
    B2AggNote,
    ClaimNote,
    ConfigAggBridgeNote,
    DeregisterAggFaucetNote,
    RemoveGerNote,
    UpdateGerNote,
};

mod table;
pub use table::*;

// NOTE CONSUMPTION COST IMPLS
// ================================================================================================

impl NoteConsumptionCost for ClaimNote {
    fn consumption_cycles() -> u64 {
        CLAIM_CONSUMPTION_CYCLES
    }

    /// Consuming a CLAIM note creates the MINT note routed to the agglayer faucet (a network
    /// account).
    fn created_network_notes() -> Vec<NoteScriptRoot> {
        vec![MintNote::script_root()]
    }
}

impl NoteConsumptionCost for B2AggNote {
    fn consumption_cycles() -> u64 {
        B2AGG_CONSUMPTION_CYCLES
    }

    /// Consuming a B2AGG note creates the BURN note routed to the agglayer faucet (a network
    /// account).
    fn created_network_notes() -> Vec<NoteScriptRoot> {
        vec![BurnNote::script_root()]
    }
}

impl NoteConsumptionCost for ConfigAggBridgeNote {
    fn consumption_cycles() -> u64 {
        CONFIG_AGG_BRIDGE_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for DeregisterAggFaucetNote {
    fn consumption_cycles() -> u64 {
        DEREGISTER_AGG_FAUCET_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for UpdateGerNote {
    fn consumption_cycles() -> u64 {
        UPDATE_GER_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for RemoveGerNote {
    fn consumption_cycles() -> u64 {
        REMOVE_GER_CONSUMPTION_CYCLES
    }
}

// COST LOOKUP
// ================================================================================================

/// Returns the benchmarked consumption cost of the note with the given script root, resolving
/// the agglayer notes first and falling back to the standard notes
/// ([`miden_standards::note::costs::note_cost`]).
pub fn note_cost(root: NoteScriptRoot) -> Option<NoteCost> {
    if root == ClaimNote::script_root() {
        return Some(NoteCost::of::<ClaimNote>());
    }
    if root == B2AggNote::script_root() {
        return Some(NoteCost::of::<B2AggNote>());
    }
    if root == ConfigAggBridgeNote::script_root() {
        return Some(NoteCost::of::<ConfigAggBridgeNote>());
    }
    if root == DeregisterAggFaucetNote::script_root() {
        return Some(NoteCost::of::<DeregisterAggFaucetNote>());
    }
    if root == UpdateGerNote::script_root() {
        return Some(NoteCost::of::<UpdateGerNote>());
    }
    if root == RemoveGerNote::script_root() {
        return Some(NoteCost::of::<RemoveGerNote>());
    }

    miden_standards::note::costs::note_cost(root)
}

/// Computes the fee-schedule entries for all agglayer notes, pricing recursively with the
/// agglayer-aware [`note_cost`] lookup (a CLAIM's price includes the MINT and P2ID legs it
/// triggers, a B2AGG's price includes the BURN leg).
pub fn agglayer_note_prices(
    pricer: &NotePricer,
) -> Result<Vec<(NoteScriptRoot, AssetAmount)>, NotePricingError> {
    [
        ClaimNote::script_root(),
        B2AggNote::script_root(),
        ConfigAggBridgeNote::script_root(),
        DeregisterAggFaucetNote::script_root(),
        UpdateGerNote::script_root(),
        RemoveGerNote::script_root(),
    ]
    .into_iter()
    .map(|root| Ok((root, pricer.price_with(root, &note_cost)?)))
    .collect()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_standards::note::P2idNote;
    use miden_standards::note::costs::{MINT_CONSUMPTION_CYCLES, P2ID_CONSUMPTION_CYCLES};

    use super::*;

    fn pricer() -> NotePricer {
        NotePricer::builder()
            .verification_base_fee(500)
            .safety_margin_verification_cycles(0)
            .build()
    }

    #[test]
    fn note_cost_resolves_agglayer_notes_and_falls_back_to_standards() {
        let claim_cost = note_cost(ClaimNote::script_root()).expect("CLAIM should have a cost");
        assert_eq!(claim_cost.cycles(), CLAIM_CONSUMPTION_CYCLES);
        assert_eq!(claim_cost.created_network_notes(), [MintNote::script_root()]);

        let p2id_cost = note_cost(P2idNote::script_root()).expect("P2ID should resolve here too");
        assert_eq!(p2id_cost.cycles(), P2ID_CONSUMPTION_CYCLES);
    }

    #[test]
    fn agglayer_note_prices_cover_all_notes_and_include_created_legs() {
        let pricer = pricer();
        let prices = agglayer_note_prices(&pricer).unwrap();
        assert_eq!(prices.len(), 6);
        assert!(prices.iter().all(|(_, price)| price.as_u64() > 0));

        // A CLAIM's price covers the whole chain it triggers: CLAIM + MINT + P2ID.
        let claim_price = prices
            .iter()
            .find(|(root, _)| *root == ClaimNote::script_root())
            .map(|(_, price)| price.as_u64())
            .unwrap();
        let expected = pricer.fee_for_cycles(CLAIM_CONSUMPTION_CYCLES).unwrap().as_u64()
            + pricer.fee_for_cycles(MINT_CONSUMPTION_CYCLES).unwrap().as_u64()
            + pricer.fee_for_cycles(P2ID_CONSUMPTION_CYCLES).unwrap().as_u64();
        assert_eq!(claim_price, expected);
    }
}
