//! Benchmarked consumption costs of the agglayer notes.
//!
//! Each constant is the number of VM cycles of the canonical network-account transaction
//! consuming the note - measured by the `bench-transaction` binary. See
//! [`miden_standards::note::costs`] for the full definition of the canonical transaction, the
//! cycle denomination, why the values are estimates rather than guaranteed worst cases, and the
//! [`NetworkNotePricer`](miden_standards::note::costs::NetworkNotePricer) turning cycle costs
//! into fees; build it with this module's [`note_cost`] as the lookup to price agglayer and
//! standard
//! notes through a single pricer.
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when a checked-in value drifts more than 5% from the measured
//! one (small drift from unrelated changes is tolerated - the pricing safety margin dwarfs
//! it).

use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::note::NoteScriptRoot;
use miden_standards::note::costs::{NoteConsumptionCost, NoteCost};
use miden_standards::note::{BurnNote, MintNote, StandardNote};

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
    fn consumption_cycles() -> u32 {
        CLAIM_CONSUMPTION_CYCLES
    }

    /// Consuming a CLAIM note creates the MINT note routed to the agglayer faucet (a network
    /// account).
    fn created_notes() -> Vec<NoteScriptRoot> {
        vec![MintNote::script_root()]
    }
}

impl NoteConsumptionCost for B2AggNote {
    fn consumption_cycles() -> u32 {
        B2AGG_CONSUMPTION_CYCLES
    }

    /// Consuming a B2AGG note creates the BURN note routed to the agglayer faucet (a network
    /// account).
    fn created_notes() -> Vec<NoteScriptRoot> {
        vec![BurnNote::script_root()]
    }
}

impl NoteConsumptionCost for ConfigAggBridgeNote {
    fn consumption_cycles() -> u32 {
        CONFIG_AGG_BRIDGE_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for DeregisterAggFaucetNote {
    fn consumption_cycles() -> u32 {
        DEREGISTER_AGG_FAUCET_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for UpdateGerNote {
    fn consumption_cycles() -> u32 {
        UPDATE_GER_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for RemoveGerNote {
    fn consumption_cycles() -> u32 {
        REMOVE_GER_CONSUMPTION_CYCLES
    }
}

// COST LOOKUP
// ================================================================================================

/// Returns the benchmarked consumption cost of the note with the given script root, resolving
/// the agglayer notes first and falling back to the standard notes
/// ([`StandardNote::note_cost`]).
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

    StandardNote::note_cost(root)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountId;
    use miden_protocol::block::FeeParameters;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
    use miden_standards::note::P2idNote;
    use miden_standards::note::costs::{
        MINT_CONSUMPTION_CYCLES,
        NetworkNotePricer,
        P2ID_CONSUMPTION_CYCLES,
    };

    use super::*;

    fn pricer() -> NetworkNotePricer {
        let fee_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("testing faucet ID should be valid");
        NetworkNotePricer::builder()
            .fee_parameters(FeeParameters::new(fee_faucet_id, 500))
            .safety_margin_verification_cycles(0)
            .lookup(note_cost)
            .build()
    }

    #[test]
    fn note_cost_resolves_agglayer_notes_and_falls_back_to_standards() {
        let claim_cost = note_cost(ClaimNote::script_root()).expect("CLAIM should have a cost");
        assert_eq!(claim_cost.cycles(), CLAIM_CONSUMPTION_CYCLES);
        assert_eq!(claim_cost.created_notes(), [MintNote::script_root()]);

        let p2id_cost = note_cost(P2idNote::script_root()).expect("P2ID should resolve here too");
        assert_eq!(p2id_cost.cycles(), P2ID_CONSUMPTION_CYCLES);
    }

    #[test]
    fn claim_price_includes_the_mint_and_p2id_legs() {
        let pricer = pricer();

        // A CLAIM's price covers the whole chain it triggers: CLAIM + MINT + P2ID.
        let expected = pricer.fee_for_cycles(CLAIM_CONSUMPTION_CYCLES).unwrap().as_u64()
            + pricer.fee_for_cycles(MINT_CONSUMPTION_CYCLES).unwrap().as_u64()
            + pricer.fee_for_cycles(P2ID_CONSUMPTION_CYCLES).unwrap().as_u64();
        assert_eq!(pricer.price(ClaimNote::script_root()).unwrap().as_u64(), expected);
    }
}
