//! Benchmarked consumption costs of the agglayer notes.
//!
//! Each constant is the number of VM cycles of the canonical network-account transaction
//! consuming the note - measured by the `bench-transaction` binary. See
//! [`miden_standards::note::costs`] for the full definition of the canonical transaction, the
//! cycle denomination, why the values are estimates rather than guaranteed worst cases, and the
//! [`NetworkNotePricer`](miden_standards::note::costs::NetworkNotePricer) turning cycle costs
//! into fees; build it with [`AgglayerNote::note_cost`](crate::AgglayerNote::note_cost) as the
//! lookup to price agglayer and standard notes through a single pricer.
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when a checked-in value drifts more than 5% from the measured
//! one (small drift from unrelated changes is tolerated - the pricing safety margin dwarfs
//! it).

use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::note::NoteScriptRoot;
use miden_standards::note::costs::NoteConsumptionCost;
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
