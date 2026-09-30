//! Benchmarked consumption costs for notes whose execution on the xUSDC faucet differs from the
//! corresponding standard note.

use miden_protocol::note::NoteScriptRoot;
use miden_standards::note::costs::{NoteConsumptionCost, NoteCost};
use miden_standards::note::P2idNote;

use super::xreserve_admin::XReserveSetAttesterNote;
use super::xreserve_burn::XReserveBurnNote;
use super::xreserve_mint::XUsdcMintNote;

/// Cycles of consuming an xUSDC MINT note: empty hook data 47309, maximum hook data 65787.
pub const XUSDC_MINT_CONSUMPTION_CYCLES: u32 = 65787;

/// Cycles of consuming an xUSDC BURN note.
pub const XUSDC_BURN_CONSUMPTION_CYCLES: u32 = 33113;

/// Cycles of consuming an xUSDC set-attester note: enable 30314, disable 30177.
pub const XRESERVE_SET_ATTESTER_CONSUMPTION_CYCLES: u32 = 30314;

impl NoteConsumptionCost for XUsdcMintNote {
    fn consumption_cycles() -> u32 {
        XUSDC_MINT_CONSUMPTION_CYCLES
    }

    fn created_notes() -> Vec<NoteScriptRoot> {
        vec![P2idNote::script_root()]
    }
}

impl NoteConsumptionCost for XReserveBurnNote {
    fn consumption_cycles() -> u32 {
        XUSDC_BURN_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for XReserveSetAttesterNote {
    fn consumption_cycles() -> u32 {
        XRESERVE_SET_ATTESTER_CONSUMPTION_CYCLES
    }
}

/// Returns the xUSDC-specific costs keyed by script root.
pub(crate) fn note_costs() -> [(NoteScriptRoot, NoteCost); 3] {
    [
        (
            XUsdcMintNote::script_root(),
            NoteCost::of::<XUsdcMintNote>(),
        ),
        (
            XReserveBurnNote::script_root(),
            NoteCost::of::<XReserveBurnNote>(),
        ),
        (
            XReserveSetAttesterNote::script_root(),
            NoteCost::of::<XReserveSetAttesterNote>(),
        ),
    ]
}
