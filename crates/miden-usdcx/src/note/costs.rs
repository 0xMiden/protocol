//! Benchmarked consumption costs for notes whose execution on the xUSDC faucet differs from the
//! corresponding standard note.

use miden_protocol::note::NoteScriptRoot;
use miden_standards::note::P2idNote;
use miden_standards::note::costs::{NoteConsumptionCost, NoteCost};

use super::xreserve_admin::XReserveSetAttesterNote;
use super::xreserve_burn::XReserveBurnNote;
use super::xreserve_mint::XUsdcMintNote;

/// Cycles of consuming an xUSDC MINT note: empty hook data 45506, maximum hook data 63984.
pub const XUSDC_MINT_CONSUMPTION_CYCLES: u32 = 63984;

/// Cycles of consuming an xUSDC BURN note.
pub const XUSDC_BURN_CONSUMPTION_CYCLES: u32 = 35118;

/// Cycles of consuming an xUSDC set-attester note: enable 31245, disable 31092.
pub const XRESERVE_SET_ATTESTER_CONSUMPTION_CYCLES: u32 = 31245;

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
        (XUsdcMintNote::script_root(), NoteCost::of::<XUsdcMintNote>()),
        (XReserveBurnNote::script_root(), NoteCost::of::<XReserveBurnNote>()),
        (
            XReserveSetAttesterNote::script_root(),
            NoteCost::of::<XReserveSetAttesterNote>(),
        ),
    ]
}
