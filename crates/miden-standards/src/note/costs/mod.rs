//! Benchmarked consumption costs of the standard notes, and helpers turning them into fees.
//!
//! Each constant is the number of VM cycles of the canonical network-account transaction
//! consuming the note, measured by the `bench-transaction` binary: an account authenticated
//! with [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount) (carrying the
//! components the note requires) consumes the note on a fee-charging chain, so the measured
//! cycles include the allowlist checks and TX_FEE note creation.
//!
//! The values are denominated in cycles rather than fee units, since the fee
//! (`verification_base_fee * (ilog2(cycles) + 1)`) depends on a block-header parameter. Use
//! the `NetworkNotePricer` in `miden-tx` to turn cycle costs into concrete fees and populate a
//! fee schedule via
//! [`BasicConstantFeePolicy::with_fees`](crate::account::fees::BasicConstantFeePolicy::with_fees).
//!
//! The values are estimates from canonical scenarios, not worst cases: asset-scaling paths
//! carry 16 callback-free assets (the maximum per note) and action notes run one selector, so
//! callback-carrying notes can exceed the values - do not treat them as guaranteed fee upper
//! bounds.
//!
//! Terminology: a note's *cost* is its measured cycle count; its *price* is the fee derived
//! from that cost (and from the costs of the notes its consumption creates).
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when a checked-in value drifts more than 5% from the measured
//! one (small drift from unrelated changes is tolerated - the pricing safety margin dwarfs
//! it).

use alloc::vec::Vec;

use miden_protocol::note::NoteScriptRoot;

use crate::note::config::{
    AllowlistConfigNote,
    BlocklistConfigNote,
    ConstantFeePolicyConfigNote,
    FaucetMetadataConfigNote,
    FaucetPolicyConfigNote,
    MinBurnAmountConfigNote,
    NetworkAccountConfigNote,
    OwnerConfigNote,
    PauseConfigNote,
    RbacConfigNote,
};
use crate::note::{
    BurnNote,
    FeeSponsorshipNote,
    MintNote,
    P2idNote,
    P2ideNote,
    PswapNote,
    StandardNote,
    SwapNote,
};

mod table;
pub use table::*;

// NOTE CONSUMPTION COST
// ================================================================================================

/// Benchmarked consumption cost of a note when consumed by a network account.
///
/// Implemented by every priced note type in `miden-standards` and `miden-agglayer`; the values
/// come from the generated cost tables (see the module docs).
pub trait NoteConsumptionCost {
    /// Cycles of the canonical network-account transaction consuming this note
    /// (maximum across the benchmarked execution paths - an estimate, not a worst case).
    fn consumption_cycles() -> u32;

    /// Script roots of all the notes this note's consumption is expected to create.
    ///
    /// Where a note's outputs are chosen by its creator rather than fixed by the script (e.g. a
    /// MINT note's recipient digest may encode any script), the list covers the typical case.
    fn created_notes() -> Vec<NoteScriptRoot> {
        Vec::new()
    }
}

// NOTE COST
// ================================================================================================

/// A note's benchmarked consumption cost together with the notes its consumption creates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteCost {
    cycles: u32,
    created_notes: Vec<NoteScriptRoot>,
}

impl NoteCost {
    /// Returns a new [`NoteCost`] from a note's consumption cycles and the script roots of the
    /// notes its consumption creates.
    pub fn new(cycles: u32, created_notes: Vec<NoteScriptRoot>) -> Self {
        Self { cycles, created_notes }
    }

    /// Returns a [`NoteCost`] read from the given note type's [`NoteConsumptionCost`] impl.
    pub fn of<N: NoteConsumptionCost>() -> Self {
        Self::new(N::consumption_cycles(), N::created_notes())
    }

    /// Cycles of the canonical network-account transaction consuming the note (maximum across
    /// the benchmarked execution paths - an estimate, not a worst case).
    pub fn cycles(&self) -> u32 {
        self.cycles
    }

    /// Script roots of the notes created when the note is consumed.
    pub fn created_notes(&self) -> &[NoteScriptRoot] {
        &self.created_notes
    }
}

impl StandardNote {
    /// Returns the benchmarked consumption cost of the standard note with the given script
    /// root, or `None` if the root does not match a priced standard note.
    ///
    /// TX_FEE is not priced: it is consumed by fee-collecting operators, not by network
    /// accounts.
    pub fn note_cost(root: NoteScriptRoot) -> Option<NoteCost> {
        match StandardNote::from_script_root(root)? {
            StandardNote::P2ID => Some(NoteCost::of::<P2idNote>()),
            StandardNote::P2IDE => Some(NoteCost::of::<P2ideNote>()),
            StandardNote::SWAP => Some(NoteCost::of::<SwapNote>()),
            StandardNote::PSWAP => Some(NoteCost::of::<PswapNote>()),
            StandardNote::MINT => Some(NoteCost::of::<MintNote>()),
            StandardNote::BURN => Some(NoteCost::of::<BurnNote>()),
            StandardNote::CONSTANT_FEE_POLICY_CONFIG => {
                Some(NoteCost::of::<ConstantFeePolicyConfigNote>())
            },
            StandardNote::FAUCET_POLICY_CONFIG => Some(NoteCost::of::<FaucetPolicyConfigNote>()),
            StandardNote::FAUCET_METADATA_CONFIG => {
                Some(NoteCost::of::<FaucetMetadataConfigNote>())
            },
            StandardNote::MIN_BURN_AMOUNT_CONFIG => Some(NoteCost::of::<MinBurnAmountConfigNote>()),
            StandardNote::ALLOWLIST_CONFIG => Some(NoteCost::of::<AllowlistConfigNote>()),
            StandardNote::BLOCKLIST_CONFIG => Some(NoteCost::of::<BlocklistConfigNote>()),
            StandardNote::PAUSE_CONFIG => Some(NoteCost::of::<PauseConfigNote>()),
            StandardNote::OWNER_CONFIG => Some(NoteCost::of::<OwnerConfigNote>()),
            StandardNote::RBAC_CONFIG => Some(NoteCost::of::<RbacConfigNote>()),
            StandardNote::NETWORK_ACCOUNT_CONFIG => {
                Some(NoteCost::of::<NetworkAccountConfigNote>())
            },
            StandardNote::FEE_SPONSORSHIP => Some(NoteCost::of::<FeeSponsorshipNote>()),
            StandardNote::TX_FEE => None,
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::TxFeeNote;

    /// Pins each priced standard note's cost to its own table constant: a swap between two
    /// note types' impls could otherwise hide inside the bench snapshot tests' 5% drift
    /// tolerance (several constants differ by less than that).
    #[test]
    fn note_cost_pins_every_priced_standard_note_to_its_table_constant() {
        for (root, expected_cycles) in [
            (P2idNote::script_root(), P2ID_CONSUMPTION_CYCLES),
            (P2ideNote::script_root(), P2IDE_CONSUMPTION_CYCLES),
            (SwapNote::script_root(), SWAP_CONSUMPTION_CYCLES),
            (PswapNote::script_root(), PSWAP_CONSUMPTION_CYCLES),
            (MintNote::script_root(), MINT_CONSUMPTION_CYCLES),
            (BurnNote::script_root(), BURN_CONSUMPTION_CYCLES),
            (
                ConstantFeePolicyConfigNote::script_root(),
                CONSTANT_FEE_POLICY_CONFIG_CONSUMPTION_CYCLES,
            ),
            (FaucetPolicyConfigNote::script_root(), FAUCET_POLICY_CONFIG_CONSUMPTION_CYCLES),
            (
                FaucetMetadataConfigNote::script_root(),
                FAUCET_METADATA_CONFIG_CONSUMPTION_CYCLES,
            ),
            (
                MinBurnAmountConfigNote::script_root(),
                MIN_BURN_AMOUNT_CONFIG_CONSUMPTION_CYCLES,
            ),
            (AllowlistConfigNote::script_root(), ALLOWLIST_CONFIG_CONSUMPTION_CYCLES),
            (BlocklistConfigNote::script_root(), BLOCKLIST_CONFIG_CONSUMPTION_CYCLES),
            (PauseConfigNote::script_root(), PAUSE_CONFIG_CONSUMPTION_CYCLES),
            (OwnerConfigNote::script_root(), OWNER_CONFIG_CONSUMPTION_CYCLES),
            (RbacConfigNote::script_root(), RBAC_CONFIG_CONSUMPTION_CYCLES),
            (
                NetworkAccountConfigNote::script_root(),
                NETWORK_ACCOUNT_CONFIG_CONSUMPTION_CYCLES,
            ),
            (FeeSponsorshipNote::script_root(), FEE_SPONSORSHIP_CONSUMPTION_CYCLES),
        ] {
            let cost = StandardNote::note_cost(root).expect("standard note should have a cost");
            assert_eq!(cost.cycles(), expected_cycles);
        }

        assert!(StandardNote::note_cost(TxFeeNote::script_root()).is_none());
    }
}
