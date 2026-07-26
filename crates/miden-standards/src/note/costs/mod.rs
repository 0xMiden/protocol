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
//! [`NetworkNotePricer`] to turn cycle costs into concrete [`AssetAmount`] fees and populate a
//! fee schedule via
//! [`BasicConstantFeePolicy::with_fees`](crate::account::fees::BasicConstantFeePolicy::with_fees).
//!
//! The values are estimates from canonical scenarios, not worst cases: asset-scaling paths
//! carry 16 callback-free assets (the P2ID/P2IDE cap planned in
//! <https://github.com/0xMiden/protocol/issues/3381>) and action notes run one selector, so
//! callback-carrying or maximally packed notes can exceed the values - do not treat them as
//! guaranteed fee upper bounds.
//!
//! Terminology: a note's *cost* is its measured cycle count; its *price* is the fee derived
//! from that cost (and from the costs of the notes its consumption creates).
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when a checked-in value drifts more than 5% from the measured
//! one (small drift from unrelated changes is tolerated - the pricing safety margin dwarfs
//! it).

use alloc::vec::Vec;

use miden_protocol::asset::AssetAmount;
use miden_protocol::block::FeeParameters;
use miden_protocol::errors::AssetError;
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::TransactionFee;

use crate::note::{
    BurnNote,
    FaucetPolicyActionNote,
    FeeSponsorshipNote,
    MintNote,
    NetworkAccountConfigNote,
    OwnerActionNote,
    P2idNote,
    P2ideNote,
    PauseActionNote,
    PswapNote,
    RbacActionNote,
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
            StandardNote::FAUCET_POLICY_ACTION => Some(NoteCost::of::<FaucetPolicyActionNote>()),
            StandardNote::PAUSE_ACTION => Some(NoteCost::of::<PauseActionNote>()),
            StandardNote::OWNER_ACTION => Some(NoteCost::of::<OwnerActionNote>()),
            StandardNote::RBAC_ACTION => Some(NoteCost::of::<RbacActionNote>()),
            StandardNote::NETWORK_ACCOUNT_CONFIG => {
                Some(NoteCost::of::<NetworkAccountConfigNote>())
            },
            StandardNote::FEE_SPONSORSHIP => Some(NoteCost::of::<FeeSponsorshipNote>()),
            StandardNote::TX_FEE => None,
        }
    }
}

// NETWORK NOTE PRICER
// ================================================================================================

/// Error returned by [`NetworkNotePricer`] operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NotePricingError {
    /// A note cost of zero cycles was priced; the cost tables never contain zero, so this
    /// indicates a broken custom lookup.
    #[error("cannot price a note with zero consumption cycles")]
    ZeroCycles,
    /// The computed fee overflowed during accumulation.
    #[error("computed fee overflows u64")]
    FeeOverflow,
    /// The computed fee exceeds the maximum representable asset amount.
    #[error("computed fee exceeds the maximum asset amount")]
    FeeExceedsMaxAssetAmount(#[source] AssetError),
    /// The priced script root has no known consumption cost.
    #[error("no consumption cost is known for note script root {0}")]
    UnknownNoteScriptRoot(NoteScriptRoot),
}

/// The lookup resolving a note script root to its benchmarked consumption cost.
pub type CostLookupFn = fn(NoteScriptRoot) -> Option<NoteCost>;

/// Prices the consumption of notes by network accounts from their benchmarked cycle costs,
/// e.g. to populate a network account's fee schedule or to size a sponsorship.
///
/// The fee formula lives in [`TransactionFee`] (the Rust mirror of the transaction kernel's
/// `compute_fee`); this pricer adds a safety margin expressed in extra verification cycles on
/// top. The default margin of one (verification cycle) prices a note as-if it consumed at
/// twice its measured cycles.
///
/// The chain's current [`FeeParameters`] provide the verification base fee. The cost lookup
/// resolves script roots to their benchmarked costs and defaults to the standard-note lookup
/// ([`StandardNote::note_cost`]); build the `NetworkNotePricer` with
/// `miden_agglayer::AgglayerNote::note_cost` to price agglayer and standard notes through the
/// same pricer.
///
/// The computed fees are denominated in the chain's fee asset - the asset issued by the fee
/// faucet of the given [`FeeParameters`]. A fee schedule stores bare amounts, so install the
/// fees only into a policy whose
/// [`FeePolicyManager`](crate::account::fees::FeePolicyManager) charges in that same asset;
/// [`Self::fee_parameters`] exposes the parameters for that check.
#[derive(Debug, Clone, bon::Builder)]
pub struct NetworkNotePricer {
    /// The chain's fee parameters, providing the verification base fee.
    fee_parameters: FeeParameters,
    /// Safety margin in verification cycles added on top of the kernel formula.
    #[builder(default = 1)]
    safety_margin_verification_cycles: u32,
    /// The cost lookup used to resolve note script roots.
    #[builder(default = StandardNote::note_cost)]
    lookup: CostLookupFn,
}

impl NetworkNotePricer {
    /// Returns the chain fee parameters the pricer computes fees under; the fees are
    /// denominated in the asset of the parameters' fee faucet.
    pub fn fee_parameters(&self) -> &FeeParameters {
        &self.fee_parameters
    }

    /// Returns the fee charged for a network transaction with the given fee inputs, including
    /// the configured safety margin.
    ///
    /// The kernel fee is computed entirely by [`TransactionFee::compute_fee`] under the
    /// pricer's [`FeeParameters`], so fee terms added to the kernel formula in the future flow
    /// through without changes here; the safety margin is charged on top as
    /// `verification_base_fee * safety_margin_verification_cycles`.
    pub fn fee(&self, fee_inputs: TransactionFee) -> Result<AssetAmount, NotePricingError> {
        let fee = self.fee_raw(fee_inputs)?;
        AssetAmount::new(fee).map_err(NotePricingError::FeeExceedsMaxAssetAmount)
    }

    /// Prices the consumption by a network account of the note with the given script root.
    ///
    /// The price of a note is the fee for its own consumption plus the prices of the notes its
    /// consumption creates:
    ///
    /// ```text
    /// price(N) = fee(cycles(N)) + sum(price(M) for M created by consuming N)
    /// ```
    ///
    /// Since a script root alone cannot tell whether a created note will be network-targeted,
    /// EVERY created note is priced in, suiting root-keyed fee schedules - though like the
    /// underlying costs, the result is an estimate, not a guaranteed upper bound (see the
    /// module docs). To avoid infinite recursion, a root already being priced further up the
    /// recursion contributes only its own consumption fee: a partially filled PSWAP is priced
    /// for one fill level, and the paybacks of any further partial fills are not covered.
    pub fn price(&self, root: NoteScriptRoot) -> Result<AssetAmount, NotePricingError> {
        let fee = self.price_recursive(root, &mut Vec::new())?;
        AssetAmount::new(fee).map_err(NotePricingError::FeeExceedsMaxAssetAmount)
    }

    /// Returns the fee for the given fee inputs as a raw `u64`.
    fn fee_raw(&self, fee_inputs: TransactionFee) -> Result<u64, NotePricingError> {
        let kernel_fee = fee_inputs.compute_fee(&self.fee_parameters).as_u64();
        // A u32 * u32 product widened to u64 cannot overflow; the sum with the kernel fee can.
        let margin_fee = u64::from(self.fee_parameters.verification_base_fee())
            * u64::from(self.safety_margin_verification_cycles);
        kernel_fee.checked_add(margin_fee).ok_or(NotePricingError::FeeOverflow)
    }

    /// Computes the recursive price of `root` as a raw `u64`, tracking the roots currently
    /// being priced to cut off self-recursion.
    fn price_recursive(
        &self,
        root: NoteScriptRoot,
        pricing_stack: &mut Vec<NoteScriptRoot>,
    ) -> Result<u64, NotePricingError> {
        let cost = (self.lookup)(root).ok_or(NotePricingError::UnknownNoteScriptRoot(root))?;
        // Cycle counts enter the fee computation only here, where the looked-up cost is
        // converted into the kernel's fee inputs.
        let fee_inputs = TransactionFee::new(cost.cycles())
            .map_err(|_zero_cycles| NotePricingError::ZeroCycles)?;
        let own_fee = self.fee_raw(fee_inputs)?;

        if pricing_stack.contains(&root) {
            return Ok(own_fee);
        }

        pricing_stack.push(root);
        let mut total = own_fee;
        for &created in cost.created_notes() {
            let created_price = self.price_recursive(created, pricing_stack)?;
            total = total.checked_add(created_price).ok_or(NotePricingError::FeeOverflow)?;
        }
        pricing_stack.pop();

        Ok(total)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountId;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    use super::*;
    use crate::note::TxFeeNote;

    fn fee_parameters(base_fee: u32) -> FeeParameters {
        let fee_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("testing faucet ID should be valid");
        FeeParameters::new(fee_faucet_id, base_fee)
    }

    fn pricer(base_fee: u32, margin: u32) -> NetworkNotePricer {
        NetworkNotePricer::builder()
            .fee_parameters(fee_parameters(base_fee))
            .safety_margin_verification_cycles(margin)
            .build()
    }

    fn fee_inputs(cycles: u32) -> TransactionFee {
        TransactionFee::new(cycles).expect("test cycle counts are non-zero")
    }

    #[test]
    fn fee_implements_the_kernel_formula() {
        let no_margin = pricer(500, 0);

        // ilog2(2^16) = 16 -> 17 verification cycles.
        assert_eq!(no_margin.fee(fee_inputs(1 << 16)).unwrap().as_u64(), 500 * 17);
        // The fee only changes at the next power of two.
        assert_eq!(no_margin.fee(fee_inputs((1 << 17) - 1)).unwrap().as_u64(), 500 * 17);
        assert_eq!(no_margin.fee(fee_inputs(1 << 17)).unwrap().as_u64(), 500 * 18);
        // The smallest non-zero cycle count is charged one verification cycle.
        assert_eq!(no_margin.fee(fee_inputs(1)).unwrap().as_u64(), 500);
    }

    #[test]
    fn default_safety_margin_adds_one_verification_cycle() {
        let default_margin =
            NetworkNotePricer::builder().fee_parameters(fee_parameters(500)).build();
        assert_eq!(default_margin.fee(fee_inputs(1 << 16)).unwrap().as_u64(), 500 * 18);
    }

    /// Fabricated broken lookup returning a zero-cycle cost, which the real tables never
    /// contain.
    fn zero_cost_lookup(_root: NoteScriptRoot) -> Option<NoteCost> {
        Some(NoteCost::new(0, Vec::new()))
    }

    #[test]
    fn zero_cycle_costs_cannot_be_priced() {
        let broken = custom_pricer(zero_cost_lookup);
        let root = NoteScriptRoot::from_array([1, 0, 0, 0]);
        assert!(matches!(broken.price(root), Err(NotePricingError::ZeroCycles)));
    }

    #[test]
    fn overflowing_fee_is_rejected() {
        // The kernel fee (u32::MAX * 32) plus the margin fee (u32::MAX * u32::MAX) overflows a
        // u64.
        assert!(matches!(
            pricer(u32::MAX, u32::MAX).fee(fee_inputs(u32::MAX)),
            Err(NotePricingError::FeeOverflow)
        ));
    }

    /// Fabricated lookup: `[1, 0, 0, 0]` creates `[2, 0, 0, 0]`; the child creates nothing.
    fn parent_child_lookup(root: NoteScriptRoot) -> Option<NoteCost> {
        let parent = NoteScriptRoot::from_array([1, 0, 0, 0]);
        let child = NoteScriptRoot::from_array([2, 0, 0, 0]);
        if root == parent {
            Some(NoteCost::new(1 << 16, vec![child]))
        } else if root == child {
            Some(NoteCost::new(1 << 10, Vec::new()))
        } else {
            None
        }
    }

    /// Fabricated lookup mirroring PSWAP: `[1, 0, 0, 0]` re-creates itself besides the child.
    fn self_recursive_lookup(root: NoteScriptRoot) -> Option<NoteCost> {
        let selfish = NoteScriptRoot::from_array([1, 0, 0, 0]);
        let child = NoteScriptRoot::from_array([2, 0, 0, 0]);
        if root == selfish {
            Some(NoteCost::new(1 << 16, vec![child, selfish]))
        } else if root == child {
            Some(NoteCost::new(1 << 10, Vec::new()))
        } else {
            None
        }
    }

    fn custom_pricer(lookup: CostLookupFn) -> NetworkNotePricer {
        NetworkNotePricer::builder()
            .fee_parameters(fee_parameters(500))
            .safety_margin_verification_cycles(0)
            .lookup(lookup)
            .build()
    }

    #[test]
    fn price_includes_created_notes() {
        let parent = NoteScriptRoot::from_array([1, 0, 0, 0]);
        let expected = 500 * 17 + 500 * 11;
        assert_eq!(custom_pricer(parent_child_lookup).price(parent).unwrap().as_u64(), expected);
    }

    #[test]
    fn self_recursive_notes_are_priced_at_one_level_of_nesting() {
        let selfish = NoteScriptRoot::from_array([1, 0, 0, 0]);
        // Own fee + child fee + own fee again (the nested self-reference, cut off there).
        let expected = 500 * 17 + 500 * 11 + 500 * 17;
        assert_eq!(custom_pricer(self_recursive_lookup).price(selfish).unwrap().as_u64(), expected);
    }

    #[test]
    fn unknown_roots_cannot_be_priced() {
        let unknown = NoteScriptRoot::from_array([9, 9, 9, 9]);
        assert!(matches!(
            pricer(500, 0).price(unknown),
            Err(NotePricingError::UnknownNoteScriptRoot(root)) if root == unknown
        ));
    }

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
            (FaucetPolicyActionNote::script_root(), FAUCET_POLICY_ACTION_CONSUMPTION_CYCLES),
            (PauseActionNote::script_root(), PAUSE_ACTION_CONSUMPTION_CYCLES),
            (OwnerActionNote::script_root(), OWNER_ACTION_CONSUMPTION_CYCLES),
            (RbacActionNote::script_root(), RBAC_ACTION_CONSUMPTION_CYCLES),
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

    #[test]
    fn swap_price_includes_the_p2id_payback_leg() {
        let pricer = pricer(500, 0);
        let p2id_fee = pricer.fee(fee_inputs(P2ID_CONSUMPTION_CYCLES)).unwrap().as_u64();
        let swap_fee = pricer.fee(fee_inputs(SWAP_CONSUMPTION_CYCLES)).unwrap().as_u64();
        assert_eq!(pricer.price(SwapNote::script_root()).unwrap().as_u64(), swap_fee + p2id_fee);
    }
}
