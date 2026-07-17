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
//! [`NotePricer`] to turn cycle costs into concrete [`AssetAmount`] fees and populate a fee
//! schedule via
//! [`ConstantFeePolicy::with_fees`](crate::account::fees::ConstantFeePolicy::with_fees).
//!
//! The values are estimates from canonical scenarios, not worst cases: asset-scaling paths
//! carry 16 callback-free assets (the P2ID/P2IDE cap planned in
//! <https://github.com/0xMiden/protocol/issues/3381>) and action notes run one selector, so
//! callback-carrying or maximally packed notes can exceed the values - do not treat them as
//! guaranteed fee upper bounds.
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when a checked-in value drifts more than 5% from the measured
//! one (small drift from unrelated changes is tolerated - the pricing safety margin dwarfs
//! it).

use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::asset::AssetAmount;
use miden_protocol::errors::AssetError;
use miden_protocol::note::NoteScriptRoot;

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
    /// Worst-case cycles of the canonical network-account transaction consuming this note
    /// (maximum across the benchmarked execution paths).
    fn consumption_cycles() -> u64;

    /// Script roots of the notes created when this note is consumed, conservatively assuming
    /// every created note targets a network account.
    ///
    /// The TX_FEE note created by fee payment is excluded: its creation is part of the measured
    /// consumption cycles and it is not consumed by a network account.
    fn created_network_notes() -> Vec<NoteScriptRoot> {
        Vec::new()
    }
}

impl NoteConsumptionCost for P2idNote {
    fn consumption_cycles() -> u64 {
        P2ID_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for P2ideNote {
    fn consumption_cycles() -> u64 {
        P2IDE_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for SwapNote {
    fn consumption_cycles() -> u64 {
        SWAP_CONSUMPTION_CYCLES
    }

    /// Filling a SWAP note creates the P2ID payback note for the swap creator.
    fn created_network_notes() -> Vec<NoteScriptRoot> {
        vec![P2idNote::script_root()]
    }
}

impl NoteConsumptionCost for PswapNote {
    fn consumption_cycles() -> u64 {
        PSWAP_CONSUMPTION_CYCLES
    }

    /// Filling a PSWAP note creates the P2ID payback note for the swap creator and, on a
    /// partial fill, the residual PSWAP note carrying the unfilled remainder.
    fn created_network_notes() -> Vec<NoteScriptRoot> {
        vec![P2idNote::script_root(), PswapNote::script_root()]
    }
}

impl NoteConsumptionCost for MintNote {
    fn consumption_cycles() -> u64 {
        MINT_CONSUMPTION_CYCLES
    }

    /// Consuming a MINT note creates the P2ID note delivering the minted asset.
    fn created_network_notes() -> Vec<NoteScriptRoot> {
        vec![P2idNote::script_root()]
    }
}

impl NoteConsumptionCost for BurnNote {
    fn consumption_cycles() -> u64 {
        BURN_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for FaucetPolicyActionNote {
    fn consumption_cycles() -> u64 {
        FAUCET_POLICY_ACTION_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for PauseActionNote {
    fn consumption_cycles() -> u64 {
        PAUSE_ACTION_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for OwnerActionNote {
    fn consumption_cycles() -> u64 {
        OWNER_ACTION_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for RbacActionNote {
    fn consumption_cycles() -> u64 {
        RBAC_ACTION_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for NetworkAccountConfigNote {
    fn consumption_cycles() -> u64 {
        NETWORK_ACCOUNT_CONFIG_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for FeeSponsorshipNote {
    fn consumption_cycles() -> u64 {
        FEE_SPONSORSHIP_CONSUMPTION_CYCLES
    }
}

// NOTE COST
// ================================================================================================

/// A note's benchmarked consumption cost together with the notes its consumption creates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteCost {
    cycles: u64,
    created_network_notes: Vec<NoteScriptRoot>,
}

impl NoteCost {
    /// Returns a new [`NoteCost`] from a note's consumption cycles and the script roots of the
    /// network notes its consumption creates.
    pub fn new(cycles: u64, created_network_notes: Vec<NoteScriptRoot>) -> Self {
        Self { cycles, created_network_notes }
    }

    /// Returns a [`NoteCost`] read from the given note type's [`NoteConsumptionCost`] impl.
    pub fn of<N: NoteConsumptionCost>() -> Self {
        Self::new(N::consumption_cycles(), N::created_network_notes())
    }

    /// Worst-case cycles of the canonical network-account transaction consuming the note.
    pub fn cycles(&self) -> u64 {
        self.cycles
    }

    /// Script roots of the network notes created when the note is consumed.
    pub fn created_network_notes(&self) -> &[NoteScriptRoot] {
        &self.created_network_notes
    }
}

/// Returns the benchmarked consumption cost of the standard note with the given script root, or
/// `None` if the root does not match a priced standard note.
///
/// TX_FEE is not priced: it is consumed by fee-collecting operators, not by network accounts.
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
        StandardNote::FEE_SPONSORSHIP => Some(NoteCost::of::<FeeSponsorshipNote>()),
        StandardNote::NETWORK_ACCOUNT_CONFIG => Some(NoteCost::of::<NetworkAccountConfigNote>()),
        StandardNote::TX_FEE => None,
    }
}

// NOTE PRICER
// ================================================================================================

/// Error returned by [`NotePricer`] operations.
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

/// Converts benchmarked note-consumption cycle counts into concrete fees.
///
/// Implements the kernel fee formula `verification_base_fee * (ilog2(cycles) + 1)` (see the
/// transaction kernel's `compute_fee`, whose `+ 1` is unconditional - the testing-crate
/// `TransactionFee` mirror rounds differently at exact powers of two) plus a safety margin
/// expressed in extra verification cycles. The default margin of one verification cycle prices
/// a note as if it consumed twice its measured cycles, absorbing moderate cost growth between
/// benchmark regenerations at the price of a small fee increase.
///
/// The `verification_base_fee` should come from the chain's current
/// [`FeeParameters`](miden_protocol::block::FeeParameters).
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct NotePricer {
    /// The chain's verification base fee.
    verification_base_fee: u32,
    /// Safety margin in verification cycles added on top of the kernel formula.
    #[builder(default = 1)]
    safety_margin_verification_cycles: u32,
}

impl NotePricer {
    /// Returns the fee charged for a transaction of the given cycle count, including the
    /// configured safety margin.
    pub fn fee_for_cycles(&self, cycles: u64) -> Result<AssetAmount, NotePricingError> {
        let fee = self.fee_for_cycles_raw(cycles)?;
        AssetAmount::new(fee).map_err(NotePricingError::FeeExceedsMaxAssetAmount)
    }

    /// Prices the note with the given script root using the standard-note cost lookup
    /// ([`note_cost`]).
    ///
    /// See [`Self::price_with`] for the pricing rule.
    pub fn price(&self, root: NoteScriptRoot) -> Result<AssetAmount, NotePricingError> {
        self.price_with(root, &note_cost)
    }

    /// Prices the note with the given script root using a custom cost lookup (e.g.
    /// `miden_agglayer::costs::note_cost` for a lookup that also resolves agglayer notes).
    ///
    /// The price of a note is the fee for its own consumption plus the prices of the network
    /// notes its consumption creates:
    ///
    /// ```text
    /// price(N) = fee_for_cycles(cycles(N)) + sum(price(M) for M created by consuming N)
    /// ```
    ///
    /// A root that is already being priced further up the recursion contributes its own
    /// consumption fee only (a PSWAP partial fill re-creates a PSWAP note, which would
    /// otherwise recurse forever).
    pub fn price_with(
        &self,
        root: NoteScriptRoot,
        lookup: &dyn Fn(NoteScriptRoot) -> Option<NoteCost>,
    ) -> Result<AssetAmount, NotePricingError> {
        let fee = self.price_recursive(root, lookup, &mut Vec::new())?;
        AssetAmount::new(fee).map_err(NotePricingError::FeeExceedsMaxAssetAmount)
    }

    /// Returns the fee for the given cycle count as a raw `u64`.
    fn fee_for_cycles_raw(&self, cycles: u64) -> Result<u64, NotePricingError> {
        if cycles == 0 {
            return Err(NotePricingError::ZeroCycles);
        }
        // ilog2(cycles) is at most 63 and the margin at most u32::MAX, so the addition cannot
        // overflow a u64.
        let verification_cycles =
            u64::from(cycles.ilog2()) + 1 + u64::from(self.safety_margin_verification_cycles);
        u64::from(self.verification_base_fee)
            .checked_mul(verification_cycles)
            .ok_or(NotePricingError::FeeOverflow)
    }

    /// Computes the recursive price of `root` as a raw `u64`, tracking the roots currently
    /// being priced to cut off self-recursion.
    fn price_recursive(
        &self,
        root: NoteScriptRoot,
        lookup: &dyn Fn(NoteScriptRoot) -> Option<NoteCost>,
        pricing_stack: &mut Vec<NoteScriptRoot>,
    ) -> Result<u64, NotePricingError> {
        let cost = lookup(root).ok_or(NotePricingError::UnknownNoteScriptRoot(root))?;
        let own_fee = self.fee_for_cycles_raw(cost.cycles())?;

        if pricing_stack.contains(&root) {
            return Ok(own_fee);
        }

        pricing_stack.push(root);
        let mut total = own_fee;
        for &created in cost.created_network_notes() {
            let created_price = self.price_recursive(created, lookup, pricing_stack)?;
            total = total.checked_add(created_price).ok_or(NotePricingError::FeeOverflow)?;
        }
        pricing_stack.pop();

        Ok(total)
    }
}

/// Computes the fee-schedule entries for all priced standard notes, e.g. to populate a
/// [`ConstantFeePolicy`](crate::account::fees::ConstantFeePolicy) via its `with_fees` method.
pub fn standard_note_prices(
    pricer: &NotePricer,
) -> Result<Vec<(NoteScriptRoot, AssetAmount)>, NotePricingError> {
    [
        P2idNote::script_root(),
        P2ideNote::script_root(),
        SwapNote::script_root(),
        PswapNote::script_root(),
        MintNote::script_root(),
        BurnNote::script_root(),
        FaucetPolicyActionNote::script_root(),
        PauseActionNote::script_root(),
        OwnerActionNote::script_root(),
        RbacActionNote::script_root(),
        FeeSponsorshipNote::script_root(),
    ]
    .into_iter()
    .map(|root| Ok((root, pricer.price(root)?)))
    .collect()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::TxFeeNote;

    fn pricer(base_fee: u32, margin: u32) -> NotePricer {
        NotePricer::builder()
            .verification_base_fee(base_fee)
            .safety_margin_verification_cycles(margin)
            .build()
    }

    #[test]
    fn fee_for_cycles_implements_the_kernel_formula() {
        let no_margin = pricer(500, 0);

        // ilog2(2^16) = 16 -> 17 verification cycles.
        assert_eq!(no_margin.fee_for_cycles(1 << 16).unwrap().as_u64(), 500 * 17);
        // The fee only changes at the next power of two.
        assert_eq!(no_margin.fee_for_cycles((1 << 17) - 1).unwrap().as_u64(), 500 * 17);
        assert_eq!(no_margin.fee_for_cycles(1 << 17).unwrap().as_u64(), 500 * 18);
        // The smallest non-zero cycle count is charged one verification cycle.
        assert_eq!(no_margin.fee_for_cycles(1).unwrap().as_u64(), 500);
    }

    #[test]
    fn default_safety_margin_adds_one_verification_cycle() {
        let default_margin = NotePricer::builder().verification_base_fee(500).build();
        assert_eq!(default_margin.fee_for_cycles(1 << 16).unwrap().as_u64(), 500 * 18);
    }

    #[test]
    fn zero_cycles_cannot_be_priced() {
        assert!(matches!(pricer(500, 0).fee_for_cycles(0), Err(NotePricingError::ZeroCycles)));
    }

    #[test]
    fn overflowing_fee_is_rejected() {
        // u32::MAX * (63 + 1 + u32::MAX) overflows a u64.
        assert!(matches!(
            pricer(u32::MAX, u32::MAX).fee_for_cycles(u64::MAX),
            Err(NotePricingError::FeeOverflow)
        ));
    }

    #[test]
    fn price_includes_created_network_notes() {
        let parent = NoteScriptRoot::from_array([1, 0, 0, 0]);
        let child = NoteScriptRoot::from_array([2, 0, 0, 0]);
        let lookup = move |root: NoteScriptRoot| -> Option<NoteCost> {
            if root == parent {
                Some(NoteCost::new(1 << 16, vec![child]))
            } else if root == child {
                Some(NoteCost::new(1 << 10, Vec::new()))
            } else {
                None
            }
        };

        let pricer = pricer(500, 0);
        let expected = 500 * 17 + 500 * 11;
        assert_eq!(pricer.price_with(parent, &lookup).unwrap().as_u64(), expected);
    }

    #[test]
    fn self_recursive_notes_are_priced_at_one_level_of_nesting() {
        // Mirrors PSWAP: consuming the note re-creates a note with the same script root.
        let selfish = NoteScriptRoot::from_array([1, 0, 0, 0]);
        let child = NoteScriptRoot::from_array([2, 0, 0, 0]);
        let lookup = move |root: NoteScriptRoot| -> Option<NoteCost> {
            if root == selfish {
                Some(NoteCost::new(1 << 16, vec![child, selfish]))
            } else if root == child {
                Some(NoteCost::new(1 << 10, Vec::new()))
            } else {
                None
            }
        };

        let pricer = pricer(500, 0);
        // Own fee + child fee + own fee again (the nested self-reference, cut off there).
        let expected = 500 * 17 + 500 * 11 + 500 * 17;
        assert_eq!(pricer.price_with(selfish, &lookup).unwrap().as_u64(), expected);
    }

    #[test]
    fn unknown_roots_cannot_be_priced() {
        let unknown = NoteScriptRoot::from_array([9, 9, 9, 9]);
        assert!(matches!(
            pricer(500, 0).price(unknown),
            Err(NotePricingError::UnknownNoteScriptRoot(root)) if root == unknown
        ));
    }

    #[test]
    fn note_cost_resolves_every_priced_standard_note() {
        for root in [
            P2idNote::script_root(),
            P2ideNote::script_root(),
            SwapNote::script_root(),
            PswapNote::script_root(),
            MintNote::script_root(),
            BurnNote::script_root(),
            FaucetPolicyActionNote::script_root(),
            PauseActionNote::script_root(),
            OwnerActionNote::script_root(),
            RbacActionNote::script_root(),
            NetworkAccountConfigNote::script_root(),
            FeeSponsorshipNote::script_root(),
        ] {
            let cost = note_cost(root).expect("standard note should have a cost");
            assert!(cost.cycles() > 0);
        }

        assert!(note_cost(TxFeeNote::script_root()).is_none());
    }

    #[test]
    fn standard_note_prices_cover_all_priced_notes() {
        let prices = standard_note_prices(&pricer(500, 0)).unwrap();
        assert_eq!(prices.len(), 11);
        assert!(prices.iter().all(|(_, price)| price.as_u64() > 0));

        // A SWAP's price includes the P2ID payback leg.
        let price_of = |root: NoteScriptRoot| {
            prices
                .iter()
                .find(|(r, _)| *r == root)
                .map(|(_, price)| price.as_u64())
                .unwrap()
        };
        let pricer = pricer(500, 0);
        let p2id_fee = pricer.fee_for_cycles(P2ID_CONSUMPTION_CYCLES).unwrap().as_u64();
        let swap_fee = pricer.fee_for_cycles(SWAP_CONSUMPTION_CYCLES).unwrap().as_u64();
        assert_eq!(price_of(SwapNote::script_root()), swap_fee + p2id_fee);
    }
}
