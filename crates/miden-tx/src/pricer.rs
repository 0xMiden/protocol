use alloc::vec::Vec;

use miden_agglayer::AgglayerNote;
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::FeeParameters;
use miden_protocol::errors::AssetError;
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::{TransactionFee, TransactionFeeError};
use miden_standards::note::StandardNote;
use miden_standards::note::costs::NoteCost;

// NETWORK NOTE PRICER
// ================================================================================================

/// Error returned by [`NetworkNotePricer`] operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NotePricingError {
    /// The kernel fee computation rejected a note's fee inputs or the resulting fee. The cost
    /// tables never contain out-of-range cycle counts, so a cycle-count error indicates a
    /// broken cost table.
    #[error("cannot compute the fee for a note")]
    Fee(#[source] TransactionFeeError),
    /// The prices accumulated across a note's created notes overflowed u64.
    #[error("accumulated note price overflows u64")]
    PriceOverflow,
    /// The accumulated price exceeds the maximum representable asset amount.
    #[error("accumulated note price exceeds the maximum asset amount")]
    PriceExceedsMaxAssetAmount(#[source] AssetError),
    /// The priced script root has no known consumption cost.
    #[error("no consumption cost is known for note script root {0}")]
    UnknownNoteScriptRoot(NoteScriptRoot),
}

/// The lookup resolving a note script root to its benchmarked consumption cost.
type CostLookupFn = fn(NoteScriptRoot) -> Option<NoteCost>;

/// Resolves a note script root to its benchmarked consumption cost, consulting the standard
/// and agglayer cost tables (their script-root domains are disjoint, so the order is
/// irrelevant).
fn resolve_note_cost(root: NoteScriptRoot) -> Option<NoteCost> {
    StandardNote::note_cost(root).or_else(|| AgglayerNote::note_cost(root))
}

/// Prices the consumption of notes by network accounts from their benchmarked cycle costs,
/// e.g. to populate a network account's fee schedule or to size a sponsorship.
///
/// The fee formula lives in [`TransactionFee`]; this pricer adds a safety margin expressed in
/// extra verification cycles on top. The default margin prices a note as-if it consumed at
/// twice its measured cycles.
///
/// The chain's current [`FeeParameters`] provide the verification base fee. Costs are
/// resolved from the standard and agglayer cost tables ([`StandardNote::note_cost`] and
/// [`AgglayerNote::note_cost`]), so both families of notes are priced alike.
///
/// The computed fees are denominated in the chain's fee asset - the asset issued by the fee
/// faucet of the given [`FeeParameters`]. A fee schedule stores bare amounts, so install the
/// fees only into a policy whose
/// [`FeePolicyManager`](miden_standards::account::fees::FeePolicyManager) charges in that same
/// asset; [`Self::fee_parameters`] exposes the parameters for that check.
#[derive(Debug, Clone, bon::Builder)]
pub struct NetworkNotePricer {
    /// The chain's fee parameters, providing the verification base fee.
    fee_parameters: FeeParameters,
    /// Safety margin in verification cycles added on top of the kernel formula.
    #[builder(default = 1)]
    safety_margin_verification_cycles: u32,
    /// The cost lookup resolving note script roots; always `resolve_note_cost`, swapped out
    /// only by tests.
    #[builder(skip = resolve_note_cost)]
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
    /// The fee is computed entirely by [`TransactionFee::compute_fee`] under the pricer's
    /// [`FeeParameters`], with the safety margin folded into the fee inputs
    /// ([`TransactionFee::with_safety_margin`]), so fee terms added to the kernel formula in
    /// the future flow through without changes here.
    pub fn fee(&self, fee_inputs: TransactionFee) -> Result<AssetAmount, NotePricingError> {
        fee_inputs
            .with_safety_margin(self.safety_margin_verification_cycles)
            .compute_fee(&self.fee_parameters)
            .map_err(NotePricingError::Fee)
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
    /// [`miden_standards::note::costs`] module docs). To avoid infinite recursion, a root
    /// already being priced further up the recursion contributes only its own consumption fee:
    /// a partially filled PSWAP is priced for one fill level, and the paybacks of any further
    /// partial fills are not covered.
    pub fn price(&self, root: NoteScriptRoot) -> Result<AssetAmount, NotePricingError> {
        let price = self.price_recursive(root, &mut Vec::new())?;
        AssetAmount::new(price).map_err(NotePricingError::PriceExceedsMaxAssetAmount)
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
        let fee_inputs = TransactionFee::new(cost.cycles()).map_err(NotePricingError::Fee)?;
        let own_fee = self.fee(fee_inputs)?.as_u64();

        if pricing_stack.contains(&root) {
            return Ok(own_fee);
        }

        pricing_stack.push(root);
        let mut total = own_fee;
        for &created in cost.created_notes() {
            let created_price = self.price_recursive(created, pricing_stack)?;
            total = total.checked_add(created_price).ok_or(NotePricingError::PriceOverflow)?;
        }
        pricing_stack.pop();

        Ok(total)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_agglayer::ClaimNote;
    use miden_agglayer::costs::CLAIM_CONSUMPTION_CYCLES;
    use miden_protocol::MAX_TX_EXECUTION_CYCLES;
    use miden_protocol::account::AccountId;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
    use miden_standards::note::SwapNote;
    use miden_standards::note::costs::{
        MINT_CONSUMPTION_CYCLES,
        P2ID_CONSUMPTION_CYCLES,
        SWAP_CONSUMPTION_CYCLES,
    };

    use super::*;

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

    /// Fabricated broken lookup returning a cost above the kernel's maximum cycle count.
    fn oversized_cost_lookup(_root: NoteScriptRoot) -> Option<NoteCost> {
        Some(NoteCost::new(u32::MAX, Vec::new()))
    }

    #[test]
    fn out_of_range_cycle_costs_cannot_be_priced() {
        let root = NoteScriptRoot::from_array([1, 0, 0, 0]);
        for lookup in [zero_cost_lookup as CostLookupFn, oversized_cost_lookup] {
            let broken = custom_pricer(lookup);
            assert!(matches!(broken.price(root), Err(NotePricingError::Fee(_))));
        }
    }

    #[test]
    fn fee_exceeding_max_asset_amount_is_rejected() {
        // The margin saturates the charged verification cycles at u32::MAX; with a u32::MAX
        // base fee the product exceeds `AssetAmount::MAX`.
        assert!(matches!(
            pricer(u32::MAX, u32::MAX).fee(fee_inputs(MAX_TX_EXECUTION_CYCLES)),
            Err(NotePricingError::Fee(_))
        ));
    }

    /// Fabricated lookup where `[1, 0, 0, 0]` creates two notes and `[2, 0, 0, 0]` one;
    /// every note costs `2^16` cycles.
    fn creating_lookup(root: NoteScriptRoot) -> Option<NoteCost> {
        let triple = NoteScriptRoot::from_array([1, 0, 0, 0]);
        let double = NoteScriptRoot::from_array([2, 0, 0, 0]);
        let leaf = NoteScriptRoot::from_array([3, 0, 0, 0]);
        if root == triple {
            Some(NoteCost::new(1 << 16, vec![double, leaf]))
        } else if root == double {
            Some(NoteCost::new(1 << 16, vec![leaf]))
        } else {
            Some(NoteCost::new(1 << 16, Vec::new()))
        }
    }

    /// Builds a pricer whose every fee lands exactly at `AssetAmount::MAX`: a `2^16`-cycle
    /// cost is charged `17` formula cycles plus the margin, and
    /// `u32::MAX * 2^31 = AssetAmount::MAX`.
    fn max_fee_pricer() -> NetworkNotePricer {
        NetworkNotePricer {
            fee_parameters: fee_parameters(u32::MAX),
            safety_margin_verification_cycles: (1 << 31) - 17,
            lookup: creating_lookup,
        }
    }

    #[test]
    fn overflowing_accumulated_price_is_rejected() {
        // Three maximal fees (the note and its two created notes) overflow u64.
        assert!(matches!(
            max_fee_pricer().price(NoteScriptRoot::from_array([1, 0, 0, 0])),
            Err(NotePricingError::PriceOverflow)
        ));
    }

    #[test]
    fn accumulated_price_above_max_asset_amount_is_rejected() {
        // Two maximal fees fit in a u64 but exceed `AssetAmount::MAX`.
        assert!(matches!(
            max_fee_pricer().price(NoteScriptRoot::from_array([2, 0, 0, 0])),
            Err(NotePricingError::PriceExceedsMaxAssetAmount(_))
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

    /// Builds a pricer over a fabricated lookup; only tests can bypass the built-in cost
    /// resolution.
    fn custom_pricer(lookup: CostLookupFn) -> NetworkNotePricer {
        NetworkNotePricer {
            fee_parameters: fee_parameters(500),
            safety_margin_verification_cycles: 0,
            lookup,
        }
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

    /// The built-in lookup resolves standard notes: a SWAP prices as its own fee plus the
    /// P2ID payback leg.
    #[test]
    fn swap_price_includes_the_p2id_payback_leg() {
        let pricer = pricer(500, 0);
        let p2id_fee = pricer.fee(fee_inputs(P2ID_CONSUMPTION_CYCLES)).unwrap().as_u64();
        let swap_fee = pricer.fee(fee_inputs(SWAP_CONSUMPTION_CYCLES)).unwrap().as_u64();
        assert_eq!(pricer.price(SwapNote::script_root()).unwrap().as_u64(), swap_fee + p2id_fee);
    }

    /// The built-in lookup resolves agglayer notes: a CLAIM's price covers the whole chain it
    /// triggers - CLAIM + MINT + P2ID.
    #[test]
    fn claim_price_includes_the_mint_and_p2id_legs() {
        let pricer = pricer(500, 0);
        let expected = pricer.fee(fee_inputs(CLAIM_CONSUMPTION_CYCLES)).unwrap().as_u64()
            + pricer.fee(fee_inputs(MINT_CONSUMPTION_CYCLES)).unwrap().as_u64()
            + pricer.fee(fee_inputs(P2ID_CONSUMPTION_CYCLES)).unwrap().as_u64();
        assert_eq!(pricer.price(ClaimNote::script_root()).unwrap().as_u64(), expected);
    }
}
