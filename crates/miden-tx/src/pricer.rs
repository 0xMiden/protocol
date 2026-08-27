use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_agglayer::AgglayerNote;
use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::block::FeeParameters;
use miden_protocol::errors::AssetError;
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::{TransactionFee, TransactionFeeError};
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::note::costs::NoteCost;
use miden_standards::note::{FeeSponsorshipNote, StandardNote};

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

/// Prices the consumption of notes by network accounts from their benchmarked cycle costs,
/// e.g. to populate a network account's fee schedule or to size a sponsorship.
///
/// The fee formula lives in [`TransactionFee`]; this pricer adds a safety margin expressed in
/// extra verification cycles on top. The default margin prices a note as-if it consumed at
/// twice its measured cycles.
///
/// The chain's current [`FeeParameters`] provide the verification base fee. Costs are
/// resolved from the standard and agglayer cost tables ([`StandardNote::note_cost`] and
/// [`AgglayerNote::note_cost`]), so both families of notes are priced alike. Costs supplied
/// through the builder's `note_costs` take precedence over the tables, letting an account
/// price note families the tables do not know — or a table-known script root whose
/// consumption on that account runs extra code and so measures a different cost.
///
/// [`FeeSponsorshipNote`] defaults to zero because standard network-account fee collection exempts
/// sponsorship notes from sponsoring themselves. A cost supplied through the builder's `note_cost`
/// or `note_costs` methods takes precedence over this default.
///
/// The computed fees are denominated in the given fee asset. A fee schedule stores bare amounts,
/// so install the fees only into a policy whose
/// [`FeePolicyManager`](miden_standards::account::fees::FeePolicyManager) charges in that same
/// asset; [`Self::fee_asset_id`] exposes it for that check.
#[derive(Debug, Clone, bon::Builder)]
pub struct NetworkNotePricer {
    /// Benchmarked costs overriding or extending the built-in tables: a root present here is
    /// priced from this map, shadowing the standard and agglayer cost tables. Populated through
    /// the builder's [`note_cost`](NetworkNotePricerBuilder::note_cost) and
    /// [`note_costs`](NetworkNotePricerBuilder::note_costs) extensions.
    #[builder(field)]
    note_costs: BTreeMap<NoteScriptRoot, NoteCost>,
    /// The chain's fee parameters, providing the verification base fee.
    fee_parameters: FeeParameters,
    /// The chain's fee asset, which the computed fees are denominated in.
    fee_asset_id: AssetId,
    /// Safety margin in verification cycles added on top of the kernel formula.
    #[builder(default = 1)]
    safety_margin_verification_cycles: u32,
}

impl NetworkNotePricer {
    /// Returns the chain fee parameters the pricer computes fees under.
    pub fn fee_parameters(&self) -> &FeeParameters {
        &self.fee_parameters
    }

    /// Returns the asset the computed fees are denominated in.
    pub fn fee_asset_id(&self) -> AssetId {
        self.fee_asset_id
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

    /// Builds a [`BasicConstantFeePolicy`] that prices every supplied note script root through
    /// [`Self::price`].
    ///
    /// The policy's bare fee amounts are denominated in the fee asset configured by
    /// [`Self::fee_asset_id`]. Each root is priced through [`Self::price`], so the fee includes
    /// the default safety margin and the recursively priced notes created by consuming it.
    pub fn basic_constant_fee_policy(
        &self,
        note_script_roots: impl IntoIterator<Item = NoteScriptRoot>,
    ) -> Result<BasicConstantFeePolicy, NotePricingError> {
        let mut policy = BasicConstantFeePolicy::new();
        for root in note_script_roots {
            policy = policy.with_fee(root, self.price(root)?);
        }
        Ok(policy)
    }

    /// Builds a fee policy manager whose active [`BasicConstantFeePolicy`] is generated from the
    /// supplied note script roots.
    ///
    /// The manager charges in the fee asset configured by [`Self::fee_asset_id`], keeping the
    /// policy's bare fee amounts and their denomination together.
    pub fn basic_constant_fee_policy_manager(
        &self,
        note_script_roots: impl IntoIterator<Item = NoteScriptRoot>,
    ) -> Result<FeePolicyManager, NotePricingError> {
        let policy = self.basic_constant_fee_policy(note_script_roots)?;
        Ok(FeePolicyManager::builder()
            .fee_faucet_id(self.fee_asset_id.faucet_id())
            .active_fee_policy(policy.into())
            .build())
    }

    /// Resolves a note script root to its pricing cost. Supplied costs take precedence over the
    /// defaults, `Ok(None)` indicates a recognized note whose default price is zero, and unknown
    /// roots return an error.
    fn resolve_note_cost(
        &self,
        root: NoteScriptRoot,
    ) -> Result<Option<NoteCost>, NotePricingError> {
        if let Some(cost) = self.note_costs.get(&root) {
            return Ok(Some(cost.clone()));
        }
        if root == FeeSponsorshipNote::script_root() {
            return Ok(None);
        }

        StandardNote::note_cost(root)
            .or_else(|| AgglayerNote::note_cost(root))
            .map(Some)
            .ok_or(NotePricingError::UnknownNoteScriptRoot(root))
    }

    /// Computes the recursive price of `root` as a raw `u64`, tracking the roots currently
    /// being priced to cut off self-recursion.
    fn price_recursive(
        &self,
        root: NoteScriptRoot,
        pricing_stack: &mut Vec<NoteScriptRoot>,
    ) -> Result<u64, NotePricingError> {
        let Some(cost) = self.resolve_note_cost(root)? else {
            return Ok(0);
        };
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

// BUILDER EXTENSIONS
// ================================================================================================

impl<S: network_note_pricer_builder::State> NetworkNotePricerBuilder<S> {
    /// Adds a single benchmarked note cost, overriding or extending the built-in tables for the
    /// given script root.
    pub fn note_cost(mut self, root: NoteScriptRoot, cost: NoteCost) -> Self {
        self.note_costs.insert(root, cost);
        self
    }

    /// Adds multiple benchmarked note costs, overriding or extending the built-in tables.
    pub fn note_costs(
        mut self,
        note_costs: impl IntoIterator<Item = (NoteScriptRoot, NoteCost)>,
    ) -> Self {
        self.note_costs.extend(note_costs);
        self
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
    use miden_standards::note::costs::{
        MINT_CONSUMPTION_CYCLES,
        P2ID_CONSUMPTION_CYCLES,
        SWAP_CONSUMPTION_CYCLES,
    };
    use miden_standards::note::{
        ConstantFeePolicyConfigNote,
        FeeSponsorshipNote,
        P2idNote,
        SwapNote,
    };

    use super::*;

    fn fee_asset_id() -> AssetId {
        let fee_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("testing faucet ID should be valid");
        AssetId::new_fungible(fee_faucet_id)
    }

    fn pricer(base_fee: u32, margin: u32) -> NetworkNotePricer {
        NetworkNotePricer::builder()
            .fee_parameters(FeeParameters::new(base_fee))
            .fee_asset_id(fee_asset_id())
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
        let default_margin = NetworkNotePricer::builder()
            .fee_parameters(FeeParameters::new(500))
            .fee_asset_id(fee_asset_id())
            .build();
        assert_eq!(default_margin.fee(fee_inputs(1 << 16)).unwrap().as_u64(), 500 * 18);
    }

    #[test]
    fn out_of_range_cycle_costs_cannot_be_priced() {
        let root = NoteScriptRoot::from_array([1, 0, 0, 0]);
        // Zero-cycle and above-maximum costs, which the real tables never contain.
        for cycles in [0, u32::MAX] {
            let broken = custom_pricer([(root, NoteCost::new(cycles, Vec::new()))]);
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

    /// Fabricated creation graph shared by the recursion and accumulation tests, mirroring
    /// PSWAP's self-recreation: `[1, 0, 0, 0]` (`2^16` cycles) creates `[2, 0, 0, 0]` and
    /// itself, `[2, 0, 0, 0]` (`2^10` cycles) creates `[3, 0, 0, 0]`, and `[3, 0, 0, 0]`
    /// (`2^16` cycles) creates nothing. The roots are fabricated, so the costs extend rather
    /// than shadow the built-in tables.
    fn test_graph() -> [(NoteScriptRoot, NoteCost); 3] {
        let self_recursive = NoteScriptRoot::from_array([1, 0, 0, 0]);
        let parent = NoteScriptRoot::from_array([2, 0, 0, 0]);
        let leaf = NoteScriptRoot::from_array([3, 0, 0, 0]);
        [
            (self_recursive, NoteCost::new(1 << 16, vec![parent, self_recursive])),
            (parent, NoteCost::new(1 << 10, vec![leaf])),
            (leaf, NoteCost::new(1 << 16, Vec::new())),
        ]
    }

    /// Builds a pricer whose fee for a `2^16`-cycle cost lands exactly at `AssetAmount::MAX`:
    /// such a cost is charged `17` formula cycles plus the margin, and
    /// `u32::MAX * 2^31 = AssetAmount::MAX`. The `2^10`-cycle parent's fee falls six base
    /// fees short of that.
    fn max_fee_pricer() -> NetworkNotePricer {
        NetworkNotePricer::builder()
            .fee_parameters(FeeParameters::new(u32::MAX))
            .fee_asset_id(fee_asset_id())
            .safety_margin_verification_cycles((1 << 31) - 17)
            .note_costs(test_graph())
            .build()
    }

    #[test]
    fn overflowing_accumulated_price_is_rejected() {
        // The self-recursive root accumulates nearly three maximal fees (its own, the
        // parent's, and the leaf's), overflowing u64.
        assert!(matches!(
            max_fee_pricer().price(NoteScriptRoot::from_array([1, 0, 0, 0])),
            Err(NotePricingError::PriceOverflow)
        ));
    }

    #[test]
    fn accumulated_price_above_max_asset_amount_is_rejected() {
        // The parent's and leaf's fees together fit in a u64 but exceed `AssetAmount::MAX`.
        assert!(matches!(
            max_fee_pricer().price(NoteScriptRoot::from_array([2, 0, 0, 0])),
            Err(NotePricingError::PriceExceedsMaxAssetAmount(_))
        ));
    }

    /// Builds a zero-margin pricer carrying the given fabricated costs.
    fn custom_pricer(
        costs: impl IntoIterator<Item = (NoteScriptRoot, NoteCost)>,
    ) -> NetworkNotePricer {
        NetworkNotePricer::builder()
            .fee_parameters(FeeParameters::new(500))
            .fee_asset_id(fee_asset_id())
            .safety_margin_verification_cycles(0)
            .note_costs(costs)
            .build()
    }

    #[test]
    fn price_includes_created_notes() {
        let parent = NoteScriptRoot::from_array([2, 0, 0, 0]);
        // The parent's own fee (11 verification cycles) plus the leaf's (17).
        let expected = 500 * 11 + 500 * 17;
        assert_eq!(custom_pricer(test_graph()).price(parent).unwrap().as_u64(), expected);
    }

    #[test]
    fn self_recursive_notes_are_priced_at_one_level_of_nesting() {
        let selfish = NoteScriptRoot::from_array([1, 0, 0, 0]);
        // Own fee + the created chain (parent + leaf) + own fee again (the nested
        // self-reference, cut off there).
        let expected = 500 * 17 + (500 * 11 + 500 * 17) + 500 * 17;
        assert_eq!(custom_pricer(test_graph()).price(selfish).unwrap().as_u64(), expected);
    }

    #[test]
    fn unknown_roots_cannot_be_priced() {
        let unknown = NoteScriptRoot::from_array([9, 9, 9, 9]);
        assert!(matches!(
            pricer(500, 0).price(unknown),
            Err(NotePricingError::UnknownNoteScriptRoot(root)) if root == unknown
        ));
    }

    /// A root absent from the built-in tables is priced from the supplied costs, and its
    /// created notes still resolve through the built-in tables.
    #[test]
    fn supplied_note_costs_extend_the_built_in_tables() {
        let custom = NoteScriptRoot::from_array([7, 0, 0, 0]);
        let pricer =
            custom_pricer([(custom, NoteCost::new(1 << 16, vec![P2idNote::script_root()]))]);
        let expected = pricer.fee(fee_inputs(1 << 16)).unwrap().as_u64()
            + pricer.fee(fee_inputs(P2ID_CONSUMPTION_CYCLES)).unwrap().as_u64();
        assert_eq!(pricer.price(custom).unwrap().as_u64(), expected);
    }

    /// Individual costs can be supplied one at a time through the `note_cost` builder extension,
    /// accumulating across chained calls just like the iterator-taking `note_costs`.
    #[test]
    fn individual_note_costs_can_be_supplied_one_at_a_time() {
        let first = NoteScriptRoot::from_array([7, 0, 0, 0]);
        let second = NoteScriptRoot::from_array([8, 0, 0, 0]);
        let pricer = NetworkNotePricer::builder()
            .fee_parameters(FeeParameters::new(500))
            .fee_asset_id(fee_asset_id())
            .safety_margin_verification_cycles(0)
            .note_cost(first, NoteCost::new(1 << 16, Vec::new()))
            .note_cost(second, NoteCost::new(1 << 10, Vec::new()))
            .build();
        assert_eq!(
            pricer.price(first).unwrap().as_u64(),
            pricer.fee(fee_inputs(1 << 16)).unwrap().as_u64()
        );
        assert_eq!(
            pricer.price(second).unwrap().as_u64(),
            pricer.fee(fee_inputs(1 << 10)).unwrap().as_u64()
        );
    }

    /// A root present in both the supplied costs and the built-in tables is priced from the
    /// supplied cost: the map shadows the tables. The override drops the P2ID payback leg the
    /// table's SWAP cost carries, so a table-derived price could not produce this value.
    #[test]
    fn supplied_note_costs_shadow_the_built_in_tables() {
        let root = SwapNote::script_root();
        let pricer =
            custom_pricer([(root, NoteCost::new(2 * SWAP_CONSUMPTION_CYCLES, Vec::new()))]);
        let expected = pricer.fee(fee_inputs(2 * SWAP_CONSUMPTION_CYCLES)).unwrap().as_u64();
        assert_eq!(pricer.price(root).unwrap().as_u64(), expected);
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

    #[test]
    fn basic_constant_fee_policy_manager_prices_every_root_in_the_native_fee_asset() {
        let pricer = pricer(500, 0);
        let roots = [
            SwapNote::script_root(),
            ClaimNote::script_root(),
            ConstantFeePolicyConfigNote::script_root(),
        ];

        let manager = pricer.basic_constant_fee_policy_manager(roots).unwrap();
        assert_eq!(manager.active_fee_policy(), BasicConstantFeePolicy::root());
        assert_eq!(manager.fee_asset_id(), pricer.fee_asset_id());
    }

    #[test]
    fn sponsorship_defaults_to_zero_but_allows_a_cost_override() {
        let root = FeeSponsorshipNote::script_root();

        let default_pricer = pricer(500, 0);
        let default_policy = default_pricer.basic_constant_fee_policy([root]).unwrap();
        assert_eq!(default_pricer.price(root).unwrap(), AssetAmount::ZERO);
        assert_eq!(default_policy.fee_schedule().get(&root), Some(&AssetAmount::ZERO));

        const CUSTOM_SPONSORSHIP_CYCLES: u32 = 65_536;
        let custom_pricer =
            custom_pricer([(root, NoteCost::new(CUSTOM_SPONSORSHIP_CYCLES, Vec::new()))]);
        let custom_price = custom_pricer.fee(fee_inputs(CUSTOM_SPONSORSHIP_CYCLES)).unwrap();
        let custom_policy = custom_pricer.basic_constant_fee_policy([root]).unwrap();

        assert_eq!(custom_pricer.price(root).unwrap(), custom_price);
        assert_eq!(custom_policy.fee_schedule().get(&root), Some(&custom_price));
    }

    #[test]
    fn basic_constant_fee_policy_rejects_unknown_roots() {
        let unknown = NoteScriptRoot::from_array([9, 9, 9, 9]);
        assert!(matches!(
            pricer(500, 0).basic_constant_fee_policy([unknown]),
            Err(NotePricingError::UnknownNoteScriptRoot(root)) if root == unknown
        ));
    }
}
