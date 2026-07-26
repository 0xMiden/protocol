use miden_protocol::note::{NoteScript, NoteScriptRoot};
use miden_standards::note::StandardNote;
use miden_standards::note::costs::NoteCost;

use crate::{
    B2AggNote,
    ClaimNote,
    ConfigAggBridgeNote,
    DeregisterAggFaucetNote,
    RemoveGerNote,
    UpdateGerNote,
};

// AGGLAYER NOTE
// ================================================================================================

/// The enum holding the types of notes provided by `miden-agglayer`, mirroring
/// [`StandardNote`].
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgglayerNote {
    CLAIM,
    B2AGG,
    CONFIG_AGG_BRIDGE,
    DEREGISTER_AGG_FAUCET,
    UPDATE_GER,
    REMOVE_GER,
}

impl AgglayerNote {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns an [`AgglayerNote`] instance based on the provided script root. Returns `None`
    /// if the provided root does not match any agglayer note script - unlike
    /// [`Self::note_cost`], which falls back to the standard notes for unmatched roots.
    pub fn from_script_root(root: NoteScriptRoot) -> Option<Self> {
        match root {
            r if r == ClaimNote::script_root() => Some(Self::CLAIM),
            r if r == B2AggNote::script_root() => Some(Self::B2AGG),
            r if r == ConfigAggBridgeNote::script_root() => Some(Self::CONFIG_AGG_BRIDGE),
            r if r == DeregisterAggFaucetNote::script_root() => Some(Self::DEREGISTER_AGG_FAUCET),
            r if r == UpdateGerNote::script_root() => Some(Self::UPDATE_GER),
            r if r == RemoveGerNote::script_root() => Some(Self::REMOVE_GER),
            _ => None,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the name of this [`AgglayerNote`] variant as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Self::CLAIM => "CLAIM",
            Self::B2AGG => "B2AGG",
            Self::CONFIG_AGG_BRIDGE => "CONFIG_AGG_BRIDGE",
            Self::DEREGISTER_AGG_FAUCET => "DEREGISTER_AGG_FAUCET",
            Self::UPDATE_GER => "UPDATE_GER",
            Self::REMOVE_GER => "REMOVE_GER",
        }
    }

    /// Returns the note script of the current [`AgglayerNote`] instance.
    pub fn script(&self) -> NoteScript {
        match self {
            Self::CLAIM => ClaimNote::script(),
            Self::B2AGG => B2AggNote::script(),
            Self::CONFIG_AGG_BRIDGE => ConfigAggBridgeNote::script(),
            Self::DEREGISTER_AGG_FAUCET => DeregisterAggFaucetNote::script(),
            Self::UPDATE_GER => UpdateGerNote::script(),
            Self::REMOVE_GER => RemoveGerNote::script(),
        }
    }

    /// Returns the script root of the current [`AgglayerNote`] instance.
    pub fn script_root(&self) -> NoteScriptRoot {
        match self {
            Self::CLAIM => ClaimNote::script_root(),
            Self::B2AGG => B2AggNote::script_root(),
            Self::CONFIG_AGG_BRIDGE => ConfigAggBridgeNote::script_root(),
            Self::DEREGISTER_AGG_FAUCET => DeregisterAggFaucetNote::script_root(),
            Self::UPDATE_GER => UpdateGerNote::script_root(),
            Self::REMOVE_GER => RemoveGerNote::script_root(),
        }
    }

    /// Returns the benchmarked consumption cost of this note.
    fn cost(&self) -> NoteCost {
        match self {
            Self::CLAIM => NoteCost::of::<ClaimNote>(),
            Self::B2AGG => NoteCost::of::<B2AggNote>(),
            Self::CONFIG_AGG_BRIDGE => NoteCost::of::<ConfigAggBridgeNote>(),
            Self::DEREGISTER_AGG_FAUCET => NoteCost::of::<DeregisterAggFaucetNote>(),
            Self::UPDATE_GER => NoteCost::of::<UpdateGerNote>(),
            Self::REMOVE_GER => NoteCost::of::<RemoveGerNote>(),
        }
    }

    /// Returns the benchmarked consumption cost of the note with the given script root,
    /// resolving the agglayer notes first and falling back to the standard notes
    /// ([`StandardNote::note_cost`]).
    ///
    /// This is the widest cost lookup: pass it as the `NetworkNotePricer` lookup to price
    /// agglayer and standard notes through a single pricer.
    pub fn note_cost(root: NoteScriptRoot) -> Option<NoteCost> {
        match Self::from_script_root(root) {
            Some(note) => Some(note.cost()),
            None => StandardNote::note_cost(root),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountId;
    use miden_protocol::block::FeeParameters;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
    use miden_protocol::transaction::TransactionFee;
    use miden_standards::note::costs::{
        MINT_CONSUMPTION_CYCLES,
        NetworkNotePricer,
        P2ID_CONSUMPTION_CYCLES,
    };
    use miden_standards::note::{MintNote, P2idNote};

    use super::*;
    use crate::costs::{
        B2AGG_CONSUMPTION_CYCLES,
        CLAIM_CONSUMPTION_CYCLES,
        CONFIG_AGG_BRIDGE_CONSUMPTION_CYCLES,
        DEREGISTER_AGG_FAUCET_CONSUMPTION_CYCLES,
        REMOVE_GER_CONSUMPTION_CYCLES,
        UPDATE_GER_CONSUMPTION_CYCLES,
    };

    const ALL_NOTES: [AgglayerNote; 6] = [
        AgglayerNote::CLAIM,
        AgglayerNote::B2AGG,
        AgglayerNote::CONFIG_AGG_BRIDGE,
        AgglayerNote::DEREGISTER_AGG_FAUCET,
        AgglayerNote::UPDATE_GER,
        AgglayerNote::REMOVE_GER,
    ];

    /// Ties the hand-written per-variant tables to each other and each variant's cost to its
    /// own table constant: a copy-paste swap between two variants could otherwise hide inside
    /// the bench snapshot tests' 5% drift tolerance (CONFIG_AGG_BRIDGE and
    /// DEREGISTER_AGG_FAUCET differ by 0.05%).
    #[test]
    fn variant_tables_are_self_consistent_and_pin_the_table_constants() {
        for note in ALL_NOTES {
            assert_eq!(AgglayerNote::from_script_root(note.script_root()), Some(note));
            assert_eq!(note.script().root(), note.script_root());

            let expected_cycles = match note {
                AgglayerNote::CLAIM => CLAIM_CONSUMPTION_CYCLES,
                AgglayerNote::B2AGG => B2AGG_CONSUMPTION_CYCLES,
                AgglayerNote::CONFIG_AGG_BRIDGE => CONFIG_AGG_BRIDGE_CONSUMPTION_CYCLES,
                AgglayerNote::DEREGISTER_AGG_FAUCET => DEREGISTER_AGG_FAUCET_CONSUMPTION_CYCLES,
                AgglayerNote::UPDATE_GER => UPDATE_GER_CONSUMPTION_CYCLES,
                AgglayerNote::REMOVE_GER => REMOVE_GER_CONSUMPTION_CYCLES,
            };
            let cost = AgglayerNote::note_cost(note.script_root())
                .expect("every agglayer note should have a cost");
            assert_eq!(cost.cycles(), expected_cycles, "cost mismatch for {}", note.name());
        }

        // A standard-note root is not an agglayer note; only `note_cost` falls back to it.
        assert_eq!(AgglayerNote::from_script_root(P2idNote::script_root()), None);
    }

    /// Builds a pricer over the agglayer-aware lookup - the way a network account operator
    /// prices agglayer and standard notes through a single pricer.
    fn pricer() -> NetworkNotePricer {
        let fee_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("testing faucet ID should be valid");
        NetworkNotePricer::builder()
            .fee_parameters(FeeParameters::new(fee_faucet_id, 500))
            .safety_margin_verification_cycles(0)
            .lookup(AgglayerNote::note_cost)
            .build()
    }

    #[test]
    fn note_cost_resolves_agglayer_notes_and_falls_back_to_standards() {
        let claim_cost =
            AgglayerNote::note_cost(ClaimNote::script_root()).expect("CLAIM should have a cost");
        assert_eq!(claim_cost.cycles(), CLAIM_CONSUMPTION_CYCLES);
        assert_eq!(claim_cost.created_notes(), [MintNote::script_root()]);

        let p2id_cost =
            AgglayerNote::note_cost(P2idNote::script_root()).expect("P2ID should resolve here too");
        assert_eq!(p2id_cost.cycles(), P2ID_CONSUMPTION_CYCLES);
    }

    fn fee(pricer: &NetworkNotePricer, cycles: u32) -> u64 {
        let fee_inputs = TransactionFee::new(cycles).expect("cycle counts are non-zero");
        pricer.fee(fee_inputs).expect("fee should be representable").as_u64()
    }

    #[test]
    fn claim_price_includes_the_mint_and_p2id_legs() {
        let pricer = pricer();

        // A CLAIM's price covers the whole chain it triggers: CLAIM + MINT + P2ID.
        let expected = fee(&pricer, CLAIM_CONSUMPTION_CYCLES)
            + fee(&pricer, MINT_CONSUMPTION_CYCLES)
            + fee(&pricer, P2ID_CONSUMPTION_CYCLES);
        assert_eq!(pricer.price(ClaimNote::script_root()).unwrap().as_u64(), expected);
    }
}
