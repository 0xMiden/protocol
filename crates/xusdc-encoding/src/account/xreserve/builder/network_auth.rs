//! The keyless network account's authorization surface: the note-script allowlist and the auth
//! component that carries the fee manager built from the network fee parameters.
//!
//! It lives beside the builder rather than inside it because the grouping is cohesive: the faucet
//! has no signing key, so this allowlist IS its authorization model, and nothing else decides which
//! notes the account will consume.

use std::collections::BTreeSet;

use miden_protocol::asset::AssetId;
use miden_protocol::block::FeeParameters;
use miden_protocol::note::NoteScriptRoot;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::note::config::{
    BlocklistConfigNote, ConstantFeePolicyConfigNote, FaucetMetadataConfigNote, PauseConfigNote,
    RbacConfigNote,
};
use miden_standards::note::{BurnNote, FeeSponsorshipNote, MintNote};
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_tx::NetworkNotePricer;

use super::{XReserveStablecoinBuilder, XReserveStablecoinBuilderError};
use crate::note::xreserve_admin::{XReserveMinBurnAmountNote, XReserveSetAttesterNote};

impl XReserveStablecoinBuilder {
    /// Returns the production faucet's note-script allowlist.
    ///
    /// The ten roots cover mint and burn, one faucet setter (`set_attester`), min-burn,
    /// max-supply, pause and blocklist administration, role administration, constant-fee
    /// administration, and fee sponsorship. The general network account configuration note is
    /// excluded, so the note and transaction allowlists cannot be modified through an accepted
    /// note. The faucet-metadata root also carries other metadata setters, but this account
    /// builds those fields immutable, so their setters always trap: each setter first asserts
    /// its flag in the faucet's `mutability_config` storage word, which is set at construction
    /// and has no writer.
    pub fn allowed_note_scripts() -> BTreeSet<NoteScriptRoot> {
        BTreeSet::from([
            // Supply notes.
            MintNote::script_root(),
            BurnNote::script_root(),
            // Faucet administration notes.
            XReserveSetAttesterNote::script_root(),
            XReserveMinBurnAmountNote::script_root(),
            FaucetMetadataConfigNote::script_root(),
            // Standard administration notes.
            PauseConfigNote::script_root(),
            BlocklistConfigNote::script_root(),
            RbacConfigNote::script_root(),
            // Fee administration and sponsorship notes.
            ConstantFeePolicyConfigNote::script_root(),
            FeeSponsorshipNote::script_root(),
        ])
    }

    /// Builds the production `AuthNetworkAccount` component from the network fee parameters and
    /// fee asset. It constructs the xUSDC fee schedule through the pricer, admits only
    /// `ExpirationTransactionScript::script_root()` as a transaction script, and excludes the
    /// mutable `NetworkAccountConfigNote` entry point.
    pub fn auth_component(
        fee_parameters: FeeParameters,
        fee_asset_id: AssetId,
    ) -> Result<AuthNetworkAccount, XReserveStablecoinBuilderError> {
        let fee_policy_manager = NetworkNotePricer::builder()
            .fee_parameters(fee_parameters)
            .fee_asset_id(fee_asset_id)
            .note_costs(crate::note::costs::note_costs())
            .build()
            .basic_constant_fee_policy_manager(Self::allowed_note_scripts())?;
        Ok(
            AuthNetworkAccount::custom(Self::allowed_note_scripts(), fee_policy_manager)?
                .with_allowed_tx_scripts(BTreeSet::from([
                    ExpirationTransactionScript::script_root(),
                ])),
        )
    }
}
