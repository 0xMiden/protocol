//! The faucet's note allowlist, transaction-script allowlist, and fee configuration.

use std::collections::BTreeSet;

use miden_protocol::asset::AssetId;
use miden_protocol::block::FeeParameters;
use miden_protocol::note::NoteScriptRoot;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::note::config::{
    BlocklistConfigNote,
    ConstantFeePolicyConfigNote,
    FaucetMetadataConfigNote,
    NetworkAccountConfigNote,
    PauseConfigNote,
    RbacConfigNote,
};
use miden_standards::note::{BurnNote, FeeSponsorshipNote, MintNote, UpgradeNote};
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_tx::NetworkNotePricer;

use super::{XReserveStablecoinBuilder, XReserveStablecoinBuilderError};
use crate::note::xreserve_admin::{XReserveMinBurnAmountNote, XReserveSetAttesterNote};

impl XReserveStablecoinBuilder {
    /// Returns the note scripts allowed on a new faucet.
    ///
    /// `ADMIN` can change the script and fee-policy allowlists with `NetworkAccountConfigNote`,
    /// or upgrade the faucet code with `UpgradeNote`.
    /// Allowing `FaucetMetadataConfigNote` does not make all metadata mutable: its setters still
    /// check the account's mutability settings.
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
            UpgradeNote::script_root(),
            NetworkAccountConfigNote::script_root(),
            // Fee administration and sponsorship notes.
            ConstantFeePolicyConfigNote::script_root(),
            FeeSponsorshipNote::script_root(),
        ])
    }

    /// Builds network-account authorization and fees using the network's fee parameters and asset.
    /// A new faucet allows only `ExpirationTransactionScript` as its transaction script.
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
        Ok(AuthNetworkAccount::custom(Self::allowed_note_scripts(), fee_policy_manager)?
            .with_allowed_tx_scripts(BTreeSet::from([ExpirationTransactionScript::script_root()])))
    }
}
