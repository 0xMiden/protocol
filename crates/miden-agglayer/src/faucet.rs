extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

use miden_protocol::account::{AccountProcedureRoot, RoleSymbol};
use miden_protocol::note::NoteScriptRoot;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::ConstantFeeManager;
use miden_standards::note::{BurnNote, ConstantFeePolicyConfigNote, MintNote, RbacConfigNote};
use miden_utils_sync::LazyLock;

// FAUCET RBAC ROLES
// ================================================================================================

static FEE_MANAGER_ROLE: LazyLock<RoleSymbol> =
    LazyLock::new(|| RoleSymbol::new("FEE_MNGR").expect("FEE_MNGR role symbol should be valid"));

// AGGLAYER FAUCET
// ================================================================================================

/// The deployment configuration of an AggLayer faucet.
///
/// An AggLayer faucet is a [`FungibleFaucet`](miden_standards::account::faucets::FungibleFaucet)
/// owned by the bridge. This type is a stateless namespace for the settings the bridge and the
/// faucet operator agree on when one is deployed: the note allowlist, the RBAC roles, and the
/// account builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggLayerFaucet;

impl AggLayerFaucet {
    // RBAC ROLES
    // --------------------------------------------------------------------------------------------

    /// Returns the `FEE_MNGR` role symbol. Holders may update the faucet's note fee schedule.
    pub fn fee_manager_role() -> RoleSymbol {
        FEE_MANAGER_ROLE.clone()
    }

    /// Returns the fixed procedure-to-role map used to configure the faucet's `Authority`
    /// (`RbacControlled`) component.
    pub fn procedure_roles() -> BTreeMap<AccountProcedureRoot, RoleSymbol> {
        BTreeMap::from([(ConstantFeeManager::set_note_fee_root(), Self::fee_manager_role())])
    }

    // ALLOWED NOTES
    // --------------------------------------------------------------------------------------------

    /// Returns the input-note script roots allowlisted on a newly deployed AggLayer faucet.
    ///
    /// A live account's allowlist is available through
    /// [`NetworkAccount::allowed_notes`](miden_standards::account::auth::NetworkAccount::allowed_notes).
    pub fn allowed_notes() -> BTreeSet<NoteScriptRoot> {
        let mut notes = BTreeSet::from([
            MintNote::script_root(),
            BurnNote::script_root(),
            ConstantFeePolicyConfigNote::script_root(),
            RbacConfigNote::script_root(),
        ]);
        notes.extend(AuthNetworkAccount::default_allowed_note_scripts());
        notes
    }
}
