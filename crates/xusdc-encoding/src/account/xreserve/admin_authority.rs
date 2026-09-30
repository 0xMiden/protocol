//! [`XReserveAdminAuthority`] — the account-wide authority configuration for the faucet's admin
//! surface, expressed as a per-procedure role assignment over the standard manager components.
//!
//! Pause, unpause, attester administration and the transfer blocklist each have a dedicated role.
//! Under [`Authority`]'s RBAC mode, each gated procedure's root selects its role; an unassigned
//! procedure falls back to `ADMIN`. Every role is initially administered directly by `ADMIN`.
//!
//! This type takes no arguments: the five roots come from the shipped managers and faucet
//! extension, and the role symbols are fixed, so callers cannot misconfigure the assignment.
//!
//! Two conversions make it usable: into the [`Authority`] configuration it describes, and into the
//! [`AccountComponent`] that carries it into an account.
//!
//! Installed by [`XReserveStablecoinBuilder::build_components`][crate::account::xreserve::XReserveStablecoinBuilder::build_components]
//! as the account's only authority component. One consequence is worth stating where a reader will
//! look for it: administrator membership is account-bound, and it is the account's ONLY authority
//! handle — the faucet installs no ownership component, so nothing else can move authority over the
//! unmapped setters. Rotating it is a grant to the incoming account then a revoke from the
//! outgoing one, both through the standard role-action note.

use std::collections::BTreeMap;

use miden_protocol::account::{AccountComponent, AccountProcedureRoot, RoleSymbol};
use miden_standards::account::access::{Authority, PausableManager};
use miden_standards::account::policies::BlocklistManager;

use super::{
    XReserveFaucetExtension, ATTEST_ADMIN_ROLE, BLK_MANAGER_ROLE, DOM_PAUSER_ROLE,
    DOM_UNPAUSER_ROLE, XRESERVE_SET_ATTESTER_PROC_PATH,
};

/// Dedicated-role procedures: pause, unpause, set_attester, block and unblock.
const ROLE_GATED_PROCEDURE_COUNT: usize = 5;

/// The faucet's account-wide RBAC authority with five dedicated procedure assignments.
///
/// `DOM_PAUSER` gates pause, `DOM_UNPAUSER` gates unpause, `ATTEST_ADMIN` gates set_attester,
/// and `BLK_MANAGER` gates block/unblock. Every other authority-gated procedure resolves to ADMIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XReserveAdminAuthority {
    procedure_roles: BTreeMap<AccountProcedureRoot, RoleSymbol>,
}

impl XReserveAdminAuthority {
    /// Builds the faucet's authority configuration.
    ///
    /// Takes no arguments on purpose: the assignment is a property of the faucet's admin model, not
    /// a deployment parameter, so it cannot be misconfigured by a caller.
    pub fn new() -> Self {
        let pauser = RoleSymbol::new(DOM_PAUSER_ROLE)
            .expect("the Domain pauser role symbol is a fixed valid symbol");
        let unpauser = RoleSymbol::new(DOM_UNPAUSER_ROLE)
            .expect("the Domain unpauser role symbol is a fixed valid symbol");
        let attest_admin = RoleSymbol::new(ATTEST_ADMIN_ROLE)
            .expect("the attester administrator role symbol is a fixed valid symbol");
        let set_attester_root = XReserveFaucetExtension::code()
            .get_procedure_root_by_path(XRESERVE_SET_ATTESTER_PROC_PATH)
            .expect("the shipped faucet extension exports set_attester");
        let blocklist_manager = RoleSymbol::new(BLK_MANAGER_ROLE)
            .expect("the blocklist administrator role symbol is a fixed valid symbol");

        let procedure_roles = BTreeMap::from([
            (PausableManager::pause_root(), pauser),
            (PausableManager::unpause_root(), unpauser),
            (set_attester_root, attest_admin),
            (
                BlocklistManager::block_account_root(),
                blocklist_manager.clone(),
            ),
            (BlocklistManager::unblock_account_root(), blocklist_manager),
        ]);
        assert_eq!(
            procedure_roles.len(),
            ROLE_GATED_PROCEDURE_COUNT,
            "the five gated procedures must be five distinct roots",
        );

        Self { procedure_roles }
    }

    /// The role required to invoke each role-gated procedure, keyed by the procedure's root.
    pub fn procedure_roles(&self) -> &BTreeMap<AccountProcedureRoot, RoleSymbol> {
        &self.procedure_roles
    }
}

impl Default for XReserveAdminAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl From<XReserveAdminAuthority> for Authority {
    fn from(authority: XReserveAdminAuthority) -> Self {
        Authority::RbacControlled {
            procedure_roles: authority.procedure_roles,
        }
    }
}

impl From<XReserveAdminAuthority> for AccountComponent {
    fn from(authority: XReserveAdminAuthority) -> Self {
        Authority::from(authority).into()
    }
}
