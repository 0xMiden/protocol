use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_protocol::account::AccountProcedureRoot;

// ACCOUNT COMPONENT INTERFACE
// ================================================================================================

/// The enum holding all possible account interfaces which could be loaded to some account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountComponentInterface {
    /// Exposes procedures from the [`BasicWallet`][crate::account::wallets::BasicWallet] module.
    BasicWallet,
    /// Exposes procedures from the
    /// [`FungibleFaucet`][crate::account::faucets::FungibleFaucet] module.
    FungibleFaucet,
    /// Exposes procedures from the
    /// [`Authority`][crate::account::access::Authority] access component.
    Authority,
    /// Exposes procedures from the
    /// [`Ownable2Step`][crate::account::access::Ownable2Step] access component.
    Ownable2Step,
    /// Exposes procedures from the
    /// [`RoleBasedAccessControl`][crate::account::access::RoleBasedAccessControl] access
    /// component.
    RoleBasedAccessControl,
    /// Exposes procedures from the
    /// [`AuthSingleSig`][crate::account::auth::AuthSingleSig] module.
    AuthSingleSig,
    /// Exposes procedures from the
    /// [`AuthSingleSigAcl`][crate::account::auth::AuthSingleSigAcl] module.
    AuthSingleSigAcl,
    /// Exposes procedures from the
    /// [`AuthMultisig`][crate::account::auth::AuthMultisig] module.
    AuthMultisig,
    /// Exposes procedures from the
    /// [`AuthMultisigSmart`][crate::account::auth::AuthMultisigSmart] module.
    AuthMultisigSmart,
    /// Exposes procedures from the
    /// [`AuthGuardedMultisig`][crate::account::auth::AuthGuardedMultisig] module.
    AuthGuardedMultisig,
    /// Exposes procedures from the [`NoAuth`][crate::account::auth::NoAuth] module.
    ///
    /// This authentication scheme provides no cryptographic authentication and only increments
    /// the nonce if the account state has actually changed during transaction execution.
    AuthNoAuth,
    /// Exposes procedures from the
    /// [`AuthNetworkAccount`][crate::account::auth::AuthNetworkAccount] module.
    ///
    /// This authentication scheme is intended for network-owned accounts. It rejects transactions
    /// that executed a tx script or consumed input notes outside of a fixed allowlist of note
    /// script roots.
    AuthNetworkAccount,
    /// A non-standard, custom interface which exposes the contained procedures.
    ///
    /// Custom interface holds all procedures which are not part of some standard interface which is
    /// used by this account.
    Custom(Vec<AccountProcedureRoot>),
}

impl AccountComponentInterface {
    /// Returns a string line with the name of the [AccountComponentInterface] enum variant.
    ///
    /// In case of a [AccountComponentInterface::Custom] along with the name of the enum variant
    /// the vector of shortened hex representations of the used procedures is returned, e.g.
    /// `Custom([0x6d93447, 0x0bf23d8])`.
    pub fn name(&self) -> String {
        match self {
            AccountComponentInterface::BasicWallet => "Basic Wallet".to_string(),
            AccountComponentInterface::FungibleFaucet => "Fungible Faucet".to_string(),
            AccountComponentInterface::Authority => "Authority".to_string(),
            AccountComponentInterface::Ownable2Step => "Ownable2Step".to_string(),
            AccountComponentInterface::RoleBasedAccessControl => {
                "Role Based Access Control".to_string()
            },
            AccountComponentInterface::AuthSingleSig => "SingleSig".to_string(),
            AccountComponentInterface::AuthSingleSigAcl => "SingleSig ACL".to_string(),
            AccountComponentInterface::AuthMultisig => "Multisig".to_string(),
            AccountComponentInterface::AuthMultisigSmart => "Multisig Smart".to_string(),
            AccountComponentInterface::AuthGuardedMultisig => "Guarded Multisig".to_string(),
            AccountComponentInterface::AuthNoAuth => "No Auth".to_string(),
            AccountComponentInterface::AuthNetworkAccount => "Network Account Auth".to_string(),
            AccountComponentInterface::Custom(proc_root_vec) => {
                let result = proc_root_vec
                    .iter()
                    .map(|proc_root| proc_root.mast_root().to_hex()[..9].to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("Custom([{result}])")
            },
        }
    }

    /// Returns true if this component interface is an authentication component.
    ///
    /// TODO: currently this can identify only standard auth components
    pub fn is_auth_component(&self) -> bool {
        matches!(
            self,
            AccountComponentInterface::AuthSingleSig
                | AccountComponentInterface::AuthSingleSigAcl
                | AccountComponentInterface::AuthMultisig
                | AccountComponentInterface::AuthMultisigSmart
                | AccountComponentInterface::AuthGuardedMultisig
                | AccountComponentInterface::AuthNoAuth
                | AccountComponentInterface::AuthNetworkAccount
        )
    }
}
