use alloc::collections::BTreeSet;
use alloc::format;

use miden_protocol::account::AccountComponent;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::errors::AccountError;
use miden_protocol::note::NoteScriptRoot;

use super::{
    AuthGuardedMultisig,
    AuthGuardedMultisigConfig,
    AuthMultisig,
    AuthMultisigConfig,
    AuthMultisigSmart,
    AuthMultisigSmartConfig,
    AuthNetworkAccount,
    AuthSingleSig,
    AuthSingleSigAcl,
    AuthSingleSigAclConfig,
    NoAuth,
};

/// Categorical tag describing which standard auth scheme an [`AccountAuthComponent`] wraps.
///
/// Factory functions use this to validate `(access control, auth scheme)` combinations
/// without exposing the concrete component type. `Custom` covers any wrapper not produced
/// by the convenience constructors on [`AccountAuthComponent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountAuthScheme {
    NoAuth,
    SingleSig,
    SingleSigAcl,
    NetworkAccount,
    Multisig,
    GuardedMultisig,
    MultisigSmart,
    Custom,
}

/// A typed wrapper around an authentication [`AccountComponent`].
///
/// Replaces the previous `AuthMethod` enum: instead of describing what an auth component
/// _could_ be and translating to a concrete component inside each factory, callers construct
/// the auth component themselves with one of the convenience constructors below (or wrap a
/// custom [`AccountComponent`]) and pass the resulting [`AccountAuthComponent`] to a
/// factory. Factories use [`Self::scheme`] to validate the combination.
pub struct AccountAuthComponent {
    inner: AccountComponent,
    scheme: AccountAuthScheme,
}

impl AccountAuthComponent {
    /// Wraps an arbitrary [`AccountComponent`] as an auth component. The component is treated
    /// as opaque ([`AccountAuthScheme::Custom`]) and is accepted by factories that allow
    /// custom auth components.
    pub fn custom(component: AccountComponent) -> Self {
        Self {
            inner: component,
            scheme: AccountAuthScheme::Custom,
        }
    }

    /// Builds a [`NoAuth`] component: the account performs only a nonce increment, no
    /// signature verification.
    pub fn no_auth() -> Self {
        Self {
            inner: NoAuth::new().into(),
            scheme: AccountAuthScheme::NoAuth,
        }
    }

    /// Builds an [`AuthSingleSig`] component (per-tx signature with no procedure-level ACL).
    pub fn single_sig(pub_key: PublicKeyCommitment, scheme: AuthScheme) -> Self {
        Self {
            inner: AuthSingleSig::new(pub_key, scheme).into(),
            scheme: AccountAuthScheme::SingleSig,
        }
    }

    /// Builds an [`AuthSingleSigAcl`] component with the given configuration. Procedure roots
    /// in the ACL's trigger list force signature verification when called.
    pub fn single_sig_acl(
        pub_key: PublicKeyCommitment,
        scheme: AuthScheme,
        config: AuthSingleSigAclConfig,
    ) -> Result<Self, AccountError> {
        let component = AuthSingleSigAcl::new(pub_key, scheme, config)?.into();
        Ok(Self {
            inner: component,
            scheme: AccountAuthScheme::SingleSigAcl,
        })
    }

    /// Builds an [`AuthNetworkAccount`] component restricted to the given note script roots.
    /// The allowlist must be non-empty.
    pub fn network_account(
        allowed_script_roots: BTreeSet<NoteScriptRoot>,
    ) -> Result<Self, AccountError> {
        let component = AuthNetworkAccount::with_allowlist(allowed_script_roots)
            .map_err(|err| {
                AccountError::other(format!("invalid network account allowlist: {err}"))
            })?
            .into();
        Ok(Self {
            inner: component,
            scheme: AccountAuthScheme::NetworkAccount,
        })
    }

    /// Builds an [`AuthMultisig`] component from the given configuration.
    pub fn multisig(config: AuthMultisigConfig) -> Result<Self, AccountError> {
        let component = AuthMultisig::new(config)?.into();
        Ok(Self {
            inner: component,
            scheme: AccountAuthScheme::Multisig,
        })
    }

    /// Builds an [`AuthGuardedMultisig`] component from the given configuration.
    pub fn guarded_multisig(config: AuthGuardedMultisigConfig) -> Result<Self, AccountError> {
        let component = AuthGuardedMultisig::new(config)?.into();
        Ok(Self {
            inner: component,
            scheme: AccountAuthScheme::GuardedMultisig,
        })
    }

    /// Builds an [`AuthMultisigSmart`] component from the given configuration.
    pub fn multisig_smart(config: AuthMultisigSmartConfig) -> Result<Self, AccountError> {
        let component = AuthMultisigSmart::new(config)?.into();
        Ok(Self {
            inner: component,
            scheme: AccountAuthScheme::MultisigSmart,
        })
    }

    /// Returns the [`AccountAuthScheme`] tag identifying which standard auth scheme this
    /// component wraps. Returns [`AccountAuthScheme::Custom`] for components built via
    /// [`Self::custom`].
    pub fn scheme(&self) -> AccountAuthScheme {
        self.scheme
    }

    /// Returns a reference to the underlying [`AccountComponent`].
    pub fn as_inner(&self) -> &AccountComponent {
        &self.inner
    }

    /// Consumes `self` and returns the underlying [`AccountComponent`].
    pub fn into_inner(self) -> AccountComponent {
        self.inner
    }
}

impl From<AccountAuthComponent> for AccountComponent {
    fn from(value: AccountAuthComponent) -> Self {
        value.into_inner()
    }
}

impl From<NoAuth> for AccountAuthComponent {
    fn from(value: NoAuth) -> Self {
        Self {
            inner: value.into(),
            scheme: AccountAuthScheme::NoAuth,
        }
    }
}

impl From<AuthSingleSig> for AccountAuthComponent {
    fn from(value: AuthSingleSig) -> Self {
        Self {
            inner: value.into(),
            scheme: AccountAuthScheme::SingleSig,
        }
    }
}

impl From<AuthSingleSigAcl> for AccountAuthComponent {
    fn from(value: AuthSingleSigAcl) -> Self {
        Self {
            inner: value.into(),
            scheme: AccountAuthScheme::SingleSigAcl,
        }
    }
}

impl From<AuthNetworkAccount> for AccountAuthComponent {
    fn from(value: AuthNetworkAccount) -> Self {
        Self {
            inner: value.into(),
            scheme: AccountAuthScheme::NetworkAccount,
        }
    }
}

impl From<AuthMultisig> for AccountAuthComponent {
    fn from(value: AuthMultisig) -> Self {
        Self {
            inner: value.into(),
            scheme: AccountAuthScheme::Multisig,
        }
    }
}

impl From<AuthGuardedMultisig> for AccountAuthComponent {
    fn from(value: AuthGuardedMultisig) -> Self {
        Self {
            inner: value.into(),
            scheme: AccountAuthScheme::GuardedMultisig,
        }
    }
}

impl From<AuthMultisigSmart> for AccountAuthComponent {
    fn from(value: AuthMultisigSmart) -> Self {
        Self {
            inner: value.into(),
            scheme: AccountAuthScheme::MultisigSmart,
        }
    }
}
