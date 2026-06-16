// AUTH
// ================================================================================================
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::TransactionScriptRoot;
use miden_standards::account::auth::multisig_smart::ProcedurePolicy;
use miden_standards::account::auth::{
    Approver,
    ApproverSet,
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
    GuardianConfig,
};
use miden_standards::testing::account_component::{
    ConditionalAuthComponent,
    IncrNonceAuthComponent,
};
use miden_tx::auth::BasicAuthenticator;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Specifies which authentication mechanism is desired for accounts
#[derive(Debug, Clone)]
pub enum Auth {
    /// Creates a secret key for the account and creates a [BasicAuthenticator] used to
    /// authenticate the account with [AuthSingleSig].
    BasicAuth { auth_scheme: AuthScheme },

    /// Multisig
    Multisig {
        approver_set: ApproverSet,
        proc_threshold_map: Vec<(AccountProcedureRoot, u32)>,
    },

    /// Guarded multisig.
    GuardedMultisig {
        approver_set: ApproverSet,
        guardian_config: GuardianConfig,
        proc_threshold_map: Vec<(AccountProcedureRoot, u32)>,
    },

    /// Multisig with smart per-procedure policy configuration.
    MultisigSmart {
        approver_set: ApproverSet,
        proc_policy_map: Vec<(Word, ProcedurePolicy)>,
    },

    /// Creates a secret key for the account, and creates a [BasicAuthenticator] used to
    /// authenticate the account with [AuthSingleSigAcl]. Authentication will only be
    /// triggered if any of the procedures specified in the list are called during execution.
    Acl {
        auth_trigger_procedures: Vec<AccountProcedureRoot>,
        allow_unauthorized_output_notes: bool,
        allow_unauthorized_input_notes: bool,
        auth_scheme: AuthScheme,
    },

    /// Creates a mock authentication mechanism for the account that only increments the nonce.
    IncrNonce,

    /// Creates a mock authentication mechanism for the account that does nothing.
    Noop,

    /// Creates a mock authentication mechanism for the account that conditionally succeeds and
    /// conditionally increments the nonce based on the authentication arguments.
    ///
    /// The auth procedure expects the first three arguments as [99, 98, 97] to succeed.
    /// In case it succeeds, it conditionally increments the nonce based on the fourth argument.
    Conditional,

    /// Network-account authentication that restricts the account to consuming only notes whose
    /// script roots appear in `allowed_script_roots` (must be non-empty), and to executing only
    /// transaction scripts whose roots appear in `allowed_tx_script_roots` (may be empty).
    NetworkAccount {
        allowed_script_roots: BTreeSet<NoteScriptRoot>,
        allowed_tx_script_roots: BTreeSet<TransactionScriptRoot>,
    },
}

impl Default for Auth {
    /// Returns the most common authentication scheme used in tests:
    /// [`Auth::BasicAuth`] with [`AuthScheme::Falcon512Poseidon2`].
    fn default() -> Self {
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        }
    }
}

impl Auth {
    /// Converts `self` into its corresponding authentication [`AccountComponent`] and an optional
    /// [`BasicAuthenticator`]. The component is always returned, but the authenticator is only
    /// `Some` when [`Auth::BasicAuth`] is passed."
    pub fn build_component(&self) -> (AccountComponent, Option<BasicAuthenticator>) {
        match self {
            Auth::BasicAuth { auth_scheme } => {
                let mut rng = ChaCha20Rng::from_seed(Default::default());
                let sec_key = AuthSecretKey::with_scheme_and_rng(*auth_scheme, &mut rng)
                    .expect("failed to create secret key");
                let pub_key = sec_key.public_key().to_commitment();

                let component = AuthSingleSig::new(Approver::new(pub_key, *auth_scheme)).into();
                let authenticator = BasicAuthenticator::new(&[sec_key]);

                (component, Some(authenticator))
            },
            Auth::Multisig { approver_set, proc_threshold_map } => {
                let config = AuthMultisigConfig::new(approver_set.clone())
                    .with_proc_thresholds(proc_threshold_map.clone())
                    .expect("invalid multisig config");
                let component =
                    AuthMultisig::new(config).expect("multisig component creation failed").into();

                (component, None)
            },
            Auth::GuardedMultisig {
                approver_set,
                guardian_config,
                proc_threshold_map,
            } => {
                let config = AuthGuardedMultisigConfig::new(approver_set.clone(), *guardian_config)
                    .and_then(|cfg| cfg.with_proc_thresholds(proc_threshold_map.clone()))
                    .expect("invalid guarded multisig config");
                let component = AuthGuardedMultisig::new(config)
                    .expect("guarded multisig component creation failed")
                    .into();

                (component, None)
            },
            Auth::MultisigSmart { approver_set, proc_policy_map } => {
                let config = AuthMultisigSmartConfig::new(approver_set.clone())
                    .with_proc_policies(proc_policy_map.clone())
                    .expect("invalid multisig smart config");

                let component = AuthMultisigSmart::new(config)
                    .expect("multisig smart component creation failed")
                    .into();

                (component, None)
            },
            Auth::Acl {
                auth_trigger_procedures,
                allow_unauthorized_output_notes,
                allow_unauthorized_input_notes,
                auth_scheme,
            } => {
                let mut rng = ChaCha20Rng::from_seed(Default::default());
                let sec_key = AuthSecretKey::with_scheme_and_rng(*auth_scheme, &mut rng)
                    .expect("failed to create secret key");
                let pub_key = sec_key.public_key().to_commitment();

                let component = AuthSingleSigAcl::new(
                    Approver::new(pub_key, *auth_scheme),
                    AuthSingleSigAclConfig::new()
                        .with_auth_trigger_procedures(auth_trigger_procedures.clone())
                        .with_allow_unauthorized_output_notes(*allow_unauthorized_output_notes)
                        .with_allow_unauthorized_input_notes(*allow_unauthorized_input_notes),
                )
                .expect("component creation failed")
                .into();
                let authenticator = BasicAuthenticator::new(&[sec_key]);

                (component, Some(authenticator))
            },
            Auth::IncrNonce => (IncrNonceAuthComponent.into(), None),
            Auth::Noop => (NoopAuthComponent.into(), None),
            Auth::Conditional => (ConditionalAuthComponent.into(), None),
            Auth::NetworkAccount {
                allowed_script_roots,
                allowed_tx_script_roots,
            } => {
                let component =
                    AuthNetworkAccount::with_allowed_notes(allowed_script_roots.clone())
                        .expect("network account allowlist must be non-empty")
                        .with_allowed_tx_scripts(allowed_tx_script_roots.clone())
                        .into();
                (component, None)
            },
        }
    }
}

impl From<Auth> for AccountComponent {
    fn from(auth: Auth) -> Self {
        let (component, _) = auth.build_component();
        component
    }
}
