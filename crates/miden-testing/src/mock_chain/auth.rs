// AUTH
// ================================================================================================
use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::TransactionScriptRoot;
use miden_standards::account::auth::multisig_smart::{DelayedExecutionPolicy, ProcedurePolicy};
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
    GuardianConfig,
    SponsorshipPolicy,
};
use miden_standards::account::fees::FeePolicyManager;
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

    /// Multisig with smart per-procedure policy configuration and a delayed-execution policy
    /// controlling propose/cancel/execute timelock flows.
    MultisigSmart {
        approver_set: ApproverSet,
        proc_policy_map: Vec<(Word, ProcedurePolicy)>,
        delayed_execution_policy: DelayedExecutionPolicy,
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
    ///
    /// The `fee_policy_manager` initializes the fee-policy storage the auth component owns and
    /// contributes the components making its fee policies dispatchable.
    NetworkAccount {
        allowed_script_roots: BTreeSet<NoteScriptRoot>,
        allowed_tx_script_roots: BTreeSet<TransactionScriptRoot>,
        fee_policy_manager: FeePolicyManager,
        sponsorship_policy: SponsorshipPolicy,
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
    /// Returns [`Auth::BasicAuth`] with [`AuthScheme::Falcon512Poseidon2`].
    ///
    /// Prefer ECDSA over Falcon for tests where the auth scheme itself is not under test.
    pub fn basic_falcon() -> Self {
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        }
    }

    /// Returns [`Auth::BasicAuth`] with [`AuthScheme::EcdsaK256Keccak`].
    ///
    /// ECDSA verifies much faster than Falcon, making it the better choice for tests where the
    /// auth scheme itself is not under test.
    pub fn basic_ecdsa() -> Self {
        Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak }
    }

    /// Converts `self` into the [`AccountComponent`]s implementing this authentication scheme and
    /// an optional [`BasicAuthenticator`].
    ///
    /// The authentication component is always the first component of the returned vector; variants
    /// that expand into multiple components (e.g. [`Auth::NetworkAccount`]) yield their companion
    /// components after it. The authenticator is only `Some` when [`Auth::BasicAuth`] is passed.
    pub fn build_components(&self) -> (Vec<AccountComponent>, Option<BasicAuthenticator>) {
        match self {
            Auth::BasicAuth { auth_scheme } => {
                let mut rng = ChaCha20Rng::from_seed(Default::default());
                let sec_key = AuthSecretKey::with_scheme_and_rng(*auth_scheme, &mut rng)
                    .expect("failed to create secret key");
                let pub_key = sec_key.public_key().to_commitment();

                let component = AuthSingleSig::new(Approver::new(pub_key, *auth_scheme)).into();
                let authenticator = BasicAuthenticator::new(&[sec_key]);

                (vec![component], Some(authenticator))
            },
            Auth::Multisig { approver_set, proc_threshold_map } => {
                let config = AuthMultisigConfig::new(approver_set.clone())
                    .with_proc_thresholds(proc_threshold_map.clone())
                    .expect("invalid multisig config");
                let component =
                    AuthMultisig::new(config).expect("multisig component creation failed").into();

                (vec![component], None)
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

                (vec![component], None)
            },
            Auth::MultisigSmart {
                approver_set,
                proc_policy_map,
                delayed_execution_policy,
            } => {
                let config =
                    AuthMultisigSmartConfig::new(approver_set.clone(), *delayed_execution_policy)
                        .with_proc_policies(proc_policy_map.clone())
                        .expect("invalid multisig smart config");

                let component = AuthMultisigSmart::new(config)
                    .expect("multisig smart component creation failed")
                    .into();

                (vec![component], None)
            },
            Auth::IncrNonce => (vec![IncrNonceAuthComponent.into()], None),
            Auth::Noop => (vec![NoopAuthComponent.into()], None),
            Auth::Conditional => (vec![ConditionalAuthComponent.into()], None),
            Auth::NetworkAccount {
                allowed_script_roots,
                allowed_tx_script_roots,
                fee_policy_manager,
                sponsorship_policy,
            } => {
                let components = AuthNetworkAccount::new(
                    allowed_script_roots.clone(),
                    fee_policy_manager.clone(),
                )
                .expect("network account allowlist must be non-empty")
                .with_allowed_tx_scripts(allowed_tx_script_roots.clone())
                .with_sponsorship_policy(*sponsorship_policy)
                .into_iter()
                .collect();
                (components, None)
            },
        }
    }
}

impl IntoIterator for Auth {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s implementing this authentication scheme, discarding the
    /// authenticator. Use [`Auth::build_components`] when the authenticator is needed.
    fn into_iter(self) -> Self::IntoIter {
        let (components, _) = self.build_components();
        components.into_iter()
    }
}
