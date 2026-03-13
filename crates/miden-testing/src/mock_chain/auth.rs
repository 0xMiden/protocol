// AUTH
// ================================================================================================
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::AccountComponent;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKeyCommitment};
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_standards::account::auth::{
    AuthMultisig,
    AuthMultisigConfig,
    AuthMultisigPsm,
    AuthMultisigPsmConfig,
    AuthMultisigSmart,
    AuthMultisigSmartConfig,
    AuthSingleSig,
    AuthSingleSigAcl,
    AuthSingleSigAclConfig,
    PsmConfig,
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
        threshold: u32,
        approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
        proc_threshold_map: Vec<(Word, u32)>,
    },

    /// Multisig with a private state manager.
    MultisigPsm {
        threshold: u32,
        approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
        psm_config: PsmConfig,
        proc_threshold_map: Vec<(Word, u32)>,
    },

    /// Multisig with additional smart-policy configuration.
    MultisigSmart {
        threshold: u32,
        approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
        proc_threshold_map: Vec<(Word, u32)>,
        spending_window: u32,
        min_delay: u32,
        propose_expiration_delta: u16,
        execute_expiration_delta: u16,
        amount_limits: [u64; 4],
        tier_thresholds: [u32; 4],
        oracle_id: [miden_protocol::Felt; 2],
        get_price_proc_root: Word,
    },

    /// Creates a secret key for the account, and creates a [BasicAuthenticator] used to
    /// authenticate the account with [AuthSingleSigAcl]. Authentication will only be
    /// triggered if any of the procedures specified in the list are called during execution.
    Acl {
        auth_trigger_procedures: Vec<Word>,
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

                let component = AuthSingleSig::new(pub_key, *auth_scheme).into();
                let authenticator = BasicAuthenticator::new(&[sec_key]);

                (component, Some(authenticator))
            },
            Auth::Multisig { threshold, approvers, proc_threshold_map } => {
                let config = AuthMultisigConfig::new(approvers.clone(), *threshold)
                    .and_then(|cfg| cfg.with_proc_thresholds(proc_threshold_map.clone()))
                    .expect("invalid multisig config");
                let component =
                    AuthMultisig::new(config).expect("multisig component creation failed").into();

                (component, None)
            },
            Auth::MultisigPsm {
                threshold,
                approvers,
                psm_config,
                proc_threshold_map,
            } => {
                let config = AuthMultisigPsmConfig::new(approvers.clone(), *threshold, *psm_config)
                    .and_then(|cfg| cfg.with_proc_thresholds(proc_threshold_map.clone()))
                    .expect("invalid multisig psm config");
                let component = AuthMultisigPsm::new(config)
                    .expect("multisig psm component creation failed")
                    .into();

                (component, None)
            },
            Auth::MultisigSmart {
                threshold,
                approvers,
                proc_threshold_map,
                spending_window,
                min_delay,
                propose_expiration_delta,
                execute_expiration_delta,
                amount_limits,
                tier_thresholds,
                oracle_id,
                get_price_proc_root,
            } => {
                let config = AuthMultisigSmartConfig::new(approvers.clone(), *threshold)
                    .and_then(|cfg| cfg.with_proc_thresholds(proc_threshold_map.clone()))
                    .expect("invalid multisig smart config")
                    .with_timelock_controller(
                        *spending_window,
                        *min_delay,
                        *propose_expiration_delta,
                        *execute_expiration_delta,
                    )
                    .with_amount_limits(*amount_limits)
                    .with_tier_thresholds(*tier_thresholds)
                    .with_oracle_config(*oracle_id)
                    .with_get_price_proc_root(*get_price_proc_root);

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
                    pub_key,
                    *auth_scheme,
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
        }
    }
}

impl From<Auth> for AccountComponent {
    fn from(auth: Auth) -> Self {
        let (component, _) = auth.build_component();
        component
    }
}
