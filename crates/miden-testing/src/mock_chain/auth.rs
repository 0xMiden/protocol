// AUTH
// ================================================================================================
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::AccountComponent;
use miden_protocol::account::auth::{AuthSecretKey, PublicKeyCommitment};
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_standards::account::auth::{
    AuthEcdsaK256Keccak,
    AuthEcdsaK256KeccakAcl,
    AuthEcdsaK256KeccakAclConfig,
    AuthEcdsaK256KeccakMultisig,
    AuthEcdsaK256KeccakMultisigConfig,
    AuthFalcon512Rpo,
    AuthFalcon512RpoAcl,
    AuthFalcon512RpoAclConfig,
    AuthFalcon512RpoMultisig,
    AuthFalcon512RpoMultisigConfig,
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
    /// authenticate the account with [AuthFalcon512Rpo].
    BasicAuth,

    /// Creates a secret key for the account and creates a [BasicAuthenticator] used to
    /// authenticate the account with [AuthEcdsaK256Keccak].
    EcdsaK256KeccakAuth,

    /// Creates a secret key for the account, and creates a [BasicAuthenticator] used to
    /// authenticate the account with [AuthEcdsaK256KeccakAcl]. Authentication will only be
    /// triggered if any of the procedures specified in the list are called during execution.
    EcdsaK256KeccakAcl {
        auth_trigger_procedures: Vec<Word>,
        allow_unauthorized_output_notes: bool,
        allow_unauthorized_input_notes: bool,
    },

    // Ecsda Multisig
    EcdsaK256KeccakMultisig {
        threshold: u32,
        approvers: Vec<Word>,
        proc_threshold_map: Vec<(Word, u32)>,
    },

    /// Multisig
    Multisig {
        threshold: u32,
        approvers: Vec<Word>,
        proc_threshold_map: Vec<(Word, u32)>,
    },

    /// Creates a secret key for the account, and creates a [BasicAuthenticator] used to
    /// authenticate the account with [AuthFalcon512RpoAcl]. Authentication will only be
    /// triggered if any of the procedures specified in the list are called during execution.
    Acl {
        auth_trigger_procedures: Vec<Word>,
        allow_unauthorized_output_notes: bool,
        allow_unauthorized_input_notes: bool,
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
            Auth::BasicAuth => {
                let mut rng = ChaCha20Rng::from_seed(Default::default());
                let sec_key = AuthSecretKey::new_falcon512_rpo_with_rng(&mut rng);
                let pub_key = sec_key.public_key().to_commitment();

                let component = AuthFalcon512Rpo::new(pub_key).into();
                let authenticator = BasicAuthenticator::new(&[sec_key]);

                (component, Some(authenticator))
            },
            Auth::EcdsaK256KeccakAuth => {
                let mut rng = ChaCha20Rng::from_seed(Default::default());
                let sec_key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);
                let pub_key = sec_key.public_key().to_commitment();

                let component = AuthEcdsaK256Keccak::new(pub_key).into();
                let authenticator = BasicAuthenticator::new(&[sec_key]);

                (component, Some(authenticator))
            },
            Auth::EcdsaK256KeccakMultisig { threshold, approvers, proc_threshold_map } => {
                let pub_keys: Vec<_> =
                    approvers.iter().map(|word| PublicKeyCommitment::from(*word)).collect();

                let config = AuthEcdsaK256KeccakMultisigConfig::new(pub_keys, *threshold)
                    .and_then(|cfg| cfg.with_proc_thresholds(proc_threshold_map.clone()))
                    .expect("invalid multisig config");
                let component = AuthEcdsaK256KeccakMultisig::new(config)
                    .expect("multisig component creation failed")
                    .into();

                (component, None)
            },
            Auth::Multisig { threshold, approvers, proc_threshold_map } => {
                let pub_keys: Vec<_> =
                    approvers.iter().map(|word| PublicKeyCommitment::from(*word)).collect();

                let config = AuthFalcon512RpoMultisigConfig::new(pub_keys, *threshold)
                    .and_then(|cfg| cfg.with_proc_thresholds(proc_threshold_map.clone()))
                    .expect("invalid multisig config");
                let component = AuthFalcon512RpoMultisig::new(config)
                    .expect("multisig component creation failed")
                    .into();

                (component, None)
            },
            Auth::Acl {
                auth_trigger_procedures,
                allow_unauthorized_output_notes,
                allow_unauthorized_input_notes,
            } => {
                let mut rng = ChaCha20Rng::from_seed(Default::default());
                let sec_key = AuthSecretKey::new_falcon512_rpo_with_rng(&mut rng);
                let pub_key = sec_key.public_key().to_commitment();

                let component = AuthFalcon512RpoAcl::new(
                    pub_key,
                    AuthFalcon512RpoAclConfig::new()
                        .with_auth_trigger_procedures(auth_trigger_procedures.clone())
                        .with_allow_unauthorized_output_notes(*allow_unauthorized_output_notes)
                        .with_allow_unauthorized_input_notes(*allow_unauthorized_input_notes),
                )
                .expect("component creation failed")
                .into();
                let authenticator = BasicAuthenticator::new(&[sec_key]);

                (component, Some(authenticator))
            },
            Auth::EcdsaK256KeccakAcl {
                auth_trigger_procedures,
                allow_unauthorized_output_notes,
                allow_unauthorized_input_notes,
            } => {
                let mut rng = ChaCha20Rng::from_seed(Default::default());
                let sec_key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);
                let pub_key = sec_key.public_key().to_commitment();

                let component = AuthEcdsaK256KeccakAcl::new(
                    pub_key,
                    AuthEcdsaK256KeccakAclConfig::new()
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
