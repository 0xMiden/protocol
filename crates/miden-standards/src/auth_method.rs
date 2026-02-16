use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};

/// Defines authentication methods available to standard and faucet accounts.
pub enum AuthMethod {
    /// A minimal authentication method that provides no cryptographic authentication.
    ///
    /// It only increments the nonce if the account state has actually changed during transaction
    /// execution, avoiding unnecessary nonce increments for transactions that don't modify the
    /// account state.
    NoAuth,
    /// A single-key authentication method which relies on either RpoFalcon512 or ECDSA signatures.
    SingleSig {
        pub_key: PublicKeyCommitment,
        auth_scheme: AuthScheme,
    },
    /// A multi-signature authentication method using either RpoFalcon512 or ECDSA signatures.
    ///
    /// Requires a threshold number of signatures from the provided public keys.
    Multisig {
        threshold: u32,
        pub_keys: Vec<PublicKeyCommitment>,
        auth_schemes: Vec<AuthScheme>,
    },
    /// A non-standard authentication method.
    Unknown,
}

impl AuthMethod {
    /// Returns all public key commitments associated with this authentication method.
    ///
    /// For unknown methods, an empty vector is returned.
    pub fn get_public_key_commitments(&self) -> Vec<PublicKeyCommitment> {
        match self {
            AuthMethod::NoAuth => Vec::new(),
            AuthMethod::SingleSig { pub_key, .. } => vec![*pub_key],
            AuthMethod::Multisig { pub_keys, .. } => pub_keys.clone(),
            AuthMethod::Unknown => Vec::new(),
        }
    }
}
