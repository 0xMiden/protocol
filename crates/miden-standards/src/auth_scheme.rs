use alloc::vec::Vec;

use miden_protocol::account::auth::PublicKeyCommitment;

/// Defines authentication schemes available to standard and faucet accounts.
pub enum AuthScheme {
    /// A minimal authentication scheme that provides no cryptographic authentication.
    ///
    /// It only increments the nonce if the account state has actually changed during transaction
    /// execution, avoiding unnecessary nonce increments for transactions that don't modify the
    /// account state.
    NoAuth,
    /// A single-key authentication scheme which relies on either RpoFalcon512 or ECDSA signatures.
    SingleSig { pub_key: PublicKeyCommitment, scheme_id: u8 },
    /// A multi-signature authentication scheme using either RpoFalcon512 or ECDSA signatures.
    ///
    /// Requires a threshold number of signatures from the provided public keys.
    Multisig {
        threshold: u32,
        pub_keys: Vec<PublicKeyCommitment>,
        scheme_ids: Vec<u8>,
    },
    /// A non-standard authentication scheme.
    Unknown,
}

impl AuthScheme {
    /// Returns all public key commitments associated with this authentication scheme.
    ///
    /// For unknown schemes, an empty vector is returned.
    pub fn get_public_key_commitments(&self) -> Vec<PublicKeyCommitment> {
        match self {
            AuthScheme::NoAuth => Vec::new(),
            AuthScheme::SingleSig { pub_key, .. } => vec![*pub_key],
            AuthScheme::Multisig { pub_keys, .. } => pub_keys.clone(),
            AuthScheme::Unknown => Vec::new(),
        }
    }
}
