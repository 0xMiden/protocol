use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};

/// Defines standard authentication methods supported by account auth components.
pub enum AuthMethod {
    /// A minimal authentication method that provides no cryptographic authentication.
    ///
    /// It only increments the nonce if the account state has actually changed during transaction
    /// execution, avoiding unnecessary nonce increments for transactions that don't modify the
    /// account state.
    NoAuth,
    /// A single-key authentication method which relies on either ECDSA or Falcon512Rpo signatures.
    SingleSig {
        approver: (PublicKeyCommitment, AuthScheme),
    },
    /// A multi-signature authentication method using either ECDSA or Falcon512Rpo signatures.
    ///
    /// Requires a threshold number of signatures from the provided public keys.
    Multisig {
        threshold: u32,
        approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
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
            AuthMethod::SingleSig { approver: (pub_key, _) } => vec![*pub_key],
            AuthMethod::Multisig { approvers, .. } => {
                approvers.iter().map(|(pub_key, _)| *pub_key).collect()
            },
            AuthMethod::Unknown => Vec::new(),
        }
    }
}
