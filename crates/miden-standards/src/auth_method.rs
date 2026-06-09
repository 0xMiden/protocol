use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::TransactionScriptRoot;

/// Defines standard authentication methods supported by account auth components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// A minimal authentication method that provides no cryptographic authentication.
    ///
    /// It only increments the nonce if the account state has actually changed during transaction
    /// execution, avoiding unnecessary nonce increments for transactions that don't modify the
    /// account state.
    NoAuth,
    /// A single-key authentication method which relies on either ECDSA or Falcon512Poseidon2
    /// signatures.
    SingleSig {
        approver: (PublicKeyCommitment, AuthScheme),
    },
    /// A multi-signature authentication method using either ECDSA or Falcon512Poseidon2 signatures.
    ///
    /// Requires a threshold number of signatures from the provided public keys.
    Multisig {
        threshold: u32,
        approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
    },
    /// An authentication method intended for network-owned accounts.
    ///
    /// It restricts the account to consuming only notes whose script roots are in
    /// `allowed_script_roots` (which must be non-empty), and to executing only transaction scripts
    /// whose roots are in `allowed_tx_script_roots`. An empty `allowed_tx_script_roots` permits no
    /// transaction scripts.
    NetworkAccount {
        allowed_script_roots: BTreeSet<NoteScriptRoot>,
        allowed_tx_script_roots: BTreeSet<TransactionScriptRoot>,
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
            AuthMethod::NetworkAccount { .. } => Vec::new(),
            AuthMethod::Unknown => Vec::new(),
        }
    }
}
