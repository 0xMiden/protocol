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
    /// A single-key authentication scheme which relies on ECDSA signatures.
    EcdsaK256Keccak { pub_key: PublicKeyCommitment },
    /// A multi-signature authentication scheme using ECDSA signatures.
    ///
    /// Requires a threshold number of signatures from the provided public keys.
    EcdsaK256KeccakMultisig {
        threshold: u32,
        pub_keys: Vec<PublicKeyCommitment>,
    },
    /// A single-key authentication scheme which relies Falcon512 RPO signatures.
    ///
    /// Falcon512 RPO is a variant of the [Falcon](https://falcon-sign.info/) signature scheme.
    /// This variant differs from the standard in that instead of using SHAKE256 hash function in
    /// the hash-to-point algorithm we use RPO256. This makes the signature more efficient to
    /// verify in Miden VM.
    Falcon512Rpo { pub_key: PublicKeyCommitment },
    /// A multi-signature authentication scheme using Falcon512 RPO signatures.
    ///
    /// Requires a threshold number of signatures from the provided public keys.
    Falcon512RpoMultisig {
        threshold: u32,
        pub_keys: Vec<PublicKeyCommitment>,
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
            AuthScheme::EcdsaK256Keccak { pub_key } => vec![*pub_key],
            AuthScheme::EcdsaK256KeccakMultisig { pub_keys, .. } => pub_keys.clone(),
            AuthScheme::Falcon512Rpo { pub_key } => vec![*pub_key],
            AuthScheme::Falcon512RpoMultisig { pub_keys, .. } => pub_keys.clone(),
            AuthScheme::Unknown => Vec::new(),
        }
    }
}
