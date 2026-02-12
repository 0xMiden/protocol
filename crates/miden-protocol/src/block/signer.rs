use crate::block::BlockHeader;
use crate::crypto::dsa::ecdsa_k256_keccak as ecdsa;
use crate::crypto::dsa::ecdsa_k256_keccak::SecretKey;

// BLOCK SIGNER
// ================================================================================================

/// Trait which abstracts the signing of block headers with ECDSA signatures.
///
/// Production-level implementations will involve some sort of secure remote backend. The trait also
/// allows for testing with local and ephemeral signers.
pub trait BlockSigner {
    fn sign(&self, header: &BlockHeader) -> ecdsa::Signature;
    fn public_key(&self) -> ecdsa::PublicKey;
}

// SECRET KEY BLOCK SIGNER
// ================================================================================================

impl BlockSigner for SecretKey {
    fn sign(&self, header: &BlockHeader) -> ecdsa::Signature {
        self.sign(header.commitment())
    }

    fn public_key(&self) -> ecdsa::PublicKey {
        self.public_key()
    }
}
