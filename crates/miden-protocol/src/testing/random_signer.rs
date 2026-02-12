// NO STD ECDSA SIGNER
// ================================================================================================

use crate::block::BlockSigner;
use crate::crypto::dsa::ecdsa_k256_keccak::SecretKey;

/// An insecure, random block signer for testing purposes.
pub trait RandomBlockSigner: BlockSigner {
    fn random() -> Self;
}

// NO STD SECRET KEY BLOCK SIGNER
// ================================================================================================

impl RandomBlockSigner for SecretKey {
    fn random() -> Self {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        let mut rng = ChaCha20Rng::from_os_rng();
        SecretKey::with_rng(&mut rng)
    }
}
