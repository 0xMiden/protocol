// NO STD ECDSA SECRET KEY
// ================================================================================================

use crate::crypto::dsa::ecdsa_k256_keccak::SigningKey;

// NO STD SECRET KEY
// ================================================================================================

pub fn random_secret_key() -> SigningKey {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    let mut rng = ChaCha20Rng::from_os_rng();
    SigningKey::with_rng(&mut rng)
}
