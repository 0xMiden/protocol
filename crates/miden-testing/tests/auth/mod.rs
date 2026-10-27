use miden_protocol::account::auth::{AuthSecretKey, BoundSignature, SignatureKey};
use miden_protocol::{Felt, Word};

mod fee_payment;

mod singlesig;

mod multisig;

mod hybrid_multisig;

mod multisig_smart;

mod guarded_multisig;

mod network_account;

mod tx_fee_collector;

mod passthrough;

/// Returns an advice map entry that presents a signature by `foreign_key` as the signature for
/// `key`.
///
/// The host does not check signatures it reads from the advice map, so the entry lets a test reach
/// the signature checks of the transaction kernel.
fn foreign_signature_advice_entry(
    foreign_key: &AuthSecretKey,
    key: SignatureKey,
) -> anyhow::Result<(Word, Vec<Felt>)> {
    let message = key.message();
    let foreign_signature = BoundSignature::new(
        SignatureKey::new(foreign_key.public_key().to_commitment(), message),
        foreign_key.sign(message),
    )?;

    Ok((key.to_advice_map_key(), foreign_signature.to_encoded_signature()))
}
