
use miden_protocol::Word;
use alloc::vec::Vec;
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::{AccountComponent, StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;

use crate::account::components::basic_signature_library;

static BASIC_SIGNATURE_PUBKEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::signature::public_key")
        .expect("storage slot name should be valid")
});

static BASIC_SIGNATURE_SCHEME_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::signature::scheme_id")
        .expect("storage slot name should be valid")
});

/// An [`AccountComponent`] implementing the signature scheme for authentication
/// of transactions.
///
/// It reexports the procedures from `miden::standards::auth::signature`. When linking
/// against this component, the `miden` library (i.e.
/// [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler which is the
/// case when using [`CodeBuilder`][builder]. The procedures of this component are:
/// - `verify_signatures`, which can be used to verify a signature provided via the advice stack to
///   authenticate a transaction.
/// - `authenticate_transaction`, which can be used to authenticate a transaction using the ECDSA
///   signature scheme.
///
/// This component supports all account types.
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct AuthBasicSignature {
    pub_key: PublicKeyCommitment,
    scheme_id: u8,
}

impl AuthBasicSignature {
    /// Creates a new [`AuthBasicSignature`] component with the given `public_key`.
    pub fn new(pub_key: PublicKeyCommitment, scheme_id: u8) -> Self {
        Self { pub_key, scheme_id }
    }

    /// Returns the [`StorageSlotName`] where the public key is stored.
    pub fn public_key_slot() -> &'static StorageSlotName {
        &BASIC_SIGNATURE_PUBKEY_SLOT_NAME
    }

    // Returns the [`StorageSlotName`] where the scheme ID is stored.
    pub fn scheme_id_slot() -> &'static StorageSlotName {
        &BASIC_SIGNATURE_SCHEME_ID_SLOT_NAME
    }
}

impl From<AuthBasicSignature> for AccountComponent {
    fn from(basic_signature: AuthBasicSignature) -> Self {
        let mut storage_slots = Vec::with_capacity(2);

        // Public key slot
        storage_slots.push(StorageSlot::with_value(
            AuthBasicSignature::public_key_slot().clone(),
            basic_signature.pub_key.into(),
        ));

        // Scheme ID slot
        storage_slots.push(StorageSlot::with_value(
            AuthBasicSignature::scheme_id_slot().clone(),
            Word::from([
                basic_signature.scheme_id,
                0,
                0,
                0,
            ]),
        ));

        

        AccountComponent::new(basic_signature_library(), storage_slots)
        .expect("signature verifier component should satisfy the requirements of a valid account component")
        .with_supports_all_types()
    }
}
