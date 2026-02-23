use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{AccountComponent, StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;

use crate::account::components::ecdsa_k256_keccak_library;

/// The schema type for ECDSA K256 Keccak public keys.
const PUB_KEY_TYPE: &str = "miden::standards::auth::ecdsa_k256_keccak::pub_key";

static ECDSA_PUBKEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak::public_key")
        .expect("storage slot name should be valid")
});

/// An [`AccountComponent`] implementing the ECDSA K256 Keccak signature scheme for authentication
/// of transactions.
///
/// It reexports the procedures from `miden::standards::auth::ecdsa_k256_keccak`. When linking
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
pub struct AuthEcdsaK256Keccak {
    pub_key: PublicKeyCommitment,
}

impl AuthEcdsaK256Keccak {
    /// The name of the component.
    pub const NAME: &'static str = "miden::auth::ecdsa_k256_keccak";

    /// Creates a new [`AuthEcdsaK256Keccak`] component with the given `public_key`.
    pub fn new(pub_key: PublicKeyCommitment) -> Self {
        Self { pub_key }
    }

    /// Returns the [`StorageSlotName`] where the public key is stored.
    pub fn public_key_slot() -> &'static StorageSlotName {
        &ECDSA_PUBKEY_SLOT_NAME
    }

    /// Returns the storage slot schema for the public key slot.
    pub fn public_key_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        let pub_key_type = SchemaType::new(PUB_KEY_TYPE).expect("valid type");
        (
            Self::public_key_slot().clone(),
            StorageSlotSchema::value("Public key commitment", pub_key_type),
        )
    }
}

impl From<AuthEcdsaK256Keccak> for AccountComponent {
    fn from(ecdsa: AuthEcdsaK256Keccak) -> Self {
        let storage_schema = StorageSchema::new([AuthEcdsaK256Keccak::public_key_slot_schema()])
            .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(AuthEcdsaK256Keccak::NAME)
            .with_description("Authentication component using ECDSA K256 Keccak signature scheme")
            .with_supports_all_types()
            .with_storage_schema(storage_schema);

        AccountComponent::new(
            ecdsa_k256_keccak_library(),
            vec![StorageSlot::with_value(
                AuthEcdsaK256Keccak::public_key_slot().clone(),
                ecdsa.pub_key.into(),
            )],
            metadata,
        )
        .expect("ecdsa component should satisfy the requirements of a valid account component")
    }
}
