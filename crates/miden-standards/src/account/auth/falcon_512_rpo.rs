use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    SchemaTypeId,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{AccountComponent, StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;

use crate::account::components::falcon_512_rpo_library;

/// The schema type ID for Falcon512Rpo public keys.
const PUB_KEY_TYPE_ID: &str = "miden::standards::auth::falcon512_rpo::pub_key";

static FALCON_PUBKEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::falcon512_rpo::public_key")
        .expect("storage slot name should be valid")
});

/// An [`AccountComponent`] implementing the Falcon512Rpo signature scheme for authentication of
/// transactions.
///
/// It reexports the procedures from `miden::standards::auth::falcon512_rpo`. When linking against
/// this component, the `miden` library (i.e. [`ProtocolLib`](miden_protocol::ProtocolLib)) must
/// be available to the assembler which is the case when using [`CodeBuilder`][builder]. The
/// procedures of this component are:
/// - `verify_signatures`, which can be used to verify a signature provided via the advice stack to
///   authenticate a transaction.
/// - `authenticate_transaction`, which can be used to authenticate a transaction using the Falcon
///   signature scheme.
///
/// This component supports all account types.
///
/// ## Storage Layout
///
/// - [`Self::public_key_slot`]: Public key
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct AuthFalcon512Rpo {
    pub_key: PublicKeyCommitment,
}

impl AuthFalcon512Rpo {
    /// The name of the component.
    pub const NAME: &'static str = "miden::auth::falcon512_rpo";

    /// Creates a new [`AuthFalcon512Rpo`] component with the given `public_key`.
    pub fn new(pub_key: PublicKeyCommitment) -> Self {
        Self { pub_key }
    }

    /// Returns the [`StorageSlotName`] where the public key is stored.
    pub fn public_key_slot() -> &'static StorageSlotName {
        &FALCON_PUBKEY_SLOT_NAME
    }

    /// Returns the storage slot schema for the public key slot.
    pub fn public_key_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        let pub_key_type = SchemaTypeId::new(PUB_KEY_TYPE_ID).expect("valid type id");
        (
            Self::public_key_slot().clone(),
            StorageSlotSchema::value("Public key commitment", pub_key_type),
        )
    }
}

impl From<AuthFalcon512Rpo> for AccountComponent {
    fn from(falcon: AuthFalcon512Rpo) -> Self {
        let storage_schema = StorageSchema::new([AuthFalcon512Rpo::public_key_slot_schema()])
            .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(AuthFalcon512Rpo::NAME)
            .with_description("Authentication component using Falcon512 signature scheme")
            .with_supports_all_types()
            .with_storage_schema(storage_schema);

        AccountComponent::new(
            falcon_512_rpo_library(),
            vec![StorageSlot::with_value(
                AuthFalcon512Rpo::public_key_slot().clone(),
                falcon.pub_key.into(),
            )],
            metadata,
        )
        .expect("falcon component should satisfy the requirements of a valid account component")
    }
}
