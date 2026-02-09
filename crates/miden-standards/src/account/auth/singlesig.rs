use miden_protocol::Word;
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    SchemaTypeId,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{AccountComponent, StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;

use crate::account::components::singlesig_library;

// The schema type ID for Public Key Commitments used in the singlesig component.
const PUB_KEY_TYPE_ID: &str = "miden::standards::auth::signature::pub_key";

static PUBKEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::singlesig::public_key")
        .expect("storage slot name should be valid")
});

static SCHEME_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::singlesig::scheme_id")
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
pub struct AuthSingleSig {
    pub_key: PublicKeyCommitment,
    scheme_id: u8,
}

impl AuthSingleSig {
    /// The name of the component.
    pub const NAME: &'static str = "miden::auth::singlesig";

    /// Creates a new [`AuthSingleSig`] component with the given `public_key`.
    pub fn new(pub_key: PublicKeyCommitment, scheme_id: u8) -> Self {
        Self { pub_key, scheme_id }
    }

    /// Returns the [`StorageSlotName`] where the public key is stored.
    pub fn public_key_slot() -> &'static StorageSlotName {
        &PUBKEY_SLOT_NAME
    }

    // Returns the [`StorageSlotName`] where the scheme ID is stored.
    pub fn scheme_id_slot() -> &'static StorageSlotName {
        &SCHEME_ID_SLOT_NAME
    }

    /// Returns the storage slot schema for the public key slot.
    pub fn public_key_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        let pub_key_type = SchemaTypeId::new(PUB_KEY_TYPE_ID).expect("valid type id");
        (
            Self::public_key_slot().clone(),
            StorageSlotSchema::value("Public key commitment", pub_key_type),
        )
    }
    /// Returns the storage slot schema for the scheme ID slot.
    pub fn scheme_id_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::scheme_id_slot().clone(),
            StorageSlotSchema::value("Scheme ID", SchemaTypeId::u8()),
        )
    }
}

impl From<AuthSingleSig> for AccountComponent {
    fn from(basic_signature: AuthSingleSig) -> Self {
        let storage_schema = StorageSchema::new(vec![
            AuthSingleSig::public_key_slot_schema(),
            AuthSingleSig::scheme_id_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(AuthSingleSig::NAME)
            .with_description("Authentication component using ECDSA K256 Keccak or Rpo Falcon 512 signature scheme")
            .with_supports_all_types()
            .with_storage_schema(storage_schema);

        let storage_slots = vec![
            StorageSlot::with_value(
                AuthSingleSig::public_key_slot().clone(),
                basic_signature.pub_key.into(),
            ),
            StorageSlot::with_value(
                AuthSingleSig::scheme_id_slot().clone(),
                Word::from([basic_signature.scheme_id, 0, 0, 0]),
            ),
        ];

        AccountComponent::new(singlesig_library(), storage_slots, metadata).expect(
            "singlesig component should satisfy the requirements of a valid account component",
        )
    }
}
