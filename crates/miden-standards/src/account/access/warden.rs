use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    FeltSchema,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountComponentName,
    AccountId,
    AccountStorage,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::AccountIdError;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::account_component_code;

account_component_code!(WARDEN_CODE, "miden-standards-access-warden.masp");

static WARDEN_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::warden::warden_id")
        .expect("storage slot name should be valid")
});

/// A standalone warden actor for account components.
///
/// Stores a single warden account ID. The warden is a second privileged actor, distinct from
/// the owner, intended as a safety brake: other components consult the MASM
/// `assert_sender_is_warden` / `is_sender_warden` primitives to authorize stop-like actions.
/// The warden can never grant roles, move assets, or perform owner-only actions.
///
/// Authorization is a plain account-ID equality check, so the component needs no RBAC
/// infrastructure and behaves the same across all authority modes. When no warden is assigned
/// the stored ID is the zero address and the warden check fails for every sender.
///
/// ## Storage Layout
///
/// The warden data is stored in a single word:
///
/// ```text
/// [warden_suffix, warden_prefix, 0, 0]
/// ```
pub struct Warden {
    /// The current warden. `None` when no warden is assigned.
    warden: Option<AccountId>,
}

impl Warden {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::access::warden";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &WARDEN_CODE
    }

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`Warden`] with the given warden account ID.
    pub fn new(warden: AccountId) -> Self {
        Self { warden: Some(warden) }
    }

    /// Creates a new [`Warden`] with no warden assigned.
    pub fn unassigned() -> Self {
        Self { warden: None }
    }

    /// Reads warden data from account storage, validating any non-zero account ID.
    ///
    /// Returns an error if the warden contains an invalid (but non-zero) account ID.
    pub fn try_from_storage(storage: &AccountStorage) -> Result<Self, WardenError> {
        let word: Word =
            storage.get_item(Self::slot_name()).map_err(WardenError::StorageLookupFailed)?;

        Self::try_from_word(word)
    }

    /// Reconstructs a [`Warden`] from a raw storage word.
    ///
    /// Format: `[warden_suffix, warden_prefix, 0, 0]`
    pub fn try_from_word(word: Word) -> Result<Self, WardenError> {
        let warden =
            account_id_from_felt_pair(word[0], word[1]).map_err(WardenError::InvalidWardenId)?;

        Ok(Self { warden })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where warden data is stored.
    pub fn slot_name() -> &'static StorageSlotName {
        &WARDEN_SLOT_NAME
    }

    /// Returns the storage slot schema for the warden configuration slot.
    pub fn slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::slot_name().clone(),
            StorageSlotSchema::value(
                "Warden account ID",
                [
                    FeltSchema::felt("warden_suffix"),
                    FeltSchema::felt("warden_prefix"),
                    FeltSchema::felt("unused_0"),
                    FeltSchema::felt("unused_1"),
                ],
            ),
        )
    }

    /// Returns the current warden account ID, or `None` if no warden is assigned.
    pub fn account_id(&self) -> Option<AccountId> {
        self.warden
    }

    /// Converts this warden data into a [`StorageSlot`].
    pub fn to_storage_slot(&self) -> StorageSlot {
        StorageSlot::with_value(Self::slot_name().clone(), self.to_word())
    }

    /// Converts this warden data into a raw [`Word`].
    pub fn to_word(&self) -> Word {
        let (warden_suffix, warden_prefix) = match self.warden {
            Some(id) => (id.suffix(), id.prefix().as_felt()),
            None => (Felt::ZERO, Felt::ZERO),
        };
        [warden_suffix, warden_prefix, Felt::ZERO, Felt::ZERO].into()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema =
            StorageSchema::new([Self::slot_schema()]).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("Standalone warden actor component")
            .with_storage_schema(storage_schema)
    }
}

impl From<Warden> for AccountComponent {
    fn from(warden: Warden) -> Self {
        let storage_slot = warden.to_storage_slot();
        let metadata = Warden::component_metadata();

        AccountComponent::new(Warden::code().clone(), vec![storage_slot], metadata)
            .expect("Warden component should satisfy the requirements of a valid account component")
    }
}

// WARDEN ERROR
// ================================================================================================

/// Errors that can occur when reading [`Warden`] data from storage.
#[derive(Debug, thiserror::Error)]
pub enum WardenError {
    #[error("failed to read warden slot from storage")]
    StorageLookupFailed(#[source] miden_protocol::errors::AccountError),
    #[error("invalid warden account ID in storage")]
    InvalidWardenId(#[source] AccountIdError),
}

// HELPERS
// ================================================================================================

/// Constructs an `Option<AccountId>` from a suffix/prefix felt pair.
/// Returns `Ok(None)` when both felts are zero (no warden assigned).
fn account_id_from_felt_pair(
    suffix: Felt,
    prefix: Felt,
) -> Result<Option<AccountId>, AccountIdError> {
    if suffix == Felt::ZERO && prefix == Felt::ZERO {
        Ok(None)
    } else {
        AccountId::try_from_elements(suffix, prefix).map(Some)
    }
}
