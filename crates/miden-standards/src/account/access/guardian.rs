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

account_component_code!(GUARDIAN_CODE, "access/guardian.masl");

static GUARDIAN_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::guardian::guardian_id")
        .expect("storage slot name should be valid")
});

/// A standalone guardian actor for account components.
///
/// Stores a single guardian account ID. The guardian is a second privileged actor, distinct from
/// the owner, intended as a safety brake: other components consult the MASM
/// `assert_sender_is_guardian` / `is_sender_guardian` primitives to authorize stop-like actions.
/// The guardian can never grant roles, move assets, or perform owner-only actions.
///
/// Authorization is a plain account-ID equality check, so the component needs no RBAC
/// infrastructure and behaves the same across all authority modes. When no guardian is assigned
/// the stored ID is the zero address and the guardian check fails for every sender.
///
/// ## Storage Layout
///
/// The guardian data is stored in a single word:
///
/// ```text
/// Word:  [guardian_suffix, guardian_prefix, 0, 0]
///         word[0]          word[1]           word[2] word[3]
/// ```
pub struct Guardian {
    /// The current guardian. `None` when no guardian is assigned.
    guardian: Option<AccountId>,
}

impl Guardian {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::access::guardian";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &GUARDIAN_CODE
    }

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`Guardian`] with the given guardian account ID.
    pub fn new(guardian: AccountId) -> Self {
        Self { guardian: Some(guardian) }
    }

    /// Creates a new [`Guardian`] with no guardian assigned.
    pub fn unassigned() -> Self {
        Self { guardian: None }
    }

    /// Reads guardian data from account storage, validating any non-zero account ID.
    ///
    /// Returns an error if the guardian contains an invalid (but non-zero) account ID.
    pub fn try_from_storage(storage: &AccountStorage) -> Result<Self, GuardianError> {
        let word: Word = storage
            .get_item(Self::slot_name())
            .map_err(GuardianError::StorageLookupFailed)?;

        Self::try_from_word(word)
    }

    /// Reconstructs a [`Guardian`] from a raw storage word.
    ///
    /// Format: `[guardian_suffix, guardian_prefix, 0, 0]`
    pub fn try_from_word(word: Word) -> Result<Self, GuardianError> {
        let guardian = account_id_from_felt_pair(word[0], word[1])
            .map_err(GuardianError::InvalidGuardianId)?;

        Ok(Self { guardian })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where guardian data is stored.
    pub fn slot_name() -> &'static StorageSlotName {
        &GUARDIAN_SLOT_NAME
    }

    /// Returns the storage slot schema for the guardian configuration slot.
    pub fn slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::slot_name().clone(),
            StorageSlotSchema::value(
                "Guardian account ID",
                [
                    FeltSchema::felt("guardian_suffix"),
                    FeltSchema::felt("guardian_prefix"),
                    FeltSchema::felt("unused_0"),
                    FeltSchema::felt("unused_1"),
                ],
            ),
        )
    }

    /// Returns the current guardian, or `None` if no guardian is assigned.
    pub fn guardian(&self) -> Option<AccountId> {
        self.guardian
    }

    /// Converts this guardian data into a [`StorageSlot`].
    pub fn to_storage_slot(&self) -> StorageSlot {
        StorageSlot::with_value(Self::slot_name().clone(), self.to_word())
    }

    /// Converts this guardian data into a raw [`Word`].
    pub fn to_word(&self) -> Word {
        let (guardian_suffix, guardian_prefix) = match self.guardian {
            Some(id) => (id.suffix(), id.prefix().as_felt()),
            None => (Felt::ZERO, Felt::ZERO),
        };
        [guardian_suffix, guardian_prefix, Felt::ZERO, Felt::ZERO].into()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema =
            StorageSchema::new([Self::slot_schema()]).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("Standalone guardian actor component")
            .with_storage_schema(storage_schema)
    }
}

impl From<Guardian> for AccountComponent {
    fn from(guardian: Guardian) -> Self {
        let storage_slot = guardian.to_storage_slot();
        let metadata = Guardian::component_metadata();

        AccountComponent::new(Guardian::code().clone(), vec![storage_slot], metadata).expect(
            "Guardian component should satisfy the requirements of a valid account component",
        )
    }
}

// GUARDIAN ERROR
// ================================================================================================

/// Errors that can occur when reading [`Guardian`] data from storage.
#[derive(Debug, thiserror::Error)]
pub enum GuardianError {
    #[error("failed to read guardian slot from storage")]
    StorageLookupFailed(#[source] miden_protocol::errors::AccountError),
    #[error("invalid guardian account ID in storage")]
    InvalidGuardianId(#[source] AccountIdError),
}

// HELPERS
// ================================================================================================

/// Constructs an `Option<AccountId>` from a suffix/prefix felt pair.
/// Returns `Ok(None)` when both felts are zero (no guardian assigned).
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
