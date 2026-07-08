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

use super::account_id_from_felt_pair;
use crate::account::account_component_code;

account_component_code!(SENTRY_CODE, "miden-standards-access-sentry.masp");

static SENTRY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::sentry::sentry_id")
        .expect("storage slot name should be valid")
});

/// A standalone sentry actor for account components.
///
/// Stores a single sentry account ID. The sentry is a second privileged actor,
/// distinct from the owner, intended as a safety brake: other components consult the MASM
/// `assert_sender_is_sentry` / `is_sender_sentry` primitives to authorize
/// stop-like actions. The sentry can never grant roles, move assets, or perform
/// owner-only actions.
///
/// Authorization is a plain account-ID equality check, so the component needs no RBAC
/// infrastructure and behaves the same across all authority modes. When no sentry is
/// assigned the stored ID is the zero address and the check fails for every sender.
///
/// ## Storage Layout
///
/// The sentry data is stored in a single word:
///
/// ```text
/// [sentry_suffix, sentry_prefix, 0, 0]
/// ```
pub struct Sentry {
    /// The current sentry. `None` when no sentry is assigned.
    sentry: Option<AccountId>,
}

impl Sentry {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::access::sentry";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &SENTRY_CODE
    }

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`Sentry`] with the given sentry account ID.
    pub fn new(sentry: AccountId) -> Self {
        Self { sentry: Some(sentry) }
    }

    /// Creates a new [`Sentry`] with no sentry assigned.
    pub fn unassigned() -> Self {
        Self { sentry: None }
    }

    /// Reads sentry data from account storage, validating any non-zero account ID.
    ///
    /// Returns an error if the sentry contains an invalid (but non-zero) account ID.
    pub fn try_from_storage(storage: &AccountStorage) -> Result<Self, SentryError> {
        let word: Word =
            storage.get_item(Self::slot_name()).map_err(SentryError::StorageLookupFailed)?;

        Self::try_from_word(word)
    }

    /// Reconstructs a [`Sentry`] from a raw storage word.
    ///
    /// Format: `[sentry_suffix, sentry_prefix, 0, 0]`
    pub fn try_from_word(word: Word) -> Result<Self, SentryError> {
        let sentry =
            account_id_from_felt_pair(word[0], word[1]).map_err(SentryError::InvalidSentryId)?;

        Ok(Self { sentry })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where sentry data is stored.
    pub fn slot_name() -> &'static StorageSlotName {
        &SENTRY_SLOT_NAME
    }

    /// Returns the storage slot schema for the sentry configuration slot.
    pub fn slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::slot_name().clone(),
            StorageSlotSchema::value(
                "Sentry account ID",
                [
                    FeltSchema::felt("sentry_suffix"),
                    FeltSchema::felt("sentry_prefix"),
                    FeltSchema::felt("unused_0"),
                    FeltSchema::felt("unused_1"),
                ],
            ),
        )
    }

    /// Returns the current sentry account ID, or `None` if no sentry is assigned.
    pub fn account_id(&self) -> Option<AccountId> {
        self.sentry
    }

    /// Converts this sentry data into a [`StorageSlot`].
    pub fn to_storage_slot(&self) -> StorageSlot {
        StorageSlot::with_value(Self::slot_name().clone(), self.to_word())
    }

    /// Converts this sentry data into a raw [`Word`].
    pub fn to_word(&self) -> Word {
        let (sentry_suffix, sentry_prefix) = match self.sentry {
            Some(id) => (id.suffix(), id.prefix().as_felt()),
            None => (Felt::ZERO, Felt::ZERO),
        };
        [sentry_suffix, sentry_prefix, Felt::ZERO, Felt::ZERO].into()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema =
            StorageSchema::new([Self::slot_schema()]).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("Standalone sentry actor component")
            .with_storage_schema(storage_schema)
    }
}

impl From<Sentry> for AccountComponent {
    fn from(sentry: Sentry) -> Self {
        let storage_slot = sentry.to_storage_slot();
        let metadata = Sentry::component_metadata();

        AccountComponent::new(Sentry::code().clone(), vec![storage_slot], metadata)
            .expect("Sentry component should satisfy the requirements of a valid account component")
    }
}

// SENTRY ERROR
// ================================================================================================

/// Errors that can occur when reading [`Sentry`] data from storage.
#[derive(Debug, thiserror::Error)]
pub enum SentryError {
    #[error("failed to read sentry slot from storage")]
    StorageLookupFailed(#[source] miden_protocol::errors::AccountError),
    #[error("invalid sentry account ID in storage")]
    InvalidSentryId(#[source] AccountIdError),
}
