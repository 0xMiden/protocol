use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountId,
    AccountStorage,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::AccountIdError;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::components::ownable2step_library;

static OWNER_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::ownable2step::owner_config")
        .expect("storage slot name should be valid")
});

/// Two-step ownership management for account components.
///
/// This struct holds the current owner and any nominated (pending) owner. A nominated owner
/// must explicitly accept the transfer before it takes effect, preventing accidental transfers
/// to incorrect addresses.
///
/// ## Storage Layout
///
/// The ownership data is stored in a single word:
///
/// ```text
/// Word:  [owner_suffix, owner_prefix, nominated_owner_suffix, nominated_owner_prefix]
///         word[0]       word[1]        word[2]                  word[3]
/// ```
pub struct Ownable2Step {
    /// The current owner of the component. `None` when ownership has been renounced.
    owner: Option<AccountId>,
    nominated_owner: Option<AccountId>,
}

impl Ownable2Step {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::access::ownable2step";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`Ownable2Step`] with the given owner and no nominated owner.
    pub fn new(owner: AccountId) -> Self {
        Self {
            owner: Some(owner),
            nominated_owner: None,
        }
    }

    /// Reads ownership data from account storage, validating any non-zero account IDs.
    ///
    /// Returns an error if either owner or nominated owner contains an invalid (but non-zero)
    /// account ID.
    pub fn try_from_storage(storage: &AccountStorage) -> Result<Self, Ownable2StepError> {
        let word: Word = storage
            .get_item(Self::slot_name())
            .map_err(Ownable2StepError::StorageLookupFailed)?;

        Self::try_from_word(word)
    }

    /// Reconstructs an [`Ownable2Step`] from a raw storage word.
    ///
    /// Format: `[owner_suffix, owner_prefix, nominated_suffix, nominated_prefix]`
    pub fn try_from_word(word: Word) -> Result<Self, Ownable2StepError> {
        let owner = account_id_from_felt_pair(word[0], word[1])
            .map_err(Ownable2StepError::InvalidOwnerId)?;

        let nominated_owner = account_id_from_felt_pair(word[2], word[3])
            .map_err(Ownable2StepError::InvalidNominatedOwnerId)?;

        Ok(Self { owner, nominated_owner })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where ownership data is stored.
    pub fn slot_name() -> &'static StorageSlotName {
        &OWNER_CONFIG_SLOT_NAME
    }

    /// Returns the storage slot schema for the ownership configuration slot.
    pub fn slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::slot_name().clone(),
            StorageSlotSchema::value(
                "Ownership data (owner and nominated owner)",
                [
                    FeltSchema::felt("owner_suffix"),
                    FeltSchema::felt("owner_prefix"),
                    FeltSchema::felt("nominated_suffix"),
                    FeltSchema::felt("nominated_prefix"),
                ],
            ),
        )
    }

    /// Returns the current owner, or `None` if ownership has been renounced.
    pub fn owner(&self) -> Option<AccountId> {
        self.owner
    }

    /// Returns the nominated owner, or `None` if no transfer is in progress.
    pub fn nominated_owner(&self) -> Option<AccountId> {
        self.nominated_owner
    }

    /// Converts this ownership data into a [`StorageSlot`].
    pub fn to_storage_slot(&self) -> StorageSlot {
        StorageSlot::with_value(Self::slot_name().clone(), self.to_word())
    }

    /// Converts this ownership data into a raw [`Word`].
    pub fn to_word(&self) -> Word {
        let (owner_suffix, owner_prefix) = match self.owner {
            Some(id) => (id.suffix(), id.prefix().as_felt()),
            None => (Felt::ZERO, Felt::ZERO),
        };
        let (nominated_suffix, nominated_prefix) = match self.nominated_owner {
            Some(id) => (id.suffix(), id.prefix().as_felt()),
            None => (Felt::ZERO, Felt::ZERO),
        };
        [owner_suffix, owner_prefix, nominated_suffix, nominated_prefix].into()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema =
            StorageSchema::new([Self::slot_schema()]).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, AccountType::all())
            .with_description("Two-step ownership management component")
            .with_storage_schema(storage_schema)
    }
}

impl From<Ownable2Step> for AccountComponent {
    fn from(ownership: Ownable2Step) -> Self {
        let storage_slot = ownership.to_storage_slot();
        let metadata = Ownable2Step::component_metadata();

        AccountComponent::new(ownable2step_library(), vec![storage_slot], metadata).expect(
            "Ownable2Step component should satisfy the requirements of a valid account component",
        )
    }
}

// OWNABLE2STEP ERROR
// ================================================================================================

/// Errors that can occur when reading [`Ownable2Step`] data from storage.
#[derive(Debug, thiserror::Error)]
pub enum Ownable2StepError {
    #[error("failed to read ownership slot from storage")]
    StorageLookupFailed(#[source] miden_protocol::errors::AccountError),
    #[error("invalid owner account ID in storage")]
    InvalidOwnerId(#[source] AccountIdError),
    #[error("invalid nominated owner account ID in storage")]
    InvalidNominatedOwnerId(#[source] AccountIdError),
}

// HELPERS
// ================================================================================================

/// Constructs an `Option<AccountId>` from a suffix/prefix felt pair.
/// Returns `Ok(None)` when both felts are zero (renounced / no nomination).
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
