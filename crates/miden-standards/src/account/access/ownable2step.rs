use miden_protocol::account::component::{FeltSchema, StorageSlotSchema};
use miden_protocol::account::{AccountId, AccountStorage, StorageSlot, StorageSlotName};
use miden_protocol::errors::AccountIdError;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, FieldElement, Word};

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
/// Rust Word:  [nominated_owner_suffix, nominated_owner_prefix, owner_suffix, owner_prefix]
///              word[0]                  word[1]                 word[2]       word[3]
/// ```
///
/// After `get_item` (which reverses the word onto the MASM stack), the stack is:
///
/// ```text
/// Stack: [owner_prefix, owner_suffix, nominated_owner_prefix, nominated_owner_suffix]
///         (word[3])     (word[2])      (word[1])               (word[0])
/// ```
pub struct Ownable2Step {
    owner: Option<AccountId>,
    nominated_owner: Option<AccountId>,
}

impl Ownable2Step {
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
    /// Format: `[nominated_suffix, nominated_prefix, owner_suffix, owner_prefix]`
    pub fn try_from_word(word: Word) -> Result<Self, Ownable2StepError> {
        let owner = account_id_from_felt_pair(word[3], word[2])
            .map_err(Ownable2StepError::InvalidOwnerId)?;

        let nominated_owner = account_id_from_felt_pair(word[1], word[0])
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
                    FeltSchema::felt("nominated_suffix"),
                    FeltSchema::felt("nominated_prefix"),
                    FeltSchema::felt("owner_suffix"),
                    FeltSchema::felt("owner_prefix"),
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
        let (owner_prefix, owner_suffix) = match self.owner {
            Some(id) => (id.prefix().as_felt(), id.suffix()),
            None => (Felt::ZERO, Felt::ZERO),
        };
        let (nominated_prefix, nominated_suffix) = match self.nominated_owner {
            Some(id) => (id.prefix().as_felt(), id.suffix()),
            None => (Felt::ZERO, Felt::ZERO),
        };
        [nominated_suffix, nominated_prefix, owner_suffix, owner_prefix].into()
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

/// Constructs an `Option<AccountId>` from a prefix/suffix felt pair.
/// Returns `Ok(None)` when both felts are zero (renounced / no nomination).
fn account_id_from_felt_pair(
    prefix: Felt,
    suffix: Felt,
) -> Result<Option<AccountId>, AccountIdError> {
    if prefix == Felt::ZERO && suffix == Felt::ZERO {
        Ok(None)
    } else {
        AccountId::try_from([prefix, suffix]).map(Some)
    }
}
