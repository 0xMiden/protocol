use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountStorage,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;
use thiserror::Error;

use crate::account::components::authority_library;

// CONSTANTS
// ================================================================================================

static AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::authority::authority")
        .expect("storage slot name should be valid")
});

// AUTHORITY
// ================================================================================================

/// Identifies which authority is allowed to invoke an authority-gated procedure on an account.
///
/// Components that gate state-mutating procedures (such as
/// [`TokenPolicyManager`][crate::account::policies::TokenPolicyManager] for `set_mint_policy` /
/// `set_burn_policy`, or the fungible token metadata setters) consult this single shared slot via
/// the MASM helper `authority::assert_authorized`. Installing the [`Authority`] component on an
/// account thus selects the gating mode for *all* such procedures in one place.
///
/// Storage layout: `[discriminator, 0, 0, 0]` — single Felt at index 0.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Authority {
    /// Authority is the account's auth component; no extra check is performed by
    /// `authority::assert_authorized`.
    AuthControlled = 0,
    /// Authority is the [`Ownable2Step`][crate::account::access::Ownable2Step] owner; the call
    /// must be sent by the registered owner.
    OwnerControlled = 1,
    /// Authority is determined via RBAC role-based checks.
    ///
    /// Note: not yet supported by `authority::assert_authorized`. Reserved for a future
    /// extension; selecting this variant today will cause `assert_authorized` to panic when
    /// invoked.
    RbacControlled = 2,
}

impl Authority {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::access::authority";

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] holding the authority discriminator.
    pub fn slot_name() -> &'static StorageSlotName {
        &AUTHORITY_SLOT_NAME
    }

    /// Reads the authority discriminator from account storage.
    pub fn try_from_storage(storage: &AccountStorage) -> Result<Self, AuthorityError> {
        let word = storage
            .get_item(Self::slot_name())
            .map_err(|err| AuthorityError::StorageLookupFailed(alloc::format!("{err}")))?;
        Self::try_from(word)
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![(
            AUTHORITY_SLOT_NAME.clone(),
            StorageSlotSchema::value(
                "Authority discriminator",
                [
                    FeltSchema::u8("authority"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, AccountType::all())
            .with_description(
                "Account-wide authority discriminator shared by procedures that gate \
                 state-mutating operations behind either auth-only or owner-based checks",
            )
            .with_storage_schema(storage_schema)
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl From<Authority> for Word {
    fn from(value: Authority) -> Self {
        Word::from([value as u8, 0, 0, 0])
    }
}

impl TryFrom<Word> for Authority {
    type Error = AuthorityError;

    fn try_from(word: Word) -> Result<Self, Self::Error> {
        match word[0].as_canonical_u64() {
            0 => Ok(Self::AuthControlled),
            1 => Ok(Self::OwnerControlled),
            2 => Ok(Self::RbacControlled),
            v => Err(AuthorityError::InvalidDiscriminator(v)),
        }
    }
}

impl From<Authority> for AccountComponent {
    fn from(value: Authority) -> Self {
        let slot = StorageSlot::with_value(AUTHORITY_SLOT_NAME.clone(), Word::from(value));
        AccountComponent::new(authority_library(), vec![slot], Authority::component_metadata())
            .expect(
                "authority component should satisfy the requirements of a valid account component",
            )
    }
}

// AUTHORITY ERROR
// ================================================================================================

/// Errors raised when reading or parsing an [`Authority`] from storage.
#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("invalid authority discriminator: {0}")]
    InvalidDiscriminator(u64),
    #[error("failed to read authority slot from storage: {0}")]
    StorageLookupFailed(alloc::string::String),
}
