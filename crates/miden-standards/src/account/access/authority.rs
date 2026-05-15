use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    FeltSchema,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountStorage,
    AccountType,
    RoleSymbol,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::{AccountError, RoleSymbolError};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use thiserror::Error;

use crate::account::account_component_code;

// CONSTANTS
// ================================================================================================

account_component_code!(AUTHORITY_CODE, "access/authority.masl");

static AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::authority")
        .expect("storage slot name should be valid")
});

/// Authority value written to the storage slot for [`Authority::AuthControlled`].
const AUTH_CONTROLLED: u8 = 0;
/// Authority value written to the storage slot for [`Authority::OwnerControlled`].
const OWNER_CONTROLLED: u8 = 1;
/// Authority value written to the storage slot for [`Authority::RbacControlled`].
const RBAC_CONTROLLED: u8 = 2;

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
/// Storage layout: `[authority, role_symbol_or_zero, 0, 0]` — single Word.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Authority {
    /// Authority is the account's auth component; no extra check is performed by
    /// `authority::assert_authorized`.
    AuthControlled = AUTH_CONTROLLED,
    /// Authority is the [`Ownable2Step`][crate::account::access::Ownable2Step] owner; the call
    /// must be sent by the registered owner.
    OwnerControlled = OWNER_CONTROLLED,
    /// Authority is membership in a specific RBAC role. The call must be sent by an account that
    /// holds `role` in the
    /// [`RoleBasedAccessControl`][crate::account::access::RoleBasedAccessControl] component.
    ///
    /// Requires the [`RoleBasedAccessControl`][crate::account::access::RoleBasedAccessControl]
    /// component to be installed on the account; the MASM helper calls into
    /// `rbac::assert_sender_has_role` and will fail to link otherwise.
    RbacControlled { role: RoleSymbol } = RBAC_CONTROLLED,
}

impl Authority {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::access::authority";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &AUTHORITY_CODE
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] holding the authority configuration.
    pub fn authority_slot() -> &'static StorageSlotName {
        &AUTHORITY_SLOT_NAME
    }

    /// Reads the authority configuration from account storage.
    pub fn try_from_storage(storage: &AccountStorage) -> Result<Self, AuthorityError> {
        let word = storage
            .get_item(Self::authority_slot())
            .map_err(AuthorityError::MissingStorageSlot)?;
        Self::try_from(word)
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![(
            AUTHORITY_SLOT_NAME.clone(),
            StorageSlotSchema::value(
                "Authority configuration",
                [
                    FeltSchema::u8("authority"),
                    FeltSchema::felt("role_symbol"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, AccountType::all())
            .with_description(
                "Account-wide authority shared by procedures that gate state-mutating \
                 operations behind auth-only, owner-based, or RBAC role-based checks",
            )
            .with_storage_schema(storage_schema)
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl From<Authority> for Word {
    fn from(value: Authority) -> Self {
        match value {
            Authority::AuthControlled => {
                Word::new([Felt::from(AUTH_CONTROLLED), Felt::ZERO, Felt::ZERO, Felt::ZERO])
            },
            Authority::OwnerControlled => {
                Word::new([Felt::from(OWNER_CONTROLLED), Felt::ZERO, Felt::ZERO, Felt::ZERO])
            },
            Authority::RbacControlled { role } => {
                Word::new([Felt::from(RBAC_CONTROLLED), role.into(), Felt::ZERO, Felt::ZERO])
            },
        }
    }
}

impl TryFrom<Word> for Authority {
    type Error = AuthorityError;

    fn try_from(word: Word) -> Result<Self, Self::Error> {
        let authority: u8 = word[0]
            .as_canonical_u64()
            .try_into()
            .map_err(|_| AuthorityError::InvalidAuthority(word[0].as_canonical_u64()))?;
        match authority {
            AUTH_CONTROLLED => Ok(Self::AuthControlled),
            OWNER_CONTROLLED => Ok(Self::OwnerControlled),
            RBAC_CONTROLLED => {
                let role =
                    RoleSymbol::try_from(word[1]).map_err(AuthorityError::InvalidRoleSymbol)?;
                Ok(Self::RbacControlled { role })
            },
            other => Err(AuthorityError::InvalidAuthority(other.into())),
        }
    }
}

impl From<Authority> for AccountComponent {
    fn from(value: Authority) -> Self {
        let slot = StorageSlot::with_value(AUTHORITY_SLOT_NAME.clone(), Word::from(value));
        AccountComponent::new(
            Authority::code().clone(),
            vec![slot],
            Authority::component_metadata(),
        )
        .expect("authority component should satisfy the requirements of a valid account component")
    }
}

// AUTHORITY ERROR
// ================================================================================================

/// Errors raised when reading or parsing an [`Authority`] from storage.
#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("invalid authority value: {0}")]
    InvalidAuthority(u64),
    #[error("invalid role symbol in authority slot")]
    InvalidRoleSymbol(#[source] RoleSymbolError),
    #[error("failed to read authority slot from storage")]
    MissingStorageSlot(#[source] AccountError),
}
