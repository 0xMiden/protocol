use alloc::collections::BTreeMap;
use alloc::vec;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    FeltSchema,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountProcedureRoot,
    AccountStorage,
    RoleSymbol,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotContent,
    StorageSlotName,
};
use miden_protocol::errors::{AccountError, RoleSymbolError};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use thiserror::Error;

use crate::account::account_component_code;
use crate::procedure_root;

// CONSTANTS
// ================================================================================================

account_component_code!(AUTHORITY_CODE, "access/authority.masl");

procedure_root!(
    AUTHORITY_SET_TARGET_CLOSED,
    Authority::NAME,
    Authority::SET_TARGET_CLOSED_PROC_NAME,
    Authority::code()
);

procedure_root!(
    AUTHORITY_SET_TARGET_OPENED,
    Authority::NAME,
    Authority::SET_TARGET_OPENED_PROC_NAME,
    Authority::code()
);

static AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::authority")
        .expect("storage slot name should be valid")
});

static AUTHORITY_PROCEDURE_ROLES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::authority::procedure_roles")
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
/// `set_burn_policy`, or the fungible token metadata setters) consult this shared slot via the
/// MASM helper `authority::assert_authorized`. Installing the [`Authority`] component on an account
/// thus selects the gating mode for *all* such procedures in one place.
///
/// # Safety invariant for [`Authority::AuthControlled`]
///
/// Because `assert_authorized` is a no-op under `AuthControlled`, the account's auth component
/// is the **sole** gate for every authority-gated setter. The auth component MUST therefore
/// authenticate every such setter root, otherwise the setters become permissionless.
///
/// # Per-procedure roles under [`Authority::RbacControlled`]
///
/// Under RBAC, each gated procedure can be assigned its own role via `roles`, keyed by the
/// procedure's [`AccountProcedureRoot`] (e.g. `pause` → `PAUSER`, `unpause` → `UNPAUSER`). At
/// runtime `assert_authorized` identifies the calling procedure via the `caller` instruction and
/// looks up its role. A procedure without a mapping falls back to the
/// [`Ownable2Step`][crate::account::access::Ownable2Step] owner check.
///
/// # Emergency switch (`target_closed`)
///
/// `word[1]` of the value slot holds a global `target_closed` flag. While set, `assert_authorized`
/// panics for *every* gated procedure before any role/owner dispatch, atomically freezing the
/// account's entire management surface regardless of role membership. The flag is toggled by the
/// owner-gated `set_target_closed` / `set_target_opened` procedures, which are gated directly on
/// the [`Ownable2Step`][crate::account::access::Ownable2Step] owner check (not `assert_authorized`)
/// so the owner can always reopen a closed account. Accounts are always constructed open
/// (`target_closed = 0`). The switch is only meaningful when Ownable2Step is installed
/// ([`Authority::OwnerControlled`] / [`Authority::RbacControlled`]); under
/// [`Authority::AuthControlled`] there is no owner and the setters panic.
///
/// Storage layout:
/// - Value slot: `[authority, target_closed, 0, 0]`.
/// - Map slot (only under RBAC): `procedure_root` → `[role_symbol, 0, 0, 0]`.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Authority {
    /// Authority is the account's auth component.
    AuthControlled = AUTH_CONTROLLED,
    /// Authority is the [`Ownable2Step`][crate::account::access::Ownable2Step] owner.
    OwnerControlled = OWNER_CONTROLLED,
    /// Authority is membership in an RBAC role, resolved per gated procedure.
    ///
    /// `roles` maps a gated procedure's [`AccountProcedureRoot`] to the role required to invoke it.
    /// Requires the [`RoleBasedAccessControl`][crate::account::access::RoleBasedAccessControl]
    /// component to be installed on the account. the MASM helper calls into
    /// `rbac::assert_sender_has_role` and will fail to link otherwise.
    RbacControlled {
        roles: BTreeMap<AccountProcedureRoot, RoleSymbol>,
    } = RBAC_CONTROLLED,
}

impl Authority {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::access::authority";

    /// Name of the owner-gated procedure that closes the authority-gated surface.
    pub const SET_TARGET_CLOSED_PROC_NAME: &'static str = "set_target_closed";
    /// Name of the owner-gated procedure that reopens the authority-gated surface.
    pub const SET_TARGET_OPENED_PROC_NAME: &'static str = "set_target_opened";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &AUTHORITY_CODE
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the procedure root of the owner-gated `set_target_closed` emergency switch.
    ///
    /// This procedure is always gated on the owner check directly, so unlike role-assignable
    /// procedures it must not be placed in the [`Authority::RbacControlled`] role map.
    pub fn set_target_closed_root() -> AccountProcedureRoot {
        *AUTHORITY_SET_TARGET_CLOSED
    }

    /// Returns the procedure root of the owner-gated `set_target_opened` emergency switch.
    ///
    /// This procedure is always gated on the owner check directly, so unlike role-assignable
    /// procedures it must not be placed in the [`Authority::RbacControlled`] role map.
    pub fn set_target_opened_root() -> AccountProcedureRoot {
        *AUTHORITY_SET_TARGET_OPENED
    }

    /// Returns the [`StorageSlotName`] holding the authority configuration.
    pub fn authority_slot() -> &'static StorageSlotName {
        &AUTHORITY_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] holding the per-procedure role map (RBAC only).
    pub fn procedure_roles_slot() -> &'static StorageSlotName {
        &AUTHORITY_PROCEDURE_ROLES_SLOT_NAME
    }

    /// Reads the authority configuration from account storage.
    pub fn try_from_storage(storage: &AccountStorage) -> Result<Self, AuthorityError> {
        let word = storage
            .get_item(Self::authority_slot())
            .map_err(AuthorityError::MissingStorageSlot)?;

        let discriminant: u8 = word[0]
            .as_canonical_u64()
            .try_into()
            .map_err(|_| AuthorityError::InvalidAuthority(word[0].as_canonical_u64()))?;

        match discriminant {
            AUTH_CONTROLLED => Ok(Self::AuthControlled),
            OWNER_CONTROLLED => Ok(Self::OwnerControlled),
            RBAC_CONTROLLED => {
                let roles = Self::read_roles_from_storage(storage)?;
                Ok(Self::RbacControlled { roles })
            },
            other => Err(AuthorityError::InvalidAuthority(other.into())),
        }
    }

    /// Returns the [`AccountComponentMetadata`] for this configuration.
    pub fn component_metadata(&self) -> AccountComponentMetadata {
        let mut slots = vec![(
            AUTHORITY_SLOT_NAME.clone(),
            StorageSlotSchema::value(
                "Authority configuration",
                [
                    FeltSchema::u8("authority"),
                    FeltSchema::u8("target_closed"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )];

        if matches!(self, Authority::RbacControlled { .. }) {
            slots.push((
                AUTHORITY_PROCEDURE_ROLES_SLOT_NAME.clone(),
                StorageSlotSchema::map(
                    "Per-procedure role assignment (procedure root -> role symbol)",
                    SchemaType::native_word(),
                    SchemaType::role_symbol(),
                ),
            ));
        }

        let storage_schema = StorageSchema::new(slots).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "Account-wide authority shared by procedures that gate state-mutating \
                 operations behind auth-only, owner-based, or RBAC role-based checks",
            )
            .with_storage_schema(storage_schema)
    }

    // PRIVATE HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the discriminant byte written to `word[0]` of the authority slot.
    fn as_u8(&self) -> u8 {
        match self {
            Authority::AuthControlled => AUTH_CONTROLLED,
            Authority::OwnerControlled => OWNER_CONTROLLED,
            Authority::RbacControlled { .. } => RBAC_CONTROLLED,
        }
    }

    /// Encodes the authority configuration value slot word: `[authority, target_closed, 0, 0]`.
    ///
    /// Accounts are always constructed open, so `target_closed` (`word[1]`) is initialized to
    /// zero; the owner toggles it later via `set_target_closed` / `set_target_opened`.
    fn to_word(&self) -> Word {
        Word::new([Felt::from(self.as_u8()), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }

    /// Reconstructs the per-procedure role map from the procedure-roles storage slot.
    fn read_roles_from_storage(
        storage: &AccountStorage,
    ) -> Result<BTreeMap<AccountProcedureRoot, RoleSymbol>, AuthorityError> {
        let slot = storage
            .slots()
            .iter()
            .find(|slot| slot.name().id() == AUTHORITY_PROCEDURE_ROLES_SLOT_NAME.id())
            .ok_or(AuthorityError::MissingProcedureRolesSlot)?;

        let StorageSlotContent::Map(map) = slot.content() else {
            return Err(AuthorityError::MissingProcedureRolesSlot);
        };

        let mut roles = BTreeMap::new();
        for (key, value) in map.entries() {
            let proc_root = AccountProcedureRoot::from_raw(key.as_word());
            let role = RoleSymbol::try_from(value[0]).map_err(AuthorityError::InvalidRoleSymbol)?;
            roles.insert(proc_root, role);
        }

        Ok(roles)
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl From<Authority> for AccountComponent {
    fn from(value: Authority) -> Self {
        let metadata = value.component_metadata();

        let mut slots = vec![StorageSlot::with_value(AUTHORITY_SLOT_NAME.clone(), value.to_word())];

        if let Authority::RbacControlled { roles } = value {
            let entries = roles.into_iter().map(|(proc_root, role)| {
                (StorageMapKey::new(proc_root.as_word()), role_value_word(&role))
            });
            slots.push(StorageSlot::with_map(
                AUTHORITY_PROCEDURE_ROLES_SLOT_NAME.clone(),
                StorageMap::with_entries(entries)
                    .expect("authority procedure-roles map should be valid"),
            ));
        }

        AccountComponent::new(Authority::code().clone(), slots, metadata).expect(
            "authority component should satisfy the requirements of a valid account component",
        )
    }
}

/// Encodes a role symbol as a map value word: `[role_symbol, 0, 0, 0]`.
fn role_value_word(role: &RoleSymbol) -> Word {
    Word::new([role.into(), Felt::ZERO, Felt::ZERO, Felt::ZERO])
}

// AUTHORITY ERROR
// ================================================================================================

/// Errors raised when reading or parsing an [`Authority`] from storage.
#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("invalid authority value: {0}")]
    InvalidAuthority(u64),
    #[error("invalid role symbol in authority storage")]
    InvalidRoleSymbol(#[source] RoleSymbolError),
    #[error("failed to read authority slot from storage")]
    MissingStorageSlot(#[source] AccountError),
    #[error("authority procedure-roles slot is missing or not a map")]
    MissingProcedureRolesSlot,
}
