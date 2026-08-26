use alloc::collections::BTreeMap;
use alloc::vec;

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
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

use crate::account::{account_component_code, metadata_without_slots, package_metadata};
use crate::procedure_root;

// CONSTANTS
// ================================================================================================

account_component_code!(AUTHORITY_CODE, "miden-standards-access-authority.masp");

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from [`Authority::NAME`], which
/// mirrors the standards-side MASM module path.
const AUTHORITY_LIBRARY_PATH: &str = "miden::standards::components::access::authority";

procedure_root!(
    AUTHORITY_FREEZE,
    AUTHORITY_LIBRARY_PATH,
    Authority::FREEZE_PROC_NAME,
    Authority::code()
);

procedure_root!(
    AUTHORITY_UNFREEZE,
    AUTHORITY_LIBRARY_PATH,
    Authority::UNFREEZE_PROC_NAME,
    Authority::code()
);

static AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::authority::authority_config")
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
/// Under RBAC, each gated procedure can be assigned its own role via `procedure_roles`, keyed by
/// the procedure's [`AccountProcedureRoot`] (e.g. `pause` → `PAUSER`, `unpause` → `UNPAUSER`). At
/// runtime `assert_authorized` identifies the calling procedure via the `caller` instruction and
/// looks up its role. A procedure without a mapping falls back to the `ADMIN` role check.
///
/// # Emergency switch (`is_frozen`)
///
/// The component includes an `is_frozen` flag. If it is `true`, all procedures that call
/// `assert_authorized` would panic, effectively freezing them. Accounts are always constructed
/// unfrozen.
///
/// The flag is toggled via `freeze` / `unfreeze`. Under [`Authority::OwnerControlled`] these are
/// gated on the [`Ownable2Step`][crate::account::access::Ownable2Step] owner; under
/// [`Authority::RbacControlled`] they resolve their role from the role map (e.g. `FREEZER` /
/// `UNFREEZER`), defaulting to the `ADMIN` role. Both bypass the frozen flag itself so the switch
/// can always be toggled.
///
/// This flag has no effect under [`Authority::AuthControlled`], where `freeze` / `unfreeze` panic
/// (there is no owner and no role graph).
///
/// # Freeze-only actor (incident-response "panic button")
///
/// A second actor that can freeze the account in an incident but can never re-open it, or authorize
/// anything else, needs no dedicated component: it is a plain [`Authority::RbacControlled`] role
/// assignment. Map `freeze` to a role of its own, map `unfreeze` to a *different* role, and grant
/// the incident responder only the former:
///
/// ```no_run
/// use std::collections::BTreeMap;
///
/// use miden_protocol::account::{AccountBuilder, RoleSymbol};
/// use miden_standards::account::access::{AccessControl, Authority};
/// # let admin: miden_protocol::account::AccountId = unimplemented!();
/// # let init_seed = [0u8; 32];
///
/// let procedure_roles = BTreeMap::from([
///     (Authority::freeze_root(), RoleSymbol::new("FREEZER")?),
///     (Authority::unfreeze_root(), RoleSymbol::new("UNFREEZER")?),
/// ]);
///
/// AccountBuilder::new(init_seed).with_components(AccessControl::Rbac { admin, procedure_roles });
///
/// // Then grant `FREEZER` to the incident responder and `UNFREEZER` to the recovery authority
/// // through the `RoleBasedAccessControl` component's `grant_role`.
/// # Ok::<(), miden_protocol::errors::RoleSymbolError>(())
/// ```
///
/// This yields the intended asymmetry: freezing is available to the `FREEZER`, re-opening is not.
/// A compromised freeze-only actor can at worst deny service by freezing the account; it can never
/// keep the account open, grant roles, move assets, or invoke any other gated procedure.
///
/// Two things to get right when wiring this up:
///
/// - Map `unfreeze` explicitly, or leave it unmapped and keep the freeze-only actor out of `ADMIN`.
///   An unmapped procedure falls back to the `ADMIN` role, so a freeze-only actor that also holds
///   `ADMIN` could re-open the account and defeat the asymmetry.
/// - The pattern requires `RbacControlled`. Under [`Authority::OwnerControlled`] the owner is the
///   only emergency authority, and under [`Authority::AuthControlled`] there is no switch at all,
///   so an account that wants a freeze-only actor must use RBAC.
///
/// The same shape generalizes to any "can stop, cannot start" authority: give the cancelling or
/// pausing procedure its own role and keep the resuming procedure on a separate one.
///
/// Storage layout:
/// - Value slot: `[authority, is_frozen, 0, 0]`.
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
    /// `procedure_roles` maps a gated procedure's [`AccountProcedureRoot`] to the role required to
    /// invoke it. Requires the
    /// [`RoleBasedAccessControl`][crate::account::access::RoleBasedAccessControl] component to be
    /// installed on the account. the MASM helper calls into `rbac::assert_sender_has_role` and will
    /// fail to link otherwise.
    RbacControlled {
        procedure_roles: BTreeMap<AccountProcedureRoot, RoleSymbol>,
    } = RBAC_CONTROLLED,
}

impl Authority {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::access::authority";

    /// Name of the owner-gated procedure that freezes the authority-gated surface.
    const FREEZE_PROC_NAME: &'static str = "freeze";
    /// Name of the owner-gated procedure that unfreezes the authority-gated surface.
    const UNFREEZE_PROC_NAME: &'static str = "unfreeze";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &AUTHORITY_CODE
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the procedure root of the `freeze` emergency switch.
    ///
    /// Under [`Authority::OwnerControlled`] this is gated on the owner. Under
    /// [`Authority::RbacControlled`] it may be assigned its own role via the role map (e.g.
    /// `FREEZER`); when unmapped it falls back to the `ADMIN` role. Unlike ordinary gated
    /// procedures it bypasses the frozen flag so it can always be toggled.
    pub fn freeze_root() -> AccountProcedureRoot {
        *AUTHORITY_FREEZE
    }

    /// Returns the procedure root of the `unfreeze` emergency switch.
    ///
    /// Under [`Authority::OwnerControlled`] this is gated on the owner. Under
    /// [`Authority::RbacControlled`] it may be assigned its own role via the role map (e.g.
    /// `UNFREEZER`); when unmapped it falls back to the `ADMIN` role. Unlike ordinary gated
    /// procedures it bypasses the frozen flag so it can always be toggled.
    pub fn unfreeze_root() -> AccountProcedureRoot {
        *AUTHORITY_UNFREEZE
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
        let word = Self::read_config_word(storage)?;

        let discriminant: u8 = word[0]
            .as_canonical_u64()
            .try_into()
            .map_err(|_| AuthorityError::InvalidAuthority(word[0].as_canonical_u64()))?;

        match discriminant {
            AUTH_CONTROLLED => Ok(Self::AuthControlled),
            OWNER_CONTROLLED => Ok(Self::OwnerControlled),
            RBAC_CONTROLLED => {
                let procedure_roles = Self::read_roles_from_storage(storage)?;
                Ok(Self::RbacControlled { procedure_roles })
            },
            other => Err(AuthorityError::InvalidAuthority(other.into())),
        }
    }

    /// Reads the `is_frozen` emergency-switch flag from account storage.
    ///
    /// Returns `true` if the account's authority-gated surface is currently frozen (every
    /// procedure that calls `assert_authorized` panics until it is unfrozen).
    pub fn try_read_frozen(storage: &AccountStorage) -> Result<bool, AuthorityError> {
        let word = Self::read_config_word(storage)?;

        Ok(word[1] != Felt::ZERO)
    }

    /// Returns the [`AccountComponentMetadata`] for this configuration.
    ///
    /// The manifest declares the full storage schema, but only [`Authority::RbacControlled`]
    /// installs the `procedure_roles` slot; the other authorities drop it from the schema.
    pub fn component_metadata(&self) -> AccountComponentMetadata {
        let metadata = package_metadata(Self::code());
        if matches!(self, Authority::RbacControlled { .. }) {
            return metadata;
        }

        metadata_without_slots(metadata, &[Self::procedure_roles_slot()])
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

    /// Encodes the authority configuration value slot word: `[authority, is_frozen, 0, 0]`.
    fn to_word(&self) -> Word {
        Word::new([Felt::from(self.as_u8()), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }

    /// Reads and validates the authority value-slot word `[authority, is_frozen, 0, 0]`.
    ///
    /// Enforces the canonical encoding on read: the reserved felts `word[2]` and `word[3]` must be
    /// zero, and `is_frozen` (`word[1]`) must be a boolean (`0` or `1`) - the exact form the write
    /// path (`to_word` plus the MASM freeze/unfreeze switch) always produces.
    fn read_config_word(storage: &AccountStorage) -> Result<Word, AuthorityError> {
        let word = storage
            .get_item(Self::authority_slot())
            .map_err(AuthorityError::MissingStorageSlot)?;

        if word[2] != Felt::ZERO || word[3] != Felt::ZERO || word[1].as_canonical_u64() > 1 {
            return Err(AuthorityError::NonCanonicalConfig);
        }

        Ok(word)
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
            // Enforce the canonical encoding on read: the reserved felts must be zero.
            if value[1..4].iter().any(|v| *v != Felt::ZERO) {
                return Err(AuthorityError::NonCanonicalConfig);
            }
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

        if let Authority::RbacControlled { procedure_roles } = value {
            let entries = procedure_roles.into_iter().map(|(proc_root, role)| {
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
    #[error("authority configuration word is not in canonical form")]
    NonCanonicalConfig,
    #[error("invalid role symbol in authority storage")]
    InvalidRoleSymbol(#[source] RoleSymbolError),
    #[error("failed to read authority slot from storage")]
    MissingStorageSlot(#[source] AccountError),
    #[error("authority procedure-roles slot is missing or not a map")]
    MissingProcedureRolesSlot,
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    /// Procedure-root key of the single entry inserted by [`rbac_storage_with_role_value`].
    const ROLE_KEY_WORD: [u32; 4] = [1, 2, 3, 4];

    /// Builds account storage whose authority value slot holds `word`.
    fn storage_with_config(word: Word) -> AccountStorage {
        let slot = StorageSlot::with_value(Authority::authority_slot().clone(), word);
        AccountStorage::new(vec![slot]).expect("storage should be valid")
    }

    /// Builds RBAC account storage whose procedure-roles map holds a single entry, keyed by
    /// [`ROLE_KEY_WORD`], with `role_value` as its value word.
    fn rbac_storage_with_role_value(role_value: Word) -> AccountStorage {
        let config = StorageSlot::with_value(
            Authority::authority_slot().clone(),
            Word::from([u32::from(RBAC_CONTROLLED), 0, 0, 0]),
        );
        let key = StorageMapKey::new(Word::from(ROLE_KEY_WORD));
        let map = StorageMap::with_entries([(key, role_value)]).expect("map should be valid");
        let roles = StorageSlot::with_map(Authority::procedure_roles_slot().clone(), map);
        AccountStorage::new(vec![config, roles]).expect("storage should be valid")
    }

    #[test]
    fn canonical_config_is_accepted() {
        // AuthControlled, not frozen.
        let storage = storage_with_config(Word::from([u32::from(AUTH_CONTROLLED), 0, 0, 0]));
        assert_eq!(Authority::try_from_storage(&storage).unwrap(), Authority::AuthControlled);
        assert!(!Authority::try_read_frozen(&storage).unwrap());

        // OwnerControlled, frozen.
        let storage = storage_with_config(Word::from([u32::from(OWNER_CONTROLLED), 1, 0, 0]));
        assert_eq!(Authority::try_from_storage(&storage).unwrap(), Authority::OwnerControlled);
        assert!(Authority::try_read_frozen(&storage).unwrap());
    }

    #[test]
    fn non_zero_reserved_felt_is_rejected() {
        // word[3] carries unexpected trailing data.
        let storage = storage_with_config(Word::from([u32::from(OWNER_CONTROLLED), 0, 0, 7]));
        assert!(matches!(
            Authority::try_from_storage(&storage),
            Err(AuthorityError::NonCanonicalConfig)
        ));
        assert!(matches!(
            Authority::try_read_frozen(&storage),
            Err(AuthorityError::NonCanonicalConfig)
        ));

        // word[2] carries unexpected trailing data.
        let storage = storage_with_config(Word::from([u32::from(OWNER_CONTROLLED), 0, 5, 0]));
        assert!(matches!(
            Authority::try_from_storage(&storage),
            Err(AuthorityError::NonCanonicalConfig)
        ));
    }

    #[test]
    fn non_boolean_frozen_flag_is_rejected() {
        // is_frozen (word[1]) must be 0 or 1; 2 is non-canonical.
        let storage = storage_with_config(Word::from([u32::from(AUTH_CONTROLLED), 2, 0, 0]));
        assert!(matches!(
            Authority::try_from_storage(&storage),
            Err(AuthorityError::NonCanonicalConfig)
        ));
        assert!(matches!(
            Authority::try_read_frozen(&storage),
            Err(AuthorityError::NonCanonicalConfig)
        ));
    }

    #[test]
    fn non_zero_reserved_felt_in_role_value_is_rejected() {
        let role = RoleSymbol::new("ADMIN").unwrap();
        let role_felt: Felt = (&role).into();
        let expected_root = AccountProcedureRoot::from_raw(Word::from(ROLE_KEY_WORD));

        // A canonical role value word `[role, 0, 0, 0]` is accepted and parses the configured role.
        let storage = rbac_storage_with_role_value(Word::new([
            role_felt,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ]));
        assert_matches!(
            Authority::try_from_storage(&storage),
            Ok(Authority::RbacControlled { procedure_roles })
                if procedure_roles.get(&expected_root) == Some(&role)
        );

        // A non-zero reserved felt in the role value word carries unexpected trailing data.
        let storage = rbac_storage_with_role_value(Word::new([
            role_felt,
            Felt::ZERO,
            Felt::from(9u8),
            Felt::ZERO,
        ]));
        assert_matches!(
            Authority::try_from_storage(&storage),
            Err(AuthorityError::NonCanonicalConfig)
        );
    }
}
